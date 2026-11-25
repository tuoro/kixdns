//! 配置用到的 Geo 数据：放在引擎状态里，和按它算的缓存命名空间一起换进去（见 `EngineInner::geo`）。启动和热重载按
//! 同一套规则加载，热重载时只有配置里决定加载什么的部分变了才重新加载，同时改为监视新的文件。
//! The Geo data a configuration uses: kept in the engine state, swapped in together with the
//! cache namespaces worked out from it (see `EngineInner::geo`). Startup and hot reload load it
//! by the same rules, and a hot reload loads it again, and moves the file watches to the new
//! files, only when the part of the configuration that decides what is loaded changed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::{error, info, warn};

use super::Engine;
use super::types::EngineInner;
use crate::matcher::geoip::{GeoIpManager, is_country_tag};
use crate::matcher::geosite::{GeoSiteManager, parsed_provides_any};
use crate::matcher::{GeoManagers, RuntimePipelineConfig};
use crate::watcher::{FileWatch, PendingWatch, SEEN_WITHIN};
use parking_lot::Mutex;

/// 配置里决定加载哪些 GeoSite 数据的部分 / The part of a configuration that decides which GeoSite data is loaded
#[derive(Debug, PartialEq, Eq)]
struct GeoSiteSpec {
    paths: Vec<String>,
    /// 规则用到的标签，排好序（见 `RuntimePipelineConfig::geosite_tags`），可以比较 / The tags
    /// rules use, sorted (see `RuntimePipelineConfig::geosite_tags`), so specs compare
    tags: Vec<String>,
}

impl GeoSiteSpec {
    fn of(cfg: &RuntimePipelineConfig) -> Self {
        Self {
            paths: cfg.settings.geosite_data_paths.clone(),
            tags: cfg.geosite_tags(),
        }
    }
}

/// 配置里决定加载哪些 GeoIP 数据的部分：规则按 GeoIP 匹配的国家代码和命名标签，以及要读的文件。
/// 只有两个字母的国家代码会查 MMDB，所以没有国家代码时 MMDB 不读；规则不按 GeoIP 匹配时什么都不读
/// The part of a configuration that decides which GeoIP data is loaded: the country codes and
/// named tags rules match on GeoIP, and the files to read. Only two-letter country codes are
/// looked up in the MMDB, so without any it is not read; when no rule matches on GeoIP nothing
/// is read
#[derive(Debug, PartialEq, Eq)]
struct GeoIpSpec {
    /// 大写，排好序 / Uppercase and sorted
    tags: Vec<String>,
    db_path: Option<String>,
    dat_path: Option<String>,
}

impl GeoIpSpec {
    fn of(cfg: &RuntimePipelineConfig) -> Self {
        let tags = cfg.geoip_tags();
        let wants_countries = tags.iter().any(|tag| is_country_tag(tag));
        Self {
            db_path: cfg
                .settings
                .geoip_db_path
                .clone()
                .filter(|_| wants_countries),
            dat_path: cfg
                .settings
                .geoip_dat_path
                .clone()
                .filter(|_| !tags.is_empty()),
            tags,
        }
    }
}

/// 按一份 spec 加载的数据从哪来、谁在监视（监视线程起不来时没有）/ Where the data loaded for a spec came
/// from, and what watches it (nothing when the watch thread could not start)
struct Loaded<S> {
    spec: S,
    watch: Option<FileWatch>,
}

/// 两种 Geo 数据眼下的问题：配置了却不存在或读不了的文件、读得出来却没有规则用到的标签了的文件（留着先前读进来的数据）、
/// 起不来的监视线程和有位置监视不上的文件、规则用到却没有数据提供的标签。启动、热重载和监视到文件变了时跟着更新，面板
/// 经控制通道读（见 [`Engine::geo_data_warnings`]）
/// What is wrong with the two kinds of Geo data right now: configured files that are missing
/// or cannot be read, files that read yet have none of the tags rules use any more (the data
/// read from them before staying), watch threads that cannot start and files with places that
/// cannot be watched, and tags rules use that no data provides. Kept up to date at
/// startup, on hot reloads and as watched files change, and read by the panel over the
/// control channel (see [`Engine::geo_data_warnings`])
#[derive(Default)]
pub(crate) struct GeoStatus {
    site: Mutex<DataStatus>,
    ip: Mutex<DataStatus>,
}

/// 一种 Geo 数据的问题，每样一句话 / What is wrong with one kind of Geo data, a sentence each
#[derive(Default)]
struct DataStatus {
    /// 读不进来的文件，和读得出来却没有规则用到的标签了的文件，各带说它的那句话 / The files that could not be
    /// read in, and those that read yet have none of the tags rules use any more, each with the
    /// sentence saying so
    files: Vec<(PathBuf, String)>,
    /// 监视线程起不来时说它的那句话 / The sentence saying the watch thread could not start, when it could not
    watch: Option<String>,
    /// 监视着、却有位置监视不上的文件（事件报不出那里的变化，由监视的核对接上），各带说它的那句话
    /// The files watched, yet with places that cannot be (events not reporting changes there,
    /// which the watch's checks catch), each with the sentence saying so
    partly_watched: Vec<(PathBuf, String)>,
    /// 规则用到、却没有数据提供的标签，说它们的那句话 / The sentence naming the tags rules use that no data provides
    tags: Option<String>,
}

impl DataStatus {
    /// `what`（比如 GeoSite data file）`path` 不存在 / `what` (GeoSite data file, say) `path` is not there
    fn missing(&mut self, what: &str, path: &Path) {
        self.file(path, format!("{what} {} does not exist", path.display()));
    }

    /// 读 `what` `path` 时出了 `err`：不存在，或者读不了 / Reading `what` `path` failed with `err`:
    /// it is not there, or cannot be read
    fn not_read(&mut self, what: &str, path: &Path, err: &anyhow::Error) {
        if path.exists() {
            self.file(
                path,
                format!("{what} {} cannot be read: {err:#}", path.display()),
            );
        } else {
            self.missing(what, path);
        }
    }

    fn file(&mut self, path: &Path, said: String) {
        say(&mut self.files, (path.to_path_buf(), said));
    }

    /// `what` 的监视线程因为 `err` 起不来：哪个文件都没人监视，改了要等重启或者改了读什么的热加载才读
    /// The watch thread of `what` could not start because of `err`: no file is watched by
    /// anything, and a change waits to be read for a restart or a reload changing which files are
    /// read
    fn not_watched(&mut self, what: &str, err: &dyn std::fmt::Display) {
        self.watch = Some(format!(
            "{what} cannot be watched for changes, which are read after a restart or a reload changing which files are read: {err}"
        ));
        self.partly_watched.clear();
    }

    /// 监视着的 `what` `path` 有位置因为 `err` 监视不上（见 `PendingWatch::uncovered`、
    /// `PendingWatch::start_reporting`），那里的变化由监视的核对接上；是 None 时都监视上了
    /// Watched `what` `path` has places that cannot be watched because of `err` (see
    /// `PendingWatch::uncovered`, `PendingWatch::start_reporting`), changes there being caught by
    /// the watch's checks; None when every place is watched
    fn watched(&mut self, what: &str, path: &Path, err: Option<&notify::Error>) {
        match err {
            Some(err) => {
                let said = format!(
                    "{what} {} cannot be watched everywhere it leads, {SEEN_WITHIN}: {err}",
                    path.display()
                );
                say(&mut self.partly_watched, (path.to_path_buf(), said));
            }
            None => self.partly_watched.retain(|(file, _)| file != path),
        }
    }

    /// 有没有一句说 `path` 的 / Whether a sentence says something of `path`
    fn has(&self, path: &Path) -> bool {
        self.files.iter().any(|(file, _)| file == path)
    }

    /// `path` 读进来了 / `path` was read in
    fn read(&mut self, path: &Path) {
        self.files.retain(|(file, _)| file != path);
    }

    fn sentences(&self) -> impl Iterator<Item = &str> {
        let files = self.files.iter().map(|(_, said)| said.as_str());
        let partly_watched = self.partly_watched.iter().map(|(_, said)| said.as_str());
        files
            .chain(self.watch.as_deref())
            .chain(partly_watched)
            .chain(self.tags.as_deref())
    }
}

/// `said` 换掉 `sentences` 里说同一个文件的那句，没有就排到最后 / `said` takes the place of the one of
/// `sentences` saying something of the same file, or goes last when there is none
fn say<F: AsRef<Path>>(sentences: &mut Vec<(F, String)>, said: (F, String)) {
    match sentences
        .iter_mut()
        .find(|(file, _)| file.as_ref() == said.0.as_ref())
    {
        Some(was) => *was = said,
        None => sentences.push(said),
    }
}

impl Engine {
    /// Geo 数据眼下的问题，一样一句话：配置了却不存在或读不了的文件、读得出来却没有规则用到的标签了的文件（只有它提供的
    /// 标签留着先前读进来的数据，重启以后就没有了）、起不来的监视线程、有位置监视不上的文件、规则用到却没有数据提供的标签
    /// （这样的规则 geo_site、geoip_country 永不命中，geo_site_not 总命中）。没有问题时是空的。启动、热重载和监视到文件
    /// 变了时跟着更新
    /// What is wrong with the Geo data right now, a sentence each: configured files that are
    /// missing or cannot be read, files that read yet have none of the tags rules use any more
    /// (the tags only they provide keeping the data read from them before, gone after a
    /// restart), watch threads that cannot start, files with places that cannot be watched, and
    /// tags rules use that no data provides (geo_site and geoip_country never match them, and
    /// geo_site_not always does).
    /// Empty when nothing is wrong. Kept up to date at startup, on hot reloads and as watched
    /// files change
    pub fn geo_data_warnings(&self) -> Vec<String> {
        let (site, ip) = (self.geo_status.site.lock(), self.geo_status.ip.lock());
        site.sentences()
            .chain(ip.sentences())
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
impl Engine {
    /// 测试用：状态里现在的 Geo 数据 / For tests: the Geo data in the state now
    pub(crate) fn geo(&self) -> GeoManagers {
        self.state.load().geo.clone()
    }

    /// 测试用：不经数据文件，把 `change` 改过的 Geo 数据换进状态 / For tests: the Geo data as
    /// `change` leaves it goes into the state, no data file involved
    pub(crate) fn change_geo(&self, change: impl Fn(&mut GeoManagers)) {
        store(&self.state, change);
    }
}

/// 规则用到、却没有 GeoSite 数据文件提供的标签记一条告警，给出状态里说它们的那句话
/// Logs the tags rules use that no GeoSite data file provides, giving the status's sentence
/// naming them
fn unprovided_geosite_tags(missing: &[String]) -> Option<String> {
    (!missing.is_empty()).then(|| {
        warn!(tags = ?missing, "GeoSite tags used by rules are not in any data file and never match");
        format!(
            "GeoSite tags {} are in no data file: geo_site never matches them and geo_site_not always does",
            missing.join(", ")
        )
    })
}

/// 规则用到、却没有 GeoIP 数据提供的标签记一条告警，给出状态里说它们的那句话
/// Logs the tags rules use that no GeoIP data provides, giving the status's sentence naming them
fn unprovided_geoip_tags(missing: &[String]) -> Option<String> {
    (!missing.is_empty()).then(|| {
        warn!(tags = ?missing, "GeoIP tags used by rules are in no GeoIP data and never match");
        format!(
            "GeoIP tags {} are in no GeoIP data: geoip_country never matches them",
            missing.join(", ")
        )
    })
}

/// `what`（比如 GeoSite data file）`path` 读得出来，却没有一个规则用到的标签了（多半是空文件或写坏了的文件），只有它
/// 提供的 `kept` 这几个留着先前从它读进来的数据：记一条错误，给出状态里说它的那句话。文件下次改好、读进来时这句话跟着
/// 去掉；不说的话，下次重启这几个标签就没有数据，规则不再命中，事先没有一点预兆
/// `what` (GeoSite data file, say) `path` reads, yet has none of the tags rules use any more
/// (most likely an empty or broken file), and the tags `kept`, which it alone provided, keep the
/// data read from it before: logs an error, giving the status's sentence saying so. The
/// sentence goes once the file is put right and read in; unsaid, the next restart would leave
/// those tags without data and their rules no longer matching, with nothing to warn of it
fn kept_from(what: &str, path: &Path, kept: &[String]) -> String {
    error!(what, path = %path.display(), tags = ?kept, "data file now has none of the tags rules use, keeping the data read from it before");
    format!(
        "{what} {} now has none of the tags rules use; the data read from it before stays for {} until it changes again",
        path.display(),
        kept.join(", ")
    )
}

/// 状态里的 Geo 数据从哪来；只在重载锁下使用（见 `Engine::reload_lock`）
/// Where the Geo data in the state came from; used only under the reload lock (see
/// `Engine::reload_lock`)
pub(crate) struct GeoSources {
    geosite: Loaded<GeoSiteSpec>,
    geoip: Loaded<GeoIpSpec>,
    /// 引擎状态，Geo 数据在它里面（见 `EngineInner::geo`）/ The engine state, which holds the Geo
    /// data (see `EngineInner::geo`)
    state: Arc<ArcSwap<EngineInner>>,
    status: Arc<GeoStatus>,
}

impl GeoSources {
    /// 读进配置 `cfg` 用到的 Geo 数据，引擎状态从带着这份数据的 `cfg` 开始，再监视数据文件
    /// Reads in the Geo data the configuration `cfg` uses, the engine state starting as `cfg`
    /// with that data, then watches the data files
    pub(crate) fn load(cfg: RuntimePipelineConfig) -> Self {
        let (geosite, site) = load_geosite(GeoSiteSpec::of(&cfg), &GeoSiteManager::default());
        let (geoip, ip) = load_geoip(GeoIpSpec::of(&cfg), None, &GeoIpManager::default());
        let inner = EngineInner::new(cfg, GeoManagers { geoip, geosite });
        let state = Arc::new(ArcSwap::from_pointee(inner));
        let status = Arc::default();
        Self {
            geosite: site.watch(&GEOSITE, &state, &status),
            geoip: ip.watch(&GEOIP, &state, &status),
            state,
            status,
        }
    }

    /// 引擎状态 / The engine state
    pub(crate) fn state(&self) -> Arc<ArcSwap<EngineInner>> {
        Arc::clone(&self.state)
    }

    /// 两种 Geo 数据眼下的问题，加载和监视都往这里写 / What is wrong with the two kinds of Geo data,
    /// which loading and the watches write to
    pub(crate) fn status(&self) -> Arc<GeoStatus> {
        Arc::clone(&self.status)
    }

    /// 热重载到配置 `cfg`：它要的 Geo 数据和现在的不同时读进新数据，改为监视新的文件。新配置连同它的 Geo 数据和按这份
    /// 数据算的命名空间一次换进状态，新规则从第一个请求起就用新的标签和文件
    /// Hot reload to the configuration `cfg`: when the Geo data it needs differs from the data
    /// loaded, new data is read in and the watches move to the new files. The new configuration
    /// goes into the state at once with its Geo data and the namespaces worked out from that
    /// data, so the new rules find the new tags and files from their first query
    pub(crate) fn follow(&mut self, cfg: RuntimePipelineConfig) {
        let spec = GeoSiteSpec::of(&cfg);
        let (geosite, site) = (self.geosite.spec != spec)
            .then(|| {
                info!(paths = ?spec.paths, tags = spec.tags.len(), "GeoSite data follows the new configuration");
                // 先停下旧的监视并等它结束：它不会再换数据，状态里的就是在用的那份
                // Stop the old watch and wait for it first: it swaps no more data, so the state
                // holds the data in use
                self.geosite.watch = None;
                load_geosite(spec, &self.state.load().geo.geosite)
            })
            .unzip();
        let spec = GeoIpSpec::of(&cfg);
        let (geoip, ip) = (self.geoip.spec != spec)
            .then(|| {
                info!(tags = ?spec.tags, db_path = ?spec.db_path, dat_path = ?spec.dat_path, "GeoIP data follows the new configuration");
                self.geoip.watch = None;
                let in_use = self.geoip.spec.dat_path.as_deref();
                load_geoip(spec, in_use, &self.state.load().geo.geoip)
            })
            .unzip();
        // 没有重新读的那种数据用状态里的：它的监视还在，这时换了数据、存进了新状态，rcu 就重来一遍，带上新的
        // The kind of data not read again is taken from the state: its watch goes on, and when
        // it swaps data and stores a new state meanwhile, rcu starts over and takes it
        let geo = |current: &EngineInner| GeoManagers {
            geoip: Arc::clone(geoip.as_ref().unwrap_or(&current.geo.geoip)),
            geosite: Arc::clone(geosite.as_ref().unwrap_or(&current.geo.geosite)),
        };
        let inner = Arc::new(EngineInner::new(cfg, geo(&self.state.load())));
        self.state.rcu(|current| inner.at_geo(geo(current)));
        if let Some(site) = site {
            self.geosite = site.watch(&GEOSITE, &self.state, &self.status);
        }
        if let Some(ip) = ip {
            self.geoip = ip.watch(&GEOIP, &self.state, &self.status);
        }
    }
}

/// 状态换成 Geo 数据由 `change` 改过、命名空间按改过的数据算的那份。同时有配置重载存了新状态时 rcu 重来一遍，改在新
/// 状态上，不会把它盖回去
/// The state moves to one whose Geo data `change` changed, with the namespaces worked out from
/// the changed data. When a configuration reload stores a new state meanwhile, rcu starts over
/// and changes that one, instead of overwriting it
fn store(state: &ArcSwap<EngineInner>, change: impl Fn(&mut GeoManagers)) {
    state.rcu(|current| {
        let mut geo = current.geo.clone();
        change(&mut geo);
        current.at_geo(geo)
    });
}

/// 一种 Geo 数据的监视：它的文件（全部和一个）在日志里怎么叫、监视线程叫什么、问题写进状态的哪一格
/// The watch of one kind of Geo data: what the log calls its files (all of them, and one),
/// what the watch thread is called, and which part of the status takes its problems
struct Kind {
    files: &'static str,
    file: &'static str,
    thread: &'static str,
    status: fn(&GeoStatus) -> &Mutex<DataStatus>,
}

const GEOSITE: Kind = Kind {
    files: "GeoSite data files",
    file: "GeoSite data file",
    thread: "geosite-watch",
    status: |status| &status.site,
};

const GEOIP: Kind = Kind {
    files: "GeoIP data files",
    file: "GeoIP data file",
    thread: "geoip-watch",
    status: |status| &status.ip,
};

/// 监视到一个文件变了时怎么读：参数是状态、配置里写的路径和这种数据的问题 / How a file is read once
/// the watch sees it change: given the state, the path as configured and this kind of data's problems
type Reload = Box<dyn Fn(&ArcSwap<EngineInner>, &Path, &Mutex<DataStatus>) + Send>;

/// 按一份 spec 读好、还没换进状态的数据的监视和问题 / The watch and the problems of data read for a
/// spec, not in the state yet
struct Pending<S> {
    spec: S,
    /// 装好、还没起线程的监视 / The watch installed, its thread not started yet
    watch: Option<PendingWatch>,
    /// 监视着的 MMDB，GeoSite 没有（见 [`named`]）/ The MMDB watched, none for GeoSite (see [`named`])
    mmdb: Option<PathBuf>,
    reload: Reload,
    problems: DataStatus,
}

/// 状态里怎么叫 `path`：`mmdb` 是 GeoIP database，别的是 `file`（比如 GeoSite data file）/ What the status
/// calls `path`: a GeoIP database when it is `mmdb`, `file` otherwise (GeoSite data file, say)
fn named(file: &'static str, mmdb: Option<&Path>, path: &Path) -> &'static str {
    if mmdb == Some(path) {
        "GeoIP database"
    } else {
        file
    }
}

impl<S> Pending<S> {
    /// 数据换进状态以后开始监视：监视线程读到的在用数据就是这份。问题在监视开始之前写好，监视线程之后写进来的不会被它
    /// 盖掉
    /// Starts watching once the data is in the state, so the watch thread finds this data in
    /// use. The problems are written before the watch starts, so what the watch thread writes
    /// later is not overwritten by them
    fn watch(
        self,
        kind: &Kind,
        state: &Arc<ArcSwap<EngineInner>>,
        status: &Arc<GeoStatus>,
    ) -> Loaded<S> {
        *(kind.status)(status).lock() = self.problems;
        let (reload, of, file, mmdb) = (self.reload, kind.status, kind.file, self.mmdb);
        let state = Arc::clone(state);
        let (changed, watching) = (Arc::clone(status), Arc::clone(status));
        let watch = start_watch(
            self.watch,
            kind.files,
            kind.thread,
            of(status),
            move |path| reload(&state, path, of(&changed)),
            move |path, err| {
                let what = named(file, mmdb.as_deref(), path);
                of(&watching).lock().watched(what, path, err);
            },
        );
        Loaded {
            spec: self.spec,
            watch,
        }
    }
}

/// 装好的监视里有位置监视不上的文件，写进 `problems`（见 [`DataStatus::watched`]）；`mmdb` 见 [`named`]
/// The files of the watch installed with places that cannot be watched go to `problems` (see
/// [`DataStatus::watched`]); for `mmdb` see [`named`]
fn note_uncovered(
    kind: &Kind,
    watch: Option<&PendingWatch>,
    mmdb: Option<&Path>,
    problems: &mut DataStatus,
) {
    for (path, err) in watch.into_iter().flat_map(PendingWatch::uncovered) {
        problems.watched(named(kind.file, mmdb, path), path, Some(err));
    }
}

/// 起线程处理监视到的变化，文件每次改了指向以后监视得怎样交给 `on_watch`（见 [`PendingWatch::start_reporting`]）；
/// 起不了线程就记一条错误，写进 `status`
/// Starts the thread that handles watched changes, how a file is watched each time it is
/// resolved again going to `on_watch` (see [`PendingWatch::start_reporting`]); when it cannot
/// start an error is logged and written to `status`
fn start_watch(
    pending: Option<PendingWatch>,
    what: &str,
    name: &str,
    status: &Mutex<DataStatus>,
    on_change: impl FnMut(&Path) + Send + 'static,
    on_watch: impl FnMut(&Path, Option<&notify::Error>) + Send + 'static,
) -> Option<FileWatch> {
    pending?
        .start_reporting(name, on_change, on_watch)
        .inspect_err(|err| {
            error!(name, error = %err, "cannot start the data file watcher, changes to the files are read after a restart or a reload changing which files are read");
            status.lock().not_watched(what, err);
        })
        .ok()
}

/// 建好 `spec` 的 GeoSite 数据，监视等数据换进状态以后再开始（见 [`Pending::watch`]）。`in_use` 是正在用的数据；读的
/// 时候出的问题记在给回的 [`Pending`] 里
/// Builds `spec`'s GeoSite data, the watch waiting until the data is in the state (see
/// [`Pending::watch`]). `in_use` is the data in use; what goes wrong reading is noted in the
/// [`Pending`] given back
fn load_geosite(
    spec: GeoSiteSpec,
    in_use: &GeoSiteManager,
) -> (Arc<GeoSiteManager>, Pending<GeoSiteSpec>) {
    // 数据文件只读规则用到的标签，一个都没用到就不必读，也不必监视
    // A data file is read only for the tags rules use; with none used it is neither read nor
    // watched
    let files: Vec<PathBuf> = if spec.tags.is_empty() {
        if !spec.paths.is_empty() {
            info!(paths = ?spec.paths, "No GeoSite tags used in config, skipping GeoSite data loading");
        }
        Vec::new()
    } else {
        spec.paths.iter().map(PathBuf::from).collect()
    };
    let mut problems = DataStatus::default();
    // 读之前先监视。不在的文件也监视：所在的目录在，出现时就看得见；目录也不在（或者经悬空的符号链接），就和别的有位置
    // 监视不上的文件一样，由监视的核对接上（见 `note_uncovered`），链接换了指向照样看得见
    // Watched before they are read. A file not there is watched too: with its directory there
    // it is seen once created; with its directory not there either (or behind a dangling
    // symlink) it is caught up with by the watch's checks, as any other file with places that
    // cannot be watched (see `note_uncovered`), and a link along the way pointing elsewhere is
    // still seen
    let watch = (!files.is_empty()).then(|| PendingWatch::new(&files));
    note_uncovered(&GEOSITE, watch.as_ref(), None, &mut problems);
    let mut fresh = GeoSiteManager::default();
    // 读出来没有一个规则用到的标签的文件（读不了的也算）/ The files whose read gave none of the
    // tags rules use (unreadable ones included)
    let mut gave_nothing = Vec::new();
    for path in &files {
        // 解析失败的文件照样监视：写了一半或被截断的文件在下次写完时能自己恢复，不必重启进程
        // A file that failed to parse is watched all the same: a half-written or truncated
        // file heals itself on the next write instead of needing a restart
        let parsed = if path.exists() {
            let parsed = match GeoSiteManager::parse_file(path, &spec.tags) {
                Ok(parsed) => {
                    info!(path = %path.display(), loaded_count = parsed.len(), used_tags = spec.tags.len(), "loaded GeoSite data from file");
                    parsed
                }
                Err(err) => {
                    error!(path = %path.display(), error = %format!("{err:#}"), "failed to load GeoSite data, waiting for the file to change");
                    problems.not_read("GeoSite data file", path, &err);
                    Vec::new()
                }
            };
            if !parsed_provides_any(&parsed, &spec.tags) {
                gave_nothing.push(path);
            }
            parsed
        } else {
            error!(path = %path.display(), "GeoSite data file not found");
            problems.missing("GeoSite data file", path);
            Vec::new()
        };
        // 每个文件在文件里的先后都记下，不在的、读不了的也算（几个文件声明同一个标签时排在后面的说了算），它们之后读进来
        // 的数据照样排在这里
        // Every file's place among the files is recorded, those not there or unreadable
        // included (of files declaring one tag the later decides), so what is read from them
        // later still ranks there
        fresh.apply_source(path, parsed);
    }
    // 和监视到文件变了时一样（见 `reload_geosite_file`）：这份文件此前提供着规则现在还用的标签，重新读出来却一个都没有，
    // 多半是空文件或写坏了的文件。其中别的文件都不提供的标签留着正在用的数据，等文件下次改动；别的文件也提供的用那个
    // 文件的，和全部重新读一遍一样
    // As when a watched file changes (see `reload_geosite_file`): the file provided tags the
    // rules still use, yet reading it again gives none of them, most likely an empty or broken
    // file. Those of them no other file provides keep the data in use until the file changes
    // again; those another file provides too take that file's, as a full load would have them
    let unprovided = fresh.missing_tags(&spec.tags);
    for path in gave_nothing {
        let kept = in_use.decided_by(path, &unprovided);
        if kept.is_empty() {
            continue;
        }
        let tags: Vec<String> = kept.iter().map(|(tag, _)| tag.clone()).collect();
        // 这份文件在 `fresh` 里什么都没提供，没有要交出去的标签 / The file provides nothing in
        // `fresh`, so there are no tags to hand over
        fresh.swap_source(path, kept, Vec::new(), false);
        // 读不了的文件已经有一句说它读不了 / An unreadable file has a sentence saying so already
        if !problems.has(path) {
            let said = kept_from("GeoSite data file", path, &tags);
            problems.file(path, said);
        }
    }
    // 没有要读的文件时不算，配置的告警已经说了（见 `config::geo_tags_without_data`）/ Not with no
    // file to read: the configuration's warnings say so already (see `config::geo_tags_without_data`)
    problems.tags = (!files.is_empty())
        .then(|| unprovided_geosite_tags(&fresh.missing_tags(&spec.tags)))
        .flatten();
    let tags = spec.tags.clone();
    let pending = Pending {
        spec,
        watch,
        mmdb: None,
        reload: Box::new(move |state, path, status| {
            reload_geosite_file(state, path, &tags, status);
        }),
        problems,
    };
    (Arc::new(fresh), pending)
}

/// 监视到 GeoSite 数据文件 `path` 变了：只替换它贡献的标签，其它文件贡献的标签不动（见
/// [`GeoSiteManager::apply_source`]）。新数据建在在用那份的克隆上（各个标签的匹配器共用，只复制表），建好再换进状态
/// `state`；建的这段时间里请求照常按在用的那份判断。监视线程是唯一换 GeoSite 数据的（热重载先停下监视再换数据），
/// 所以开始时拿到的在用数据到换进去时仍是在用的那份。读得了、读不了都写进 `status`
/// A watched GeoSite data file `path` changed: only the tags it contributes are replaced,
/// leaving other files' tags alone (see [`GeoSiteManager::apply_source`]). The new data is
/// built on a clone of the data in use (the tags' matchers shared, the tables alone copied)
/// and swapped into the state `state` once built; requests go on judging by the data in use
/// meanwhile. The watch thread is the only one swapping GeoSite data (a hot reload stops the
/// watch before swapping data), so the data in use taken at the start is still the data in
/// use at the swap. Whether it could be read or not goes to `status`
fn reload_geosite_file(
    state: &ArcSwap<EngineInner>,
    path: &Path,
    tags: &[String],
    status: &Mutex<DataStatus>,
) {
    let parsed = match GeoSiteManager::parse_file(path, tags) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!(path = %path.display(), error = %format!("{err:#}"), "GeoSite data reload failed, keeping the data in use");
            status.lock().not_read("GeoSite data file", path, &err);
            return;
        }
    };
    status.lock().read(path);
    // 新读出来一个规则用到的标签都没有：多半是空文件或写坏了的文件（下载失败、磁盘写满）。只有它提供的标签换掉会让用
    // 它们的规则一下子全不命中，所以留着正在用的数据，等文件下次改动，状态里也说一句；别的文件也提供的标签照常交给那个
    // 文件，和全部重新读一遍一样。没有要交出去的标签时什么都不变
    // The new read has none of the tags rules use: most likely an empty or broken file (a
    // failed download, a full disk). Dropping the tags only it provides would stop the rules
    // using them matching at once, so they keep the data in use until the file changes again,
    // and the status says so; the tags another file provides too go over to that file as
    // usual, as a full load would have it. With none to hand over nothing changes
    let gives_none = !parsed_provides_any(&parsed, tags);
    let in_use = Arc::clone(&state.load().geo.geosite);
    if gives_none {
        let kept = in_use.provided_only_by(path);
        if !kept.is_empty() {
            let said = kept_from("GeoSite data file", path, &kept);
            status.lock().file(path, said);
        }
    }
    let handovers = in_use.handovers(path, &parsed);
    if gives_none && handovers.is_empty() {
        return;
    }
    let handed_over = GeoSiteManager::read_handovers(handovers);
    let mut fresh = GeoSiteManager::clone(&in_use);
    let count = fresh.swap_source(path, parsed, handed_over, gives_none);
    let missing = fresh.missing_tags(tags);
    let fresh = Arc::new(fresh);
    store(state, |geo| geo.geosite = Arc::clone(&fresh));
    info!(path = %path.display(), loaded_count = count, "GeoSite data reloaded");
    status.lock().tags = unprovided_geosite_tags(&missing);
}

/// 建好 `spec` 的 GeoIP 数据，监视等数据换进状态以后再开始（见 [`Pending::watch`]）。`in_use` 是正在用的数据，
/// `in_use_file` 是它读自哪个数据文件（启动时还没有）；读的时候出的问题记在给回的 [`Pending`] 里
/// Builds `spec`'s GeoIP data, the watch waiting until the data is in the state (see
/// [`Pending::watch`]). `in_use` is the data in use and `in_use_file` the data file it was read
/// from (none yet at startup); what goes wrong reading is noted in the [`Pending`] given back
fn load_geoip(
    spec: GeoIpSpec,
    in_use_file: Option<&str>,
    in_use: &GeoIpManager,
) -> (Arc<GeoIpManager>, Pending<GeoIpSpec>) {
    let mut problems = DataStatus::default();
    let mut fresh = GeoIpManager::default();
    // MMDB 和数据文件一样先装监视再读。数据文件要不要读、读哪些标签，读完 MMDB 才知道（见下面），那时再加进监视，也在读
    // 它之前
    // The MMDB, like the data file, is watched before it is read. Whether the data file is
    // read, and for which tags, is known only once the MMDB is read (see below), and it joins
    // the watch then, still before it is read
    let mmdb = spec.db_path.as_ref().map(PathBuf::from);
    let mut watch = (spec.db_path.is_some() || spec.dat_path.is_some())
        .then(|| PendingWatch::new(mmdb.as_slice()));
    if let Some(db) = &mmdb
        && let Err(err) = fresh.use_mmdb(db, in_use)
    {
        error!(geoip_db = %db.display(), error = %format!("{err:#}"), keeping_the_one_in_use = fresh.has_mmdb(), "failed to open GeoIP database, waiting for the file to change");
        problems.not_read("GeoIP database", db, &err);
    }

    // MMDB 加载上了，国家代码就只查它（见 GeoIpManager::matches_any_tag），数据文件只读其余的标签
    // With an MMDB loaded country codes are looked up there alone (see
    // GeoIpManager::matches_any_tag), so the data file is read only for the other tags
    let dat_tags: Vec<String> = spec
        .tags
        .iter()
        .filter(|tag| !(fresh.has_mmdb() && is_country_tag(tag)))
        .cloned()
        .collect();
    let mut files = Vec::new();
    if let Some(dat_path) = &spec.dat_path {
        if dat_tags.is_empty() {
            info!(path = %dat_path, "every GeoIP tag rules use is a country code the GeoIP database answers, skipping the GeoIP data file");
        } else {
            files.push(PathBuf::from(dat_path));
        }
    }
    if let Some(pending) = &mut watch {
        pending.add(&files);
    }
    note_uncovered(&GEOIP, watch.as_ref(), mmdb.as_deref(), &mut problems);
    // 读出来没有一个规则用到的标签的数据文件（读不了的也算）/ The data file if its read gave none of
    // the tags rules use (an unreadable one included)
    let mut gave_nothing = None;
    for path in &files {
        if !path.exists() {
            error!(path = %path.display(), "GeoIP data file not found");
            problems.missing("GeoIP data file", path);
            continue;
        }
        // 解析失败的文件和 GeoSite 一样照样监视 / A file that failed to parse is watched, as for GeoSite
        match GeoIpManager::parse_file(path, &dat_tags) {
            Ok(parsed) => {
                if parsed.tag_count() == 0 {
                    gave_nothing = Some(path);
                }
                let count = fresh.apply_parsed(parsed);
                info!(path = %path.display(), loaded_count = count, used_tags = dat_tags.len(), "loaded GeoIP data from file");
            }
            Err(err) => {
                error!(path = %path.display(), error = %format!("{err:#}"), "failed to load GeoIP data, waiting for the file to change");
                problems.not_read("GeoIP data file", path, &err);
                gave_nothing = Some(path);
            }
        }
    }
    // 和监视到文件变了时一样（见 `reload_geoip_file`）：还是正在用的那份数据文件，重新读出来却没有一个规则用到的标签，
    // 多半是空文件或写坏了的文件。规则现在还用的标签留着正在用的数据，等文件下次改动
    // As when a watched file changes (see `reload_geoip_file`): the data file is the one the
    // data in use came from, yet reading it again gives none of the tags rules use, most
    // likely an empty or broken file. The tags the rules still use keep the data in use until
    // the file changes again
    if let Some(path) =
        gave_nothing.filter(|path| in_use_file.is_some_and(|in_use| Path::new(in_use) == *path))
    {
        let kept = fresh.keep_tags_of(in_use, &dat_tags);
        // 读不了的文件已经有一句说它读不了 / An unreadable file has a sentence saying so already
        if !kept.is_empty() && !problems.has(path) {
            let said = kept_from("GeoIP data file", path, &kept);
            problems.file(path, said);
        }
    }
    let dat_given = spec.dat_path.is_some();
    let missing = missing_geoip_tags(&fresh, &spec.tags, dat_given, mmdb.is_some());
    problems.tags = unprovided_geoip_tags(&missing);
    let (tags, database) = (spec.tags.clone(), mmdb.clone());
    let pending = Pending {
        spec,
        watch,
        mmdb,
        reload: Box::new(move |state, path, status| {
            if database.as_deref() == Some(path) {
                reload_mmdb(state, path, &tags, dat_given, status);
            } else {
                reload_geoip_file(state, path, &dat_tags, status);
            }
        }),
        problems,
    };
    (Arc::new(fresh), pending)
}

/// 规则用到的 `tags` 里 `fresh` 答不了的。配置里没给数据的不算（`dat_given`：配了数据文件，`mmdb_given`：配了
/// MMDB），配置的告警已经说了（见 `config::geo_tags_without_data`）
/// Those of the `tags` rules use that `fresh` cannot answer. Tags the configuration gives no
/// data for do not count (`dat_given`: a data file is configured, `mmdb_given`: an MMDB is), its
/// warnings saying so already (see `config::geo_tags_without_data`)
fn missing_geoip_tags(
    fresh: &GeoIpManager,
    tags: &[String],
    dat_given: bool,
    mmdb_given: bool,
) -> Vec<String> {
    fresh
        .missing_tags(tags)
        .into_iter()
        .filter(|tag| dat_given || (mmdb_given && is_country_tag(tag)))
        .collect()
}

/// 监视到 MMDB `path` 变了：重新读进来，和在用的标签一起装进新的管理器（见 [`GeoIpManager::with_mmdb`]：不看文件的
/// 样子，按内容比），建好再换进状态 `state`，建的这段时间里请求照常按在用的那份判断；内容没变时什么都不换。读不了（正在
/// 替换、写坏了、删掉了）时留着在用的那份，写进 `status`，等文件下次改动。`tags` 是规则用到的 GeoIP 标签，`dat_given`
/// 说配置里有没有数据文件，算没有数据提供的标签用（见 [`missing_geoip_tags`]）。监视线程是唯一换 GeoIP 数据的（热重载先
/// 停下监视再换数据），所以开始时拿到的在用数据到换进去时仍是在用的那份
/// A watched MMDB `path` changed: it is read in again, into a new manager with the tags in use
/// (see [`GeoIpManager::with_mmdb`]: by the content, not by what the file looks like), swapped
/// into the state `state` once built, requests going on judging by the data in use meanwhile;
/// with the content unchanged nothing is swapped. When it cannot be read (being replaced,
/// broken, removed) the one in use stays, `status` is told, and the file's next change is
/// waited for. `tags` are the GeoIP tags rules use and `dat_given` whether a data file is
/// configured, for the tags no data provides (see [`missing_geoip_tags`]). The watch thread is
/// the only one swapping GeoIP data (a hot reload stops the watch before swapping data), so the
/// data in use taken at the start is still the data in use at the swap
fn reload_mmdb(
    state: &ArcSwap<EngineInner>,
    path: &Path,
    tags: &[String],
    dat_given: bool,
    status: &Mutex<DataStatus>,
) {
    let in_use = Arc::clone(&state.load().geo.geoip);
    let fresh = match in_use.with_mmdb(path) {
        Ok(fresh) => fresh,
        Err(err) => {
            error!(geoip_db = %path.display(), error = %format!("{err:#}"), "GeoIP database reload failed, keeping the one in use");
            status.lock().not_read("GeoIP database", path, &err);
            return;
        }
    };
    status.lock().read(path);
    let Some(fresh) = fresh else {
        return;
    };
    let missing = missing_geoip_tags(&fresh, tags, dat_given, true);
    let fresh = Arc::new(fresh);
    store(state, |geo| geo.geoip = Arc::clone(&fresh));
    info!(geoip_db = %path.display(), "GeoIP database reloaded");
    status.lock().tags = unprovided_geoip_tags(&missing);
}

/// 监视到 GeoIP 数据文件 `path` 变了：读取、解码、建索引装进一个和在用的共用 MMDB 的新管理器，建好再换进状态
/// `state`，建的这段时间里请求照常按在用的那份判断。监视线程是唯一换 GeoIP 数据的（热重载先停下监视再换数据），所以
/// 开始时拿到的 MMDB 到换进去时仍是在用的那份。读得了、读不了都写进 `status`
/// A watched GeoIP data file `path` changed: it is read, decoded and indexed into a new manager
/// sharing the MMDB in use, swapped into the state `state` once built, requests going on
/// judging by the data in use meanwhile. The watch thread is the only one swapping GeoIP data
/// (a hot reload stops the watch before swapping data), so the MMDB taken at the start is
/// still the one in use at the swap. Whether it could be read or not goes to `status`
fn reload_geoip_file(
    state: &ArcSwap<EngineInner>,
    path: &Path,
    tags: &[String],
    status: &Mutex<DataStatus>,
) {
    let parsed = match GeoIpManager::parse_file(path, tags) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!(path = %path.display(), error = %format!("{err:#}"), "GeoIP data reload failed, keeping the data in use");
            status.lock().not_read("GeoIP data file", path, &err);
            return;
        }
    };
    status.lock().read(path);
    let in_use = Arc::clone(&state.load().geo.geoip);
    // 和 GeoSite 一样：规则用到的标签这份文件此前给着、现在一个都没有了，多半是文件坏了，
    // 留着正在用的数据，状态里说一句 / As for GeoSite: the file gave tags rules use until now
    // and has none of them any more, most likely a broken file, so the data in use stays, and
    // the status says so
    if parsed.tag_count() == 0 {
        let kept = in_use.tags();
        if !kept.is_empty() {
            let said = kept_from("GeoIP data file", path, &kept);
            status.lock().file(path, said);
            return;
        }
    }
    let mut fresh = in_use.sharing_mmdb();
    let count = fresh.apply_parsed(parsed);
    let missing = fresh.missing_tags(tags);
    let fresh = Arc::new(fresh);
    store(state, |geo| geo.geoip = Arc::clone(&fresh));
    info!(path = %path.display(), loaded_count = count, "GeoIP data reloaded");
    status.lock().tags = unprovided_geoip_tags(&missing);
}
