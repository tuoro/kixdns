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
use crate::watcher::{FileStamp, FileWatch, PendingWatch};
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

/// 按一份 spec 加载的数据从哪来、谁在监视 / Where the data loaded for a spec came from, and what watches it
struct Loaded<S> {
    spec: S,
    /// 监视以外的文件，各带读它之前它什么样：MMDB（读不了时照样算），监视装不上、起不来时还有全部数据文件。监视着、
    /// 却有位置监视不上的文件（比如所在的目录不在）记在状态里（见 [`DataStatus::watched`]）
    /// The files outside the watch, each with what it looked like before it was read: the MMDB
    /// (one that could not be read included), and every data file when the watch could not be
    /// installed or started. The files watched, yet with places that cannot be (their directory
    /// not there, say), are kept in the status (see [`DataStatus::watched`])
    unwatched: Vec<Stamped>,
    watch: Option<FileWatch>,
}

impl<S: PartialEq> Loaded<S> {
    /// 按 `spec` 加载的数据是否就是现在这份：监视看不全的文件（监视以外的，和 `status` 里有位置监视不上的）有哪个换了
    /// 样子就不是；都还是那个样子时，存在却读不了的也一样，读出来的数据不会不同
    /// Whether loading for `spec` would give the data already loaded: not once any file the
    /// watch does not wholly see (those outside it, and those in `status` with places it cannot
    /// watch) looks otherwise; while each looks the same, one there yet unreadable included,
    /// reading again would give the same data
    fn is_current(&self, spec: &S, status: &Mutex<DataStatus>) -> bool {
        self.spec == *spec
            && self.unwatched.iter().all(Stamped::unchanged)
            && status
                .lock()
                .partly_watched
                .iter()
                .all(|(file, _)| file.unchanged())
    }
}

/// 一个文件，和读它之前它什么样（不存在时是 None）/ A file, and what it looked like before it was
/// read (None when it was missing)
struct Stamped {
    path: PathBuf,
    seen: Option<FileStamp>,
}

impl Stamped {
    /// `path` 现在的样子，在读它之前看：读的时候换了，下次热重载照样看得出来 / What `path` looks like
    /// now, looked at before it is read: one replaced meanwhile is still noticed by the next hot reload
    fn now(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let seen = FileStamp::of(&path).ok();
        Self { path, seen }
    }

    fn unchanged(&self) -> bool {
        FileStamp::of(&self.path).ok() == self.seen
    }
}

impl AsRef<Path> for Stamped {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

/// 两种 Geo 数据眼下的问题：配置了却不存在或读不了的文件、读得出来却没有规则用到的标签了的文件（留着先前读进来的数据）、
/// 装不上的监视和有位置监视不上的文件、规则用到却没有数据提供的标签。启动、热重载和监视到文件变了时跟着更新，面板经控制
/// 通道读（见 [`Engine::geo_data_warnings`]）
/// What is wrong with the two kinds of Geo data right now: configured files that are missing
/// or cannot be read, files that read yet have none of the tags rules use any more (the data
/// read from them before staying), watches that cannot be installed and files with places
/// that cannot be watched, and tags rules use that no data provides. Kept up to date at
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
    /// 监视装不上时说它的那句话 / The sentence saying the watch could not be installed, when it could not
    watch: Option<String>,
    /// 监视着、却有位置监视不上的文件（监视看不到那里的变化），各带读它之前它什么样和说它的那句话；热重载时有哪个换了样子
    /// 就重新加载（见 [`Loaded::is_current`]）
    /// The files watched, yet with places that cannot be (the watch not seeing changes there),
    /// each with what it looked like before it was read and the sentence saying so; a hot reload
    /// loads again once any of them looks otherwise (see [`Loaded::is_current`])
    partly_watched: Vec<(Stamped, String)>,
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

    /// `what` 的监视因为 `err` 装不上：没有一个文件监视着，都在监视以外（见 `Loaded::unwatched`）
    /// The watch on `what` could not be installed because of `err`: no file is watched, every
    /// one being outside the watch (see `Loaded::unwatched`)
    fn not_watched(&mut self, what: &str, err: &dyn std::fmt::Display) {
        self.watch = Some(format!(
            "{what} cannot be watched for changes, which are read at the next configuration reload: {err}"
        ));
        self.partly_watched.clear();
    }

    /// 监视着的 `what` `path` 有位置因为 `err` 监视不上（见 `PendingWatch::uncovered`、
    /// `PendingWatch::start_reporting`）；是 None 时都监视上了。监视不全的文件记下它现在的样子，所以要在读它之前调用：
    /// 那里的变化由下一次热重载读
    /// Watched `what` `path` has places that cannot be watched because of `err` (see
    /// `PendingWatch::uncovered`, `PendingWatch::start_reporting`); None when every place is
    /// watched. A file not wholly watched is noted as it looks now, so call this before it is
    /// read: changes there are read by the next hot reload
    fn watched(&mut self, what: &str, path: &Path, err: Option<&notify::Error>) {
        match err {
            Some(err) => {
                let said = format!(
                    "{what} {} cannot be watched everywhere it leads, changes there are read at the next configuration reload: {err}",
                    path.display()
                );
                say(&mut self.partly_watched, (Stamped::now(path), said));
            }
            None => self.partly_watched.retain(|(file, _)| file.path != path),
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
    /// 标签留着先前读进来的数据，重启以后就没有了）、装不上的文件监视、有位置监视不上的文件、规则用到却没有数据提供的标签
    /// （这样的规则 geo_site、geoip_country 永不命中，geo_site_not 总命中）。没有问题时是空的。启动、热重载和监视到文件
    /// 变了时跟着更新
    /// What is wrong with the Geo data right now, a sentence each: configured files that are
    /// missing or cannot be read, files that read yet have none of the tags rules use any more
    /// (the tags only they provide keeping the data read from them before, gone after a
    /// restart), file watches that cannot be installed, files with places that cannot be
    /// watched, and tags rules use that no data provides (geo_site and geoip_country never match
    /// them, and geo_site_not always does).
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
        let (geosite, site) = (!self.geosite.is_current(&spec, &self.status.site))
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
        let (geoip, ip) = (!self.geoip.is_current(&spec, &self.status.ip))
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

/// 一种 Geo 数据的监视：它的文件（全部和一个）在日志里怎么叫、监视线程叫什么、问题写进状态的哪一格、监视到文件变了
/// 怎么读
/// The watch of one kind of Geo data: what the log calls its files (all of them, and one),
/// what the watch thread is called, which part of the status takes its problems, and how a
/// changed file is read
struct Kind {
    files: &'static str,
    file: &'static str,
    thread: &'static str,
    status: fn(&GeoStatus) -> &Mutex<DataStatus>,
    reload: fn(&ArcSwap<EngineInner>, &Path, &[String], &Mutex<DataStatus>),
}

const GEOSITE: Kind = Kind {
    files: "GeoSite data files",
    file: "GeoSite data file",
    thread: "geosite-watch",
    status: |status| &status.site,
    reload: reload_geosite_file,
};

const GEOIP: Kind = Kind {
    files: "GeoIP data file",
    file: "GeoIP data file",
    thread: "geoip-watch",
    status: |status| &status.ip,
    reload: reload_geoip_file,
};

/// 按一份 spec 读好、还没换进状态的数据的监视和问题 / The watch and the problems of data read for a
/// spec, not in the state yet
struct Pending<S> {
    spec: S,
    /// 监视到文件变了时读的标签 / The tags read when a watched file changes
    tags: Vec<String>,
    /// 读之前看过的 MMDB（见 [`Stamped::now`]），它不被监视 / The MMDB as looked at before reading
    /// (see [`Stamped::now`]), which is not watched
    mmdb: Option<Stamped>,
    /// 读之前看过的数据文件，都交给了监视 / The data files as looked at before reading, every one
    /// handed to the watch
    files: Vec<Stamped>,
    /// 装好、还没起线程的监视 / The watch installed, its thread not started yet
    watch: Option<PendingWatch>,
    problems: DataStatus,
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
        let (reload, of, file) = (kind.reload, kind.status, kind.file);
        let (state, tags) = (Arc::clone(state), self.tags);
        let (changed, watching) = (Arc::clone(status), Arc::clone(status));
        let watch = start_watch(
            self.watch,
            kind.files,
            kind.thread,
            of(status),
            move |path| reload(&state, path, &tags, of(&changed)),
            move |path, err| of(&watching).lock().watched(file, path, err),
        );
        // 监视起不来时数据文件也都在监视以外 / Without the watch running the data files are outside it too
        let files = if watch.is_some() {
            Vec::new()
        } else {
            self.files
        };
        Loaded {
            spec: self.spec,
            unwatched: self.mmdb.into_iter().chain(files).collect(),
            watch,
        }
    }
}

/// 开始监视 `files`，在读它们之前调用。不在的文件也监视：所在的目录在，出现时就看得见；目录也不在（或者经悬空的符号
/// 链接），就和别的有位置监视不上的文件一样写进 `problems`（见 [`DataStatus::watched`]），那里的变化由下一次热重载读，
/// 链接换了指向照样看得见。装不上时记一条错误、写进 `problems`，数据照样加载
/// Starts watching `files`; call it before reading them. A file not there is watched too:
/// with its directory there it is seen once created; with its directory not there either (or
/// behind a dangling symlink) it goes to `problems` as any other file with places that cannot
/// be watched (see [`DataStatus::watched`]), changes there being read by the next hot reload,
/// and a link along the way pointing elsewhere is still seen. When the watch cannot be
/// installed an error is logged and written to `problems`, and the data is loaded all the same
fn pending_watch(
    kind: &Kind,
    files: &[PathBuf],
    problems: &mut DataStatus,
) -> Option<PendingWatch> {
    if files.is_empty() {
        return None;
    }
    match PendingWatch::new(files) {
        Ok(pending) => {
            for (path, err) in pending.uncovered() {
                problems.watched(kind.file, path, Some(err));
            }
            Some(pending)
        }
        Err(err) => {
            error!(what = kind.files, error = %err, "cannot watch data files for changes, they are read again at the next configuration reload");
            problems.not_watched(kind.files, &err);
            None
        }
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
            error!(name, error = %err, "cannot start the data file watcher, the files are read again at the next configuration reload");
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
    let seen = files.iter().map(Stamped::now).collect();
    let watch = pending_watch(&GEOSITE, &files, &mut problems);
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
        tags,
        mmdb: None,
        files: seen,
        watch,
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
    // MMDB 不被监视，换了样子由热重载读（见 `Loaded::unwatched`）/ The MMDB is not watched, a hot
    // reload reading it once it looks otherwise (see `Loaded::unwatched`)
    let mmdb = spec.db_path.as_ref().map(Stamped::now);
    if let Some(db_path) = &spec.db_path
        && let Err(err) = fresh.use_mmdb(db_path, in_use)
    {
        error!(geoip_db = %db_path, error = %format!("{err:#}"), keeping_the_one_in_use = fresh.has_mmdb(), "failed to open GeoIP database, read again by the next configuration reload once it changes");
        problems.not_read("GeoIP database", Path::new(db_path), &err);
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
    let seen = files.iter().map(Stamped::now).collect();
    let watch = pending_watch(&GEOIP, &files, &mut problems);
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
    // 配置里没给数据的标签不算，配置的告警已经说了（见 `config::geo_tags_without_data`）/ Tags the
    // configuration gives no data for do not count: its warnings say so already (see
    // `config::geo_tags_without_data`)
    let given_data =
        |tag: &String| spec.dat_path.is_some() || (spec.db_path.is_some() && is_country_tag(tag));
    let missing_tags: Vec<String> = fresh
        .missing_tags(&spec.tags)
        .into_iter()
        .filter(given_data)
        .collect();
    problems.tags = unprovided_geoip_tags(&missing_tags);
    let pending = Pending {
        spec,
        tags: dat_tags,
        mmdb,
        files: seen,
        watch,
        problems,
    };
    (Arc::new(fresh), pending)
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
