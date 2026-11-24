//! 配置用到的 Geo 数据：启动和热重载按同一套规则加载，热重载时只有配置里决定加载什么的部分
//! 变了才重新加载，同时改为监视新的文件。
//! The Geo data a configuration uses: startup and hot reload load it by the same rules, and a
//! hot reload loads it again, and moves the file watches to the new files, only when the part
//! of the configuration that decides what is loaded changed.

use std::mem;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use tracing::{error, info, warn};

use super::Engine;
use super::types::EngineInner;
use super::utils::{extract_geoip_tags_from_config, extract_geosite_tags_from_config};
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::geoip::{FileStamp, GeoIpManager, is_country_tag};
use crate::matcher::geosite::{GeoSiteManager, Swapped, parsed_provides_any};
use crate::watcher::{FileWatch, PendingWatch};
use parking_lot::{Mutex, RwLock};

/// 配置里决定加载哪些 GeoSite 数据的部分 / The part of a configuration that decides which GeoSite data is loaded
#[derive(Debug, PartialEq, Eq)]
struct GeoSiteSpec {
    paths: Vec<String>,
    /// 规则用到的标签，排好序以便比较 / The tags rules use, sorted so specs compare
    tags: Vec<String>,
}

impl GeoSiteSpec {
    fn of(cfg: &RuntimePipelineConfig) -> Self {
        let mut tags = extract_geosite_tags_from_config(cfg);
        tags.sort_unstable();
        Self {
            paths: cfg.settings.geosite_data_paths.clone(),
            tags,
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
        let tags = extract_geoip_tags_from_config(cfg);
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
    /// 加载时看过、没有监视的文件：MMDB（读不了时照样算），所在目录也不在的数据文件，监视装不上时还有全部数据文件。
    /// 再次热重载时有哪个换了样子就重新加载；还是那个样子的，存在却读不了的也一样，读出来的数据不会不同，就不重新加载
    /// The files looked at when loading that nothing watches: the MMDB (one that could not be
    /// read included), data files whose directory is not there either, and every data file
    /// when the watch could not be installed. A later hot reload loads again once any of them
    /// looks otherwise; while each looks the same, one there yet unreadable included, reading
    /// again would give the same data, so nothing is loaded again
    unwatched: Vec<Unwatched>,
    watch: Option<FileWatch>,
}

impl<S: PartialEq> Loaded<S> {
    /// 按 `spec` 加载的数据是否就是现在这份 / Whether loading for `spec` would give the data already loaded
    fn is_current(&self, spec: &S) -> bool {
        self.spec == *spec && self.unwatched.iter().all(Unwatched::unchanged)
    }
}

/// 没有监视的文件，和加载时它什么样（不存在时是 None）/ A file nothing watches, and what it looked
/// like when loading (None when it was missing)
struct Unwatched {
    path: PathBuf,
    seen: Option<FileStamp>,
}

impl Unwatched {
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

/// 两种 Geo 数据各自换过几次：缓存命名空间算上它，数据一换，用到它的 pipeline 就换命名空间（见
/// `EngineInner::at_geo`）
/// How many times each kind of Geo data has been swapped: cache namespaces take it in, so
/// once the data is swapped the pipelines that use it move to a new namespace (see
/// `EngineInner::at_geo`)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GeoGeneration {
    pub(crate) site: u64,
    pub(crate) ip: u64,
}

/// 数据换进管理器以后，代数加一，引擎状态换成这一代的命名空间
/// After data is swapped into a manager, its generation goes up by one and the engine
/// state moves to that generation's namespaces
#[derive(Clone)]
struct Rotation {
    site: Arc<AtomicU64>,
    ip: Arc<AtomicU64>,
    state: Arc<ArcSwap<EngineInner>>,
}

impl Rotation {
    fn generation(&self) -> GeoGeneration {
        GeoGeneration {
            site: self.site.load(Ordering::SeqCst),
            ip: self.ip.load(Ordering::SeqCst),
        }
    }

    /// `counter` 那种数据刚换进管理器 / The data `counter` counts was just swapped into its manager
    fn swapped(&self, counter: &AtomicU64) {
        // 数据先换、代数后加：拿到新命名空间的请求读到的一定是新数据。换状态用 rcu，同时有配置重载存进新状态时重来一遍，
        // 不会把它盖回去；重载那边存的时候也读一遍代数（见 `Engine::apply_config`）
        // The data first, the generation after: a request that gets the new namespace
        // reads the new data. The state is swapped with rcu, which starts over when a
        // configuration reload stores a new state meanwhile instead of overwriting it; the
        // reload reads the generation as it stores too (see `Engine::apply_config`)
        counter.fetch_add(1, Ordering::SeqCst);
        self.state.rcu(|state| state.at_geo(self.generation()));
    }

    fn site_swapped(&self) {
        self.swapped(&self.site);
    }

    fn ip_swapped(&self) {
        self.swapped(&self.ip);
    }
}

/// 两种 Geo 数据眼下的问题：配置了却不存在或读不了的文件、装不上的监视、规则用到却没有数据提供的标签。启动、热重载和
/// 监视到文件变了时跟着更新，面板经控制通道读（见 [`Engine::geo_data_warnings`]）
/// What is wrong with the two kinds of Geo data right now: configured files that are missing
/// or cannot be read, watches that cannot be installed, and tags rules use that no data
/// provides. Kept up to date at startup, on hot reloads and as watched files change, and read
/// by the panel over the control channel (see [`Engine::geo_data_warnings`])
#[derive(Default)]
pub(crate) struct GeoStatus {
    site: Mutex<DataStatus>,
    ip: Mutex<DataStatus>,
}

/// 一种 Geo 数据的问题，每样一句话 / What is wrong with one kind of Geo data, a sentence each
#[derive(Default)]
struct DataStatus {
    /// 读不进来的文件，各带说它的那句话 / The files that could not be read in, each with the sentence saying so
    files: Vec<(PathBuf, String)>,
    /// 监视装不上时说它的那句话 / The sentence saying the watch could not be installed, when it could not
    watch: Option<String>,
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
        match self.files.iter_mut().find(|(file, _)| file == path) {
            Some((_, was)) => *was = said,
            None => self.files.push((path.to_path_buf(), said)),
        }
    }

    /// `what` 的监视因为 `err` 装不上 / The watch on `what` could not be installed because of `err`
    fn not_watched(&mut self, what: &str, err: &dyn std::fmt::Display) {
        self.watch = Some(format!(
            "{what} cannot be watched for changes, which are read at the next configuration reload: {err}"
        ));
    }

    /// `path` 读进来了 / `path` was read in
    fn read(&mut self, path: &Path) {
        self.files.retain(|(file, _)| file != path);
    }

    fn sentences(&self) -> impl Iterator<Item = &str> {
        let files = self.files.iter().map(|(_, said)| said.as_str());
        files
            .chain(self.watch.as_deref())
            .chain(self.tags.as_deref())
    }
}

impl Engine {
    /// Geo 数据眼下的问题，一样一句话：配置了却不存在或读不了的文件、装不上的文件监视、规则用到却没有数据提供的标签
    /// （这样的规则 geo_site、geoip_country 永不命中，geo_site_not 总命中）。没有问题时是空的。启动、热重载和监视到
    /// 文件变了时跟着更新
    /// What is wrong with the Geo data right now, a sentence each: configured files that are
    /// missing or cannot be read, file watches that cannot be installed, and tags rules use
    /// that no data provides (geo_site and geoip_country never match them, and geo_site_not
    /// always does). Empty when nothing is wrong. Kept up to date at startup, on hot reloads and
    /// as watched files change
    pub fn geo_data_warnings(&self) -> Vec<String> {
        let (site, ip) = (self.geo_status.site.lock(), self.geo_status.ip.lock());
        site.sentences()
            .chain(ip.sentences())
            .map(str::to_owned)
            .collect()
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

/// 两个管理器里现在的 Geo 数据从哪来；只在重载锁下使用（见 `Engine::reload_lock`）
/// Where the Geo data now in the two managers came from; used only under the reload lock
/// (see `Engine::reload_lock`)
pub(crate) struct GeoSources {
    geosite: Loaded<GeoSiteSpec>,
    geoip: Loaded<GeoIpSpec>,
    rotation: Rotation,
    status: Arc<GeoStatus>,
}

impl GeoSources {
    /// 把 `cfg` 用到的 Geo 数据装进两个管理器，并监视它的文件；数据每换一次，`state` 换成新一代的命名空间
    /// Loads the Geo data `cfg` uses into the two managers and watches its files; every
    /// time the data is swapped, `state` moves to the new generation's namespaces
    pub(crate) fn load(
        cfg: &RuntimePipelineConfig,
        geosite: &Arc<RwLock<GeoSiteManager>>,
        geoip: &Arc<RwLock<GeoIpManager>>,
        state: &Arc<ArcSwap<EngineInner>>,
    ) -> Self {
        let rotation = Rotation {
            site: Arc::default(),
            ip: Arc::default(),
            state: Arc::clone(state),
        };
        let status = Arc::default();
        Self {
            geosite: load_geosite(GeoSiteSpec::of(cfg), geosite, &rotation, &status),
            geoip: load_geoip(GeoIpSpec::of(cfg), None, geoip, &rotation, &status),
            rotation,
            status,
        }
    }

    /// 两种 Geo 数据现在的代数 / The two kinds of Geo data's generations now
    pub(crate) fn generation(&self) -> GeoGeneration {
        self.rotation.generation()
    }

    /// 两种 Geo 数据眼下的问题，加载和监视都往这里写 / What is wrong with the two kinds of Geo data,
    /// which loading and the watches write to
    pub(crate) fn status(&self) -> Arc<GeoStatus> {
        Arc::clone(&self.status)
    }

    /// 热重载到 `cfg`：它要的 Geo 数据和现在的不同时，换成新数据并改为监视新的文件。在换入新规则
    /// 之前调用，新规则一生效就能用上新的标签和文件。
    /// Hot reload to `cfg`: when the Geo data it needs differs from the data loaded, swaps in
    /// new data and moves the watches to the new files. Called before the new rules are
    /// swapped in, so they find the new tags and files from their first query.
    pub(crate) fn follow(
        &mut self,
        cfg: &RuntimePipelineConfig,
        geosite: &Arc<RwLock<GeoSiteManager>>,
        geoip: &Arc<RwLock<GeoIpManager>>,
    ) {
        let spec = GeoSiteSpec::of(cfg);
        if !self.geosite.is_current(&spec) {
            info!(paths = ?spec.paths, tags = spec.tags.len(), "GeoSite data follows the new configuration");
            // 先停下旧的监视并等它结束，它就不会在新数据换入以后再写进来
            // Stop the old watch and wait for it first, so it cannot write into the new
            // data after the swap
            self.geosite.watch = None;
            self.geosite = load_geosite(spec, geosite, &self.rotation, &self.status);
        }
        let spec = GeoIpSpec::of(cfg);
        if !self.geoip.is_current(&spec) {
            info!(tags = ?spec.tags, db_path = ?spec.db_path, dat_path = ?spec.dat_path, "GeoIP data follows the new configuration");
            self.geoip.watch = None;
            let in_use = self.geoip.spec.dat_path.clone();
            self.geoip = load_geoip(spec, in_use.as_deref(), geoip, &self.rotation, &self.status);
        }
    }
}

/// 开始监视 `files` 里监视得了的：在的文件，以及所在的目录在、出现时看得见的不在的文件。装不上时记一条错误、写进
/// `problems`，数据照样加载。给出装好的监视和它监视的文件
/// Starts watching those of `files` that can be: the files there, and those not there whose
/// directory is, where they show up once created. When the watch cannot be installed an
/// error is logged and written to `problems`, and the data is loaded all the same. Gives the
/// watch installed and the files it watches
fn pending_watch(
    what: &str,
    files: &[PathBuf],
    problems: &mut DataStatus,
) -> (Option<PendingWatch>, Vec<PathBuf>) {
    let watchable: Vec<PathBuf> = files
        .iter()
        .filter(|path| {
            path.exists()
                || path
                    .parent()
                    .is_none_or(|dir| dir.as_os_str().is_empty() || dir.is_dir())
        })
        .cloned()
        .collect();
    if watchable.is_empty() {
        return (None, watchable);
    }
    match PendingWatch::new(&watchable) {
        Ok(pending) => (Some(pending), watchable),
        Err(err) => {
            error!(what, error = %err, "cannot watch data files for changes, they are read again at the next configuration reload");
            problems.not_watched(what, &err);
            (None, Vec::new())
        }
    }
}

/// 起线程处理监视到的变化；起不了线程就记一条错误，写进 `status`
/// Starts the thread that handles watched changes; when it cannot start an error is logged and
/// written to `status`
fn start_watch(
    pending: Option<PendingWatch>,
    what: &str,
    name: &str,
    status: &Mutex<DataStatus>,
    on_change: impl FnMut(&Path) + Send + 'static,
) -> Option<FileWatch> {
    pending?
        .start(name, on_change)
        .inspect_err(|err| {
            error!(name, error = %err, "cannot start the data file watcher, the files are read again at the next configuration reload");
            status.lock().not_watched(what, err);
        })
        .ok()
}

/// 在锁外建好 `spec` 的 GeoSite 数据，整体换进 `shared`，再按新的文件和标签监视；读的时候出的问题写进 `status`
/// Builds `spec`'s GeoSite data outside the lock, swaps it into `shared` whole, then watches
/// the new files for the new tags; what goes wrong reading them is written to `status`
fn load_geosite(
    spec: GeoSiteSpec,
    shared: &Arc<RwLock<GeoSiteManager>>,
    rotation: &Rotation,
    status: &Arc<GeoStatus>,
) -> Loaded<GeoSiteSpec> {
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
    let seen: Vec<Unwatched> = files.iter().map(Unwatched::now).collect();
    let (pending, watched) = pending_watch("GeoSite data files", &files, &mut problems);
    let mut fresh = GeoSiteManager::new();
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
            error!(path = %path.display(), "GeoSite data file not found, waiting for it to appear");
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
    // 规则用到、刚读的文件却一个都不提供的标签 / The tags rules use that none of the files just
    // read provides
    let unprovided = fresh.missing_tags(&spec.tags);
    // 和监视到文件变了时一样（见 `reload_geosite_file`）：这份文件此前提供着规则现在还用的标签，重新读出来却一个都没有，
    // 多半是空文件或写坏了的文件。其中别的文件都不提供的标签留着正在用的数据，等文件下次改动；别的文件也提供的用那个
    // 文件的，和全部重新读一遍一样。写锁下只换数据，换完的收尾和日志放锁以后再做，旧数据也在锁外释放
    // As when a watched file changes (see `reload_geosite_file`): the file provided tags the
    // rules still use, yet reading it again gives none of them, most likely an empty or broken
    // file. Those of them no other file provides keep the data in use until the file changes
    // again; those another file provides too take that file's, as a full load would have them.
    // The write lock is held only to swap data: finishing the swaps and logging wait until it
    // is released, and the old data is freed outside it too
    let (old, kept, missing_tags) = {
        let mut in_use = shared.write();
        let kept: Vec<(&PathBuf, Swapped)> = gave_nothing
            .into_iter()
            .filter_map(|path| {
                let taken = in_use.take_source(path, &unprovided);
                // 这份文件在 `fresh` 里什么都没提供，没有要交出去的标签 / The file provides nothing
                // in `fresh`, so there are no tags to hand over
                (!taken.is_empty())
                    .then(|| (path, fresh.swap_source(path, taken, Vec::new(), false)))
            })
            .collect();
        let missing_tags = fresh.missing_tags(&spec.tags);
        (mem::replace(&mut *in_use, fresh), kept, missing_tags)
    };
    drop(old);
    for (path, swapped) in kept {
        let tags = swapped.finish();
        warn!(path = %path.display(), tags, "GeoSite data file now has none of the tags rules use, keeping the data in use");
    }
    // 没有要读的文件时不算，配置的告警已经说了（见 `config::geo_tags_without_data`）/ Not with no
    // file to read: the configuration's warnings say so already (see `config::geo_tags_without_data`)
    problems.tags = (!files.is_empty())
        .then(|| unprovided_geosite_tags(&missing_tags))
        .flatten();
    rotation.site_swapped();

    // 状态在监视开始之前写好：监视线程之后写进来的不会被它盖掉 / The status is written before the
    // watch starts, so what the watch thread writes later is not overwritten by it
    *status.site.lock() = problems;
    let manager = Arc::clone(shared);
    let tags = spec.tags.clone();
    let rotation = rotation.clone();
    let watching = Arc::clone(status);
    let watch = start_watch(
        pending,
        "GeoSite data files",
        "geosite-watch",
        &status.site,
        move |path| {
            if reload_geosite_file(&manager, path, &tags, &watching.site) {
                rotation.site_swapped();
            }
        },
    );
    Loaded {
        spec,
        unwatched: unwatched(seen, watch.is_some().then_some(&watched)),
        watch,
    }
}

/// `seen` 里不在 `watched` 之下的文件（没有监视时是全部）/ The files of `seen` that `watched` does
/// not cover (all of them without a watch)
fn unwatched(seen: Vec<Unwatched>, watched: Option<&Vec<PathBuf>>) -> Vec<Unwatched> {
    seen.into_iter()
        .filter(|file| watched.is_none_or(|watched| !watched.contains(&file.path)))
        .collect()
}

/// 监视到 GeoSite 数据文件 `path` 变了：只替换它贡献的标签，其它文件贡献的标签不动（见
/// [`GeoSiteManager::apply_source`]）。文件都在锁外读：先在读锁下算出哪些标签要由前面的文件顶上，在锁外读那些
/// 文件，再短暂持写锁换进去。以前要顶上的标签在写锁里读，这期间所有按 GeoSite 匹配的查询都停着。监视线程是管理器
/// 唯一写数据的（热重载先停下监视再换数据），所以读锁下算出来的到换进去时仍然成立。读得了、读不了都写进 `status`
/// A watched GeoSite data file `path` changed: only the tags it contributes are replaced,
/// leaving other files' tags alone (see [`GeoSiteManager::apply_source`]). Every file is read
/// outside the lock: which tags earlier files are to take over is worked out under the read
/// lock, those files are read outside it, and the write lock is held briefly to swap in. The
/// tags taken over used to be read under the write lock, stalling every GeoSite match
/// meanwhile. The watch thread is the only one writing to the manager (a hot reload stops
/// the watch before swapping data), so what was worked out under the read lock still holds
/// at the swap. Whether it could be read or not goes to `status`. Gives whether new data went
/// in / 换进了新数据时为 true
fn reload_geosite_file(
    manager: &RwLock<GeoSiteManager>,
    path: &Path,
    tags: &[String],
    status: &Mutex<DataStatus>,
) -> bool {
    let parsed = match GeoSiteManager::parse_file(path, tags) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!(path = %path.display(), error = %format!("{err:#}"), "GeoSite data reload failed, keeping the data in use");
            status.lock().not_read("GeoSite data file", path, &err);
            return false;
        }
    };
    status.lock().read(path);
    let handovers = manager.read().handovers(path, &parsed);
    // 新读出来一个规则用到的标签都没有：多半是空文件或写坏了的文件（下载失败、磁盘写满）。只有它提供的标签换掉会让用
    // 它们的规则一下子全不命中，所以留着正在用的数据，等文件下次改动；别的文件也提供的标签照常交给那个文件，和全部
    // 重新读一遍一样。没有要交出去的标签时什么都不变。以前整份留着，别的文件明明还提供着的标签也一直用这份的旧数据
    // The new read has none of the tags rules use: most likely an empty or broken file (a
    // failed download, a full disk). Dropping the tags only it provides would stop the rules
    // using them matching at once, so they keep the data in use until the file changes again;
    // the tags another file provides too go over to that file as usual, as a full load would
    // have it. With none to hand over nothing changes. It used to be kept whole, so a tag
    // another file still provided went on with this file's old data
    let gives_none = !parsed_provides_any(&parsed, tags);
    if gives_none {
        warn!(path = %path.display(), "GeoSite data file now has none of the tags rules use, keeping the data only it provided");
        if handovers.is_empty() {
            return false;
        }
    }
    let handed_over = GeoSiteManager::read_handovers(handovers);
    let mut manager = manager.write();
    let swapped = manager.swap_source(path, parsed, handed_over, gives_none);
    let missing = manager.missing_tags(tags);
    drop(manager);
    let count = swapped.finish();
    info!(path = %path.display(), loaded_count = count, "GeoSite data reloaded");
    status.lock().tags = unprovided_geosite_tags(&missing);
    true
}

/// 在锁外建好 `spec` 的 GeoIP 数据，整体换进 `shared`，再监视新的数据文件；读的时候出的问题写进 `status`。`in_use` 是
/// `shared` 里正在用的数据读自哪个数据文件（启动时还没有）
/// Builds `spec`'s GeoIP data outside the lock, swaps it into `shared` whole, then watches the
/// new data file; what goes wrong reading it is written to `status`. `in_use` is the data file
/// the data in `shared` was read from (none yet at startup)
fn load_geoip(
    spec: GeoIpSpec,
    in_use: Option<&str>,
    shared: &Arc<RwLock<GeoIpManager>>,
    rotation: &Rotation,
    status: &Arc<GeoStatus>,
) -> Loaded<GeoIpSpec> {
    let mut problems = DataStatus::default();
    let mut fresh = GeoIpManager::default();
    // MMDB 不被监视，换了样子由热重载读（见 `Loaded::unwatched`）/ The MMDB is not watched, a hot
    // reload reading it once it looks otherwise (see `Loaded::unwatched`)
    let mmdb = spec.db_path.as_ref().map(Unwatched::now);
    if let Some(db_path) = &spec.db_path
        && let Err(err) = fresh.use_mmdb(db_path, &shared.read())
    {
        error!(geoip_db = %db_path, error = %format!("{err:#}"), keeping_the_one_in_use = fresh.has_mmdb(), "failed to open GeoIP database, waiting for it to change");
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
    let seen: Vec<Unwatched> = files.iter().map(Unwatched::now).collect();
    let (pending, watched) = pending_watch("GeoIP data file", &files, &mut problems);
    // 读出来没有一个规则用到的标签的数据文件（读不了的也算）/ The data file if its read gave none of
    // the tags rules use (an unreadable one included)
    let mut gave_nothing = None;
    for path in &files {
        if !path.exists() {
            error!(path = %path.display(), "GeoIP data file not found, waiting for it to appear");
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
    // 多半是空文件或写坏了的文件。规则现在还用的标签留着正在用的数据，等文件下次改动。写锁下只搬数据，告警放锁以后
    // 再记，旧数据也在锁外释放
    // As when a watched file changes (see `reload_geoip_file`): the data file is the one the
    // data in use came from, yet reading it again gives none of the tags rules use, most
    // likely an empty or broken file. The tags the rules still use keep the data in use until
    // the file changes again. The write lock is held only to move data: the warning waits
    // until it is released, and the old data is freed outside it too
    let gave_nothing = gave_nothing
        .filter(|path| in_use.is_some_and(|in_use| Path::new(in_use) == path.as_path()));
    let (old, kept, missing_tags) = {
        let mut current = shared.write();
        let kept = gave_nothing.map_or(0, |_| fresh.keep_tags_of(&mut current, &dat_tags));
        let missing_tags = fresh.missing_tags(&spec.tags);
        (mem::replace(&mut *current, fresh), kept, missing_tags)
    };
    drop(old);
    if let Some(path) = gave_nothing
        && kept > 0
    {
        warn!(path = %path.display(), tags = kept, "GeoIP data file now has none of the tags rules use, keeping the data in use");
    }
    // 配置里没给数据的标签不算，配置的告警已经说了（见 `config::geo_tags_without_data`）/ Tags the
    // configuration gives no data for do not count: its warnings say so already (see
    // `config::geo_tags_without_data`)
    let given_data =
        |tag: &String| spec.dat_path.is_some() || (spec.db_path.is_some() && is_country_tag(tag));
    let missing_tags: Vec<String> = missing_tags.into_iter().filter(given_data).collect();
    problems.tags = unprovided_geoip_tags(&missing_tags);
    rotation.ip_swapped();

    // 状态在监视开始之前写好，和 GeoSite 一样 / The status is written before the watch starts, as for GeoSite
    *status.ip.lock() = problems;
    let manager = Arc::clone(shared);
    let rotation = rotation.clone();
    let watching = Arc::clone(status);
    let watch = start_watch(
        pending,
        "GeoIP data file",
        "geoip-watch",
        &status.ip,
        move |path| {
            if reload_geoip_file(&manager, path, &dat_tags, &watching.ip) {
                rotation.ip_swapped();
            }
        },
    );
    let files = unwatched(seen, watch.is_some().then_some(&watched));
    Loaded {
        spec,
        unwatched: mmdb.into_iter().chain(files).collect(),
        watch,
    }
}

/// 监视到 GeoIP 数据文件 `path` 变了：在锁外读取、解码、建索引、记日志，装进一个和在用的共用 MMDB 的新管理器，只在
/// 把它换进去时短暂持写锁，换下来的也在锁外放掉——匹配走读锁，整个重载都在写锁里时，三十万网段的 .dat 让所有 GeoIP
/// 匹配停了 961 ms。监视线程是唯一写管理器的（热重载先停下监视再换数据），所以读锁下拿到的 MMDB 到换进去时仍是在用的那份。
/// 读得了、读不了都写进 `status`
/// A watched GeoIP data file `path` changed: reading, decoding, indexing and logging happen
/// outside the lock, into a new manager sharing the MMDB in use, and the write lock is held only
/// to swap it in, the old one freed outside it too. Matching takes the read lock, and with the
/// whole reload under the write lock a .dat of 300k networks stalled every GeoIP match for
/// 961 ms. The watch thread is the only one writing to the manager (a hot reload stops the
/// watch before swapping data), so the MMDB taken under the read lock is still the one in use
/// at the swap. Whether it could be read or not goes to `status`. Gives whether new data went
/// in / 换进了新数据时为 true
fn reload_geoip_file(
    manager: &RwLock<GeoIpManager>,
    path: &Path,
    tags: &[String],
    status: &Mutex<DataStatus>,
) -> bool {
    let parsed = match GeoIpManager::parse_file(path, tags) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!(path = %path.display(), error = %format!("{err:#}"), "GeoIP data reload failed, keeping the data in use");
            status.lock().not_read("GeoIP data file", path, &err);
            return false;
        }
    };
    status.lock().read(path);
    // 和 GeoSite 一样：规则用到的标签这份文件此前给着、现在一个都没有了，多半是文件坏了，
    // 留着正在用的数据 / As for GeoSite: the file gave tags rules use until now and has
    // none of them any more, most likely a broken file, so the data in use stays
    if parsed.tag_count() == 0 && manager.read().tag_count() > 0 {
        warn!(path = %path.display(), "GeoIP data file now has none of the tags rules use, keeping the data in use");
        return false;
    }
    let mut fresh = manager.read().sharing_mmdb();
    let count = fresh.apply_parsed(parsed);
    let missing = fresh.missing_tags(tags);
    let old = mem::replace(&mut *manager.write(), fresh);
    drop(old);
    info!(path = %path.display(), loaded_count = count, "GeoIP data reloaded");
    status.lock().tags = unprovided_geoip_tags(&missing);
    true
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    /// 只有一个标签、标签里只有一个后缀的 JSON 数据文件 / A JSON data file with one tag holding one
    /// suffix
    fn json(tag: &str, suffix: &str) -> String {
        format!(r#"{{"entries":[{{"tag":"{tag}","domains":["domain:{suffix}"]}}]}}"#)
    }

    /// 数日志的订阅者层：一共记了几条，几条是在两个管理器有一个拿着写锁时记的
    /// A subscriber layer counting log lines: how many there were, and how many came while
    /// either manager's write lock was held
    struct LogsUnderLock {
        geosite: Arc<RwLock<GeoSiteManager>>,
        geoip: Arc<RwLock<GeoIpManager>>,
        logged: Arc<std::sync::atomic::AtomicUsize>,
        under_lock: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogsUnderLock {
        fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            self.logged.fetch_add(1, Ordering::SeqCst);
            if self.geosite.is_locked_exclusive() || self.geoip.is_locked_exclusive() {
                self.under_lock.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// 监视到数据文件变了时，日志都在写锁外记，换下来的数据也在锁外放掉：写锁只在换数据时拿着。以前换完的规模在写锁里记、
    /// 放掉换下来的数据的线程在写锁里起，GeoIP 的日志也在写锁里记，旧数据在写锁里放掉，这期间所有按 Geo 数据匹配的查询
    /// 都停着
    /// When a watched data file changes, every log line is written outside the write lock, and
    /// the data swapped out is freed outside it too: the write lock is held only for the swap.
    /// The size after the swap used to be logged, and the thread freeing the data swapped out
    /// started, under the write lock, and GeoIP logged and freed its old data under it too, every
    /// match on Geo data stalled meanwhile
    #[test]
    fn a_reload_logs_nothing_under_the_write_lock() {
        use tracing_subscriber::layer::SubscriberExt;
        let dir = tempfile::tempdir().unwrap();
        let (site, ip) = (dir.path().join("site.json"), dir.path().join("ip.json"));
        let site_tags = ["ads".to_string()];
        let ip_tags = ["LAN".to_string()];
        let ip_json =
            |net: &str| format!(r#"{{"entries":[{{"country_code":"LAN","ips":["{net}"]}}]}}"#);
        std::fs::write(&site, json("ads", "old.test")).unwrap();
        std::fs::write(&ip, ip_json("192.0.2.0/24")).unwrap();
        let geosite = Arc::new(RwLock::new(GeoSiteManager::new()));
        let parsed = GeoSiteManager::parse_file(&site, &site_tags).unwrap();
        geosite.write().apply_source(&site, parsed);
        let geoip = Arc::new(RwLock::new(GeoIpManager::default()));
        geoip
            .write()
            .apply_parsed(GeoIpManager::parse_file(&ip, &ip_tags).unwrap());
        std::fs::write(&site, json("ads", "new.test")).unwrap();
        std::fs::write(&ip, ip_json("198.51.100.0/24")).unwrap();

        let (logged, under_lock) = (Arc::default(), Arc::default());
        let subscriber = tracing_subscriber::registry().with(LogsUnderLock {
            geosite: Arc::clone(&geosite),
            geoip: Arc::clone(&geoip),
            logged: Arc::clone(&logged),
            under_lock: Arc::clone(&under_lock),
        });
        tracing::subscriber::with_default(subscriber, || {
            let status = GeoStatus::default();
            assert!(reload_geosite_file(
                &geosite,
                &site,
                &site_tags,
                &status.site
            ));
            assert!(reload_geoip_file(&geoip, &ip, &ip_tags, &status.ip));
        });
        assert!(logged.load(Ordering::SeqCst) > 0, "the reloads log");
        assert_eq!(
            under_lock.load(Ordering::SeqCst),
            0,
            "logged under the write lock"
        );
        assert!(geosite.read().matches("ads", "x.new.test"));
        assert!(!geosite.read().matches("ads", "x.old.test"));
        let lan = [Arc::from("LAN")];
        assert!(
            geoip
                .read()
                .matches_any_tag("198.51.100.7".parse().unwrap(), &lan)
        );
        assert!(
            !geoip
                .read()
                .matches_any_tag("192.0.2.7".parse().unwrap(), &lan)
        );
    }

    /// 换数据时把代数加一、换命名空间的引擎状态：一份什么规则都没有的配置的 / The engine state a swap
    /// moves to the next generation's namespaces: that of a configuration without rules
    fn rotation() -> Rotation {
        let cfg = RuntimePipelineConfig::from_config(
            serde_json::from_value(serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipelines": []
            }))
            .unwrap(),
        )
        .unwrap();
        Rotation {
            site: Arc::default(),
            ip: Arc::default(),
            state: Arc::new(ArcSwap::from_pointee(EngineInner::new(cfg))),
        }
    }

    /// 热重载读出来的数据文件一个规则用到的标签都没有、留着正在用的数据时，日志也都在写锁外记，和监视到文件变了时
    /// 一样。以前这条告警和换数据的收尾日志都在写锁里记，这期间所有按 Geo 数据匹配的查询都停着
    /// When a hot reload reads a data file giving none of the tags rules use and the data in
    /// use stays, every log line is written outside the write lock too, as when a watched file
    /// changes. That warning and the log ending the swap used to be written under it, every
    /// match on Geo data stalled meanwhile
    #[test]
    fn a_hot_reload_keeping_the_data_in_use_logs_nothing_under_the_write_lock() {
        use tracing_subscriber::layer::SubscriberExt;
        let dir = tempfile::tempdir().unwrap();
        let (site, ip) = (dir.path().join("site.json"), dir.path().join("ip.json"));
        let ip_json = |tag: &str| {
            format!(r#"{{"entries":[{{"country_code":"{tag}","ips":["192.0.2.0/24"]}}]}}"#)
        };
        std::fs::write(&site, json("ads", "old.test")).unwrap();
        std::fs::write(&ip, ip_json("LAN")).unwrap();
        let site_tags = vec!["ads".to_string()];
        let ip_tags = vec!["LAN".to_string()];
        let geosite = Arc::new(RwLock::new(GeoSiteManager::new()));
        let parsed = GeoSiteManager::parse_file(&site, &site_tags).unwrap();
        geosite.write().apply_source(&site, parsed);
        let geoip = Arc::new(RwLock::new(GeoIpManager::default()));
        geoip
            .write()
            .apply_parsed(GeoIpManager::parse_file(&ip, &ip_tags).unwrap());
        // 两个文件都换成别的标签 / Both files now hold other tags only
        std::fs::write(&site, json("other", "new.test")).unwrap();
        std::fs::write(&ip, ip_json("OTHER")).unwrap();

        let (logged, under_lock) = (Arc::default(), Arc::default());
        let subscriber = tracing_subscriber::registry().with(LogsUnderLock {
            geosite: Arc::clone(&geosite),
            geoip: Arc::clone(&geoip),
            logged: Arc::clone(&logged),
            under_lock: Arc::clone(&under_lock),
        });
        let rotation = rotation();
        let ip_path = ip.to_str().unwrap();
        tracing::subscriber::with_default(subscriber, || {
            // 监视一装上就停下，它的线程不会在这期间写数据 / Each watch is stopped as soon as it is
            // installed, so its thread writes no data meanwhile
            let spec = GeoSiteSpec {
                paths: vec![site.to_str().unwrap().to_string()],
                tags: site_tags,
            };
            let status = Arc::default();
            drop(load_geosite(spec, &geosite, &rotation, &status));
            let spec = GeoIpSpec {
                tags: ip_tags,
                db_path: None,
                dat_path: Some(ip_path.to_string()),
            };
            drop(load_geoip(spec, Some(ip_path), &geoip, &rotation, &status));
        });
        assert!(logged.load(Ordering::SeqCst) > 0, "the reloads log");
        assert_eq!(
            under_lock.load(Ordering::SeqCst),
            0,
            "logged under the write lock"
        );
        assert!(geosite.read().matches("ads", "x.old.test"));
        assert!(
            geoip
                .read()
                .matches_any_tag("192.0.2.7".parse().unwrap(), &[Arc::from("LAN")])
        );
    }

    /// 监视到文件变了、共享的标签要从前面的文件读回来时，那个文件在锁外读：读的这段时间里匹配照常拿得到读锁。以前在写锁
    /// 里读，读一个大文件要几十毫秒，这期间所有按 GeoSite 匹配的查询都停着。前面那个文件换成命名管道，读它的一方停在
    /// 那里等写的一方，正好看这时锁有没有被拿着
    /// When a watched file changes and a shared tag is read back from an earlier file, that file
    /// is read outside the lock: matching gets the read lock as usual while it is read. It used
    /// to be read under the write lock, and reading a large file takes tens of milliseconds, with
    /// every GeoSite match stalled meanwhile. The earlier file is made a named pipe, whose reader
    /// waits there for the writer, just when the lock can be looked at
    #[test]
    fn a_shared_tag_is_read_back_outside_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (first, last) = (dir.path().join("first.json"), dir.path().join("last.json"));
        let tags = ["shared".to_string(), "only".to_string()];
        std::fs::write(&first, json("shared", "first.test")).unwrap();
        std::fs::write(
            &last,
            r#"{"entries":[{"tag":"shared","domains":["domain:last.test"]},{"tag":"only","domains":["domain:only.test"]}]}"#,
        )
        .unwrap();
        let manager = RwLock::new(GeoSiteManager::new());
        for path in [&first, &last] {
            let parsed = GeoSiteManager::parse_file(path, &tags).unwrap();
            manager.write().apply_source(path, parsed);
        }

        // 后面的文件交出 shared，前面的文件换成命名管道 / The later file gives up `shared`, and
        // the earlier one becomes a named pipe
        std::fs::write(&last, json("only", "only.test")).unwrap();
        std::fs::remove_file(&first).unwrap();
        let fifo = std::ffi::CString::new(first.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` 是以 NUL 结尾的路径，调用期间一直在 / `fifo` is a NUL-terminated path that
        // outlives the call
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let status = Mutex::default();
        std::thread::scope(|scope| {
            let reload = scope.spawn(|| reload_geosite_file(&manager, &last, &tags, &status));
            // 打开写的一端要等读的一端也打开：这时重载正在读前面那个文件 / Opening the writing end
            // waits for the reading end to open: the reload is reading the earlier file now
            let mut pipe = std::fs::OpenOptions::new()
                .write(true)
                .open(&first)
                .unwrap();
            assert!(
                manager.try_read().is_some(),
                "matching must not wait while another file is read"
            );
            pipe.write_all(json("shared", "first.test").as_bytes())
                .unwrap();
            drop(pipe);
            assert!(reload.join().unwrap());
        });
        let manager = manager.read();
        assert!(manager.matches("shared", "x.first.test"));
        assert!(!manager.matches("shared", "x.last.test"));
        assert!(manager.matches("only", "x.only.test"));
    }
}
