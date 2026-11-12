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
use tracing::{info, warn};

use super::types::EngineInner;
use super::utils::{extract_geoip_tags_from_config, extract_geosite_tags_from_config};
use crate::lock::RwLock;
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::geoip::{GeoIpManager, is_country_tag};
use crate::matcher::geosite::{GeoSiteManager, parsed_provides_any};
use crate::watcher::{FileWatch, PendingWatch, load_with_retry};

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
    /// 配置了、加载时却还不存在的文件：没有监视，再次热重载时它们出现了就重新加载
    /// Configured files that did not exist when loading: they are not watched, and a later
    /// hot reload loads again once they appear
    missing: Vec<PathBuf>,
    watch: Option<FileWatch>,
}

impl<S: PartialEq> Loaded<S> {
    /// 按 `spec` 加载的数据是否就是现在这份 / Whether loading for `spec` would give the data already loaded
    fn is_current(&self, spec: &S) -> bool {
        self.spec == *spec && !self.missing.iter().any(|path| path.exists())
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

/// 两个管理器里现在的 Geo 数据从哪来；只在重载锁下使用（见 `Engine::reload_lock`）
/// Where the Geo data now in the two managers came from; used only under the reload lock
/// (see `Engine::reload_lock`)
pub(crate) struct GeoSources {
    geosite: Loaded<GeoSiteSpec>,
    geoip: Loaded<GeoIpSpec>,
    rotation: Rotation,
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
        Self {
            geosite: load_geosite(GeoSiteSpec::of(cfg), geosite, &rotation),
            geoip: load_geoip(GeoIpSpec::of(cfg), None, geoip, &rotation),
            rotation,
        }
    }

    /// 两种 Geo 数据现在的代数 / The two kinds of Geo data's generations now
    pub(crate) fn generation(&self) -> GeoGeneration {
        self.rotation.generation()
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
            info!(target = "geosite", paths = ?spec.paths, tags = spec.tags.len(), "GeoSite data follows the new configuration");
            // 先停下旧的监视并等它结束，它就不会在新数据换入以后再写进来
            // Stop the old watch and wait for it first, so it cannot write into the new
            // data after the swap
            self.geosite.watch = None;
            self.geosite = load_geosite(spec, geosite, &self.rotation);
        }
        let spec = GeoIpSpec::of(cfg);
        if !self.geoip.is_current(&spec) {
            info!(target = "geoip", tags = ?spec.tags, db_path = ?spec.db_path, dat_path = ?spec.dat_path, "GeoIP data follows the new configuration");
            self.geoip.watch = None;
            let in_use = self.geoip.spec.dat_path.clone();
            self.geoip = load_geoip(spec, in_use.as_deref(), geoip, &self.rotation);
        }
    }
}

/// `path` 是否 `.dat` 文件 / Whether `path` is a `.dat` file
fn is_dat(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("dat"))
}

/// 开始监视 `paths`；装不上就只记一条告警，数据照样加载
/// Starts watching `paths`; when the watch cannot be installed a warning is logged and the
/// data is loaded all the same
fn pending_watch(what: &str, paths: &[PathBuf]) -> Option<PendingWatch> {
    if paths.is_empty() {
        return None;
    }
    PendingWatch::new(paths)
        .inspect_err(|err| warn!(target = "watcher", what, error = %err, "cannot watch data files for changes"))
        .ok()
}

/// 起线程处理监视到的变化；起不了线程就只记一条告警
/// Starts the thread that handles watched changes; when it cannot start a warning is logged
fn start_watch(
    pending: Option<PendingWatch>,
    name: &str,
    on_change: impl FnMut(&Path) + Send + 'static,
) -> Option<FileWatch> {
    pending?
        .start(name, on_change)
        .inspect_err(|err| warn!(target = "watcher", name, error = %err, "cannot start the data file watcher"))
        .ok()
}

/// 在锁外建好 `spec` 的 GeoSite 数据，整体换进 `shared`，再按新的文件和标签监视
/// Builds `spec`'s GeoSite data outside the lock, swaps it into `shared` whole, then watches
/// the new files for the new tags
fn load_geosite(
    spec: GeoSiteSpec,
    shared: &Arc<RwLock<GeoSiteManager>>,
    rotation: &Rotation,
) -> Loaded<GeoSiteSpec> {
    let mut missing = Vec::new();
    let mut files = Vec::new();
    for path_str in &spec.paths {
        let path = PathBuf::from(path_str);
        if !path.exists() {
            warn!(path = %path.display(), "GeoSite data file not found, skipping");
            missing.push(path);
        } else if is_dat(&path) && spec.tags.is_empty() {
            // .dat 只读规则用到的标签，一个都没用到就不必读，也不必监视
            // A .dat is read only for the tags rules use; with none used it is neither read
            // nor watched
            info!(path = %path.display(), "No GeoSite tags used in config, skipping GeoSite data loading");
        } else {
            files.push(path);
        }
    }

    let pending = pending_watch("GeoSite data", &files);
    let mut fresh = GeoSiteManager::new();
    // 读出来没有一个规则用到的标签的文件（读不了的也算）/ The files whose read gave none of the
    // tags rules use (unreadable ones included)
    let mut gave_nothing = Vec::new();
    for path in &files {
        // 解析失败的文件照样监视：写了一半或被截断的文件在下次写完时能自己恢复，不必重启进程。它在文件里的
        // 先后也照样记下（几个文件声明同一个标签时排在后面的说了算）
        // A file that failed to parse is watched all the same: a half-written or truncated
        // file heals itself on the next write instead of needing a restart. Its place among
        // the files is recorded all the same (of files declaring one tag the later decides)
        let parsed = GeoSiteManager::parse_file(path, &spec.tags)
            .inspect_err(|e| warn!(path = %path.display(), error = %e, "failed to load GeoSite data, waiting for the file to change"))
            .ok();
        let readable = parsed.is_some();
        let parsed = parsed.unwrap_or_default();
        if !parsed_provides_any(&parsed, &spec.tags) {
            gave_nothing.push(path);
        }
        let count = fresh.apply_source(path, parsed);
        if readable {
            info!(path = %path.display(), loaded_count = count,
                 used_tags = spec.tags.len(),
                 "loaded GeoSite data from file");
        }
    }
    let old = {
        let mut in_use = shared.write();
        // 和监视到文件变了时一样（见 `reload_geosite_file`）：这份文件此前提供着规则现在还用的标签，重新读出来
        // 却一个都没有，多半是空文件或写坏了的文件。这些标签留着正在用的数据，等文件下次改动
        // As when a watched file changes (see `reload_geosite_file`): the file provided tags
        // the rules still use, yet reading it again gives none of them, most likely an empty or
        // broken file. Those tags keep the data in use until the file changes again
        for path in gave_nothing {
            let kept = in_use.take_source(path, &spec.tags);
            if !kept.is_empty() {
                warn!(target = "geosite", path = %path.display(), tags = kept.len(), "GeoSite data file now has none of the tags rules use, keeping the data in use");
                fresh.apply_source(path, kept);
            }
        }
        let missing = fresh.missing_tags(&spec.tags);
        let old = mem::replace(&mut *in_use, fresh);
        drop(in_use);
        if !files.is_empty() {
            warn_missing_geosite_tags(&missing);
        }
        old
    };
    // 旧数据在锁外释放 / The old data is freed outside the lock
    drop(old);
    rotation.site_swapped();

    let manager = Arc::clone(shared);
    let tags = spec.tags.clone();
    let rotation = rotation.clone();
    let watch = start_watch(pending, "geosite-watch", move |path| {
        if reload_geosite_file(&manager, path, &tags) {
            rotation.site_swapped();
        }
    });
    Loaded {
        spec,
        missing,
        watch,
    }
}

/// 监视到 GeoSite 数据文件 `path` 变了：在锁外重新读这一份，再短暂持写锁只替换它贡献的标签，
/// 其它文件贡献的标签不动（见 [`GeoSiteManager::apply_source`]）
/// A watched GeoSite data file `path` changed: it is read again outside the lock, then the
/// write lock is held briefly to replace only the tags it contributes, leaving other files'
/// tags alone (see [`GeoSiteManager::apply_source`]). Gives whether new data went in
/// 换进了新数据时为 true
fn reload_geosite_file(manager: &RwLock<GeoSiteManager>, path: &Path, tags: &[String]) -> bool {
    let what = format!("GeoSite data {}", path.display());
    let Some(parsed) = load_with_retry(&what, || GeoSiteManager::parse_file(path, tags)) else {
        return false;
    };
    {
        // 这份文件此前提供着规则用到的标签，新读出来却一个都没有了：多半是空文件或写坏了的文件（下载
        // 失败、磁盘写满）。换进去会让这些规则一下子全不命中，所以留着正在用的数据，等文件下次改动
        // The file provided tags rules use until now, yet the new read has none of them: most
        // likely an empty or broken file (a failed download, a full disk). Swapping it in would
        // stop those rules matching at once, so the data in use stays until the file changes again
        if !tags.is_empty()
            && !parsed_provides_any(&parsed, tags)
            && manager.read().source_provides_any(path, tags)
        {
            warn!(target = "geosite_watcher", path = %path.display(), "GeoSite data file now has none of the tags rules use, keeping the data in use");
            return false;
        }
        let mut manager = manager.write();
        let count = manager.apply_source(path, parsed);
        let missing = manager.missing_tags(tags);
        drop(manager);
        info!(target = "geosite_watcher", path = %path.display(), loaded_count = count, "GeoSite data reloaded");
        warn_missing_geosite_tags(&missing);
    }
    true
}

/// 规则用到、却没有一个 GeoSite 数据文件提供的标签记一条告警，和 GeoIP 一样
/// Logs the tags rules use that no GeoSite data file provides, as GeoIP does
fn warn_missing_geosite_tags(missing: &[String]) {
    if !missing.is_empty() {
        warn!(target = "geosite", tags = ?missing, "GeoSite tags used by rules are not in any data file and never match");
    }
}

/// 在锁外建好 `spec` 的 GeoIP 数据，整体换进 `shared`，再监视新的数据文件。`in_use` 是 `shared` 里正在用的
/// 数据读自哪个数据文件（启动时还没有）
/// Builds `spec`'s GeoIP data outside the lock, swaps it into `shared` whole, then watches the
/// new data file. `in_use` is the data file the data in `shared` was read from (none yet at
/// startup)
fn load_geoip(
    spec: GeoIpSpec,
    in_use: Option<&str>,
    shared: &Arc<RwLock<GeoIpManager>>,
    rotation: &Rotation,
) -> Loaded<GeoIpSpec> {
    let mut missing = Vec::new();
    if let Some(db_path) = &spec.db_path
        && !Path::new(db_path).exists()
    {
        // GeoIpManager::new 自己记告警 / GeoIpManager::new logs the warning itself
        missing.push(PathBuf::from(db_path));
    }
    let mut fresh = GeoIpManager::new(spec.db_path.clone()).unwrap_or_else(|e| {
        warn!(error = %e, "Failed to initialize GeoIpManager, running without GeoIP support");
        GeoIpManager::new(None).expect("GeoIpManager::new(None) should always succeed")
    });

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
        let path = PathBuf::from(dat_path);
        if dat_tags.is_empty() {
            info!(path = %path.display(), "every GeoIP tag rules use is a country code the GeoIP database answers, skipping the GeoIP data file");
        } else if path.exists() {
            files.push(path);
        } else {
            warn!(path = %path.display(), "GeoIP data file not found, skipping");
            missing.push(path);
        }
    }

    let pending = pending_watch("GeoIP data", &files);
    for path in &files {
        // 解析失败的文件和 GeoSite 一样照样监视 / A file that failed to parse is watched, as for GeoSite
        match GeoIpManager::parse_file(path, &dat_tags) {
            Ok(parsed) => {
                let count = fresh.apply_parsed(parsed);
                info!(path = %path.display(), loaded_count = count, used_tags = dat_tags.len(), "loaded GeoIP data from file");
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to load GeoIP data, waiting for the file to change");
            }
        }
    }
    let old = {
        let mut current = shared.write();
        // 和监视到文件变了时一样（见 `reload_geoip_file`）：还是正在用的那份数据文件，重新读出来却没有一个规则
        // 用到的标签，多半是空文件或写坏了的文件。规则现在还用的标签留着正在用的数据，等文件下次改动
        // As when a watched file changes (see `reload_geoip_file`): the data file is the one
        // the data in use came from, yet reading it again gives none of the tags rules use,
        // most likely an empty or broken file. The tags the rules still use keep the data in
        // use until the file changes again
        if fresh.tag_count() == 0
            && let Some(path) = files.first()
            && in_use.is_some_and(|in_use| Path::new(in_use) == path.as_path())
            && fresh.keep_tags_of(&mut current, &dat_tags) > 0
        {
            warn!(target = "geoip", path = %path.display(), "GeoIP data file now has none of the tags rules use, keeping the data in use");
        }
        mem::replace(&mut *current, fresh)
    };
    // 旧数据在锁外释放 / The old data is freed outside the lock
    drop(old);
    rotation.ip_swapped();

    let manager = Arc::clone(shared);
    let rotation = rotation.clone();
    let watch = start_watch(pending, "geoip-watch", move |path| {
        if reload_geoip_file(&manager, path, &dat_tags) {
            rotation.ip_swapped();
        }
    });
    Loaded {
        spec,
        missing,
        watch,
    }
}

/// 监视到 GeoIP 数据文件 `path` 变了：在锁外读取、解码、建索引，只在换入时短暂持写锁——匹配
/// 走读锁，整个重载都在写锁里时，三十万网段的 .dat 让所有 GeoIP 匹配停了 961 ms
/// A watched GeoIP data file `path` changed: reading, decoding and indexing happen outside
/// the lock, which is held only for the swap. Matching takes the read lock, and with the
/// whole reload under the write lock a .dat of 300k networks stalled every GeoIP match for
/// 961 ms. Gives whether new data went in / 换进了新数据时为 true
fn reload_geoip_file(manager: &RwLock<GeoIpManager>, path: &Path, tags: &[String]) -> bool {
    let what = format!("GeoIP data {}", path.display());
    let Some(parsed) = load_with_retry(&what, || GeoIpManager::parse_file(path, tags)) else {
        return false;
    };
    {
        // 和 GeoSite 一样：规则用到的标签这份文件此前给着、现在一个都没有了，多半是文件坏了，
        // 留着正在用的数据 / As for GeoSite: the file gave tags rules use until now and has
        // none of them any more, most likely a broken file, so the data in use stays
        if parsed.tag_count() == 0 && manager.read().tag_count() > 0 {
            warn!(target = "geoip_watcher", path = %path.display(), "GeoIP data file now has none of the tags rules use, keeping the data in use");
            return false;
        }
        let count = manager.write().apply_parsed(parsed);
        info!(target = "geoip_watcher", path = %path.display(), loaded_count = count, "GeoIP data reloaded");
    }
    true
}
