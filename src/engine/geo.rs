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
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::geoip::{GeoIpManager, is_country_tag};
use crate::matcher::geosite::{GeoSiteManager, parsed_provides_any};
use crate::watcher::{FileWatch, PendingWatch};
use parking_lot::RwLock;

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
    /// 配置了、加载时却不存在或读不了的文件：没有监视，再次热重载时它们在了就重新加载
    /// Configured files that were missing or could not be read when loading: they are not
    /// watched, and a later hot reload loads again once they are there
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
        // MMDB 不被监视：热重载时它换过了也要重新读（见 `GeoIpManager::mmdb_replaced`）/ The MMDB is not
        // watched: a hot reload reads it again once it was replaced (see `GeoIpManager::mmdb_replaced`)
        let mmdb_replaced = spec
            .db_path
            .as_deref()
            .is_some_and(|path| geoip.read().mmdb_replaced(path));
        if !self.geoip.is_current(&spec) || mmdb_replaced {
            info!(target = "geoip", tags = ?spec.tags, db_path = ?spec.db_path, dat_path = ?spec.dat_path, "GeoIP data follows the new configuration");
            self.geoip.watch = None;
            let in_use = self.geoip.spec.dat_path.clone();
            self.geoip = load_geoip(spec, in_use.as_deref(), geoip, &self.rotation);
        }
    }
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
        } else if spec.tags.is_empty() {
            // 数据文件只读规则用到的标签，一个都没用到就不必读，也不必监视
            // A data file is read only for the tags rules use; with none used it is neither
            // read nor watched
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
    // 规则用到、刚读的文件却一个都不提供的标签 / The tags rules use that none of the files just
    // read provides
    let unprovided = fresh.missing_tags(&spec.tags);
    let old = {
        let mut in_use = shared.write();
        // 和监视到文件变了时一样（见 `reload_geosite_file`）：这份文件此前提供着规则现在还用的标签，重新读出来
        // 却一个都没有，多半是空文件或写坏了的文件。其中别的文件都不提供的标签留着正在用的数据，等文件下次改动；
        // 别的文件也提供的用那个文件的，和全部重新读一遍一样
        // As when a watched file changes (see `reload_geosite_file`): the file provided tags
        // the rules still use, yet reading it again gives none of them, most likely an empty or
        // broken file. Those of them no other file provides keep the data in use until the
        // file changes again; those another file provides too take that file's, as a full
        // load would have them
        for path in gave_nothing {
            let kept = in_use.take_source(path, &unprovided);
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

/// 监视到 GeoSite 数据文件 `path` 变了：只替换它贡献的标签，其它文件贡献的标签不动（见
/// [`GeoSiteManager::apply_source`]）。文件都在锁外读：先在读锁下算出哪些标签要由前面的文件顶上，在锁外读那些
/// 文件，再短暂持写锁换进去。以前要顶上的标签在写锁里读，这期间所有按 GeoSite 匹配的查询都停着。监视线程是管理器
/// 唯一写数据的（热重载先停下监视再换数据），所以读锁下算出来的到换进去时仍然成立
/// A watched GeoSite data file `path` changed: only the tags it contributes are replaced,
/// leaving other files' tags alone (see [`GeoSiteManager::apply_source`]). Every file is read
/// outside the lock: which tags earlier files are to take over is worked out under the read
/// lock, those files are read outside it, and the write lock is held briefly to swap in. The
/// tags taken over used to be read under the write lock, stalling every GeoSite match
/// meanwhile. The watch thread is the only one writing to the manager (a hot reload stops
/// the watch before swapping data), so what was worked out under the read lock still holds
/// at the swap. Gives whether new data went in / 换进了新数据时为 true
fn reload_geosite_file(manager: &RwLock<GeoSiteManager>, path: &Path, tags: &[String]) -> bool {
    let parsed = match GeoSiteManager::parse_file(path, tags) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(target = "geosite_watcher", path = %path.display(), error = %format!("{err:#}"), "GeoSite data reload failed, keeping the data in use");
            return false;
        }
    };
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
        warn!(target = "geosite_watcher", path = %path.display(), "GeoSite data file now has none of the tags rules use, keeping the data only it provided");
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
    info!(target = "geosite_watcher", path = %path.display(), loaded_count = count, "GeoSite data reloaded");
    warn_missing_geosite_tags(&missing);
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
    let mut fresh = GeoIpManager::default();
    // 读不了的 MMDB 等下次重载再读，告警 use_mmdb 自己记 / An MMDB that cannot be read waits for a
    // later reload, use_mmdb logging the warning itself
    if let Some(db_path) = &spec.db_path
        && !fresh.use_mmdb(db_path, &shared.read())
    {
        missing.push(PathBuf::from(db_path));
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

/// 监视到 GeoIP 数据文件 `path` 变了：在锁外读取、解码、建索引、记日志，装进一个和在用的共用 MMDB 的新管理器，只在
/// 把它换进去时短暂持写锁，换下来的也在锁外放掉——匹配走读锁，整个重载都在写锁里时，三十万网段的 .dat 让所有 GeoIP
/// 匹配停了 961 ms。监视线程是唯一写管理器的（热重载先停下监视再换数据），所以读锁下拿到的 MMDB 到换进去时仍是在用的那份
/// A watched GeoIP data file `path` changed: reading, decoding, indexing and logging happen
/// outside the lock, into a new manager sharing the MMDB in use, and the write lock is held only
/// to swap it in, the old one freed outside it too. Matching takes the read lock, and with the
/// whole reload under the write lock a .dat of 300k networks stalled every GeoIP match for
/// 961 ms. The watch thread is the only one writing to the manager (a hot reload stops the
/// watch before swapping data), so the MMDB taken under the read lock is still the one in use
/// at the swap. Gives whether new data went in / 换进了新数据时为 true
fn reload_geoip_file(manager: &RwLock<GeoIpManager>, path: &Path, tags: &[String]) -> bool {
    let parsed = match GeoIpManager::parse_file(path, tags) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(target = "geoip_watcher", path = %path.display(), error = %format!("{err:#}"), "GeoIP data reload failed, keeping the data in use");
            return false;
        }
    };
    // 和 GeoSite 一样：规则用到的标签这份文件此前给着、现在一个都没有了，多半是文件坏了，
    // 留着正在用的数据 / As for GeoSite: the file gave tags rules use until now and has
    // none of them any more, most likely a broken file, so the data in use stays
    if parsed.tag_count() == 0 && manager.read().tag_count() > 0 {
        warn!(target = "geoip_watcher", path = %path.display(), "GeoIP data file now has none of the tags rules use, keeping the data in use");
        return false;
    }
    let mut fresh = manager.read().sharing_mmdb();
    let count = fresh.apply_parsed(parsed);
    let old = mem::replace(&mut *manager.write(), fresh);
    drop(old);
    info!(target = "geoip_watcher", path = %path.display(), loaded_count = count, "GeoIP data reloaded");
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
            assert!(reload_geosite_file(&geosite, &site, &site_tags));
            assert!(reload_geoip_file(&geoip, &ip, &ip_tags));
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

        std::thread::scope(|scope| {
            let reload = scope.spawn(|| reload_geosite_file(&manager, &last, &tags));
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
