use std::collections::{HashMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use notify::event::{AccessKind, AccessMode, EventKind, ModifyKind, RenameMode};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, WatcherKind};
use tracing::{debug, error, info};

use crate::config;
use crate::engine::Engine;

/// 文件写完以后（写的一方关上了它，或者改名到了位）再等这么久，把同一次保存的其它事件收齐：改名盖过目标文件时
/// notify 报一个「改名到这里」，再报一个同时列出两端的「改名」；证书和私钥前后脚换。
/// How long to wait once a file is written (its writer closed it, or it was renamed into
/// place), gathering the other events of the same save: a rename over the target is reported
/// as "renamed to" and again as a rename naming both ends; a certificate and its key are
/// replaced one right after the other.
const SETTLE: Duration = Duration::from_millis(50);

/// 看不出什么时候写完时（报不出关闭文件的平台，或者新建出来的），写入停了这么久才算写完
/// When the end of a write cannot be seen (a platform that does not report a file being
/// closed, or a file just created), writing counts as over once it has stopped this long
const QUIET: Duration = Duration::from_millis(300);

/// 一阵改动从第一个事件起最多等这么久：一直有人在写，也照样读一次 / A burst of changes is waited for
/// at most this long from its first event: a file written to without end is still read
const AT_MOST: Duration = Duration::from_secs(2);

/// 主配置文件的监视，读配置之前装好（见 `PendingWatch`）：读的时候文件又改了，这次改动排着队，[`ConfigWatch::start`]
/// 以后照样重载。以前读完配置、建好引擎才装监视，这中间的改动就丢了，内核一直用着旧配置，等下一次改动才跟上
/// The watch on the main configuration file, installed before the configuration is read (see
/// `PendingWatch`): a change made while it is read waits in line and is still reloaded after
/// [`ConfigWatch::start`]. The watch used to go in only once the configuration was read and the
/// engine built, and a change in between was lost, the kernel keeping the old configuration
/// until the next change
pub struct ConfigWatch {
    watch: PendingWatch,
    /// 读之前配置文件什么样（见 [`ConfigWatch::start_reporting`]）/ What the configuration file
    /// looked like before it was read (see [`ConfigWatch::start_reporting`])
    before_read: Option<FileStamp>,
}

impl ConfigWatch {
    /// 开始监视配置文件 `path`，在读它之前调用 / Starts watching the configuration file `path`;
    /// call it before reading the file
    pub fn new(path: &Path) -> notify::Result<Self> {
        let watch = PendingWatch::new(&[path.to_path_buf()], "changes there are not reloaded")?;
        let before_read = FileStamp::of(path).ok();
        Ok(Self { watch, before_read })
    }

    /// 配置文件每改一次（开始之前排着的也算）就照着它重载 `engine`，直到返回的 [`FileWatch`] 被丢掉。`read` 是启动时
    /// 读到的配置文本（见 [`ConfigWatch::start_reporting`]）
    /// Reloads `engine` from the configuration file on every change to it (those queued before
    /// the start included), until the returned [`FileWatch`] is dropped. `read` is the
    /// configuration text startup read (see [`ConfigWatch::start_reporting`])
    pub fn start(self, engine: Engine, read: String) -> notify::Result<FileWatch> {
        self.start_reporting(engine, read, |_| {})
    }

    /// 同 [`ConfigWatch::start`]，监视得怎样交给 `on_watch`：为什么有位置监视不上，都监视上了是 None。开始时报一次装的
    /// 时候的（见 [`PendingWatch::uncovered`]），之后每次重载之前文件重新解析、监视跟着换，再报一次（见
    /// [`PendingWatch::start_reporting`]）
    ///
    /// 头一次重载之前，文件还是启动时读它之前的样子（见 [`FileStamp`]）、内容也和启动时读到的 `read` 一字不差时不重载：
    /// 内核用的就是它。macOS 的 FSEvents 会把装监视之前不久的写入报给刚装上的监视，同一份配置就会在启动以后又重载一次，
    /// 配置里有问题时还多记一条重载失败。一字不差地再存一次照样重载（让重载重读 MMDB、监视不了的 Geo 文件），存过以后
    /// 修改时间就变了；修改时间只精确到秒的文件系统上，同一秒里改成一样长的别的内容，靠内容看得出来
    /// As [`ConfigWatch::start`], with how the file is watched going to `on_watch`: why some of
    /// its places cannot be watched, None when every one is. It is reported once at the start, as
    /// installed (see [`PendingWatch::uncovered`]), and again before each reload, as the file is
    /// resolved again with the watches following (see [`PendingWatch::start_reporting`])
    ///
    /// Until the first reload, the file still looking as it did before startup read it (see
    /// [`FileStamp`]) and holding word for word the `read` startup got is not reloaded: it is
    /// what the kernel runs. macOS's FSEvents reports a write made shortly before the watch was
    /// installed to the watch just installed, and the same configuration would be reloaded once
    /// more after startup, a failed reload logged besides for a configuration with a problem.
    /// Saved again word for word it is reloaded all the same (making the reload read the MMDB or
    /// Geo files that cannot be watched again), the save changing its modification time; on a
    /// file system keeping that time to the second, other content of the same length written
    /// within that second is told by the content
    pub fn start_reporting(
        self,
        engine: Engine,
        read: String,
        mut on_watch: impl FnMut(Option<&notify::Error>) + Send + 'static,
    ) -> notify::Result<FileWatch> {
        let Self { watch, before_read } = self;
        let mut as_read = before_read.map(|stamp| (stamp, read));
        on_watch(watch.uncovered().next().map(|(_, err)| err));
        watch
            .start_reporting("config-watcher", move |path| {
                let loaded = config::load_config_with_source(path);
                if as_read.as_ref().is_some_and(|(stamp, read)| {
                    FileStamp::of(path).is_ok_and(|now| now == *stamp)
                        && loaded.as_ref().is_ok_and(|(_, raw)| raw == read)
                }) {
                    debug!(path = %path.display(), "config file as read at startup, not reloaded");
                    return;
                }
                as_read = None;
                // 启动时只记错误、照样加载的那些写法，重载时拒绝（见 config::compile）
                // What startup only logs as errors and loads all the same, a reload refuses (see
                // config::compile)
                let loaded = loaded.and_then(|(cfg, raw)| {
                    let version = cfg.version.clone();
                    config::compile(cfg).map(|cfg| (cfg, raw, version))
                });
                match loaded {
                    Ok((new_cfg, raw, version)) => {
                        engine.reload_from(new_cfg, path, &raw);
                        info!(path = %path.display(), version, "config reloaded");
                    }
                    // 默认日志级别是 error：记成 warn 的话，没开面板时重载失败谁也看不到
                    // The default log level is error: logged as a warn, a failed reload would go
                    // unseen without the panel
                    Err(err) => {
                        error!(path = %path.display(), error = %format!("{err:#}"), "config reload failed, keeping current state");
                        engine.notify_config_reload_failed(path, &err);
                    }
                }
            }, move |_, watched| on_watch(watched))
            .map_err(notify::Error::io)
    }
}

/// 一个文件的路径、长度和修改时间：三样都没变，就当内容没变。记下文件读之前什么样：监视报来的改动是不是还是读到的那份
/// （见 [`ConfigWatch`]），监视看不全的文件（MMDB、有位置监视不上的 Geo 数据文件）换没换样子
/// A file's path, length and modification time: with all three unchanged, its content counts
/// as unchanged. It notes what a file looked like before it was read: whether a change the
/// watch reports is still what was read (see [`ConfigWatch`]), and whether a file the watch
/// does not wholly see (the MMDB, Geo data files with places that cannot be watched) looks
/// otherwise
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileStamp {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
}

impl FileStamp {
    pub(crate) fn of(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }

    /// 是哪个文件 / Which file it is
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// 已经装好、还没开始处理的文件监视：这期间的变化先排队，[`PendingWatch::start`] 以后再交给回调。
/// 先装好监视再读文件，读的时候文件又变了也不会漏掉。
/// A file watch that is installed but not yet handling changes: changes queue meanwhile and
/// reach the callback after [`PendingWatch::start`]. Installing the watch before reading the
/// files means a change made while they are being read is not missed.
pub(crate) struct PendingWatch {
    watcher: RecommendedWatcher,
    targets: Targets,
    /// 装的时候有位置监视不上的文件，和为什么（见 [`PendingWatch::uncovered`]）/ The files with places
    /// that could not be watched when installed, and why (see [`PendingWatch::uncovered`])
    uncovered: Uncovered,
    /// 监视不上的地方改了会怎样（见 [`PendingWatch::new`]）/ What becomes of a change where the
    /// watch cannot see (see [`PendingWatch::new`])
    unseen: &'static str,
    tx: Sender<Message>,
    rx: Receiver<Message>,
}

impl PendingWatch {
    /// 开始监视 `paths`（见 [`Targets`]）。`unseen` 说监视不上的地方改了会怎样，比如 "a renewal there is not used
    /// until restart"：装的时候有位置监视不上的文件（见 [`PendingWatch::uncovered`]），和开始以后文件改了指向、新的
    /// 地方监视不上的（见 [`PendingWatch::start_reporting`]），各记一条带着它的 error
    /// Starts watching `paths` (see [`Targets`]). `unseen` tells what becomes of a change where
    /// the watch cannot see, "a renewal there is not used until restart", say: a file with
    /// places that cannot be watched as it is installed (see [`PendingWatch::uncovered`]), or
    /// once it comes to lead somewhere that cannot be after the start (see
    /// [`PendingWatch::start_reporting`]), is logged as an error carrying it
    pub(crate) fn new(paths: &[PathBuf], unseen: &'static str) -> notify::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let events = tx.clone();
        let (watcher, targets, uncovered) = Targets::watch(paths, move |event| {
            let _ = events.send(Message::Event(event));
        })?;
        for (path, err) in &uncovered {
            error!(path = %path.display(), error = %err, "cannot watch every place the file leads, {unseen}");
        }
        Ok(Self {
            watcher,
            targets,
            uncovered,
            unseen,
            tx,
            rx,
        })
    }

    /// 装的时候有位置监视不上的文件（一处都没监视上的也算）：配置里写的路径，和为什么（这个监视看不到那里的变化）。比如
    /// 符号链接指向的目录还不存在：链接所在的目录监视着，链接换了指向看得到，目录建好以后里面的文件出现了却看不到。开始
    /// 以后文件重新解析时监视得怎样经 [`PendingWatch::start_reporting`] 的 `on_watch` 报
    /// The files with places that could not be watched when installed (those watched nowhere
    /// included): the path as configured, and why (the watch does not see changes there). A
    /// symlink into a directory not there yet, say: the link's directory is watched, so the
    /// link pointing elsewhere is seen, yet once the directory is made the file showing up in
    /// it is not. How a file is watched as it is resolved again after the start goes to
    /// `on_watch` of [`PendingWatch::start_reporting`]
    pub(crate) fn uncovered(&self) -> impl Iterator<Item = (&Path, &notify::Error)> {
        self.uncovered
            .iter()
            .map(|(path, err)| (path.as_path(), err))
    }

    /// 在名为 `name` 的线程上把每次变化交给 `on_change`，参数是配置里写的那个路径，直到返回的
    /// [`FileWatch`] 被丢掉
    /// Hands every change to `on_change` on a thread named `name`, passing the path as it was
    /// configured, until the returned [`FileWatch`] is dropped
    pub(crate) fn start(
        self,
        name: &str,
        on_change: impl FnMut(&Path) + Send + 'static,
    ) -> std::io::Result<FileWatch> {
        self.start_reporting(name, on_change, |_, _| {})
    }

    /// 同 [`PendingWatch::start`]，每次回调之前文件重新解析、监视跟着换以后，把它监视得怎样交给 `on_watch`：参数是
    /// 配置里写的路径，和它新的位置为什么监视不上（这个监视看不到那里的变化；这时也记一条 error），都监视上了是 None。
    /// 开始之前监视得怎样见 [`PendingWatch::uncovered`]
    /// As [`PendingWatch::start`], and each time a file is resolved again before its callback,
    /// with the watches following, how it is watched goes to `on_watch`: the path as configured,
    /// and why its new places cannot be watched (the watch does not see changes there; an error
    /// is logged too), None when every one is. How it is watched before the start, see
    /// [`PendingWatch::uncovered`]
    pub(crate) fn start_reporting(
        self,
        name: &str,
        mut on_change: impl FnMut(&Path) + Send + 'static,
        mut on_watch: impl FnMut(&Path, Option<&notify::Error>) + Send + 'static,
    ) -> std::io::Result<FileWatch> {
        let Self {
            watcher,
            targets,
            unseen,
            tx,
            rx,
            ..
        } = self;
        info!(name, files = ?targets.configured(), "file watcher started (watching parent directories for atomic replacement support)");
        let name = name.to_owned();
        let thread = thread::Builder::new().name(name.clone()).spawn(move || {
            // 监视随线程一起结束 / The watch ends with the thread
            let (mut watcher, mut targets) = (watcher, targets);
            pump(
                &name,
                unseen,
                &mut watcher,
                &mut targets,
                &rx,
                &mut on_change,
                &mut on_watch,
            );
        })?;
        Ok(FileWatch {
            stop: tx,
            thread: Some(thread),
        })
    }
}

/// 在自己线程上运行的文件监视。丢掉时停下线程并等它结束：正在处理的那次变化先处理完，此后回调
/// 不会再被调用。
/// A file watch running on a thread of its own. Dropping it stops the thread and waits for it
/// to end: a change being handled is finished first, and the callback is not called again.
pub struct FileWatch {
    stop: Sender<Message>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for FileWatch {
    fn drop(&mut self) {
        let _ = self.stop.send(Message::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

enum Message {
    Event(notify::Result<notify::Event>),
    Stop,
}

/// 被监视的文件。每个文件经它所在的目录监视，原子替换（写好临时文件再 rename 盖过去）也能察觉：
/// Linux inotify 监视的是 inode 而不是路径，目录能收到目标文件名的 IN_MOVED_TO/IN_CREATE。
/// 路径经过符号链接时，路上每个符号链接所在的目录和真文件所在的目录都监视（见 [`watch_points`]），
/// 链接指向别的目录、Kubernetes 卷换 `..data` 这样的变化也能察觉；有变化时重新解析，监视跟着换。
/// 在监视的目录自己删掉、改名挪走时，用到它的文件也重新解析（见 [`Targets::lost`]）。
/// 事件按完整路径对上文件，另一个被监视的目录里同名的文件不算。
/// The watched files. Each file is watched through its directory so atomic replacement
/// (write tmp + rename over target) is detected: Linux inotify watches inodes, not paths, and
/// the directory captures IN_MOVED_TO/IN_CREATE for the target filename. When the path goes
/// through symlinks, the directory of every symlink along the way and that of the real file
/// are watched too (see [`watch_points`]), so a link to another directory, or a Kubernetes
/// volume swapping `..data`, is detected as well; on a change the path is resolved again and
/// the watches follow. A watched directory itself removed or renamed away has the files using
/// it resolved again too (see [`Targets::lost`]). Events are matched to files by full path, so
/// a file of the same name in another watched directory does not count.
struct Targets {
    files: Vec<Target>,
    /// 在监视的目录，以及各被几个监视点用着 / The directories watched, and how many watch points use each
    dirs: HashMap<PathBuf, usize>,
}

/// 一个被监视的文件 / One watched file
struct Target {
    /// 配置里写的路径 / The path as configured
    configured: PathBuf,
    /// 它的变化出现在哪些路径的事件里（见 [`watch_points`]）/ The paths its changes show up under in events (see [`watch_points`])
    points: Vec<PathBuf>,
    /// 替它记着数的目录（见 [`Targets::dirs`]）：监视点所在的目录里监视上了的，每个监视点一项，没了的不算（见
    /// [`Targets::lost`]）。撤它的监视时只减这些，没替它监视上的目录不减：那个目录后来替它或别的文件监视上了，记的数是
    /// 后来那些的
    /// The directories counted for it (see [`Targets::dirs`]): those of its watch points'
    /// directories that went in, one per watch point, less those gone (see [`Targets::lost`]).
    /// Its watches come out by these alone, never by a directory that did not go in for it:
    /// watched later, for it or another file, that directory's count is theirs
    held: Vec<PathBuf>,
}

/// 有位置监视不上的文件：配置里写的路径，和为什么 / The files with places that cannot be watched:
/// the path as configured, and why
type Uncovered = Vec<(PathBuf, notify::Error)>;

impl Targets {
    /// 监视 `paths`，事件交给 `handler`，并给出有监视点所在的目录监视不了的文件和为什么，一个都监视不了的也在里面（它
    /// 哪儿都没监视上，同一个监视里别的文件照常监视）。只有建不起监视、解析不了路径时报错
    /// Watches `paths`, sending events to `handler`, and gives the files with a watch point
    /// directory that cannot be watched, and why, those with none that can included (watched
    /// nowhere, the other files of the watch being watched as usual). An error only when the
    /// watcher cannot be made or a path cannot be resolved
    fn watch(
        paths: &[PathBuf],
        handler: impl notify::EventHandler,
    ) -> notify::Result<(RecommendedWatcher, Self, Uncovered)> {
        let mut watcher = RecommendedWatcher::new(handler, Config::default())?;
        let mut targets = Self {
            files: Vec::with_capacity(paths.len()),
            dirs: HashMap::new(),
        };
        let mut uncovered = Vec::new();
        for path in paths {
            if targets
                .files
                .iter()
                .any(|target| target.configured == *path)
            {
                continue;
            }
            let points = watch_points(path).map_err(notify::Error::io)?;
            let (held, first_error) = targets.hold(&mut watcher, &points);
            if let Some(err) = first_error {
                uncovered.push((path.clone(), err));
            }
            targets.files.push(Target {
                configured: path.clone(),
                points,
                held,
            });
        }
        Ok((watcher, targets, uncovered))
    }

    /// 监视 `points` 所在的目录，给出监视上了的（见 [`Target::held`]），和第一个监视不上的为什么
    /// Watches the directories of `points`, giving those that went in (see [`Target::held`]),
    /// and why the first that did not
    fn hold(
        &mut self,
        watcher: &mut RecommendedWatcher,
        points: &[PathBuf],
    ) -> (Vec<PathBuf>, Option<notify::Error>) {
        let mut held = Vec::with_capacity(points.len());
        let mut first_error = None;
        for dir in points.iter().filter_map(|point| point.parent()) {
            match self.add_dir(watcher, dir) {
                Ok(()) => held.push(dir.to_path_buf()),
                Err(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }
        (held, first_error)
    }

    /// 多一个监视点用 `dir`，头一个时开始监视它 / One more watch point uses `dir`; the first starts watching it
    fn add_dir(&mut self, watcher: &mut RecommendedWatcher, dir: &Path) -> notify::Result<()> {
        if let Some(count) = self.dirs.get_mut(dir) {
            *count += 1;
            return Ok(());
        }
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
        self.dirs.insert(dir.to_path_buf(), 1);
        Ok(())
    }

    /// 少一个监视点用 `dir`，没有了就不再监视。目录已经删掉时 notify 报错，不用管
    /// One watch point fewer uses `dir`; with none left it is no longer watched. notify
    /// errs when the directory is gone already, which needs no handling
    fn remove_dir(&mut self, watcher: &mut RecommendedWatcher, dir: &Path) {
        if let Some(count) = self.dirs.get_mut(dir) {
            *count -= 1;
            if *count == 0 {
                self.dirs.remove(dir);
                let _ = watcher.unwatch(dir);
            }
        }
    }

    /// 文件 `index` 重新解析一遍，监视换到新的监视点所在的目录。解析不了（监视留在原处），或者有监视点所在的目录
    /// 监视不上时报错：这个监视看不到那里的变化
    /// Resolves file `index` again and moves the watches to the directories of its new watch
    /// points. An error when it cannot be resolved (the watches staying where they were), or a
    /// watch point's directory cannot be watched: the watch does not see changes there
    fn refresh(&mut self, watcher: &mut RecommendedWatcher, index: usize) -> notify::Result<()> {
        let points = watch_points(&self.files[index].configured).map_err(notify::Error::io)?;
        // 先装新的再撤旧的，两边都用着的目录不会断开 / The new watches go in before the old come out,
        // so a directory both use is never dropped
        let (held, uncovered) = self.hold(watcher, &points);
        let target = &mut self.files[index];
        target.points = points;
        let old = std::mem::replace(&mut target.held, held);
        for dir in &old {
            self.remove_dir(watcher, dir);
        }
        uncovered.map_or(Ok(()), Err)
    }

    /// 在监视的目录里 `gone` 说没了的（见 [`gone`]）不再监视、不再记数，给出替它们记着数的文件（见 [`Target::held`]）：
    /// 这些文件重新解析时，目录回来了就重新监视，没回来就是监视不上。监视总要撤：inotify 的监视跟着改名挪走的旧目录走，
    /// 事件却还按原来的路径报；删掉的目录 inotify、kqueue 已经撤了，再撤只是报错；FSEvents 按路径监视，撤了和别的平台
    /// 一样。notify 监视着的目录就总是这里记着的那些
    /// Those of the watched directories that `gone` names (see [`gone`]) are watched and
    /// counted no more, giving the files they were counted for (see [`Target::held`]): resolved
    /// again, these are watched there anew once the directory is back, and cannot be watched
    /// there if not. The watch always comes out: inotify's follows a directory renamed away, its
    /// events still reported under the old path; inotify and kqueue have taken out a removed
    /// directory's already, so this only errs; FSEvents watches by path, and with it out
    /// behaves as the others. So the directories notify watches are always those counted here
    fn lost(&mut self, watcher: &mut RecommendedWatcher, gone: &[PathBuf]) -> Vec<usize> {
        let mut files = Vec::new();
        for dir in gone {
            if self.dirs.remove(dir).is_none() {
                continue;
            }
            // notify 已经撤了的报错，不用管 / notify errs for one it has taken out, which needs no handling
            let _ = watcher.unwatch(dir);
            for (index, target) in self.files.iter_mut().enumerate() {
                let counted = target.held.len();
                target.held.retain(|held| held != dir);
                if target.held.len() != counted && !files.contains(&index) {
                    files.push(index);
                }
            }
        }
        files
    }

    /// 配置里写的路径，按文件的顺序，记日志用 / The paths as configured, in the files' order, for
    /// the log
    fn configured(&self) -> Vec<&Path> {
        self.files
            .iter()
            .map(|target| target.configured.as_path())
            .collect()
    }

    /// 监视点在 `paths` 里的文件 / The files with a watch point among `paths`
    fn named<'a>(&'a self, paths: &'a [PathBuf]) -> impl Iterator<Item = usize> + 'a {
        self.files
            .iter()
            .enumerate()
            .filter(|(_, target)| paths.iter().any(|path| target.points.contains(path)))
            .map(|(index, _)| index)
    }
}

/// 一个事件给它说到的文件带来的变化 / The change an event brings to the files it names
#[derive(Clone, Copy, Debug, PartialEq)]
enum Change {
    /// 写完了：写着的文件关上了，或者别的文件改名到了这里 / Written: a file open for writing was
    /// closed, or another file was renamed here
    Written,
    /// 正写着 / Being written
    Writing,
    /// 新出现的：可能接着写，也可能就这样了（一个链接）/ Newly there: writes may follow, or not (a link)
    Created,
}

impl Change {
    /// 事件带来的变化，和它落在哪些路径上。内容不变的不算：读、改属性（chmod、chown）、删掉、改名挪走
    /// The change an event brings, and the paths it lands on. What leaves the content as it
    /// was does not count: a read, a metadata change (chmod, chown), a removal, a rename away
    fn of(event: &notify::Event) -> Option<(Self, &[PathBuf])> {
        let change = match event.kind {
            EventKind::Access(AccessKind::Close(AccessMode::Write)) => Self::Written,
            // 两端都列出来的改名只算到达的那头 / A rename naming both ends counts at its arrival only
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                return Some((Self::Written, event.paths.get(1..)?));
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::From) | ModifyKind::Metadata(_)) => {
                return None;
            }
            EventKind::Modify(ModifyKind::Name(_)) => Self::Written,
            EventKind::Modify(_) => Self::Writing,
            EventKind::Create(_) => Self::Created,
            _ => return None,
        };
        Some((change, &event.paths))
    }

    /// 这之后多久没有新动静，文件就算改完了。`close_reported`：平台报得出写的一方什么时候关上文件
    /// （Linux 的 inotify），这时写着的文件等它关上，别的平台只能看写入停了多久
    /// How long without news after it the file counts as done changing. `close_reported`: the
    /// platform reports when the writer closes the file (inotify on Linux), and a file being
    /// written waits for that; elsewhere only how long writing has stopped tells
    fn settle(self, close_reported: bool) -> Duration {
        match self {
            Self::Written => SETTLE,
            Self::Writing if close_reported => AT_MOST,
            Self::Writing | Self::Created => QUIET,
        }
    }
}

/// 事件说没了的路径：删掉的，改名挪走的（两端都列出来的改名是头一个）。说不出是哪头的改名（kqueue、FSEvents）也算：
/// 那里的已经不是原来那个了
/// The paths an event says are gone: removed, or renamed away (the first of a rename naming
/// both ends). A rename not telling which end it is (kqueue, FSEvents) counts too: what is
/// there is no longer what was
fn gone(event: &notify::Event) -> &[PathBuf] {
    match event.kind {
        EventKind::Remove(_)
        | EventKind::Modify(ModifyKind::Name(RenameMode::From | RenameMode::Any)) => &event.paths,
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            event.paths.get(..1).unwrap_or_default()
        }
        _ => &[],
    }
}

/// 一阵改动：从第一个事件起，等到改了的文件都安静下来，最多等 [`AT_MOST`]
/// A burst of changes: from its first event until every file changed has settled, at most [`AT_MOST`]
struct Burst {
    since: Instant,
    /// 改了的文件，和它什么时候安静下来 / The files changed, and when each settles
    files: Vec<(usize, Instant)>,
}

impl Burst {
    fn new(since: Instant) -> Self {
        Self {
            since,
            files: Vec::new(),
        }
    }

    /// 文件 `index` 又有了动静，到 `settles` 才安静下来 / File `index` changed again and settles at `settles`
    fn note(&mut self, index: usize, settles: Instant) {
        match self.files.iter_mut().find(|(file, _)| *file == index) {
            Some((_, at)) => *at = settles,
            None => self.files.push((index, settles)),
        }
    }

    /// 什么时候回调 / When to call back
    fn due(&self) -> Instant {
        let settled = self.files.iter().map(|&(_, at)| at).max();
        settled.unwrap_or(self.since).min(self.since + AT_MOST)
    }
}

/// 符号链接最多跟这么多层，再多（比如链接绕成圈）就停下 / At most this many symlinks are followed;
/// past that (a loop of links, say) resolution stops
const MAX_SYMLINKS: usize = 40;

/// `path` 的变化会出现在哪些路径的事件里：路上每个符号链接所在的位置，和最后的那个文件（不存在也算）。
/// 每段都解析掉符号链接，所以每个位置都是「真目录 + 名字」，监视那个目录时 notify 报的就是它，按这个对得上。
/// The paths `path`'s changes show up under in events: where every symlink along the way
/// sits, and the file it ends at (whether or not it exists). Every component has its
/// symlinks resolved, so each is a real directory plus a name, which is what notify reports
/// when that directory is watched, and events match on it.
fn watch_points(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let part = |component: Component<'_>| PathBuf::from(component.as_os_str());
    let mut pending: VecDeque<PathBuf> = absolute.components().map(part).collect();
    let mut resolved = PathBuf::new();
    let mut points = Vec::new();
    let mut links = 0;
    while let Some(next) = pending.pop_front() {
        match next.components().next() {
            Some(Component::Prefix(_) | Component::RootDir) => resolved.push(&next),
            Some(Component::ParentDir) => {
                resolved.pop();
            }
            Some(Component::Normal(name)) => {
                let candidate = resolved.join(name);
                let target = (links < MAX_SYMLINKS)
                    .then(|| std::fs::read_link(&candidate).ok())
                    .flatten();
                match target {
                    Some(target) => {
                        links += 1;
                        points.push(candidate);
                        // 相对的目标接在链接所在的目录后面；绝对的目标第一段是根（Windows 上是盘符），
                        // push 它会换掉整个路径，从根开始
                        // A relative target goes on from the link's directory; an absolute one
                        // starts with the root (the drive on Windows), and pushing that replaces
                        // the whole path, starting over from the root
                        for component in target.components().rev() {
                            pending.push_front(part(component));
                        }
                    }
                    None => {
                        if pending.is_empty() {
                            points.push(candidate.clone());
                        }
                        resolved = candidate;
                    }
                }
            }
            Some(Component::CurDir) | None => {}
        }
    }
    Ok(points)
}

/// 把变化交给 `on_change`，直到收到停止消息或通道关闭。一阵改动等到改了的文件都写完（见 [`Change::settle`]）、
/// 最多 [`AT_MOST`]，每个文件重新解析、监视跟着换，监视得怎样交给 `on_watch`（见 [`PendingWatch::start_reporting`]），
/// 再各回调一次。在监视的目录删掉、改名挪走时，用到它的文件也算改了（见 [`Targets::lost`]）。记的日志带着监视的名字
/// `name` 和它的文件，看得出是哪个监视；文件改了指向、新的地方监视不上时记的那条带着 `unseen`（见 [`PendingWatch::new`]）
/// Hands changes to `on_change` until told to stop or the channel closes. A burst of changes
/// is waited for until every file changed is written (see [`Change::settle`]), at most
/// [`AT_MOST`]; then each file is resolved again with the watches following, how it is watched
/// goes to `on_watch` (see [`PendingWatch::start_reporting`]), and it is called back once. A
/// watched directory removed or renamed away counts as a change to the files using it (see
/// [`Targets::lost`]). What it logs carries the watch's `name` and its files, telling which
/// watch it is; a file coming to lead somewhere that cannot be watched is logged with `unseen`
/// (see [`PendingWatch::new`])
fn pump(
    name: &str,
    unseen: &str,
    watcher: &mut RecommendedWatcher,
    targets: &mut Targets,
    rx: &Receiver<Message>,
    mut on_change: impl FnMut(&Path),
    mut on_watch: impl FnMut(&Path, Option<&notify::Error>),
) {
    let close_reported = RecommendedWatcher::kind() == WatcherKind::Inotify;
    let mut burst: Option<Burst> = None;
    loop {
        let message = match &burst {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(burst) => rx.recv_timeout(burst.due().saturating_duration_since(Instant::now())),
        };
        match message {
            // 漏了事件（比如 inotify 的队列满了）时 notify 报一个不带路径的 Rescan：什么都可能改过，每个文件都当写完了
            // When events were missed (inotify's queue overflowing, say) notify reports a Rescan
            // naming no path: anything may have changed, and every file counts as written
            Ok(Message::Event(Ok(event))) if event.need_rescan() => {
                error!(name, files = ?targets.configured(), "the file watcher missed events, reading every watched file again");
                // 漏掉的事件里可能有在监视的目录没了：监视全部撤掉，回调之前各文件重新解析时再装上
                // The events missed may include a watched directory going away: every watch
                // comes out, to go in again as each file is resolved again before its callback
                let dirs: Vec<PathBuf> = targets.dirs.keys().cloned().collect();
                targets.lost(watcher, &dirs);
                let now = Instant::now();
                let burst = burst.get_or_insert_with(|| Burst::new(now));
                for index in 0..targets.files.len() {
                    burst.note(index, now + Change::Written.settle(close_reported));
                }
            }
            Ok(Message::Event(Ok(event))) => {
                // 在监视的目录没了的，用到它的文件重新解析（见 `Targets::lost`）。目录可能马上重建、文件跟着写进来，和
                // 新出现的文件一样等写入停下
                // For a watched directory gone, the files using it are resolved again (see
                // `Targets::lost`). The directory may be made again at once, the file written
                // into it: waited for as a file newly there is
                let lost = targets.lost(watcher, gone(&event));
                let lost = lost.into_iter().map(|index| (index, Change::Created));
                let named = Change::of(&event).into_iter().flat_map(|(change, paths)| {
                    targets.named(paths).map(move |index| (index, change))
                });
                let now = Instant::now();
                for (index, change) in lost.chain(named) {
                    burst
                        .get_or_insert_with(|| Burst::new(now))
                        .note(index, now + change.settle(close_reported));
                }
            }
            // 出了错，改动可能就看不到了；默认日志级别是 error，记成 warn 谁也看不到 / After an error
            // changes may go unseen; the default log level is error, and a warn would show nowhere
            Ok(Message::Event(Err(err))) => {
                error!(name, files = ?targets.configured(), error = %err, "file watcher error, changes may go unseen");
            }
            // 只有一阵改动在等时才会超时 / Only a burst being waited for times out
            Err(RecvTimeoutError::Timeout) => {
                for (index, _) in burst.take().into_iter().flat_map(|burst| burst.files) {
                    // 先跟上新的解析结果再回调：回调读文件时，新位置上的变化已经在监视之下
                    // The watches follow the new resolution before the callback: by the time it
                    // reads the file, changes at the new places are being watched
                    let watched = targets.refresh(watcher, index);
                    let configured = &targets.files[index].configured;
                    if let Err(err) = &watched {
                        error!(name, path = %configured.display(), error = %err, "cannot watch the file where it now leads, {unseen}");
                    }
                    on_watch(configured, watched.as_ref().err());
                    on_change(configured);
                }
            }
            Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试里监视不上的地方改了会怎样（见 [`PendingWatch::new`]）/ What becomes of a change where a
    /// test's watch cannot see (see [`PendingWatch::new`])
    const UNSEEN: &str = "changes there go unseen in this test";

    /// 监视装好、还没开始处理时文件变了，开始处理以后这次变化照样交给回调
    /// A change made after the watch is installed but before it starts handling changes
    /// still reaches the callback once it starts
    #[test]
    fn a_change_while_pending_reaches_the_callback_after_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let pending = PendingWatch::new(std::slice::from_ref(&target), UNSEEN).expect("watch");
        std::fs::write(&target, "v2").expect("change file");
        let (tx, rx) = mpsc::channel();
        let _watch = pending
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok(),
            Some(target),
            "the queued change must reach the callback, under the configured path"
        );
    }

    /// 丢掉 [`FileWatch`] 以后线程已经结束，文件再变也不会调用回调
    /// Once a [`FileWatch`] is dropped its thread has ended, and further changes do not
    /// call the callback
    #[test]
    fn a_dropped_watch_calls_back_no_more() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = mpsc::channel();
        let watch = PendingWatch::new(std::slice::from_ref(&target), UNSEEN)
            .expect("watch")
            .start("test-watch", move |_| {
                let _ = tx.send(());
            })
            .expect("start");
        drop(watch);

        std::fs::write(&target, "v2").expect("change file");
        // 线程结束时回调连同发送端一起被释放，通道随之断开
        // The callback, and the sender with it, is freed when the thread ends, which
        // disconnects the channel
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }

    /// 事件按完整路径对上文件：另一个被监视目录里的同名文件变了不算
    /// Events are matched by full path: a file of the same name changing in another watched
    /// directory does not count
    #[test]
    fn a_same_named_file_in_another_watched_directory_does_not_count() {
        let first = tempfile::tempdir().expect("tempdir");
        let second = tempfile::tempdir().expect("tempdir");
        let target = first.path().join("data.file");
        let other = second.path().join("other.file");
        std::fs::write(&target, "v1").expect("seed file");
        std::fs::write(&other, "v1").expect("seed file");

        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(&[target.clone(), other.clone()], UNSEEN)
            .expect("watch")
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        std::fs::write(second.path().join("data.file"), "unrelated").expect("write namesake");
        std::fs::write(&other, "v2").expect("change file");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok(),
            Some(other),
            "only the configured file may be reported"
        );
    }

    /// 相对路径也按 notify 报告的完整路径对上（它把相对路径接在当前目录后面）
    /// A relative path is matched too, by the full path notify reports (it joins a relative
    /// path onto the current directory)
    #[test]
    fn a_relative_path_is_matched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");
        // 从当前目录一路 .. 到根，再接上目标的绝对路径 / .. up from the current directory to the root, then the target's absolute path
        let current_dir = std::env::current_dir().expect("current dir");
        let up: PathBuf = current_dir.components().skip(1).map(|_| "..").collect();
        let relative = up.join(target.strip_prefix("/").expect("absolute temp dir"));
        assert!(relative.is_relative());

        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&relative), UNSEEN)
            .expect("watch")
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        std::fs::write(&target, "v2").expect("change file");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok(),
            Some(relative),
            "the change must be reported under the configured relative path"
        );
    }

    /// 改名盖过目标文件只回调一次。notify 为这一次改名报两个事件（「改名到这里」和列出两端的
    /// 「改名」），此前每个都回调，面板的每次保存都让配置完整重载两遍。
    /// Renaming over the target calls back once. notify reports two events for that one
    /// rename ("renamed to" and a rename naming both ends), and each used to call back, so
    /// every save from the panel reloaded the configuration twice.
    #[test]
    fn an_atomic_replacement_calls_back_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&target), UNSEEN)
            .expect("watch")
            .start("test-watch", move |_| {
                let _ = tx.send(());
            })
            .expect("start");

        let tmp = dir.path().join("target.renew.tmp");
        std::fs::write(&tmp, "v2").expect("write tmp");
        std::fs::rename(&tmp, &target).expect("atomic rename");
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the replacement is called back");
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "one replacement, one call back"
        );
    }

    /// 事件按内容有没有变归类：关上写着的文件、改名到这里算写完，写入算正写着，新建单算；读、改属性、删掉、
    /// 改名挪走都不算。两端都列出来的改名只算到达的那头
    /// Events are told apart by whether the content changed: a file open for writing closed,
    /// or one renamed here, is written; a write is being written; a creation is its own; a
    /// read, a metadata change, a removal and a rename away do not count. A rename naming both
    /// ends counts at its arrival only
    #[test]
    fn events_count_by_whether_the_content_changed() {
        use notify::event::{CreateKind, DataChange, MetadataKind, RemoveKind};
        let (from, to) = (PathBuf::from("/d/f.tmp"), PathBuf::from("/d/f"));
        let event = |kind| notify::Event::new(kind).add_path(to.clone());
        let change = |event: &notify::Event| Change::of(event).map(|(change, _)| change);
        let close = EventKind::Access(AccessKind::Close(AccessMode::Write));
        assert_eq!(change(&event(close)), Some(Change::Written));
        let renamed_to = EventKind::Modify(ModifyKind::Name(RenameMode::To));
        assert_eq!(change(&event(renamed_to)), Some(Change::Written));
        let written = EventKind::Modify(ModifyKind::Data(DataChange::Content));
        assert_eq!(change(&event(written)), Some(Change::Writing));
        assert_eq!(
            change(&event(EventKind::Create(CreateKind::File))),
            Some(Change::Created)
        );
        for unchanged in [
            EventKind::Access(AccessKind::Open(AccessMode::Any)),
            EventKind::Access(AccessKind::Close(AccessMode::Read)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            EventKind::Remove(RemoveKind::File),
        ] {
            assert_eq!(change(&event(unchanged)), None, "{unchanged:?}");
        }
        let both = notify::Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(from.clone())
            .add_path(to.clone());
        assert_eq!(
            Change::of(&both),
            Some((Change::Written, std::slice::from_ref(&to)))
        );
    }

    /// 事件说没了的路径：删掉的、改名挪走的，两端都列出来的改名是头一个，说不出是哪头的改名（kqueue、FSEvents）也算；
    /// 改名到达、新建、写入都不算
    /// The paths an event says are gone: removed, renamed away, the first of a rename naming
    /// both ends, and a rename not telling which end it is (kqueue, FSEvents) too; an arrival, a
    /// creation and a write are not
    #[test]
    fn events_tell_which_paths_are_gone() {
        use notify::event::{CreateKind, DataChange, RemoveKind};
        let (old, new) = (PathBuf::from("/d/geo"), PathBuf::from("/d/geo.new"));
        let event = |kind| notify::Event::new(kind).add_path(old.clone());
        for kind in [
            EventKind::Remove(RemoveKind::Folder),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            EventKind::Modify(ModifyKind::Name(RenameMode::Any)),
        ] {
            assert_eq!(gone(&event(kind)), std::slice::from_ref(&old), "{kind:?}");
        }
        for kind in [
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            EventKind::Create(CreateKind::Folder),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Access(AccessKind::Close(AccessMode::Write)),
        ] {
            assert_eq!(gone(&event(kind)), [] as [PathBuf; 0], "{kind:?}");
        }
        let both = notify::Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(old.clone())
            .add_path(new);
        assert_eq!(gone(&both), std::slice::from_ref(&old));
    }

    /// notify 漏了事件（比如 inotify 的队列满了）时报的 Rescan 不带路径：什么都可能改过，每个文件都回调一次，记一条
    /// error；notify 报的错也记 error，这两条带着监视的文件。重新解析以后有位置监视不上的文件（这里是所在的目录不在）
    /// 也记一条 error，带着它的路径和那里改了会怎样（见 [`PendingWatch::new`]）。每条都带着监视的名字：配置、GeoSite、
    /// GeoIP、DoH 证书各有一个监视，看得出是哪个
    /// The Rescan notify reports when events were missed (inotify's queue overflowing, say)
    /// names no path: anything may have changed, so every file is called back once and an
    /// error is logged; an error notify reports is logged as an error too, both carrying the
    /// watch's files. A file with places that cannot be watched once resolved again (here its
    /// directory is not there) logs an error too, carrying its path and what becomes of a change
    /// there (see [`PendingWatch::new`]). Each carries the watch's name: the configuration,
    /// GeoSite, GeoIP and the DoH certificate each have a watch, and which one it is shows
    #[test]
    fn a_rescan_calls_every_file_back_and_errors_are_logged() {
        use tracing_subscriber::layer::SubscriberExt as _;
        /// 记下的每条 error 的字段 / The fields of each error logged
        struct Errors(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Errors {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() == tracing::Level::ERROR {
                    let mut fields = String::new();
                    event.record(
                        &mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                            fields.push_str(&format!("{}={value:?} ", field.name()));
                        },
                    );
                    self.0.lock().unwrap().push(fields);
                }
            }
        }
        let dir = tempfile::tempdir().expect("tempdir");
        // 不建这些文件，免得真的事件也回调它们；最后一个所在的目录也不在 / The files are not created,
        // so that no real event calls them back too; the last one's directory is not there either
        let files = [
            dir.path().join("a.json"),
            dir.path().join("b.json"),
            dir.path().join("missing").join("c.json"),
        ];
        let PendingWatch {
            mut watcher,
            mut targets,
            tx,
            rx,
            ..
        } = PendingWatch::new(&files, UNSEEN).expect("watch");
        let rescan = notify::Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
        tx.send(Message::Event(Ok(rescan))).unwrap();
        tx.send(Message::Event(Err(notify::Error::generic("broken"))))
            .unwrap();
        // 一个都不回调时也停得下来 / Stops even when nothing is called back
        let stop = tx.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            let _ = stop.send(Message::Stop);
        });

        // 重新解析时记的那条，别的测试的监视线程也会碰到 / The one logged when resolving again is hit
        // by other tests' watch threads too
        crate::engine::test_support::callsites_ask_every_time();
        let errors = std::sync::Arc::default();
        let subscriber =
            tracing_subscriber::registry().with(Errors(std::sync::Arc::clone(&errors)));
        let mut called = Vec::new();
        tracing::subscriber::with_default(subscriber, || {
            pump(
                "test-watch",
                UNSEEN,
                &mut watcher,
                &mut targets,
                &rx,
                |path| {
                    called.push(path.to_path_buf());
                    if called.len() == files.len() {
                        let _ = tx.send(Message::Stop);
                    }
                },
                |_, _| {},
            );
        });
        called.sort();
        assert_eq!(called, files);
        let errors = errors.lock().unwrap();
        assert_eq!(errors.len(), 3, "{errors:#?}");
        for error in errors.iter() {
            assert!(error.contains("name=\"test-watch\""), "{error}");
        }
        for error in &errors[..2] {
            for file in &files {
                assert!(error.contains(&format!("{file:?}")), "{error}");
            }
        }
        let unwatched = format!("path={} ", files[2].display());
        assert!(errors[2].contains(&unwatched), "{}", errors[2]);
        assert!(errors[2].contains(UNSEEN), "{}", errors[2]);
    }

    /// 一阵改动等到每个文件都安静下来：写着的文件晚，其它文件早安静了也得等它；它写完了就按它的时刻；
    /// 怎么都不超过从第一个事件起的 AT_MOST
    /// A burst waits until every file has settled: a file still being written holds it back
    /// however early the others settle; once written, its moment counts; never past AT_MOST
    /// from the first event
    #[test]
    fn a_burst_is_due_once_every_file_has_settled_and_at_most_at_the_cap() {
        let ms = Duration::from_millis;
        let start = Instant::now();
        let mut burst = Burst::new(start);
        burst.note(0, start + Change::Writing.settle(true));
        burst.note(1, start + ms(10) + Change::Written.settle(true));
        assert_eq!(
            burst.due(),
            start + AT_MOST,
            "file 0 is still being written"
        );
        burst.note(0, start + ms(100) + Change::Written.settle(true));
        assert_eq!(
            burst.due(),
            start + ms(100) + SETTLE,
            "file 0 was closed at 100 ms"
        );
        burst.note(1, start + ms(1900) + Change::Created.settle(true));
        assert_eq!(burst.due(), start + AT_MOST, "never past the cap");
    }

    /// 分几次写进去的文件，写完才读：中间停一下也不会读到一半。报得出关闭文件的平台等它关上，中间停得比 QUIET
    /// 还久也一样；别的平台看写入停了多久。以前收到第一个事件 50 ms 后就读，读到前一半
    /// A file written in pieces is read once written: a pause in between does not get half of
    /// it read. Where closing the file is reported it is waited for, through a pause longer
    /// than QUIET too; elsewhere how long writing has stopped tells. The file used to be read
    /// 50 ms after the first event, getting its first half
    #[test]
    fn a_file_written_in_pieces_is_read_once_written() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = mpsc::channel();
        let read = target.clone();
        let _watch = PendingWatch::new(std::slice::from_ref(&target), UNSEEN)
            .expect("watch")
            .start("test-watch", move |_| {
                let _ = tx.send(std::fs::read_to_string(&read).unwrap_or_default());
            })
            .expect("start");

        let pause = if RecommendedWatcher::kind() == WatcherKind::Inotify {
            QUIET * 2
        } else {
            SETTLE * 3
        };
        let mut file = std::fs::File::create(&target).expect("open for writing");
        file.write_all(b"first half, ").expect("write");
        thread::sleep(pause);
        file.write_all(b"second half").expect("write");
        drop(file);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok().as_deref(),
            Some("first half, second half")
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "one write, one call back"
        );
    }

    /// 只改属性（chmod）不回调：内容没变，没有要重新读的。以前每次都重载。只在 Linux 上测：macOS 的 FSEvents
    /// 给这次 chmod 报的事件把此前新建、写入的标志也带上，分不出来
    /// A metadata change alone (chmod) calls nothing back: the content is as it was, with
    /// nothing to read again. Each used to reload. Tested on Linux only: for this chmod macOS
    /// FSEvents reports events carrying the earlier creation and write too, which cannot be
    /// told apart
    #[cfg(target_os = "linux")]
    #[test]
    fn a_metadata_change_calls_nothing_back() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&target), UNSEEN)
            .expect("watch")
            .start("test-watch", move |_| {
                let _ = tx.send(());
            })
            .expect("start");

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
    }

    /// 收到一次回调，报的是配置里写的路径 / One callback, reporting the path as configured
    #[cfg(unix)]
    fn called_back(rx: &Receiver<PathBuf>, configured: &Path, what: &str) {
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok().as_deref(),
            Some(configured),
            "{what}"
        );
        // 同一次改动的后续事件 / What else the same change brings
        while rx.recv_timeout(Duration::from_millis(200)).is_ok() {}
    }

    /// 符号链接指向别的目录里的文件：那个文件原地改写、在它自己的目录里被替换，都回调，报的是配置里写的路径。
    /// 以前只监视链接所在的目录，事件里没有这个路径，一次都不回调
    /// A symlink to a file in another directory: the file edited in place, or replaced in
    /// its own directory, is called back, under the path as configured. Only the link's
    /// directory used to be watched, whose events never name the path, so nothing was called
    /// back
    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_changed_in_its_own_directory_is_called_back() {
        let root = tempfile::tempdir().expect("tempdir");
        let (conf, real) = (root.path().join("conf"), root.path().join("real"));
        std::fs::create_dir_all(&conf).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("config.json"), "v1").unwrap();
        let configured = conf.join("config.json");
        std::os::unix::fs::symlink(real.join("config.json"), &configured).unwrap();

        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&configured), UNSEEN)
            .expect("watch")
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        std::fs::write(real.join("config.json"), "v2").unwrap();
        called_back(&rx, &configured, "the target edited in place");
        std::fs::write(real.join("config.json.tmp"), "v3").unwrap();
        std::fs::rename(real.join("config.json.tmp"), real.join("config.json")).unwrap();
        called_back(&rx, &configured, "the target replaced in its own directory");
        // 目标目录里别的文件不算 / Other files in the target's directory do not count
        std::fs::write(real.join("other.json"), "x").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
    }

    /// Kubernetes 的 ConfigMap、Secret 卷：`tls.crt` 链到 `..data/tls.crt`，`..data` 链到带时间戳的目录。更新时
    /// 写好新目录，把新的 `..data` 改名盖过旧的，再删掉旧目录。每次换都回调，换过以后新目录里的文件变了也回调。以前
    /// 证书续期后一直用旧证书，直到重启
    /// A Kubernetes ConfigMap or Secret volume: `tls.crt` links to `..data/tls.crt`, and
    /// `..data` to a timestamped directory. An update writes a new directory, renames a new
    /// `..data` over the old one and removes the old directory. Every swap is called back,
    /// and so is a change to the file in the new directory after it. A renewed certificate
    /// used to go unused until a restart
    #[cfg(unix)]
    #[test]
    fn a_kubernetes_style_volume_swap_is_called_back() {
        use std::os::unix::fs::symlink;
        let volume = tempfile::tempdir().expect("tempdir");
        let at = |name: &str| volume.path().join(name);
        std::fs::create_dir(at("..2026_11_10_a")).unwrap();
        std::fs::write(at("..2026_11_10_a/tls.crt"), "first").unwrap();
        symlink("..2026_11_10_a", at("..data")).unwrap();
        symlink("..data/tls.crt", at("tls.crt")).unwrap();
        let configured = at("tls.crt");

        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&configured), UNSEEN)
            .expect("watch")
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        let swap = |from: &str, to: &str, content: &str| {
            std::fs::create_dir(at(to)).unwrap();
            std::fs::write(at(to).join("tls.crt"), content).unwrap();
            symlink(to, at("..data_tmp")).unwrap();
            std::fs::rename(at("..data_tmp"), at("..data")).unwrap();
            std::fs::remove_dir_all(at(from)).unwrap();
        };
        swap("..2026_11_10_a", "..2026_11_10_b", "renewed");
        called_back(&rx, &configured, "the first swap");
        assert_eq!(std::fs::read_to_string(&configured).unwrap(), "renewed");
        swap("..2026_11_10_b", "..2026_11_10_c", "renewed again");
        called_back(&rx, &configured, "the second swap");
        std::fs::write(at("..2026_11_10_c/tls.crt"), "edited").unwrap();
        called_back(&rx, &configured, "the file in the new directory edited");
    }

    /// 符号链接改指向另一个目录里的文件以后，监视跟着走：新文件变了回调，旧文件变了不再回调
    /// Once a symlink is pointed at a file in another directory, the watch follows it: the
    /// new file changing is called back, and the old one changing no longer is
    #[cfg(unix)]
    #[test]
    fn the_watch_follows_a_retargeted_symlink() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let dir = |name: &str| {
            let dir = root.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        };
        let (conf, old, new) = (dir("conf"), dir("old"), dir("new"));
        std::fs::write(old.join("data.json"), "old").unwrap();
        std::fs::write(new.join("data.json"), "new").unwrap();
        let configured = conf.join("data.json");
        symlink(old.join("data.json"), &configured).unwrap();

        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&configured), UNSEEN)
            .expect("watch")
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        symlink(new.join("data.json"), conf.join("data.json.tmp")).unwrap();
        std::fs::rename(conf.join("data.json.tmp"), &configured).unwrap();
        called_back(&rx, &configured, "the link pointed elsewhere");
        std::fs::write(new.join("data.json"), "new v2").unwrap();
        called_back(&rx, &configured, "the new target edited");
        std::fs::write(old.join("data.json"), "old v2").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "the old target is no longer watched"
        );
    }

    /// 在监视的目录，排好序 / The directories watched, sorted
    #[cfg(unix)]
    fn watched_dirs(targets: &Targets) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = targets.dirs.keys().cloned().collect();
        dirs.sort();
        dirs
    }

    /// 链接改指向以后，旧目标所在的目录不再监视，新目标所在的目录开始监视；目录集合里只剩还用得着的
    /// Once a link points elsewhere, the old target's directory is no longer watched and the
    /// new target's is; the directory set keeps only what is still needed
    #[cfg(unix)]
    #[test]
    fn the_watch_moves_off_directories_no_longer_used() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let real = std::fs::canonicalize(root.path()).unwrap();
        for dir in ["conf", "old", "new"] {
            std::fs::create_dir(real.join(dir)).unwrap();
            std::fs::write(real.join(dir).join("data.json"), dir).unwrap();
        }
        let configured = real.join("conf/data.json.link");
        symlink(real.join("old/data.json"), &configured).unwrap();
        let (mut watcher, mut targets, _) =
            Targets::watch(std::slice::from_ref(&configured), |_| {}).expect("watch");
        assert_eq!(
            watched_dirs(&targets),
            [real.join("conf"), real.join("old")]
        );

        std::fs::remove_file(&configured).unwrap();
        symlink(real.join("new/data.json"), &configured).unwrap();
        targets.refresh(&mut watcher, 0).expect("watched");
        assert_eq!(
            watched_dirs(&targets),
            [real.join("conf"), real.join("new")]
        );
        assert_eq!(
            targets.files[0].points,
            [configured.clone(), real.join("new/data.json")]
        );
    }

    /// 装监视的时候符号链接指向的目录还不在，后来建好了：文件重新解析（链接重建、Rescan）时那个目录监视上，并且留着——
    /// 撤旧监视只减当初替它监视上的目录，没监视上的那个不减
    /// A symlink leading into a directory not there when the watch is installed, made later:
    /// once the file is resolved again (the link made anew, a Rescan) that directory is
    /// watched, and stays so, as the old watches come out only for the directories that went in
    /// for it, not for the one that did not
    #[cfg(unix)]
    #[test]
    fn a_directory_made_later_stays_watched_once_the_file_is_resolved_again() {
        let root = tempfile::tempdir().expect("tempdir");
        let real = std::fs::canonicalize(root.path()).unwrap();
        let (conf, missing) = (real.join("conf"), real.join("missing"));
        std::fs::create_dir(&conf).unwrap();
        let configured = conf.join("data.json");
        std::os::unix::fs::symlink(missing.join("data.json"), &configured).unwrap();
        let (mut watcher, mut targets, uncovered) =
            Targets::watch(std::slice::from_ref(&configured), |_| {}).expect("watch");
        assert_eq!(uncovered.len(), 1, "{uncovered:?}");
        assert_eq!(watched_dirs(&targets), std::slice::from_ref(&conf));

        std::fs::create_dir(&missing).unwrap();
        std::fs::write(missing.join("data.json"), "v1").unwrap();
        targets
            .refresh(&mut watcher, 0)
            .expect("watched everywhere");
        assert_eq!(watched_dirs(&targets), [conf, missing]);
    }

    /// 两个文件都经同一个目录监视：其中一个改指别处以后，另一个在那个目录的监视还在。别的文件替它监视上的目录，一个文件
    /// 不会当成自己的减掉
    /// Two files watched through one directory: once one of them points elsewhere, the other
    /// is still watched there. A directory watched for another file is not taken away by a file
    /// as its own
    #[cfg(unix)]
    #[test]
    fn a_file_moving_off_a_shared_directory_leaves_the_other_watched_there() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let real = std::fs::canonicalize(root.path()).unwrap();
        let (conf, shared) = (real.join("conf"), real.join("shared"));
        std::fs::create_dir(&conf).unwrap();
        let (first, second) = (conf.join("first.json"), conf.join("second.json"));
        symlink(shared.join("first.json"), &first).unwrap();
        std::fs::write(&second, "second").unwrap();
        let (mut watcher, mut targets, _) =
            Targets::watch(&[first, second.clone()], |_| {}).expect("watch");
        let point_second_at = |target: PathBuf| {
            std::fs::remove_file(&second).unwrap();
            symlink(target, &second).unwrap();
        };

        std::fs::create_dir(&shared).unwrap();
        point_second_at(shared.join("second.json"));
        targets.refresh(&mut watcher, 1).expect("second watched");
        targets.refresh(&mut watcher, 0).expect("first watched");
        assert_eq!(watched_dirs(&targets), [conf.clone(), shared.clone()]);

        point_second_at(conf.join("second.real.json"));
        targets.refresh(&mut watcher, 1).expect("second watched");
        assert_eq!(
            watched_dirs(&targets),
            [conf, shared],
            "first is still watched in the shared directory"
        );
    }

    /// 一个文件的监视点所在的目录一个都监视不上（所在的目录不在）：它哪儿都没监视上，带着为什么列在 `uncovered` 里，监视
    /// 照样装好，同一个监视里别的文件照常监视、回调
    /// A file none of whose watch point directories can be watched (its directory not there) is
    /// watched nowhere and listed in `uncovered` with why; the watch is installed all the same,
    /// the other files of it watched and called back as usual
    #[test]
    fn a_file_watched_nowhere_leaves_the_others_watched() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 真路径：macOS 的临时目录在符号链接 /var 下面，链接所在的根目录监视得上 / The real path:
        // macOS's temporary directory is under the symlink /var, and the root it sits in can be
        // watched
        let real = std::fs::canonicalize(dir.path()).expect("real path");
        let (watched, nowhere) = (real.join("watched.file"), real.join("missing/nowhere.file"));
        std::fs::write(&watched, "v1").expect("seed file");

        let pending =
            PendingWatch::new(&[nowhere.clone(), watched.clone()], UNSEEN).expect("watch");
        let uncovered: Vec<&Path> = pending.uncovered().map(|(path, _)| path).collect();
        assert_eq!(uncovered, [nowhere.as_path()]);
        let (tx, rx) = mpsc::channel();
        let _watch = pending
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");
        std::fs::write(&watched, "v2").expect("change file");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok(),
            Some(watched),
            "the other file is watched"
        );
    }

    /// 装监视的时候符号链接就指向不存在的目录：链接所在的目录监视得上，监视照样装好，这个文件带着为什么列在
    /// `uncovered` 里，都监视得上的文件不在。以前只要有一个监视点装上就当监视着，监视不上的那些谁也不知道
    /// A symlink leading into a directory not there when the watch is installed: the link's
    /// directory can be watched, so the watch is installed all the same, and the file is listed
    /// in `uncovered` with why, while a file watched everywhere is not. It used to count as
    /// watched once any of its watch points went in, the others unknown to anyone
    #[cfg(unix)]
    #[test]
    fn a_file_partly_watched_from_the_start_is_uncovered() {
        let root = tempfile::tempdir().expect("tempdir");
        let conf = root.path().join("conf");
        std::fs::create_dir(&conf).unwrap();
        let (linked, plain) = (conf.join("linked.json"), conf.join("plain.json"));
        std::os::unix::fs::symlink(root.path().join("missing/linked.json"), &linked).unwrap();
        std::fs::write(&plain, "plain").unwrap();

        let pending = PendingWatch::new(&[linked.clone(), plain], UNSEEN).expect("watch");
        let uncovered: Vec<(&Path, String)> = pending
            .uncovered()
            .map(|(path, err)| (path, err.to_string()))
            .collect();
        assert_eq!(uncovered.len(), 1, "{uncovered:?}");
        assert_eq!(uncovered[0].0, linked);
        assert!(uncovered[0].1.contains("missing"), "{uncovered:?}");
    }

    /// 配置文件装监视的时候就有位置监视不上（符号链接指向不存在的目录），开始时就经 `on_watch` 报出来，和后来改了指向
    /// 监视不上一样，面板的 `watch_error` 也就写着；都监视得上时报 None
    /// A configuration file with places that cannot be watched when the watch is installed (a
    /// symlink into a directory not there) is reported to `on_watch` at the start, as when it
    /// later comes to lead somewhere unwatchable, so the panel's `watch_error` says so too; one
    /// watched everywhere is reported None
    #[cfg(unix)]
    #[tokio::test]
    async fn a_config_file_partly_watched_from_the_start_is_reported_at_the_start() {
        let root = tempfile::tempdir().expect("tempdir");
        let conf = root.path().join("conf");
        std::fs::create_dir(&conf).unwrap();
        let (linked, plain) = (conf.join("linked.json"), conf.join("plain.json"));
        std::os::unix::fs::symlink(root.path().join("missing/linked.json"), &linked).unwrap();
        std::fs::write(&plain, "{}").unwrap();
        let engine =
            crate::engine::test_support::engine_from(serde_json::json!({ "pipelines": [] }));

        for (path, uncovered) in [(linked, true), (plain, false)] {
            let (tx, rx) = mpsc::channel();
            let read = std::fs::read_to_string(&path).unwrap_or_default();
            let _watch = ConfigWatch::new(&path)
                .expect("watch")
                .start_reporting(engine.clone(), read, move |watched| {
                    let _ = tx.send(watched.map(ToString::to_string));
                })
                .expect("start");
            let reported = rx.try_recv().expect("reported at the start");
            assert_eq!(
                reported
                    .as_deref()
                    .is_some_and(|why| why.contains("missing")),
                uncovered,
                "{path:?}: {reported:?}"
            );
        }
    }

    /// 符号链接改指向一个监视不上的地方（目录不存在）以后，`on_watch` 拿到为什么（另记一条 error），又指回监视得上的
    /// 地方以后拿到 None；回调照常。以前只记一条 warn，配置文件的 `watch_error` 也不变，面板以为它还监视着
    /// Once a symlink is pointed somewhere that cannot be watched (a directory that does not
    /// exist), `on_watch` is handed why (and an error logged), and once it points back
    /// somewhere watchable, None; the callback runs as ever. Only a warn used to be logged,
    /// the configuration file's `watch_error` staying as it was, so the panel took it as watched
    #[cfg(unix)]
    #[test]
    fn a_link_leading_where_nothing_can_be_watched_is_reported() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let (conf, good) = (root.path().join("conf"), root.path().join("good"));
        std::fs::create_dir(&conf).unwrap();
        std::fs::create_dir(&good).unwrap();
        std::fs::write(good.join("data.json"), "good").unwrap();
        let configured = conf.join("data.json");
        symlink(good.join("data.json"), &configured).unwrap();
        let point_at = |target: PathBuf| {
            symlink(target, conf.join("data.json.tmp")).unwrap();
            std::fs::rename(conf.join("data.json.tmp"), &configured).unwrap();
        };

        let (tx, rx) = mpsc::channel();
        let (called, called_rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&configured), UNSEEN)
            .expect("watch")
            .start_reporting(
                "test-watch",
                move |path| {
                    let _ = called.send(path.to_path_buf());
                },
                move |path, watched| {
                    let _ = tx.send((path.to_path_buf(), watched.map(ToString::to_string)));
                },
            )
            .expect("start");

        point_at(root.path().join("missing").join("data.json"));
        let (path, watched) = rx.recv_timeout(Duration::from_secs(5)).expect("reported");
        assert_eq!(path, configured);
        assert!(
            watched
                .as_deref()
                .is_some_and(|why| why.contains("missing")),
            "{watched:?}"
        );
        called_back(
            &called_rx,
            &configured,
            "the link pointed somewhere unwatchable",
        );
        // 同一次改动的后续事件各报一次，在回调之前，已经随回调收完 / What else the same change
        // brings is reported before its callback, so it is in by now
        while rx.try_recv().is_ok() {}

        point_at(good.join("data.json"));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok(),
            Some((configured.clone(), None)),
            "watched again"
        );
        called_back(&called_rx, &configured, "the link pointed back");
    }

    /// 文件所在的目录删掉、马上重建（`rm -rf` 以后再建、装包时重装）：监视装到新目录上，文件读一遍，之后再改照样回调。
    /// inotify 在目录删掉时撤了它的监视，以前这里还当它监视着，新目录里怎么改都看不到，直到重启
    /// The directory a file sits in removed and made again at once (`rm -rf` then made anew, a
    /// package reinstalled): the watch goes in on the new directory, the file is read once, and
    /// later edits are called back as ever. inotify takes a directory's watch out when it is
    /// removed, which used to be counted as watched still, so nothing done in the new directory
    /// was seen until a restart
    #[cfg(unix)]
    #[test]
    fn a_directory_removed_and_made_again_at_once_is_watched_again() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("geo");
        std::fs::create_dir(&dir).unwrap();
        let configured = dir.join("data.json");
        std::fs::write(&configured, "v1").unwrap();
        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&configured), UNSEEN)
            .expect("watch")
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(&configured, "v2").unwrap();
        called_back(&rx, &configured, "the file in the directory made again");
        std::fs::write(&configured, "v3").unwrap();
        called_back(&rx, &configured, "the file edited afterwards");
    }

    /// 文件所在的目录改名换掉（`mv geo geo.old; mv geo.new geo`）：监视换到新目录上，读一遍新目录里的文件，之后新目录里
    /// 改了回调，挪走的旧目录里改了不回调。inotify 的监视跟着旧目录走、事件却还按原来的路径报：以前新目录里的改动看不到，
    /// 旧目录里的改动反而当成这个文件的
    /// The directory a file sits in swapped by renames (`mv geo geo.old; mv geo.new geo`): the
    /// watch moves to the new directory and the file in it is read once; later edits in the new
    /// directory are called back, and edits in the old one moved away are not. inotify's watch
    /// follows the old directory, its events still reported under the old path: edits in the new
    /// directory used to go unseen, and edits in the old one were taken for this file's
    #[cfg(unix)]
    #[test]
    fn a_directory_swapped_by_renames_is_watched_in_its_new_place() {
        let root = tempfile::tempdir().expect("tempdir");
        let (dir, new, old) = (
            root.path().join("geo"),
            root.path().join("geo.new"),
            root.path().join("geo.old"),
        );
        std::fs::create_dir(&dir).unwrap();
        std::fs::create_dir(&new).unwrap();
        let configured = dir.join("data.json");
        std::fs::write(&configured, "v1").unwrap();
        std::fs::write(new.join("data.json"), "v2").unwrap();
        let (tx, rx) = mpsc::channel();
        let _watch = PendingWatch::new(std::slice::from_ref(&configured), UNSEEN)
            .expect("watch")
            .start("test-watch", move |path| {
                let _ = tx.send(path.to_path_buf());
            })
            .expect("start");

        std::fs::rename(&dir, &old).unwrap();
        std::fs::rename(&new, &dir).unwrap();
        called_back(&rx, &configured, "the directory swapped");
        std::fs::write(&configured, "v3").unwrap();
        called_back(&rx, &configured, "the file in the new directory edited");
        std::fs::write(old.join("data.json"), "old edited").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "the old directory is no longer watched"
        );
    }

    /// 漏了事件（Rescan）以后监视全部重新装上：漏掉的里面可能有在监视的目录删掉重建。以前重新解析只给记着的目录加个数，
    /// 新目录一直没监视，之后的改动都看不到
    /// After events are missed (a Rescan) every watch goes in anew: those missed may include a
    /// watched directory removed and made again. Resolving the file again used to add one to
    /// the count of the directory as recorded, the new directory never watched, and later
    /// changes all went unseen
    #[cfg(unix)]
    #[test]
    fn a_rescan_watches_every_directory_anew() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("geo");
        std::fs::create_dir(&dir).unwrap();
        let configured = dir.join("data.json");
        std::fs::write(&configured, "v1").unwrap();
        let PendingWatch {
            mut watcher,
            mut targets,
            tx,
            rx,
            ..
        } = PendingWatch::new(std::slice::from_ref(&configured), UNSEEN).expect("watch");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        // 删掉、重建的事件漏了 / The events of the removal and the making again are missed
        while rx.recv_timeout(Duration::from_millis(500)).is_ok() {}
        let rescan = notify::Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
        tx.send(Message::Event(Ok(rescan))).unwrap();
        let stop = tx.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(5));
            let _ = stop.send(Message::Stop);
        });

        let mut called = 0;
        pump(
            "test-watch",
            UNSEEN,
            &mut watcher,
            &mut targets,
            &rx,
            |path| {
                called += 1;
                // 头一次是 Rescan 的，这时写进去的应该看得到 / The first is the Rescan's, and what is
                // written now should be seen
                if called == 1 {
                    std::fs::write(path, "v2").unwrap();
                } else {
                    let _ = tx.send(Message::Stop);
                }
            },
            |_, _| {},
        );
        assert_eq!(
            called, 2,
            "the file written after the rescan is called back"
        );
    }
}
