use std::collections::{HashMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use notify::event::{AccessKind, AccessMode, EventKind, ModifyKind, RenameMode};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, WatcherKind};
use tracing::{error, info, warn};

use crate::config;
use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

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

pub fn spawn(path: PathBuf, engine: Engine) {
    // 使用阻塞线程持有watcher，避免异步生命周期问题。 / Use blocking thread to hold watcher, avoiding async lifetime issues.
    thread::spawn(move || {
        let result = run_files_watcher(std::slice::from_ref(&path), || {
            // 启动时只记警告的那些写法，重载时拒绝（见 config::problems）
            // What startup only warns about, a reload refuses (see config::problems)
            let loaded = config::load_config_with_source(&path).and_then(|(cfg, raw)| {
                config::refuse_problems(&cfg)?;
                config::warn_ignored_settings(&cfg);
                RuntimePipelineConfig::from_config(cfg).map(|cfg| (cfg, raw))
            });
            match loaded {
                Ok((new_cfg, raw)) => {
                    engine.reload_from(new_cfg, &path, &raw);
                    info!(target = "watcher", path = %path.display(), "config reloaded");
                }
                Err(err) => {
                    let error = format!("{err:#}");
                    warn!(target = "watcher", path = %path.display(), error = %error, "config reload failed, keeping current state");
                    engine.notify_config_reload_failed(&path, &error);
                }
            }
        });
        if let Err(err) = result {
            error!(target = "watcher", error = %err, "config watcher exited with error");
        }
    });
}

/// Watch the given files and invoke `on_change` whenever any of them is created
/// or its data modified (see [`Targets`] for how each file is watched).
///
/// Blocking — pumps events until the internal channel closes; run it on a
/// dedicated thread. Used for both config hot-reload and DoH TLS certificate
/// reload; the reload action itself belongs to the `on_change` callback.
pub(crate) fn run_files_watcher(
    paths: &[PathBuf],
    mut on_change: impl FnMut(),
) -> notify::Result<()> {
    let (tx, rx) = mpsc::channel();
    let (mut watcher, mut targets) = Targets::watch(paths, move |event| {
        let _ = tx.send(Message::Event(event));
    })?;

    info!(target = "watcher", files = ?paths, "file watcher started (watching parent directories for atomic replacement support)");

    pump(&mut watcher, &mut targets, &rx, |_| on_change());
    Ok(())
}

/// 已经装好、还没开始处理的文件监视：这期间的变化先排队，[`PendingWatch::start`] 以后再交给回调。
/// 先装好监视再读文件，读的时候文件又变了也不会漏掉。
/// A file watch that is installed but not yet handling changes: changes queue meanwhile and
/// reach the callback after [`PendingWatch::start`]. Installing the watch before reading the
/// files means a change made while they are being read is not missed.
pub(crate) struct PendingWatch {
    watcher: RecommendedWatcher,
    targets: Targets,
    tx: Sender<Message>,
    rx: Receiver<Message>,
}

impl PendingWatch {
    /// 开始监视 `paths`（见 [`Targets`]）/ Starts watching `paths` (see [`Targets`])
    pub(crate) fn new(paths: &[PathBuf]) -> notify::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let events = tx.clone();
        let (watcher, targets) = Targets::watch(paths, move |event| {
            let _ = events.send(Message::Event(event));
        })?;
        Ok(Self {
            watcher,
            targets,
            tx,
            rx,
        })
    }

    /// 在名为 `name` 的线程上把每次变化交给 `on_change`，参数是配置里写的那个路径，直到返回的
    /// [`FileWatch`] 被丢掉
    /// Hands every change to `on_change` on a thread named `name`, passing the path as it was
    /// configured, until the returned [`FileWatch`] is dropped
    pub(crate) fn start(
        self,
        name: &str,
        mut on_change: impl FnMut(&Path) + Send + 'static,
    ) -> std::io::Result<FileWatch> {
        let Self {
            watcher,
            targets,
            tx,
            rx,
        } = self;
        let files: Vec<&Path> = targets
            .files
            .iter()
            .map(|target| target.configured.as_path())
            .collect();
        info!(target = "watcher", name, files = ?files, "file watcher started (watching parent directories for atomic replacement support)");
        let thread = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                // 监视随线程一起结束 / The watch ends with the thread
                let (mut watcher, mut targets) = (watcher, targets);
                pump(&mut watcher, &mut targets, &rx, &mut on_change);
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
pub(crate) struct FileWatch {
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
/// 事件按完整路径对上文件，另一个被监视的目录里同名的文件不算。
/// The watched files. Each file is watched through its directory so atomic replacement
/// (write tmp + rename over target) is detected: Linux inotify watches inodes, not paths, and
/// the directory captures IN_MOVED_TO/IN_CREATE for the target filename. When the path goes
/// through symlinks, the directory of every symlink along the way and that of the real file
/// are watched too (see [`watch_points`]), so a link to another directory, or a Kubernetes
/// volume swapping `..data`, is detected as well; on a change the path is resolved again and
/// the watches follow. Events are matched to files by full path, so a file of the same name
/// in another watched directory does not count.
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
}

impl Targets {
    /// 监视 `paths`，事件交给 `handler`。一个文件的监视点所在的目录一个都监视不了时报错
    /// Watches `paths`, sending events to `handler`. An error when none of a file's watch
    /// point directories can be watched
    fn watch(
        paths: &[PathBuf],
        handler: impl notify::EventHandler,
    ) -> notify::Result<(RecommendedWatcher, Self)> {
        let mut watcher = RecommendedWatcher::new(handler, Config::default())?;
        let mut targets = Self {
            files: Vec::with_capacity(paths.len()),
            dirs: HashMap::new(),
        };
        for path in paths {
            if targets
                .files
                .iter()
                .any(|target| target.configured == *path)
            {
                continue;
            }
            let points = watch_points(path).map_err(notify::Error::io)?;
            let mut watched = false;
            let mut first_error = None;
            for dir in points.iter().filter_map(|point| point.parent()) {
                match targets.add_dir(&mut watcher, dir) {
                    Ok(()) => watched = true,
                    Err(err) => {
                        first_error.get_or_insert(err);
                    }
                }
            }
            if let (false, Some(err)) = (watched, first_error) {
                return Err(err);
            }
            targets.files.push(Target {
                configured: path.clone(),
                points,
            });
        }
        Ok((watcher, targets))
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

    /// 文件 `index` 重新解析一遍，监视换到新的监视点所在的目录 / Resolves file `index` again and moves
    /// the watches to the directories of its new watch points
    fn refresh(&mut self, watcher: &mut RecommendedWatcher, index: usize) {
        let points = match watch_points(&self.files[index].configured) {
            Ok(points) => points,
            Err(err) => {
                warn!(target = "watcher", path = %self.files[index].configured.display(), error = %err, "cannot resolve the watched file again");
                return;
            }
        };
        // 先装新的再撤旧的，两边都用着的目录不会断开 / The new watches go in before the old come out,
        // so a directory both use is never dropped
        for dir in points.iter().filter_map(|point| point.parent()) {
            if let Err(err) = self.add_dir(watcher, dir) {
                warn!(target = "watcher", dir = %dir.display(), error = %err, "cannot watch a directory the file now resolves through");
            }
        }
        let old = std::mem::replace(&mut self.files[index].points, points);
        for dir in old.iter().filter_map(|point| point.parent()) {
            self.remove_dir(watcher, dir);
        }
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
/// 最多 [`AT_MOST`]，每个文件重新解析、监视跟着换，再各回调一次。
/// Hands changes to `on_change` until told to stop or the channel closes. A burst of changes
/// is waited for until every file changed is written (see [`Change::settle`]), at most
/// [`AT_MOST`]; then each file is resolved again with the watches following, and called back once.
fn pump(
    watcher: &mut RecommendedWatcher,
    targets: &mut Targets,
    rx: &Receiver<Message>,
    mut on_change: impl FnMut(&Path),
) {
    let close_reported = RecommendedWatcher::kind() == WatcherKind::Inotify;
    let mut burst: Option<Burst> = None;
    loop {
        let message = match &burst {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(burst) => rx.recv_timeout(burst.due().saturating_duration_since(Instant::now())),
        };
        match message {
            Ok(Message::Event(Ok(event))) => {
                let Some((change, paths)) = Change::of(&event) else {
                    continue;
                };
                let now = Instant::now();
                for index in targets.named(paths) {
                    burst
                        .get_or_insert_with(|| Burst::new(now))
                        .note(index, now + change.settle(close_reported));
                }
            }
            Ok(Message::Event(Err(err))) => {
                warn!(target = "watcher", error = %err, "watcher event error");
            }
            // 只有一阵改动在等时才会超时 / Only a burst being waited for times out
            Err(RecvTimeoutError::Timeout) => {
                for (index, _) in burst.take().into_iter().flat_map(|burst| burst.files) {
                    // 先跟上新的解析结果再回调：回调读文件时，新位置上的变化已经在监视之下
                    // The watches follow the new resolution before the callback: by the time it
                    // reads the file, changes at the new places are being watched
                    targets.refresh(watcher, index);
                    on_change(&targets.files[index].configured);
                }
            }
            Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The watcher fires `on_change` when a watched file is atomically replaced
    /// (write sibling tmp + rename over target) and reports it exactly per event.
    #[test]
    fn run_files_watcher_detects_atomic_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = std::sync::mpsc::channel();
        let watched = target.clone();
        let signal = tx.clone();
        // The watcher pumps events until the process exits by design, so the
        // thread is never joined here — assert via the channel instead.
        thread::spawn(move || {
            let _ = run_files_watcher(std::slice::from_ref(&watched), || {
                let _ = signal.send(());
            });
        });

        // The watcher thread may not have registered its watch() yet when the
        // first swap lands, so re-swap until the resulting event is observed.
        let mut fired = false;
        for _ in 0..20 {
            let tmp = dir.path().join("target.renew.tmp");
            std::fs::write(&tmp, "v2").expect("write tmp");
            std::fs::rename(&tmp, &target).expect("atomic rename");
            if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                fired = true;
                break;
            }
        }
        assert!(fired, "on_change must fire on atomic replacement");
    }

    /// Events for sibling files (e.g. the tmp side of an atomic replace) must
    /// not trigger `on_change`.
    #[test]
    fn run_files_watcher_ignores_unrelated_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let watched = target.clone();
        let signal = tx.clone();
        let _handle = thread::spawn(move || {
            let _ = run_files_watcher(std::slice::from_ref(&watched), || {
                signal.send(()).ok();
            });
        });

        thread::sleep(Duration::from_millis(300));
        // Only the sibling changes; the watched file stays untouched.
        std::fs::write(dir.path().join("target.renew.tmp"), "other").expect("write sibling");

        let fired = rx.recv_timeout(Duration::from_secs(2));
        assert!(
            fired.is_err(),
            "on_change must not fire for unrelated files"
        );
    }

    /// 监视装好、还没开始处理时文件变了，开始处理以后这次变化照样交给回调
    /// A change made after the watch is installed but before it starts handling changes
    /// still reaches the callback once it starts
    #[test]
    fn a_change_while_pending_reaches_the_callback_after_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let pending = PendingWatch::new(std::slice::from_ref(&target)).expect("watch");
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
        let watch = PendingWatch::new(std::slice::from_ref(&target))
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
        let _watch = PendingWatch::new(&[target.clone(), other.clone()])
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
        let _watch = PendingWatch::new(std::slice::from_ref(&relative))
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
        let _watch = PendingWatch::new(std::slice::from_ref(&target))
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
        let _watch = PendingWatch::new(std::slice::from_ref(&target))
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
        let _watch = PendingWatch::new(std::slice::from_ref(&target))
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
        let _watch = PendingWatch::new(std::slice::from_ref(&configured))
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
        let _watch = PendingWatch::new(std::slice::from_ref(&configured))
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
        let _watch = PendingWatch::new(std::slice::from_ref(&configured))
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
        let (mut watcher, mut targets) =
            Targets::watch(std::slice::from_ref(&configured), |_| {}).expect("watch");
        let dirs = |targets: &Targets| {
            let mut dirs: Vec<PathBuf> = targets.dirs.keys().cloned().collect();
            dirs.sort();
            dirs
        };
        assert_eq!(dirs(&targets), [real.join("conf"), real.join("old")]);

        std::fs::remove_file(&configured).unwrap();
        symlink(real.join("new/data.json"), &configured).unwrap();
        targets.refresh(&mut watcher, 0);
        assert_eq!(dirs(&targets), [real.join("conf"), real.join("new")]);
        assert_eq!(
            targets.files[0].points,
            [configured.clone(), real.join("new/data.json")]
        );
    }
}
