use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{error, info, warn};

use crate::config;
use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

/// Reload attempts before giving up, and the delay between attempts —
/// rides out non-atomic writes (e.g. truncate+write) observed mid-way.
const RELOAD_RETRIES: u32 = 5;
const RELOAD_RETRY_DELAY: Duration = Duration::from_millis(100);

/// 一次保存常常带来好几个事件：改名盖过目标文件时，notify 为它报一个「改名到这里」，再报一个
/// 同时列出两端的「改名」。收到第一个以后再等这么久，把同一次保存的事件收齐，每个文件只回调一次，
/// 否则面板的每次保存都会让配置完整重载两遍。
/// One save often brings several events: a rename over the target is reported once as
/// "renamed to" and again as a rename naming both ends. After the first one, events are
/// gathered for this long so each file is called back once per save; otherwise every save
/// from the panel reloaded the configuration twice.
const COALESCE_WINDOW: Duration = Duration::from_millis(50);

pub fn spawn(path: PathBuf, engine: Engine) {
    // 使用阻塞线程持有watcher，避免异步生命周期问题。 / Use blocking thread to hold watcher, avoiding async lifetime issues.
    thread::spawn(move || {
        let result = run_files_watcher(std::slice::from_ref(&path), || {
            // The final error is only kept for the observer / 仅为观察者保留最终错误
            let observed = engine.observer().is_some();
            let mut last_error = None;
            let loaded = load_with_retry("config", || {
                let result = config::load_config_with_source(&path).and_then(|(cfg, raw)| {
                    RuntimePipelineConfig::from_config(cfg).map(|cfg| (cfg, raw))
                });
                if observed && let Err(err) = &result {
                    last_error = Some(format!("{err:#}"));
                }
                result
            });
            match loaded {
                Some((new_cfg, raw)) => {
                    engine.reload_from(new_cfg, &path, &raw);
                    info!(target = "watcher", path = %path.display(), "config reloaded");
                }
                None => engine.notify_config_reload_failed(
                    &path,
                    last_error.as_deref().unwrap_or("config reload failed"),
                ),
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
    let (_watcher, targets) = Targets::watch(paths, move |event| {
        let _ = tx.send(Message::Event(event));
    })?;

    info!(target = "watcher", files = ?paths, "file watcher started (watching parent directories for atomic replacement support)");

    pump(&targets, &rx, |_| on_change());
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
            .map(|(_, path)| path.as_path())
            .collect();
        info!(target = "watcher", name, files = ?files, "file watcher started (watching parent directories for atomic replacement support)");
        let thread = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                // 监视随线程一起结束 / The watch ends with the thread
                let _watcher = watcher;
                pump(&targets, &rx, &mut on_change);
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

/// 被监视的文件。每个文件经它的父目录监视，原子替换（写好临时文件再 rename 盖过去）也能察觉：
/// Linux inotify 监视的是 inode 而不是路径，父目录能收到目标文件名的 IN_MOVED_TO/IN_CREATE。
/// 事件按完整路径对上文件，另一个被监视的目录里同名的文件不算。
/// The watched files. Each file is watched through its parent directory so atomic replacement
/// (write tmp + rename over target) is detected: Linux inotify watches inodes, not paths, and
/// the parent directory captures IN_MOVED_TO/IN_CREATE for the target filename. Events are
/// matched to files by full path, so a file of the same name in another watched directory
/// does not count.
struct Targets {
    /// (notify 报告这个文件用的路径, 配置里写的路径) / (the path notify reports the file by, the path as configured)
    files: Vec<(PathBuf, PathBuf)>,
}

impl Targets {
    /// 监视 `paths` 的父目录，事件交给 `handler` / Watches the parent directories of `paths`, sending events to `handler`
    fn watch(
        paths: &[PathBuf],
        handler: impl notify::EventHandler,
    ) -> notify::Result<(RecommendedWatcher, Self)> {
        let mut watcher = RecommendedWatcher::new(handler, Config::default())?;
        let mut watched_parents: HashSet<&Path> = HashSet::new();
        let mut files: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(paths.len());
        for path in paths {
            if files.iter().any(|(_, configured)| configured == path) {
                continue;
            }
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            // cert and key often live in the same directory; watch it once
            if watched_parents.insert(parent) {
                watcher.watch(parent, RecursiveMode::NonRecursive)?;
            }
            // notify 把相对路径接在当前目录后面再报告，这里照做，事件才能按完整路径对上
            // notify reports a relative path joined onto the current directory; doing the same
            // lets events be matched by full path
            let reported_parent = if parent.is_absolute() {
                parent.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(notify::Error::io)?
                    .join(parent)
            };
            let reported = reported_parent.join(path.file_name().unwrap_or_default());
            files.push((reported, path.clone()));
        }
        Ok((watcher, Self { files }))
    }

    /// 这个事件改了数据的文件，按配置里写的路径 / The files whose data this event changed, as configured
    fn changed<'a>(&'a self, event: &notify::Event) -> impl Iterator<Item = &'a Path> {
        // Only data changes count / 只算数据的变化
        let data_change = event.kind.is_modify() || event.kind.is_create();
        self.files
            .iter()
            .filter(move |(reported, _)| data_change && event.paths.contains(reported))
            .map(|(_, configured)| configured.as_path())
    }
}

/// 把变化交给 `on_change`，直到收到停止消息或通道关闭。一个文件的变化先收齐
/// [`COALESCE_WINDOW`] 内的事件再回调一次。
/// Hands changes to `on_change` until told to stop or the channel closes. A file's change
/// is called back once, after the events within [`COALESCE_WINDOW`] are gathered.
fn pump(targets: &Targets, rx: &Receiver<Message>, mut on_change: impl FnMut(&Path)) {
    while let Ok(message) = rx.recv() {
        let mut changed = Vec::new();
        if !gather(targets, message, &mut changed) {
            return;
        }
        if changed.is_empty() {
            continue;
        }
        let deadline = Instant::now() + COALESCE_WINDOW;
        while let Ok(message) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            if !gather(targets, message, &mut changed) {
                return;
            }
        }
        changed.into_iter().for_each(&mut on_change);
    }
}

/// 处理一条消息：它改了数据的文件记进 `changed`，同一个文件只记一次。收到停止消息时返回 false。
/// Takes one message: the files whose data it changed go into `changed`, each file once.
/// False on the stop message.
fn gather<'a>(targets: &'a Targets, message: Message, changed: &mut Vec<&'a Path>) -> bool {
    match message {
        Message::Event(Ok(event)) => {
            for path in targets.changed(&event) {
                if !changed.contains(&path) {
                    changed.push(path);
                }
            }
            true
        }
        Message::Event(Err(err)) => {
            warn!(target = "watcher", error = %err, "watcher event error");
            true
        }
        Message::Stop => false,
    }
}

/// Retry `load` on failure so partially-written files are not mistaken for
/// broken content. Returns `None` (and logs) once all attempts fail, letting
/// the caller keep its current state instead of adopting a broken file.
pub(crate) fn load_with_retry<T>(
    what: &str,
    mut load: impl FnMut() -> anyhow::Result<T>,
) -> Option<T> {
    let mut retries = RELOAD_RETRIES;
    loop {
        match load() {
            Ok(value) => return Some(value),
            Err(err) => {
                retries -= 1;
                if retries == 0 {
                    warn!(target = "watcher", what = %what, error = %err, "reload failed, keeping current state");
                    return None;
                }
                thread::sleep(RELOAD_RETRY_DELAY);
            }
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

    /// A load closure that always fails is retried, then reported as None so
    /// the caller keeps its current state.
    #[test]
    fn load_with_retry_gives_up_after_bounded_attempts() {
        let mut attempts = 0u32;
        let result: Option<()> = load_with_retry("unit-test", || {
            attempts += 1;
            Err(anyhow::anyhow!("persistent failure"))
        });
        assert!(result.is_none(), "persistent failure must return None");
        assert_eq!(
            attempts, RELOAD_RETRIES,
            "must attempt exactly RELOAD_RETRIES times"
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
}
