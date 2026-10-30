//! Lock abstraction layer.
//!
//! This module re-exports parking_lot's RwLock as the one lock type the crate uses.
//! It is no drop-in for std::sync::RwLock: std's guards come wrapped in a
//! `LockResult` for poisoning, so switching would change every call site.
//!
//! 锁抽象层：把 parking_lot 的 RwLock 作为整个 crate 统一使用的锁转出来。它不能直接换成
//! std::sync::RwLock：std 的锁返回包在 `LockResult` 里的守卫（为了处理中毒），换的话每个调用处都要改。
//!
//! # Performance
//!
//! parking_lot::RwLock provides:
//! - ~3x faster read/write operations
//! - ~10x faster under contention
//! - Smaller memory footprint
//!
//! # Usage
//!
//! ```rust
//! # use kixdns::lock::RwLock;
//! # use std::sync::Arc;
//! #
//! let lock = Arc::new(RwLock::new(42));
//! {
//!     let r = lock.read();
//!     assert_eq!(*r, 42);
//! }
//! {
//!     let mut w = lock.write();
//!     *w = 100;
//! }
//! ```

// Use parking_lot for better performance
// 使用 parking_lot 获得更好的性能
pub use parking_lot::RwLock;

// Re-export guard types for convenience
// 重新导出 guard 类型以便使用
pub use parking_lot::{RwLockReadGuard, RwLockWriteGuard};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_rwlock_basic_read() {
        let lock = RwLock::new(42);
        {
            let r = lock.read();
            assert_eq!(*r, 42);
        }
    }

    #[test]
    fn test_rwlock_basic_write() {
        let lock = RwLock::new(42);
        {
            let mut w = lock.write();
            *w = 100;
        }
        let r = lock.read();
        assert_eq!(*r, 100);
    }

    #[test]
    fn test_rwlock_concurrent_reads() {
        let lock = Arc::new(RwLock::new(42));
        let mut handles = vec![];

        for _ in 0..10 {
            let lock_clone = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                let r = lock_clone.read();
                *r
            });
            handles.push(handle);
        }

        for handle in handles {
            assert_eq!(handle.join().unwrap(), 42);
        }
    }

    #[test]
    fn test_rwlock_read_write_blocking() {
        let lock = Arc::new(RwLock::new(42));
        let lock_clone = Arc::clone(&lock);
        let (held, acquired) = std::sync::mpsc::channel();

        // Spawn a thread that holds the read lock
        let read_handle = thread::spawn(move || {
            let r = lock_clone.read();
            held.send(()).unwrap();
            // Hold the lock for a bit
            thread::sleep(std::time::Duration::from_millis(50));
            *r
        });

        // Wait until the read lock is held: a fixed sleep let the writer go first on a
        // busy machine / 等读锁真的拿到：固定的等待在机器忙时会让写线程先拿到锁
        acquired.recv().unwrap();

        // Clone again for the write handle
        let lock_for_write = Arc::clone(&lock);
        // Try to acquire write lock (should block until read is released)
        let write_handle = thread::spawn(move || {
            let mut w = lock_for_write.write();
            *w = 100;
        });

        assert_eq!(read_handle.join().unwrap(), 42);
        write_handle.join().unwrap();

        let r = lock.read();
        assert_eq!(*r, 100);
    }

    #[test]
    fn test_rwlock_try_read() {
        let lock = RwLock::new(42);

        // Try read should succeed
        assert!(lock.try_read().is_some());

        // Acquire write lock
        let _w = lock.write();

        // Try read should fail now
        assert!(lock.try_read().is_none());
    }

    #[test]
    fn test_rwlock_try_write() {
        let lock = RwLock::new(42);

        // Try write should succeed
        assert!(lock.try_write().is_some());

        // Acquire another write lock
        let _w = lock.write();

        // Try write should fail now
        assert!(lock.try_write().is_none());
    }
}
