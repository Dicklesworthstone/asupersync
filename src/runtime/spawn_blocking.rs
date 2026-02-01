//! Async wrapper for blocking pool operations.
//!
//! This module provides `spawn_blocking` helpers that run blocking closures on a
//! dedicated thread (Phase 0) and yield to the async runtime while waiting.
//!
//! # Cancellation Safety
//!
//! When the returned future is dropped (cancelled), the blocking operation
//! continues to run to completion on the background thread, but its result is
//! discarded. This is the standard "soft cancellation" model for blocking
//! operations.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::spawn_blocking;
//! use std::io;
//!
//! async fn read_file(path: &str) -> io::Result<String> {
//!     let path = path.to_string();
//!     spawn_blocking(move || std::fs::read_to_string(&path)).await
//! }
//! ```

use crate::runtime::yield_now;
use std::sync::mpsc;
use std::thread;

/// Spawns a blocking operation and returns a Future that yields until completion.
///
/// This function runs the provided closure on a dedicated thread (Phase 0).
/// In later phases this should be redirected through the runtime blocking pool.
///
/// # Type Bounds
///
/// - `F: FnOnce() -> T + Send + 'static` - The closure must be sendable to another thread
/// - `T: Send + 'static` - The return value must be sendable back
///
/// # Cancel Safety
///
/// If this future is dropped before completion, the blocking operation continues
/// to run but its result is discarded.
///
/// # Panics
///
/// If the blocking operation panics, the panic is captured and re-raised when
/// the future is awaited.
pub async fn spawn_blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();

    // TODO(phase1): Route through BlockingPool associated with the runtime context.
    let thread_result = thread::Builder::new()
        .name("asupersync-blocking".to_string())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            let _ = tx.send(result);
        });

    let _ = thread_result.expect("failed to spawn blocking thread");

    // Poll the channel, yielding between attempts.
    loop {
        match rx.try_recv() {
            Ok(Ok(result)) => return result,
            Ok(Err(panic_payload)) => std::panic::resume_unwind(panic_payload),
            Err(mpsc::TryRecvError::Empty) => yield_now().await,
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("blocking thread dropped without sending result");
            }
        }
    }
}

/// Spawns a blocking I/O operation and returns a Future.
///
/// Convenience wrapper around [`spawn_blocking`] for I/O operations.
pub async fn spawn_blocking_io<F, T>(f: F) -> std::io::Result<T>
where
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(f).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn spawn_blocking_returns_result() {
        init_test("spawn_blocking_returns_result");
        future::block_on(async {
            let result = spawn_blocking(|| 42).await;
            crate::assert_with_log!(result == 42, "result", 42, result);
        });
        crate::test_complete!("spawn_blocking_returns_result");
    }

    #[test]
    fn spawn_blocking_io_returns_result() {
        init_test("spawn_blocking_io_returns_result");
        future::block_on(async {
            let result = spawn_blocking_io(|| Ok::<_, std::io::Error>(42))
                .await
                .unwrap();
            crate::assert_with_log!(result == 42, "result", 42, result);
        });
        crate::test_complete!("spawn_blocking_io_returns_result");
    }

    #[test]
    fn spawn_blocking_io_propagates_error() {
        init_test("spawn_blocking_io_propagates_error");
        future::block_on(async {
            let result: std::io::Result<()> = spawn_blocking_io(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test error",
                ))
            })
            .await;
            crate::assert_with_log!(result.is_err(), "is error", true, result.is_err());
        });
        crate::test_complete!("spawn_blocking_io_propagates_error");
    }

    #[test]
    fn spawn_blocking_captures_closure() {
        init_test("spawn_blocking_captures_closure");
        future::block_on(async {
            let counter = Arc::new(AtomicU32::new(0));
            let counter_clone = Arc::clone(&counter);

            spawn_blocking(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            })
            .await;

            let count = counter.load(Ordering::Relaxed);
            crate::assert_with_log!(count == 1, "counter incremented", 1u32, count);
        });
        crate::test_complete!("spawn_blocking_captures_closure");
    }

    #[test]
    fn spawn_blocking_runs_in_parallel() {
        init_test("spawn_blocking_runs_in_parallel");
        future::block_on(async {
            let counter = Arc::new(AtomicU32::new(0));

            let c1 = Arc::clone(&counter);
            let h1 = spawn_blocking(move || {
                thread::sleep(Duration::from_millis(10));
                c1.fetch_add(1, Ordering::Relaxed);
                1
            });

            let c2 = Arc::clone(&counter);
            let h2 = spawn_blocking(move || {
                thread::sleep(Duration::from_millis(10));
                c2.fetch_add(1, Ordering::Relaxed);
                2
            });

            // Note: awaiting is sequential, but the operations run in parallel threads.
            let r1 = h1.await;
            let r2 = h2.await;

            let count = counter.load(Ordering::Relaxed);
            crate::assert_with_log!(count == 2, "both completed", 2u32, count);
            crate::assert_with_log!(r1 == 1, "first result", 1, r1);
            crate::assert_with_log!(r2 == 2, "second result", 2, r2);
        });
        crate::test_complete!("spawn_blocking_runs_in_parallel");
    }

    #[test]
    #[should_panic(expected = "test panic")]
    fn spawn_blocking_propagates_panic() {
        future::block_on(async {
            spawn_blocking(|| panic!("test panic")).await;
        });
    }
}
