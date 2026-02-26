//! Async wrapper for blocking pool operations.
//!
//! This module provides `spawn_blocking` helpers that run blocking closures on a
//! runtime blocking pool when available, or a dedicated thread as a fallback.
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

use crate::cx::Cx;
use crate::runtime::blocking_pool::{BlockingPoolHandle, BlockingTaskHandle};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Waker;
use std::thread;

/// Maximum number of concurrent fallback blocking threads (when no pool exists).
/// Prevents unbounded thread creation under load.
const MAX_FALLBACK_THREADS: usize = 256;

/// Current number of active fallback blocking threads.
static FALLBACK_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

struct CancelOnDrop {
    handle: BlockingTaskHandle,
    done: bool,
}

impl CancelOnDrop {
    fn new(handle: BlockingTaskHandle) -> Self {
        Self {
            handle,
            done: false,
        }
    }

    fn mark_done(&mut self) {
        self.done = true;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.done {
            self.handle.cancel();
        }
    }
}

struct BlockingOneshotState<T> {
    result: Option<std::thread::Result<T>>,
    waker: Option<Waker>,
    done: bool,
}

struct BlockingOneshot<T> {
    state: Arc<Mutex<BlockingOneshotState<T>>>,
}

impl<T> BlockingOneshot<T> {
    fn new() -> (Self, BlockingOneshotReceiver<T>) {
        let state = Arc::new(Mutex::new(BlockingOneshotState {
            result: None,
            waker: None,
            done: false,
        }));
        (
            Self {
                state: state.clone(),
            },
            BlockingOneshotReceiver { state },
        )
    }

    fn send(self, val: std::thread::Result<T>) {
        let mut guard = self.state.lock();
        guard.result = Some(val);
        guard.done = true;
        if let Some(waker) = guard.waker.take() {
            waker.wake();
        }
    }
}

struct BlockingOneshotReceiver<T> {
    state: Arc<Mutex<BlockingOneshotState<T>>>,
}

impl<T> Drop for BlockingOneshotReceiver<T> {
    fn drop(&mut self) {
        self.state.lock().waker = None;
    }
}

impl<T> std::future::Future for BlockingOneshotReceiver<T> {
    type Output = T;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut guard = self.state.lock();
        if guard.done {
            let result = guard.result.take().expect("result consumed twice");
            match result {
                Ok(val) => std::task::Poll::Ready(val),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        } else {
            if !guard
                .waker
                .as_ref()
                .is_some_and(|w| w.will_wake(cx.waker()))
            {
                guard.waker = Some(cx.waker().clone());
            }
            std::task::Poll::Pending
        }
    }
}

/// Spawns a blocking operation and returns a Future that yields until completion.
///
/// This function runs the provided closure on the runtime blocking pool when
/// a current `Cx` is available, and falls back to a dedicated thread when
/// no runtime context is set.
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
    if let Some(cx) = Cx::current() {
        if let Some(pool) = cx.blocking_pool_handle() {
            return spawn_blocking_on_pool(pool, f).await;
        }
        // Deterministic fallback when running inside a runtime without a pool.
        return f();
    }

    spawn_blocking_on_thread(f).await
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

async fn spawn_blocking_on_pool<F, T>(pool: BlockingPoolHandle, f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = BlockingOneshot::new();
    let handle = pool.spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        tx.send(result);
    });

    let mut guard = CancelOnDrop::new(handle);
    let result = rx.await;
    guard.mark_done();
    result
}

struct FallbackGuard;

impl Drop for FallbackGuard {
    fn drop(&mut self) {
        FALLBACK_THREAD_COUNT.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) async fn spawn_blocking_on_thread<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // Wait until we are under the fallback thread limit to prevent unbounded
    // thread creation when no blocking pool is available.
    loop {
        let current = FALLBACK_THREAD_COUNT.load(Ordering::Relaxed);
        if current < MAX_FALLBACK_THREADS {
            if FALLBACK_THREAD_COUNT
                .compare_exchange_weak(current, current + 1, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        } else {
            // Yield back to the executor instead of blocking the worker thread
            // with a busy spin.
            crate::runtime::yield_now::yield_now().await;
        }
    }

    let (tx, rx) = BlockingOneshot::new();

    // If thread spawn fails, run the closure inline instead of panicking.
    // This keeps `spawn_blocking` usable under resource pressure.
    let f_cell = Arc::new(Mutex::new(Some(f)));
    let f_for_thread = Arc::clone(&f_cell);
    let thread_result = thread::Builder::new()
        .name("asupersync-blocking".to_string())
        .spawn(move || {
            let _guard = FallbackGuard;
            let f = f_for_thread
                .lock()
                .take()
                .expect("spawn_blocking_on_thread fn missing");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            tx.send(result);
        });

    match thread_result {
        Ok(_) => rx.await,
        Err(_err) => {
            FALLBACK_THREAD_COUNT.fetch_sub(1, Ordering::Release);
            let f = f_cell
                .lock()
                .take()
                .expect("spawn_blocking_on_thread fn missing");
            f()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, RegionId, TaskId};
    use futures_lite::future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
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
    fn spawn_blocking_uses_pool_when_current() {
        init_test("spawn_blocking_uses_pool_when_current");
        let pool = crate::runtime::BlockingPool::new(1, 1);
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            None,
            None,
        )
        .with_blocking_pool_handle(Some(pool.handle()));

        let _guard = Cx::set_current(Some(cx));

        let thread_name = future::block_on(async {
            spawn_blocking(|| {
                std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .to_string()
            })
            .await
        });

        crate::assert_with_log!(
            thread_name.contains("-blocking-"),
            "thread name uses pool",
            true,
            thread_name.contains("-blocking-")
        );
        crate::test_complete!("spawn_blocking_uses_pool_when_current");
    }

    #[test]
    fn spawn_blocking_inline_when_no_pool() {
        init_test("spawn_blocking_inline_when_no_pool");
        let cx: Cx = Cx::for_testing();
        let _guard = Cx::set_current(Some(cx));
        let current_id = std::thread::current().id();

        let thread_id =
            future::block_on(async { spawn_blocking(|| std::thread::current().id()).await });

        crate::assert_with_log!(
            thread_id == current_id,
            "same thread",
            current_id,
            thread_id
        );
        crate::test_complete!("spawn_blocking_inline_when_no_pool");
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

            // Since `spawn_blocking` is lazy, we must poll them concurrently
            // to actually run the background threads in parallel.
            let (r1, r2) = future::zip(h1, h2).await;

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
            spawn_blocking(|| std::panic::panic_any("test panic")).await;
        });
    }
}
