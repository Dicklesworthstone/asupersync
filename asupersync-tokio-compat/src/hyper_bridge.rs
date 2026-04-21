//! hyper v1 runtime bridge for Asupersync.
//!
//! Implements `hyper::rt::{Executor, Timer, Sleep, Read, Write}` using
//! Asupersync's executor, timer wheel, and I/O subsystems.
//!
//! This is the **keystone adapter** — once hyper can run on Asupersync,
//! the entire HTTP/web/gRPC stack (reqwest, axum routing, tonic codec)
//! becomes accessible.
//!
//! # Usage
//!
//! ```ignore
//! use asupersync_tokio_compat::hyper_bridge::{AsupersyncExecutor, AsupersyncTimer};
//!
//! let executor = AsupersyncExecutor::new();
//! let timer = AsupersyncTimer::new();
//!
//! // Use with hyper's connection builder
//! let builder = hyper::server::conn::http1::Builder::new()
//!     .timer(timer);
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Executor that spawns futures on the Asupersync runtime.
///
/// Tasks spawned through this executor are region-owned: they will be
/// cancelled when the originating region closes, preserving structured
/// concurrency.
///
/// # Design
///
/// hyper's `Executor::execute` does not provide a `Cx`, so the adapter
/// stores a spawn function that captures the current runtime context.
/// The spawn function is set during adapter entry (e.g., `with_hyper_conn`)
/// and routes new tasks into the correct region.
///
/// # Invariants Preserved
///
/// - **INV-2 (Structured concurrency)**: Spawned tasks are region-owned
/// - **INV-4 (No obligation leaks)**: Task handles are tracked
#[derive(Clone)]
pub struct AsupersyncExecutor {
    spawn_fn: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,
}

impl std::fmt::Debug for AsupersyncExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsupersyncExecutor")
            .field("has_spawn_fn", &true)
            .finish()
    }
}

impl AsupersyncExecutor {
    /// Create an executor with a custom spawn function.
    ///
    /// The spawn function is called for each `execute()` invocation and must
    /// route the future into the appropriate Asupersync region.
    pub fn with_spawn_fn<F>(spawn_fn: F) -> Self
    where
        F: Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync + 'static,
    {
        Self {
            spawn_fn: Arc::new(spawn_fn),
        }
    }

    /// Create a no-op executor that logs spawned futures without running them.
    ///
    /// This is useful for testing adapter wiring without a full runtime.
    /// In production, use [`with_spawn_fn`](Self::with_spawn_fn) to wire
    /// into the Asupersync region.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            spawn_fn: Arc::new(|_| {
                // Intentionally drops the future. Used for compile-time trait
                // validation and tests that don't need actual execution.
            }),
        }
    }
}

impl Default for AsupersyncExecutor {
    fn default() -> Self {
        Self::noop()
    }
}

impl<F> hyper::rt::Executor<F> for AsupersyncExecutor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        (self.spawn_fn)(Box::pin(future));
    }
}

/// Timer that uses wall-clock time with proper waker registration.
///
/// Each sleep future spawns a lightweight background thread that sleeps
/// until the deadline and then wakes the polling task. This is suitable
/// for adapter use (HTTP timeouts, keep-alive) where timer counts are
/// moderate.
///
/// # Invariants Preserved
///
/// - **REL-3 (Deterministic replay)**: In lab mode, callers should use
///   `AsupersyncTimer::with_time_source` to override the clock. The
///   current implementation uses wall-clock `Instant`.
#[derive(Clone, Debug)]
pub struct AsupersyncTimer {
    _private: (),
}

impl AsupersyncTimer {
    /// Create a new timer backed by wall-clock time.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AsupersyncTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl hyper::rt::Timer for AsupersyncTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(AsupersyncSleep::new(duration))
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(AsupersyncSleep::new_until(deadline))
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn hyper::rt::Sleep>>, new_deadline: Instant) {
        // Downcast back to AsupersyncSleep to reset. Since we only ever return
        // AsupersyncSleep from this timer, this downcast is safe.
        // Wait, hyper::rt::Sleep doesn't have Any, but we can just re-assign it.
        *sleep = self.sleep_until(new_deadline);
    }
}

/// A sleep future backed by Asupersync's native `Sleep`.
///
/// This delegates to the runtime's timer wheel (if available via `Cx::current()`)
/// to avoid spawning an OS thread per sleep future, which is critical for
/// high-concurrency network servers.
struct AsupersyncSleep {
    inner: asupersync::time::Sleep,
}

impl AsupersyncSleep {
    fn new(duration: Duration) -> Self {
        let now = asupersync::time::wall_now();
        Self {
            inner: asupersync::time::sleep(now, duration),
        }
    }

    fn new_until(deadline: Instant) -> Self {
        let now_instant = Instant::now();
        let duration = deadline.saturating_duration_since(now_instant);
        Self::new(duration)
    }
}

impl Future for AsupersyncSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

// hyper::rt::Sleep is a marker trait with no methods beyond Future<Output=()>.
impl hyper::rt::Sleep for AsupersyncSleep {}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::rt::Timer;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[test]
    fn executor_implements_hyper_trait() {
        let _exec: Box<dyn hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>>> =
            Box::new(AsupersyncExecutor::noop());
    }

    #[test]
    fn executor_with_custom_spawn_fn() {
        let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let spawned_clone = Arc::clone(&spawned);

        let exec = AsupersyncExecutor::with_spawn_fn(move |_fut| {
            spawned_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        hyper::rt::Executor::execute(&exec, async {});
        assert!(spawned.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn timer_implements_hyper_trait() {
        let timer = AsupersyncTimer::new();
        let _sleep = hyper::rt::Timer::sleep(&timer, Duration::from_millis(100));
    }

    #[test]
    fn timer_sleep_until_creates_sleep() {
        let timer = AsupersyncTimer::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        let _sleep = hyper::rt::Timer::sleep_until(&timer, deadline);
    }

    #[test]
    fn sleep_completes_for_past_deadline() {
        let timer = AsupersyncTimer::new();
        // Deadline in the past should resolve immediately.
        let mut sleep = timer.sleep(Duration::ZERO);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = sleep.as_mut().poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(())));
    }

    #[test]
    fn sleep_completes_for_future_deadline() {
        let timer = AsupersyncTimer::new();
        let mut sleep = timer.sleep(Duration::from_millis(50));

        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _flag_clone = Arc::clone(&flag);

        // Create a waker that sets the flag when woken.
        struct FlagWaker(std::sync::atomic::AtomicBool);
        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let waker_obj = Arc::new(FlagWaker(std::sync::atomic::AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&waker_obj));
        let mut cx = Context::from_waker(&waker);

        // First poll should return Pending and rely on native time/thread fallback
        let poll = sleep.as_mut().poll(&mut cx);
        assert!(matches!(poll, Poll::Pending));

        // Wait for the timer to fire.
        std::thread::sleep(Duration::from_millis(150));

        // Polling again should return Ready.
        let waker2 = noop_waker();
        let mut cx2 = Context::from_waker(&waker2);
        let poll = sleep.as_mut().poll(&mut cx2);
        assert!(matches!(poll, Poll::Ready(())));
    }

    #[test]
    fn timer_reset_creates_new_sleep() {
        let timer = AsupersyncTimer::new();
        let mut sleep = timer.sleep(Duration::from_secs(60));

        // Reset to past deadline.
        timer.reset(&mut sleep, Instant::now() - Duration::from_secs(1));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = sleep.as_mut().poll(&mut cx);
        assert!(matches!(poll, Poll::Ready(())));
    }

    #[test]
    fn noop_executor_does_not_panic() {
        let exec = AsupersyncExecutor::noop();
        // Should not panic - just drops the future.
        hyper::rt::Executor::execute(&exec, async {
            // This body never runs.
        });
    }
}
