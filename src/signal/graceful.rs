//! Graceful shutdown helpers and patterns.
//!
//! Provides utilities for running tasks with graceful shutdown support,
//! including grace period handling and server wrappers.

use std::future::Future;
use std::time::Duration;

use super::ShutdownReceiver;
use crate::combinator::{Either, Select};
use crate::time::{timeout, wall_now};

fn wall_clock_now() -> std::time::Instant {
    std::time::Instant::now()
}

/// Outcome of a task run with graceful shutdown support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GracefulOutcome<T> {
    /// The task completed normally before shutdown.
    Completed(T),
    /// Shutdown was signaled; the task was interrupted.
    ShutdownSignaled,
}

impl<T> GracefulOutcome<T> {
    /// Returns `true` if the task completed normally.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Returns `true` if shutdown was signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        matches!(self, Self::ShutdownSignaled)
    }

    /// Returns the completed value, or `None` if shutdown was signaled.
    #[must_use]
    pub fn into_completed(self) -> Option<T> {
        match self {
            Self::Completed(v) => Some(v),
            Self::ShutdownSignaled => None,
        }
    }

    /// Maps the completed value using the provided function.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> GracefulOutcome<U> {
        match self {
            Self::Completed(v) => GracefulOutcome::Completed(f(v)),
            Self::ShutdownSignaled => GracefulOutcome::ShutdownSignaled,
        }
    }
}

/// Runs a future with graceful shutdown support.
///
/// The future is raced against the shutdown signal. If shutdown is signaled
/// first, `GracefulOutcome::ShutdownSignaled` is returned.
///
/// # Example
///
/// ```ignore
/// use asupersync::signal::{ShutdownController, with_graceful_shutdown, GracefulOutcome};
///
/// async fn long_running_task() -> i32 {
///     // ... do work ...
///     42
/// }
///
/// async fn run() {
///     let controller = ShutdownController::new();
///     let mut receiver = controller.subscribe();
///
///     match with_graceful_shutdown(long_running_task(), receiver).await {
///         GracefulOutcome::Completed(value) => {
///             println!("Task completed with: {}", value);
///         }
///         GracefulOutcome::ShutdownSignaled => {
///             println!("Shutdown signaled, task interrupted");
///         }
///     }
/// }
/// ```
pub async fn with_graceful_shutdown<F, T>(
    fut: F,
    mut shutdown: ShutdownReceiver,
) -> GracefulOutcome<T>
where
    F: Future<Output = T> + Unpin,
{
    // Check if already shut down.
    if shutdown.is_shutting_down() {
        return GracefulOutcome::ShutdownSignaled;
    }

    // Race the future against shutdown using Select combinator.
    let shutdown_fut = async { shutdown.wait().await };

    // Pin both futures for Select.
    let pinned_fut = fut;
    let pinned_shutdown = Box::pin(shutdown_fut);

    // Use our Select combinator.
    // NOTE: When shutdown wins, `fut` is dropped (not drained). This is
    // intentional for graceful shutdown: the caller is responsible for
    // cleanup via scope finalizers. If `fut` holds obligations, those are
    // resolved by the enclosing region's close protocol.
    match Select::new(pinned_fut, pinned_shutdown).await {
        Either::Left(result) => GracefulOutcome::Completed(result),
        Either::Right(()) => GracefulOutcome::ShutdownSignaled,
    }
}

/// Configuration for graceful shutdown behavior.
#[derive(Debug, Clone)]
pub struct GracefulConfig {
    /// Grace period before forced shutdown.
    pub grace_period: Duration,
    /// Whether to log shutdown events.
    pub log_events: bool,
}

impl Default for GracefulConfig {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_secs(30),
            log_events: true,
        }
    }
}

impl GracefulConfig {
    /// Creates a new configuration with the specified grace period.
    #[must_use]
    pub fn with_grace_period(mut self, duration: Duration) -> Self {
        self.grace_period = duration;
        self
    }

    /// Sets whether to log shutdown events.
    #[must_use]
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_events = enabled;
        self
    }
}

/// Builder for running tasks with graceful shutdown.
///
/// Provides a fluent interface for configuring graceful shutdown behavior.
#[derive(Debug)]
pub struct GracefulBuilder {
    shutdown: ShutdownReceiver,
    config: GracefulConfig,
}

impl GracefulBuilder {
    /// Creates a new builder with the given shutdown receiver.
    #[must_use]
    pub fn new(shutdown: ShutdownReceiver) -> Self {
        Self {
            shutdown,
            config: GracefulConfig::default(),
        }
    }

    /// Sets the grace period.
    #[must_use]
    pub fn grace_period(mut self, duration: Duration) -> Self {
        self.config.grace_period = duration;
        self
    }

    /// Enables or disables logging.
    #[must_use]
    pub fn logging(mut self, enabled: bool) -> Self {
        self.config.log_events = enabled;
        self
    }

    /// Runs the given future with graceful shutdown support.
    pub async fn run<F, T>(self, fut: F) -> GracefulOutcome<T>
    where
        F: Future<Output = T>,
    {
        let Self {
            mut shutdown,
            config,
        } = self;

        if shutdown.is_shutting_down() {
            if config.log_events {
                tracing::info!("graceful builder observed pre-signaled shutdown");
            }
            return GracefulOutcome::ShutdownSignaled;
        }

        let mut fut = Box::pin(fut);
        let mut shutdown_fut = Box::pin(async { shutdown.wait().await });

        match Select::new(fut.as_mut(), shutdown_fut.as_mut()).await {
            Either::Left(result) => GracefulOutcome::Completed(result),
            Either::Right(()) => {
                if config.log_events {
                    tracing::info!(grace_period = ?config.grace_period, "graceful shutdown signaled");
                }

                if config.grace_period.is_zero() {
                    return GracefulOutcome::ShutdownSignaled;
                }

                timeout(wall_now(), config.grace_period, fut.as_mut())
                    .await
                    .map_or_else(
                        |_| {
                            if config.log_events {
                                tracing::warn!(
                                    grace_period = ?config.grace_period,
                                    "grace period elapsed before task completed"
                                );
                            }
                            GracefulOutcome::ShutdownSignaled
                        },
                        |result| {
                            if config.log_events {
                                tracing::info!(
                                    grace_period = ?config.grace_period,
                                    "task completed within graceful shutdown grace period"
                                );
                            }
                            GracefulOutcome::Completed(result)
                        },
                    )
            }
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &GracefulConfig {
        &self.config
    }
}

/// A guard that tracks whether we're in a shutdown grace period.
///
/// This is useful for tasks that need to know if they should finish
/// up quickly versus continue normal operation.
#[derive(Debug)]
pub struct GracePeriodGuard {
    started_at: std::time::Instant,
    duration: Duration,
    time_getter: fn() -> std::time::Instant,
}

impl GracePeriodGuard {
    /// Creates a new grace period guard.
    #[must_use]
    pub fn new(duration: Duration) -> Self {
        Self {
            started_at: wall_clock_now(),
            duration,
            time_getter: wall_clock_now,
        }
    }

    /// Creates a new grace period guard with a custom time source.
    ///
    /// This is useful for deterministic tests and virtual-time harnesses that
    /// should not depend on wall-clock progression.
    #[must_use]
    pub fn with_time_getter(duration: Duration, time_getter: fn() -> std::time::Instant) -> Self {
        Self {
            started_at: time_getter(),
            duration,
            time_getter,
        }
    }

    /// Returns the remaining time in the grace period.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.remaining_at((self.time_getter)())
    }

    /// Returns the remaining time in the grace period at a specific instant.
    #[must_use]
    pub fn remaining_at(&self, now: std::time::Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.started_at);
        self.duration.saturating_sub(elapsed)
    }

    /// Returns `true` if the grace period has elapsed.
    #[must_use]
    pub fn is_elapsed(&self) -> bool {
        self.is_elapsed_at((self.time_getter)())
    }

    /// Returns `true` if the grace period has elapsed at a specific instant.
    #[must_use]
    pub fn is_elapsed_at(&self, now: std::time::Instant) -> bool {
        now.saturating_duration_since(self.started_at) >= self.duration
    }

    /// Returns the total duration of the grace period.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns when the grace period started.
    #[must_use]
    pub fn started_at(&self) -> std::time::Instant {
        self.started_at
    }

    /// Returns the time source used by this guard.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> std::time::Instant {
        self.time_getter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::ShutdownController;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    fn poll_once<F: std::future::Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        std::pin::Pin::new(fut).poll(&mut cx)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct ShutdownThenComplete {
        shutdown: Option<ShutdownController>,
        remaining_pending_polls: usize,
        value: i32,
    }

    impl ShutdownThenComplete {
        fn new(shutdown: ShutdownController, remaining_pending_polls: usize, value: i32) -> Self {
            Self {
                shutdown: Some(shutdown),
                remaining_pending_polls,
                value,
            }
        }
    }

    impl Future for ShutdownThenComplete {
        type Output = i32;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(shutdown) = self.shutdown.take() {
                shutdown.shutdown();
            }

            if self.remaining_pending_polls == 0 {
                return Poll::Ready(self.value);
            }

            self.remaining_pending_polls -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    struct ShutdownThenPending {
        shutdown: Option<ShutdownController>,
    }

    impl ShutdownThenPending {
        fn new(shutdown: ShutdownController) -> Self {
            Self {
                shutdown: Some(shutdown),
            }
        }
    }

    impl Future for ShutdownThenPending {
        type Output = i32;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(shutdown) = self.shutdown.take() {
                shutdown.shutdown();
            }

            Poll::Pending
        }
    }

    static TEST_GRACE_TIME_BASE: OnceLock<std::time::Instant> = OnceLock::new();
    static TEST_GRACE_TIME_NANOS: AtomicU64 = AtomicU64::new(0);

    fn test_grace_time_now() -> std::time::Instant {
        let base = *TEST_GRACE_TIME_BASE.get_or_init(std::time::Instant::now);
        let offset = Duration::from_nanos(TEST_GRACE_TIME_NANOS.load(Ordering::SeqCst));
        base.checked_add(offset).unwrap_or(base)
    }

    #[test]
    fn graceful_outcome_completed() {
        init_test("graceful_outcome_completed");
        let outcome: GracefulOutcome<i32> = GracefulOutcome::Completed(42);
        let completed = outcome.is_completed();
        crate::assert_with_log!(completed, "completed", true, completed);
        let shutdown = outcome.is_shutdown();
        crate::assert_with_log!(!shutdown, "not shutdown", false, shutdown);
        let value = outcome.into_completed();
        crate::assert_with_log!(value == Some(42), "value", Some(42), value);
        crate::test_complete!("graceful_outcome_completed");
    }

    #[test]
    fn graceful_outcome_shutdown() {
        init_test("graceful_outcome_shutdown");
        let outcome: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        let completed = outcome.is_completed();
        crate::assert_with_log!(!completed, "not completed", false, completed);
        let shutdown = outcome.is_shutdown();
        crate::assert_with_log!(shutdown, "shutdown", true, shutdown);
        let value = outcome.into_completed();
        let none = value.is_none();
        crate::assert_with_log!(none, "value none", true, none);
        crate::test_complete!("graceful_outcome_shutdown");
    }

    #[test]
    fn graceful_outcome_map() {
        init_test("graceful_outcome_map");
        let outcome: GracefulOutcome<i32> = GracefulOutcome::Completed(21);
        let mapped = outcome.map(|x| x * 2);
        let value = mapped.into_completed();
        crate::assert_with_log!(value == Some(42), "mapped value", Some(42), value);

        let outcome: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        let mapped = outcome.map(|x| x * 2);
        let shutdown = mapped.is_shutdown();
        crate::assert_with_log!(shutdown, "mapped shutdown", true, shutdown);
        crate::test_complete!("graceful_outcome_map");
    }

    #[test]
    fn with_graceful_shutdown_already_shutdown() {
        init_test("with_graceful_shutdown_already_shutdown");
        let controller = ShutdownController::new();
        controller.shutdown();
        let receiver = controller.subscribe();

        // Use std::future::ready which is Unpin
        let ready_fut = std::future::ready(42);
        let fut = with_graceful_shutdown(ready_fut, receiver);
        let mut boxed = Box::pin(fut);

        // Should immediately return ShutdownSignaled.
        match poll_once(&mut boxed) {
            Poll::Ready(outcome) => {
                let shutdown = outcome.is_shutdown();
                crate::assert_with_log!(shutdown, "shutdown", true, shutdown);
            }
            Poll::Pending => {
                crate::assert_with_log!(
                    false,
                    "already-shutdown future should be ready",
                    true,
                    false
                );
            }
        }
        crate::test_complete!("with_graceful_shutdown_already_shutdown");
    }

    #[test]
    fn graceful_builder_config() {
        init_test("graceful_builder_config");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_mins(1))
            .logging(false);

        let grace_period = builder.config().grace_period;
        crate::assert_with_log!(
            grace_period == Duration::from_mins(1),
            "grace_period",
            Duration::from_mins(1),
            grace_period
        );
        let log_events = builder.config().log_events;
        crate::assert_with_log!(!log_events, "log_events false", false, log_events);
        crate::test_complete!("graceful_builder_config");
    }

    #[test]
    fn graceful_builder_run_completes_within_grace_period_after_shutdown() {
        init_test("graceful_builder_run_completes_within_grace_period_after_shutdown");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();
        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_millis(50))
            .logging(false);
        let fut = ShutdownThenComplete::new(controller, 1, 42);
        let result = futures_lite::future::block_on(builder.run(fut));

        crate::assert_with_log!(
            matches!(result, GracefulOutcome::Completed(42)),
            "future completed during grace period",
            "GracefulOutcome::Completed(42)",
            result
        );
        crate::test_complete!("graceful_builder_run_completes_within_grace_period_after_shutdown");
    }

    #[test]
    fn graceful_builder_run_returns_shutdown_after_grace_period_elapses() {
        init_test("graceful_builder_run_returns_shutdown_after_grace_period_elapses");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();
        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_millis(10))
            .logging(false);
        let fut = ShutdownThenPending::new(controller);
        let result = futures_lite::future::block_on(builder.run(fut));

        crate::assert_with_log!(
            matches!(result, GracefulOutcome::ShutdownSignaled),
            "future interrupted after grace period elapsed",
            "GracefulOutcome::ShutdownSignaled",
            result
        );
        crate::test_complete!("graceful_builder_run_returns_shutdown_after_grace_period_elapses");
    }

    #[test]
    fn grace_period_guard() {
        init_test("grace_period_guard");
        TEST_GRACE_TIME_NANOS.store(0, Ordering::SeqCst);
        let guard =
            GracePeriodGuard::with_time_getter(Duration::from_millis(100), test_grace_time_now);
        let elapsed = guard.is_elapsed();
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);
        let remaining = guard.remaining();
        crate::assert_with_log!(
            remaining == Duration::from_millis(100),
            "remaining == 100ms",
            Duration::from_millis(100),
            remaining
        );

        TEST_GRACE_TIME_NANOS.store(40_000_000, Ordering::SeqCst);
        let elapsed = guard.is_elapsed();
        crate::assert_with_log!(!elapsed, "not elapsed at 40ms", false, elapsed);
        let remaining = guard.remaining();
        crate::assert_with_log!(
            remaining == Duration::from_millis(60),
            "remaining == 60ms",
            Duration::from_millis(60),
            remaining
        );

        TEST_GRACE_TIME_NANOS.store(150_000_000, Ordering::SeqCst);
        let elapsed = guard.is_elapsed();
        crate::assert_with_log!(elapsed, "elapsed at 150ms", true, elapsed);
        let remaining = guard.remaining();
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining zero",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("grace_period_guard");
    }

    #[test]
    fn graceful_config_builder() {
        init_test("graceful_config_builder");
        let config = GracefulConfig::default()
            .with_grace_period(Duration::from_secs(10))
            .with_logging(false);

        crate::assert_with_log!(
            config.grace_period == Duration::from_secs(10),
            "grace_period",
            Duration::from_secs(10),
            config.grace_period
        );
        crate::assert_with_log!(
            !config.log_events,
            "log_events false",
            false,
            config.log_events
        );
        crate::test_complete!("graceful_config_builder");
    }

    // =========================================================================
    // Wave 27: Data-type trait coverage
    // =========================================================================

    #[test]
    fn graceful_outcome_debug() {
        let completed: GracefulOutcome<i32> = GracefulOutcome::Completed(42);
        let dbg = format!("{completed:?}");
        assert!(dbg.contains("Completed"));
        assert!(dbg.contains("42"));

        let shutdown: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        let dbg = format!("{shutdown:?}");
        assert!(dbg.contains("ShutdownSignaled"));
    }

    #[test]
    fn graceful_outcome_clone_copy() {
        let outcome: GracefulOutcome<i32> = GracefulOutcome::Completed(7);
        let cloned = outcome;
        let copied = outcome; // Copy
        assert_eq!(cloned, copied);
        assert_eq!(cloned, GracefulOutcome::Completed(7));
    }

    #[test]
    fn graceful_outcome_eq() {
        let a: GracefulOutcome<i32> = GracefulOutcome::Completed(1);
        let b: GracefulOutcome<i32> = GracefulOutcome::Completed(1);
        let c: GracefulOutcome<i32> = GracefulOutcome::Completed(2);
        let d: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn graceful_config_debug() {
        let config = GracefulConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("GracefulConfig"));
        assert!(dbg.contains("grace_period"));
        assert!(dbg.contains("log_events"));
    }

    #[test]
    fn graceful_config_clone() {
        let config = GracefulConfig::default()
            .with_grace_period(Duration::from_secs(5))
            .with_logging(false);
        let config2 = config;
        assert_eq!(config2.grace_period, Duration::from_secs(5));
        assert!(!config2.log_events);
    }

    #[test]
    fn graceful_config_default_values() {
        let config = GracefulConfig::default();
        assert_eq!(config.grace_period, Duration::from_secs(30));
        assert!(config.log_events);
    }

    #[test]
    fn grace_period_guard_debug() {
        let guard = GracePeriodGuard::new(Duration::from_mins(1));
        let dbg = format!("{guard:?}");
        assert!(dbg.contains("GracePeriodGuard"));
        assert!(dbg.contains("duration"));
    }

    #[test]
    fn grace_period_guard_duration_accessor() {
        let guard = GracePeriodGuard::new(Duration::from_millis(500));
        assert_eq!(guard.duration(), Duration::from_millis(500));
    }

    #[test]
    fn grace_period_guard_started_at_accessor() {
        TEST_GRACE_TIME_NANOS.store(3_000_000, Ordering::SeqCst);
        let guard = GracePeriodGuard::with_time_getter(Duration::from_secs(1), test_grace_time_now);
        assert_eq!(guard.started_at(), test_grace_time_now());
    }

    #[test]
    fn grace_period_guard_remaining_and_elapsed_at() {
        TEST_GRACE_TIME_NANOS.store(0, Ordering::SeqCst);
        let guard =
            GracePeriodGuard::with_time_getter(Duration::from_millis(250), test_grace_time_now);

        let at_100 = guard
            .started_at()
            .checked_add(Duration::from_millis(100))
            .expect("test instant should not overflow");
        assert_eq!(guard.remaining_at(at_100), Duration::from_millis(150));
        assert!(!guard.is_elapsed_at(at_100));

        let at_260 = guard
            .started_at()
            .checked_add(Duration::from_millis(260))
            .expect("test instant should not overflow");
        assert_eq!(guard.remaining_at(at_260), Duration::ZERO);
        assert!(guard.is_elapsed_at(at_260));
    }
}
