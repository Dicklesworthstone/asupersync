//! Graceful shutdown helpers and patterns.
//!
//! Provides utilities for running tasks with graceful shutdown support,
//! including grace period handling and server wrappers.

use std::future::Future;
use std::time::Duration;

use super::ShutdownReceiver;
use crate::combinator::{Either, Select, SelectError};
use crate::time::{TimeoutFuture, wall_now};
use crate::tracing_compat::{info, warn};
use crate::types::Time;

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
        Ok(Either::Left(result)) => GracefulOutcome::Completed(result),
        Ok(Either::Right(())) => GracefulOutcome::ShutdownSignaled,
        Err(SelectError::PolledAfterCompletion) => {
            unreachable!("fresh select future should not be repolled")
        }
    }
}

/// Configuration for graceful shutdown behavior.
#[derive(Debug, Clone)]
pub struct GracefulConfig {
    /// Grace period before forced shutdown.
    pub grace_period: Duration,
    /// Whether to log shutdown events.
    pub log_events: bool,
    /// Optional custom time source used for grace-period deadlines.
    pub time_getter: Option<fn() -> Time>,
}

impl Default for GracefulConfig {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_secs(30),
            log_events: true,
            time_getter: None,
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

    /// Sets the time source used for grace-period deadlines.
    #[must_use]
    pub fn with_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = Some(time_getter);
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

    /// Sets the time source used for grace-period deadlines.
    #[must_use]
    pub fn time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.config.time_getter = Some(time_getter);
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
                info!("graceful builder observed pre-signaled shutdown");
            }
            return GracefulOutcome::ShutdownSignaled;
        }

        let mut fut = Box::pin(fut);
        let mut shutdown_fut = Box::pin(async { shutdown.wait().await });

        match Select::new(fut.as_mut(), shutdown_fut.as_mut()).await {
            Ok(Either::Left(result)) => GracefulOutcome::Completed(result),
            Ok(Either::Right(())) => {
                if config.log_events {
                    info!(grace_period = ?config.grace_period, "graceful shutdown signaled");
                }

                if config.grace_period.is_zero() {
                    return GracefulOutcome::ShutdownSignaled;
                }

                let result = if let Some(time_getter) = config.time_getter {
                    let deadline = time_getter() + config.grace_period;
                    TimeoutFuture::with_time_getter(fut.as_mut(), deadline, time_getter).await
                } else {
                    TimeoutFuture::after(wall_now(), config.grace_period, fut.as_mut()).await
                };

                result.map_or_else(
                    |_| {
                        if config.log_events {
                            warn!(
                                grace_period = ?config.grace_period,
                                "grace period elapsed before task completed"
                            );
                        }
                        GracefulOutcome::ShutdownSignaled
                    },
                    |result| {
                        if config.log_events {
                            info!(
                                grace_period = ?config.grace_period,
                                "task completed within graceful shutdown grace period"
                            );
                        }
                        GracefulOutcome::Completed(result)
                    },
                )
            }
            Err(SelectError::PolledAfterCompletion) => {
                unreachable!("fresh select future should not be repolled")
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
#[path = "graceful_inline_tests.rs"]
mod tests;
