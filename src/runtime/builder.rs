//! Runtime builder, handles, and configuration.
//!
//! This module provides [`RuntimeBuilder`] for constructing an Asupersync runtime
//! with customizable threading, scheduling, and deadline monitoring. The builder
//! follows a move-based fluent pattern where each method consumes `self` and
//! returns `Self`, enabling natural chaining.
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::runtime::RuntimeBuilder;
//!
//! // Minimal — uses all defaults (available parallelism, 128 poll budget, etc.)
//! let runtime = RuntimeBuilder::new().build()?;
//!
//! runtime.block_on(async {
//!     println!("Hello from asupersync!");
//! });
//! ```
//!
//! # Common Configurations
//!
//! ## High-Throughput Server
//!
//! ```ignore
//! let runtime = RuntimeBuilder::high_throughput()
//!     .blocking_threads(4, 256)
//!     .build()?;
//! ```
//!
//! ## Low-Latency Application
//!
//! ```ignore
//! let runtime = RuntimeBuilder::low_latency()
//!     .worker_threads(2)
//!     .build()?;
//! ```
//!
//! ## Single-Threaded (Phase 0 / Testing)
//!
//! ```ignore
//! let runtime = RuntimeBuilder::current_thread().build()?;
//! ```
//!
//! ## With Deadline Monitoring
//!
//! ```ignore
//! use std::time::Duration;
//!
//! let runtime = RuntimeBuilder::new()
//!     .deadline_monitoring(|m| {
//!         m.enabled(true)
//!          .check_interval(Duration::from_secs(1))
//!          .warning_threshold_fraction(0.2)
//!          .checkpoint_timeout(Duration::from_secs(30))
//!     })
//!     .build()?;
//! ```
//!
//! ## With Environment Variable Overrides
//!
//! The builder supports 12-factor app style environment variable configuration.
//! Environment variables override defaults but are themselves overridden by
//! programmatic settings applied after the call:
//!
//! ```ignore
//! // ASUPERSYNC_WORKER_THREADS=8 in environment
//! let runtime = RuntimeBuilder::new()
//!     .with_env_overrides()?     // reads env vars
//!     .steal_batch_size(32)      // programmatic override (highest priority)
//!     .build()?;
//!
//! assert_eq!(runtime.config().worker_threads, 8);  // from env
//! assert_eq!(runtime.config().steal_batch_size, 32); // from code
//! ```
//!
//! See [`env_config`](super::env_config) for the full list of supported variables.
//!
//! ## With TOML Config File (requires `config-file` feature)
//!
//! ```ignore
//! let runtime = RuntimeBuilder::from_toml("config/runtime.toml")?
//!     .with_env_overrides()?   // env vars override file values
//!     .worker_threads(4)       // programmatic override (highest priority)
//!     .build()?;
//! ```
//!
//! # Configuration Precedence
//!
//! When multiple sources set the same field, the highest-priority source wins:
//!
//! 1. **Programmatic** — `builder.worker_threads(4)` (highest)
//! 2. **Environment** — `ASUPERSYNC_WORKER_THREADS=8`
//! 3. **Config file** — `worker_threads = 16` in TOML
//! 4. **Defaults** — `RuntimeConfig::default()` (lowest)
//!
//! # Configuration Reference
//!
//! | Method | Default | Description |
//! |--------|---------|-------------|
//! | [`worker_threads`](RuntimeBuilder::worker_threads) | available parallelism | Number of async worker threads |
//! | [`thread_stack_size`](RuntimeBuilder::thread_stack_size) | 2 MiB | Stack size per worker |
//! | [`thread_name_prefix`](RuntimeBuilder::thread_name_prefix) | `"asupersync-worker"` | Thread name prefix |
//! | [`global_queue_limit`](RuntimeBuilder::global_queue_limit) | 0 (unbounded) | Global queue depth |
//! | [`steal_batch_size`](RuntimeBuilder::steal_batch_size) | 16 | Work-stealing batch size |
//! | [`blocking_threads`](RuntimeBuilder::blocking_threads) | 0, 0 | Blocking pool min/max |
//! | [`enable_parking`](RuntimeBuilder::enable_parking) | true | Park idle workers |
//! | [`poll_budget`](RuntimeBuilder::poll_budget) | 128 | Polls before cooperative yield |
//! | [`cancel_lane_max_streak`](RuntimeBuilder::cancel_lane_max_streak) | 16 | Max consecutive cancel dispatches |
//! | [`root_region_limits`](RuntimeBuilder::root_region_limits) | None | Admission limits for the root region |
//! | [`observability`](RuntimeBuilder::observability) | None | Attach structured logging collectors |
//!
//! # Error Handling
//!
//! The `build()` method returns `Result<Runtime, Error>`. Configuration values
//! are normalized (e.g., `worker_threads = 0` becomes 1) rather than rejected,
//! so `build()` rarely fails in practice:
//!
//! ```ignore
//! match RuntimeBuilder::new().build() {
//!     Ok(runtime) => { /* ready */ }
//!     Err(e) => eprintln!("runtime build failed: {e}"),
//! }
//! ```
//!
//! Environment variable and config file errors are returned eagerly:
//!
//! ```ignore
//! // Returns Err immediately if ASUPERSYNC_WORKER_THREADS contains "abc"
//! let builder = RuntimeBuilder::new().with_env_overrides()?;
//! ```

use crate::error::Error;
use crate::observability::metrics::MetricsProvider;
use crate::observability::ObservabilityConfig;
use crate::record::RegionLimits;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::deadline_monitor::{
    default_warning_handler, AdaptiveDeadlineConfig, DeadlineWarning, MonitorConfig,
};
use crate::runtime::reactor::Reactor;
use crate::runtime::scheduler::ThreeLaneScheduler;
use crate::runtime::RuntimeState;
use crate::runtime::SpawnError;
use crate::time::TimerDriverHandle;
use crate::trace::distributed::LogicalClockMode;
use crate::types::{Budget, CancelAttributionConfig};
use std::future::Future;
use std::io;
use std::pin::Pin;
use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Builder for constructing an Asupersync [`Runtime`] with custom configuration.
///
/// Use the fluent API to set fields, then call [`build()`](Self::build) to
/// produce a [`Runtime`]. Each setter takes `self` by value and returns `Self`,
/// so the builder cannot be partially consumed.
///
/// # Example
///
/// ```ignore
/// use asupersync::runtime::RuntimeBuilder;
/// use std::time::Duration;
///
/// let runtime = RuntimeBuilder::new()
///     .worker_threads(4)
///     .poll_budget(256)
///     .steal_batch_size(32)
///     .deadline_monitoring(|m| {
///         m.enabled(true)
///          .check_interval(Duration::from_secs(1))
///     })
///     .build()?;
/// ```
#[derive(Clone)]
pub struct RuntimeBuilder {
    config: RuntimeConfig,
    reactor: Option<Arc<dyn Reactor>>,
}

impl RuntimeBuilder {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: RuntimeConfig::default(),
            reactor: None,
        }
    }

    /// Set the number of worker threads.
    #[must_use]
    pub fn worker_threads(mut self, n: usize) -> Self {
        self.config.worker_threads = n;
        self
    }

    /// Set the response policy for obligation leaks.
    #[must_use]
    pub fn obligation_leak_response(
        mut self,
        response: crate::runtime::config::ObligationLeakResponse,
    ) -> Self {
        self.config.obligation_leak_response = response;
        self
    }

    /// Set the worker thread stack size.
    #[must_use]
    pub fn thread_stack_size(mut self, size: usize) -> Self {
        self.config.thread_stack_size = size;
        self
    }

    /// Set the worker thread name prefix.
    #[must_use]
    pub fn thread_name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.thread_name_prefix = prefix.into();
        self
    }

    /// Set the global queue limit (0 = unbounded).
    #[must_use]
    pub fn global_queue_limit(mut self, limit: usize) -> Self {
        self.config.global_queue_limit = limit;
        self
    }

    /// Set the work stealing batch size.
    #[must_use]
    pub fn steal_batch_size(mut self, size: usize) -> Self {
        self.config.steal_batch_size = size;
        self
    }

    /// Set the logical clock mode used for causal trace ordering.
    #[must_use]
    pub fn logical_clock_mode(mut self, mode: LogicalClockMode) -> Self {
        self.config.logical_clock_mode = Some(mode);
        self
    }

    /// Set cancellation attribution chain limits.
    #[must_use]
    pub fn cancel_attribution_config(mut self, config: CancelAttributionConfig) -> Self {
        self.config.cancel_attribution = config;
        self
    }

    /// Configure blocking pool thread limits.
    #[must_use]
    pub fn blocking_threads(mut self, min: usize, max: usize) -> Self {
        self.config.blocking.min_threads = min;
        self.config.blocking.max_threads = max;
        self
    }

    /// Enable or disable parking for idle workers.
    #[must_use]
    pub fn enable_parking(mut self, enable: bool) -> Self {
        self.config.enable_parking = enable;
        self
    }

    /// Set the poll budget before yielding.
    #[must_use]
    pub fn poll_budget(mut self, budget: u32) -> Self {
        self.config.poll_budget = budget;
        self
    }

    /// Set the maximum consecutive cancel-lane dispatches before yielding.
    #[must_use]
    pub fn cancel_lane_max_streak(mut self, max_streak: usize) -> Self {
        self.config.cancel_lane_max_streak = max_streak;
        self
    }

    /// Enable the Lyapunov governor for scheduling suggestions.
    ///
    /// When enabled, the scheduler periodically snapshots runtime state and
    /// consults the governor for lane-ordering hints that accelerate
    /// cancellation convergence.
    #[must_use]
    pub fn enable_governor(mut self, enable: bool) -> Self {
        self.config.enable_governor = enable;
        self
    }

    /// Set the number of scheduling steps between governor snapshots.
    ///
    /// Lower values increase responsiveness but add snapshot overhead.
    /// Default is 32. Only relevant when the governor is enabled.
    #[must_use]
    pub fn governor_interval(mut self, interval: u32) -> Self {
        self.config.governor_interval = interval;
        self
    }

    /// Set admission limits for the root region.
    #[must_use]
    pub fn root_region_limits(mut self, limits: RegionLimits) -> Self {
        self.config.root_region_limits = Some(limits);
        self
    }

    /// Clear root region admission limits (unlimited).
    #[must_use]
    pub fn clear_root_region_limits(mut self) -> Self {
        self.config.root_region_limits = None;
        self
    }

    /// Register a callback to run when a worker thread starts.
    #[must_use]
    pub fn on_thread_start<F>(mut self, f: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.config.on_thread_start = Some(Arc::new(f));
        self
    }

    /// Register a callback to run when a worker thread stops.
    #[must_use]
    pub fn on_thread_stop<F>(mut self, f: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.config.on_thread_stop = Some(Arc::new(f));
        self
    }

    /// Set the metrics provider for the runtime.
    ///
    /// The metrics provider receives callbacks for task spawning, completion,
    /// region lifecycle events, and scheduler metrics. Use this to export
    /// runtime metrics to OpenTelemetry, Prometheus, or custom backends.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::runtime::RuntimeBuilder;
    /// use asupersync::observability::OtelMetrics;
    /// use opentelemetry::global;
    ///
    /// let meter = global::meter("asupersync");
    /// let metrics = OtelMetrics::new(meter);
    ///
    /// let runtime = RuntimeBuilder::new()
    ///     .metrics(metrics)
    ///     .build()?;
    /// ```
    #[must_use]
    pub fn metrics<M: MetricsProvider>(mut self, provider: M) -> Self {
        self.config.metrics_provider = Arc::new(provider);
        self
    }

    /// Configure runtime observability (logging and diagnostic context).
    ///
    /// When provided, the runtime attaches a shared log collector to task
    /// contexts and configures diagnostic context defaults.
    #[must_use]
    pub fn observability(mut self, config: ObservabilityConfig) -> Self {
        self.config.observability = Some(config);
        self
    }

    /// Configure deadline monitoring for this runtime.
    ///
    /// The provided closure can customize thresholds and warning handlers.
    ///
    /// ```ignore
    /// use asupersync::runtime::RuntimeBuilder;
    /// use std::time::Duration;
    ///
    /// let runtime = RuntimeBuilder::new()
    ///     .deadline_monitoring(|m| {
    ///         m.check_interval(Duration::from_secs(1))
    ///             .warning_threshold_fraction(0.2)
    ///             .checkpoint_timeout(Duration::from_secs(30))
    ///             .on_warning(|w| {
    ///                 asupersync::tracing_compat::warn!(?w, "deadline warning");
    ///             })
    ///     })
    ///     .build();
    /// ```
    #[must_use]
    pub fn deadline_monitoring<F>(mut self, f: F) -> Self
    where
        F: FnOnce(DeadlineMonitoringBuilder) -> DeadlineMonitoringBuilder,
    {
        let builder = f(DeadlineMonitoringBuilder::new());
        let (config, handler) = builder.finish();
        let handler =
            handler.or_else(|| {
                if config.enabled {
                    Some(Arc::new(default_warning_handler)
                        as Arc<dyn Fn(DeadlineWarning) + Send + Sync>)
                } else {
                    None
                }
            });

        self.config.deadline_monitor = Some(config);
        self.config.deadline_warning_handler = handler;
        self
    }

    /// Apply environment variable overrides to the current configuration.
    ///
    /// Only environment variables that are set are applied. Unset variables
    /// leave the current configuration unchanged.
    ///
    /// # Precedence
    ///
    /// Environment variables override config file values and defaults, but
    /// programmatic settings applied *after* this call take highest priority.
    ///
    /// Typical usage:
    ///
    /// ```ignore
    /// let runtime = RuntimeBuilder::new()
    ///     .with_env_overrides()?   // env vars override defaults
    ///     .worker_threads(4)       // programmatic override (highest priority)
    ///     .build()?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if an environment variable is set but contains an
    /// unparseable value (e.g., `ASUPERSYNC_WORKER_THREADS=abc`).
    ///
    /// See [`env_config`](super::env_config) for the full list of supported variables.
    #[allow(clippy::result_large_err)]
    pub fn with_env_overrides(mut self) -> Result<Self, Error> {
        crate::runtime::env_config::apply_env_overrides(&mut self.config).map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        Ok(self)
    }

    /// Load configuration from a TOML file.
    ///
    /// Values from the file are applied as a base; environment variables
    /// and programmatic settings take precedence.
    ///
    /// Requires the `config-file` feature.
    ///
    /// ```ignore
    /// let runtime = RuntimeBuilder::from_toml("config/runtime.toml")?
    ///     .with_env_overrides()?   // env vars override file values
    ///     .worker_threads(4)       // programmatic override (highest priority)
    ///     .build()?;
    /// ```
    #[cfg(feature = "config-file")]
    pub fn from_toml(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let toml_config =
            crate::runtime::env_config::parse_toml_file(path.as_ref()).map_err(|e| {
                Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
            })?;
        let mut config = RuntimeConfig::default();
        crate::runtime::env_config::apply_toml_config(&mut config, &toml_config);
        Ok(Self {
            config,
            reactor: None,
        })
    }

    /// Load configuration from a TOML string.
    ///
    /// Values from the string are applied as a base; environment variables
    /// and programmatic settings take precedence.
    ///
    /// Requires the `config-file` feature.
    ///
    /// ```ignore
    /// let toml = r#"
    /// [scheduler]
    /// worker_threads = 4
    /// poll_budget = 256
    /// "#;
    /// let runtime = RuntimeBuilder::from_toml_str(toml)?
    ///     .with_env_overrides()?
    ///     .build()?;
    /// ```
    #[cfg(feature = "config-file")]
    pub fn from_toml_str(toml: &str) -> Result<Self, Error> {
        let toml_config = crate::runtime::env_config::parse_toml_str(toml).map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        let mut config = RuntimeConfig::default();
        crate::runtime::env_config::apply_toml_config(&mut config, &toml_config);
        Ok(Self {
            config,
            reactor: None,
        })
    }

    /// Build a runtime from this configuration.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<Runtime, Error> {
        Runtime::with_config_and_reactor(self.config, self.reactor)
    }

    /// Provide a reactor for runtime I/O integration.
    ///
    /// When set, the runtime will attach an `IoDriver` backed by this reactor.
    #[must_use]
    pub fn with_reactor(mut self, reactor: Arc<dyn Reactor>) -> Self {
        self.reactor = Some(reactor);
        self
    }

    /// Preset: single-threaded runtime.
    ///
    /// Equivalent to `RuntimeBuilder::new().worker_threads(1)`.
    /// Suitable for testing, deterministic replay, and Phase 0 usage.
    ///
    /// ```ignore
    /// let rt = RuntimeBuilder::current_thread().build()?;
    /// rt.block_on(async { /* single-threaded execution */ });
    /// ```
    #[must_use]
    pub fn current_thread() -> Self {
        Self::new().worker_threads(1)
    }

    /// Preset: multi-threaded runtime with default parallelism.
    ///
    /// Equivalent to `RuntimeBuilder::new()`. Worker count defaults to
    /// the available CPU parallelism.
    #[must_use]
    pub fn multi_thread() -> Self {
        Self::new()
    }

    /// Preset: high-throughput server.
    ///
    /// Uses 2x the available parallelism for workers and a larger
    /// steal batch size (32) to amortize scheduling overhead.
    ///
    /// ```ignore
    /// let rt = RuntimeBuilder::high_throughput()
    ///     .blocking_threads(4, 256)
    ///     .build()?;
    /// ```
    #[must_use]
    pub fn high_throughput() -> Self {
        let workers = RuntimeConfig::default_worker_threads()
            .saturating_mul(2)
            .max(1);
        Self::new().worker_threads(workers).steal_batch_size(32)
    }

    /// Preset: low-latency interactive application.
    ///
    /// Uses smaller steal batches (4) and tighter poll budgets (32)
    /// to reduce tail latency at the cost of throughput.
    ///
    /// ```ignore
    /// let rt = RuntimeBuilder::low_latency()
    ///     .worker_threads(2)
    ///     .build()?;
    /// ```
    #[must_use]
    pub fn low_latency() -> Self {
        Self::new().steal_batch_size(4).poll_budget(32)
    }
}

/// Sub-builder for deadline monitoring configuration.
///
/// Obtained through [`RuntimeBuilder::deadline_monitoring`]. Allows fine-grained
/// control over deadline checking intervals, warning thresholds, and adaptive
/// deadline behavior.
///
/// # Example
///
/// ```ignore
/// use std::time::Duration;
///
/// RuntimeBuilder::new()
///     .deadline_monitoring(|m| {
///         m.enabled(true)
///          .check_interval(Duration::from_secs(1))
///          .warning_threshold_fraction(0.2) // warn at 80% of deadline
///          .checkpoint_timeout(Duration::from_secs(30))
///          .adaptive_enabled(true)
///          .adaptive_warning_percentile(0.95)
///          .on_warning(|w| eprintln!("deadline warning: {w:?}"))
///     })
///     .build()?;
/// ```
pub struct DeadlineMonitoringBuilder {
    config: MonitorConfig,
    on_warning: Option<Arc<dyn Fn(DeadlineWarning) + Send + Sync>>,
}

impl DeadlineMonitoringBuilder {
    fn new() -> Self {
        Self {
            config: MonitorConfig::default(),
            on_warning: None,
        }
    }

    /// Use an explicit monitor configuration.
    #[must_use]
    pub fn config(mut self, config: MonitorConfig) -> Self {
        self.config = config;
        self
    }

    /// Set how often the monitor should scan for warnings.
    #[must_use]
    pub fn check_interval(mut self, interval: Duration) -> Self {
        self.config.check_interval = interval;
        self
    }

    /// Set the fraction of deadline remaining that triggers a warning.
    #[must_use]
    pub fn warning_threshold_fraction(mut self, fraction: f64) -> Self {
        self.config.warning_threshold_fraction = fraction;
        self
    }

    /// Set how long a task may go without progress before warning.
    #[must_use]
    pub fn checkpoint_timeout(mut self, timeout: Duration) -> Self {
        self.config.checkpoint_timeout = timeout;
        self
    }

    /// Use an explicit adaptive deadline configuration.
    #[must_use]
    pub fn adaptive_config(mut self, config: AdaptiveDeadlineConfig) -> Self {
        self.config.adaptive = config;
        self
    }

    /// Enable or disable adaptive deadline thresholds.
    #[must_use]
    pub fn adaptive_enabled(mut self, enabled: bool) -> Self {
        self.config.adaptive.adaptive_enabled = enabled;
        self
    }

    /// Set the adaptive warning percentile.
    #[must_use]
    pub fn adaptive_warning_percentile(mut self, percentile: f64) -> Self {
        self.config.adaptive.warning_percentile = percentile;
        self
    }

    /// Set the minimum samples required for adaptive thresholds.
    #[must_use]
    pub fn adaptive_min_samples(mut self, min_samples: usize) -> Self {
        self.config.adaptive.min_samples = min_samples;
        self
    }

    /// Set the maximum history length per task type.
    #[must_use]
    pub fn adaptive_max_history(mut self, max_history: usize) -> Self {
        self.config.adaptive.max_history = max_history;
        self
    }

    /// Set the fallback threshold used before enough samples are collected.
    #[must_use]
    pub fn adaptive_fallback_threshold(mut self, threshold: Duration) -> Self {
        self.config.adaptive.fallback_threshold = threshold;
        self
    }

    /// Enable or disable deadline monitoring.
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Register a custom warning handler.
    #[must_use]
    pub fn on_warning<F>(mut self, f: F) -> Self
    where
        F: Fn(DeadlineWarning) + Send + Sync + 'static,
    {
        self.on_warning = Some(Arc::new(f));
        self
    }

    #[allow(clippy::type_complexity)]
    fn finish(
        self,
    ) -> (
        MonitorConfig,
        Option<Arc<dyn Fn(DeadlineWarning) + Send + Sync>>,
    ) {
        (self.config, self.on_warning)
    }
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A configured Asupersync runtime.
///
/// Created via [`RuntimeBuilder`]. The runtime owns worker threads and a
/// three-lane priority scheduler. Clone is cheap (shared `Arc`).
///
/// # Example
///
/// ```ignore
/// let runtime = RuntimeBuilder::new().worker_threads(2).build()?;
///
/// // Run a future to completion on the current thread.
/// let result = runtime.block_on(async { 1 + 1 });
/// assert_eq!(result, 2);
///
/// // Spawn from outside async context via a handle.
/// let handle = runtime.handle().spawn(async { 42u32 });
/// let value = runtime.block_on(handle);
/// assert_eq!(value, 42);
/// ```
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

impl Runtime {
    /// Construct a runtime from the given configuration.
    #[allow(clippy::result_large_err)]
    pub fn with_config(config: RuntimeConfig) -> Result<Self, Error> {
        Self::with_config_and_reactor(config, None)
    }

    /// Construct a runtime from the given configuration and reactor.
    #[allow(clippy::result_large_err)]
    pub fn with_config_and_reactor(
        mut config: RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
    ) -> Result<Self, Error> {
        config.normalize();
        Ok(Self {
            inner: Arc::new(RuntimeInner::new(config, reactor).map_err(|e| {
                Error::new(crate::error::ErrorKind::Internal)
                    .with_message(format!("runtime init: {e}"))
            })?),
        })
    }

    /// Returns a handle that can spawn tasks from outside the runtime.
    #[must_use]
    pub fn handle(&self) -> RuntimeHandle {
        RuntimeHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Run a future to completion on the current thread.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        if let Some(callback) = self.inner.config.on_thread_start.as_ref() {
            callback();
        }
        let output = run_future_with_budget(future, self.inner.config.poll_budget);
        if let Some(callback) = self.inner.config.on_thread_stop.as_ref() {
            callback();
        }
        output
    }

    /// Returns a reference to the runtime configuration.
    #[must_use]
    pub fn config(&self) -> &RuntimeConfig {
        &self.inner.config
    }

    /// Returns true if the runtime is quiescent (no live tasks or I/O).
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        let guard = self
            .inner
            .state
            .lock()
            .expect("runtime state lock poisoned");
        guard.is_quiescent()
    }

    /// Spawns a blocking task on the blocking pool.
    ///
    /// Returns `None` if the blocking pool is not configured (max_threads = 0).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let runtime = RuntimeBuilder::new()
    ///     .blocking_threads(1, 4)
    ///     .build()?;
    ///
    /// let handle = runtime.spawn_blocking(|| {
    ///     std::fs::read_to_string("/etc/hosts")
    /// });
    /// ```
    pub fn spawn_blocking<F>(
        &self,
        f: F,
    ) -> Option<crate::runtime::blocking_pool::BlockingTaskHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        self.inner.blocking_pool.as_ref().map(|pool| pool.spawn(f))
    }

    /// Returns a handle to the blocking pool, if configured.
    #[must_use]
    pub fn blocking_handle(&self) -> Option<crate::runtime::blocking_pool::BlockingPoolHandle> {
        self.inner.blocking_handle()
    }
}

/// Handle for spawning tasks onto a runtime from outside async context.
///
/// Cheap to clone (shared `Arc`). Use [`Runtime::handle`] to obtain one.
///
/// ```ignore
/// let runtime = RuntimeBuilder::new().build()?;
/// let handle = runtime.handle();
///
/// // Spawn from any thread.
/// let join = handle.spawn(async { compute_result().await });
/// let result = runtime.block_on(join);
/// ```
#[derive(Clone)]
pub struct RuntimeHandle {
    inner: Arc<RuntimeInner>,
}

impl RuntimeHandle {
    /// Spawn a task from outside async context.
    ///
    /// Panics if the root region rejects admission. Use [`RuntimeHandle::try_spawn`]
    /// to handle admission errors explicitly.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.try_spawn(future)
            .expect("failed to create runtime task")
    }

    /// Spawn a task from outside async context, returning admission errors.
    pub fn try_spawn<F>(&self, future: F) -> Result<JoinHandle<F::Output>, SpawnError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.spawn(future)
    }

    /// Spawns a blocking task on the blocking pool.
    ///
    /// Returns `None` if the blocking pool is not configured.
    pub fn spawn_blocking<F>(
        &self,
        f: F,
    ) -> Option<crate::runtime::blocking_pool::BlockingTaskHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        self.inner.blocking_pool.as_ref().map(|pool| pool.spawn(f))
    }

    /// Returns a handle to the blocking pool, if configured.
    #[must_use]
    pub fn blocking_handle(&self) -> Option<crate::runtime::blocking_pool::BlockingPoolHandle> {
        self.inner.blocking_handle()
    }
}

/// A join handle returned by [`RuntimeHandle::spawn`].
pub struct JoinHandle<T> {
    state: Arc<Mutex<JoinState<T>>>,
}

impl<T> JoinHandle<T> {
    fn new(state: Arc<Mutex<JoinState<T>>>) -> Self {
        Self { state }
    }

    /// Returns true if the task has completed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        let guard = lock_state(&self.state);
        guard.result.is_some()
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = lock_state(&self.state);
        match guard.result.take() {
            None => {
                guard.waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Some(Ok(output)) => Poll::Ready(output),
            Some(Err(payload)) => std::panic::resume_unwind(payload),
        }
    }
}

struct CatchUnwind<F>(Pin<Box<F>>);

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.0.as_mut();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx)));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

struct RuntimeInner {
    config: RuntimeConfig,
    state: Arc<crate::sync::ContendedMutex<RuntimeState>>,
    scheduler: ThreeLaneScheduler,
    worker_threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    root_region: crate::types::RegionId,
    /// Blocking pool for synchronous operations.
    blocking_pool: Option<crate::runtime::blocking_pool::BlockingPool>,
    /// Shutdown signal for the deadline monitor thread.
    deadline_monitor_shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Deadline monitor background thread handle.
    deadline_monitor_thread: Option<std::thread::JoinHandle<()>>,
}

impl RuntimeInner {
    fn new(config: RuntimeConfig, reactor: Option<Arc<dyn Reactor>>) -> io::Result<Self> {
        // Runtime currently instantiates the unified RuntimeState path.
        // ShardedState exists behind migration work, but there is not yet a
        // RuntimeConfig layout switch wired here (see bd-2f7uj runbook).
        let state = Arc::new(crate::sync::ContendedMutex::new(
            "runtime_state",
            match reactor {
                Some(reactor) => {
                    RuntimeState::with_reactor_and_metrics(reactor, config.metrics_provider.clone())
                }
                None => RuntimeState::new_with_metrics(config.metrics_provider.clone()),
            },
        ));
        let root_region = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            if let Some(observability) = config.observability.clone() {
                guard.set_observability_config(observability);
            }
            if let Some(mode) = config.logical_clock_mode.clone() {
                guard.set_logical_clock_mode(mode);
            }
            guard.set_cancel_attribution_config(config.cancel_attribution);
            guard.set_obligation_leak_response(config.obligation_leak_response);
            guard.set_leak_escalation(config.leak_escalation);
            if guard.timer_driver().is_none() {
                guard.set_timer_driver(TimerDriverHandle::with_wall_clock());
            }
            let root = guard.create_root_region(Budget::INFINITE);
            if let Some(limits) = config.root_region_limits.clone() {
                let _ = guard.set_region_limits(root, limits);
            }
            root
        };

        let mut scheduler = ThreeLaneScheduler::new_with_options(
            config.worker_threads,
            &state,
            config.cancel_lane_max_streak,
            config.enable_governor,
            config.governor_interval,
        );
        scheduler.set_steal_batch_size(config.steal_batch_size);
        scheduler.set_enable_parking(config.enable_parking);
        scheduler.set_global_queue_limit(config.global_queue_limit);

        let mut worker_threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
        if config.worker_threads > 0 {
            let workers = scheduler.take_workers();
            for worker in workers {
                let name = {
                    let id = worker.id;
                    format!("{}-{id}", config.thread_name_prefix)
                };
                let on_start = config.on_thread_start.clone();
                let on_stop = config.on_thread_stop.clone();
                let mut builder = std::thread::Builder::new().name(name);
                if config.thread_stack_size > 0 {
                    builder = builder.stack_size(config.thread_stack_size);
                }
                let handle = builder
                    .spawn(move || {
                        if let Some(callback) = on_start.as_ref() {
                            callback();
                        }
                        let mut worker = worker;
                        worker.run_loop();
                        if let Some(callback) = on_stop.as_ref() {
                            callback();
                        }
                    })
                    .map_err(|e| {
                        // Signal already-running workers to exit their run loops,
                        // then join them so they don't leak.
                        scheduler.shutdown();
                        while let Some(handle) = worker_threads.pop() {
                            let _ = handle.join();
                        }
                        io::Error::other(format!("failed to spawn worker thread: {e}"))
                    })?;
                worker_threads.push(handle);
            }
        }

        let (deadline_monitor_shutdown, deadline_monitor_thread) =
            Self::start_deadline_monitor(&config, &state);

        let blocking_pool = Self::create_blocking_pool(&config);
        if let Some(pool) = blocking_pool.as_ref() {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            guard.set_blocking_pool(pool.handle());
        }

        Ok(Self {
            config,
            state,
            scheduler,
            worker_threads: Mutex::new(worker_threads),
            root_region,
            blocking_pool,
            deadline_monitor_shutdown,
            deadline_monitor_thread,
        })
    }

    /// Creates the blocking pool if configured with non-zero max threads.
    fn create_blocking_pool(
        config: &RuntimeConfig,
    ) -> Option<crate::runtime::blocking_pool::BlockingPool> {
        if config.blocking.max_threads == 0 {
            return None;
        }
        let options = crate::runtime::blocking_pool::BlockingPoolOptions {
            idle_timeout: Duration::from_secs(10),
            thread_name_prefix: format!("{}-blocking", config.thread_name_prefix),
            on_thread_start: config.on_thread_start.clone(),
            on_thread_stop: config.on_thread_stop.clone(),
        };
        Some(crate::runtime::blocking_pool::BlockingPool::with_config(
            config.blocking.min_threads,
            config.blocking.max_threads,
            options,
        ))
    }

    /// Starts the deadline monitor background thread if configured and enabled.
    fn start_deadline_monitor(
        config: &RuntimeConfig,
        state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
    ) -> (
        Option<Arc<std::sync::atomic::AtomicBool>>,
        Option<std::thread::JoinHandle<()>>,
    ) {
        use crate::runtime::deadline_monitor::DeadlineMonitor;
        use std::sync::atomic::AtomicBool;

        let monitor_config = match config.deadline_monitor {
            Some(ref mc) if mc.enabled => mc,
            _ => return (None, None),
        };

        let dm_shutdown = Arc::new(AtomicBool::new(false));
        let dm_shutdown_clone = Arc::clone(&dm_shutdown);
        let dm_state = Arc::clone(state);
        let check_interval = monitor_config.check_interval;
        let mut monitor = DeadlineMonitor::new(monitor_config.clone());
        if let Some(ref handler) = config.deadline_warning_handler {
            let handler = Arc::clone(handler);
            monitor.on_warning(move |w| handler(w));
        }
        monitor.set_metrics_provider(Arc::clone(&config.metrics_provider));

        let thread_name = format!("{}-deadline-monitor", config.thread_name_prefix);
        let thread = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                while !dm_shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(check_interval);
                    if dm_shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let guard = dm_state.lock().expect("runtime state lock poisoned");
                    let now = guard.now;
                    monitor.check(now, guard.tasks_iter().map(|(_, record)| record));
                }
            })
            .ok();
        (Some(dm_shutdown), thread)
    }

    fn spawn<F>(&self, future: F) -> Result<JoinHandle<F::Output>, SpawnError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let join_state = Arc::new(Mutex::new(JoinState::new()));
        let join_state_for_task = Arc::clone(&join_state);

        let wrapped = async move {
            // Ensure panics in the spawned task don't take down a worker thread. If the join
            // handle is awaited, we re-raise the original panic payload on the awaiter.
            let result = CatchUnwind(Box::pin(future)).await;
            complete_task(&join_state_for_task, result);
        };

        let task_id = {
            let mut guard = self.state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) =
                guard.create_task(self.root_region, Budget::INFINITE, wrapped)?;
            task_id
        };

        self.scheduler
            .inject_ready(task_id, Budget::INFINITE.priority);

        Ok(JoinHandle::new(join_state))
    }

    /// Returns a handle to the blocking pool, if configured.
    fn blocking_handle(&self) -> Option<crate::runtime::blocking_pool::BlockingPoolHandle> {
        self.blocking_pool
            .as_ref()
            .map(crate::runtime::blocking_pool::BlockingPool::handle)
    }
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        // Signal deadline monitor to stop, then join its thread.
        if let Some(shutdown) = self.deadline_monitor_shutdown.take() {
            shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(thread) = self.deadline_monitor_thread.take() {
            let _ = thread.join();
        }
        self.scheduler.shutdown();
        // Shutdown blocking pool first (it may have tasks that need to drain)
        if let Some(pool) = self.blocking_pool.take() {
            pool.shutdown();
        }
        let mut handles = lock_state(&self.worker_threads);
        for handle in handles.drain(..) {
            let _ = handle.join();
        }
    }
}

struct JoinState<T> {
    result: Option<std::thread::Result<T>>,
    waker: Option<Waker>,
}

impl<T> JoinState<T> {
    fn new() -> Self {
        Self {
            result: None,
            waker: None,
        }
    }
}

fn lock_state<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state.lock()
}

fn run_task<F, T>(
    state: &Arc<Mutex<JoinState<T>>>,
    future: &Arc<Mutex<Option<F>>>,
    config: &RuntimeConfig,
) where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if let Some(callback) = config.on_thread_start.as_ref() {
        callback();
    }

    let future = {
        let mut guard = lock_state(future);
        guard.take()
    };
    let Some(future) = future else {
        return;
    };
    let output = run_future_with_budget(future, config.poll_budget);

    if let Some(callback) = config.on_thread_stop.as_ref() {
        callback();
    }

    complete_task(state, Ok(output));
}

fn complete_task<T>(state: &Arc<Mutex<JoinState<T>>>, output: std::thread::Result<T>) {
    let waker = {
        let mut guard = lock_state(state);
        guard.result = Some(output);
        guard.waker.take()
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn run_future_with_budget<F: Future>(future: F, poll_budget: u32) -> F::Output {
    let thread = std::thread::current();
    let waker = Waker::from(Arc::new(ThreadWaker(thread)));
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    let mut polls = 0u32;
    let budget = poll_budget.max(1);

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {
                polls = polls.saturating_add(1);
                if polls >= budget {
                    // Yield to other threads if we exhausted budget (cooperative)
                    std::thread::yield_now();
                    polls = 0;
                } else {
                    // Park until woken
                    std::thread::park();
                }
            }
        }
    }
}

struct ThreadWaker(std::thread::Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::lab::{LabConfig, LabRuntime};
    use crate::runtime::reactor::{Event, Interest, LabReactor, Reactor};
    use crate::test_utils::init_test_logging;
    use crate::time::sleep;
    use crate::trace::{TraceEvent, TraceEventKind};
    use crate::types::{Budget, CancelReason, Time};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn runtime_handle_spawn_completes_via_scheduler() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime build");

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        let handle = runtime.handle().spawn(async move {
            flag_clone.store(true, Ordering::SeqCst);
            42u32
        });

        let result = runtime.block_on(handle);
        assert_eq!(result, 42);
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn runtime_spawn_blocking_executes_on_pool() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(1, 2)
            .build()
            .expect("runtime build");

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        // Spawn blocking task via runtime
        let handle = runtime
            .spawn_blocking(move || {
                flag_clone.store(true, Ordering::SeqCst);
            })
            .expect("blocking pool configured");

        // Wait for completion
        handle.wait();
        assert!(flag.load(Ordering::SeqCst), "blocking task should have run");
    }

    #[test]
    fn runtime_without_blocking_pool_returns_none() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(0, 0)
            .build()
            .expect("runtime build");

        let handle = runtime.spawn_blocking(|| {});
        assert!(
            handle.is_none(),
            "spawn_blocking should return None when pool is not configured"
        );
        assert!(
            runtime.blocking_handle().is_none(),
            "blocking_handle should return None"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TraceCounts {
        region_created: usize,
        spawn: usize,
        complete: usize,
        timer_scheduled: usize,
        timer_fired: usize,
        timer_cancelled: usize,
        io_requested: usize,
        io_ready: usize,
        cancel_request: usize,
    }

    fn parity_counts(events: Vec<TraceEvent>) -> TraceCounts {
        let mut counts = TraceCounts {
            region_created: 0,
            spawn: 0,
            complete: 0,
            timer_scheduled: 0,
            timer_fired: 0,
            timer_cancelled: 0,
            io_requested: 0,
            io_ready: 0,
            cancel_request: 0,
        };

        for event in events {
            match event.kind {
                TraceEventKind::RegionCreated => counts.region_created += 1,
                TraceEventKind::Spawn => counts.spawn += 1,
                TraceEventKind::Complete => counts.complete += 1,
                TraceEventKind::TimerScheduled => counts.timer_scheduled += 1,
                TraceEventKind::TimerFired => counts.timer_fired += 1,
                TraceEventKind::TimerCancelled => counts.timer_cancelled += 1,
                TraceEventKind::IoRequested => counts.io_requested += 1,
                TraceEventKind::IoReady => counts.io_ready += 1,
                TraceEventKind::CancelRequest => counts.cancel_request += 1,
                _ => {}
            }
        }

        counts
    }

    fn wait_for_runtime_quiescent(runtime: &Runtime) {
        for _ in 0..1000 {
            let live_tasks = runtime
                .inner
                .state
                .lock()
                .expect("runtime state lock poisoned")
                .live_task_count();
            if live_tasks == 0 {
                return;
            }
            std::thread::yield_now();
        }
        unreachable!("runtime failed to reach quiescence after waiting");
    }

    #[cfg(unix)]
    struct TestFdSource;

    #[cfg(unix)]
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[test]
    fn lab_runtime_matches_prod_trace_for_basic_spawn() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let lab_region = lab.state.create_root_region(Budget::INFINITE);
        for _ in 0..2 {
            let (task_id, _handle) = lab
                .state
                .create_task(lab_region, Budget::INFINITE, async { 1_u8 })
                .expect("lab task spawn");
            lab.scheduler
                .lock()
                .schedule(task_id, Budget::INFINITE.priority);
            lab.run_until_quiescent();
        }

        let lab_counts = parity_counts(lab.trace().snapshot());
        assert_eq!(
            lab_counts.spawn, lab_counts.complete,
            "lab trace should complete every spawned task"
        );

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        for _ in 0..2 {
            let handle = runtime.handle().spawn(async { 1_u8 });
            let _ = runtime.block_on(handle);
        }
        wait_for_runtime_quiescent(&runtime);

        let runtime_counts = {
            let guard = runtime
                .inner
                .state
                .lock()
                .expect("runtime state lock poisoned");
            parity_counts(guard.trace.snapshot())
        };
        assert_eq!(
            runtime_counts.spawn, runtime_counts.complete,
            "runtime trace should complete every spawned task"
        );

        assert_eq!(lab_counts, runtime_counts);
    }

    async fn sleep_once() {
        let now = Cx::current()
            .and_then(|cx| cx.timer_driver())
            .map_or(Time::ZERO, |driver| driver.now());
        sleep(now, Duration::from_millis(1)).await;
    }

    #[test]
    #[ignore = "block_on parks thread on Pending; current-thread runtime cannot drive timers"]
    fn lab_runtime_matches_prod_trace_for_timer_sleep() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let lab_region = lab.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = lab
            .state
            .create_task(lab_region, Budget::INFINITE, sleep_once())
            .expect("lab sleep task spawn");
        lab.scheduler
            .lock()
            .schedule(task_id, Budget::INFINITE.priority);

        lab.step_for_test(); // register timer
        lab.advance_time(1_000_000);
        lab.run_until_quiescent();

        let lab_counts = parity_counts(lab.trace().snapshot());
        assert!(
            lab_counts.timer_scheduled > 0,
            "lab trace should record timer scheduling"
        );
        assert_eq!(
            lab_counts.timer_scheduled, lab_counts.timer_fired,
            "lab trace should fire every scheduled timer"
        );

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let handle = runtime.handle().spawn(sleep_once());
        runtime.block_on(handle);
        wait_for_runtime_quiescent(&runtime);

        let runtime_counts = {
            let guard = runtime
                .inner
                .state
                .lock()
                .expect("runtime state lock poisoned");
            parity_counts(guard.trace.snapshot())
        };
        assert!(
            runtime_counts.timer_scheduled > 0,
            "runtime trace should record timer scheduling"
        );
        assert_eq!(
            runtime_counts.timer_scheduled, runtime_counts.timer_fired,
            "runtime trace should fire every scheduled timer"
        );

        assert_eq!(lab_counts, runtime_counts);
    }

    #[test]
    fn lab_runtime_matches_prod_trace_for_cancel_request() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let lab_region = lab.state.create_root_region(Budget::INFINITE);
        let _ = lab
            .state
            .create_task(lab_region, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("lab task spawn");
        let _ = lab
            .state
            .cancel_request(lab_region, &CancelReason::user("stop"), None);
        let lab_counts = parity_counts(lab.trace().snapshot());
        assert!(
            lab_counts.cancel_request > 0,
            "lab trace should record cancel request"
        );

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        {
            let mut guard = runtime
                .inner
                .state
                .lock()
                .expect("runtime state lock poisoned");
            let region = runtime.inner.root_region;
            let _ = guard
                .create_task(region, Budget::INFINITE, async {
                    std::future::pending::<()>().await;
                })
                .expect("runtime task spawn");
            let _ = guard.cancel_request(region, &CancelReason::user("stop"), None);
        }
        let runtime_counts = {
            let guard = runtime
                .inner
                .state
                .lock()
                .expect("runtime state lock poisoned");
            parity_counts(guard.trace.snapshot())
        };
        assert!(
            runtime_counts.cancel_request > 0,
            "runtime trace should record cancel request"
        );

        assert_eq!(lab_counts, runtime_counts);
    }

    #[cfg(unix)]
    #[test]
    fn lab_runtime_matches_prod_trace_for_io_ready() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let handle = lab.state.io_driver_handle().expect("lab io driver");
        let registration = handle
            .register(&TestFdSource, Interest::READABLE, noop_waker())
            .expect("lab register source");
        let io_key = registration.token();
        lab.lab_reactor()
            .inject_event(io_key, Event::readable(io_key), Duration::ZERO);
        lab.step_for_test();
        let lab_counts = parity_counts(lab.trace().snapshot());
        assert!(
            lab_counts.io_requested > 0,
            "lab trace should record io requested"
        );
        assert_eq!(
            lab_counts.io_requested, lab_counts.io_ready,
            "lab trace should record ready after request"
        );

        let reactor = Arc::new(LabReactor::new());
        let reactor_handle: Arc<dyn Reactor> = reactor.clone();
        let state = RuntimeState::with_reactor(reactor_handle);
        let driver = state.io_driver_handle().expect("runtime state io driver");
        let registration = driver
            .register(&TestFdSource, Interest::READABLE, noop_waker())
            .expect("runtime state register source");
        let io_key = registration.token();
        reactor.inject_event(io_key, Event::readable(io_key), Duration::ZERO);
        let trace = state.trace_handle();
        let now = Time::ZERO;
        let mut seen = HashSet::new();
        let _ = driver.turn_with(Some(Duration::ZERO), |event, interest| {
            let io_key = event.token.0 as u64;
            let interest_bits = interest.unwrap_or(event.ready).bits();
            if seen.insert(io_key) {
                let seq = trace.next_seq();
                trace.push_event(TraceEvent::io_requested(seq, now, io_key, interest_bits));
            }
            let seq = trace.next_seq();
            trace.push_event(TraceEvent::io_ready(seq, now, io_key, event.ready.bits()));
        });

        let runtime_counts = parity_counts(state.trace.snapshot());
        assert!(
            runtime_counts.io_requested > 0,
            "runtime trace should record io requested"
        );
        assert_eq!(
            runtime_counts.io_requested, runtime_counts.io_ready,
            "runtime trace should record ready after request"
        );

        assert_eq!(lab_counts.io_requested, runtime_counts.io_requested);
        assert_eq!(lab_counts.io_ready, runtime_counts.io_ready);
    }

    fn with_clean_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = crate::test_utils::env_lock();
        clean_env_locked();
        f()
    }

    /// Helper: set env vars for a closure, then clean up.
    fn with_envs<F, R>(vars: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_env(|| {
            for (k, v) in vars {
                std::env::set_var(k, v);
            }
            let result = f();
            for (k, _) in vars {
                std::env::remove_var(k);
            }
            result
        })
    }

    fn clean_env() {
        let _guard = crate::test_utils::env_lock();
        clean_env_locked();
    }

    fn clean_env_locked() {
        use crate::runtime::env_config::*;
        for var in &[
            ENV_WORKER_THREADS,
            ENV_TASK_QUEUE_DEPTH,
            ENV_THREAD_STACK_SIZE,
            ENV_THREAD_NAME_PREFIX,
            ENV_STEAL_BATCH_SIZE,
            ENV_BLOCKING_MIN_THREADS,
            ENV_BLOCKING_MAX_THREADS,
            ENV_ENABLE_PARKING,
            ENV_POLL_BUDGET,
        ] {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn with_env_overrides_applies_env_vars() {
        use crate::runtime::env_config::*;
        with_envs(
            &[(ENV_WORKER_THREADS, "4"), (ENV_POLL_BUDGET, "64")],
            || {
                let runtime = RuntimeBuilder::new()
                    .with_env_overrides()
                    .expect("env overrides")
                    .build()
                    .expect("runtime build");
                assert_eq!(runtime.config().worker_threads, 4);
                assert_eq!(runtime.config().poll_budget, 64);
            },
        );
    }

    #[test]
    fn programmatic_overrides_env_vars() {
        use crate::runtime::env_config::*;
        with_envs(&[(ENV_WORKER_THREADS, "8")], || {
            // Env says 8, but programmatic says 2 — programmatic wins.
            let runtime = RuntimeBuilder::new()
                .with_env_overrides()
                .expect("env overrides")
                .worker_threads(2)
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 2);
        });
    }

    #[test]
    fn with_env_overrides_invalid_var_returns_error() {
        use crate::runtime::env_config::*;
        with_envs(&[(ENV_WORKER_THREADS, "not_a_number")], || {
            let result = RuntimeBuilder::new().with_env_overrides();
            assert!(result.is_err());
        });
    }

    #[test]
    fn with_env_overrides_no_vars_uses_defaults() {
        with_clean_env(|| {
            let defaults = RuntimeConfig::default();
            let runtime = RuntimeBuilder::new()
                .with_env_overrides()
                .expect("env overrides")
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().poll_budget, defaults.poll_budget);
        });
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_builds_runtime() {
        let toml = r#"
[scheduler]
worker_threads = 2
poll_budget = 32
"#;
        let runtime = RuntimeBuilder::from_toml_str(toml)
            .expect("from_toml_str")
            .build()
            .expect("runtime build");
        assert_eq!(runtime.config().worker_threads, 2);
        assert_eq!(runtime.config().poll_budget, 32);
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_with_programmatic_override() {
        let toml = r#"
[scheduler]
worker_threads = 8
"#;
        let runtime = RuntimeBuilder::from_toml_str(toml)
            .expect("from_toml_str")
            .worker_threads(2) // programmatic override
            .build()
            .expect("runtime build");
        assert_eq!(runtime.config().worker_threads, 2);
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_invalid_returns_error() {
        let result = RuntimeBuilder::from_toml_str("not valid {{{{");
        assert!(result.is_err());
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn precedence_programmatic_over_env_over_toml() {
        use crate::runtime::env_config::*;
        // TOML says 16, env says 8, programmatic says 2.
        with_envs(&[(ENV_WORKER_THREADS, "8")], || {
            let toml = r#"
[scheduler]
worker_threads = 16
"#;
            let runtime = RuntimeBuilder::from_toml_str(toml)
                .expect("from_toml_str")
                .with_env_overrides()
                .expect("env overrides")
                .worker_threads(2) // programmatic: highest priority
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 2);
        });
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn precedence_env_over_toml() {
        use crate::runtime::env_config::*;
        // TOML says 16, env says 8.
        with_envs(&[(ENV_WORKER_THREADS, "8")], || {
            let toml = r#"
[scheduler]
worker_threads = 16
"#;
            let runtime = RuntimeBuilder::from_toml_str(toml)
                .expect("from_toml_str")
                .with_env_overrides()
                .expect("env overrides")
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 8);
        });
    }
}
