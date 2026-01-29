//! Runtime builder and handles.

use crate::error::Error;
use crate::observability::metrics::MetricsProvider;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::deadline_monitor::{
    default_warning_handler, AdaptiveDeadlineConfig, DeadlineWarning, MonitorConfig,
};
use crate::runtime::scheduler::ThreeLaneScheduler;
use crate::runtime::RuntimeState;
use crate::types::Budget;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Builder for constructing a runtime with custom configuration.
#[derive(Clone)]
pub struct RuntimeBuilder {
    config: RuntimeConfig,
}

impl RuntimeBuilder {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: RuntimeConfig::default(),
        }
    }

    /// Set the number of worker threads.
    #[must_use]
    pub fn worker_threads(mut self, n: usize) -> Self {
        self.config.worker_threads = n;
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
        Ok(Self { config })
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
        Ok(Self { config })
    }

    /// Build a runtime from this configuration.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<Runtime, Error> {
        Runtime::with_config(self.config)
    }

    /// Single-threaded runtime (Phase 0 compatible).
    #[must_use]
    pub fn current_thread() -> Self {
        Self::new().worker_threads(1)
    }

    /// Multi-threaded runtime with defaults.
    #[must_use]
    pub fn multi_thread() -> Self {
        Self::new()
    }

    /// High-throughput preset: more workers, larger steal batches.
    #[must_use]
    pub fn high_throughput() -> Self {
        let workers = RuntimeConfig::default_worker_threads()
            .saturating_mul(2)
            .max(1);
        Self::new().worker_threads(workers).steal_batch_size(32)
    }

    /// Low-latency preset: smaller batches and tighter budgets.
    #[must_use]
    pub fn low_latency() -> Self {
        Self::new().steal_batch_size(4).poll_budget(32)
    }
}

/// Builder for deadline monitoring configuration.
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

/// Runtime instance created from a [`RuntimeBuilder`].
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

impl Runtime {
    /// Construct a runtime from the given configuration.
    #[allow(clippy::result_large_err)]
    pub fn with_config(mut config: RuntimeConfig) -> Result<Self, Error> {
        config.normalize();
        Ok(Self {
            inner: Arc::new(RuntimeInner::new(config)),
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
}

/// Handle for spawning tasks onto a runtime.
#[derive(Clone)]
pub struct RuntimeHandle {
    inner: Arc<RuntimeInner>,
}

impl RuntimeHandle {
    /// Spawn a task from outside async context.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.spawn(future)
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
        guard.result.take().map_or_else(
            || {
                guard.waker = Some(cx.waker().clone());
                Poll::Pending
            },
            Poll::Ready,
        )
    }
}

struct RuntimeInner {
    config: RuntimeConfig,
    next_worker_id: AtomicUsize,
    state: Arc<Mutex<RuntimeState>>,
    scheduler: ThreeLaneScheduler,
    worker_threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    root_region: crate::types::RegionId,
}

impl RuntimeInner {
    fn new(config: RuntimeConfig) -> Self {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let root_region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let mut scheduler = ThreeLaneScheduler::new(config.worker_threads, &state);

        let mut worker_threads = Vec::new();
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
                if let Ok(handle) = builder.spawn(move || {
                    if let Some(callback) = on_start.as_ref() {
                        callback();
                    }
                    let mut worker = worker;
                    worker.run_loop();
                    if let Some(callback) = on_stop.as_ref() {
                        callback();
                    }
                }) {
                    worker_threads.push(handle);
                }
            }
        }

        Self {
            config,
            next_worker_id: AtomicUsize::new(0),
            state,
            scheduler,
            worker_threads: Mutex::new(worker_threads),
            root_region,
        }
    }

    fn next_thread_name(&self) -> String {
        let id = self.next_worker_id.fetch_add(1, Ordering::Relaxed);
        format!("{}-{id}", self.config.thread_name_prefix)
    }

    fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let join_state = Arc::new(Mutex::new(JoinState::new()));
        let join_state_for_task = Arc::clone(&join_state);

        let wrapped = async move {
            let output = future.await;
            complete_task(&join_state_for_task, output);
        };

        let task_id = {
            let mut guard = self.state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(self.root_region, Budget::INFINITE, wrapped)
                .expect("failed to create runtime task");
            task_id
        };

        self.scheduler
            .inject_ready(task_id, Budget::INFINITE.priority);

        JoinHandle::new(join_state)
    }
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        self.scheduler.shutdown();
        let mut handles = lock_state(&self.worker_threads);
        for handle in handles.drain(..) {
            let _ = handle.join();
        }
    }
}

struct JoinState<T> {
    result: Option<T>,
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
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
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

    complete_task(state, output);
}

fn complete_task<T>(state: &Arc<Mutex<JoinState<T>>>, output: T) {
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
    use crate::test_utils::init_test_logging;
    use std::sync::atomic::{AtomicBool, Ordering};

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
}
