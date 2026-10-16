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
//! // Minimal — uses all defaults (4 worker threads, 128 poll budget, etc.)
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
//! ## Browser/WASM Status
//!
//! Browser-safe profiles can validate semantic-core closure on `wasm32`, and
//! this module now exposes a preview public browser bootstrap path through
//! [`RuntimeBuilder::browser`]. The preview surface is dispatcher-backed and
//! truthful about the current execution ladder: supported hosts receive a
//! browser runtime handle, while unsupported hosts fail closed with structured
//! diagnostics instead of pretending native-thread parity already exists.
//! Runtime startup still routes through an explicit `RuntimeHostServices`
//! seam, and the native std-thread host implementation remains the only
//! shipped full runtime host. Browser-facing guidance should continue to rely
//! on the repository-maintained Rust/WASM fixture and the shipped JS/TS Browser
//! Edition packages when broad end-user parity is required.
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
//! ## With TOML or Versioned JSON Config (requires `config-file` feature)
//!
//! ```ignore
//! let runtime = RuntimeBuilder::from_toml("config/runtime.toml")?
//!     .with_env_overrides()?   // env vars override file values
//!     .worker_threads(4)       // programmatic override (highest priority)
//!     .build()?;
//!
//! let runtime = RuntimeBuilder::from_json("config/runtime.json")?
//!     .with_env_overrides()?
//!     .worker_threads(4)
//!     .build()?;
//! ```
//!
//! # Configuration Precedence
//!
//! When several sources set the same field, the one applied last wins, so order the calls:
//!
//! 1. **Config file** — `from_toml`/`from_json` start the builder from the shared typed layer
//! 2. **Environment** — `with_env_overrides()` replaces what was set before it, presets included
//! 3. **Programmatic** — `builder.worker_threads(4)` after it, as in the example above
//! 4. **Defaults** — `RuntimeConfig::default()` fills every field nothing set, except that the builder adds an on-demand blocking pool
//!
//! # Configuration Reference
//!
//! | Method | Default | Description |
//! |--------|---------|-------------|
//! | [`worker_threads`](RuntimeBuilder::worker_threads) | 4 (host-independent default) | Number of async worker threads |
//! | [`thread_stack_size`](RuntimeBuilder::thread_stack_size) | 2 MiB | Stack size per worker |
//! | [`thread_name_prefix`](RuntimeBuilder::thread_name_prefix) | `"asupersync-worker"` | Thread name prefix |
//! | [`global_queue_limit`](RuntimeBuilder::global_queue_limit) | 0 (unbounded) | Global queue depth |
//! | [`steal_batch_size`](RuntimeBuilder::steal_batch_size) | 16 | Work-stealing batch size |
//! | [`adaptive_ready_batch`](RuntimeBuilder::adaptive_ready_batch) | disabled | Observe-first adaptive ready-lane batch sizing |
//! | [`blocking_threads`](RuntimeBuilder::blocking_threads) | 0, 512 (threads start on demand; 0, 0 on wasm32) | Blocking pool min/max; `0, 0` runs blocking work inline |
//! | [`enable_parking`](RuntimeBuilder::enable_parking) | true | Park idle workers |
//! | [`poll_budget`](RuntimeBuilder::poll_budget) | 128 | Self-woken `block_on` root polls before a backoff sleep |
//! | [`capacity_hints`](RuntimeBuilder::capacity_hints) | auto from `worker_threads` | Initial task/region/obligation table sizing |
//! | [`expected_concurrent_tasks`](RuntimeBuilder::expected_concurrent_tasks) | unset | Burst-tolerant task-capacity shortcut with 50% headroom |
//! | [`browser_ready_handoff_limit`](RuntimeBuilder::browser_ready_handoff_limit) | 0 (disabled) | Max ready dispatch burst before host-turn handoff |
//! | [`browser_worker_offload`](RuntimeBuilder::browser_worker_offload) | disabled | Browser worker offload policy contract |
//! | [`cancel_lane_max_streak`](RuntimeBuilder::cancel_lane_max_streak) | 16 | Max consecutive cancel dispatches |
//! | [`enable_adaptive_cancel_streak`](RuntimeBuilder::enable_adaptive_cancel_streak) | false | Enable regret-bounded adaptive cancel streak |
//! | [`adaptive_cancel_streak_epoch_steps`](RuntimeBuilder::adaptive_cancel_streak_epoch_steps) | 128 | Dispatches per adaptive epoch |
//! | [`root_region_limits`](RuntimeBuilder::root_region_limits) | None | Admission limits for the root region |
//! | [`observability`](RuntimeBuilder::observability) | None | Attach structured logging collectors |
//! | [`scheduler_evidence_sink`](RuntimeBuilder::scheduler_evidence_sink) | None | Record the governor's scheduling decisions |
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
use crate::observability::ObservabilityConfig;
use crate::observability::diagnostics::Diagnostics;
use crate::observability::metrics::MetricsProvider;
use crate::observability::task_inspector::{
    RuntimeStateSource, TaskInspector, TaskInspectorConfig,
};
use crate::record::RegionLimits;
use crate::runtime::RuntimeState;
use crate::runtime::SpawnError;
use crate::runtime::config::{
    AdaptiveReadyBatchConfig, RuntimeCapacityHints, RuntimeConfig, SchedulerPlacementMode,
    WorkerCohortMapping,
};
use crate::runtime::deadline_monitor::{
    AdaptiveDeadlineConfig, DeadlineTaskSnapshot, DeadlineWarning, MonitorConfig,
    default_warning_handler,
};
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::reactor::{IoReactorCapabilitySnapshot, IoUringCapabilityPolicy, Reactor};
use crate::runtime::resource_monitor::ResourceMonitor;
use crate::runtime::scheduler::three_lane::{
    AdaptiveBatchSizingProfile, PreemptionFairnessCertificate, SchedulerConstructionHandles,
};
use crate::runtime::scheduler::{ThreeLaneScheduler, ThreeLaneWorker};
use crate::time::TimerDriverHandle;
use crate::trace::distributed::LogicalClockMode;
use crate::types::{Budget, CancelAttributionConfig};
use crate::util::EntropySource;
#[cfg(target_arch = "wasm32")]
use js_sys::{Reflect, global};
use parking_lot::{Condvar, Mutex, MutexGuard};
use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use thiserror::Error as ThisError;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

use crate::types::{
    WasmAbiOutcomeEnvelope, WasmAbiVersion, WasmAbortPropagationMode, WasmDispatchError,
    WasmDispatcherDiagnostics, WasmExportDispatcher, WasmHandleRef, WasmScopeEnterBuilder,
};

// ---------------------------------------------------------------------------
// Thread-local RuntimeHandle (issue #21)
// ---------------------------------------------------------------------------
//
// When `Runtime::block_on` enters the poll loop, it installs a thread-local
// `RuntimeHandle` so that futures running inside `block_on` can discover the
// runtime and spawn tasks onto the real scheduler via
// `Runtime::current_handle()`.

thread_local! {
    static CURRENT_RUNTIME_HANDLE: RefCell<Option<RuntimeHandle>> = const { RefCell::new(None) };
}

/// RAII guard that installs (and restores) a thread-local [`RuntimeHandle`].
struct ScopedRuntimeHandle {
    prev: Option<RuntimeHandle>,
}

impl ScopedRuntimeHandle {
    fn new(handle: RuntimeHandle) -> Self {
        let prev = CURRENT_RUNTIME_HANDLE.with(|cell| cell.replace(Some(handle)));
        Self { prev }
    }
}

impl Drop for ScopedRuntimeHandle {
    fn drop(&mut self) {
        let prev = self.prev.take();
        let _ = CURRENT_RUNTIME_HANDLE.try_with(|cell| {
            *cell.borrow_mut() = prev;
        });
    }
}

#[allow(dead_code)] // Used on wasm32 target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeHostServicesKind {
    NativeStdThread,
    BrowserMicrotask,
}

#[allow(dead_code)] // Used on wasm32 target
impl RuntimeHostServicesKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NativeStdThread => "native-std-thread",
            Self::BrowserMicrotask => "browser-microtask",
        }
    }
}

#[allow(dead_code)] // Used on wasm32 target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BrowserHostServicesContract {
    required_capabilities: &'static [&'static str],
}

#[allow(dead_code)] // Used on wasm32 target
impl BrowserHostServicesContract {
    const V1: Self = Self {
        required_capabilities: &[
            "host-turn wakeups",
            "worker bootstrap hooks",
            "timer/deadline driving",
            "lane-health callbacks",
        ],
    };

    fn diagnostic_requirements(self) -> &'static str {
        if self
            .required_capabilities
            .contains(&"lane-health callbacks")
        {
            "host-turn wakeups, worker bootstrap hooks, timer/deadline driving, and lane-health callbacks for threadless startup"
        } else {
            "browser host-services contract requirements"
        }
    }
}

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct DeadlineMonitorHostService {
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
impl DeadlineMonitorHostService {
    const fn disabled() -> Self {
        Self {
            shutdown: None,
            thread: None,
        }
    }
}

/// Wait for either the next deadline-monitor scan interval or shutdown.
///
/// Returns `true` only when the full interval elapsed and the caller should
/// perform a scan. A shutdown signal or sender disconnect terminates the loop.
fn wait_for_deadline_monitor_tick(
    shutdown: &std::sync::mpsc::Receiver<()>,
    check_interval: Duration,
) -> bool {
    match shutdown.recv_timeout(check_interval) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => true,
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => false,
    }
}

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
trait RuntimeHostServices: Send + Sync {
    fn kind(&self) -> RuntimeHostServicesKind;

    fn browser_contract(&self) -> BrowserHostServicesContract {
        BrowserHostServicesContract::V1
    }

    fn browser_pump(&self) -> Option<Arc<BrowserWorkerPump>> {
        None
    }

    fn spawn_workers(
        &self,
        runtime: &Arc<RuntimeInner>,
        workers: Vec<ThreeLaneWorker>,
    ) -> io::Result<Vec<std::thread::JoinHandle<()>>>;

    /// E1.2 subsystem 3d (E1.1 row B01): `dispatch_task_table` is the
    /// scheduler's external shard-A table when the runtime dispatches
    /// against one; the monitor must snapshot deadlines from the table the
    /// workers actually run, in addition to the embedded table.
    fn start_deadline_monitor(
        &self,
        config: &RuntimeConfig,
        state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
        dispatch_task_table: Option<Arc<crate::sync::ContendedMutex<crate::runtime::TaskTable>>>,
    ) -> DeadlineMonitorHostService;
}

#[derive(Default)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct NativeThreadHostServices;

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
impl NativeThreadHostServices {
    const fn new() -> Self {
        Self
    }

    fn spawn_worker_threads(
        runtime: &Arc<RuntimeInner>,
        workers: Vec<ThreeLaneWorker>,
    ) -> io::Result<Vec<std::thread::JoinHandle<()>>> {
        let mut worker_threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
        if runtime.config.worker_threads == 0 {
            return Ok(worker_threads);
        }

        for worker in workers {
            let name = {
                let id = worker.id;
                format!("{}-{id}", runtime.config.thread_name_prefix)
            };
            let runtime_handle = RuntimeHandle::weak(runtime);
            let on_start = runtime.config.on_thread_start.clone();
            let on_stop = runtime.config.on_thread_stop.clone();
            // GH#58: a current-thread runtime's worker is loaned to
            // `Runtime::block_on` callers; the thread parks while it is out.
            let current_thread_driver = runtime.current_thread_driver.get().map(Arc::clone);
            let mut builder = std::thread::Builder::new().name(name);
            if runtime.config.thread_stack_size > 0 {
                builder = builder.stack_size(runtime.config.thread_stack_size);
            }
            let handle = builder
                .spawn(move || {
                    let _guard = ScopedRuntimeHandle::new(runtime_handle);
                    match current_thread_driver {
                        Some(driver) => driver.run_background(worker, || {
                            if let Some(callback) = on_start.as_ref() {
                                callback();
                            }
                        }),
                        None => {
                            if let Some(callback) = on_start.as_ref() {
                                callback();
                            }
                            let mut worker = worker;
                            worker.run_worker_thread();
                        }
                    }
                    if let Some(callback) = on_stop.as_ref() {
                        callback();
                    }
                })
                .map_err(|e| {
                    // Signal already-running workers to exit their run loops,
                    // then join them so they don't leak.
                    runtime.scheduler.shutdown();
                    while let Some(handle) = worker_threads.pop() {
                        let _ = handle.join();
                    }
                    io::Error::other(format!("failed to spawn worker thread: {e}"))
                })?;
            worker_threads.push(handle);
        }

        Ok(worker_threads)
    }

    fn start_deadline_monitor(
        config: &RuntimeConfig,
        state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
        dispatch_task_table: Option<Arc<crate::sync::ContendedMutex<crate::runtime::TaskTable>>>,
    ) -> DeadlineMonitorHostService {
        use crate::runtime::deadline_monitor::DeadlineMonitor;

        let monitor_config = match config.deadline_monitor {
            Some(ref mc) if mc.enabled => mc,
            _ => return DeadlineMonitorHostService::disabled(),
        };

        let (dm_shutdown, dm_shutdown_rx) = std::sync::mpsc::channel();
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
                while wait_for_deadline_monitor_tick(&dm_shutdown_rx, check_interval) {
                    let guard = dm_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let (logical_now, driver) = (guard.now, guard.timer_driver_handle());
                    let mut tasks = guard
                        .tasks_iter()
                        .map(|(_, record)| DeadlineTaskSnapshot::from_task_record(record))
                        .collect::<Vec<_>>();
                    drop(guard);
                    // E1.2 subsystem 3d (E1.1 row B01): a dispatch-table
                    // runtime's live tasks reside in the external shard-A
                    // table; snapshot it after the state lock is released
                    // (sequential B then A, never nested here).
                    if let Some(table) = dispatch_task_table.as_ref() {
                        let table = table
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        tasks.extend(
                            table
                                .iter()
                                .map(|(_, record)| DeadlineTaskSnapshot::from_task_record(record)),
                        );
                    }
                    monitor.check_snapshots(driver.map_or(logical_now, |d| d.now()), tasks);
                }
            })
            .ok();

        DeadlineMonitorHostService {
            shutdown: Some(dm_shutdown),
            thread,
        }
    }
}

impl RuntimeHostServices for NativeThreadHostServices {
    fn kind(&self) -> RuntimeHostServicesKind {
        RuntimeHostServicesKind::NativeStdThread
    }

    fn spawn_workers(
        &self,
        runtime: &Arc<RuntimeInner>,
        workers: Vec<ThreeLaneWorker>,
    ) -> io::Result<Vec<std::thread::JoinHandle<()>>> {
        Self::spawn_worker_threads(runtime, workers)
    }

    fn start_deadline_monitor(
        &self,
        config: &RuntimeConfig,
        state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
        dispatch_task_table: Option<Arc<crate::sync::ContendedMutex<crate::runtime::TaskTable>>>,
    ) -> DeadlineMonitorHostService {
        Self::start_deadline_monitor(config, state, dispatch_task_table)
    }
}

fn default_runtime_host_services() -> Arc<dyn RuntimeHostServices> {
    #[cfg(target_arch = "wasm32")]
    {
        Arc::new(BrowserHostServices::new())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Arc::new(NativeThreadHostServices::new())
    }
}

/// Outcome of draining a batch of scheduler tasks through [`BrowserWorkerPump`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpDrainOutcome {
    /// No runnable tasks were available in the scheduler queues.
    Idle,
    /// Successfully executed tasks within the burst limit.
    Completed(usize),
    /// Reached the microtask burst limit while more tasks remain runnable.
    BurstLimitReached(usize),
    /// The pump was invoked re-entrantly and was rejected by the re-entrancy guard.
    ReentrantPrevented,
    /// The underlying worker is currently locked or unavailable.
    WorkerUnavailable,
}

/// A microtask-driven execution pump for single-worker browser runtimes.
///
/// Drives `ThreeLaneWorker::run_pump_step` in bounded microtask bursts, enforces
/// a re-entrancy guard against recursive host turn invocation, and yields to the
/// macro-task event loop when the burst limit is exhausted.
pub struct BrowserWorkerPump {
    worker: Mutex<Option<ThreeLaneWorker>>,
    in_pump: AtomicBool,
    scheduled: AtomicBool,
    wake_requested: AtomicBool,
    microtask_burst_limit: usize,
    self_weak: Mutex<Weak<Self>>,
    pump_turns: AtomicU32,
}

impl BrowserWorkerPump {
    /// Creates a new pump with the specified microtask burst limit.
    #[must_use]
    pub fn new(microtask_burst_limit: usize) -> Self {
        Self {
            worker: Mutex::new(None),
            in_pump: AtomicBool::new(false),
            scheduled: AtomicBool::new(false),
            wake_requested: AtomicBool::new(false),
            microtask_burst_limit: if microtask_burst_limit == 0 {
                32
            } else {
                microtask_burst_limit
            },
            self_weak: Mutex::new(Weak::new()),
            pump_turns: AtomicU32::new(0),
        }
    }

    /// Sets the weak reference back to the owning `Arc`.
    pub fn set_self_weak(&self, weak: Weak<Self>) {
        *self.self_weak.lock() = weak;
    }

    /// Returns the configured microtask burst limit.
    #[must_use]
    pub fn microtask_burst_limit(&self) -> usize {
        self.microtask_burst_limit
    }

    /// Returns the total number of pump turns executed by this pump.
    #[must_use]
    pub fn pump_turns(&self) -> u32 {
        self.pump_turns.load(Ordering::Relaxed)
    }

    /// Installs the single worker and registers its wake notifier.
    fn install_worker(&self, worker: ThreeLaneWorker, _runtime: &Arc<RuntimeInner>) {
        let weak_self = self.self_weak.lock().clone();
        worker.set_wake_notifier(Arc::new(move || {
            if let Some(pump) = weak_self.upgrade() {
                pump.schedule_pump();
            }
        }));
        *self.worker.lock() = Some(worker);
    }

    /// Schedules a microtask pump step if not already scheduled.
    pub fn schedule_pump(&self) {
        self.wake_requested.store(true, Ordering::Release);
        if self.scheduled.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak_self = self.self_weak.lock().clone();
        schedule_microtask(move || {
            if let Some(pump) = weak_self.upgrade() {
                pump.run_pump_turn();
            }
        });
    }

    fn run_pump_turn(&self) {
        self.pump_turns.fetch_add(1, Ordering::Relaxed);
        self.wake_requested.store(false, Ordering::Release);
        let outcome = self.drain_batch(self.microtask_burst_limit);
        if matches!(outcome, PumpDrainOutcome::BurstLimitReached(_)) {
            let weak_yield = self.self_weak.lock().clone();
            schedule_macro_yield(move || {
                if let Some(pump) = weak_yield.upgrade() {
                    pump.run_pump_turn();
                }
            });
            return;
        }

        self.scheduled.store(false, Ordering::Release);
        if self.wake_requested.load(Ordering::Acquire) {
            if !self.scheduled.swap(true, Ordering::AcqRel) {
                let weak_self = self.self_weak.lock().clone();
                schedule_microtask(move || {
                    if let Some(pump) = weak_self.upgrade() {
                        pump.run_pump_turn();
                    }
                });
            }
        }
    }

    /// Drains runnable tasks up to `max_steps`, enforcing the re-entrancy guard.
    pub fn drain_batch(&self, max_steps: usize) -> PumpDrainOutcome {
        if self.in_pump.swap(true, Ordering::AcqRel) {
            return PumpDrainOutcome::ReentrantPrevented;
        }
        struct ReentrancyGuard<'a>(&'a AtomicBool);
        impl Drop for ReentrancyGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _guard = ReentrancyGuard(&self.in_pump);

        let outcome = self.drain_batch_inner(max_steps);
        // The last runtime owner can be dropped by a task's poll. Wait until
        // that poll has returned its storage and released the pump lock before
        // retiring the worker and any newly parked local future.
        self.retire_stopped_worker();
        outcome
    }

    fn drain_batch_inner(&self, max_steps: usize) -> PumpDrainOutcome {
        let mut worker_guard = match self.worker.try_lock() {
            Some(g) => g,
            None => return PumpDrainOutcome::WorkerUnavailable,
        };
        let Some(worker) = worker_guard.as_mut() else {
            return PumpDrainOutcome::WorkerUnavailable;
        };

        let mut executed = 0;
        while executed < max_steps {
            if !worker.run_pump_step() {
                if executed == 0 {
                    return PumpDrainOutcome::Idle;
                }
                return PumpDrainOutcome::Completed(executed);
            }
            executed += 1;
        }

        PumpDrainOutcome::BurstLimitReached(executed)
    }

    fn retire_stopped_worker(&self) {
        let retired = {
            // Runtime drop can occur inside this pump's active poll. That turn
            // will retire the worker after it releases the lock above.
            let Some(mut worker) = self.worker.try_lock() else {
                return;
            };
            if worker
                .as_ref()
                .is_some_and(|worker| worker.shutdown.load(Ordering::Acquire))
            {
                worker.take()
            } else {
                None
            }
        };
        if let Some(worker) = retired {
            crate::runtime::local::retire_local_store(worker.local_store_key());
            // Worker/state destructors and completion callbacks must run after
            // the pump mutex is released, just like local-store destructors.
            drop(worker);
        }
    }

    /// Executes a single pump step.
    pub fn step(&self) -> bool {
        matches!(
            self.drain_batch(1),
            PumpDrainOutcome::Completed(1) | PumpDrainOutcome::BurstLimitReached(1)
        )
    }

    /// Runs until all currently queued tasks have finished executing.
    pub fn run_until_idle(&self) -> usize {
        let mut total = 0;
        loop {
            match self.drain_batch(self.microtask_burst_limit) {
                PumpDrainOutcome::Idle => break total,
                PumpDrainOutcome::Completed(n) | PumpDrainOutcome::BurstLimitReached(n) => {
                    total += n;
                }
                PumpDrainOutcome::ReentrantPrevented | PumpDrainOutcome::WorkerUnavailable => {
                    break total;
                }
            }
        }
    }
}

impl std::fmt::Debug for BrowserWorkerPump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserWorkerPump")
            .field("in_pump", &self.in_pump.load(Ordering::Relaxed))
            .field("scheduled", &self.scheduled.load(Ordering::Relaxed))
            .field(
                "wake_requested",
                &self.wake_requested.load(Ordering::Relaxed),
            )
            .field("microtask_burst_limit", &self.microtask_burst_limit)
            .field("pump_turns", &self.pump_turns.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm_pump_bindings {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = queueMicrotask, catch)]
        pub fn js_queue_microtask(cb: &js_sys::Function) -> Result<(), JsValue>;
    }
}

#[cfg(target_arch = "wasm32")]
fn schedule_microtask<F: FnOnce() + 'static>(f: F) {
    use wasm_bindgen::JsCast;
    let cb = wasm_bindgen::closure::Closure::once_into_js(f);
    if let Ok(func) = cb.dyn_into::<js_sys::Function>() {
        let _ = wasm_pump_bindings::js_queue_microtask(&func);
    }
}

#[cfg(target_arch = "wasm32")]
fn schedule_macro_yield<F: FnOnce() + 'static>(f: F) {
    use wasm_bindgen::JsCast;
    if let Ok(channel) = web_sys::MessageChannel::new() {
        let port1 = channel.port1();
        let port2 = channel.port2();
        let p1 = port1.clone();
        let p2 = port2.clone();
        let cb = wasm_bindgen::closure::Closure::once_into_js(move || {
            p1.set_onmessage(None);
            p1.close();
            p2.close();
            f();
        });
        if let Ok(func) = cb.dyn_into::<js_sys::Function>() {
            port1.set_onmessage(Some(&func));
            let _ = port2.post_message(&wasm_bindgen::JsValue::UNDEFINED);
        }
    } else {
        schedule_microtask(f);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn schedule_microtask<F: FnOnce() + 'static>(_f: F) {
    // Native tests drive the pump directly
}

#[cfg(not(target_arch = "wasm32"))]
fn schedule_macro_yield<F: FnOnce() + 'static>(_f: F) {
    // Native tests drive the pump directly
}

/// Browser host services providing threadless single-worker startup and microtask scheduling.
#[derive(Clone, Debug)]
pub struct BrowserHostServices {
    pump: Arc<BrowserWorkerPump>,
}

impl BrowserHostServices {
    /// Creates a new browser host services instance with default burst limit (32).
    #[must_use]
    pub fn new() -> Self {
        Self::with_burst_limit(32)
    }

    /// Creates a new browser host services instance with the specified microtask burst limit.
    #[must_use]
    pub fn with_burst_limit(microtask_burst_limit: usize) -> Self {
        let pump = Arc::new(BrowserWorkerPump::new(microtask_burst_limit));
        pump.set_self_weak(Arc::downgrade(&pump));
        Self { pump }
    }

    /// Returns the underlying browser worker pump.
    #[must_use]
    pub fn pump(&self) -> Arc<BrowserWorkerPump> {
        Arc::clone(&self.pump)
    }
}

impl Default for BrowserHostServices {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeHostServices for BrowserHostServices {
    fn kind(&self) -> RuntimeHostServicesKind {
        RuntimeHostServicesKind::BrowserMicrotask
    }

    fn browser_contract(&self) -> BrowserHostServicesContract {
        BrowserHostServicesContract::V1
    }

    fn browser_pump(&self) -> Option<Arc<BrowserWorkerPump>> {
        Some(Arc::clone(&self.pump))
    }

    fn spawn_workers(
        &self,
        runtime: &Arc<RuntimeInner>,
        mut workers: Vec<ThreeLaneWorker>,
    ) -> io::Result<Vec<std::thread::JoinHandle<()>>> {
        if workers.is_empty() {
            return Ok(Vec::new());
        }
        if workers.len() != 1 {
            return Err(io::Error::other(format!(
                "BrowserHostServices requires single-worker topology, got {} workers",
                workers.len()
            )));
        }
        let Some(worker) = workers.pop() else {
            return Ok(Vec::new());
        };
        self.pump.install_worker(worker, runtime);
        Ok(Vec::new())
    }

    fn start_deadline_monitor(
        &self,
        _config: &RuntimeConfig,
        _state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
        _dispatch_task_table: Option<Arc<crate::sync::ContendedMutex<crate::runtime::TaskTable>>>,
    ) -> DeadlineMonitorHostService {
        DeadlineMonitorHostService::disabled()
    }
}

#[allow(dead_code)] // Used on wasm32 target
fn unsupported_browser_bootstrap_message(host_services: &dyn RuntimeHostServices) -> String {
    let contract = host_services.browser_contract();
    format!(
        "RuntimeBuilder browser bootstrap is not yet supported on wasm browser profiles; \
         startup now routes through the RuntimeHostServices seam, but this build still only \
         ships the {} host implementation. A future browser host must provide {}. Use the \
         Browser Edition JS/TS bindings or the repository-maintained browser fixtures until \
         that browser host implementation lands.",
        host_services.kind().as_str(),
        contract.diagnostic_requirements(),
    )
}

/// Browser execution API capabilities used for runtime support diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserExecutionApiCapabilities {
    /// Whether `AbortController` is available.
    pub has_abort_controller: bool,
    /// Whether `fetch` is available.
    pub has_fetch: bool,
    /// Whether `WebAssembly` is available.
    pub has_webassembly: bool,
}

/// Browser DOM capabilities used for runtime support diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserDomCapabilities {
    /// Whether `document` is available.
    pub has_document: bool,
    /// Whether `window` is available.
    pub has_window: bool,
}

/// Browser storage capabilities used for runtime support diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserStorageCapabilities {
    /// Whether `indexedDB` is available.
    pub has_indexed_db: bool,
    /// Whether `localStorage` is available.
    pub has_local_storage: bool,
}

/// Browser transport capabilities used for runtime support diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserTransportCapabilities {
    /// Whether `WebSocket` is available.
    pub has_web_socket: bool,
    /// Whether `WebTransport` is available.
    pub has_web_transport: bool,
}

/// Browser capability snapshot used for runtime support diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserCapabilitySnapshot {
    /// Execution-related browser APIs.
    pub execution_api: BrowserExecutionApiCapabilities,
    /// DOM-related capabilities.
    pub dom: BrowserDomCapabilities,
    /// Storage-related capabilities.
    pub storage: BrowserStorageCapabilities,
    /// Transport-related capabilities.
    pub transport: BrowserTransportCapabilities,
}

/// Browser runtime support classes aligned with the Browser Edition control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserRuntimeSupportClass {
    /// The current host context truthfully supports direct runtime execution.
    DirectRuntimeSupported,
    /// The current host context does not support a direct browser runtime lane.
    Unsupported,
}

impl BrowserRuntimeSupportClass {
    /// Stable string label aligned with the Browser Edition package surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectRuntimeSupported => "direct_runtime_supported",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Browser runtime context classification aligned with the Browser Edition package surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserRuntimeContext {
    /// Browser main-thread context (`window` + `document`).
    BrowserMainThread,
    /// Dedicated worker context.
    DedicatedWorker,
    /// Service worker context.
    ServiceWorker,
    /// Shared worker context.
    SharedWorker,
    /// Anything outside the currently classified browser runtime contexts.
    Unknown,
}

impl BrowserRuntimeContext {
    /// Stable string label aligned with the Browser Edition package surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserMainThread => "browser_main_thread",
            Self::DedicatedWorker => "dedicated_worker",
            Self::ServiceWorker => "service_worker",
            Self::SharedWorker => "shared_worker",
            Self::Unknown => "unknown",
        }
    }
}

/// Browser runtime support reasons aligned with the Browser Edition diagnostics model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserRuntimeSupportReason {
    /// `globalThis` or an equivalent global object is missing.
    MissingGlobalThis,
    /// The current context is a service worker, which is not yet a shipped lane.
    ServiceWorkerNotYetShipped,
    /// The current context is a shared worker, which is not yet a shipped lane.
    SharedWorkerNotYetShipped,
    /// The current context is not a shipped direct-runtime browser role.
    UnsupportedRuntimeContext,
    /// `WebAssembly` is unavailable in the current host.
    MissingWebAssembly,
    /// The current context is supported.
    Supported,
}

/// Runtime support diagnostics for the Rust-authored browser surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserRuntimeSupportDiagnostics {
    /// Whether the current host truthfully supports direct runtime execution.
    pub supported: bool,
    /// High-level support class.
    pub support_class: BrowserRuntimeSupportClass,
    /// Browser runtime context classification.
    pub runtime_context: BrowserRuntimeContext,
    /// Support reason code.
    pub reason: BrowserRuntimeSupportReason,
    /// Human-readable explanation.
    pub message: String,
    /// Operator guidance for this support decision.
    pub guidance: Vec<String>,
    /// Capability snapshot used to reach the decision.
    pub capabilities: BrowserCapabilitySnapshot,
}

const BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID: &str = "wasm-service-worker-broker-contract-v1";
const BROWSER_SERVICE_WORKER_BROKER_LANE: &str = "lane.browser.service_worker.broker";
const BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID: &str =
    "wasm-shared-worker-tenancy-lifecycle-v1";
const BROWSER_SHARED_WORKER_COORDINATOR_LANE: &str = "lane.browser.shared_worker.coordinator";

/// Truthful fallback targets for bounded browser worker helper surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserWorkerFallbackTarget {
    /// Downgrade to the dedicated-worker direct-runtime lane.
    DedicatedWorkerDirectRuntime,
    /// Downgrade to the browser main-thread direct-runtime lane.
    BrowserMainThreadDirectRuntime,
    /// Downgrade to an application-owned bridge-only fallback.
    BridgeFallback,
}

impl BrowserWorkerFallbackTarget {
    /// Stable string label aligned with the Browser Edition package surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DedicatedWorkerDirectRuntime => "lane.browser.dedicated_worker.direct_runtime",
            Self::BrowserMainThreadDirectRuntime => "lane.browser.main_thread.direct_runtime",
            Self::BridgeFallback => "bridge_fallback",
        }
    }

    const fn fallback_lane_id(self) -> Option<BrowserExecutionLane> {
        match self {
            Self::DedicatedWorkerDirectRuntime => {
                Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime)
            }
            Self::BrowserMainThreadDirectRuntime => {
                Some(BrowserExecutionLane::BrowserMainThreadDirectRuntime)
            }
            Self::BridgeFallback => None,
        }
    }
}

/// Reason codes for service-worker broker host-class preflight diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserServiceWorkerBrokerSupportReason {
    /// The current host supports the bounded broker surface.
    Supported,
    /// The current host is not a service-worker-like host.
    ServiceWorkerApiMissing,
    /// The current host lacks the durable store required by the default restartable profile.
    DurableStoreUnavailableForRestartableProfile,
}

impl BrowserServiceWorkerBrokerSupportReason {
    /// Stable string label aligned with the Browser Edition package surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::ServiceWorkerApiMissing => "service_worker_api_missing",
            Self::DurableStoreUnavailableForRestartableProfile => {
                "durable_store_unavailable_for_restartable_profile"
            }
        }
    }
}

/// Host-class preflight diagnostics for the bounded service-worker broker surface.
///
/// Unlike the JS helper, this Rust preview surface does not try to mirror every
/// registration/admission field. It only reports the host-class facts that the
/// Rust browser builder can inspect truthfully without widening the shipped
/// direct-runtime contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserServiceWorkerBrokerSupportDiagnostics {
    /// Whether the current host satisfies the bounded broker preflight.
    pub supported: bool,
    /// Stable bounded broker contract id.
    pub contract_id: &'static str,
    /// Stable bounded broker lane id.
    pub requested_lane: &'static str,
    /// Truthful first downgrade target when broker admission is unavailable.
    pub fallback_target: BrowserWorkerFallbackTarget,
    /// Truthful first downgrade lane, if it maps to a direct-runtime lane.
    pub fallback_lane_id: Option<BrowserExecutionLane>,
    /// Ordered downgrade targets for this helper surface.
    pub downgrade_order: Vec<BrowserWorkerFallbackTarget>,
    /// Browser host-role classification.
    pub host_role: BrowserExecutionHostRole,
    /// Browser runtime context classification.
    pub runtime_context: BrowserRuntimeContext,
    /// Host-class support reason.
    pub reason: BrowserServiceWorkerBrokerSupportReason,
    /// Human-readable explanation.
    pub message: String,
    /// Operator guidance.
    pub guidance: Vec<String>,
    /// Underlying direct-runtime support reason for the current host.
    pub direct_runtime_reason: BrowserRuntimeSupportReason,
    /// Underlying execution-ladder reason for the current host.
    pub direct_execution_reason_code: BrowserExecutionReasonCode,
    /// Underlying runtime-support diagnostics for the current host.
    pub runtime_support: BrowserRuntimeSupportDiagnostics,
    /// Capability snapshot copied from runtime support diagnostics.
    pub capabilities: BrowserCapabilitySnapshot,
}

/// Reason codes for shared-worker coordinator caller-side preflight diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSharedWorkerCoordinatorSupportReason {
    /// The current caller host supports the bounded coordinator surface.
    Supported,
    /// The current caller host cannot attach to the bounded coordinator surface.
    SharedWorkerApiMissing,
}

impl BrowserSharedWorkerCoordinatorSupportReason {
    /// Stable string label aligned with the Browser Edition package surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::SharedWorkerApiMissing => "shared_worker_api_missing",
        }
    }
}

/// Host-class preflight diagnostics for the bounded shared-worker coordinator surface.
///
/// This remains intentionally narrower than the JS helper. The Rust preview
/// surface only reports whether the current caller host is a truthful place to
/// start a bounded coordinator attach flow; full same-origin script resolution
/// and admission checks remain on the JS helper surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSharedWorkerCoordinatorSupportDiagnostics {
    /// Whether the current caller host satisfies the bounded coordinator preflight.
    pub supported: bool,
    /// Stable bounded coordinator contract id.
    pub contract_id: &'static str,
    /// Stable bounded coordinator lane id.
    pub requested_lane: &'static str,
    /// Truthful first downgrade target when coordinator attach is unavailable.
    pub fallback_target: BrowserWorkerFallbackTarget,
    /// Truthful first downgrade lane, if it maps to a direct-runtime lane.
    pub fallback_lane_id: Option<BrowserExecutionLane>,
    /// Ordered downgrade targets for this helper surface.
    pub downgrade_order: Vec<BrowserWorkerFallbackTarget>,
    /// Browser host-role classification for the caller host.
    pub host_role: BrowserExecutionHostRole,
    /// Browser runtime context classification for the caller host.
    pub runtime_context: BrowserRuntimeContext,
    /// Caller-side support reason.
    pub reason: BrowserSharedWorkerCoordinatorSupportReason,
    /// Human-readable explanation.
    pub message: String,
    /// Operator guidance.
    pub guidance: Vec<String>,
    /// Direct-runtime reason for the shared-worker host itself.
    pub direct_runtime_reason: BrowserRuntimeSupportReason,
    /// Execution-ladder reason for the shared-worker host itself.
    pub direct_execution_reason_code: BrowserExecutionReasonCode,
    /// Underlying runtime-support diagnostics for the caller host.
    pub runtime_support: BrowserRuntimeSupportDiagnostics,
    /// Capability snapshot copied from runtime support diagnostics.
    pub capabilities: BrowserCapabilitySnapshot,
}

/// Browser execution host-role classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserExecutionHostRole {
    /// Browser main-thread entrypoint.
    BrowserMainThread,
    /// Dedicated worker entrypoint.
    DedicatedWorker,
    /// Service worker entrypoint.
    ServiceWorker,
    /// Shared worker entrypoint.
    SharedWorker,
    /// Anything else, including non-browser hosts.
    NonBrowserOrUnknown,
}

impl BrowserExecutionHostRole {
    /// Stable string label aligned with the shared execution-ladder contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserMainThread => "browser_main_thread",
            Self::DedicatedWorker => "dedicated_worker",
            Self::ServiceWorker => "service_worker",
            Self::SharedWorker => "shared_worker",
            Self::NonBrowserOrUnknown => "non_browser_or_unknown",
        }
    }
}

/// Browser execution lane identifiers aligned with the shared execution ladder contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserExecutionLane {
    /// Browser main-thread direct-runtime lane.
    BrowserMainThreadDirectRuntime,
    /// Dedicated-worker direct-runtime lane.
    DedicatedWorkerDirectRuntime,
    /// Terminal fail-closed lane.
    Unsupported,
}

impl BrowserExecutionLane {
    /// Stable lane identifier aligned with the shared execution-ladder contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserMainThreadDirectRuntime => "lane.browser.main_thread.direct_runtime",
            Self::DedicatedWorkerDirectRuntime => "lane.browser.dedicated_worker.direct_runtime",
            Self::Unsupported => "lane.unsupported",
        }
    }

    const fn lane_kind(self) -> BrowserExecutionLaneKind {
        match self {
            Self::Unsupported => BrowserExecutionLaneKind::Unsupported,
            Self::BrowserMainThreadDirectRuntime | Self::DedicatedWorkerDirectRuntime => {
                BrowserExecutionLaneKind::DirectRuntime
            }
        }
    }

    const fn lane_rank(self) -> u16 {
        match self {
            Self::BrowserMainThreadDirectRuntime => 10,
            Self::DedicatedWorkerDirectRuntime => 20,
            Self::Unsupported => 99,
        }
    }

    const fn fallback_lane(self) -> Option<Self> {
        match self {
            Self::Unsupported => None,
            Self::BrowserMainThreadDirectRuntime | Self::DedicatedWorkerDirectRuntime => {
                Some(Self::Unsupported)
            }
        }
    }
}

/// Browser execution lane kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserExecutionLaneKind {
    /// Direct browser runtime execution.
    DirectRuntime,
    /// Terminal fail-closed lane.
    Unsupported,
}

/// Browser execution reason codes aligned with the shared ladder semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserExecutionReasonCode {
    /// The selected lane is directly supported.
    Supported,
    /// The candidate lane does not match the current host role.
    CandidateHostRoleMismatch,
    /// The candidate lane matches the host role but prerequisites are missing.
    CandidatePrerequisiteMissing,
    /// The current context is a service worker and that lane is not yet shipped.
    ServiceWorkerDirectRuntimeNotShipped,
    /// The current context is a shared worker and that lane is not yet shipped.
    SharedWorkerDirectRuntimeNotShipped,
    /// `globalThis` is unavailable.
    MissingGlobalThis,
    /// `WebAssembly` is unavailable.
    MissingWebAssembly,
    /// The runtime context is unsupported.
    UnsupportedRuntimeContext,
    /// The current host is not a browser runtime.
    NonBrowserRuntime,
}

impl BrowserExecutionReasonCode {
    /// Stable string label aligned with the shared execution-ladder contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::CandidateHostRoleMismatch => "candidate_host_role_mismatch",
            Self::CandidatePrerequisiteMissing => "candidate_prerequisite_missing",
            Self::ServiceWorkerDirectRuntimeNotShipped => {
                "service_worker_direct_runtime_not_shipped"
            }
            Self::SharedWorkerDirectRuntimeNotShipped => "shared_worker_direct_runtime_not_shipped",
            Self::MissingGlobalThis => "missing_global_this",
            Self::MissingWebAssembly => "missing_webassembly",
            Self::UnsupportedRuntimeContext => "unsupported_runtime_context",
            Self::NonBrowserRuntime => "non_browser_runtime",
        }
    }
}

/// Candidate diagnostics for one browser execution lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserExecutionLaneCandidate {
    /// Candidate lane id.
    pub lane_id: BrowserExecutionLane,
    /// Candidate lane kind.
    pub lane_kind: BrowserExecutionLaneKind,
    /// Candidate lane rank.
    pub lane_rank: u16,
    /// Host role used for candidate evaluation.
    pub host_role: BrowserExecutionHostRole,
    /// Support class inherited from runtime support diagnostics.
    pub support_class: BrowserRuntimeSupportClass,
    /// Terminal fallback lane, if any.
    pub fallback_lane_id: Option<BrowserExecutionLane>,
    /// Whether the candidate is currently available.
    pub available: bool,
    /// Whether the candidate was selected.
    pub selected: bool,
    /// Candidate reason code.
    pub reason_code: BrowserExecutionReasonCode,
    /// Candidate explanation.
    pub message: String,
    /// Candidate operator guidance.
    pub guidance: Vec<String>,
}

/// Rust-side Browser Edition execution ladder diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserExecutionLadderDiagnostics {
    /// Whether the selected lane is a supported direct-runtime lane.
    pub supported: bool,
    /// Operator-requested preferred lane, if any.
    pub preferred_lane: Option<BrowserExecutionLane>,
    /// Selected lane id.
    pub selected_lane: BrowserExecutionLane,
    /// Selected lane kind.
    pub lane_kind: BrowserExecutionLaneKind,
    /// Selected lane rank.
    pub lane_rank: u16,
    /// Host role classification.
    pub host_role: BrowserExecutionHostRole,
    /// Support class inherited from runtime support diagnostics.
    pub support_class: BrowserRuntimeSupportClass,
    /// Runtime context classification.
    pub runtime_context: BrowserRuntimeContext,
    /// Selected reason code.
    pub reason_code: BrowserExecutionReasonCode,
    /// Human-readable explanation.
    pub message: String,
    /// Operator guidance.
    pub guidance: Vec<String>,
    /// Terminal fallback lane, if any.
    pub fallback_lane_id: Option<BrowserExecutionLane>,
    /// Truthful lane downgrade order for the current host role.
    pub downgrade_order: Vec<BrowserExecutionLane>,
    /// Reproduction command for the maintained Rust browser fixture.
    pub repro_command: String,
    /// Candidate diagnostics across the ladder.
    pub candidates: Vec<BrowserExecutionLaneCandidate>,
    /// Underlying runtime support diagnostics.
    pub runtime_support: BrowserRuntimeSupportDiagnostics,
    /// Capability snapshot copied from runtime support diagnostics.
    pub capabilities: BrowserCapabilitySnapshot,
}

/// Synthetic or observed host snapshot used to inspect browser ladder behavior.
///
/// This lets external Rust callers and maintained fixtures exercise the
/// execution-ladder policy against a deterministic host snapshot without
/// widening runtime support claims or depending on browser-only globals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserExecutionProbe {
    /// Whether a browser-like `globalThis` object exists.
    pub has_global_this: bool,
    /// Runtime context classification associated with this host snapshot.
    pub runtime_context: BrowserRuntimeContext,
    /// Browser host role associated with this host snapshot.
    pub host_role: BrowserExecutionHostRole,
    /// Capability snapshot carried by the synthetic or observed host.
    pub capabilities: BrowserCapabilitySnapshot,
}

impl BrowserExecutionProbe {
    /// Creates a non-browser probe that truthfully fail-closes the ladder.
    #[must_use]
    pub const fn non_browser() -> Self {
        Self {
            has_global_this: false,
            runtime_context: BrowserRuntimeContext::Unknown,
            host_role: BrowserExecutionHostRole::NonBrowserOrUnknown,
            capabilities: BrowserCapabilitySnapshot {
                execution_api: BrowserExecutionApiCapabilities {
                    has_abort_controller: false,
                    has_fetch: false,
                    has_webassembly: false,
                },
                dom: BrowserDomCapabilities {
                    has_document: false,
                    has_window: false,
                },
                storage: BrowserStorageCapabilities {
                    has_indexed_db: false,
                    has_local_storage: false,
                },
                transport: BrowserTransportCapabilities {
                    has_web_socket: false,
                    has_web_transport: false,
                },
            },
        }
    }

    /// Creates a browser main-thread probe with a minimal direct-runtime shape.
    #[must_use]
    pub const fn browser_main_thread() -> Self {
        Self {
            has_global_this: true,
            runtime_context: BrowserRuntimeContext::BrowserMainThread,
            host_role: BrowserExecutionHostRole::BrowserMainThread,
            capabilities: BrowserCapabilitySnapshot {
                execution_api: BrowserExecutionApiCapabilities {
                    has_abort_controller: true,
                    has_fetch: true,
                    has_webassembly: true,
                },
                dom: BrowserDomCapabilities {
                    has_document: true,
                    has_window: true,
                },
                storage: browser_storage_capabilities_for_host_role(
                    BrowserExecutionHostRole::BrowserMainThread,
                ),
                transport: BrowserTransportCapabilities {
                    has_web_socket: true,
                    has_web_transport: false,
                },
            },
        }
    }

    /// Creates a dedicated-worker probe with a minimal direct-runtime shape.
    #[must_use]
    pub const fn dedicated_worker() -> Self {
        Self {
            has_global_this: true,
            runtime_context: BrowserRuntimeContext::DedicatedWorker,
            host_role: BrowserExecutionHostRole::DedicatedWorker,
            capabilities: BrowserCapabilitySnapshot {
                execution_api: BrowserExecutionApiCapabilities {
                    has_abort_controller: true,
                    has_fetch: true,
                    has_webassembly: true,
                },
                dom: BrowserDomCapabilities {
                    has_document: false,
                    has_window: false,
                },
                storage: browser_storage_capabilities_for_host_role(
                    BrowserExecutionHostRole::DedicatedWorker,
                ),
                transport: BrowserTransportCapabilities {
                    has_web_socket: true,
                    has_web_transport: false,
                },
            },
        }
    }

    /// Creates a service-worker probe that remains fail-closed for direct runtime.
    #[must_use]
    pub const fn service_worker() -> Self {
        Self {
            has_global_this: true,
            runtime_context: BrowserRuntimeContext::ServiceWorker,
            host_role: BrowserExecutionHostRole::ServiceWorker,
            capabilities: BrowserCapabilitySnapshot {
                execution_api: BrowserExecutionApiCapabilities {
                    has_abort_controller: true,
                    has_fetch: true,
                    has_webassembly: true,
                },
                dom: BrowserDomCapabilities {
                    has_document: false,
                    has_window: false,
                },
                storage: browser_storage_capabilities_for_host_role(
                    BrowserExecutionHostRole::ServiceWorker,
                ),
                transport: BrowserTransportCapabilities {
                    has_web_socket: true,
                    has_web_transport: false,
                },
            },
        }
    }

    /// Creates a shared-worker probe that remains fail-closed for direct runtime.
    #[must_use]
    pub const fn shared_worker() -> Self {
        Self {
            has_global_this: true,
            runtime_context: BrowserRuntimeContext::SharedWorker,
            host_role: BrowserExecutionHostRole::SharedWorker,
            capabilities: BrowserCapabilitySnapshot {
                execution_api: BrowserExecutionApiCapabilities {
                    has_abort_controller: true,
                    has_fetch: true,
                    has_webassembly: true,
                },
                dom: BrowserDomCapabilities {
                    has_document: false,
                    has_window: false,
                },
                storage: browser_storage_capabilities_for_host_role(
                    BrowserExecutionHostRole::SharedWorker,
                ),
                transport: BrowserTransportCapabilities {
                    has_web_socket: true,
                    has_web_transport: false,
                },
            },
        }
    }
}

const fn browser_storage_capabilities_for_host_role(
    host_role: BrowserExecutionHostRole,
) -> BrowserStorageCapabilities {
    match host_role {
        BrowserExecutionHostRole::BrowserMainThread => BrowserStorageCapabilities {
            has_indexed_db: true,
            has_local_storage: true,
        },
        BrowserExecutionHostRole::DedicatedWorker
        | BrowserExecutionHostRole::ServiceWorker
        | BrowserExecutionHostRole::SharedWorker => BrowserStorageCapabilities {
            has_indexed_db: true,
            has_local_storage: false,
        },
        BrowserExecutionHostRole::NonBrowserOrUnknown => BrowserStorageCapabilities {
            has_indexed_db: false,
            has_local_storage: false,
        },
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_capability_snapshot(global_object: &JsValue) -> BrowserCapabilitySnapshot {
    BrowserCapabilitySnapshot {
        execution_api: BrowserExecutionApiCapabilities {
            has_abort_controller: browser_global_has(global_object, "AbortController"),
            has_fetch: browser_global_has(global_object, "fetch"),
            has_webassembly: browser_global_has(global_object, "WebAssembly"),
        },
        dom: BrowserDomCapabilities {
            has_document: browser_global_has(global_object, "document"),
            has_window: browser_global_has(global_object, "window"),
        },
        storage: BrowserStorageCapabilities {
            has_indexed_db: browser_global_has(global_object, "indexedDB"),
            has_local_storage: browser_global_has(global_object, "localStorage"),
        },
        transport: BrowserTransportCapabilities {
            has_web_socket: browser_global_has(global_object, "WebSocket"),
            has_web_transport: browser_global_has(global_object, "WebTransport"),
        },
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_global_has(global_object: &JsValue, key: &str) -> bool {
    Reflect::has(global_object, &JsValue::from_str(key)).unwrap_or(false)
}

#[cfg(target_arch = "wasm32")]
fn browser_global_constructor_name(global_object: &JsValue) -> Option<String> {
    let constructor = Reflect::get(global_object, &JsValue::from_str("constructor")).ok()?;
    let name = Reflect::get(&constructor, &JsValue::from_str("name")).ok()?;
    name.as_string()
}

#[cfg(target_arch = "wasm32")]
fn detect_browser_execution_probe() -> BrowserExecutionProbe {
    let global_object = global();
    let has_global_this = global_object.is_object();
    let capabilities = browser_capability_snapshot(&global_object);
    let constructor_name = browser_global_constructor_name(&global_object);

    let host_role = match constructor_name.as_deref() {
        Some("ServiceWorkerGlobalScope") => BrowserExecutionHostRole::ServiceWorker,
        Some("SharedWorkerGlobalScope") => BrowserExecutionHostRole::SharedWorker,
        Some("DedicatedWorkerGlobalScope") => BrowserExecutionHostRole::DedicatedWorker,
        _ if capabilities.dom.has_window && capabilities.dom.has_document => {
            BrowserExecutionHostRole::BrowserMainThread
        }
        _ => BrowserExecutionHostRole::NonBrowserOrUnknown,
    };

    let runtime_context = match host_role {
        BrowserExecutionHostRole::BrowserMainThread => BrowserRuntimeContext::BrowserMainThread,
        BrowserExecutionHostRole::DedicatedWorker => BrowserRuntimeContext::DedicatedWorker,
        BrowserExecutionHostRole::ServiceWorker => BrowserRuntimeContext::ServiceWorker,
        BrowserExecutionHostRole::SharedWorker => BrowserRuntimeContext::SharedWorker,
        BrowserExecutionHostRole::NonBrowserOrUnknown => BrowserRuntimeContext::Unknown,
    };

    BrowserExecutionProbe {
        has_global_this,
        runtime_context,
        host_role,
        capabilities,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn detect_browser_execution_probe() -> BrowserExecutionProbe {
    BrowserExecutionProbe::non_browser()
}

fn browser_runtime_support_diagnostics(
    probe: BrowserExecutionProbe,
    supported: bool,
    support_class: BrowserRuntimeSupportClass,
    reason: BrowserRuntimeSupportReason,
    message: &str,
    guidance: &[&str],
) -> BrowserRuntimeSupportDiagnostics {
    BrowserRuntimeSupportDiagnostics {
        supported,
        support_class,
        runtime_context: probe.runtime_context,
        reason,
        message: message.to_string(),
        guidance: guidance.iter().map(|entry| (*entry).to_string()).collect(),
        capabilities: probe.capabilities,
    }
}

fn browser_runtime_support_missing_global_this(
    probe: BrowserExecutionProbe,
) -> BrowserRuntimeSupportDiagnostics {
    browser_runtime_support_diagnostics(
        probe,
        false,
        BrowserRuntimeSupportClass::Unsupported,
        BrowserRuntimeSupportReason::MissingGlobalThis,
        "Rust Browser Edition runtime inspection could not find a browser global object.",
        &[
            "Run this inspection from a browser main-thread or dedicated-worker entrypoint.",
            "Use the maintained Rust browser fixture when validating browser support outside a browser host.",
        ],
    )
}

fn browser_runtime_support_not_yet_shipped(
    probe: BrowserExecutionProbe,
    reason: BrowserRuntimeSupportReason,
) -> BrowserRuntimeSupportDiagnostics {
    let (message, guidance) = match reason {
        BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped => (
            "Rust Browser Edition does not yet ship a service-worker direct-runtime lane.",
            &[
                "Keep Rust Browser Edition runtime creation out of service-worker hosts; the direct-runtime lane is intentionally fail-closed today.",
                "Use the bounded service-worker broker helpers for registration, durable handoff, and fallback orchestration instead of widening the direct-runtime claim.",
            ][..],
        ),
        BrowserRuntimeSupportReason::SharedWorkerNotYetShipped => (
            "Rust Browser Edition does not yet ship a shared-worker direct-runtime lane.",
            &[
                "Keep Rust Browser Edition runtime creation out of shared-worker hosts; the direct-runtime lane is intentionally fail-closed today.",
                "Use the bounded shared-worker coordinator helpers from a browser main-thread or dedicated-worker caller instead of widening the direct-runtime claim.",
            ][..],
        ),
        BrowserRuntimeSupportReason::MissingGlobalThis
        | BrowserRuntimeSupportReason::UnsupportedRuntimeContext
        | BrowserRuntimeSupportReason::MissingWebAssembly
        | BrowserRuntimeSupportReason::Supported => {
            unreachable!("only not-yet-shipped reasons are valid here")
        }
    };
    browser_runtime_support_diagnostics(
        probe,
        false,
        BrowserRuntimeSupportClass::Unsupported,
        reason,
        message,
        guidance,
    )
}

fn browser_runtime_support_unsupported_context(
    probe: BrowserExecutionProbe,
) -> BrowserRuntimeSupportDiagnostics {
    browser_runtime_support_diagnostics(
        probe,
        false,
        BrowserRuntimeSupportClass::Unsupported,
        BrowserRuntimeSupportReason::UnsupportedRuntimeContext,
        "Rust Browser Edition inspection only recognizes browser main-thread and dedicated-worker direct-runtime contexts.",
        &[
            "Move the call into a browser main-thread or dedicated-worker entrypoint before expecting a direct runtime lane.",
        ],
    )
}

fn browser_runtime_support_missing_webassembly(
    probe: BrowserExecutionProbe,
) -> BrowserRuntimeSupportDiagnostics {
    browser_runtime_support_diagnostics(
        probe,
        false,
        BrowserRuntimeSupportClass::Unsupported,
        BrowserRuntimeSupportReason::MissingWebAssembly,
        "Rust Browser Edition runtime inspection found no WebAssembly support in the current host.",
        &[
            "Enable WebAssembly in the target browser/runtime before expecting a direct runtime lane.",
        ],
    )
}

fn browser_runtime_support_supported(
    probe: BrowserExecutionProbe,
) -> BrowserRuntimeSupportDiagnostics {
    let message = match probe.runtime_context {
        BrowserRuntimeContext::BrowserMainThread => {
            "Rust Browser Edition runtime inspection found a browser main-thread direct-runtime context."
        }
        BrowserRuntimeContext::DedicatedWorker => {
            "Rust Browser Edition runtime inspection found a dedicated-worker direct-runtime context."
        }
        BrowserRuntimeContext::ServiceWorker
        | BrowserRuntimeContext::SharedWorker
        | BrowserRuntimeContext::Unknown => {
            unreachable!(
                "supported browser runtime inspection requires a shipped direct-runtime context"
            )
        }
    };
    browser_runtime_support_diagnostics(
        probe,
        true,
        BrowserRuntimeSupportClass::DirectRuntimeSupported,
        BrowserRuntimeSupportReason::Supported,
        message,
        &[],
    )
}

fn browser_runtime_support_from_probe(
    probe: BrowserExecutionProbe,
) -> BrowserRuntimeSupportDiagnostics {
    if !probe.has_global_this {
        return browser_runtime_support_missing_global_this(probe);
    }

    match probe.host_role {
        BrowserExecutionHostRole::ServiceWorker => browser_runtime_support_not_yet_shipped(
            probe,
            BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped,
        ),
        BrowserExecutionHostRole::SharedWorker => browser_runtime_support_not_yet_shipped(
            probe,
            BrowserRuntimeSupportReason::SharedWorkerNotYetShipped,
        ),
        BrowserExecutionHostRole::BrowserMainThread
        | BrowserExecutionHostRole::DedicatedWorker
        | BrowserExecutionHostRole::NonBrowserOrUnknown => {
            if probe.runtime_context == BrowserRuntimeContext::Unknown {
                return browser_runtime_support_unsupported_context(probe);
            }

            if !probe.capabilities.execution_api.has_webassembly {
                return browser_runtime_support_missing_webassembly(probe);
            }

            browser_runtime_support_supported(probe)
        }
    }
}

const fn browser_execution_direct_lane_for_host_role(
    host_role: BrowserExecutionHostRole,
) -> Option<BrowserExecutionLane> {
    match host_role {
        BrowserExecutionHostRole::BrowserMainThread => {
            Some(BrowserExecutionLane::BrowserMainThreadDirectRuntime)
        }
        BrowserExecutionHostRole::DedicatedWorker => {
            Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime)
        }
        BrowserExecutionHostRole::ServiceWorker
        | BrowserExecutionHostRole::SharedWorker
        | BrowserExecutionHostRole::NonBrowserOrUnknown => None,
    }
}

fn browser_execution_downgrade_order(
    host_role: BrowserExecutionHostRole,
) -> Vec<BrowserExecutionLane> {
    browser_execution_direct_lane_for_host_role(host_role).map_or_else(
        || vec![BrowserExecutionLane::Unsupported],
        |direct| vec![direct, BrowserExecutionLane::Unsupported],
    )
}

fn browser_execution_reason_from_support(
    support: &BrowserRuntimeSupportDiagnostics,
    host_role: BrowserExecutionHostRole,
) -> BrowserExecutionReasonCode {
    match support.reason {
        BrowserRuntimeSupportReason::MissingGlobalThis => {
            BrowserExecutionReasonCode::MissingGlobalThis
        }
        BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped => {
            BrowserExecutionReasonCode::ServiceWorkerDirectRuntimeNotShipped
        }
        BrowserRuntimeSupportReason::SharedWorkerNotYetShipped => {
            BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped
        }
        BrowserRuntimeSupportReason::UnsupportedRuntimeContext => {
            if host_role == BrowserExecutionHostRole::NonBrowserOrUnknown {
                BrowserExecutionReasonCode::NonBrowserRuntime
            } else {
                BrowserExecutionReasonCode::UnsupportedRuntimeContext
            }
        }
        BrowserRuntimeSupportReason::MissingWebAssembly => {
            BrowserExecutionReasonCode::MissingWebAssembly
        }
        BrowserRuntimeSupportReason::Supported => BrowserExecutionReasonCode::Supported,
    }
}

fn browser_execution_repro_command() -> String {
    "PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh".to_string()
}

fn browser_execution_host_mismatch_message(lane_id: BrowserExecutionLane) -> String {
    match lane_id {
        BrowserExecutionLane::BrowserMainThreadDirectRuntime => {
            "lane.browser.main_thread.direct_runtime only applies when Rust Browser Edition is running on the browser main thread."
                .to_string()
        }
        BrowserExecutionLane::DedicatedWorkerDirectRuntime => {
            "lane.browser.dedicated_worker.direct_runtime only applies when Rust Browser Edition is already executing inside a dedicated worker."
                .to_string()
        }
        BrowserExecutionLane::Unsupported => {
            "lane.unsupported is the terminal fail-closed lane and is only selected after a truthful downgrade."
                .to_string()
        }
    }
}

fn browser_execution_host_mismatch_guidance(lane_id: BrowserExecutionLane) -> Vec<String> {
    match lane_id {
        BrowserExecutionLane::BrowserMainThreadDirectRuntime => vec![
            "Initialize the Rust browser surface from a browser main-thread entrypoint before pinning this lane."
                .to_string(),
        ],
        BrowserExecutionLane::DedicatedWorkerDirectRuntime => vec![
            "Move the Rust browser surface into a dedicated-worker entrypoint before pinning this lane."
                .to_string(),
        ],
        BrowserExecutionLane::Unsupported => vec![
            "Treat lane.unsupported as the terminal fail-closed lane when no truthful direct-runtime browser lane remains."
                .to_string(),
        ],
    }
}

fn browser_execution_missing_prerequisite_message(lane_id: BrowserExecutionLane) -> String {
    match lane_id {
        BrowserExecutionLane::Unsupported => {
            "lane.unsupported remains the terminal fail-closed fallback if the current direct-runtime lane loses truthful prerequisites."
                .to_string()
        }
        BrowserExecutionLane::BrowserMainThreadDirectRuntime
        | BrowserExecutionLane::DedicatedWorkerDirectRuntime => {
            format!(
                "{} matches the current host role but is unavailable until the required Browser Edition prerequisites are restored.",
                match lane_id {
                    BrowserExecutionLane::BrowserMainThreadDirectRuntime => {
                        "lane.browser.main_thread.direct_runtime"
                    }
                    BrowserExecutionLane::DedicatedWorkerDirectRuntime => {
                        "lane.browser.dedicated_worker.direct_runtime"
                    }
                    BrowserExecutionLane::Unsupported => unreachable!(),
                }
            )
        }
    }
}

fn browser_execution_missing_prerequisite_guidance(lane_id: BrowserExecutionLane) -> Vec<String> {
    match lane_id {
        BrowserExecutionLane::Unsupported => vec![
            "Expect Rust Browser Edition to demote here instead of pretending a direct-runtime lane exists when prerequisites disappear."
                .to_string(),
        ],
        BrowserExecutionLane::BrowserMainThreadDirectRuntime
        | BrowserExecutionLane::DedicatedWorkerDirectRuntime => vec![
            "Restore the missing Browser Edition prerequisites before pinning this lane again."
                .to_string(),
        ],
    }
}

fn browser_execution_preferred_lane_mismatch(
    preferred_lane: BrowserExecutionLane,
    selected_lane: BrowserExecutionLane,
    host_role: BrowserExecutionHostRole,
    direct_lane_for_host: Option<BrowserExecutionLane>,
    reason_code: BrowserExecutionReasonCode,
) -> (String, Vec<String>) {
    if preferred_lane != BrowserExecutionLane::Unsupported
        && Some(preferred_lane) != direct_lane_for_host
    {
        return (
            format!(
                "Preferred lane {} is not truthful for host role {}, so Rust Browser Edition stayed on {}.",
                preferred_lane.as_str(),
                host_role.as_str(),
                selected_lane.as_str(),
            ),
            vec![format!(
                "Use {} for this host role, or switch entrypoints before pinning {}.",
                selected_lane.as_str(),
                preferred_lane.as_str(),
            )],
        );
    }

    if selected_lane == BrowserExecutionLane::Unsupported {
        return (
            format!(
                "Preferred lane {} could not be selected because Rust Browser Edition currently reports {} and stayed on {}.",
                preferred_lane.as_str(),
                reason_code.as_str(),
                selected_lane.as_str(),
            ),
            vec![format!(
                "Restore the reported Browser Edition prerequisites before pinning {} again.",
                preferred_lane.as_str(),
            )],
        );
    }

    (
        format!(
            "Preferred lane {} is a lower-priority fail-closed fallback, so Rust Browser Edition stayed on {}.",
            preferred_lane.as_str(),
            selected_lane.as_str(),
        ),
        vec![format!(
            "Only pin {} when you intentionally want the fail-closed fallback lane.",
            preferred_lane.as_str(),
        )],
    )
}

struct BrowserExecutionLaneCandidateInput {
    lane_id: BrowserExecutionLane,
    host_role: BrowserExecutionHostRole,
    support_class: BrowserRuntimeSupportClass,
    available: bool,
    selected: bool,
    reason_code: BrowserExecutionReasonCode,
    message: String,
    guidance: Vec<String>,
}

fn create_browser_execution_lane_candidate(
    input: BrowserExecutionLaneCandidateInput,
) -> BrowserExecutionLaneCandidate {
    BrowserExecutionLaneCandidate {
        lane_id: input.lane_id,
        lane_kind: input.lane_id.lane_kind(),
        lane_rank: input.lane_id.lane_rank(),
        host_role: input.host_role,
        support_class: input.support_class,
        fallback_lane_id: input.lane_id.fallback_lane(),
        available: input.available,
        selected: input.selected,
        reason_code: input.reason_code,
        message: input.message,
        guidance: input.guidance,
    }
}

fn browser_execution_candidates(
    selected_lane: BrowserExecutionLane,
    host_role: BrowserExecutionHostRole,
    support_class: BrowserRuntimeSupportClass,
    selected_reason_code: BrowserExecutionReasonCode,
    selected_message: &str,
    selected_guidance: &[String],
) -> Vec<BrowserExecutionLaneCandidate> {
    let direct_lane_for_host = browser_execution_direct_lane_for_host_role(host_role);
    let lane_ids = [
        BrowserExecutionLane::BrowserMainThreadDirectRuntime,
        BrowserExecutionLane::DedicatedWorkerDirectRuntime,
        BrowserExecutionLane::Unsupported,
    ];

    lane_ids
        .into_iter()
        .map(|lane_id| {
            if lane_id == selected_lane {
                return create_browser_execution_lane_candidate(
                    BrowserExecutionLaneCandidateInput {
                        lane_id,
                        host_role,
                        support_class,
                        available: true,
                        selected: true,
                        reason_code: selected_reason_code,
                        message: selected_message.to_string(),
                        guidance: selected_guidance.to_vec(),
                    },
                );
            }

            let prerequisite_missing = if lane_id == BrowserExecutionLane::Unsupported {
                selected_lane != BrowserExecutionLane::Unsupported
            } else {
                direct_lane_for_host == Some(lane_id)
                    && selected_lane == BrowserExecutionLane::Unsupported
            };

            if prerequisite_missing {
                return create_browser_execution_lane_candidate(
                    BrowserExecutionLaneCandidateInput {
                        lane_id,
                        host_role,
                        support_class,
                        available: false,
                        selected: false,
                        reason_code: BrowserExecutionReasonCode::CandidatePrerequisiteMissing,
                        message: browser_execution_missing_prerequisite_message(lane_id),
                        guidance: browser_execution_missing_prerequisite_guidance(lane_id),
                    },
                );
            }

            create_browser_execution_lane_candidate(BrowserExecutionLaneCandidateInput {
                lane_id,
                host_role,
                support_class,
                available: false,
                selected: false,
                reason_code: BrowserExecutionReasonCode::CandidateHostRoleMismatch,
                message: browser_execution_host_mismatch_message(lane_id),
                guidance: browser_execution_host_mismatch_guidance(lane_id),
            })
        })
        .collect()
}

fn build_browser_execution_ladder_from_probe(
    preferred_lane: Option<BrowserExecutionLane>,
    probe: BrowserExecutionProbe,
) -> BrowserExecutionLadderDiagnostics {
    let runtime_support = browser_runtime_support_from_probe(probe);
    let host_role = probe.host_role;
    let direct_lane_for_host = browser_execution_direct_lane_for_host_role(host_role);
    let selected_lane = runtime_support
        .supported
        .then_some(direct_lane_for_host)
        .flatten()
        .unwrap_or(BrowserExecutionLane::Unsupported);
    let reason_code = browser_execution_reason_from_support(&runtime_support, host_role);
    let mut message = runtime_support.message.clone();
    let mut guidance = runtime_support.guidance.clone();

    if let Some(preferred_lane) = preferred_lane.filter(|lane| *lane != selected_lane) {
        let (mismatch_message, mismatch_guidance) = browser_execution_preferred_lane_mismatch(
            preferred_lane,
            selected_lane,
            host_role,
            direct_lane_for_host,
            reason_code,
        );
        message = format!("{message} {mismatch_message}");
        guidance.extend(mismatch_guidance);
    }

    let support_class = runtime_support.support_class;
    let candidates = browser_execution_candidates(
        selected_lane,
        host_role,
        support_class,
        reason_code,
        &message,
        &guidance,
    );
    let capabilities = runtime_support.capabilities;

    BrowserExecutionLadderDiagnostics {
        supported: selected_lane != BrowserExecutionLane::Unsupported,
        preferred_lane,
        selected_lane,
        lane_kind: selected_lane.lane_kind(),
        lane_rank: selected_lane.lane_rank(),
        host_role,
        support_class,
        runtime_context: runtime_support.runtime_context,
        reason_code,
        message,
        guidance,
        fallback_lane_id: selected_lane.fallback_lane(),
        downgrade_order: browser_execution_downgrade_order(host_role),
        repro_command: browser_execution_repro_command(),
        candidates,
        runtime_support,
        capabilities,
    }
}

fn browser_service_worker_broker_downgrade_order() -> Vec<BrowserWorkerFallbackTarget> {
    vec![
        BrowserWorkerFallbackTarget::DedicatedWorkerDirectRuntime,
        BrowserWorkerFallbackTarget::BrowserMainThreadDirectRuntime,
        BrowserWorkerFallbackTarget::BridgeFallback,
    ]
}

fn browser_shared_worker_coordinator_downgrade_order(
    host_role: BrowserExecutionHostRole,
) -> Vec<BrowserWorkerFallbackTarget> {
    let mut targets = Vec::new();
    if host_role == BrowserExecutionHostRole::DedicatedWorker {
        targets.push(BrowserWorkerFallbackTarget::DedicatedWorkerDirectRuntime);
    }
    if host_role == BrowserExecutionHostRole::BrowserMainThread {
        targets.push(BrowserWorkerFallbackTarget::BrowserMainThreadDirectRuntime);
    }
    if !targets.contains(&BrowserWorkerFallbackTarget::DedicatedWorkerDirectRuntime) {
        targets.push(BrowserWorkerFallbackTarget::DedicatedWorkerDirectRuntime);
    }
    if !targets.contains(&BrowserWorkerFallbackTarget::BrowserMainThreadDirectRuntime) {
        targets.push(BrowserWorkerFallbackTarget::BrowserMainThreadDirectRuntime);
    }
    targets.push(BrowserWorkerFallbackTarget::BridgeFallback);
    targets
}

fn browser_service_worker_broker_support_from_probe(
    probe: BrowserExecutionProbe,
) -> BrowserServiceWorkerBrokerSupportDiagnostics {
    let runtime_support = browser_runtime_support_from_probe(probe);
    let capabilities = runtime_support.capabilities;
    let downgrade_order = browser_service_worker_broker_downgrade_order();
    let fallback_target = downgrade_order[0];
    let direct_runtime_reason = runtime_support.reason;
    let direct_execution_reason_code =
        browser_execution_reason_from_support(&runtime_support, probe.host_role);
    let (supported, reason, message, guidance) = if probe.host_role
        != BrowserExecutionHostRole::ServiceWorker
    {
        (
            false,
            BrowserServiceWorkerBrokerSupportReason::ServiceWorkerApiMissing,
            "Rust Browser Edition service-worker broker preflight only admits service-worker hosts."
                .to_string(),
            vec![
                "Call the bounded broker surface only from a service-worker entrypoint."
                    .to_string(),
                format!(
                    "Keep direct BrowserRuntime creation on {} or {} when broker admission is unavailable.",
                    BrowserExecutionLane::DedicatedWorkerDirectRuntime.as_str(),
                    BrowserExecutionLane::BrowserMainThreadDirectRuntime.as_str()
                ),
            ],
        )
    } else if !probe.capabilities.storage.has_indexed_db {
        (
            false,
            BrowserServiceWorkerBrokerSupportReason::DurableStoreUnavailableForRestartableProfile,
            "Rust Browser Edition service-worker broker preflight found no durable store for the default restartable broker profile."
                .to_string(),
            vec![
                "Restore IndexedDB-backed durability before claiming restartable broker progress."
                    .to_string(),
                "Downgrade explicitly instead of pretending restartability without a durable substrate."
                    .to_string(),
            ],
        )
    } else {
        (
            true,
            BrowserServiceWorkerBrokerSupportReason::Supported,
            "Rust Browser Edition service-worker broker preflight found a bounded broker host surface; direct runtime creation remains fail-closed and work must hand off explicitly."
                .to_string(),
            vec![
                "Keep direct BrowserRuntime creation out of the service-worker host itself."
                    .to_string(),
                "Treat registration-scope and capability-manifest checks as explicit broker admission work on the JS helper surface."
                    .to_string(),
            ],
        )
    };

    BrowserServiceWorkerBrokerSupportDiagnostics {
        supported,
        contract_id: BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID,
        requested_lane: BROWSER_SERVICE_WORKER_BROKER_LANE,
        fallback_target,
        fallback_lane_id: fallback_target.fallback_lane_id(),
        downgrade_order,
        host_role: probe.host_role,
        runtime_context: runtime_support.runtime_context,
        reason,
        message,
        guidance,
        direct_runtime_reason,
        direct_execution_reason_code,
        runtime_support,
        capabilities,
    }
}

fn browser_shared_worker_coordinator_support_from_probe(
    probe: BrowserExecutionProbe,
) -> BrowserSharedWorkerCoordinatorSupportDiagnostics {
    let runtime_support = browser_runtime_support_from_probe(probe);
    let capabilities = runtime_support.capabilities;
    let downgrade_order = browser_shared_worker_coordinator_downgrade_order(probe.host_role);
    let fallback_target = downgrade_order[0];
    let direct_runtime_reason = BrowserRuntimeSupportReason::SharedWorkerNotYetShipped;
    let direct_execution_reason_code =
        BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped;
    let (supported, reason, message, guidance) = match probe.host_role {
        BrowserExecutionHostRole::BrowserMainThread | BrowserExecutionHostRole::DedicatedWorker => (
            true,
            BrowserSharedWorkerCoordinatorSupportReason::Supported,
            "Rust Browser Edition shared-worker coordinator preflight found a truthful caller host; direct BrowserRuntime creation inside the shared-worker host remains fail-closed."
                .to_string(),
            vec![
                "Call the bounded shared-worker coordinator only from a browser main-thread or dedicated-worker caller."
                    .to_string(),
                "Treat same-origin script resolution, admission tuple checks, and protocol negotiation as explicit JS helper responsibilities."
                    .to_string(),
            ],
        ),
        _ => (
            false,
            BrowserSharedWorkerCoordinatorSupportReason::SharedWorkerApiMissing,
            "Rust Browser Edition shared-worker coordinator preflight only admits browser main-thread or dedicated-worker callers."
                .to_string(),
            vec![
                "Move the coordinator attach flow into a browser main-thread or dedicated-worker caller before expecting a bounded coordinator surface."
                    .to_string(),
                "Keep direct BrowserRuntime creation fail-closed inside the shared-worker host itself."
                    .to_string(),
            ],
        ),
    };

    BrowserSharedWorkerCoordinatorSupportDiagnostics {
        supported,
        contract_id: BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
        requested_lane: BROWSER_SHARED_WORKER_COORDINATOR_LANE,
        fallback_target,
        fallback_lane_id: fallback_target.fallback_lane_id(),
        downgrade_order,
        host_role: probe.host_role,
        runtime_context: runtime_support.runtime_context,
        reason,
        message,
        guidance,
        direct_runtime_reason,
        direct_execution_reason_code,
        runtime_support,
        capabilities,
    }
}

/// Error returned when the preview Rust browser runtime cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
pub enum BrowserRuntimeBuildError {
    /// The current host truthfully fail-closed to `lane.unsupported`.
    #[error("{message}")]
    Unsupported {
        /// Execution-ladder diagnostics that explain the fail-closed decision.
        execution_ladder: BrowserExecutionLadderDiagnostics,
        /// Human-readable explanation preserved for quick surfacing.
        message: String,
    },
    /// Runtime handle creation failed at the dispatcher boundary.
    #[error("failed to create preview browser runtime handle: {source}")]
    RuntimeCreate {
        /// Execution-ladder diagnostics in effect when creation failed.
        execution_ladder: BrowserExecutionLadderDiagnostics,
        /// Boundary-level error returned by the dispatcher.
        source: WasmDispatchError,
    },
}

impl BrowserRuntimeBuildError {
    /// Returns the browser execution-ladder diagnostics associated with this failure.
    #[must_use]
    pub fn execution_ladder(&self) -> &BrowserExecutionLadderDiagnostics {
        match self {
            Self::Unsupported {
                execution_ladder, ..
            }
            | Self::RuntimeCreate {
                execution_ladder, ..
            } => execution_ladder,
        }
    }
}

#[derive(Debug)]
struct BrowserRuntimeInner {
    dispatcher: RefCell<WasmExportDispatcher>,
    runtime_handle: WasmHandleRef,
    consumer_version: Option<WasmAbiVersion>,
    execution_ladder: BrowserExecutionLadderDiagnostics,
}

/// Dispatcher-backed preview runtime for Rust-authored browser consumers.
///
/// This is intentionally narrower than the native [`Runtime`]: it provides a
/// truthful browser entrypoint over the wasm ABI dispatcher instead of
/// pretending the browser already has full native-thread runtime parity.
#[derive(Debug, Clone)]
pub struct BrowserRuntime {
    inner: Rc<BrowserRuntimeInner>,
}

impl BrowserRuntime {
    fn new(
        dispatcher: WasmExportDispatcher,
        runtime_handle: WasmHandleRef,
        consumer_version: Option<WasmAbiVersion>,
        execution_ladder: BrowserExecutionLadderDiagnostics,
    ) -> Self {
        Self {
            inner: Rc::new(BrowserRuntimeInner {
                dispatcher: RefCell::new(dispatcher),
                runtime_handle,
                consumer_version,
                execution_ladder,
            }),
        }
    }

    /// Returns the browser runtime handle exported through the wasm dispatcher.
    #[must_use]
    pub fn runtime_handle(&self) -> WasmHandleRef {
        self.inner.runtime_handle
    }

    /// Returns the consumer ABI version used for boundary calls, if pinned.
    #[must_use]
    pub fn consumer_version(&self) -> Option<WasmAbiVersion> {
        self.inner.consumer_version
    }

    /// Returns the execution-ladder diagnostics used to select this runtime.
    #[must_use]
    pub fn execution_ladder(&self) -> &BrowserExecutionLadderDiagnostics {
        &self.inner.execution_ladder
    }

    /// Returns a snapshot of dispatcher state for leak detection and observability.
    #[must_use]
    pub fn dispatcher_diagnostics(&self) -> WasmDispatcherDiagnostics {
        self.inner.dispatcher.borrow().diagnostic_snapshot()
    }

    /// Enters a child scope beneath the runtime handle.
    pub fn enter_scope(&self, label: Option<&str>) -> Result<WasmHandleRef, WasmDispatchError> {
        let mut dispatcher = self.inner.dispatcher.borrow_mut();
        dispatcher.scope_enter(
            &WasmScopeEnterBuilder::new(self.runtime_handle())
                .label(label.unwrap_or("root"))
                .build(),
            self.consumer_version(),
        )
    }

    /// Closes a previously entered child scope.
    pub fn close_scope(
        &self,
        scope: &WasmHandleRef,
    ) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.inner
            .dispatcher
            .borrow_mut()
            .scope_close(scope, self.consumer_version())
    }

    /// Closes the runtime and drains all remaining child handles.
    pub fn close(&self) -> Result<WasmAbiOutcomeEnvelope, WasmDispatchError> {
        self.inner
            .dispatcher
            .borrow_mut()
            .runtime_close(&self.inner.runtime_handle, self.consumer_version())
    }
}

/// No-throw preview browser runtime selection result.
#[derive(Debug, Clone)]
pub struct BrowserRuntimeSelectionResult {
    /// Truthful execution-ladder diagnostics for the current host.
    pub execution_ladder: BrowserExecutionLadderDiagnostics,
    /// Constructed preview runtime, when the selected lane is supported.
    pub runtime: Option<BrowserRuntime>,
    /// Structured failure, when construction fail-closes.
    pub error: Option<BrowserRuntimeBuildError>,
}

impl BrowserRuntimeSelectionResult {
    /// Returns `true` when a preview runtime was constructed successfully.
    #[must_use]
    pub fn runtime_available(&self) -> bool {
        self.runtime.is_some()
    }
}

fn build_browser_runtime_selection_from_probe(
    preferred_lane: Option<BrowserExecutionLane>,
    consumer_version: Option<WasmAbiVersion>,
    abort_mode: WasmAbortPropagationMode,
    probe: BrowserExecutionProbe,
) -> BrowserRuntimeSelectionResult {
    build_browser_runtime_selection_with_dispatcher_from_probe(
        preferred_lane,
        consumer_version,
        abort_mode,
        probe,
        WasmExportDispatcher::new(),
    )
}

fn build_browser_runtime_selection_with_dispatcher_from_probe(
    preferred_lane: Option<BrowserExecutionLane>,
    consumer_version: Option<WasmAbiVersion>,
    abort_mode: WasmAbortPropagationMode,
    probe: BrowserExecutionProbe,
    dispatcher: WasmExportDispatcher,
) -> BrowserRuntimeSelectionResult {
    let execution_ladder = build_browser_execution_ladder_from_probe(preferred_lane, probe);

    if !execution_ladder.supported {
        return BrowserRuntimeSelectionResult {
            runtime: None,
            error: Some(BrowserRuntimeBuildError::Unsupported {
                message: execution_ladder.message.clone(),
                execution_ladder: execution_ladder.clone(),
            }),
            execution_ladder,
        };
    }

    let mut dispatcher = dispatcher.with_abort_mode(abort_mode);
    match dispatcher.runtime_create(consumer_version) {
        Ok(runtime_handle) => BrowserRuntimeSelectionResult {
            runtime: Some(BrowserRuntime::new(
                dispatcher,
                runtime_handle,
                consumer_version,
                execution_ladder.clone(),
            )),
            error: None,
            execution_ladder,
        },
        Err(source) => BrowserRuntimeSelectionResult {
            runtime: None,
            error: Some(BrowserRuntimeBuildError::RuntimeCreate {
                execution_ladder: execution_ladder.clone(),
                source,
            }),
            execution_ladder,
        },
    }
}

/// Preview builder for Rust-authored browser runtime construction.
#[derive(Debug, Clone)]
pub struct BrowserRuntimeBuilder {
    preferred_lane: Option<BrowserExecutionLane>,
    consumer_version: Option<WasmAbiVersion>,
    abort_mode: WasmAbortPropagationMode,
}

impl Default for BrowserRuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserRuntimeBuilder {
    /// Creates a preview browser runtime builder with automatic lane negotiation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            preferred_lane: None,
            consumer_version: None,
            abort_mode: WasmAbortPropagationMode::Bidirectional,
        }
    }

    /// Requests an explicit browser execution lane.
    #[must_use]
    pub fn preferred_lane(mut self, lane: BrowserExecutionLane) -> Self {
        self.preferred_lane = Some(lane);
        self
    }

    /// Restores automatic truthful lane negotiation.
    #[must_use]
    pub fn automatic_lane(mut self) -> Self {
        self.preferred_lane = None;
        self
    }

    /// Pins the consumer ABI version used for dispatcher boundary calls.
    #[must_use]
    pub fn consumer_version(mut self, version: WasmAbiVersion) -> Self {
        self.consumer_version = Some(version);
        self
    }

    /// Configures abort propagation semantics for the preview runtime dispatcher.
    #[must_use]
    pub fn abort_mode(mut self, mode: WasmAbortPropagationMode) -> Self {
        self.abort_mode = mode;
        self
    }

    /// Returns the truthful execution ladder for the current host and builder options.
    #[must_use]
    pub fn inspect_execution_ladder(self) -> BrowserExecutionLadderDiagnostics {
        build_browser_execution_ladder_from_probe(
            self.preferred_lane,
            detect_browser_execution_probe(),
        )
    }

    /// Returns a no-throw preview browser runtime selection result.
    #[must_use]
    pub fn build_selection(self) -> BrowserRuntimeSelectionResult {
        build_browser_runtime_selection_from_probe(
            self.preferred_lane,
            self.consumer_version,
            self.abort_mode,
            detect_browser_execution_probe(),
        )
    }

    /// Builds a preview browser runtime or returns a structured fail-closed error.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<BrowserRuntime, BrowserRuntimeBuildError> {
        let selection = self.build_selection();
        match (selection.runtime, selection.error) {
            (Some(runtime), None) => Ok(runtime),
            (None | Some(_), Some(error)) => Err(error),
            (None, None) => Err(BrowserRuntimeBuildError::Unsupported {
                message: selection.execution_ladder.message.clone(),
                execution_ladder: selection.execution_ladder,
            }),
        }
    }
}

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
    scoped_cpu_worker_limit: Option<usize>,
    reactor: Option<Arc<dyn Reactor>>,
    io_driver: Option<IoDriverHandle>,
    io_uring_capability_policy: IoUringCapabilityPolicy,
    /// Construct the platform reactor at build time by default
    /// (br-asupersync-1ajbtl).
    platform_reactor: bool,
    timer_driver: Option<TimerDriverHandle>,
    entropy_source: Option<Arc<dyn EntropySource>>,
    host_services: Arc<dyn RuntimeHostServices>,
    /// Set by [`RuntimeBuilder::current_thread`]: `Runtime::block_on` drives
    /// the single worker from the calling thread (GH#58).
    current_thread: bool,
    /// Optional bounded production poll/wake capture, installed before exposure.
    capture_schedules: bool,
    /// Given to every worker before it starts (asupersync-7yq1pv item 2).
    scheduler_evidence_sink: Option<Arc<dyn crate::evidence_sink::EvidenceSink>>,
    /// Set once the blocking pool's maximum is chosen explicitly. The default
    /// pool is marked so CPU-bound fan-out ignores its cap (kpmoy5.1.15).
    blocking_sized: bool,
    /// Set by [`RuntimeBuilder::resource_sampling`]: how often a sampler
    /// thread refreshes resource pressure (asupersync-1ir2em).
    resource_sampling: Option<Duration>,
}

/// The builder's on-demand blocking pool maximum; wasm32 has no pool threads.
const DEFAULT_BLOCKING_MAX_THREADS: usize = if cfg!(target_arch = "wasm32") { 0 } else { 512 };

impl RuntimeBuilder {
    /// Create a new builder with default configuration.
    ///
    /// On native targets it starts with an on-demand blocking pool,
    /// `blocking_threads(0, 512)`: threads start on first use and retire when
    /// idle, so `spawn_blocking` and the `fs` facades leave the async workers.
    /// `blocking_threads(0, 0)` restores the inline fallback.
    #[must_use]
    pub fn new() -> Self {
        let mut config = RuntimeConfig::default();
        config.blocking.max_threads = DEFAULT_BLOCKING_MAX_THREADS;
        Self {
            config,
            scoped_cpu_worker_limit: None,
            reactor: None,
            io_driver: None,
            io_uring_capability_policy: IoUringCapabilityPolicy::default(),
            platform_reactor: true,
            timer_driver: None,
            entropy_source: None,
            host_services: default_runtime_host_services(),
            current_thread: false,
            capture_schedules: false,
            scheduler_evidence_sink: None,
            blocking_sized: false,
            resource_sampling: None,
        }
    }

    /// Creates a preview builder for Rust-authored browser runtime construction.
    ///
    /// The returned builder performs truthful execution-ladder selection and
    /// fail-closes to structured diagnostics when no direct browser-runtime
    /// lane is available.
    #[must_use]
    pub fn browser() -> BrowserRuntimeBuilder {
        BrowserRuntimeBuilder::new()
    }

    /// Set the number of worker threads.
    #[must_use]
    pub fn worker_threads(mut self, n: usize) -> Self {
        self.config.worker_threads = n;
        self
    }

    /// Capture native task dispatch, poll, wake, yield and cancellation-ack events.
    ///
    /// Disabled by default. Enabled capture shares the bounded trace storage
    /// selected by [`Self::trace_storage_profile`] and records worker metadata
    /// separately without changing the canonical trace event schema. Inspect
    /// [`Runtime::schedule_capture_snapshot`] for explicit truncation and
    /// projection errors before attempting production-to-Lab replay.
    #[must_use]
    pub fn capture_schedules(mut self, enabled: bool) -> Self {
        self.capture_schedules = enabled;
        self
    }

    /// Record the scheduling decisions of the Lyapunov governor into `sink`.
    ///
    /// Every worker emits one `scheduler` evidence entry each time it consults
    /// the governor, which is once per scheduling turn (between snapshots the
    /// cached suggestion still counts as a decision), plus the decision
    /// contract's audit entries. Only a runtime with
    /// [`enable_governor`](Self::enable_governor) consults the governor; without
    /// it nothing is recorded. Each entry locks the runtime state for its
    /// snapshot, so this is for audits and debugging, not steady production.
    ///
    /// Task-level budget and cancellation evidence is separate: attach a sink
    /// to a context with [`Cx::with_evidence_sink`](crate::cx::Cx::with_evidence_sink).
    #[must_use]
    pub fn scheduler_evidence_sink(
        mut self,
        sink: Arc<dyn crate::evidence_sink::EvidenceSink>,
    ) -> Self {
        self.scheduler_evidence_sink = Some(sink);
        self
    }

    /// Samples resource pressure every `interval` on a background thread, so
    /// child region admission and [`Cx::pressure`](crate::cx::Cx::pressure)
    /// react to load (asupersync-1ir2em). Off by default.
    ///
    /// The thread runs
    /// [`ResourceMonitor::process_current_state`](crate::runtime::resource_monitor::ResourceMonitor::process_current_state)
    /// on [`Runtime::resource_monitor`] every interval (at least 100 ms; 1 s
    /// suits most uses) and stops when the runtime is dropped. While it runs:
    /// - every task context the runtime builds carries the monitor's pressure,
    ///   so `Cx::pressure()` reports its headroom instead of `None`;
    /// - child region creation consults the sampled levels: under pressure
    ///   `Low` and `BestEffort` regions are refused, and at `Emergency`
    ///   `Normal` ones too. `Critical` and `High` regions are always admitted.
    ///
    /// The probes read host-wide signals (on Linux, the load average per
    /// online host CPU and every socket of the network namespace). In a
    /// container they describe the host, not the container's CPU quota, so a
    /// busy shared host can reach `Emergency` and refuse `Normal`-priority
    /// regions, the default for `open_child_region`. Sampling also makes a run
    /// depend on real load, so it does not combine with schedule capture for
    /// replay. On wasm32 it does nothing.
    #[must_use]
    pub fn resource_sampling(mut self, interval: Duration) -> Self {
        self.resource_sampling = Some(interval);
        self
    }

    /// Set the host services implementation for worker and deadline-monitor lifecycle.
    #[must_use]
    fn host_services(mut self, host_services: Arc<dyn RuntimeHostServices>) -> Self {
        self.host_services = host_services;
        self
    }

    /// Configures the runtime with browser host services for single-worker execution.
    #[must_use]
    pub fn browser_host_services(self, host_services: Arc<BrowserHostServices>) -> Self {
        self.host_services(host_services)
    }

    /// Set the runtime-wide admission ceiling for borrowed scoped CPU workers.
    ///
    /// Every [`Cx::scoped_cpu`](crate::cx::Cx::scoped_cpu) call backed by this
    /// runtime retains its own declared worker cap, while all such calls share
    /// this additional global ceiling. A zero limit is normalized to one.
    /// Without this explicit setting, the v0.4.3 per-scope behavior is retained.
    #[must_use]
    pub fn scoped_cpu_worker_limit(mut self, limit: usize) -> Self {
        self.scoped_cpu_worker_limit = Some(limit.max(1));
        self
    }

    /// Selects the spawn admission mode
    /// (br-asupersync-dx-core-api-v2-u1z5hn.1.3).
    ///
    /// `Direct` (default) creates tasks synchronously under the state lock.
    /// `Mailbox` routes spawns through the lock-free spawn mailbox; scheduler
    /// workers admit them at dispatch time. Direct stays the default until
    /// the spawn-throughput bench evidence justifies flipping it.
    #[must_use]
    pub fn spawn_admission(mut self, mode: crate::runtime::config::SpawnAdmissionMode) -> Self {
        self.config.spawn_admission = mode;
        self
    }

    /// Set an explicit worker-to-cohort mapping for locality-aware stealing.
    ///
    /// The mapping must contain exactly one cohort label per worker thread at
    /// build time. Validation happens during [`build`](Self::build), after
    /// worker-thread normalization has been applied.
    #[must_use]
    pub fn worker_cohorts(mut self, worker_to_cohort: impl Into<Vec<usize>>) -> Self {
        self.config.worker_cohort_map = Some(WorkerCohortMapping::new(worker_to_cohort.into()));
        self
    }

    /// Set the scheduler placement mode used with explicit worker cohorts.
    ///
    /// The mode is deterministic and only affects worker victim ordering. Use
    /// [`worker_cohorts`](Self::worker_cohorts) to provide the actual topology.
    #[must_use]
    pub fn scheduler_placement_mode(mut self, mode: SchedulerPlacementMode) -> Self {
        self.config.scheduler_placement_mode = mode;
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

    /// Set the observe-first adaptive ready-lane batch sizing profile.
    ///
    /// The default profile is disabled, preserving fixed `steal_batch_size`
    /// behavior. When enabled, workers can scale ready-lane batch drains from
    /// deterministic scheduler-local pressure signals while retaining a
    /// conservative fixed-profile fallback.
    #[must_use]
    pub fn adaptive_ready_batch(mut self, profile: AdaptiveReadyBatchConfig) -> Self {
        self.config.adaptive_ready_batch = profile;
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
    ///
    /// The default is `(0, 512)` on native targets: no thread runs until
    /// first use. `(0, 0)` configures no pool, so blocking work runs inline on
    /// the calling worker. An explicit maximum also bounds CPU-bound fan-out
    /// onto the pool, such as ATP's RaptorQ decode; the default's does not.
    #[must_use]
    pub fn blocking_threads(mut self, min: usize, max: usize) -> Self {
        self.config.blocking.min_threads = min;
        self.config.blocking.max_threads = max;
        self.blocking_sized = true;
        self
    }

    /// Configure cohort-aware affinity routing for the blocking pool.
    #[must_use]
    pub fn blocking_affinity_profile(
        mut self,
        profile: crate::runtime::config::BlockingPoolAffinityProfile,
    ) -> Self {
        self.config.blocking.affinity_profile = profile;
        self
    }

    /// Enable or disable parking for idle workers.
    #[must_use]
    pub fn enable_parking(mut self, enable: bool) -> Self {
        self.config.enable_parking = enable;
        self
    }

    /// Set the `block_on` root's backoff threshold; see [`RuntimeConfig::poll_budget`].
    #[must_use]
    pub fn poll_budget(mut self, budget: u32) -> Self {
        self.config.poll_budget = budget;
        self
    }

    /// Set explicit initial table capacities for runtime state.
    ///
    /// This overrides the default auto-scaling derived from `worker_threads`.
    #[must_use]
    pub fn capacity_hints(
        mut self,
        task_capacity: usize,
        region_capacity: usize,
        obligation_capacity: usize,
    ) -> Self {
        self.config.capacity_hints = Some(RuntimeCapacityHints::new(
            task_capacity,
            region_capacity,
            obligation_capacity,
        ));
        self
    }

    /// Derive runtime-state capacities from an expected concurrent task count.
    ///
    /// The task arena receives 50% headroom to absorb initial bursts without
    /// immediate growth reallocations; region and obligation tables scale from
    /// the same estimate with smaller multipliers.
    #[must_use]
    pub fn expected_concurrent_tasks(mut self, expected_tasks: usize) -> Self {
        self.config.capacity_hints = Some(RuntimeCapacityHints::from_expected_concurrent_tasks(
            expected_tasks,
        ));
        self
    }

    /// Clear any explicit capacity override and return to worker-scaled defaults.
    #[must_use]
    pub fn clear_capacity_hints(mut self) -> Self {
        self.config.capacity_hints = None;
        self
    }

    /// Select a storage-temperature policy (reported only, not yet applied to allocation).
    #[must_use]
    pub fn arena_temperature_policy(
        mut self,
        policy: crate::runtime::config::ArenaTemperaturePolicy,
    ) -> Self {
        self.config.arena_temperature_policy = policy;
        self
    }

    /// Select a trace and diagnostic retention profile.
    ///
    /// This changes only storage envelopes and retention limits. Scheduling
    /// semantics, cancellation behavior, and fairness remain unchanged.
    #[must_use]
    pub fn trace_storage_profile(
        mut self,
        profile: crate::runtime::config::TraceStorageProfile,
    ) -> Self {
        self.config.trace_storage_profile = profile;
        self
    }

    /// Set browser-style ready-lane burst handoff limit.
    ///
    /// When non-zero, scheduler workers can force a one-shot handoff after
    /// `limit` consecutive ready dispatches, allowing host task queues to run.
    /// This is primarily intended for browser event-loop adapters.
    /// `0` disables forced handoff (default).
    #[must_use]
    pub fn browser_ready_handoff_limit(mut self, limit: usize) -> Self {
        self.config.browser_ready_handoff_limit = limit;
        self
    }

    /// Set the browser worker offload policy contract.
    ///
    /// This config defines ownership, cancellation, and transfer semantics
    /// for CPU-heavy work that may be dispatched to browser workers.
    #[must_use]
    pub fn browser_worker_offload(
        mut self,
        config: crate::runtime::config::BrowserWorkerOffloadConfig,
    ) -> Self {
        self.config.browser_worker_offload = config;
        self
    }

    /// Enable or disable browser worker offload.
    #[must_use]
    pub fn browser_worker_offload_enabled(mut self, enabled: bool) -> Self {
        self.config.browser_worker_offload.enabled = enabled;
        self
    }

    /// Set worker offload cost/in-flight thresholds.
    #[must_use]
    pub fn browser_worker_offload_limits(
        mut self,
        min_task_cost: u32,
        max_in_flight: usize,
    ) -> Self {
        self.config.browser_worker_offload.min_task_cost = min_task_cost;
        self.config.browser_worker_offload.max_in_flight = max_in_flight;
        self
    }

    /// Set payload transfer strategy for browser worker offload.
    #[must_use]
    pub fn browser_worker_transfer_mode(
        mut self,
        mode: crate::runtime::config::WorkerTransferMode,
    ) -> Self {
        self.config.browser_worker_offload.transfer_mode = mode;
        self
    }

    /// Set cancellation propagation strategy for browser worker offload.
    #[must_use]
    pub fn browser_worker_cancellation_mode(
        mut self,
        mode: crate::runtime::config::WorkerCancellationMode,
    ) -> Self {
        self.config.browser_worker_offload.cancellation_mode = mode;
        self
    }

    /// Set the maximum consecutive cancel-lane dispatches before yielding.
    #[must_use]
    pub fn cancel_lane_max_streak(mut self, max_streak: usize) -> Self {
        self.config.cancel_lane_max_streak = max_streak;
        self
    }

    /// Set the spawn authorization key.
    ///
    /// Only `RuntimeState::create_task_with_auth` checks it: `Cx::spawn`, `Scope::spawn*` and
    /// runtime-handle spawns do not consult it (asupersync-s45073 H3). Unset, nothing is checked.
    #[must_use]
    pub fn with_spawn_authorization_key(mut self, key: crate::security::key::AuthKey) -> Self {
        self.config.security.spawn_authorization_key = Some(key);
        self
    }

    /// Disable spawn authorization (fail-open for testing).
    ///
    /// This explicitly disables spawn authorization even if it was previously enabled.
    #[must_use]
    pub fn disable_spawn_authorization(mut self) -> Self {
        self.config.security.spawn_authorization_key = None;
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

    /// Enable the cached draining-region fast path for governor snapshots.
    #[must_use]
    pub fn enable_read_biased_region_snapshot(mut self, enable: bool) -> Self {
        self.config.enable_read_biased_region_snapshot = enable;
        self
    }

    /// Enable or disable adaptive cancel-streak scheduling.
    ///
    /// Off by default. When enabled, workers run a deterministic discounted-UCB1
    /// policy that updates the base cancel streak limit across fixed-length epochs.
    #[must_use]
    pub fn enable_adaptive_cancel_streak(mut self, enable: bool) -> Self {
        self.config.enable_adaptive_cancel_streak = enable;
        self
    }

    /// Set the number of dispatches per adaptive cancel-streak epoch.
    ///
    /// Lower values react faster but add policy-update overhead.
    #[must_use]
    pub fn adaptive_cancel_streak_epoch_steps(mut self, steps: u32) -> Self {
        self.config.adaptive_cancel_streak_epoch_steps = steps;
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
    /// ```
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
        let env = crate::runtime::env_config::SystemEnvReader::new();
        crate::runtime::env_config::apply_env_overrides(&mut self.config, &env).map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        self.blocking_sized |= crate::runtime::env_config::EnvReader::read_env(
            &env,
            crate::runtime::env_config::ENV_BLOCKING_MAX_THREADS,
        )
        .is_some();
        Ok(self)
    }

    #[cfg(feature = "config-file")]
    #[allow(clippy::result_large_err)]
    fn from_runtime_config_layer(
        layer: &crate::runtime::env_config::RuntimeConfigLayer,
    ) -> Result<Self, Error> {
        let mut builder = Self::new();
        crate::runtime::env_config::apply_runtime_config_layer(&mut builder.config, layer)
            .map_err(|e| {
                Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
            })?;
        builder.blocking_sized = layer.blocking.max_threads.is_some();
        Ok(builder)
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
    #[allow(clippy::result_large_err)]
    pub fn from_toml(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let toml_config = crate::runtime::env_config::parse_toml_file(
            path.as_ref(),
            &crate::runtime::env_config::SystemEnvReader::new(),
        )
        .map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        Self::from_runtime_config_layer(&toml_config)
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
    #[allow(clippy::result_large_err)]
    pub fn from_toml_str(toml: &str) -> Result<Self, Error> {
        let toml_config = crate::runtime::env_config::parse_toml_str(toml).map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        Self::from_runtime_config_layer(&toml_config)
    }

    /// Load configuration from a versioned JSON file.
    ///
    /// JSON is additive: it deserializes into the same typed layer and uses
    /// the same application path as TOML. Environment variables and later
    /// programmatic settings therefore retain identical precedence.
    ///
    /// Requires the `config-file` feature.
    ///
    /// ```ignore
    /// let runtime = RuntimeBuilder::from_json("config/runtime.json")?
    ///     .with_env_overrides()?
    ///     .worker_threads(4)
    ///     .build()?;
    /// ```
    #[cfg(feature = "config-file")]
    #[allow(clippy::result_large_err)]
    pub fn from_json(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let json_config = crate::runtime::env_config::parse_json_file(
            path.as_ref(),
            &crate::runtime::env_config::SystemEnvReader::new(),
        )
        .map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        Self::from_runtime_config_layer(&json_config)
    }

    /// Load configuration from a versioned JSON string.
    ///
    /// The document shape is
    /// `{ "schema_version": 1, "config": { "scheduler": { ... } } }`.
    /// Missing `schema_version` migrates to version 1. Unsupported explicit
    /// versions fail closed. TOML and JSON share defaults and validation.
    ///
    /// Requires the `config-file` feature.
    #[cfg(feature = "config-file")]
    #[allow(clippy::result_large_err)]
    pub fn from_json_str(json: &str) -> Result<Self, Error> {
        let json_config = crate::runtime::env_config::parse_json_str(json).map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        Self::from_runtime_config_layer(&json_config)
    }

    /// Build a runtime from this configuration.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<Runtime, Error> {
        let Self {
            config,
            scoped_cpu_worker_limit,
            reactor,
            io_driver,
            io_uring_capability_policy,
            platform_reactor,
            timer_driver,
            entropy_source,
            host_services,
            current_thread,
            capture_schedules,
            scheduler_evidence_sink,
            blocking_sized,
            resource_sampling,
        } = self;
        #[cfg(target_arch = "wasm32")]
        let _ = (platform_reactor, io_uring_capability_policy);
        #[cfg(target_arch = "wasm32")]
        let _ = resource_sampling;
        // br-asupersync-1ajbtl: default builds construct the platform reactor
        // so socket I/O uses readiness wakeups instead of the 1ms timer-paced
        // fallback re-poll path. Explicit with_reactor / with_io_driver
        // injections take precedence, and enable_platform_reactor(false) keeps
        // the fallback regime available for burn-in/debugging.
        #[cfg(not(target_arch = "wasm32"))]
        let (reactor, terminal_io_reactor_snapshot) = if platform_reactor
            && reactor.is_none()
            && io_driver.is_none()
        {
            match crate::runtime::reactor::create_reactor_with_policy(io_uring_capability_policy) {
                Ok(reactor) => (Some(reactor), None),
                Err(err) => {
                    #[cfg(not(feature = "tracing-integration"))]
                    let _ = &err;
                    crate::tracing_compat::warn!(
                        event = "runtime_builder_platform_reactor_unavailable",
                        error = %err,
                        "platform reactor unavailable; falling back to timer-paced I/O polling"
                    );
                    (
                        None,
                        Some(IoReactorCapabilitySnapshot::reactor_unavailable(
                            io_uring_capability_policy,
                        )),
                    )
                }
            }
        } else {
            (reactor, None)
        };
        #[cfg(target_arch = "wasm32")]
        let reactor = reactor;
        #[cfg(target_arch = "wasm32")]
        let terminal_io_reactor_snapshot = None;
        // br-asupersync-8fuxnt / br-asupersync-sched-hot-path-perf-bt4y5f.2.2:
        // the Sharded shape is publicly constructible. The former build-time
        // ConfigError gate flipped once its stated preconditions landed:
        // replay-fingerprint identity across Unified|Sharded (11-task corpus
        // x workers={1,2}, order-insensitive canonicalization), ShardGuard
        // label coverage + loom lane, and dispatch-table-aware admission,
        // finalizer, completion, spawn-fallback, snapshot, liveness, and
        // deadline-monitor surfaces (E1.2 subsystems 1-3d + step 4). The
        // default shape remains `Unified`; the default flip is E1.3
        // (br-asupersync-sched-hot-path-perf-bt4y5f.2.3) bake evidence.
        let runtime = Runtime::with_config_and_platform_snapshot(
            config,
            reactor,
            io_driver,
            timer_driver,
            entropy_source,
            terminal_io_reactor_snapshot,
            host_services.as_ref(),
            current_thread,
            scheduler_evidence_sink,
        )?;
        if capture_schedules {
            let trace = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .trace_handle();
            runtime.inner.scheduler.enable_schedule_capture(trace);
        }
        // The default pool is sized for blocking I/O, so CPU-bound fan-out
        // must not read its cap as a core count (kpmoy5.1.15).
        if !blocking_sized && let Some(pool) = runtime.inner.blocking_pool.as_ref() {
            pool.handle().mark_default_sized();
        }
        if let Some(limit) = scoped_cpu_worker_limit {
            let gateway = {
                let guard = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.spawn_gateway()
            };
            if let Some(gateway) = gateway {
                gateway.set_scoped_cpu_worker_limit(limit);
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(interval) = resource_sampling {
            runtime.inner.start_resource_sampling(interval);
        }
        Ok(runtime)
    }

    /// Inspect the truthful browser execution ladder for the current host.
    ///
    /// This surfaces Rust-side lane negotiation diagnostics that stay aligned
    /// with the shared Browser Edition execution-ladder contract without
    /// claiming that a public direct browser-runtime constructor already
    /// exists on every target.
    #[must_use]
    pub fn inspect_browser_execution_ladder(&self) -> BrowserExecutionLadderDiagnostics {
        let _ = self;
        build_browser_execution_ladder_from_probe(None, detect_browser_execution_probe())
    }

    /// Inspect the truthful browser execution ladder for a supplied host snapshot.
    ///
    /// This is intended for deterministic fixtures, documentation examples,
    /// and contract tests that need to preserve Rust-side ladder semantics for
    /// host roles that are not directly executing the runtime.
    #[must_use]
    pub fn inspect_browser_execution_ladder_for_probe(
        &self,
        probe: BrowserExecutionProbe,
    ) -> BrowserExecutionLadderDiagnostics {
        let _ = self;
        build_browser_execution_ladder_from_probe(None, probe)
    }

    /// Inspect the truthful browser execution ladder while requesting a preferred lane.
    ///
    /// When the preferred lane is not truthful for the current host role, the
    /// returned diagnostics preserve the truthful selected lane and annotate
    /// the mismatch in the message and guidance.
    #[must_use]
    pub fn inspect_browser_execution_ladder_with_preferred_lane(
        &self,
        preferred_lane: BrowserExecutionLane,
    ) -> BrowserExecutionLadderDiagnostics {
        let _ = self;
        build_browser_execution_ladder_from_probe(
            Some(preferred_lane),
            detect_browser_execution_probe(),
        )
    }

    /// Inspect the truthful browser execution ladder for a supplied probe while
    /// also requesting a preferred lane.
    #[must_use]
    pub fn inspect_browser_execution_ladder_with_preferred_lane_for_probe(
        &self,
        probe: BrowserExecutionProbe,
        preferred_lane: BrowserExecutionLane,
    ) -> BrowserExecutionLadderDiagnostics {
        let _ = self;
        build_browser_execution_ladder_from_probe(Some(preferred_lane), probe)
    }

    /// Inspect bounded service-worker broker host-class diagnostics for the current host.
    ///
    /// This stays intentionally narrower than the JS helper surface: it only
    /// reports the truthful host-class facts that the Rust browser builder can
    /// inspect locally without widening the shipped direct-runtime contract.
    #[must_use]
    pub fn inspect_browser_service_worker_broker_support(
        &self,
    ) -> BrowserServiceWorkerBrokerSupportDiagnostics {
        let _ = self;
        browser_service_worker_broker_support_from_probe(detect_browser_execution_probe())
    }

    /// Inspect bounded service-worker broker host-class diagnostics for a supplied probe.
    #[must_use]
    pub fn inspect_browser_service_worker_broker_support_for_probe(
        &self,
        probe: BrowserExecutionProbe,
    ) -> BrowserServiceWorkerBrokerSupportDiagnostics {
        let _ = self;
        browser_service_worker_broker_support_from_probe(probe)
    }

    /// Inspect bounded shared-worker coordinator caller-side diagnostics for the current host.
    ///
    /// This reports whether the current caller host is a truthful place to
    /// start a bounded coordinator attach flow while preserving the fail-closed
    /// shared-worker direct-runtime truth.
    #[must_use]
    pub fn inspect_browser_shared_worker_coordinator_support(
        &self,
    ) -> BrowserSharedWorkerCoordinatorSupportDiagnostics {
        let _ = self;
        browser_shared_worker_coordinator_support_from_probe(detect_browser_execution_probe())
    }

    /// Inspect bounded shared-worker coordinator caller-side diagnostics for a supplied probe.
    #[must_use]
    pub fn inspect_browser_shared_worker_coordinator_support_for_probe(
        &self,
        probe: BrowserExecutionProbe,
    ) -> BrowserSharedWorkerCoordinatorSupportDiagnostics {
        let _ = self;
        browser_shared_worker_coordinator_support_from_probe(probe)
    }

    /// Provide a reactor for runtime I/O integration.
    ///
    /// When set, the runtime will attach an `IoDriver` backed by this reactor.
    #[must_use]
    pub fn with_reactor(mut self, reactor: Arc<dyn Reactor>) -> Self {
        self.reactor = Some(reactor);
        self
    }

    /// Provide an explicit I/O driver handle for runtime capability contexts.
    ///
    /// This overrides the default reactor-backed driver creation path and is
    /// useful for platform seam injection (for example, browser adapters).
    #[must_use]
    pub fn with_io_driver(mut self, driver: IoDriverHandle) -> Self {
        self.io_driver = Some(driver);
        self
    }

    /// Sets typed request and force-off policy for advanced io_uring capabilities.
    ///
    /// The policy is consulted only when this builder constructs its default
    /// platform reactor. Explicit [`with_reactor`](Self::with_reactor) or
    /// [`with_io_driver`](Self::with_io_driver) injection takes precedence.
    /// Unrequested capabilities are not probed. Forced-off capabilities are
    /// reported as `URING-FB-FORCED-OFF` without consulting the host.
    #[must_use]
    pub fn io_uring_capability_policy(mut self, policy: IoUringCapabilityPolicy) -> Self {
        self.io_uring_capability_policy = policy;
        self
    }

    /// Enable or disable automatic platform I/O reactor construction.
    ///
    /// Default builds construct the platform backend via
    /// [`create_reactor`](crate::runtime::reactor::create_reactor) — epoll
    /// (or io_uring with the `io-uring` feature) on Linux, kqueue on
    /// BSD/macOS, IOCP on Windows — and attach an `IoDriver` backed by it, so
    /// sockets get readiness wakeups instead of timer-paced re-polls
    /// (br-asupersync-1ajbtl). Passing `false` keeps the old fallback regime
    /// available for narrow debugging and platform bring-up. If the default
    /// reactor cannot be constructed, `build()` logs a warning and falls back
    /// to timer-paced polling rather than failing runtime construction.
    ///
    /// An explicit [`with_reactor`](Self::with_reactor) or
    /// [`with_io_driver`](Self::with_io_driver) takes precedence; this flag
    /// is then a no-op.
    #[must_use]
    pub fn enable_platform_reactor(mut self, enable: bool) -> Self {
        self.platform_reactor = enable;
        self
    }

    /// Provide an explicit timer driver handle for runtime capability contexts.
    ///
    /// When set, this driver is installed into runtime state before root-region
    /// initialization, so spawned tasks inherit it through `Cx`.
    #[must_use]
    pub fn with_timer_driver(mut self, driver: TimerDriverHandle) -> Self {
        self.timer_driver = Some(driver);
        self
    }

    /// Enable wall-clock time for this runtime (tokio-compatible convenience).
    ///
    /// [`Self::build`] already installs a wall-clock timer driver by default, so
    /// every standard runtime has one and spawned tasks inherit it through `Cx`.
    /// This method exists as an explicit, discoverable opt-in (mirroring
    /// `tokio::runtime::Builder::enable_time`) so consumers migrating from tokio
    /// — or hardening against the off-driver `Sleep` fallback
    /// (br-asupersync-runtime-cpu-overhaul-5vt09v.3.1 / .3.5) — have a named
    /// method to reach for instead of constructing a [`TimerDriverHandle`] by
    /// hand. It installs a wall-clock driver unless an explicit one was already
    /// provided via [`Self::with_timer_driver`], so the two compose in any
    /// order without clobbering a custom driver.
    #[must_use]
    pub fn enable_time(mut self) -> Self {
        if self.timer_driver.is_none() {
            #[cfg(target_arch = "wasm32")]
            {
                self.timer_driver = Some(TimerDriverHandle::with_browser_clock(Arc::new(
                    crate::time::BrowserMonotonicClock::host_sampled(),
                )));
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                self.timer_driver = Some(TimerDriverHandle::with_wall_clock());
            }
        }
        self
    }

    /// Provide an explicit entropy source for capability-based randomness.
    ///
    /// The runtime forks this source per task and wires it into task contexts,
    /// avoiding implicit ambient entropy.
    #[must_use]
    pub fn with_entropy_source(mut self, source: Arc<dyn EntropySource>) -> Self {
        self.entropy_source = Some(source);
        self
    }

    /// Selects the runtime backing-state shape (Unified vs Sharded).
    ///
    /// br-asupersync-8fuxnt /
    /// br-asupersync-sched-hot-path-perf-bt4y5f.2.2: `Sharded` is a
    /// supported opt-in. `build()` routes it to `ShardedState` +
    /// `ThreeLaneScheduler::new_with_sharded_state`, so workers dispatch
    /// against the Arc-shared shard-A task table while the unified state
    /// remains the region/obligation lifecycle owner. Semantics are
    /// proven identical across shapes by the replay-fingerprint corpus
    /// (11 tasks x workers={1,2}); the default remains `Unified` until
    /// the E1.3 bench/bake evidence lands
    /// (br-asupersync-sched-hot-path-perf-bt4y5f.2.3).
    #[must_use]
    pub fn with_sharded_state(mut self, enabled: bool) -> Self {
        self.config.runtime_state_shape = if enabled {
            crate::runtime::config::RuntimeStateShape::Sharded
        } else {
            crate::runtime::config::RuntimeStateShape::Unified
        };
        self
    }

    /// Preset: single-threaded runtime.
    ///
    /// One scheduler worker, driven from the thread that calls
    /// [`Runtime::block_on`] for the life of that call (GH#58): while
    /// `block_on` runs, every task spawned on the runtime — through
    /// [`RuntimeHandle::spawn`], [`Cx::spawn`](crate::cx::Cx::spawn) or
    /// [`Cx::spawn_local`](crate::cx::Cx::spawn_local) — is polled on the
    /// calling thread, and the root future is a registered task in the root
    /// region: `Cx::current()` inside it is a real task context with
    /// `spawn_local` authority, [`Runtime::is_quiescent`] is false until the
    /// root completes, and root-region cancellation reaches the root through
    /// its checkpoints. Between `block_on` calls the runtime's background
    /// thread runs the worker, so work spawned through a handle keeps
    /// making progress (unlike Tokio's `current_thread`, which only runs
    /// inside `block_on`). The root future itself is polled in place on the
    /// caller and may be `!Send` and non-`'static`.
    ///
    /// A nested `block_on` on the same runtime from the root future (or from
    /// its destructor) drives the same worker re-entrantly on the same
    /// thread, with its own registered root task and its own bounded
    /// post-root drain. A `block_on` that cannot borrow the worker — from
    /// inside a task poll, from the runtime's background thread, or from
    /// another OS thread while the worker is already on loan — polls its
    /// future directly on the caller as before GH#58: that root is not a
    /// registered task, and `spawn_local` from it is accepted only when the
    /// calling thread is itself a runtime worker.
    ///
    /// Caveat: the worker is parked for the duration of each poll of the
    /// root future, so nothing else on the runtime (spawned tasks, timers,
    /// reactor turns) progresses until that poll returns. A root that blocks
    /// its thread synchronously on a spawned task — a std channel `recv`, a
    /// thread join — deadlocks here, whereas a plain `worker_threads(1)`
    /// runtime keeps that task running on its own worker thread; await the
    /// task instead. After the root completes, `block_on` drains work that is
    /// already runnable under a bounded stop-predicate check budget, without
    /// waiting on timers or I/O. Remaining `Send` tasks resume on the background
    /// thread; local tasks resume when their owning thread drives the runtime.
    ///
    /// Configuring more than one worker after this preset keeps the plain
    /// worker-thread topology (`worker_threads(1)` alone does not enable the
    /// caller-driven mode; only this preset does).
    ///
    /// Suitable for testing, deterministic replay, and Phase 0 usage.
    ///
    /// ```ignore
    /// let rt = RuntimeBuilder::current_thread().build()?;
    /// rt.block_on(async { /* single-threaded execution */ });
    /// ```
    #[must_use]
    pub fn current_thread() -> Self {
        let mut builder = Self::new().worker_threads(1);
        builder.current_thread = true;
        builder
    }

    /// Preset: multi-threaded runtime with the deterministic default worker count.
    ///
    /// Equivalent to `RuntimeBuilder::new()`. Worker count defaults to the
    /// host-independent `RuntimeConfig::DEFAULT_WORKER_THREADS`.
    #[must_use]
    pub fn multi_thread() -> Self {
        Self::new()
    }

    /// Preset: high-throughput server.
    ///
    /// Uses 2x the deterministic default worker count and a larger steal batch
    /// size (32) to amortize scheduling overhead.
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
    /// Uses smaller steal batches (4) to reduce tail latency at the cost of
    /// throughput. Its `poll_budget` of 32 only makes a self-waking root back off sooner.
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
    ///
    /// A zero interval is normalized to the default [`MonitorConfig`] interval
    /// when the runtime is constructed, preventing an unbounded scan loop.
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

fn scheduler_adaptive_ready_batch_profile(
    config: AdaptiveReadyBatchConfig,
) -> Option<AdaptiveBatchSizingProfile> {
    config.enabled.then_some(AdaptiveBatchSizingProfile {
        enabled: true,
        min_batch_size: config.min_batch_size,
        max_batch_size: config.max_batch_size,
        scale_up_ready_depth: config.scale_up_ready_depth,
        scale_up_in_flight: config.scale_up_in_flight,
        scale_up_claim_failures: config.scale_up_claim_failures,
        cancel_debt_floor: config.cancel_debt_floor,
        cooldown_steps: config.cooldown_steps,
    })
}

/// Result of [`Runtime::drain_root_region`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootDrainOutcome {
    /// The root and its descendants closed after their tasks, obligations,
    /// and finalizers completed the close protocol.
    Quiescent,
    /// The bound elapsed before close completed. The borrowed drain call
    /// retains unfinished work; subsequent teardown is a separate operation.
    TimedOut,
}

/// Terminal observation from [`Runtime::shutdown_drained`].
///
/// A timed-out report retains the runtime and its unfinished work. It does
/// not certify that a non-cooperative task or pending finalizer was cleaned up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootDrainReport {
    /// Whether the root close protocol completed within the requested bound.
    pub outcome: RootDrainOutcome,
    /// Wall-clock time spent requesting and observing the drain.
    pub elapsed: Duration,
    /// Non-terminal tasks, including running asynchronous finalizers.
    pub live_tasks: usize,
    /// Obligations still awaiting commit or abort.
    pub pending_obligations: usize,
    /// Regions that have not completed their close protocol.
    pub live_regions: usize,
    /// Finalizers not yet dispatched; running finalizers count in `live_tasks`.
    pub queued_finalizers: usize,
    /// Reserved task admissions that have not been applied.
    pub pending_spawns: usize,
    /// Accepted obligation publications still awaiting application.
    pub has_pending_obligation_posts: bool,
}

#[cfg(test)]
mod root_drain_tests;

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
        let host_services = default_runtime_host_services();
        Self::with_config_and_platform(config, None, None, None, None, host_services.as_ref())
    }

    /// Construct a runtime from the given configuration and reactor.
    #[allow(clippy::result_large_err)]
    pub fn with_config_and_reactor(
        config: RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
    ) -> Result<Self, Error> {
        let host_services = default_runtime_host_services();
        Self::with_config_and_platform(config, reactor, None, None, None, host_services.as_ref())
    }

    /// Construct a runtime from configuration, explicit platform seams, and
    /// startup host services.
    #[allow(clippy::result_large_err)]
    fn with_config_and_platform(
        config: RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
        io_driver: Option<IoDriverHandle>,
        timer_driver: Option<TimerDriverHandle>,
        entropy_source: Option<Arc<dyn EntropySource>>,
        host_services: &dyn RuntimeHostServices,
    ) -> Result<Self, Error> {
        Self::with_config_and_platform_snapshot(
            config,
            reactor,
            io_driver,
            timer_driver,
            entropy_source,
            None,
            host_services,
            false,
            None,
        )
    }

    /// `current_thread` selects the caller-driven worker topology of
    /// [`RuntimeBuilder::current_thread`] (GH#58); it is honoured only for a
    /// single-worker configuration.
    #[allow(clippy::result_large_err)]
    fn with_config_and_platform_snapshot(
        mut config: RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
        io_driver: Option<IoDriverHandle>,
        timer_driver: Option<TimerDriverHandle>,
        entropy_source: Option<Arc<dyn EntropySource>>,
        terminal_io_reactor_snapshot: Option<IoReactorCapabilitySnapshot>,
        host_services: &dyn RuntimeHostServices,
        current_thread: bool,
        scheduler_evidence_sink: Option<Arc<dyn crate::evidence_sink::EvidenceSink>>,
    ) -> Result<Self, Error> {
        config.normalize();
        if let Some(monitor) = config.deadline_monitor.as_mut()
            && monitor.check_interval.is_zero()
        {
            monitor.check_interval = MonitorConfig::default().check_interval;
        }
        if let Some(mapping) = config.worker_cohort_map.as_ref() {
            mapping
                .validate_for_workers(config.worker_threads)
                .map_err(|message| {
                    Error::new(crate::error::ErrorKind::ConfigError)
                        .with_message(message.to_string())
                })?;
        }
        #[cfg(target_arch = "wasm32")]
        {
            if host_services.kind() != RuntimeHostServicesKind::BrowserMicrotask {
                let _ = (
                    reactor,
                    io_driver,
                    timer_driver,
                    entropy_source,
                    terminal_io_reactor_snapshot,
                    current_thread,
                );
                return Err(Error::new(crate::error::ErrorKind::ConfigError)
                    .with_message(unsupported_browser_bootstrap_message(host_services)));
            }
            config.worker_threads = 1;
            let (inner, workers) = RuntimeInner::new(
                config,
                reactor,
                io_driver,
                timer_driver,
                entropy_source,
                terminal_io_reactor_snapshot,
                host_services,
                scheduler_evidence_sink,
            );
            let inner = Arc::new(inner);
            if let Some(pump) = host_services.browser_pump() {
                let _ = inner.browser_pump.set(pump);
            }
            let _ = host_services.spawn_workers(&inner, workers).map_err(|e| {
                Error::new(crate::error::ErrorKind::Internal)
                    .with_message(format!("runtime init: {e}"))
            })?;
            Ok(Self { inner })
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (inner, workers) = RuntimeInner::new(
                config,
                reactor,
                io_driver,
                timer_driver,
                entropy_source,
                terminal_io_reactor_snapshot,
                host_services,
                scheduler_evidence_sink,
            );
            let inner = Arc::new(inner);
            if let Some(pump) = host_services.browser_pump() {
                let _ = inner.browser_pump.set(pump);
            }
            // GH#58: install the current-thread driver before the worker
            // thread exists, so that thread runs the loan protocol from its
            // first dispatch loop.
            if current_thread && inner.config.worker_threads == 1 {
                let gateway = inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .spawn_gateway();
                let _ = inner.current_thread_driver.set(Arc::new(
                    crate::runtime::current_thread::CurrentThreadDriver::new(
                        gateway,
                        inner.scheduler.local_store_key(),
                    ),
                ));
            }
            let worker_threads = host_services.spawn_workers(&inner, workers).map_err(|e| {
                Error::new(crate::error::ErrorKind::Internal)
                    .with_message(format!("runtime init: {e}"))
            })?;
            *lock_state(&inner.worker_threads) = worker_threads;
            Ok(Self { inner })
        }
    }

    /// Returns a handle that can spawn tasks from outside the runtime.
    #[must_use]
    pub fn handle(&self) -> RuntimeHandle {
        RuntimeHandle::strong(Arc::clone(&self.inner))
    }

    /// Returns the browser worker pump if this runtime was constructed with [`BrowserHostServices`].
    #[must_use]
    pub fn browser_pump(&self) -> Option<Arc<BrowserWorkerPump>> {
        self.inner.browser_pump.get().map(Arc::clone)
    }

    /// Spawns a local `!Send` future pinned to the runtime's single worker thread.
    ///
    /// # Panics
    ///
    /// Panics if the runtime is no longer available or admission is denied.
    pub fn spawn_local<F>(&self, future: F) -> LocalJoinHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        self.try_spawn_local(future)
            .expect("failed to spawn local task")
    }

    /// Tries to spawn a local `!Send` future pinned to the runtime's single worker thread.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] if the runtime has shut down,
    /// or other admission errors if rejected.
    pub fn try_spawn_local<F>(&self, future: F) -> Result<LocalJoinHandle<F::Output>, SpawnError>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        self.inner.spawn_local(future)
    }

    /// Run a future to completion on the current thread.
    ///
    /// While the future is being polled, a thread-local [`RuntimeHandle`] is
    /// available via [`Runtime::current_handle`]. This allows futures inside
    /// `block_on` to spawn tasks onto the real scheduler without having to
    /// thread the handle through every layer.
    ///
    /// How the future runs depends on the runtime flavor:
    ///
    /// - On a [`RuntimeBuilder::current_thread`] runtime the calling thread
    ///   borrows the runtime's single worker for the life of the call: the
    ///   root future is a registered task with `spawn_local` authority, every
    ///   task, timer and reactor turn of the runtime runs on the caller, and
    ///   nothing else progresses while the root itself is being polled. See
    ///   the preset's docs for the nesting rules and the synchronous-blocking
    ///   caveat. After the root completes, already-runnable work is drained
    ///   for a bounded number of dispatch turns before this returns.
    /// - Other flavors poll the future on the caller as a registered root task
    ///   with checked obligation authority and root cancellation. The record
    ///   retires after the future's destructor, including on panic. Spawned
    ///   tasks run on workers and may outlive this call. If root admission fails
    ///   (closed region or task limit), the compatibility fallback runs without
    ///   checked holder authority.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        let _guard = ScopedRuntimeHandle::new(self.handle());
        // #41: install an ambient Cx backed by this runtime's drivers (IO, timer, blocking pool,
        // observability). Without it `Cx::current()` is None inside the polled future, and public
        // async networking (e.g. `TcpListener::accept`) spins on `WouldBlock` instead of waiting
        // through the reactor. `_cx_guard` installs it for the poll and removes it on return, as
        // `block_on_with_cx` does for a caller that has a request-scoped Cx.
        let request_cx = self.request_cx_with_budget(Budget::INFINITE);
        let _cx_guard = crate::cx::Cx::set_current(Some(request_cx.clone()));
        // GH#58 / br-asupersync-94jh37: on a `RuntimeBuilder::current_thread()`
        // runtime the calling thread drives the single worker for the life
        // of this call and the root is a registered task (see
        // `crate::runtime::current_thread`). A nested call from the root
        // future drives the worker re-entrantly. The driver hands the future
        // back untouched when the worker cannot be borrowed (a call from
        // inside a task poll, a concurrent call from another thread while the
        // worker is on loan, the worker thread itself, shutdown), in which
        // case the caller-polled path below admits its own ownership record.
        let future = match self.inner.current_thread_driver.get() {
            Some(driver) => match driver.drive(&self.inner.scheduler, &request_cx, future) {
                Ok(output) => return output,
                Err(future) => future,
            },
            None => future,
        };
        // Admit synchronously: this fallback also runs when block_on is nested
        // inside a worker poll. Waiting for a spawned accounting task here could
        // require the very worker occupied by the caller. The actual future
        // remains pinned on this thread and need not be Send or 'static.
        let registration = CallerTaskRegistration::new(&self.inner, &request_cx).ok();
        let _caller_cx_guard = registration
            .as_ref()
            .map(|registration| crate::cx::Cx::set_current(Some(registration.cx.clone())));
        // Workers drive the tasks this root spawns, so the root may wait for them as a worker
        // would: a race whose winner panics joins its losers instead of polling them once.
        let _driven = (self.inner.current_thread_driver.get().is_none()
            && self.inner.config.worker_threads > 0)
            .then(crate::runtime::scheduler::three_lane::ScopedSchedulerDriven::enter);
        run_future_with_budget(
            future,
            self.inner.config.poll_budget,
            registration.as_ref().map(|registration| &registration.cx),
        )
    }

    /// Run a future to completion with an ambient [`Cx`](crate::cx::Cx).
    ///
    /// This is for execution paths that are polled directly by `block_on`
    /// rather than through the scheduler, but still need `Cx::current()` to
    /// reflect the active request/task context.
    #[allow(dead_code)]
    // Exposed to native integration tests (which drive real runtime scenarios
    // with a caller-supplied Cx, the companion to the public
    // `request_cx_with_budget`) under the opt-in test-internals feature, not the
    // stable public API. br-asupersync-ymj7j3.
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn block_on_with_cx<F: Future>(
        &self,
        request_cx: crate::cx::Cx,
        future: F,
    ) -> F::Output {
        let _runtime_guard = ScopedRuntimeHandle::new(self.handle());
        let _cx_guard = crate::cx::Cx::set_current(Some(request_cx));
        run_future_with_budget(future, self.inner.config.poll_budget, None)
    }

    /// Run a future to completion using the currently installed runtime handle
    /// while temporarily overriding the ambient [`Cx`](crate::cx::Cx).
    ///
    /// Unlike [`block_on_with_cx`](Self::block_on_with_cx), this preserves the
    /// existing thread-local runtime handle instead of replacing it. That is
    /// required for framework adapter paths that are invoked from within an
    /// already-running runtime task and must not sever deadline/cancellation
    /// propagation by switching to a detached helper runtime.
    #[allow(dead_code)]
    pub(crate) fn block_on_current_with_cx<F: Future>(
        request_cx: crate::cx::Cx,
        future: F,
    ) -> Option<F::Output> {
        let handle = Self::current_handle()?;
        let inner = handle.try_inner().ok()?;
        let _cx_guard = crate::cx::Cx::set_current(Some(request_cx));
        Some(run_future_with_budget(future, inner.config.poll_budget, None))
    }

    /// Create a request-scoped [`Cx`](crate::cx::Cx) backed by this runtime's
    /// drivers, tracing, and logical clock configuration.
    ///
    /// This is the ambient-free production entry point for an external
    /// consumer that must begin an operation with explicit runtime authority.
    /// The caller supplies the operation budget; the resulting context is
    /// bound to this runtime rather than manufacturing test-only authority.
    #[must_use]
    pub fn request_cx_with_budget(&self, budget: Budget) -> crate::cx::Cx {
        build_request_cx_from_inner(&self.inner, budget)
    }

    /// Create a request-scoped [`Cx`](crate::cx::Cx) from the currently
    /// installed runtime handle, if one exists.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn current_request_cx_with_budget(budget: Budget) -> Option<crate::cx::Cx> {
        let handle = Self::current_handle()?;
        let inner = handle.try_inner().ok()?;
        Some(build_request_cx_from_inner(&inner, budget))
    }

    /// Returns a handle to the current runtime, if called from within
    /// [`Runtime::block_on`] or a worker thread.
    ///
    /// Returns `None` when called outside of a runtime context.
    ///
    /// # Example
    ///
    /// ```ignore
    /// runtime.block_on(async {
    ///     let handle = Runtime::current_handle()
    ///         .expect("inside block_on");
    ///     handle.spawn(async { do_work().await });
    /// });
    /// ```
    ///
    /// Returns `None` when no runtime is installed on the current thread and
    /// during thread-local teardown, where the ambient handle is no longer
    /// accessible.
    #[must_use]
    pub fn current_handle() -> Option<RuntimeHandle> {
        CURRENT_RUNTIME_HANDLE
            .try_with(|cell| cell.borrow().clone())
            .unwrap_or(None)
    }

    /// Returns a reference to the runtime configuration.
    #[must_use]
    pub fn config(&self) -> &RuntimeConfig {
        &self.inner.config
    }

    /// Returns the immutable reactor selection and advanced-capability receipt.
    #[must_use]
    pub fn io_reactor_capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .io_reactor_capability_snapshot()
    }

    /// Returns the latest worker-local fairness certificate for each runtime worker.
    ///
    /// Entries are ordered by worker id. Busy workers publish snapshots at a
    /// bounded dispatch cadence and publish their final dispatch state before
    /// idle parking and shutdown.
    ///
    /// This is an aggregate of worker-local dispatch-step observations. It does
    /// not prove wall-clock latency, bounded task poll duration, global priority
    /// ordering, or cross-worker fairness.
    #[must_use]
    pub fn preemption_fairness_certificates(&self) -> Vec<PreemptionFairnessCertificate> {
        self.inner.scheduler.preemption_fairness_certificates()
    }

    /// Shut down the runtime, waiting at most `timeout` for teardown to finish.
    ///
    /// Ordinary `Runtime` drop from outside its workers performs a blocking
    /// teardown: it signals the scheduler, then joins every worker thread with
    /// no bound. A final owner dropped by an async worker transfers those joins
    /// and the retained runtime state to a teardown thread so that its own poll
    /// can finish. A future that blocks inside `poll` (in violation of the
    /// cooperative contract) keeps
    /// its worker from returning, so plain drop can wait forever ([#60]).
    ///
    /// This method is the bounded alternative. It synchronously closes every
    /// runtime-owned spawn gateway, then a background reaper waits for any
    /// already-started publication, coordinates scheduler and blocking-pool
    /// shutdown, and runs the normal teardown. The caller waits at most
    /// `timeout` for that teardown to complete.
    ///
    /// Returns `true` when teardown fully completed within the bound.
    /// Returns `false` when the bound elapsed first or the reaper thread could
    /// not be created. After a timeout, teardown continues on the background
    /// reaper thread, which retains a strong runtime reference while any cloned
    /// `Runtime` or strong [`RuntimeHandle`] remains. This ensures the final,
    /// potentially unbounded destructor also runs on the reaper rather than on
    /// whichever application thread releases the last external owner. If
    /// thread creation itself fails, new spawn admission remains closed and a
    /// bounded best effort signals the scheduler after any in-flight
    /// publication that finishes within the bound. Blocking-pool admission
    /// closes synchronously in every case, while scheduler shutdown follows
    /// the admitted publication boundary. The reaper performs the pool's
    /// potentially blocking condition-variable coordination. A blocking
    /// wrapper that has reached the scheduler but not yet submitted its closure
    /// may therefore observe pool shutdown; the blocking submission boundary
    /// handles that rejection through its deterministic fallback.
    /// The runtime is then intentionally retained until process exit instead of
    /// running an unbounded destructor on this caller. In either case,
    /// scheduler state, runtime state, timer/IO drivers, and the blocking pool
    /// remain alive for as long as a blocked worker can still touch them. Join
    /// handles for unfinished tasks observe cancellation exactly as with
    /// ordinary runtime drop.
    ///
    /// Cloned `Runtime`s and strong [`RuntimeHandle`]s keep the runtime alive as
    /// usual. The reaper waits until they are released; if that happens within
    /// the bound, this method can still return `true`. A successful `true`
    /// result therefore always means that final teardown actually completed,
    /// including the exit of every blocking-pool thread. Ordinary drop waits
    /// for those threads at most five seconds; this method waits for them up
    /// to its bound, so a blocking job that is still running yields `false`.
    ///
    /// On a multi-thread runtime the reaper does not wait for those owners to
    /// retire the tasks. Once the workers have exited, it drops the task
    /// futures as ordinary drop would. So a `block_on` caller on a clone that
    /// waits for a task sees that join end, and a task that holds a strong
    /// `RuntimeHandle` releases it. A current-thread runtime's tasks are retired
    /// by the final drop.
    ///
    /// [#60]: https://github.com/Dicklesworthstone/asupersync/issues/60
    #[must_use = "the return value reports whether teardown completed within the bound"]
    pub fn shutdown_timeout(self, timeout: Duration) -> bool {
        self.shutdown_timeout_with_spawner(timeout, |job| {
            std::thread::Builder::new()
                .name("asupersync-shutdown".into())
                .spawn(job)
                .map(crate::runtime::spawn_blocking::reap_spawned_thread)
                .is_ok()
        })
    }

    fn shutdown_timeout_with_spawner(
        self,
        timeout: Duration,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send + 'static>) -> bool,
    ) -> bool {
        let started = Instant::now();

        // Close every runtime-wired spawn gateway before handing teardown to
        // the reaper. A producer that already acquired a publication guard is
        // allowed to finish; the reaper waits for those guards before stopping
        // the scheduler. New RuntimeHandle and retained-Cx spawns fail closed.
        let spawn_publishers = self.inner.close_spawn_admission();
        // The pool is independently safe to close now: an admitted
        // Cx::spawn_blocking wrapper that reaches the pool after this boundary
        // uses the blocking bridge's deterministic inline fallback. Closing it
        // synchronously also prevents a previously issued BlockingPoolHandle
        // from admitting unrelated work while shutdown waits for a scheduler
        // publication to finish.
        if let Some(pool) = self.inner.blocking_pool.as_ref() {
            pool.close_admission();
        }
        if spawn_publishers
            .as_ref()
            .is_none_or(|publishers| publishers.strong_count() == 0)
        {
            // With no admitted scheduler publication in flight, stop scheduler
            // admission now too. Otherwise the reaper defers that signal until
            // the publication boundary completes.
            self.inner.begin_shutdown();
        }
        let fallback_publishers = spawn_publishers.clone();
        let shutdown_complete = Arc::clone(&self.inner.shutdown_completion);

        // The token owner is the sole teardown reaper. A concurrent or later
        // shutdown call must release its strong Runtime reference and wait on
        // the shared final-teardown latch; starting another retaining reaper
        // would leave both reapers waiting forever for Arc uniqueness.
        if spawn_publishers.is_none() {
            drop(self);
            return shutdown_complete.wait_with_budget(started, timeout);
        }

        // Keep one caller-owned reference outside the spawn closure. If the OS
        // refuses the thread, `Builder::spawn` drops its closure; moving `self`
        // directly into that closure would therefore run the unbounded runtime
        // destructor on this caller and defeat the method's central guarantee.
        let retained = Arc::new(Mutex::new(Some(self)));
        let reaper_retained = Arc::clone(&retained);
        let reaper_completion = Arc::clone(&shutdown_complete);
        let job = Box::new(move || {
            let Some(Runtime { mut inner }) = reaper_retained.lock().take() else {
                return;
            };
            RuntimeInner::wait_for_spawn_publishers(spawn_publishers.as_ref());
            inner.signal_shutdown();
            inner.retire_stopped_tasks_after_shutdown();
            loop {
                match Arc::try_unwrap(inner) {
                    Ok(mut inner) => {
                        // The final drop waits at most 5 s for blocking-pool
                        // threads and discards the result. Wait for all of them
                        // here, after that drop has retired the tasks their jobs
                        // may wait on, so that completion means teardown
                        // completed (br-asupersync-1pi7ne M1).
                        let blocking_pool = inner.blocking_pool.take();
                        drop(inner);
                        if let Some(pool) = blocking_pool {
                            let _ = pool.shutdown_and_wait(Duration::MAX);
                        }
                        reaper_completion.signal();
                        break;
                    }
                    Err(retained_inner) => {
                        inner = retained_inner;
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        });
        if !spawn(job) {
            // Thread creation failed, so make a bounded best effort to let an
            // in-flight publication finish before stopping the scheduler. If
            // it does not finish within the caller's bound, retain the still-
            // live runtime rather than stranding that publication or running
            // the unbounded destructor inline.
            while fallback_publishers
                .as_ref()
                .is_some_and(|publishers| publishers.strong_count() > 0)
                && started.elapsed() < timeout
            {
                std::thread::yield_now();
            }
            if fallback_publishers
                .as_ref()
                .is_none_or(|publishers| publishers.strong_count() == 0)
                && let Some(runtime) = retained.lock().as_ref()
            {
                runtime.inner.begin_shutdown();
            }
            std::mem::forget(retained);
            return false;
        }
        drop(retained);

        // The shared latch is signalled only after RuntimeInner::drop returns
        // normally, after worker joins and mailbox cleanup both completed.
        shutdown_complete.wait_with_budget(started, timeout)
    }

    /// Shut down the runtime without waiting for teardown to finish.
    ///
    /// Equivalent to [`shutdown_timeout`](Self::shutdown_timeout) with a zero
    /// bound: new spawn admission closes synchronously, teardown proceeds on a
    /// background thread, and this call returns immediately. See
    /// [`shutdown_timeout`](Self::shutdown_timeout) for the ownership rules
    /// that keep a still-blocked worker's state alive.
    pub fn shutdown_background(self) {
        let _ = self.shutdown_timeout(Duration::ZERO);
    }

    /// Returns true if the runtime is quiescent (no live tasks or I/O).
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.is_quiescent() {
            return false;
        }
        // E1.2 subsystem 3d (E1.1 row B02): a dispatch-table runtime's live
        // tasks reside in the external shard-A table; consult it under the
        // held state lock (canonical B → A, A released before B).
        self.inner
            .scheduler
            .dispatch_task_table()
            .is_none_or(|table| {
                table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .live_task_count()
                    == 0
            })
    }

    /// Requests cancellation of every task owned by the root region and waits
    /// up to `bound` for the region to reach quiescence.
    ///
    /// Until this method existed, nothing closed the root region: `block_on`
    /// returns as soon as its future completes and runtime teardown joins the
    /// workers and drops state, so root-region tasks that outlived the entry
    /// future were abort-by-dropped and their cleanup never ran. This is the
    /// request -> drain -> finalize protocol applied to the root: every live
    /// root-region task receives [`CancelKind::Shutdown`](crate::types::CancelKind::Shutdown),
    /// is scheduled on the cancel lane, and is given until `bound` to reach a
    /// terminal state. The entry macros call this after the entry future
    /// returns (`drain_ms = N` to change the bound, `0` to skip).
    ///
    /// Returns [`RootDrainOutcome::Quiescent`] only after the root region and
    /// its descendants have closed, including synchronous and asynchronous
    /// finalizers. Unrelated I/O registrations are outside this predicate.
    /// A timeout leaves unfinished work alive; ordinary runtime teardown still
    /// has its established abort-by-drop semantics. Use
    /// [`Self::shutdown_drained`] to receive counts and a terminal trace record.
    pub fn drain_root_region(&self, bound: Duration) -> RootDrainOutcome {
        self.shutdown_drained(bound).outcome
    }

    /// Requests a structured shutdown of the root and reports its actual drain.
    ///
    /// Every region-owned task receives shutdown cancellation, and the workers
    /// keep progressing children, obligations, and finalizers until the root
    /// closes or `bound` expires. Closing the root rejects new work admitted to
    /// that region. The report is also recorded as a `root_drain` user trace.
    ///
    /// This borrowed API keeps worker threads and runtime ownership alive. A
    /// timeout neither drops unfinished tasks nor claims they were cleaned up;
    /// the caller may release a blocked resource and drain again. Call
    /// [`Self::shutdown_timeout`] separately to request bounded thread teardown.
    /// Runtime `Drop` behavior is unchanged. The bound limits waiting, not a
    /// user future that blocks a worker inside one poll.
    #[must_use = "inspect the drain outcome before treating shutdown as complete"]
    pub fn shutdown_drained(&self, bound: Duration) -> RootDrainReport {
        let started = Instant::now();
        let reason = crate::types::CancelReason::new(crate::types::CancelKind::Shutdown);
        let effects = {
            let mut guard = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard
                .region(self.inner.root_region)
                .is_some()
                .then(|| guard.cancel_request(self.inner.root_region, &reason, None))
        };
        if let Some(effects) = effects {
            let (tasks_to_schedule, wakes) = effects.into_parts();
            for (task_id, priority) in tasks_to_schedule {
                self.inner.scheduler.inject_cancel(task_id, priority);
            }
            wakes.dispatch();
        }
        // An otherwise empty root can own only finalizers. Cancellation puts
        // it into Finalizing without publishing a task, so wake parked workers
        // to discover the finalizer queue before observing quiescence.
        self.inner.scheduler.wake_all();

        // GH#58: on a current-thread runtime this thread drives the worker
        // while it waits, so cancelled tasks — including `!Send` tasks whose
        // future lives on this thread — make progress here; the observation
        // loop below is the fallback when the worker cannot be borrowed.
        let driven = self.inner.current_thread_driver.get().and_then(|driver| {
            driver.drain_until(&self.inner.scheduler, started, bound, &mut || {
                self.work_is_drained()
            })
        });
        let drained_in_time = driven.unwrap_or_else(|| {
            loop {
                if self.work_is_drained() {
                    break true;
                }
                if started.elapsed() >= bound {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let mut report = self.root_drain_snapshot(started.elapsed());
        if !drained_in_time {
            report.outcome = RootDrainOutcome::TimedOut;
        }
        let status = match report.outcome {
            RootDrainOutcome::Quiescent => "drain_completed",
            RootDrainOutcome::TimedOut => "drain_timed_out",
        };
        let message = format!(
            "root_drain outcome={status} elapsed_ms={} live_tasks={} pending_obligations={} live_regions={} queued_finalizers={} pending_spawns={} pending_obligation_posts={}",
            report.elapsed.as_millis(),
            report.live_tasks,
            report.pending_obligations,
            report.live_regions,
            report.queued_finalizers,
            report.pending_spawns,
            report.has_pending_obligation_posts,
        );
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.record_trace_event(|seq| {
            crate::trace::TraceEvent::user_trace(seq, guard.now, message)
        });
        report
    }

    /// True after root close, including all finalizers, with no live task
    /// (embedded or dispatch-table resident), pending obligation, or reserved
    /// admission remaining.
    ///
    /// Spawns travel through the admission mailbox, so a task spawned just
    /// before `block_on` returned may not have a record yet; counting only
    /// live records would report an empty runtime while work is still
    /// queued for admission (observed under parallel test load).
    fn work_is_drained(&self) -> bool {
        self.root_drain_snapshot(Duration::ZERO).outcome == RootDrainOutcome::Quiescent
    }

    fn root_drain_snapshot(&self, elapsed: Duration) -> RootDrainReport {
        // Keep B held through the external task-table read (B -> A) so a
        // finalizer's publication/completion cannot disappear between counts.
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let external_live = self
            .inner
            .scheduler
            .dispatch_task_table()
            .map_or(0, |table| {
                table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .live_task_count()
            });
        let mut report = RootDrainReport {
            outcome: RootDrainOutcome::TimedOut,
            elapsed,
            live_tasks: guard.live_task_count().saturating_add(external_live),
            pending_obligations: guard.pending_obligation_count(),
            live_regions: guard.live_region_count(),
            queued_finalizers: 0,
            pending_spawns: self
                .inner
                .root_pending_spawns
                .as_ref()
                .map_or(0, |pending| pending.count() as usize),
            has_pending_obligation_posts: guard.has_pending_obligation_posts(),
        };
        for (_, region) in guard.regions_iter() {
            report.queued_finalizers = report
                .queued_finalizers
                .saturating_add(region.finalizer_count());
            if region.id != self.inner.root_region {
                report.pending_spawns = report
                    .pending_spawns
                    .saturating_add(region.pending_spawn_count() as usize);
            }
            report.has_pending_obligation_posts |= region.pending_obligation_post_count() != 0;
        }
        if guard.region(self.inner.root_region).is_none()
            && report.live_tasks == 0
            && report.pending_obligations == 0
            && report.live_regions == 0
            && report.queued_finalizers == 0
            && report.pending_spawns == 0
            && !report.has_pending_obligation_posts
        {
            report.outcome = RootDrainOutcome::Quiescent;
        }
        report
    }

    /// Snapshot of the runtime's bounded trace buffer.
    ///
    /// The production runtime records canonical lifecycle events (`Spawn`,
    /// `Complete`, cancellation, regions, timers and `UserTrace`) into a ring buffer.
    /// [`RuntimeBuilder::capture_schedules`] additionally enables `Schedule`,
    /// `Poll`, `Wake`, `Yield` and `CancelAck`. The buffer is
    /// sized by the [`RuntimeBuilder::trace_storage_profile`] (default 4096
    /// events; the oldest are overwritten). This returns a copy of what the
    /// buffer currently holds, in sequence order, so a production trace can
    /// be saved and fed to the lab analysis tools
    /// ([`crate::trace::normalize_trace_default`],
    /// [`crate::trace::RaceDetector::from_trace`],
    /// [`crate::trace::HappensBeforeGraph::from_trace`]) offline.
    ///
    /// The snapshot is a point-in-time copy; it does not stop recording and
    /// it does not include events that the ring has already overwritten.
    #[must_use]
    pub fn trace_snapshot(&self) -> Vec<crate::trace::TraceEvent> {
        let handle = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trace_handle();
        handle.snapshot()
    }

    /// Snapshot opt-in native scheduling capture and its bounded-storage metadata.
    ///
    /// `None` means [`RuntimeBuilder::capture_schedules`] was not enabled.
    /// The returned immutable receipt reports storage loss and can reject an
    /// incomplete projection through its `production_schedule` method. This
    /// snapshot does not stop live workers or certify their terminal outcomes.
    #[must_use]
    pub fn schedule_capture_snapshot(&self) -> Option<crate::trace::ScheduleCaptureSnapshot> {
        self.inner.scheduler.schedule_capture_snapshot()
    }

    /// Build a [`TaskInspector`] bound to this runtime's live task state.
    ///
    /// Every inspector query locks the runtime state (and, on the sharded
    /// state shape, the shard-A task table and shard-C obligation table in the
    /// canonical B -> A -> C order) for exactly the duration of that query,
    /// copies plain data out, and releases the locks before returning. It
    /// never runs user code or awaits under those locks, so it is safe to call
    /// from any thread, including from a task running on this runtime. The
    /// returned inspector holds a strong reference to the runtime state and
    /// stays valid until it is dropped; queries after runtime teardown observe
    /// an empty task table.
    ///
    /// This is the production counterpart of
    /// [`TaskInspector::new`](crate::observability::task_inspector::TaskInspector::new),
    /// which inspects a detached [`RuntimeState`] that nothing else mutates.
    #[must_use]
    pub fn task_inspector(&self, config: TaskInspectorConfig) -> TaskInspector {
        TaskInspector::from_source(
            RuntimeStateSource::Shared {
                state: Arc::clone(&self.inner.state),
                tasks: self.inner.scheduler.dispatch_task_table(),
                obligations: self
                    .inner
                    .sharded_state
                    .as_ref()
                    .map(|shards| Arc::clone(&shards.obligations)),
            },
            None,
            config,
        )
    }

    /// Build a [`Diagnostics`] engine bound to this runtime's live state.
    ///
    /// `explain_task_blocked`, `explain_region_open`, `explain_cancellation`,
    /// `find_leaked_obligations`, and the structural/deadlock analyses read the
    /// live task, region, and obligation tables under the same per-query lock
    /// discipline as [`Runtime::task_inspector`].
    #[must_use]
    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics::from_source(RuntimeStateSource::Shared {
            state: Arc::clone(&self.inner.state),
            tasks: self.inner.scheduler.dispatch_task_table(),
            obligations: self
                .inner
                .sharded_state
                .as_ref()
                .map(|shards| Arc::clone(&shards.obligations)),
        })
    }

    /// Returns the current number of regions in the draining/finalizing cleanup path.
    ///
    /// This is a runtime-local observability signal for cleanup debt. It is not
    /// an admission oracle by itself; callers should compare it with the
    /// configured region-capacity envelope for the runtime.
    #[must_use]
    pub fn draining_region_count(&self) -> usize {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.draining_region_count_for_snapshot()
    }

    /// Returns this runtime's resource monitor for runtime-local pressure snapshots.
    #[must_use]
    pub fn resource_monitor(&self) -> Arc<ResourceMonitor> {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.resource_monitor()
    }

    /// Returns the configured hot trace-ring capacity for this runtime.
    #[must_use]
    pub fn trace_buffer_capacity(&self) -> usize {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.trace_buffer_capacity()
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
        let _spawn_guard = self.inner.spawn_liveness_guard().ok()?;
        self.inner.blocking_pool.as_ref().map(|pool| pool.spawn(f))
    }

    /// Spawns a blocking task with an explicit preferred cohort hint.
    ///
    /// Returns `None` if the blocking pool is not configured (max_threads = 0).
    pub fn spawn_blocking_on_cohort<F>(
        &self,
        cohort: usize,
        f: F,
    ) -> Option<crate::runtime::blocking_pool::BlockingTaskHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        let _spawn_guard = self.inner.spawn_liveness_guard().ok()?;
        self.inner
            .blocking_pool
            .as_ref()
            .map(|pool| pool.spawn_on_cohort(cohort, f))
    }

    /// Spawn blocking work owned by this runtime's root region.
    ///
    /// Unlike [`Self::spawn_blocking`], the returned task participates in
    /// [`Self::shutdown_drained`]: the root stays live until the closure and its
    /// captures retire. The closure receives its actual task `Cx`, and a
    /// started closure's exact result survives cancellation. This requires a
    /// blocking pool and never executes the closure inline.
    ///
    /// Cancellation cannot interrupt a running synchronous closure. A bounded
    /// root drain reports timeout and retains unfinished work until it returns.
    pub fn spawn_blocking_drained<F, T>(
        &self,
        f: F,
    ) -> Result<crate::runtime::spawn_blocking::DrainedBlockingHandle<T>, SpawnError>
    where
        F: FnOnce(crate::cx::Cx) -> T + Send + 'static,
        T: Send + 'static,
    {
        self.request_cx_with_budget(Budget::INFINITE).spawn_blocking_drained(f)
    }

    /// Returns a handle to the blocking pool, if configured.
    #[must_use]
    pub fn blocking_handle(&self) -> Option<crate::runtime::blocking_pool::BlockingPoolHandle> {
        self.inner.blocking_handle()
    }

    /// Returns the approximate number of ready tasks in the shared global
    /// scheduler queue.
    ///
    /// This is an observability hint, not an admission oracle: worker-local
    /// ready queues and in-flight worker prefetch buffers are intentionally not
    /// included.
    #[must_use]
    pub fn scheduler_global_ready_depth(&self) -> usize {
        self.inner.scheduler.global_injector().ready_count()
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
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
enum RuntimeHandleRef {
    Strong(Arc<RuntimeInner>),
    Weak(Weak<RuntimeInner>),
}

/// Handle for spawning tasks onto a runtime from outside async context.
///
/// Cheap to clone (shared handle backing). Use [`Runtime::handle`] to obtain one.
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
    inner: RuntimeHandleRef,
}

impl RuntimeHandle {
    fn strong(inner: Arc<RuntimeInner>) -> Self {
        Self {
            inner: RuntimeHandleRef::Strong(inner),
        }
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn weak(inner: &Arc<RuntimeInner>) -> Self {
        Self {
            inner: RuntimeHandleRef::Weak(Arc::downgrade(inner)),
        }
    }

    /// Build a [`TaskInspector`] bound to the runtime behind this handle.
    ///
    /// Returns `None` when this is a weak handle whose runtime has already
    /// been torn down. See [`Runtime::task_inspector`] for the per-query lock
    /// discipline; the same rules apply here.
    #[must_use]
    pub fn task_inspector(&self, config: TaskInspectorConfig) -> Option<TaskInspector> {
        let inner = self.try_inner().ok()?;
        Some(TaskInspector::from_source(
            RuntimeStateSource::Shared {
                state: Arc::clone(&inner.state),
                tasks: inner.scheduler.dispatch_task_table(),
                obligations: inner
                    .sharded_state
                    .as_ref()
                    .map(|shards| Arc::clone(&shards.obligations)),
            },
            None,
            config,
        ))
    }

    /// Snapshot of the trace buffer of the runtime behind this handle.
    ///
    /// Returns `None` when this is a weak handle whose runtime has already
    /// been torn down. See [`Runtime::trace_snapshot`].
    #[must_use]
    pub fn trace_snapshot(&self) -> Option<Vec<crate::trace::TraceEvent>> {
        let inner = self.try_inner().ok()?;
        let handle = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trace_handle();
        Some(handle.snapshot())
    }

    /// Build a [`Diagnostics`] engine bound to the runtime behind this handle.
    ///
    /// Returns `None` when this is a weak handle whose runtime has already
    /// been torn down. See [`Runtime::diagnostics`].
    #[must_use]
    pub fn diagnostics(&self) -> Option<Diagnostics> {
        let inner = self.try_inner().ok()?;
        Some(Diagnostics::from_source(RuntimeStateSource::Shared {
            state: Arc::clone(&inner.state),
            tasks: inner.scheduler.dispatch_task_table(),
            obligations: inner
                .sharded_state
                .as_ref()
                .map(|shards| Arc::clone(&shards.obligations)),
        }))
    }

    /// Register a real finalizer on an open native region for lifecycle tests.
    ///
    /// This uses the owning runtime's ordinary finalizer admission and returns
    /// false if the runtime or region is gone, or the region has begun closing.
    /// It does not synthesize a cleanup result or bypass region ownership.
    #[cfg(any(test, feature = "test-internals"))]
    #[doc(hidden)]
    pub fn register_sync_finalizer_for_testing<F>(
        &self,
        region_id: crate::types::RegionId,
        f: F,
    ) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        let Ok(inner) = self.try_inner() else {
            return false;
        };
        inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register_sync_finalizer(region_id, f)
    }

    fn try_inner(&self) -> Result<Arc<RuntimeInner>, SpawnError> {
        match &self.inner {
            RuntimeHandleRef::Strong(inner) => Ok(Arc::clone(inner)),
            RuntimeHandleRef::Weak(inner) => inner.upgrade().ok_or(SpawnError::RuntimeUnavailable),
        }
    }

    /// Returns the immutable reactor receipt while the runtime remains alive.
    #[must_use]
    pub fn io_reactor_capability_snapshot(&self) -> Option<IoReactorCapabilitySnapshot> {
        let inner = self.try_inner().ok()?;
        Some(
            inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .io_reactor_capability_snapshot(),
        )
    }

    /// Returns the latest worker-local fairness certificate for each runtime worker.
    ///
    /// Entries are ordered by worker id. The optional result matches this
    /// handle's existing strong-or-weak lifetime model: public strong handles
    /// keep the runtime alive, while an expired runtime-internal weak handle
    /// returns `None`.
    ///
    /// This is an aggregate of worker-local dispatch-step observations. It does
    /// not prove wall-clock latency, bounded task poll duration, global priority
    /// ordering, or cross-worker fairness.
    #[must_use]
    pub fn preemption_fairness_certificates(&self) -> Option<Vec<PreemptionFairnessCertificate>> {
        let inner = self.try_inner().ok()?;
        Some(inner.scheduler.preemption_fairness_certificates())
    }

    /// Spawn a task into the runtime's root region, from outside async context.
    ///
    /// Called inside a task, it escapes that task's region (prefer `Cx::spawn` there):
    /// only root drain or shutdown cancels it. Panics if the runtime is unavailable or
    /// admission is rejected; [`RuntimeHandle::try_spawn`] returns those errors instead.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.try_spawn(future)
            .expect("failed to create runtime task")
    }

    /// Like [`RuntimeHandle::spawn`] (root region, cancelled only by root drain or
    /// shutdown), but returns runtime-availability or admission errors instead of panicking.
    pub fn try_spawn<F>(&self, future: F) -> Result<JoinHandle<F::Output>, SpawnError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.try_inner()?.spawn(future)
    }

    /// Requests the same structured root close as [`Runtime::shutdown_drained`].
    ///
    /// The call retains the runtime while observing cleanup and leaves worker
    /// teardown to its owner. Call from outside the root's live tasks so the
    /// caller itself is not part of the work being awaited.
    ///
    /// # Errors
    /// Returns [`SpawnError::RuntimeUnavailable`] when a weak handle's runtime
    /// has already been released.
    pub fn shutdown_drained(&self, bound: Duration) -> Result<RootDrainReport, SpawnError> {
        let runtime = Runtime {
            inner: self.try_inner()?,
        };
        Ok(runtime.shutdown_drained(bound))
    }

    /// Returns the browser worker pump if the underlying runtime was constructed with [`BrowserHostServices`].
    #[must_use]
    pub fn browser_pump(&self) -> Option<Arc<BrowserWorkerPump>> {
        self.try_inner()
            .ok()
            .and_then(|inner| inner.browser_pump.get().map(Arc::clone))
    }

    /// Spawns a local `!Send` future pinned to the runtime's single worker thread, into
    /// the root region: like [`RuntimeHandle::spawn`], it outlives the caller's region.
    ///
    /// # Panics
    /// Panics if the runtime is no longer available or admission is denied.
    pub fn spawn_local<F>(&self, future: F) -> LocalJoinHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        self.try_spawn_local(future)
            .expect("failed to spawn local task")
    }

    /// Tries to spawn a local `!Send` root-region task; see [`RuntimeHandle::spawn_local`].
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] if the runtime has shut down,
    /// or other admission errors if rejected.
    pub fn try_spawn_local<F>(&self, future: F) -> Result<LocalJoinHandle<F::Output>, SpawnError>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        self.try_inner()?.spawn_local(future)
    }

/// Spawn a task with a [`Cx`](crate::cx::Cx) from outside async context.
    ///
    /// Creates a Cx in the runtime's root region (never the caller's region) and
    /// passes it to the factory closure. The Cx observes shutdown cancellation when
    /// [`Runtime::shutdown_drained`] or [`Runtime::drain_root_region`] runs.
    /// Dropping a runtime or calling `shutdown_timeout` alone does not run
    /// cooperative cancellation cleanup.
    ///
    /// Panics if the runtime is no longer available or if the root region
    /// rejects admission. Use [`RuntimeHandle::try_spawn_with_cx`] to handle
    /// those failures explicitly.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = runtime.handle();
    /// handle.spawn_with_cx(|cx| async move {
    ///     while !cx.is_cancel_requested() {
    ///         // do work
    ///     }
    /// });
    /// ```
    pub fn spawn_with_cx<F, Fut>(&self, f: F)
    where
        F: FnOnce(crate::cx::Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.try_spawn_with_cx(f)
            .expect("failed to spawn task with cx");
    }

/// Spawn a task with a [`Cx`](crate::cx::Cx) from outside async context,
    /// returning runtime-availability or admission errors instead of panicking.
    ///
    /// Creates a Cx in the runtime's root region (never the caller's region) and
    /// passes it to the factory closure. The Cx observes shutdown cancellation when
    /// [`Runtime::shutdown_drained`] or [`Runtime::drain_root_region`] runs.
    /// Dropping a runtime or calling `shutdown_timeout` alone does not run
    /// cooperative cancellation cleanup.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = runtime.handle();
    /// handle.try_spawn_with_cx(|cx| async move {
    ///     while !cx.is_cancel_requested() {
    ///         // do work
    ///     }
    /// })?;
    /// ```
    pub fn try_spawn_with_cx<F, Fut>(&self, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce(crate::cx::Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.try_inner()?.spawn_with_cx(f)
    }

    /// Spawns a blocking task on the blocking pool.
    ///
    /// Returns `None` if the blocking pool is not configured or if this handle
    /// is a stale weak handle whose runtime has already been dropped.
    pub fn spawn_blocking<F>(
        &self,
        f: F,
    ) -> Option<crate::runtime::blocking_pool::BlockingTaskHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        let inner = self.try_inner().ok()?;
        let _spawn_guard = inner.spawn_liveness_guard().ok()?;
        inner.blocking_pool.as_ref().map(|pool| pool.spawn(f))
    }

    /// Spawns a blocking task with an explicit preferred cohort hint.
    ///
    /// Returns `None` if the blocking pool is not configured or if this handle
    /// is stale.
    pub fn spawn_blocking_on_cohort<F>(
        &self,
        cohort: usize,
        f: F,
    ) -> Option<crate::runtime::blocking_pool::BlockingTaskHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        let inner = self.try_inner().ok()?;
        let _spawn_guard = inner.spawn_liveness_guard().ok()?;
        inner
            .blocking_pool
            .as_ref()
            .map(|pool| pool.spawn_on_cohort(cohort, f))
    }

    /// Returns a handle to the blocking pool, if configured and the runtime is
    /// still alive.
    #[must_use]
    pub fn blocking_handle(&self) -> Option<crate::runtime::blocking_pool::BlockingPoolHandle> {
        self.try_inner().ok()?.blocking_handle()
    }

    /// Root-region-owned counterpart of [`Runtime::spawn_blocking_drained`].
    /// A stale handle or missing blocking pool returns `RuntimeUnavailable`.
    /// The work remains part of root drain even when this handle is dropped.
    pub fn spawn_blocking_drained<F, T>(
        &self,
        f: F,
    ) -> Result<crate::runtime::spawn_blocking::DrainedBlockingHandle<T>, SpawnError>
    where
        F: FnOnce(crate::cx::Cx) -> T + Send + 'static,
        T: Send + 'static,
    {
        self.try_request_cx_with_budget(Budget::INFINITE)?.spawn_blocking_drained(f)
    }
}

/// A join handle returned by [`RuntimeHandle::spawn`].
pub struct JoinHandle<T> {
    state: Arc<Mutex<JoinState<T>>>,
    completed: bool,
}

impl<T> JoinHandle<T> {
    fn new(state: Arc<Mutex<JoinState<T>>>) -> Self {
        Self {
            state,
            completed: false,
        }
    }

    /// Returns true if the task has completed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        if self.completed {
            return true;
        }
        let guard = lock_state(&self.state);
        guard.is_terminal() || Arc::strong_count(&self.state) == 1
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(
            !this.completed,
            "runtime::JoinHandle polled after completion"
        );
        let mut guard = lock_state(&this.state);
        match guard.result.take() {
            None => {
                if guard.cancel_reason.is_some() || Arc::strong_count(&this.state) == 1 {
                    // The executor side was dropped without producing a result or panic payload
                    // (e.g. the runtime was shut down and tasks were force-cancelled).
                    this.completed = true;
                    drop(guard);
                    panic!("task was dropped or cancelled before completion"); // ubs:ignore - runtime shutdown panic
                }

                if !guard
                    .waker
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()))
                {
                    guard.waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Some(Ok(output)) => {
                this.completed = true;
                Poll::Ready(output)
            }
            Some(Err(payload)) => {
                this.completed = true;
                drop(guard);
                std::panic::resume_unwind(payload)
            }
        }
    }
}

/// A join handle returned by [`Runtime::spawn_local`] or [`RuntimeHandle::spawn_local`].
///
/// Supports caller-supplied `!Send` futures executed on the runtime's single worker thread.
/// Resolves to `Result<T, crate::runtime::JoinError>` where cancellation or shutdown drop
/// is reported as an error rather than panicking, while task panics are resumed via `resume_unwind`.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct LocalJoinHandle<T> {
    state: Arc<Mutex<JoinState<T>>>,
    completed: bool,
}

impl<T> LocalJoinHandle<T> {
    fn new(state: Arc<Mutex<JoinState<T>>>) -> Self {
        Self {
            state,
            completed: false,
        }
    }

    /// Returns `true` if the local task has completed or terminated.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        if self.completed {
            return true;
        }
        let guard = lock_state(&self.state);
        guard.is_terminal() || Arc::strong_count(&self.state) == 1
    }
}

impl<T> Future for LocalJoinHandle<T> {
    type Output = Result<T, crate::runtime::JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(crate::runtime::JoinError::PolledAfterCompletion));
        }
        let mut guard = lock_state(&this.state);
        if let Some(reason) = guard.cancel_reason.take() {
            this.completed = true;
            return Poll::Ready(Err(crate::runtime::JoinError::Cancelled(reason)));
        }
        match guard.result.take() {
            None => {
                if Arc::strong_count(&this.state) == 1 {
                    this.completed = true;
                    return Poll::Ready(Err(crate::runtime::JoinError::Cancelled(
                        crate::types::CancelReason::shutdown(),
                    )));
                }

                if !guard
                    .waker
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()))
                {
                    guard.waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Some(Ok(output)) => {
                this.completed = true;
                Poll::Ready(Ok(output))
            }
            Some(Err(payload)) => {
                this.completed = true;
                drop(guard);
                std::panic::resume_unwind(payload)
            }
        }
    }
}

impl<T> std::fmt::Debug for LocalJoinHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalJoinHandle")
            .field("completed", &self.completed)
            .finish()
    }
}

#[pin_project::pin_project]
struct CatchUnwind<F> {
    #[pin]
    inner: F,
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.inner.as_mut().poll(cx)
        }));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

/// The outcome a handle-spawned task records for the runtime. A caught panic
/// is recorded Panicked, as for `Cx::spawn`, while the payload itself goes to
/// the `JoinHandle`, which re-raises it (asupersync-6hewgp).
fn handle_spawn_outcome<T>(result: &std::thread::Result<T>) -> crate::types::Outcome<(), ()> {
    match result {
        Ok(_) => crate::types::Outcome::Ok(()),
        Err(payload) => crate::types::Outcome::Panicked(crate::types::PanicPayload::new(
            crate::cx::scope::payload_to_string(payload),
        )),
    }
}

struct RuntimeShutdownCompletion {
    completed_at: Mutex<Option<Instant>>,
    condvar: Condvar,
}

impl RuntimeShutdownCompletion {
    fn new() -> Self {
        Self {
            completed_at: Mutex::new(None),
            condvar: Condvar::new(),
        }
    }

    fn signal(&self) {
        let mut completed_at = self.completed_at.lock();
        if completed_at.is_none() {
            *completed_at = Some(Instant::now());
        }
        self.condvar.notify_all();
    }

    #[cfg(test)]
    fn wait_timeout(&self, timeout: Duration) -> bool {
        let started = Instant::now();
        self.wait_with_budget(started, timeout)
    }

    fn wait_with_budget(&self, started: Instant, timeout: Duration) -> bool {
        let mut completed_at = self.completed_at.lock();
        loop {
            if let Some(completed_at) = *completed_at {
                return completed_at.saturating_duration_since(started) <= timeout;
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return false;
            }
            if self
                .condvar
                .wait_for(&mut completed_at, remaining)
                .timed_out()
            {
                return completed_at.as_ref().is_some_and(|completed_at| {
                    completed_at.saturating_duration_since(started) <= timeout
                });
            }
        }
    }
}

struct RuntimeInner {
    config: RuntimeConfig,
    state: Arc<crate::sync::ContendedMutex<RuntimeState>>,
    /// Sharded backing whose Arc-shared shard A the scheduler dispatches
    /// against when `RuntimeStateShape::Sharded` is selected (E1.2
    /// subsystem 3d). `None` in the default unified shape. The B/C shards
    /// stay dormant until task minting moves off the unified lifecycle
    /// owner; holding the Arc here keeps shard identity stable for
    /// diagnostics and the replay-fingerprint proof lanes.
    sharded_state: Option<Arc<crate::runtime::ShardedState>>,
    scheduler: ThreeLaneScheduler,
    worker_threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    root_region: crate::types::RegionId,
    /// Lock-free spawn intake (Some only in `SpawnAdmissionMode::Mailbox`).
    spawn_mailbox: Option<Arc<crate::runtime::spawn_mailbox::SpawnMailbox>>,
    /// The mailbox every worker of this runtime owns its thread-local `!Send`
    /// lane under, kept regardless of the admission mode so `spawn_local` can
    /// tell whether the calling thread's lane is one this runtime drains.
    local_lane_mailbox: Arc<crate::runtime::spawn_mailbox::SpawnMailbox>,
    /// Root-region pending-spawn counter handle for mailbox-mode producers.
    root_pending_spawns: Option<Arc<crate::record::region::PendingSpawnCounter>>,
    /// Timer handle for producer-side enqueue timestamps in mailbox mode.
    spawn_clock: Option<TimerDriverHandle>,
    /// Keeps the producer-side spawn gateway live exactly as long as the
    /// runtime inner remains live. Retained `Cx` values hold only weak tokens.
    spawn_liveness: Mutex<Option<Arc<()>>>,
    /// Blocking pool for synchronous operations.
    blocking_pool: Option<crate::runtime::blocking_pool::BlockingPool>,
    /// Shutdown sender for the deadline monitor thread.
    deadline_monitor_shutdown: Option<std::sync::mpsc::Sender<()>>,
    /// Deadline monitor background thread handle.
    deadline_monitor_thread: Option<std::thread::JoinHandle<()>>,
    /// Resource pressure sampler started by
    /// [`RuntimeBuilder::resource_sampling`]; stopped in `Drop`.
    #[cfg(not(target_arch = "wasm32"))]
    resource_sampler: std::sync::OnceLock<crate::runtime::resource_monitor::ResourceSampler>,
    /// Per-runtime monotonic counter for request-scoped task IDs.
    ///
    /// br-asupersync-3lk5n2: every request-scoped Cx built via
    /// [`build_request_cx_from_inner`] used to mint its TaskId via
    /// `TaskId::new_ephemeral()`, which draws from a process-global
    /// `EPHEMERAL_TASK_COUNTER`. That counter is non-replayable
    /// across processes and is shared by every runtime instance in
    /// the same process. Two replays of the same lab scenario, or
    /// two ostensibly-isolated lab runtimes in the same process,
    /// produced different request-scoped TaskIds — defeating
    /// crashpack-hash determinism and leaving the request task
    /// invisible to oracle/deadline-monitor walks of `state.tasks`.
    /// This per-runtime counter restores at-least intra-runtime
    /// determinism. The TaskId is still not in the runtime's task
    /// arena (which would require a deeper structured-spawn
    /// refactor) but the determinism breach is closed.
    request_task_counter: std::sync::atomic::AtomicU32,
    /// Shared success latch for every bounded-shutdown caller. The sole reaper
    /// signals it only after `RuntimeInner::drop` returns normally.
    shutdown_completion: Arc<RuntimeShutdownCompletion>,
    /// Worker loan protocol of a `RuntimeBuilder::current_thread()` runtime
    /// (GH#58); unset for every other topology.
    current_thread_driver:
        std::sync::OnceLock<Arc<crate::runtime::current_thread::CurrentThreadDriver>>,
    /// Browser worker pump if initialized with `BrowserHostServices`.
    browser_pump: std::sync::OnceLock<Arc<BrowserWorkerPump>>,
}

/// A real task record for a future polled outside the scheduler. The future
/// itself stays on the block_on caller's stack; only its ownership record is
/// shared with workers. No ready entry or stored future is installed, so a
/// cancellation wake cannot cause a worker to poll the caller's future.
struct CallerTaskRegistration {
    inner: Arc<RuntimeInner>,
    cx: crate::cx::Cx,
}

impl CallerTaskRegistration {
    fn new(inner: &Arc<RuntimeInner>, parent: &crate::cx::Cx) -> Result<Self, SpawnError> {
        let spawn_guard = inner.spawn_liveness_guard()?;
        let dispatch_table = inner.scheduler.dispatch_task_table();
        let (cx, handle, result_tx, spawn_effects) = {
            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut target = dispatch_table.as_ref().map_or(
                crate::runtime::state::AdmissionTaskTarget::Embedded,
                |table| {
                    crate::runtime::state::AdmissionTaskTarget::External(
                        table
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    )
                },
            );
            let (task_id, handle, cx, result_tx, spawn_effects) = state
                .create_task_infrastructure_in::<()>(
                    parent,
                    parent.region_id(),
                    parent.budget(),
                    false,
                    &mut target,
                    &crate::runtime::state::AdmissionRegionTarget::Embedded,
                )?;
            match &mut target {
                crate::runtime::state::AdmissionTaskTarget::Embedded => {
                    let _ = state.update_task(task_id, crate::record::TaskRecord::start_running);
                }
                crate::runtime::state::AdmissionTaskTarget::External(table) => {
                    let _ = table.update_task(task_id, crate::record::TaskRecord::start_running);
                }
            }
            (cx, handle, result_tx, spawn_effects)
        };
        let registration = Self {
            inner: Arc::clone(inner),
            cx,
        };
        // These internal channel owners have no consumers. Retire them outside
        // the state lock, after the task-lifetime guard is established.
        drop((handle, result_tx));
        drop(spawn_guard);
        spawn_effects.dispatch();
        inner.scheduler.note_caller_task(registration.cx.task_id());
        Ok(registration)
    }

    fn retire(&self, outcome: crate::record::task::TaskOutcome) {
        let mut retirement = CallerTaskRetirement {
            registration: self,
            record: None,
            waiters: smallvec::SmallVec::new(),
            protocol_retired: false,
            completed: false,
        };
        retirement.finish(outcome, std::thread::panicking());
    }
}

/// Retains ownership across a configured leak panic in either the mailbox
/// drain or the completion audit. Its unwind path runs after all state/table
/// guards have released and finishes the remaining retirement work.
struct CallerTaskRetirement<'a> {
    registration: &'a CallerTaskRegistration,
    record: Option<crate::record::TaskRecord>,
    waiters: smallvec::SmallVec<[crate::types::TaskId; 4]>,
    protocol_retired: bool,
    completed: bool,
}

impl CallerTaskRetirement<'_> {
    fn finish(&mut self, outcome: crate::record::task::TaskOutcome, unwinding: bool) {
        let registration = self.registration;
        // Fence admission before capturing mailbox ownership. A retained clone
        // can never publish a new reservation behind the completion sweep.
        registration.cx.revoke_obligation_admission();
        let task_id = registration.cx.task_id();
        let dispatch_table = registration.inner.scheduler.dispatch_task_table();
        let (observer, retirements, cancel_wakes, finalizers) = {
            let mut state = registration
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(gateway) = state.obligation_gateway() {
                // Do not dequeue a whole batch across the deliberate Panic
                // leak-policy boundary: unwinding would discard the unvisited
                // posts and their application barriers. One post at a time
                // leaves the rest available to this guard's unwind cleanup.
                // Capture once so concurrent producers cannot extend cleanup.
                let remaining = gateway.mailbox().len();
                for _ in 0..remaining {
                    if crate::runtime::obligation_mailbox::apply_obligation_posts_with_task_table(
                        &mut state,
                        gateway.mailbox(),
                        1,
                        dispatch_table.as_ref(),
                    ) == 0
                    {
                        break;
                    }
                }
            }
            let (ack, mut cancel_wakes) = if self.record.is_none() {
                let complete = |tasks: &mut crate::runtime::TaskTable| {
                    let effects = tasks
                        .update_task(
                            task_id,
                            crate::record::TaskRecord::consume_checkpoint_cancel_ack,
                        )
                        .unwrap_or_else(|| {
                            crate::types::task_context::CancellationEffects::ready(None)
                        });
                    let (ack, wakes) = effects.into_parts();
                    let _ = tasks.update_task(task_id, |record| {
                        ThreeLaneWorker::complete_polled_record(record, outcome, ack.is_some());
                    });
                    (tasks.remove_task(task_id), ack, wakes)
                };
                let (record, ack, wakes) = match dispatch_table.as_ref() {
                    Some(table) => complete(
                        &mut table
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    ),
                    None => complete(&mut state.tasks),
                };
                self.record = record;
                (ack, wakes)
            } else {
                // A completion audit already committed the terminal record
                // before panicking. Preserve that result during cleanup.
                (None, crate::types::task_context::CancelWakeEffects::empty())
            };
            let Some(record) = self.record.as_mut() else {
                self.completed = true;
                return;
            };
            if let Some(receipt) = ack.as_ref()
                && let Some(violation) = state
                    .external_checkpoint_cancel_materialization_violation(task_id, receipt, true)
            {
                cancel_wakes.push_cancel_protocol_violation(
                    "caller task cancellation materialization",
                    violation,
                );
            }
            // The record is detached in both layouts. Cross-cutting completion
            // can now audit obligations and advance the region without holding
            // the dispatch-table lock or retiring user wakers beneath it.
            self.waiters.extend(std::mem::take(&mut record.waiters));
            let effects = state.task_completed_from_external_record_resuming(
                record,
                &mut self.protocol_retired,
            );
            let (observer, retirements) = if unwinding {
                let (waiters, retirements) =
                    effects.into_waiters_and_retirements_without_observers();
                self.waiters.extend(waiters);
                (None, Some(retirements))
            } else {
                let (waiters, observer) = effects.into_parts();
                self.waiters.extend(waiters);
                (Some(observer), None)
            };
            let mut target = dispatch_table.as_ref().map_or(
                crate::runtime::state::AdmissionTaskTarget::Embedded,
                |table| {
                    crate::runtime::state::AdmissionTaskTarget::External(
                        table
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    )
                },
            );
            let finalizers = state.drain_ready_async_finalizers_in(
                &crate::runtime::state::AdmissionRegionTarget::Embedded,
                &mut target,
            );
            (observer, retirements, cancel_wakes, finalizers)
        };
        self.completed = true;
        ThreeLaneWorker::retire_detached_task_record(self.record.take());
        for waiter in self.waiters.drain(..) {
            registration
                .inner
                .scheduler
                .wake(waiter, Budget::INFINITE.priority);
        }
        for (task, priority, spawn_effects) in finalizers {
            registration.inner.scheduler.inject_ready(task, priority);
            spawn_effects.dispatch();
        }
        if let Some(observer) = observer {
            observer.dispatch();
        }
        if let Some(retirements) = retirements {
            retirements.retire();
        }
        cancel_wakes.dispatch();
    }
}

impl Drop for CallerTaskRetirement<'_> {
    fn drop(&mut self) {
        if !self.completed && std::thread::panicking() {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.finish(
                    crate::types::Outcome::Panicked(crate::types::PanicPayload::new(
                        "block_on caller retirement panicked",
                    )),
                    true,
                );
            })) {
                std::mem::forget(payload);
            }
        }
        ThreeLaneWorker::retire_detached_task_record(self.record.take());
    }
}

impl Drop for CallerTaskRegistration {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Preserve the original caller panic even if an observer or leak
            // policy also panics during ownership retirement.
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.retire(crate::types::Outcome::Panicked(
                    crate::types::PanicPayload::new("block_on caller panicked"),
                ));
            })) {
                std::mem::forget(payload);
            }
        } else {
            self.retire(crate::types::Outcome::Ok(()));
        }
    }
}

impl RuntimeInner {
    /// Starts the resource sampler; from then on every task context the
    /// runtime builds carries its pressure (asupersync-1ir2em). A sampler that
    /// cannot start leaves `Cx::pressure()` unset instead of frozen.
    #[cfg(not(target_arch = "wasm32"))]
    fn start_resource_sampling(&self, interval: Duration) {
        let monitor = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resource_monitor();
        let Some(sampler) =
            crate::runtime::resource_monitor::ResourceSampler::start(monitor, interval)
        else {
            crate::tracing_compat::warn!(
                "resource sampling did not start; region admission and Cx::pressure() stay unsampled"
            );
            return;
        };
        let pressure = sampler.system_pressure();
        if self.resource_sampler.set(sampler).is_ok() {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .set_task_pressure(Some(pressure));
        }
    }

    fn spawn_liveness_guard(&self) -> Result<Arc<()>, SpawnError> {
        self.spawn_liveness
            .lock()
            .as_ref()
            .map(Arc::clone)
            .ok_or(SpawnError::RuntimeUnavailable)
    }

    fn close_spawn_admission(&self) -> Option<Weak<()>> {
        self.spawn_liveness.lock().take().map(|token| {
            let publishers = Arc::downgrade(&token);
            drop(token);
            publishers
        })
    }

    fn wait_for_spawn_publishers(publishers: Option<&Weak<()>>) {
        while publishers.is_some_and(|publishers| publishers.strong_count() > 0) {
            std::thread::park_timeout(Duration::from_millis(1));
        }
    }

    fn begin_shutdown(&self) {
        self.scheduler.shutdown();
        if let Some(driver) = self.current_thread_driver.get() {
            driver.shutdown();
        }
        // Threads that drove this runtime's worker from `block_on` and still
        // hold `!Send` tasks parked in its keyed local store drop that store
        // on their next local-store operation (asupersync-1fyc8f).
        crate::runtime::local::publish_retired_local_store_key(self.scheduler.local_store_key());
        if let Some(pool) = self.blocking_pool.as_ref() {
            // The bounded caller must not wait on the pool's coordination
            // mutex. Atomically close admission here; the reaper performs the
            // mutex-coordinated condition-variable wake below.
            pool.close_admission();
        }
    }

    fn signal_shutdown(&self) {
        self.begin_shutdown();
        if let Some(pool) = self.blocking_pool.as_ref() {
            pool.shutdown();
        }
    }

    /// After [`Self::signal_shutdown`], retires a multi-thread runtime's
    /// stopped tasks while other owners may still hold the runtime
    /// (br-asupersync-1pi7ne H1).
    ///
    /// Tasks are otherwise dropped only by `RuntimeInner::drop`, which needs
    /// the last strong reference. Two common owners never let it go:
    /// - a `block_on` caller on a cloned `Runtime` that waits for one of
    ///   those tasks;
    /// - a task that holds a strong `RuntimeHandle`, such as an accept loop
    ///   that spawns through a handle.
    /// Joins then hang, task-owned sockets and files stay open, and the
    /// reaper polls `Arc::try_unwrap` every millisecond forever.
    ///
    /// Once the workers have exited, dropping the task tables is the same
    /// abort-by-drop `RuntimeInner::drop` performs: joins observe
    /// cancellation, and a dropped future releases what it held. A
    /// current-thread runtime's worker is on loan to a `block_on` caller and
    /// cannot be joined here, so its tasks wait for the final drop as before.
    fn retire_stopped_tasks_after_shutdown(&self) {
        if self.current_thread_driver.get().is_some() || self.browser_pump.get().is_some() {
            return;
        }
        let handles = {
            let mut workers = self.worker_threads.lock();
            let current = std::thread::current().id();
            if workers.iter().any(|handle| handle.thread().id() == current) {
                // A worker cannot join itself; the final drop retires these.
                return;
            }
            std::mem::take(&mut *workers)
        };
        for handle in handles {
            let _ = handle.join();
        }
        let gateway_mailbox = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .spawn_gateway()
                .map(|gateway| Arc::clone(gateway.mailbox()))
        };
        retire_stopped_tasks(
            &self.state,
            self.sharded_state.as_ref(),
            gateway_mailbox.as_deref(),
        );
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn initialize_runtime_state(
        config: &RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
        io_driver: Option<IoDriverHandle>,
        timer_driver: Option<TimerDriverHandle>,
        entropy_source: Option<Arc<dyn EntropySource>>,
        terminal_io_reactor_snapshot: Option<IoReactorCapabilitySnapshot>,
    ) -> RuntimeState {
        let capacity_hints = config.resolved_capacity_hints();
        let trace_capacity = config.trace_storage_profile.trace_buffer_capacity();
        let mut runtime_state = reactor.map_or_else(
            || {
                RuntimeState::with_capacity_hints_and_trace_capacity(
                    capacity_hints.task_capacity,
                    capacity_hints.region_capacity,
                    capacity_hints.obligation_capacity,
                    trace_capacity,
                    config.metrics_provider.clone(),
                )
            },
            |reactor| {
                let mut state = RuntimeState::with_capacity_hints_and_trace_capacity(
                    capacity_hints.task_capacity,
                    capacity_hints.region_capacity,
                    capacity_hints.obligation_capacity,
                    trace_capacity,
                    config.metrics_provider.clone(),
                );
                state.set_io_driver(IoDriverHandle::new(reactor));
                #[cfg(target_arch = "wasm32")]
                state.set_timer_driver(TimerDriverHandle::with_browser_clock(Arc::new(
                    crate::time::BrowserMonotonicClock::host_sampled(),
                )));
                #[cfg(not(target_arch = "wasm32"))]
                state.set_timer_driver(TimerDriverHandle::with_wall_clock());
                state.set_logical_clock_mode(LogicalClockMode::Hybrid);
                state
            },
        );
        if let Some(snapshot) = terminal_io_reactor_snapshot {
            runtime_state.set_unavailable_io_reactor_capability_snapshot(snapshot);
        }
        if let Some(driver) = io_driver {
            // A foreign runtime cannot drive our timer wheel: share the
            // dispatcher but allocate a distinct polling participant.
            runtime_state.set_io_driver(driver.for_runtime());
        }
        if let Some(driver) = timer_driver {
            runtime_state.set_timer_driver(driver);
        }
        if let Some(source) = entropy_source {
            runtime_state.set_entropy_source(source);
        }
        runtime_state.set_spawn_authorization_key(config.security.spawn_authorization_key.clone());
        runtime_state.set_read_biased_region_snapshot(config.enable_read_biased_region_snapshot);
        // Nothing replays a native runtime's oracle histories; unbounded, they
        // grew with every region close and every drain-correct race.
        runtime_state.bound_oracle_histories(NATIVE_ORACLE_HISTORY_LIMIT);
        runtime_state
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn initialize_root_region(
        config: &RuntimeConfig,
        state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
    ) -> crate::types::RegionId {
        let mut guard = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            #[cfg(target_arch = "wasm32")]
            guard.set_timer_driver(TimerDriverHandle::with_browser_clock(Arc::new(
                crate::time::BrowserMonotonicClock::host_sampled(),
            )));
            #[cfg(not(target_arch = "wasm32"))]
            guard.set_timer_driver(TimerDriverHandle::with_wall_clock());
        }
        let root = guard.create_root_region(Budget::INFINITE);
        if let Some(limits) = config.root_region_limits.clone() {
            let _ = guard.set_region_limits(root, limits);
        }
        root
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn new(
        config: RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
        io_driver: Option<IoDriverHandle>,
        timer_driver: Option<TimerDriverHandle>,
        entropy_source: Option<Arc<dyn EntropySource>>,
        terminal_io_reactor_snapshot: Option<IoReactorCapabilitySnapshot>,
        host_services: &dyn RuntimeHostServices,
        scheduler_evidence_sink: Option<Arc<dyn crate::evidence_sink::EvidenceSink>>,
    ) -> (Self, Vec<ThreeLaneWorker>) {
        // br-asupersync-8fuxnt: RuntimeConfig::runtime_state_shape routes
        // internally below — the Sharded shape constructs a ShardedState
        // whose Arc-shared shard A the scheduler dispatches against, and
        // the admission, finalizer, completion, spawn-fallback, snapshot,
        // liveness, and deadline-monitor surfaces are dispatch-table-aware
        // (br-asupersync-sched-hot-path-perf-bt4y5f.2.2 subsystems 1-3d).
        // PUBLIC opt-in is still rejected at RuntimeBuilder::build() until
        // the unified|sharded replay-fingerprint identity proof and the
        // ShardGuard label-test coverage land (parent ACs 2/3); in-repo
        // proof lanes reach this arm through the internal constructor.
        let runtime_state = Self::initialize_runtime_state(
            &config,
            reactor,
            io_driver,
            timer_driver,
            entropy_source,
            terminal_io_reactor_snapshot,
        );
        let state = Arc::new(crate::sync::ContendedMutex::new(
            "runtime_state",
            runtime_state,
        ));
        let root_region = Self::initialize_root_region(&config, &state);

        // E1.2 subsystem 3d: sharded construction. Reachable both through
        // the public builder (`with_sharded_state(true)` — the 8fuxnt gate
        // flipped once the replay-fingerprint identity proof and label/loom
        // coverage landed) and Runtime::with_config_and_platform. The
        // unified state remains the B/C/D lifecycle owner; the scheduler
        // dispatches against ShardedState's Arc-shared shard A, which
        // activates the admission, finalizer, completion, spawn-fallback,
        // and snapshot seams landed in E1.2 subsystems 1-3d.
        let sharded_state = if matches!(
            config.runtime_state_shape,
            crate::runtime::config::RuntimeStateShape::Sharded
        ) {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let shards = Arc::new(crate::runtime::ShardedState::new(
                guard.trace_handle(),
                guard.metrics_provider(),
                guard.sharded_construction_config(),
            ));
            // E2 S4c-2c-iv (br-asupersync-m9wsza, fork option C): hand the
            // unified state its shard-table bundle in the same lock scope,
            // before any scheduler/worker exists — obligation lifecycle
            // wrappers resolve shard C (and the shard-A read side) from it.
            // Region records deliberately stay embedded this round.
            guard.install_shard_tables(Arc::clone(&shards));
            Some(shards)
        } else {
            None
        };
        // E1.2 T01/T02: one brief builder-time acquisition extracts the E/D
        // handle bundle (the state is the source of truth for driver handles
        // — `initialize_runtime_state` and `initialize_root_region` may have
        // installed reactor-derived or wall-clock drivers the builder's own
        // parameters never saw). Construction itself then takes no state
        // lock, and the parked-worker notifier is installed before any
        // worker thread exists. Both arms return with the coordinator
        // installed (`new_with_sharded_state` installs it internally).
        let mut scheduler = if let Some(shards) = sharded_state.as_deref() {
            ThreeLaneScheduler::new_with_sharded_state(
                config.worker_threads,
                &state,
                shards,
                config.cancel_lane_max_streak,
                config.enable_governor,
                config.governor_interval,
            )
        } else {
            let construction_handles = SchedulerConstructionHandles::extract_from_unified(&state);
            let scheduler = ThreeLaneScheduler::new_with_options_task_table_and_handles(
                config.worker_threads,
                &state,
                None,
                construction_handles,
                config.cancel_lane_max_streak,
                config.enable_governor,
                config.governor_interval,
            );
            scheduler.install_pending_cancel_dispatch_coordinator(&state);
            scheduler
        };
        scheduler.set_steal_batch_size(config.steal_batch_size);
        scheduler.set_enable_parking(config.enable_parking);
        scheduler.set_global_queue_limit(config.global_queue_limit);
        scheduler.set_browser_ready_handoff_limit(config.browser_ready_handoff_limit);
        scheduler.set_scheduler_placement_mode(config.scheduler_placement_mode);
        scheduler.set_adaptive_cancel_streak(
            config.enable_adaptive_cancel_streak,
            config.adaptive_cancel_streak_epoch_steps,
        );
        scheduler.set_adaptive_batch_profile(scheduler_adaptive_ready_batch_profile(
            config.adaptive_ready_batch,
        ));
        if let Some(mapping) = config.worker_cohort_map.as_ref() {
            scheduler
                .set_worker_cohort_map(&mapping.worker_to_cohort)
                .expect("validated worker cohort map should apply to scheduler");
        }
        // The spawn mailbox + producer gateway always exist so the
        // Cx::spawn surface works in every mode (workers' drain costs one
        // atomic emptiness check when idle); SpawnAdmissionMode only
        // selects RuntimeHandle::spawn routing (br-asupersync-hwjqyo / A2.2).
        let spawn_liveness = Arc::new(());
        let (mailbox, root_pending_spawns, spawn_clock) = {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mailbox = Arc::new(crate::runtime::spawn_mailbox::SpawnMailbox::with_trace(
                guard.trace_handle(),
            ));
            let pending = guard
                .region(root_region)
                .map(crate::record::RegionRecord::pending_spawn_handle);
            let clock = guard.timer_driver_handle();
            scheduler.attach_spawn_mailbox(Arc::clone(&mailbox));
            guard.set_spawn_gateway(Arc::new(crate::runtime::spawn_mailbox::SpawnGateway::new(
                Arc::clone(&mailbox),
                scheduler.spawn_enqueued_notifier(),
                clock.clone(),
                Arc::downgrade(&spawn_liveness),
            )));
            // Obligation mailbox (bi2462.13), drained next to spawn admissions; checked lock-free.
            let om = Arc::new(crate::runtime::obligation_mailbox::ObligationMailbox::new());
            scheduler.attach_obligation_mailbox(&om);
            guard.set_obligation_gateway(Arc::new(
                crate::runtime::obligation_mailbox::ObligationGateway::new(
                    Arc::clone(&om),
                    scheduler.obligation_posted_notifier(),
                    Arc::downgrade(&spawn_liveness),
                ),
            ));
            (mailbox, pending, clock)
        };
        // Every worker owns its thread-local `!Send` lane under this mailbox
        // whatever the admission mode; `spawn_local` identifies the lane by it.
        let local_lane_mailbox = Arc::clone(&mailbox);
        let spawn_mailbox =
            if config.spawn_admission == crate::runtime::config::SpawnAdmissionMode::Mailbox {
                Some(mailbox)
            } else {
                None
            };
        let mut workers = scheduler.take_workers();
        if let Some(sink) = scheduler_evidence_sink {
            for worker in &mut workers {
                worker.set_evidence_sink(Arc::clone(&sink));
            }
        }

        let deadline_monitor =
            host_services.start_deadline_monitor(&config, &state, scheduler.dispatch_task_table());

        let blocking_pool = Self::create_blocking_pool(&config);
        if let Some(pool) = blocking_pool.as_ref() {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.set_blocking_pool(pool.handle());
        }

        (
            Self {
                config,
                state,
                sharded_state,
                scheduler,
                worker_threads: Mutex::new(Vec::new()),
                root_region,
                spawn_mailbox,
                local_lane_mailbox,
                root_pending_spawns,
                spawn_clock,
                spawn_liveness: Mutex::new(Some(spawn_liveness)),
                blocking_pool,
                deadline_monitor_shutdown: deadline_monitor.shutdown,
                deadline_monitor_thread: deadline_monitor.thread,
                #[cfg(not(target_arch = "wasm32"))]
                resource_sampler: std::sync::OnceLock::new(),
                request_task_counter: std::sync::atomic::AtomicU32::new(1),
                shutdown_completion: Arc::new(RuntimeShutdownCompletion::new()),
                current_thread_driver: std::sync::OnceLock::new(),
                browser_pump: std::sync::OnceLock::new(),
            },
            workers,
        )
    }

    /// br-asupersync-3lk5n2: returns a fresh request-scoped TaskId
    /// minted from a per-runtime monotonic counter. The ID is still
    /// not in the runtime's task arena (closing that gap requires a
    /// deeper structured-spawn refactor — see the bead notes), but
    /// it is now replay-deterministic within a single runtime
    /// instance: two LabRuntimes in the same process no longer share
    /// a counter, and two replays of the same scenario produce the
    /// same sequence of request-scoped IDs.
    #[inline]
    fn next_request_task_id(&self) -> crate::types::TaskId {
        let index = self
            .request_task_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Use generation 1 as the "request-scoped" marker, matching
        // the bootstrap convention from types/id.rs::next_bootstrap_task_id.
        crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(index, 1))
    }

    /// Creates the blocking pool if configured with non-zero max threads.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
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
            affinity_profile: config.blocking.affinity_profile,
            cohort_count: config
                .worker_cohort_map
                .as_ref()
                .map(crate::runtime::config::WorkerCohortMapping::cohort_count),
            ..Default::default()
        };
        Some(crate::runtime::blocking_pool::BlockingPool::with_config(
            config.blocking.min_threads,
            config.blocking.max_threads,
            options,
        ))
    }

    fn spawn_local<F>(&self, future: F) -> Result<LocalJoinHandle<F::Output>, SpawnError>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let spawn_guard = self.spawn_liveness_guard()?;
        // A `!Send` request parks on the calling thread's lane and is only
        // admitted by a worker driving that thread. The browser pump drives
        // the single wasm thread, so any caller there is served; on a native
        // runtime a caller outside this runtime's worker threads or its
        // current-thread `block_on` root would strand the request and its
        // join handle forever, so refuse it the way `Cx::spawn_local` does.
        if self.browser_pump.get().is_none()
            && (crate::runtime::scheduler::three_lane::current_worker_id().is_none()
                || !crate::runtime::spawn_mailbox::local_spawn_lane_is_owned_by_mailbox(
                    &self.local_lane_mailbox,
                ))
        {
            return Err(SpawnError::LocalSchedulerUnavailable);
        }
        let join_state = Arc::new(Mutex::new(JoinState::new()));
        let task_producer = JoinProducer::new(Arc::clone(&join_state));

        let wrapped = async move {
            let result = CatchUnwind { inner: future }.await;
            let outcome = handle_spawn_outcome(&result);
            task_producer.complete(result);
            outcome
        };

        let provisional = self.next_request_task_id();
        let factory: crate::runtime::spawn_mailbox::LocalSpawnFactoryFn =
            Box::new(move |_cx| Box::pin(wrapped));

        let cancel_producer = JoinProducer::new(Arc::clone(&join_state));
        let error_producer = JoinProducer::new(Arc::clone(&join_state));
        let on_unadmitted_cancel: Option<crate::runtime::spawn_mailbox::LocalUnadmittedCancelFn> =
            Some(Box::new(move |reason| {
                cancel_producer.cancel(reason);
            }));
        let on_admission_error: Option<crate::runtime::spawn_mailbox::LocalAdmissionErrorFn> =
            Some(Box::new(move |error| {
                let mut reason = crate::types::CancelReason::user("spawn admission failed");
                reason.message = Some(error.to_string());
                error_producer.cancel(reason);
            }));

        let pending_reservation = self
            .root_pending_spawns
            .as_ref()
            .map(|counter| counter.reserve());

        let request = crate::runtime::spawn_mailbox::LocalSpawnRequest {
            task_id: provisional,
            region: self.root_region,
            budget: Budget::new(),
            factory,
            on_unadmitted_cancel,
            on_admission_error,
            pending_reservation,
            admitted_slot: None,
        };

        crate::runtime::spawn_mailbox::enqueue_local_spawn_for_mailbox(
            request,
            &self.local_lane_mailbox,
        );

        if let Some(pump) = self.browser_pump.get() {
            pump.schedule_pump();
        } else {
            self.scheduler.notify_spawn_enqueued();
        }

        drop(spawn_guard);
        Ok(LocalJoinHandle::new(join_state))
    }

    fn spawn<F>(&self, future: F) -> Result<JoinHandle<F::Output>, SpawnError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let spawn_guard = self.spawn_liveness_guard()?;
        let join_state = Arc::new(Mutex::new(JoinState::new()));
        let task_producer = JoinProducer::new(Arc::clone(&join_state));

        let wrapped = async move {
            // Ensure panics in the spawned task don't take down a worker thread. If the join
            // handle is awaited, we re-raise the original panic payload on the awaiter. The
            // task record still gets the Panicked outcome (metrics, capture, region close).
            let result = CatchUnwind { inner: future }.await;
            let outcome = handle_spawn_outcome(&result);
            task_producer.complete(result);
            outcome
        };

        // Mailbox admission mode (br-asupersync-dx-core-api-v2-u1z5hn.1.3):
        // reserve the root region's pending-spawn credit, then enqueue the
        // erased request without touching the RuntimeState lock. Scheduler
        // workers admit at dispatch time; cancel-before-admission resolves
        // the join handle through the cancel slot (this JoinHandle models
        // cancellation as a panic payload on the awaiter, matching the
        // existing dropped-before-completion semantics).
        if let Some(mailbox) = &self.spawn_mailbox {
            let reservation = self
                .root_pending_spawns
                .as_ref()
                .map(|counter| counter.reserve());
            let cancel_producer = JoinProducer::new(Arc::clone(&join_state));
            let provisional = mailbox.allocate_task_id();
            let mut request = crate::runtime::spawn_mailbox::SpawnRequest::new(
                provisional,
                self.root_region,
                Budget::new(),
                crate::runtime::stored_task::StoredTask::new_with_id(wrapped, provisional),
            )
            .with_unadmitted_cancel(Box::new(move |reason| {
                // Keep admission cancellation distinct from generic runtime
                // shutdown for the checked join path. The callback owns its
                // own producer lease so dropping the stored task first cannot
                // race a less-specific shutdown result ahead of this reason.
                // Legacy joins still receive their established panic payload.
                cancel_producer.cancel(reason);
            }));
            if let Some(reservation) = reservation {
                request = request.with_pending_reservation(reservation);
            }
            let now = self
                .spawn_clock
                .as_ref()
                .map_or(crate::types::Time::ZERO, TimerDriverHandle::now);
            mailbox.enqueue(request, now);
            self.scheduler.notify_spawn_enqueued();
            drop(spawn_guard);
            return Ok(JoinHandle::new(join_state));
        }

        let dispatch_table = self.scheduler.dispatch_task_table();
        let (task_id, spawn_effects) = {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // E1.2 subsystem 3d (E1.1 row B09): the legacy fallback mints
            // into the table the scheduler dispatches against. Lock order is
            // unified state (B) then dispatch table (A); scope exit releases
            // A before B.
            let mut target = dispatch_table.as_ref().map_or(
                crate::runtime::state::AdmissionTaskTarget::Embedded,
                |tt| {
                    crate::runtime::state::AdmissionTaskTarget::External(
                        tt.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                    )
                },
            );
            // Store `wrapped` itself so the record keeps its outcome. The
            // state-task wrapper would record Ok for the panic `wrapped`
            // already caught; its TaskHandle here was always discarded.
            let system_cx = crate::runtime::RuntimeState::unread_caller_cx();
            let (task_id, _handle, _cx, _result_tx, spawn_effects) = guard
                .create_task_infrastructure_in::<()>(
                    system_cx,
                    self.root_region,
                    Budget::new(),
                    false,
                    &mut target,
                    &crate::runtime::state::AdmissionRegionTarget::Embedded,
                )?;
            guard.store_spawned_task_in(
                &mut target,
                task_id,
                crate::runtime::StoredTask::new_with_id(wrapped, task_id),
            );
            (task_id, spawn_effects)
        };

        self.scheduler.inject_ready(task_id, Budget::new().priority);
        drop(spawn_guard);
        spawn_effects.dispatch();

        Ok(JoinHandle::new(join_state))
    }

    /// Spawn a task with a [`Cx`](crate::cx::Cx) passed to the factory closure.
    ///
    /// The Cx is created in the root region and linked to its cancellation
    /// tree. Explicit root drain publishes shutdown cancellation; ordinary
    /// runtime drop alone does not perform cooperative cleanup.
    fn spawn_with_cx<F, Fut>(&self, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce(crate::cx::Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        use crate::runtime::StoredTask;
        use crate::types::Outcome;

        let spawn_guard = self.spawn_liveness_guard()?;
        let dispatch_table = self.scheduler.dispatch_task_table();
        let (task_id, spawn_effects) = {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // E1.2 subsystem 3d (E1.1 row B10): mint and store into the table
            // the scheduler dispatches against. Lock order is unified state
            // (B) then dispatch table (A); A is released before B below.
            let mut target = dispatch_table.as_ref().map_or(
                crate::runtime::state::AdmissionTaskTarget::Embedded,
                |tt| {
                    crate::runtime::state::AdmissionTaskTarget::External(
                        tt.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                    )
                },
            );

            let system_cx = crate::runtime::RuntimeState::unread_caller_cx();
            let (task_id, _handle, cx, _result_tx, spawn_effects) = guard
                .create_task_infrastructure_in::<()>(
                    system_cx,
                    self.root_region,
                    Budget::new(),
                    false,
                    &mut target,
                    &crate::runtime::state::AdmissionRegionTarget::Embedded,
                )?;

            let wrapped = async move {
                // Both factory construction and future polling are inside the
                // task-panic boundary. The factory therefore cannot orphan the
                // already-published TaskRecord or unwind a state lock.
                match (CatchUnwind {
                    inner: async move { f(cx).await },
                })
                .await
                {
                    Ok(()) => Outcome::Ok(()),
                    Err(payload) => {
                        let message = crate::cx::scope::payload_to_string(&payload);
                        std::mem::forget(payload);
                        Outcome::Panicked(crate::types::PanicPayload::new(message))
                    }
                }
            };

            guard.store_spawned_task_in(
                &mut target,
                task_id,
                StoredTask::new_with_id(wrapped, task_id),
            );
            drop(target);
            drop(guard);

            (task_id, spawn_effects)
        };

        self.scheduler.inject_ready(task_id, Budget::new().priority);
        drop(spawn_guard);
        spawn_effects.dispatch();

        Ok(())
    }

    /// Returns a handle to the blocking pool, if configured.
    fn blocking_handle(&self) -> Option<crate::runtime::blocking_pool::BlockingPoolHandle> {
        let _spawn_guard = self.spawn_liveness_guard().ok()?;
        self.blocking_pool
            .as_ref()
            .map(crate::runtime::blocking_pool::BlockingPool::handle)
    }

    fn finish_teardown_off_worker(teardown: impl FnOnce() + Send + 'static) {
        Self::finish_teardown_with_spawner(teardown, |job| {
            std::thread::Builder::new()
                .name("asupersync-worker-teardown".into())
                .spawn(job)
                .map(|_| ())
        });
    }

    fn finish_teardown_with_spawner(
        teardown: impl FnOnce() + Send + 'static,
        mut spawn: impl FnMut(Box<dyn FnOnce() + Send + 'static>) -> io::Result<()>,
    ) {
        // A refused spawn drops its closure on this worker. Keep ownership of
        // the joins and state outside that closure so refusal cannot detach
        // workers, drop their state, or re-enter teardown on the current worker.
        let retained = Arc::new(Mutex::new(Some(teardown)));
        loop {
            let reaper_retained = Arc::clone(&retained);
            let job = Box::new(move || {
                let teardown = reaper_retained.lock().take();
                if let Some(teardown) = teardown {
                    teardown();
                }
            });
            if spawn(job).is_ok() {
                return;
            }
            // Ordinary drop has no timeout. Under thread-resource exhaustion,
            // retain teardown ownership and wait for capacity; do not report a
            // completed teardown or silently discard a worker's join handle.
            std::thread::park_timeout(Duration::from_millis(1));
        }
    }
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        let spawn_liveness = self.close_spawn_admission();
        let gateway_mailbox = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .spawn_gateway()
                .map(|gateway| Arc::clone(gateway.mailbox()))
        };

        // A producer that upgraded the liveness token before drop began is
        // entitled to finish publishing while workers can still admit the
        // request. Waiting only after scheduler shutdown and worker joins
        // leaves a race where the producer publishes into a stopped runtime;
        // mailbox mode can clean that request up later, but the legacy direct
        // path has already stored and scheduled a task. Close admission first,
        // then let every admitted publication reach its scheduling boundary
        // before stopping any consumer.
        if let Some(liveness) = spawn_liveness.as_ref() {
            Self::wait_for_spawn_publishers(Some(liveness));
        }

        // Signal consumers before transferring their join handles. In the
        // worker-owned case the current poll must return before it can join.
        if let Some(shutdown) = self.deadline_monitor_shutdown.take() {
            let _ = shutdown.send(());
        }
        self.scheduler.shutdown();
        if let Some(driver) = self.current_thread_driver.get() {
            driver.shutdown();
        }
        if let Some(pump) = self.browser_pump.get() {
            // Threadless hosts have no worker exit loop to retire pending
            // admissions or parked local futures. Leave other runtimes' local
            // lanes intact, and run captured destructors outside their locks.
            crate::runtime::spawn_mailbox::cancel_local_spawns_for_mailbox(
                &self.local_lane_mailbox,
            );
            pump.retire_stopped_worker();
            crate::runtime::local::retire_local_store(self.scheduler.local_store_key());
        } else {
            crate::runtime::local::publish_retired_local_store_key(
                self.scheduler.local_store_key(),
            );
        }
        let handles = std::mem::take(self.worker_threads.get_mut());
        let current_thread = std::thread::current().id();
        let on_worker = handles
            .iter()
            .any(|handle| handle.thread().id() == current_thread);
        let deadline_monitor = self.deadline_monitor_thread.take();
        #[cfg(not(target_arch = "wasm32"))]
        let resource_sampler = self.resource_sampler.take();
        let blocking_pool = self.blocking_pool.take();
        if let Some(pool) = &blocking_pool {
            pool.close_admission();
        }
        // Workers retain their scheduler handles. Also retain the runtime's
        // unified and sharded state until every worker has exited and pending
        // mailbox publications have been resolved, including during unwind.
        let state = Arc::clone(&self.state);
        let sharded_state = self.sharded_state.clone();
        let teardown = move || {
            if let Some(thread) = deadline_monitor {
                let _ = thread.join();
            }
            // Dropping the sampler stops and joins its thread.
            #[cfg(not(target_arch = "wasm32"))]
            drop(resource_sampler);
            let blocking_pool =
                blocking_pool.inspect(crate::runtime::blocking_pool::BlockingPool::shutdown);
            for handle in handles {
                let _ = handle.join();
            }
            retire_stopped_tasks(&state, sharded_state.as_ref(), gateway_mailbox.as_deref());
            drop(sharded_state);
            drop(state);
            drop(blocking_pool); // Joined last: its jobs may wait on retired values.
        };
        if on_worker {
            Self::finish_teardown_off_worker(teardown);
        } else {
            teardown();
        }
    }
}

/// Retires the tasks, region finalizers and pending spawn requests of a
/// runtime whose workers have exited: the abort-by-drop part of teardown,
/// shared by `RuntimeInner::drop` and the `shutdown_timeout` reaper.
fn retire_stopped_tasks(
    state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
    sharded_state: Option<&Arc<crate::runtime::ShardedState>>,
    gateway_mailbox: Option<&crate::runtime::spawn_mailbox::SpawnMailbox>,
) {
    // Diagnostics and retained contexts can keep state alive after the
    // runtime dies. Explicitly detach stopped task ownership, then let
    // TaskTable retire futures/records and release join barriers outside
    // every runtime and shard lock. Keep the tables owned through mailbox
    // denial dispatch, including if that dispatch unwinds.
    let retired_tasks = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let unified = std::mem::take(&mut state.tasks);
        let sharded = sharded_state.map(|sharded| {
            let mut tasks = sharded
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *tasks)
        });
        (unified, sharded)
    };
    // Finalizers admitted into regions that never closed can no longer
    // run. A retained value that holds this state (a registration, a
    // Cx) forms a cycle nothing else breaks, so take them out under
    // the lock and drop them outside it (asupersync-bi2462.147.11).
    let retired_finalizers = {
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut finalizers: Vec<_> = state
            .regions
            .iter()
            .flat_map(|(_, region)| region.take_finalizers_for_teardown())
            .collect();
        if let Some(sharded) = sharded_state {
            let regions = sharded
                .regions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            finalizers.extend(
                regions
                    .iter()
                    .flat_map(|(_, region)| region.take_finalizers_for_teardown()),
            );
        }
        finalizers
    };
    if let Some(mailbox) = gateway_mailbox {
        mailbox.retire_region_commands();
        let mut cancelled = Vec::new();
        while mailbox.dequeue_handle_cancels_into(64, &mut cancelled) > 0 {
            for request in cancelled.drain(..) {
                if let Some(slot) = request.admitted_slot {
                    slot.abandon_unpublished_spawn_effects();
                }
            }
        }
        while let Some(request) = mailbox.dequeue() {
            request
                .into_parts()
                .resolve_failed(SpawnError::RuntimeUnavailable);
        }
    }
    drop(retired_tasks);
    for finalizer in retired_finalizers {
        if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(finalizer)))
        {
            // Retained values can have arbitrary destructors; one
            // failure cannot strand the rest (as for queued commands).
            std::mem::forget(payload);
        }
    }
}

struct JoinState<T> {
    result: Option<std::thread::Result<T>>,
    cancel_reason: Option<crate::types::CancelReason>,
    waker: Option<Waker>,
    producers: usize,
}

impl<T> JoinState<T> {
    fn new() -> Self {
        Self {
            result: None,
            cancel_reason: None,
            waker: None,
            producers: 0,
        }
    }

    fn is_terminal(&self) -> bool {
        self.result.is_some() || self.cancel_reason.is_some()
    }
}

fn lock_state<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state.lock()
}

#[cfg(test)]
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

/// Failure-aware join handle returned by [`RuntimeHandle::spawn_checked`].
///
/// Unlike the legacy [`JoinHandle`], task cancellation and task panic are
/// ordinary typed results. This surface is additive so v0.4.3 callers that
/// await `RuntimeHandle::spawn` continue to compile and retain their established
/// panic-propagating behavior.
#[must_use = "checked join handles must be awaited to observe task failure"]
pub struct CheckedJoinHandle<T> {
    inner: JoinHandle<T>,
}

impl<T> CheckedJoinHandle<T> {
    fn new(inner: JoinHandle<T>) -> Self {
        Self { inner }
    }

    /// Returns true if the task has reached a terminal result.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

impl<T> Future for CheckedJoinHandle<T> {
    type Output = Result<T, crate::runtime::JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut self.get_mut().inner;
        if this.completed {
            return Poll::Ready(Err(crate::runtime::JoinError::PolledAfterCompletion));
        }
        let mut guard = lock_state(&this.state);
        if let Some(reason) = guard.cancel_reason.take() {
            this.completed = true;
            return Poll::Ready(Err(crate::runtime::JoinError::Cancelled(reason)));
        }
        match guard.result.take() {
            None => {
                if Arc::strong_count(&this.state) == 1 {
                    this.completed = true;
                    return Poll::Ready(Err(crate::runtime::JoinError::Cancelled(
                        crate::types::CancelReason::shutdown(),
                    )));
                }
                if !guard
                    .waker
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()))
                {
                    guard.waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Some(Ok(output)) => {
                this.completed = true;
                Poll::Ready(Ok(output))
            }
            Some(Err(payload)) => {
                this.completed = true;
                let message = crate::cx::scope::payload_to_string(&payload);
                // A caught panic payload may itself have a panicking destructor.
                // Match the existing task-panic transport and retain only its
                // stable string representation at this boundary.
                std::mem::forget(payload);
                Poll::Ready(Err(crate::runtime::JoinError::Panicked(
                    crate::types::PanicPayload::new(message),
                )))
            }
        }
    }
}

impl RuntimeHandle {
    /// Spawn a task whose join future reports cancellation and panic as typed
    /// [`JoinError`](crate::runtime::JoinError) values.
    ///
    /// This is the failure-aware counterpart to [`spawn`](Self::spawn). The
    /// legacy method remains unchanged for v0.4.x compatibility: awaiting its
    /// [`JoinHandle`] still returns `T` and resumes task panics. New code that
    /// needs to supervise runtime shutdown should prefer this method.
    ///
    /// # Panics
    ///
    /// Panics if the runtime is no longer available or if the root region
    /// rejects admission. Use [`RuntimeHandle::try_spawn_checked`] to handle
    /// those admission failures explicitly.
    pub fn spawn_checked<F>(&self, future: F) -> CheckedJoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.try_spawn_checked(future)
            .expect("failed to create runtime task")
    }

    /// Spawn a task with typed join errors, returning runtime-availability or
    /// admission errors instead of panicking.
    pub fn try_spawn_checked<F>(
        &self,
        future: F,
    ) -> Result<CheckedJoinHandle<F::Output>, SpawnError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.try_spawn(future).map(CheckedJoinHandle::new)
    }

    /// Create a request-scoped [`Cx`](crate::cx::Cx) backed by this runtime.
    ///
    /// This is the handle-scoped counterpart to
    /// [`Runtime::request_cx_with_budget`]. It carries the same runtime-owned
    /// drivers, tracing, logical clock, entropy source, and spawn gateway, so
    /// holders of a cloned `RuntimeHandle` can begin an operation with explicit
    /// authority without spawning a helper task merely to mint a context.
    ///
    /// # Panics
    ///
    /// Panics if this is a weak handle and the runtime has already been
    /// dropped. Use [`RuntimeHandle::try_request_cx_with_budget`] when runtime
    /// teardown can race with context creation.
    #[must_use]
    pub fn request_cx_with_budget(&self, budget: Budget) -> crate::cx::Cx {
        self.try_request_cx_with_budget(budget)
            .expect("runtime unavailable while creating request context")
    }

    /// Try to create a request-scoped [`Cx`](crate::cx::Cx) backed by this
    /// runtime.
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when a weak handle outlives
    /// its runtime. Otherwise this is semantically identical to
    /// [`Runtime::request_cx_with_budget`].
    pub fn try_request_cx_with_budget(&self, budget: Budget) -> Result<crate::cx::Cx, SpawnError> {
        let inner = self.try_inner()?;
        Ok(build_request_cx_from_inner(&inner, budget))
    }
}

/// Executor-side completion lease for a runtime-handle task.
///
/// Mailbox admission owns a second lease through its cancellation callback.
/// Dropping the stored future before invoking that callback therefore cannot
/// transiently publish a generic shutdown result ahead of the specific
/// admission-cancellation reason. Once the final live producer disappears
/// without a terminal value, the join is completed as shutdown and its waker
/// is dispatched.
struct JoinProducer<T> {
    state: Arc<Mutex<JoinState<T>>>,
    active: bool,
}

impl<T> JoinProducer<T> {
    fn new(state: Arc<Mutex<JoinState<T>>>) -> Self {
        {
            let mut guard = lock_state(&state);
            guard.producers = guard
                .producers
                .checked_add(1)
                .expect("runtime join producer count overflow");
        }
        Self {
            state,
            active: true,
        }
    }

    fn complete(mut self, output: std::thread::Result<T>) {
        let waker = {
            let state = Arc::clone(&self.state);
            let mut guard = lock_state(&state);
            let published = guard.result.is_none() && guard.cancel_reason.is_none();
            if published {
                guard.result = Some(output);
            }
            self.release_locked(&mut guard);
            if published { guard.waker.take() } else { None }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn cancel(mut self, reason: crate::types::CancelReason) {
        let waker = {
            let state = Arc::clone(&self.state);
            let mut guard = lock_state(&state);
            let published = guard.result.is_none() && guard.cancel_reason.is_none();
            if published {
                let legacy_payload = format!("spawn cancelled before admission: {reason}");
                guard.cancel_reason = Some(reason);
                guard.result = Some(Err(Box::new(legacy_payload)));
            }
            self.release_locked(&mut guard);
            if published { guard.waker.take() } else { None }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn release_locked(&mut self, guard: &mut JoinState<T>) {
        debug_assert!(self.active, "join producer released twice");
        debug_assert!(guard.producers > 0, "join producer count underflow");
        self.active = false;
        guard.producers = guard
            .producers
            .checked_sub(1)
            .expect("runtime join producer count underflow");
    }
}

impl<T> Drop for JoinProducer<T> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let waker = {
            let state = Arc::clone(&self.state);
            let mut guard = lock_state(&state);
            self.release_locked(&mut guard);
            if guard.producers == 0 && guard.result.is_none() && guard.cancel_reason.is_none() {
                guard.cancel_reason = Some(crate::types::CancelReason::shutdown());
                guard.waker.take()
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct ThreadWaker {
    thread: std::thread::Thread,
    woken: std::sync::atomic::AtomicBool,
}

use std::task::Wake;
impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.woken.store(true, std::sync::atomic::Ordering::Release);
        self.thread.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, std::sync::atomic::Ordering::Release);
        self.thread.unpark();
    }
}

fn current_timer_driver_for_block_on() -> Option<TimerDriverHandle> {
    crate::cx::Cx::current().and_then(|cx| cx.timer_driver())
}

fn process_current_block_on_timers() -> bool {
    let fired = current_timer_driver_for_block_on().is_some_and(|timer| timer.process_timers() > 0);
    if fired
        && let Some(inner) = Runtime::current_handle().and_then(|handle| handle.try_inner().ok())
    {
        inner.scheduler.wake_all();
    }
    fired
}

fn next_block_on_timer_park_duration(timer: &TimerDriverHandle) -> Option<Duration> {
    let deadline = timer.next_deadline()?;
    let now = timer.now();
    if deadline <= now {
        Some(Duration::ZERO)
    } else {
        Some(Duration::from_nanos(deadline.duration_since(now)))
    }
}

const BLOCK_ON_RUNTIME_RECHECK_INTERVAL: Duration = Duration::from_millis(1);

/// Closed regions and completed races a native runtime keeps in its
/// oracle-hydration histories (see `RuntimeState::bound_oracle_histories`).
const NATIVE_ORACLE_HISTORY_LIMIT: usize = 1024;

fn current_runtime_has_live_tasks() -> bool {
    let caller = crate::cx::Cx::current();
    let has_other_live_tasks = |tasks: &crate::runtime::TaskTable| {
        let caller_is_live = caller.as_ref().is_some_and(|cx| {
            tasks.task(cx.task_id()).is_some_and(|record| {
                !record.state.is_terminal()
                    && record
                        .cx_inner
                        .as_ref()
                        .is_some_and(|inner| Arc::ptr_eq(inner, &cx.inner))
            })
        });
        // A registered caller cannot create a new timer while it is parked.
        // Counting its own record would turn every otherwise-idle block_on
        // into a 1 ms poll loop and hide missing cancellation wakeups.
        tasks.live_task_count() > usize::from(caller_is_live)
    };
    Runtime::current_handle()
        .and_then(|handle| handle.try_inner().ok())
        .is_some_and(|inner| {
            let embedded_live = {
                let state = inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                has_other_live_tasks(&state.tasks)
            };
            if embedded_live {
                return true;
            }
            // E1.2 subsystem 3d (E1.1 row B12): a dispatch-table runtime's
            // live tasks reside in the external shard-A table (sequential
            // B then A; the state lock is released above).
            inner.scheduler.dispatch_task_table().is_some_and(|table| {
                has_other_live_tasks(
                    &table
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                )
            })
        })
}

/// Cancellation wakeup for a registered `block_on` caller.
///
/// A worker installs a cancellation waker for every task it polls; this thread
/// is the caller's only executor, so it registers its own. Otherwise root
/// cancellation cannot unpark a caller that waits on a primitive with no
/// cancellation waker of its own (an mpsc receive, a semaphore acquire), and a
/// root drain waits out its full timeout (asupersync-h64i97).
struct CallerCancelWake {
    cx: crate::cx::Cx,
    token: crate::cx::CancelWakerToken,
}

impl CallerCancelWake {
    fn new(cx: &crate::cx::Cx, waker: &Waker) -> Self {
        Self {
            cx: cx.clone(),
            token: cx.refresh_cancel_waker(None, waker),
        }
    }
}

impl Drop for CallerCancelWake {
    fn drop(&mut self) {
        self.cx.clear_cancel_waker(self.token);
    }
}

fn run_future_with_budget<F: Future>(
    future: F,
    poll_budget: u32,
    cancel_owner: Option<&crate::cx::Cx>,
) -> F::Output {
    let thread = std::thread::current();
    let thread_waker = Arc::new(ThreadWaker {
        thread,
        woken: std::sync::atomic::AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&thread_waker));
    let _cancel_wake = cancel_owner.map(|cx| CallerCancelWake::new(cx, &waker));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let mut polls = 0u32;
    let budget = poll_budget.max(1);
    let mut consecutive_budget_exhaustions: u32 = 0;

    loop {
        let _ = process_current_block_on_timers();
        // Clear the woken flag BEFORE polling. This tracks if the future
        // wakes itself during the poll or immediately after.
        thread_waker
            .woken
            .store(false, std::sync::atomic::Ordering::Relaxed);

        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {
                if thread_waker
                    .woken
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    // The future was woken without parking. This indicates a spin.
                    polls = polls.saturating_add(1);
                    if polls >= budget {
                        // Budget exhausted: the future keeps returning Pending despite
                        // immediate wakeups. Use exponential backoff sleep to prevent a
                        // tight spin loop.
                        consecutive_budget_exhaustions =
                            consecutive_budget_exhaustions.saturating_add(1);
                        let backoff_ms = match consecutive_budget_exhaustions {
                            1 => 1,
                            2 => 5,
                            _ => 25,
                        };
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                        polls = 0;
                    }
                } else {
                    // Not woken. We can safely park. The task is yielding to the OS,
                    // so it is NOT in a tight spin loop. We must reset the spin counters
                    // to prevent penalizing long-lived futures that genuinely wait.
                    polls = 0;
                    consecutive_budget_exhaustions = 0;

                    if process_current_block_on_timers()
                        || thread_waker
                            .woken
                            .load(std::sync::atomic::Ordering::Acquire)
                    {
                        continue;
                    }

                    if let Some(timer) = current_timer_driver_for_block_on() {
                        match next_block_on_timer_park_duration(&timer) {
                            Some(duration) => {
                                if !duration.is_zero() {
                                    std::thread::park_timeout(duration);
                                }
                            }
                            None if current_runtime_has_live_tasks() => {
                                std::thread::park_timeout(BLOCK_ON_RUNTIME_RECHECK_INTERVAL);
                            }
                            None => std::thread::park(),
                        }
                    } else {
                        std::thread::park();
                    }
                }
            }
        }
    }
}

fn build_request_cx_from_inner(inner: &Arc<RuntimeInner>, budget: Budget) -> crate::cx::Cx {
    // br-asupersync-3lk5n2: was `TaskId::new_ephemeral()`, which
    // drew from a process-global counter and randomised the
    // request-scoped TaskId across replays + across sibling
    // runtimes in the same process. The per-runtime counter
    // restores intra-runtime determinism. The task is still not
    // registered in `state.tasks` — that's a deeper refactor — but
    // the determinism breach is closed.
    let task = inner.next_request_task_id();
    let (
        observability,
        io_driver,
        timer_driver,
        blocking_pool,
        logical_clock,
        entropy,
        trace,
        loser_drain_history,
        spawn_gateway,
        pending_spawns,
        task_pressure,
    ) = {
        let guard = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timer_driver = guard.timer_driver_handle();
        let logical_clock = guard
            .logical_clock_mode()
            .build_handle(timer_driver.clone());
        (
            guard.observability_for_task(inner.root_region, task),
            guard.io_driver_handle(),
            timer_driver,
            guard.blocking_pool_handle(),
            logical_clock,
            guard.entropy_source().fork(task),
            guard.trace_handle(),
            guard.loser_drain_history_handle(),
            guard.spawn_gateway(),
            guard
                .region(inner.root_region)
                .map(crate::record::RegionRecord::pending_spawn_handle),
            guard.task_pressure(),
        )
    };

    // br-asupersync-zc5865: the gateway + root-region pending-spawn counter
    // must ride this Cx, or `Cx::spawn`/`Cx::spawn_in` inside `block_on`
    // (the `#[asupersync::main]` body) fail with `RuntimeUnavailable` while
    // the runtime's workers sit idle. Spawned children are admitted through
    // the mailbox into `root_region` as ordinary registered tasks; only this
    // request-scoped parent stays unregistered.
    let request_cx = crate::cx::Cx::new_with_drivers(
        inner.root_region,
        task,
        budget,
        observability,
        io_driver,
        None,
        timer_driver,
        Some(entropy),
    )
    .with_blocking_pool_handle(blocking_pool)
    .with_logical_clock(logical_clock)
    .with_spawn_gateway(spawn_gateway)
    .with_pending_spawn_counter(pending_spawns);
    // While resource sampling runs, the block_on body sees its pressure too.
    let request_cx = match task_pressure {
        Some(pressure) => request_cx.with_pressure(pressure),
        None => request_cx,
    };
    request_cx.set_trace_buffer(trace);
    request_cx.set_loser_drain_history_handle(loser_drain_history);
    request_cx
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "builder_inline_tests.rs"]
mod tests;

// Opt-in obligation leak monitoring (br-asupersync-bi2462.150.2). This block
// follows the test module so that the unsafe-boundary ledger's line locators
// in this file stay where they are.
impl Runtime {
    /// Enables an obligation leak monitor for this runtime: a
    /// [`crate::obligation::eprocess::LeakMonitor::change_detector`] over
    /// `horizon` resolved obligations. The probability of a false alarm
    /// within them is at most `alpha`. Choose `horizon` to cover the whole
    /// monitored period, for example `10^9`: the detection delay grows only
    /// with its logarithm, while a short horizon makes a latched false alarm
    /// on a busy runtime likely.
    ///
    /// Every obligation the runtime commits or aborts after this call feeds
    /// the monitor its age at resolution, exactly once, and a leaked
    /// obligation raises the alarm at once. The alarm latches. Calibrate
    /// `expected_lifetime_ns` from profiled obligation durations or the
    /// containing budget's deadline; see [`crate::obligation::eprocess`]. An
    /// obligation held indefinitely is not observed until it resolves.
    /// Monitoring is off by default, and a runtime without a monitor pays one
    /// branch per resolved obligation. A second call replaces the monitor and
    /// its evidence.
    ///
    /// # Panics
    /// If `config` or `horizon` is invalid (see
    /// [`crate::obligation::eprocess::LeakMonitor::change_detector`]). They are
    /// checked before the runtime state is locked.
    pub fn enable_obligation_leak_monitor(
        &self,
        config: crate::obligation::eprocess::MonitorConfig,
        horizon: u64,
    ) {
        let _validated = crate::obligation::eprocess::LeakMonitor::change_detector(config, horizon);
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .enable_obligation_leak_monitor(config, horizon);
    }

    /// The obligation leak monitor's current snapshot, or `None` when
    /// [`Self::enable_obligation_leak_monitor`] has not been called.
    #[must_use]
    pub fn obligation_leak_monitor_snapshot(
        &self,
    ) -> Option<crate::obligation::eprocess::MonitorSnapshot> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .obligation_leak_monitor_snapshot()
    }
}
