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
//! ## Browser/WASM Status
//!
//! Browser-safe profiles can validate semantic-core closure on `wasm32`, but
//! this module does not yet expose a truthful public browser bootstrap path.
//! Runtime startup now routes through an explicit `RuntimeHostServices` seam,
//! but the builder still only ships the native std-thread host implementation.
//! Browser-facing guidance should stay on the repository-maintained Rust/WASM
//! fixture and the shipped JS/TS Browser Edition packages until a browser host
//! implementation satisfies the threadless startup contract.
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
//! | [`browser_ready_handoff_limit`](RuntimeBuilder::browser_ready_handoff_limit) | 0 (disabled) | Max ready dispatch burst before host-turn handoff |
//! | [`browser_worker_offload`](RuntimeBuilder::browser_worker_offload) | disabled | Browser worker offload policy contract |
//! | [`cancel_lane_max_streak`](RuntimeBuilder::cancel_lane_max_streak) | 16 | Max consecutive cancel dispatches |
//! | [`enable_adaptive_cancel_streak`](RuntimeBuilder::enable_adaptive_cancel_streak) | true | Enable regret-bounded adaptive cancel streak |
//! | [`adaptive_cancel_streak_epoch_steps`](RuntimeBuilder::adaptive_cancel_streak_epoch_steps) | 128 | Dispatches per adaptive epoch |
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
use crate::observability::ObservabilityConfig;
use crate::observability::metrics::MetricsProvider;
use crate::record::RegionLimits;
use crate::runtime::RuntimeState;
use crate::runtime::SpawnError;
use crate::runtime::config::RuntimeConfig;
use crate::runtime::deadline_monitor::{
    AdaptiveDeadlineConfig, DeadlineWarning, MonitorConfig, default_warning_handler,
};
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::reactor::Reactor;
use crate::runtime::scheduler::{ThreeLaneScheduler, ThreeLaneWorker};
use crate::time::TimerDriverHandle;
use crate::trace::distributed::LogicalClockMode;
use crate::types::{Budget, CancelAttributionConfig};
use crate::util::EntropySource;
#[cfg(target_arch = "wasm32")]
use js_sys::{Reflect, global};
use parking_lot::{Mutex, MutexGuard};
use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

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
        CURRENT_RUNTIME_HANDLE.with(|cell| {
            *cell.borrow_mut() = prev;
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeHostServicesKind {
    NativeStdThread,
    BrowserHost,
}

impl RuntimeHostServicesKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NativeStdThread => "native-std-thread",
            Self::BrowserHost => "browser-host",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BrowserHostServicesContract {
    required_capabilities: &'static [&'static str],
}

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

struct DeadlineMonitorHostService {
    shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DeadlineMonitorHostService {
    const fn disabled() -> Self {
        Self {
            shutdown: None,
            thread: None,
        }
    }
}

trait RuntimeHostServices: Send + Sync {
    fn kind(&self) -> RuntimeHostServicesKind;

    fn browser_contract(&self) -> BrowserHostServicesContract {
        BrowserHostServicesContract::V1
    }

    fn spawn_workers(
        &self,
        runtime: &Arc<RuntimeInner>,
        workers: Vec<ThreeLaneWorker>,
    ) -> io::Result<Vec<std::thread::JoinHandle<()>>>;

    fn start_deadline_monitor(
        &self,
        config: &RuntimeConfig,
        state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
    ) -> DeadlineMonitorHostService;
}

#[derive(Default)]
struct NativeThreadHostServices;

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
            let mut builder = std::thread::Builder::new().name(name);
            if runtime.config.thread_stack_size > 0 {
                builder = builder.stack_size(runtime.config.thread_stack_size);
            }
            let handle = builder
                .spawn(move || {
                    let _guard = ScopedRuntimeHandle::new(runtime_handle);
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
    ) -> DeadlineMonitorHostService {
        use crate::runtime::deadline_monitor::DeadlineMonitor;
        use std::sync::atomic::AtomicBool;

        let monitor_config = match config.deadline_monitor {
            Some(ref mc) if mc.enabled => mc,
            _ => return DeadlineMonitorHostService::disabled(),
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
                    let guard = dm_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let now = guard.now;
                    monitor.check(now, guard.tasks_iter().map(|(_, record)| record));
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
    ) -> DeadlineMonitorHostService {
        Self::start_deadline_monitor(config, state)
    }
}

fn default_runtime_host_services() -> Arc<dyn RuntimeHostServices> {
    Arc::new(NativeThreadHostServices::new())
}

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
    /// Anything outside the currently shipped direct-runtime contexts.
    Unknown,
}

impl BrowserRuntimeContext {
    /// Stable string label aligned with the Browser Edition package surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserMainThread => "browser_main_thread",
            Self::DedicatedWorker => "dedicated_worker",
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

#[derive(Debug, Clone, Copy)]
struct BrowserExecutionProbe {
    has_global_this: bool,
    runtime_context: BrowserRuntimeContext,
    host_role: BrowserExecutionHostRole,
    capabilities: BrowserCapabilitySnapshot,
}

impl BrowserExecutionProbe {
    const fn non_browser() -> Self {
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
        BrowserExecutionHostRole::ServiceWorker
        | BrowserExecutionHostRole::SharedWorker
        | BrowserExecutionHostRole::NonBrowserOrUnknown => BrowserRuntimeContext::Unknown,
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
            "Use the maintained browser fixture or a bridge-oriented surface instead of treating service workers as a direct runtime lane.",
        ),
        BrowserRuntimeSupportReason::SharedWorkerNotYetShipped => (
            "Rust Browser Edition does not yet ship a shared-worker direct-runtime lane.",
            "Use the maintained browser fixture or a bridge-oriented surface instead of treating shared workers as a direct runtime lane.",
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
        &[guidance],
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
        BrowserRuntimeContext::DedicatedWorker => {
            "Rust Browser Edition runtime inspection found a dedicated-worker direct-runtime context."
        }
        BrowserRuntimeContext::BrowserMainThread | BrowserRuntimeContext::Unknown => {
            "Rust Browser Edition runtime inspection found a browser main-thread direct-runtime context."
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
    io_driver: Option<IoDriverHandle>,
    timer_driver: Option<TimerDriverHandle>,
    entropy_source: Option<Arc<dyn EntropySource>>,
    host_services: Arc<dyn RuntimeHostServices>,
}

impl RuntimeBuilder {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: RuntimeConfig::default(),
            reactor: None,
            io_driver: None,
            timer_driver: None,
            entropy_source: None,
            host_services: default_runtime_host_services(),
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

    /// Enable or disable adaptive cancel-streak scheduling.
    ///
    /// When enabled, workers run a deterministic no-regret online policy that
    /// updates the base cancel streak limit across fixed-length epochs.
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
    #[allow(clippy::result_large_err)]
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
            io_driver: None,
            timer_driver: None,
            entropy_source: None,
            host_services: default_runtime_host_services(),
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
    #[allow(clippy::result_large_err)]
    pub fn from_toml_str(toml: &str) -> Result<Self, Error> {
        let toml_config = crate::runtime::env_config::parse_toml_str(toml).map_err(|e| {
            Error::new(crate::error::ErrorKind::ConfigError).with_message(e.to_string())
        })?;
        let mut config = RuntimeConfig::default();
        crate::runtime::env_config::apply_toml_config(&mut config, &toml_config);
        Ok(Self {
            config,
            reactor: None,
            io_driver: None,
            timer_driver: None,
            entropy_source: None,
            host_services: default_runtime_host_services(),
        })
    }

    /// Build a runtime from this configuration.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<Runtime, Error> {
        let Self {
            config,
            reactor,
            io_driver,
            timer_driver,
            entropy_source,
            host_services,
        } = self;
        Runtime::with_config_and_platform(
            config,
            reactor,
            io_driver,
            timer_driver,
            entropy_source,
            host_services.as_ref(),
        )
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

    /// Provide an explicit timer driver handle for runtime capability contexts.
    ///
    /// When set, this driver is installed into runtime state before root-region
    /// initialization, so spawned tasks inherit it through `Cx`.
    #[must_use]
    pub fn with_timer_driver(mut self, driver: TimerDriverHandle) -> Self {
        self.timer_driver = Some(driver);
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
        mut config: RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
        io_driver: Option<IoDriverHandle>,
        timer_driver: Option<TimerDriverHandle>,
        entropy_source: Option<Arc<dyn EntropySource>>,
        host_services: &dyn RuntimeHostServices,
    ) -> Result<Self, Error> {
        config.normalize();
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (reactor, io_driver, timer_driver, entropy_source);
            Err(Error::new(crate::error::ErrorKind::ConfigError)
                .with_message(unsupported_browser_bootstrap_message(host_services)))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (inner, workers) = RuntimeInner::new(
                config,
                reactor,
                io_driver,
                timer_driver,
                entropy_source,
                host_services,
            );
            let inner = Arc::new(inner);
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

    /// Run a future to completion on the current thread.
    ///
    /// While the future is being polled, a thread-local [`RuntimeHandle`] is
    /// available via [`Runtime::current_handle`]. This allows futures inside
    /// `block_on` to spawn tasks onto the real scheduler without having to
    /// thread the handle through every layer.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        let _guard = ScopedRuntimeHandle::new(self.handle());
        run_future_with_budget(future, self.inner.config.poll_budget)
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
    #[must_use]
    pub fn current_handle() -> Option<RuntimeHandle> {
        CURRENT_RUNTIME_HANDLE.with(|cell| cell.borrow().clone())
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
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    fn weak(inner: &Arc<RuntimeInner>) -> Self {
        Self {
            inner: RuntimeHandleRef::Weak(Arc::downgrade(inner)),
        }
    }

    fn try_inner(&self) -> Result<Arc<RuntimeInner>, SpawnError> {
        match &self.inner {
            RuntimeHandleRef::Strong(inner) => Ok(Arc::clone(inner)),
            RuntimeHandleRef::Weak(inner) => inner.upgrade().ok_or(SpawnError::RuntimeUnavailable),
        }
    }

    /// Spawn a task from outside async context.
    ///
    /// Panics if the runtime is no longer available or if the root region
    /// rejects admission. Use [`RuntimeHandle::try_spawn`] to handle those
    /// failures explicitly.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.try_spawn(future)
            .expect("failed to create runtime task")
    }

    /// Spawn a task from outside async context, returning runtime-availability
    /// or admission errors instead of panicking.
    pub fn try_spawn<F>(&self, future: F) -> Result<JoinHandle<F::Output>, SpawnError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.try_inner()?.spawn(future)
    }

    /// Spawn a task with a [`Cx`](crate::cx::Cx) from outside async context.
    ///
    /// Creates a child Cx in the runtime's root region and passes it to the
    /// factory closure. The Cx participates in structured cancellation: it
    /// will observe cancellation when the runtime shuts down.
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
    /// Creates a child Cx in the runtime's root region and passes it to the
    /// factory closure. The Cx participates in structured cancellation: it
    /// will observe cancellation when the runtime shuts down.
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
        inner.blocking_pool.as_ref().map(|pool| pool.spawn(f))
    }

    /// Returns a handle to the blocking pool, if configured and the runtime is
    /// still alive.
    #[must_use]
    pub fn blocking_handle(&self) -> Option<crate::runtime::blocking_pool::BlockingPoolHandle> {
        self.try_inner().ok()?.blocking_handle()
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
        guard.result.is_some() || Arc::strong_count(&self.state) == 1
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
                if Arc::strong_count(&this.state) == 1 {
                    // The executor side was dropped without producing a result or panic payload
                    // (e.g. the runtime was shut down and tasks were force-cancelled).
                    this.completed = true;
                    drop(guard);
                    panic!("task was dropped or cancelled before completion");
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
    fn initialize_runtime_state(
        config: &RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
        io_driver: Option<IoDriverHandle>,
        timer_driver: Option<TimerDriverHandle>,
        entropy_source: Option<Arc<dyn EntropySource>>,
    ) -> RuntimeState {
        let mut runtime_state = reactor.map_or_else(
            || RuntimeState::new_with_metrics(config.metrics_provider.clone()),
            |reactor| {
                RuntimeState::with_reactor_and_metrics(reactor, config.metrics_provider.clone())
            },
        );
        if let Some(driver) = io_driver {
            runtime_state.set_io_driver(driver);
        }
        if let Some(driver) = timer_driver {
            runtime_state.set_timer_driver(driver);
        }
        if let Some(source) = entropy_source {
            runtime_state.set_entropy_source(source);
        }
        runtime_state
    }

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
            guard.set_timer_driver(TimerDriverHandle::with_wall_clock());
        }
        let root = guard.create_root_region(Budget::INFINITE);
        if let Some(limits) = config.root_region_limits.clone() {
            let _ = guard.set_region_limits(root, limits);
        }
        root
    }

    fn new(
        config: RuntimeConfig,
        reactor: Option<Arc<dyn Reactor>>,
        io_driver: Option<IoDriverHandle>,
        timer_driver: Option<TimerDriverHandle>,
        entropy_source: Option<Arc<dyn EntropySource>>,
        host_services: &dyn RuntimeHostServices,
    ) -> (Self, Vec<ThreeLaneWorker>) {
        // Runtime currently instantiates the unified RuntimeState path.
        // ShardedState exists behind migration work, but there is not yet a
        // RuntimeConfig layout switch wired here (see bd-2f7uj runbook).
        let runtime_state = Self::initialize_runtime_state(
            &config,
            reactor,
            io_driver,
            timer_driver,
            entropy_source,
        );
        let state = Arc::new(crate::sync::ContendedMutex::new(
            "runtime_state",
            runtime_state,
        ));
        let root_region = Self::initialize_root_region(&config, &state);

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
        scheduler.set_browser_ready_handoff_limit(config.browser_ready_handoff_limit);
        scheduler.set_adaptive_cancel_streak(
            config.enable_adaptive_cancel_streak,
            config.adaptive_cancel_streak_epoch_steps,
        );
        let workers = scheduler.take_workers();

        let deadline_monitor = host_services.start_deadline_monitor(&config, &state);

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
                scheduler,
                worker_threads: Mutex::new(Vec::new()),
                root_region,
                blocking_pool,
                deadline_monitor_shutdown: deadline_monitor.shutdown,
                deadline_monitor_thread: deadline_monitor.thread,
            },
            workers,
        )
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
            ..Default::default()
        };
        Some(crate::runtime::blocking_pool::BlockingPool::with_config(
            config.blocking.min_threads,
            config.blocking.max_threads,
            options,
        ))
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
            let result = CatchUnwind { inner: future }.await;
            complete_task(&join_state_for_task, result);
        };

        let task_id = {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (task_id, _handle) = guard.create_task(self.root_region, Budget::new(), wrapped)?;
            task_id
        };

        self.scheduler.inject_ready(task_id, Budget::new().priority);

        Ok(JoinHandle::new(join_state))
    }

    /// Spawn a task with a [`Cx`](crate::cx::Cx) passed to the factory closure.
    ///
    /// The Cx is created in the root region and linked to the runtime's
    /// cancellation tree, so it will observe cancellation when the runtime
    /// shuts down.
    fn spawn_with_cx<F, Fut>(&self, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce(crate::cx::Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        use crate::runtime::StoredTask;
        use crate::types::Outcome;

        let task_id = {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            let (task_id, _handle, cx, _result_tx) =
                guard.create_task_infrastructure::<()>(self.root_region, Budget::new())?;

            let future = f(cx);

            let wrapped = async move {
                future.await;
                Outcome::Ok(())
            };

            guard.store_spawned_task(task_id, StoredTask::new_with_id(wrapped, task_id));
            drop(guard);

            task_id
        };

        self.scheduler.inject_ready(task_id, Budget::new().priority);

        Ok(())
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
    let mut future = std::pin::pin!(future);
    let mut polls = 0u32;
    let budget = poll_budget.max(1);
    let mut consecutive_budget_exhaustions: u32 = 0;

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {
                polls = polls.saturating_add(1);
                if polls >= budget {
                    // Budget exhausted: the future keeps returning Pending despite
                    // being woken.  Use exponential backoff sleep to prevent a
                    // tight spin loop (yield_now is nearly a no-op on idle
                    // systems and was the root cause of runaway CPU usage).
                    consecutive_budget_exhaustions =
                        consecutive_budget_exhaustions.saturating_add(1);
                    let backoff_ms = match consecutive_budget_exhaustions {
                        1 => 1,
                        2 => 5,
                        _ => 25,
                    };
                    std::thread::sleep(Duration::from_millis(backoff_ms));
                    polls = 0;
                } else {
                    // Park until woken.  Do NOT reset consecutive_budget_exhaustions
                    // here: thread::park() can return instantly when an unpark token
                    // is already pending (common during waker storms), so a reset
                    // would defeat the exponential backoff.
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
#[allow(unsafe_code)]
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
        match payload.downcast::<String>() {
            Ok(message) => *message,
            Err(payload) => payload.downcast::<&'static str>().map_or_else(
                |_| "<non-string panic payload>".to_string(),
                |message| (*message).to_string(),
            ),
        }
    }

    #[derive(Default)]
    struct RecordingNativeHostServices {
        worker_bootstrap_calls: AtomicUsize,
        deadline_monitor_calls: AtomicUsize,
    }

    impl RuntimeHostServices for RecordingNativeHostServices {
        fn kind(&self) -> RuntimeHostServicesKind {
            RuntimeHostServicesKind::NativeStdThread
        }

        fn spawn_workers(
            &self,
            runtime: &Arc<RuntimeInner>,
            workers: Vec<ThreeLaneWorker>,
        ) -> io::Result<Vec<std::thread::JoinHandle<()>>> {
            self.worker_bootstrap_calls.fetch_add(1, Ordering::SeqCst);
            NativeThreadHostServices::spawn_worker_threads(runtime, workers)
        }

        fn start_deadline_monitor(
            &self,
            config: &RuntimeConfig,
            state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
        ) -> DeadlineMonitorHostService {
            self.deadline_monitor_calls.fetch_add(1, Ordering::SeqCst);
            NativeThreadHostServices::start_deadline_monitor(config, state)
        }
    }

    #[test]
    fn browser_host_services_contract_pins_threadless_startup_requirements() {
        let contract = BrowserHostServicesContract::V1;
        assert!(
            contract
                .required_capabilities
                .contains(&"host-turn wakeups"),
            "browser contract must require host-turn wakeups"
        );
        assert!(
            contract
                .required_capabilities
                .contains(&"worker bootstrap hooks"),
            "browser contract must require worker bootstrap hooks"
        );
        assert!(
            contract
                .required_capabilities
                .contains(&"timer/deadline driving"),
            "browser contract must require timer/deadline driving"
        );
        assert!(
            contract
                .required_capabilities
                .contains(&"lane-health callbacks"),
            "browser contract must require lane-health callbacks"
        );
        assert!(
            contract
                .diagnostic_requirements()
                .contains("threadless startup"),
            "diagnostics should explain why the browser path is threadless"
        );
    }

    #[test]
    fn browser_bootstrap_error_describes_host_services_requirements() {
        let message = unsupported_browser_bootstrap_message(&NativeThreadHostServices::new());
        assert!(
            message.contains("RuntimeHostServices seam"),
            "diagnostic should name the startup seam: {message}"
        );
        assert!(
            message.contains("native-std-thread"),
            "diagnostic should name the shipped native host implementation: {message}"
        );
        assert!(
            message.contains("host-turn wakeups") && message.contains("lane-health callbacks"),
            "diagnostic should enumerate the missing browser host requirements: {message}"
        );
        assert!(
            message.contains("threadless startup"),
            "diagnostic should explain the threadless browser target: {message}"
        );
    }

    fn browser_probe(
        host_role: BrowserExecutionHostRole,
        runtime_context: BrowserRuntimeContext,
        has_window: bool,
        has_document: bool,
        has_webassembly: bool,
    ) -> BrowserExecutionProbe {
        BrowserExecutionProbe {
            has_global_this: true,
            runtime_context,
            host_role,
            capabilities: BrowserCapabilitySnapshot {
                execution_api: BrowserExecutionApiCapabilities {
                    has_abort_controller: true,
                    has_fetch: true,
                    has_webassembly,
                },
                dom: BrowserDomCapabilities {
                    has_document,
                    has_window,
                },
                storage: BrowserStorageCapabilities {
                    has_indexed_db: false,
                    has_local_storage: false,
                },
                transport: BrowserTransportCapabilities {
                    has_web_socket: true,
                    has_web_transport: false,
                },
            },
        }
    }

    #[test]
    fn browser_execution_ladder_selects_main_thread_lane_for_supported_probe() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            None,
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert!(
            diagnostics.supported,
            "main-thread probe should be supported"
        );
        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "main-thread probe should select the main-thread direct-runtime lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::Supported,
            "supported probe should keep the supported reason code"
        );
        assert_eq!(
            diagnostics.host_role,
            BrowserExecutionHostRole::BrowserMainThread,
            "host role should stay on the browser main thread"
        );
        assert_eq!(
            diagnostics.runtime_context,
            BrowserRuntimeContext::BrowserMainThread,
            "runtime context should stay on the browser main thread"
        );
        let selected_candidate = diagnostics
            .candidates
            .iter()
            .find(|candidate| candidate.selected)
            .expect("one selected candidate");
        assert_eq!(
            selected_candidate.lane_id,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "selected candidate should match the selected lane"
        );
    }

    #[test]
    fn browser_execution_ladder_preserves_truthful_lane_when_preferred_lane_mismatches() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime),
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "preferred-lane mismatch must not override the truthful selected lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::Supported,
            "preferred-lane mismatch should not rewrite the truthful selected reason"
        );
        assert!(
            diagnostics
                .message
                .contains("lane.browser.dedicated_worker.direct_runtime"),
            "message should name the preferred lane mismatch"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("switch entrypoints")),
            "guidance should explain how to satisfy the preferred lane"
        );
    }

    #[test]
    fn browser_execution_ladder_keeps_prerequisite_reason_when_preferred_lane_fails_closed() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            Some(BrowserExecutionLane::BrowserMainThreadDirectRuntime),
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                false,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "missing prerequisites should still fail closed to lane.unsupported"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::MissingWebAssembly,
            "preferred-lane mismatch must preserve the real missing-prerequisite reason"
        );
        assert!(
            diagnostics.message.contains("missing_webassembly"),
            "message should preserve the real missing-prerequisite reason code"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("Restore the reported Browser Edition prerequisites")),
            "guidance should explain how to restore the missing prerequisite"
        );
    }

    #[test]
    fn browser_execution_ladder_distinguishes_intentional_fail_closed_preference() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            Some(BrowserExecutionLane::Unsupported),
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "preferred fallback pin must not override the truthful direct-runtime lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::Supported,
            "preferred fallback pin should not rewrite the selected reason"
        );
        assert!(
            diagnostics
                .message
                .contains("lower-priority fail-closed fallback"),
            "message should describe the explicit fallback pin instead of a host-role mismatch"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("Only pin")),
            "guidance should explain that lane.unsupported is an intentional fail-closed pin"
        );
    }

    #[test]
    fn browser_execution_ladder_fail_closes_non_browser_probe() {
        let diagnostics =
            build_browser_execution_ladder_from_probe(None, BrowserExecutionProbe::non_browser());

        assert!(!diagnostics.supported, "non-browser probe must fail closed");
        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "non-browser probe must demote to the terminal unsupported lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::MissingGlobalThis,
            "non-browser probe should surface the missing-global diagnostic"
        );
    }

    #[test]
    fn browser_execution_ladder_keeps_missing_webassembly_visible_in_candidates() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            None,
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                false,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "missing WebAssembly must fail closed to the unsupported lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::MissingWebAssembly,
            "selected reason should preserve the real missing-prerequisite failure"
        );
        let direct_candidate = diagnostics
            .candidates
            .iter()
            .find(|candidate| {
                candidate.lane_id == BrowserExecutionLane::BrowserMainThreadDirectRuntime
            })
            .expect("main-thread candidate");
        assert_eq!(
            direct_candidate.reason_code,
            BrowserExecutionReasonCode::CandidatePrerequisiteMissing,
            "direct lane candidate should remain a prerequisite-missing rejection"
        );
    }

    #[test]
    fn runtime_builder_routes_native_startup_through_host_services_seam() {
        init_test_logging();

        let host_services = Arc::new(RecordingNativeHostServices::default());
        let seam: Arc<dyn RuntimeHostServices> = host_services.clone();
        let mut builder = RuntimeBuilder::current_thread();
        builder.host_services = seam;

        let runtime = builder.build().expect("runtime build");
        let result = runtime.block_on(runtime.handle().spawn(async { 7u32 }));

        assert_eq!(result, 7, "runtime should remain usable through the seam");
        assert_eq!(
            host_services.worker_bootstrap_calls.load(Ordering::SeqCst),
            1,
            "worker startup should route through the host-services seam"
        );
        assert_eq!(
            host_services.deadline_monitor_calls.load(Ordering::SeqCst),
            1,
            "deadline-monitor startup should route through the host-services seam"
        );
    }

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

    #[test]
    fn runtime_builder_platform_seams_propagate_into_task_contexts() {
        init_test_logging();

        let io_driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
        {
            let mut driver = io_driver.lock();
            let _ = driver.register_waker(noop_waker());
        }

        let virtual_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(42)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(virtual_clock);

        let runtime = RuntimeBuilder::current_thread()
            .with_io_driver(io_driver)
            .with_timer_driver(timer_driver)
            .with_entropy_source(Arc::new(crate::util::DetEntropy::new(1234)))
            .build()
            .expect("runtime build");

        let (io_present, timer_now, entropy_source) =
            runtime.block_on(runtime.handle().spawn(async {
                let cx = Cx::current().expect("task context");
                (
                    cx.io_driver_handle().is_some(),
                    cx.timer_driver().map(|driver| driver.now()),
                    cx.entropy().source_id(),
                )
            }));
        assert!(io_present, "injected io driver should be visible in Cx");
        assert_eq!(
            timer_now,
            Some(Time::from_secs(42)),
            "injected virtual timer should be visible in Cx"
        );
        assert_eq!(
            entropy_source, "deterministic",
            "injected entropy source should flow through Cx"
        );

        let guard = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state_io = guard.io_driver_handle().expect("runtime io driver");
        assert_eq!(
            state_io.waker_count(),
            1,
            "runtime should retain the injected io driver instance"
        );
        let state_timer = guard.timer_driver_handle().expect("runtime timer driver");
        assert_eq!(
            state_timer.now(),
            Time::from_secs(42),
            "runtime should retain the injected timer driver instance"
        );
        drop(guard);
    }

    #[test]
    fn runtime_builder_platform_seams_override_reactor_defaults() {
        init_test_logging();

        let custom_driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
        {
            let mut driver = custom_driver.lock();
            let _ = driver.register_waker(noop_waker());
        }
        let custom_timer = TimerDriverHandle::with_virtual_clock(Arc::new(
            crate::time::VirtualClock::starting_at(Time::from_secs(7)),
        ));

        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(Arc::new(LabReactor::new()))
            .with_io_driver(custom_driver)
            .with_timer_driver(custom_timer)
            .build()
            .expect("runtime build");

        let guard = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let io = guard.io_driver_handle().expect("io driver");
        assert_eq!(
            io.waker_count(),
            1,
            "explicit io driver should override default reactor wiring"
        );
        let timer = guard.timer_driver_handle().expect("timer driver");
        assert_eq!(
            timer.now(),
            Time::from_secs(7),
            "explicit timer driver should override wall-clock default"
        );
        drop(guard);
    }

    #[test]
    fn runtime_builder_browser_worker_offload_policy_round_trips() {
        init_test_logging();

        let runtime = RuntimeBuilder::current_thread()
            .browser_worker_offload_enabled(true)
            .browser_worker_offload_limits(2048, 4)
            .browser_worker_transfer_mode(
                crate::runtime::config::WorkerTransferMode::CloneStructured,
            )
            .browser_worker_cancellation_mode(
                crate::runtime::config::WorkerCancellationMode::BestEffortAbort,
            )
            .build()
            .expect("runtime build");

        let offload = runtime.config().browser_worker_offload;
        assert!(offload.enabled, "offload policy should be enabled");
        assert_eq!(
            offload.min_task_cost, 2048,
            "min task cost should round-trip"
        );
        assert_eq!(
            offload.max_in_flight, 4,
            "in-flight limit should round-trip"
        );
        assert_eq!(
            offload.transfer_mode,
            crate::runtime::config::WorkerTransferMode::CloneStructured,
            "transfer mode should round-trip"
        );
        assert_eq!(
            offload.cancellation_mode,
            crate::runtime::config::WorkerCancellationMode::BestEffortAbort,
            "cancellation mode should round-trip"
        );
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn runtime_builder_fail_closes_browser_bootstrap_on_wasm() {
        let err = RuntimeBuilder::current_thread()
            .build()
            .expect_err("public browser bootstrap must fail closed on wasm");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::ConfigError,
            "unsupported wasm browser bootstrap must surface as ConfigError"
        );
        let message = err.to_string();
        assert!(
            message.contains("browser bootstrap")
                && message.contains("RuntimeHostServices seam")
                && message.contains("threadless startup"),
            "error should explain why wasm browser bootstrap is still unsupported: {message}"
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
                .unwrap_or_else(std::sync::PoisonError::into_inner)
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
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                trace.record_event(|seq| TraceEvent::io_requested(seq, now, io_key, interest_bits));
            }
            trace.record_event(|seq| TraceEvent::io_ready(seq, now, io_key, event.ready.bits()));
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
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::set_var(k, v) };
            }
            let result = f();
            for (k, _) in vars {
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::remove_var(k) };
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
            ENV_CANCEL_LANE_MAX_STREAK,
            ENV_ENABLE_GOVERNOR,
            ENV_GOVERNOR_INTERVAL,
            ENV_ENABLE_ADAPTIVE_CANCEL_STREAK,
            ENV_ADAPTIVE_CANCEL_EPOCH_STEPS,
            ENV_BLOCKING_MIN_THREADS,
            ENV_BLOCKING_MAX_THREADS,
            ENV_ENABLE_PARKING,
            ENV_POLL_BUDGET,
        ] {
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::remove_var(var) };
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
            assert_eq!(
                runtime.config().cancel_lane_max_streak,
                defaults.cancel_lane_max_streak
            );
            assert_eq!(runtime.config().enable_governor, defaults.enable_governor);
            assert_eq!(
                runtime.config().governor_interval,
                defaults.governor_interval
            );
            assert_eq!(
                runtime.config().enable_adaptive_cancel_streak,
                defaults.enable_adaptive_cancel_streak
            );
            assert_eq!(
                runtime.config().adaptive_cancel_streak_epoch_steps,
                defaults.adaptive_cancel_streak_epoch_steps
            );
            assert_eq!(runtime.config().poll_budget, defaults.poll_budget);
        });
    }

    #[test]
    fn with_env_overrides_applies_governor_settings() {
        use crate::runtime::env_config::*;
        with_envs(
            &[(ENV_ENABLE_GOVERNOR, "true"), (ENV_GOVERNOR_INTERVAL, "41")],
            || {
                let runtime = RuntimeBuilder::new()
                    .with_env_overrides()
                    .expect("env overrides")
                    .build()
                    .expect("runtime build");
                assert!(runtime.config().enable_governor);
                assert_eq!(runtime.config().governor_interval, 41);
            },
        );
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_builds_runtime() {
        let toml = r"
[scheduler]
worker_threads = 2
poll_budget = 32
";
        let runtime = RuntimeBuilder::from_toml_str(toml)
            .expect("from_toml_str")
            .build()
            .expect("runtime build");
        assert_eq!(runtime.config().worker_threads, 2);
        assert_eq!(runtime.config().poll_budget, 32);
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_applies_governor_settings() {
        let toml = r"
[scheduler]
enable_governor = true
governor_interval = 80
";
        let runtime = RuntimeBuilder::from_toml_str(toml)
            .expect("from_toml_str")
            .build()
            .expect("runtime build");
        assert!(runtime.config().enable_governor);
        assert_eq!(runtime.config().governor_interval, 80);
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_with_programmatic_override() {
        let toml = r"
[scheduler]
worker_threads = 8
";
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
            let toml = r"
[scheduler]
worker_threads = 16
";
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
            let toml = r"
[scheduler]
worker_threads = 16
";
            let runtime = RuntimeBuilder::from_toml_str(toml)
                .expect("from_toml_str")
                .with_env_overrides()
                .expect("env overrides")
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 8);
        });
    }

    // -----------------------------------------------------------------------
    // Issue #21: Thread-local RuntimeHandle from block_on
    // -----------------------------------------------------------------------

    #[test]
    fn current_handle_available_inside_block_on() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");

        runtime.block_on(async {
            let handle = Runtime::current_handle();
            assert!(
                handle.is_some(),
                "current_handle should be Some inside block_on"
            );
        });
    }

    #[test]
    fn current_handle_none_outside_block_on() {
        init_test_logging();
        assert!(
            Runtime::current_handle().is_none(),
            "current_handle should be None outside block_on"
        );
    }

    #[test]
    fn current_handle_spawn_completes_on_scheduler() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime build");

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        let result = runtime.block_on(async move {
            let handle = Runtime::current_handle().expect("inside block_on");
            let join = handle.spawn(async move {
                flag_clone.store(true, Ordering::SeqCst);
                99u32
            });
            join.await
        });

        assert_eq!(result, 99);
        assert!(flag.load(Ordering::SeqCst), "spawned task should have run");
    }

    #[test]
    fn current_handle_available_inside_spawned_task() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime build");

        let outer = runtime.handle().spawn(async {
            let handle = Runtime::current_handle().expect("spawned task should see runtime handle");
            handle.spawn(async { 42u32 }).await
        });

        assert_eq!(runtime.block_on(outer), 42);
    }

    #[test]
    fn current_handle_restored_after_block_on() {
        init_test_logging();
        // Before block_on: None.
        assert!(Runtime::current_handle().is_none());

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");

        runtime.block_on(async {
            assert!(Runtime::current_handle().is_some());
        });

        // After block_on: restored to None.
        assert!(Runtime::current_handle().is_none());
    }

    #[test]
    fn weak_current_handle_try_spawn_returns_runtime_unavailable_after_drop() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");

        let weak_handle = runtime.block_on(runtime.handle().spawn(async {
            Runtime::current_handle().expect("spawned task should see runtime handle")
        }));
        assert!(
            matches!(weak_handle.inner, RuntimeHandleRef::Weak(_)),
            "worker-thread current_handle should remain weak to avoid runtime cycles"
        );

        drop(runtime);

        let result = weak_handle.try_spawn(async { 42u8 });
        assert!(
            matches!(result, Err(SpawnError::RuntimeUnavailable)),
            "stale weak handle should return RuntimeUnavailable instead of panicking"
        );
        assert!(
            weak_handle.spawn_blocking(|| {}).is_none(),
            "stale weak handle should not expose a blocking pool"
        );
        assert!(
            weak_handle.blocking_handle().is_none(),
            "stale weak handle should not yield a blocking handle"
        );
    }

    #[test]
    fn thread_callbacks_do_not_fire_for_block_on_caller() {
        init_test_logging();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        let started_for_callback = Arc::clone(&started);
        let stopped_for_callback = Arc::clone(&stopped);

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .on_thread_start(move || {
                started_for_callback.fetch_add(1, Ordering::SeqCst);
            })
            .on_thread_stop(move || {
                stopped_for_callback.fetch_add(1, Ordering::SeqCst);
            })
            .build()
            .expect("runtime build");

        let join = runtime.handle().spawn(async { 7u8 });
        assert_eq!(runtime.block_on(join), 7);
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "only the worker thread should trigger on_thread_start"
        );

        drop(runtime);

        assert_eq!(
            stopped.load(Ordering::SeqCst),
            1,
            "only the worker thread should trigger on_thread_stop"
        );
    }

    #[test]
    fn join_handle_second_poll_panics_after_success_and_stays_finished() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::new()));
        complete_task(&state, Ok(7_u8));

        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = join.as_mut().poll(&mut cx);
        assert!(matches!(first, Poll::Ready(7)));
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after consuming the result"
        );

        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let message =
            panic_payload_to_string(second.expect_err("second poll must fail closed by panicking"));
        assert!(
            message.contains("runtime::JoinHandle polled after completion"),
            "second poll should panic with completion misuse message, got {message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after post-completion misuse"
        );
    }

    #[test]
    fn join_handle_pending_then_completion_then_repoll_panics_and_stays_finished() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::new()));
        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = join.as_mut().poll(&mut cx);
        assert!(matches!(first, Poll::Pending));
        assert!(
            !join.as_ref().get_ref().is_finished(),
            "join handle should not be finished while task is still pending"
        );

        complete_task(&state, Ok(11_u8));

        let second = join.as_mut().poll(&mut cx);
        assert!(matches!(second, Poll::Ready(11)));
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should become finished after ready output is observed"
        );

        let third = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let message =
            panic_payload_to_string(third.expect_err("third poll must fail closed by panicking"));
        assert!(
            message.contains("runtime::JoinHandle polled after completion"),
            "post-completion repoll should panic with completion misuse message, got {message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after post-completion misuse"
        );
    }

    #[test]
    fn join_handle_second_poll_panics_after_task_panic_and_stays_finished() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::<u8>::new()));
        complete_task(&state, Err(Box::new("join-handle boom")));

        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let first_message =
            panic_payload_to_string(first.expect_err("first poll should resume the task panic"));
        assert!(
            first_message.contains("join-handle boom"),
            "first poll should preserve the original task panic, got {first_message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after propagating a task panic"
        );

        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let second_message =
            panic_payload_to_string(second.expect_err("second poll must fail closed by panicking"));
        assert!(
            second_message.contains("runtime::JoinHandle polled after completion"),
            "second poll should panic with completion misuse message, got {second_message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after post-completion misuse"
        );
    }

    #[test]
    fn join_handle_is_finished_after_executor_side_disappears() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::<u8>::new()));
        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        drop(state);

        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should report terminal dropped-task state as finished"
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll_after_drop = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let message = panic_payload_to_string(
            poll_after_drop.expect_err("poll after executor-side disappearance must panic"),
        );
        assert!(
            message.contains("task was dropped or cancelled before completion"),
            "poll after executor-side disappearance should preserve dropped-task panic, got {message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after the terminal dropped-task poll"
        );
    }
}
