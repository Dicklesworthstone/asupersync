//! Runtime configuration types.
//!
//! These types hold the concrete values that drive runtime behavior. In most
//! cases you should use [`RuntimeBuilder`](super::builder::RuntimeBuilder) to
//! construct a runtime rather than creating a [`RuntimeConfig`] directly.
//!
//! # Defaults
//!
//! | Field | Default |
//! |-------|---------|
//! | `worker_threads` | 4 (host-independent default) |
//! | `thread_stack_size` | 2 MiB |
//! | `thread_name_prefix` | `"asupersync-worker"` |
//! | `global_queue_limit` | 0 (unbounded) |
//! | `steal_batch_size` | 16 |
//! | `enable_parking` | true |
//! | `poll_budget` | 128 |
//! | `capacity_hints` | `None` (auto from `worker_threads`) |
//! | `trace_storage_profile` | `TraceStorageProfile::Default` |
//! | `browser_ready_handoff_limit` | 0 (disabled) |
//! | `browser_worker_offload` | disabled, min cost 1024, max in-flight 16 |
//! | `root_region_limits` | `None` |
//! | `observability` | `None` |
//! | `enable_governor` | `false` |
//! | `governor_interval` | `32` |
//! | `enable_read_biased_region_snapshot` | `false` |
//! | `enable_adaptive_cancel_streak` | `true` |
//! | `adaptive_cancel_streak_epoch_steps` | `128` |

use crate::observability::ObservabilityConfig;
use crate::observability::metrics::{MetricsProvider, NoOpMetrics};
use crate::record::RegionLimits;
use crate::runtime::deadline_monitor::{DeadlineWarning, MonitorConfig};
use crate::trace::distributed::LogicalClockMode;
use crate::types::CancelAttributionConfig;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// Configuration for the blocking pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingPoolAffinityProfile {
    /// Do not apply cohort-aware queue routing.
    Disabled,
    /// Bias tasks toward same-cohort blocking workers before spilling globally.
    CohortBiased {
        /// Soft cap for tasks queued on a preferred cohort before global spillover.
        local_queue_soft_limit: usize,
        /// Maximum consecutive local dequeues before re-checking global spill work.
        spill_check_interval: usize,
    },
}

impl BlockingPoolAffinityProfile {
    /// Normalize profile parameters to safe non-zero bounds.
    pub fn normalize(&mut self) {
        if let Self::CohortBiased {
            local_queue_soft_limit,
            spill_check_interval,
        } = self
        {
            if *local_queue_soft_limit == 0 {
                *local_queue_soft_limit = 1;
            }
            if *spill_check_interval == 0 {
                *spill_check_interval = 1;
            }
        }
    }
}

impl Default for BlockingPoolAffinityProfile {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Configuration for the blocking pool.
#[derive(Clone, Default)]
pub struct BlockingPoolConfig {
    /// Minimum number of blocking threads.
    pub min_threads: usize,
    /// Maximum number of blocking threads.
    pub max_threads: usize,
    /// Optional cohort-aware affinity profile for blocking work.
    pub affinity_profile: BlockingPoolAffinityProfile,
}

impl BlockingPoolConfig {
    /// Normalize configuration values to safe defaults.
    pub fn normalize(&mut self) {
        if self.max_threads < self.min_threads {
            self.max_threads = self.min_threads;
        }
        self.affinity_profile.normalize();
    }
}

/// Initial arena capacities for runtime state tables.
///
/// These hints only change initial allocation envelopes; they do not change
/// scheduler ordering, task lifecycle semantics, or cancellation behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeCapacityHints {
    /// Initial task-table arena capacity.
    pub task_capacity: usize,
    /// Initial region-table arena capacity.
    pub region_capacity: usize,
    /// Initial obligation-table arena capacity.
    pub obligation_capacity: usize,
}

impl RuntimeCapacityHints {
    /// Historical default task-table capacity.
    pub const DEFAULT_TASK_CAPACITY: usize = 512;
    /// Historical default region-table capacity.
    pub const DEFAULT_REGION_CAPACITY: usize = 128;
    /// Historical default obligation-table capacity.
    pub const DEFAULT_OBLIGATION_CAPACITY: usize = 256;

    const TASKS_PER_WORKER: usize = 128;
    const REGIONS_PER_WORKER: usize = 32;
    const OBLIGATIONS_PER_WORKER: usize = 64;

    /// Creates explicit capacity hints.
    #[inline]
    #[must_use]
    pub const fn new(
        task_capacity: usize,
        region_capacity: usize,
        obligation_capacity: usize,
    ) -> Self {
        Self {
            task_capacity,
            region_capacity,
            obligation_capacity,
        }
    }

    #[inline]
    fn scale_ceil(value: usize, numerator: usize, denominator: usize) -> usize {
        value
            .saturating_mul(numerator)
            .saturating_add(denominator.saturating_sub(1))
            / denominator.max(1)
    }

    #[inline]
    fn scaled_per_worker(workers: usize, per_worker: usize, floor: usize) -> usize {
        workers.saturating_mul(per_worker).max(floor)
    }

    /// Derives capacity hints from an expected live-task count.
    ///
    /// The task arena gets 50% headroom to absorb bursts without immediate
    /// reallocation. Region and obligation tables scale from the same estimate
    /// with lower multipliers because they are typically sparser than tasks.
    #[must_use]
    pub fn from_expected_concurrent_tasks(expected_tasks: usize) -> Self {
        let expected_tasks = expected_tasks.max(1);
        Self {
            task_capacity: Self::scale_ceil(expected_tasks, 3, 2).max(Self::DEFAULT_TASK_CAPACITY),
            region_capacity: Self::scale_ceil(expected_tasks, 1, 4)
                .max(Self::DEFAULT_REGION_CAPACITY),
            obligation_capacity: Self::scale_ceil(expected_tasks, 1, 2)
                .max(Self::DEFAULT_OBLIGATION_CAPACITY),
        }
    }

    /// Derives auto-scaled capacity hints from the configured worker count.
    ///
    /// This preserves the historical 4-worker baseline (512/128/256) while
    /// scaling linearly for larger runtimes.
    #[must_use]
    pub fn for_worker_threads(worker_threads: usize) -> Self {
        let worker_threads = worker_threads.max(1);
        Self {
            task_capacity: Self::scaled_per_worker(
                worker_threads,
                Self::TASKS_PER_WORKER,
                Self::DEFAULT_TASK_CAPACITY,
            ),
            region_capacity: Self::scaled_per_worker(
                worker_threads,
                Self::REGIONS_PER_WORKER,
                Self::DEFAULT_REGION_CAPACITY,
            ),
            obligation_capacity: Self::scaled_per_worker(
                worker_threads,
                Self::OBLIGATIONS_PER_WORKER,
                Self::DEFAULT_OBLIGATION_CAPACITY,
            ),
        }
    }

    /// Clamps explicit hints to safe minimums.
    pub fn normalize(&mut self) {
        self.task_capacity = self.task_capacity.max(Self::DEFAULT_TASK_CAPACITY);
        self.region_capacity = self.region_capacity.max(Self::DEFAULT_REGION_CAPACITY);
        self.obligation_capacity = self
            .obligation_capacity
            .max(Self::DEFAULT_OBLIGATION_CAPACITY);
    }
}

impl Default for RuntimeCapacityHints {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_TASK_CAPACITY,
            Self::DEFAULT_REGION_CAPACITY,
            Self::DEFAULT_OBLIGATION_CAPACITY,
        )
    }
}

/// Readable storage profiles for runtime trace and diagnostic retention.
///
/// These profiles are deliberately policy-only: they scale hot/cold trace
/// buffers without changing scheduling semantics, task ordering, or
/// cancellation behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStorageProfile {
    /// Historical baseline tuned for general-purpose hosts.
    Default,
    /// High-retention profile for 256GB-class hosts.
    LargeMemory256G,
}

/// Parse error for [`TraceStorageProfile`] text values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseTraceStorageProfileError;

impl fmt::Display for ParseTraceStorageProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown trace storage profile")
    }
}

impl std::error::Error for ParseTraceStorageProfileError {}

/// Operator-facing budget summary for a [`TraceStorageProfile`].
///
/// The byte totals are planning estimates derived from explicit per-slot
/// assumptions so operators can see the memory tradeoff before enabling a
/// richer profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceStorageBudget {
    /// Selected storage profile.
    pub profile: TraceStorageProfile,
    /// Hot trace ring capacity (event slots).
    pub trace_event_slots: usize,
    /// Cancellation trace retention slots.
    pub cancellation_trace_slots: usize,
    /// Distributed trace retention slots.
    pub distributed_trace_slots: usize,
    /// Planning assumption for one hot trace slot.
    pub assumed_trace_event_bytes: usize,
    /// Planning assumption for one retained cancellation trace.
    pub assumed_cancellation_trace_bytes: usize,
    /// Planning assumption for one retained distributed trace.
    pub assumed_distributed_trace_bytes: usize,
}

impl TraceStorageBudget {
    /// Estimated bytes consumed by the hot trace ring.
    #[must_use]
    pub const fn estimated_hot_bytes(&self) -> usize {
        self.trace_event_slots
            .saturating_mul(self.assumed_trace_event_bytes)
    }

    /// Estimated bytes consumed by cold retained traces.
    #[must_use]
    pub const fn estimated_cold_bytes(&self) -> usize {
        self.cancellation_trace_slots
            .saturating_mul(self.assumed_cancellation_trace_bytes)
            .saturating_add(
                self.distributed_trace_slots
                    .saturating_mul(self.assumed_distributed_trace_bytes),
            )
    }

    /// Estimated total bytes across hot and cold trace storage.
    #[must_use]
    pub const fn estimated_total_bytes(&self) -> usize {
        self.estimated_hot_bytes()
            .saturating_add(self.estimated_cold_bytes())
    }
}

impl TraceStorageProfile {
    /// Historical runtime trace ring size.
    pub const DEFAULT_TRACE_BUFFER_CAPACITY: usize = 4_096;
    /// Large-memory runtime trace ring size.
    pub const LARGE_MEMORY_TRACE_BUFFER_CAPACITY: usize = 262_144;

    const DEFAULT_CANCELLATION_TRACE_SLOTS: usize = 10_000;
    const LARGE_MEMORY_CANCELLATION_TRACE_SLOTS: usize = 200_000;

    const DEFAULT_DISTRIBUTED_TRACE_SLOTS: usize = 10_000;
    const LARGE_MEMORY_DISTRIBUTED_TRACE_SLOTS: usize = 200_000;

    const DEFAULT_DISTRIBUTED_TRACE_MAX_AGE_SECS: u64 = 60 * 60;
    const LARGE_MEMORY_DISTRIBUTED_TRACE_MAX_AGE_SECS: u64 = 24 * 60 * 60;

    const ASSUMED_TRACE_EVENT_BYTES: usize = 256;
    const ASSUMED_CANCELLATION_TRACE_BYTES: usize = 2_048;
    const ASSUMED_DISTRIBUTED_TRACE_BYTES: usize = 1_536;

    /// Returns the stable operator-facing name for the profile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::LargeMemory256G => "large-memory-256g",
        }
    }

    /// Returns the hot trace ring capacity for the profile.
    #[must_use]
    pub const fn trace_buffer_capacity(self) -> usize {
        match self {
            Self::Default => Self::DEFAULT_TRACE_BUFFER_CAPACITY,
            Self::LargeMemory256G => Self::LARGE_MEMORY_TRACE_BUFFER_CAPACITY,
        }
    }

    /// Returns the cancellation trace retention limit for the profile.
    #[must_use]
    pub const fn cancellation_trace_slots(self) -> usize {
        match self {
            Self::Default => Self::DEFAULT_CANCELLATION_TRACE_SLOTS,
            Self::LargeMemory256G => Self::LARGE_MEMORY_CANCELLATION_TRACE_SLOTS,
        }
    }

    /// Returns the distributed trace retention limit for the profile.
    #[must_use]
    pub const fn distributed_trace_slots(self) -> usize {
        match self {
            Self::Default => Self::DEFAULT_DISTRIBUTED_TRACE_SLOTS,
            Self::LargeMemory256G => Self::LARGE_MEMORY_DISTRIBUTED_TRACE_SLOTS,
        }
    }

    /// Returns the distributed-trace eviction horizon for the profile.
    #[must_use]
    pub const fn distributed_trace_max_age(self) -> std::time::Duration {
        match self {
            Self::Default => {
                std::time::Duration::from_secs(Self::DEFAULT_DISTRIBUTED_TRACE_MAX_AGE_SECS)
            }
            Self::LargeMemory256G => {
                std::time::Duration::from_secs(Self::LARGE_MEMORY_DISTRIBUTED_TRACE_MAX_AGE_SECS)
            }
        }
    }

    /// Returns an operator-facing storage budget summary for this profile.
    #[must_use]
    pub const fn budget(self) -> TraceStorageBudget {
        TraceStorageBudget {
            profile: self,
            trace_event_slots: self.trace_buffer_capacity(),
            cancellation_trace_slots: self.cancellation_trace_slots(),
            distributed_trace_slots: self.distributed_trace_slots(),
            assumed_trace_event_bytes: Self::ASSUMED_TRACE_EVENT_BYTES,
            assumed_cancellation_trace_bytes: Self::ASSUMED_CANCELLATION_TRACE_BYTES,
            assumed_distributed_trace_bytes: Self::ASSUMED_DISTRIBUTED_TRACE_BYTES,
        }
    }
}

impl fmt::Display for TraceStorageProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TraceStorageProfile {
    type Err = ParseTraceStorageProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "default" => Ok(Self::Default),
            "large-memory-256g" | "large_memory_256g" => Ok(Self::LargeMemory256G),
            _ => Err(ParseTraceStorageProfileError),
        }
    }
}

/// Payload transfer strategy for browser worker offload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerTransferMode {
    /// Clone structured payloads (structured clone semantics).
    CloneStructured,
    /// Only allow transferable payload classes; reject others.
    TransferableOnly,
}

/// Cancellation propagation policy across browser worker boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCancellationMode {
    /// Request cancellation and continue without waiting for worker ack.
    BestEffortAbort,
    /// Require explicit worker-side acknowledgement before completion.
    RequireAck,
}

/// Browser worker offload contract for CPU-heavy runtime paths.
///
/// This is an opt-in scaffold contract for wasm/browser profiles.
/// It defines how payload ownership and cancellation are represented
/// before transport-level worker wiring is fully implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserWorkerOffloadConfig {
    /// Enable worker offload for eligible runtime operations.
    pub enabled: bool,
    /// Minimum estimated task cost required before offload is considered.
    pub min_task_cost: u32,
    /// Maximum number of in-flight worker requests.
    pub max_in_flight: usize,
    /// Payload transfer strategy across the worker boundary.
    pub transfer_mode: WorkerTransferMode,
    /// Cancellation propagation policy for offloaded operations.
    pub cancellation_mode: WorkerCancellationMode,
    /// Require caller-owned payload buffers before dispatch.
    pub require_owned_payloads: bool,
}

impl BrowserWorkerOffloadConfig {
    /// Normalize configuration values to safe defaults.
    pub fn normalize(&mut self) {
        if self.min_task_cost == 0 {
            self.min_task_cost = 1;
        }
        if self.max_in_flight == 0 {
            self.max_in_flight = 1;
        }
    }
}

impl Default for BrowserWorkerOffloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_task_cost: 1024,
            max_in_flight: 16,
            transfer_mode: WorkerTransferMode::TransferableOnly,
            cancellation_mode: WorkerCancellationMode::RequireAck,
            require_owned_payloads: true,
        }
    }
}

/// Response policy when obligation leaks are detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationLeakResponse {
    /// Panic immediately with diagnostic details.
    Panic,
    /// Log the leak and continue.
    Log,
    /// Suppress logging for leaks (still marked as leaked).
    Silent,
    /// Automatically abort leaked obligations and log a warning.
    ///
    /// Unlike `Log`, this performs best-effort cleanup by aborting the
    /// obligation (transitioning to `Aborted` instead of `Leaked`),
    /// which releases associated resources. Useful in production where
    /// crashing is unacceptable but resource cleanup is important.
    Recover,
}

/// Escalation policy for obligation leaks.
///
/// When configured, the runtime tracks the cumulative number of leaks
/// and escalates from the base response to a stricter one after a
/// threshold is reached. For example, a service might log the first
/// few leaks but panic after 10 to prevent cascading resource exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeakEscalation {
    /// Number of leaks that trigger escalation.
    pub threshold: u64,
    /// Response to switch to after the threshold is reached.
    pub escalate_to: ObligationLeakResponse,
}

impl LeakEscalation {
    /// Creates a new escalation policy.
    #[inline]
    #[must_use]
    pub const fn new(threshold: u64, escalate_to: ObligationLeakResponse) -> Self {
        let threshold = if threshold == 0 { 1 } else { threshold };
        Self {
            threshold,
            escalate_to,
        }
    }
}

/// Explicit worker-to-cohort mapping for topology-aware scheduling.
///
/// The mapping is fully caller-supplied so locality behavior remains
/// deterministic and replay-safe across hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCohortMapping {
    /// Cohort identifier for each worker index.
    pub worker_to_cohort: Vec<usize>,
}

impl WorkerCohortMapping {
    /// Creates a new explicit worker-to-cohort mapping.
    #[must_use]
    pub fn new(worker_to_cohort: Vec<usize>) -> Self {
        Self { worker_to_cohort }
    }

    /// Returns the number of cohorts implied by the mapping.
    #[must_use]
    pub fn cohort_count(&self) -> usize {
        self.worker_to_cohort
            .iter()
            .copied()
            .max()
            .map_or(0, |max| max.saturating_add(1))
    }

    /// Verifies that the mapping exactly covers the configured workers.
    pub fn validate_for_workers(&self, worker_threads: usize) -> Result<(), &'static str> {
        if self.worker_to_cohort.len() != worker_threads {
            return Err("worker cohort map length must match worker_threads");
        }
        if worker_threads == 0 || self.worker_to_cohort.is_empty() {
            return Err("worker cohort map must contain at least one worker");
        }
        Ok(())
    }
}

/// Runtime configuration.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Number of worker threads (default: available parallelism).
    pub worker_threads: usize,
    /// Optional explicit worker-to-cohort mapping for locality-aware steals.
    pub worker_cohort_map: Option<WorkerCohortMapping>,
    /// Stack size per worker thread (default: 2MB).
    pub thread_stack_size: usize,
    /// Name prefix for worker threads.
    pub thread_name_prefix: String,
    /// Global queue size limit (0 = unbounded).
    pub global_queue_limit: usize,
    /// Work stealing batch size.
    pub steal_batch_size: usize,
    /// Blocking pool configuration.
    pub blocking: BlockingPoolConfig,
    /// Enable parking for idle workers.
    pub enable_parking: bool,
    /// Time slice for cooperative yielding (polls).
    pub poll_budget: u32,
    /// Initial arena capacities for the runtime's task, region, and obligation tables.
    ///
    /// When `None`, capacities auto-scale from `worker_threads` using the
    /// historical 4-worker baseline (512 tasks / 128 regions / 256 obligations).
    pub capacity_hints: Option<RuntimeCapacityHints>,
    /// Trace and diagnostic retention policy for the runtime.
    pub trace_storage_profile: TraceStorageProfile,
    /// Browser pump fairness bound for consecutive ready dispatches.
    ///
    /// When non-zero, browser-style single-thread pumps can yield to the host
    /// queue after this many ready-lane dispatches in a burst, preventing
    /// unbounded host-turn monopolization under adversarial ready floods.
    /// `0` disables forced handoff behavior.
    pub browser_ready_handoff_limit: usize,
    /// Browser worker offload contract for CPU-heavy runtime paths.
    pub browser_worker_offload: BrowserWorkerOffloadConfig,
    /// Maximum consecutive cancel-lane dispatches before yielding to other lanes.
    pub cancel_lane_max_streak: usize,
    /// Logical clock mode used for trace causal ordering.
    ///
    /// When `None`, the runtime chooses a default:
    /// - No reactor: Lamport (deterministic lab-friendly)
    /// - With reactor: Hybrid (wall-clock + logical)
    pub logical_clock_mode: Option<LogicalClockMode>,
    /// Admission limits applied to the root region (if set).
    pub root_region_limits: Option<RegionLimits>,
    /// Callback executed when a worker thread starts.
    pub on_thread_start: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Callback executed when a worker thread stops.
    pub on_thread_stop: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Deadline monitoring configuration (when enabled).
    pub deadline_monitor: Option<MonitorConfig>,
    /// Warning callback for deadline monitoring.
    pub deadline_warning_handler: Option<Arc<dyn Fn(DeadlineWarning) + Send + Sync>>,
    /// Metrics provider for runtime instrumentation.
    pub metrics_provider: Arc<dyn MetricsProvider>,
    /// Optional runtime observability configuration.
    pub observability: Option<ObservabilityConfig>,
    /// Limits for cancellation attribution cause chains.
    ///
    /// Used to bound memory growth when cancellation cascades across deep
    /// region trees or large cancellation graphs.
    pub cancel_attribution: CancelAttributionConfig,
    /// Response policy for obligation leaks detected at runtime.
    pub obligation_leak_response: ObligationLeakResponse,
    /// Optional escalation policy for obligation leaks.
    ///
    /// When set, the runtime escalates from `obligation_leak_response` to
    /// `escalation.escalate_to` after `escalation.threshold` leaks.
    pub leak_escalation: Option<LeakEscalation>,
    /// Enable the Lyapunov governor for scheduling suggestions.
    ///
    /// When enabled, the scheduler periodically snapshots runtime state and
    /// consults the governor for lane-ordering hints. When disabled (default),
    /// scheduling behavior is identical to the ungoverned baseline.
    pub enable_governor: bool,
    /// Number of scheduling steps between governor snapshots (default: 32).
    ///
    /// Lower values increase responsiveness but add snapshot overhead.
    /// Only relevant when `enable_governor` is true.
    pub governor_interval: u32,
    /// Enable the cached draining-region fast path for governor/diagnostics snapshots.
    ///
    /// When enabled, `RuntimeState` maintains a conservative cached count for
    /// regions in `Draining`/`Finalizing`. Read-heavy snapshot paths can use
    /// that count directly, while write-heavy or invalidated cases fall back to
    /// the authoritative region-table scan.
    pub enable_read_biased_region_snapshot: bool,
    /// Enable adaptive cancel-lane streak selection.
    ///
    /// When enabled, workers use a deterministic Hedge-style online policy
    /// to adapt the base cancel streak limit across epochs.
    pub enable_adaptive_cancel_streak: bool,
    /// Number of dispatches per adaptive cancel-streak epoch.
    ///
    /// Lower values react faster but add policy-update overhead.
    /// Only relevant when `enable_adaptive_cancel_streak` is true.
    pub adaptive_cancel_streak_epoch_steps: u32,
}

impl RuntimeConfig {
    /// Normalize configuration values to safe defaults.
    pub fn normalize(&mut self) {
        if self.worker_threads == 0 {
            self.worker_threads = 1;
        }
        if self.thread_stack_size == 0 {
            self.thread_stack_size = 2 * 1024 * 1024;
        }
        if self.steal_batch_size == 0 {
            self.steal_batch_size = 1;
        }
        if self.poll_budget == 0 {
            self.poll_budget = 1;
        }
        if let Some(hints) = self.capacity_hints.as_mut() {
            hints.normalize();
        }
        if self.cancel_lane_max_streak == 0 {
            self.cancel_lane_max_streak = 1;
        }
        if self.governor_interval == 0 {
            self.governor_interval = 1;
        }
        if self.adaptive_cancel_streak_epoch_steps == 0 {
            self.adaptive_cancel_streak_epoch_steps = 1;
        }
        self.browser_worker_offload.normalize();
        if let Some(escalation) = self.leak_escalation.as_mut() {
            if escalation.threshold == 0 {
                escalation.threshold = 1;
            }
        }
        if self.thread_name_prefix.is_empty() {
            self.thread_name_prefix = "asupersync-worker".to_string();
        }
        self.blocking.normalize();
    }

    /// Resolves the effective runtime-state table capacities.
    ///
    /// Explicit hints win. Otherwise, capacities scale from `worker_threads`
    /// while preserving the historical 4-worker floor.
    #[must_use]
    pub fn resolved_capacity_hints(&self) -> RuntimeCapacityHints {
        self.capacity_hints
            .unwrap_or_else(|| RuntimeCapacityHints::for_worker_threads(self.worker_threads))
    }

    /// Returns the operator-facing trace storage budget for the selected profile.
    #[must_use]
    pub const fn trace_storage_budget(&self) -> TraceStorageBudget {
        self.trace_storage_profile.budget()
    }

    /// Default worker thread count for a `RuntimeConfig::default()`.
    ///
    /// br-asupersync-ry2trw: this is now a deterministic constant,
    /// NOT `std::thread::available_parallelism()`. The pre-fix shape
    /// silently coupled the runtime's parallelism to the host's CPU
    /// count + cgroup quota + cpuset mask + sibling-tenant cgroup
    /// throttling. That broke replay determinism (a 4-CPU CI host
    /// produced different dispatch ordering than a 32-CPU dev box)
    /// and exposed a multi-tenant influence surface (a noisy
    /// neighbour adjusting the shared cgroup quota changed the
    /// runtime's worker count). Both shapes violate the asupersync
    /// "no ambient authority" invariant.
    ///
    /// Production callers that want host-scaled parallelism opt in EXPLICITLY
    /// by passing [`ambient_default_worker_threads`] to
    /// [`RuntimeBuilder::worker_threads`], making the wall-CPU dependency
    /// visible at the call site.
    pub const DEFAULT_WORKER_THREADS: usize = 4;

    pub(crate) const fn default_worker_threads() -> usize {
        Self::DEFAULT_WORKER_THREADS
    }
}

/// Returns the host's `available_parallelism()` value (clamped to >= 1)
/// for callers that want host-scaled parallelism.
///
/// br-asupersync-ry2trw: this is the explicit, grep-able opt-in for
/// host-scaled worker counts. The previous default silently used
/// this value, which broke replay determinism + exposed a multi-tenant
/// influence surface (cgroup quota / cpuset / sibling-tenant throttling
/// silently changed the runtime's parallelism). The fall-back when
/// `available_parallelism()` errors (e.g. unsupported platform, sandboxed
/// process) is `DEFAULT_WORKER_THREADS = 4` rather than 1, so a sandbox
/// that returns Err does not silently single-thread the runtime.
///
/// Production callers must invoke this function ONLY when they want
/// host-scaled parallelism; replay-stable test harnesses must instead
/// hard-code `worker_threads(N)` to a fixed value.
#[must_use]
pub fn ambient_default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(
            RuntimeConfig::DEFAULT_WORKER_THREADS,
            std::num::NonZeroUsize::get,
        )
        .max(1)
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: Self::default_worker_threads(),
            worker_cohort_map: None,
            thread_stack_size: 2 * 1024 * 1024,
            thread_name_prefix: "asupersync-worker".to_string(),
            global_queue_limit: 0,
            steal_batch_size: 16,
            blocking: BlockingPoolConfig::default(),
            enable_parking: true,
            poll_budget: 128,
            capacity_hints: None,
            trace_storage_profile: TraceStorageProfile::Default,
            browser_ready_handoff_limit: 0,
            browser_worker_offload: BrowserWorkerOffloadConfig::default(),
            cancel_lane_max_streak: 16,
            logical_clock_mode: None,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::default(),
            // Plan v4 §I2 makes "no obligation leaks" a non-negotiable invariant;
            // the runtime fails fast (Panic) on detection by default. Tests and
            // lab harnesses opt in to Log/Silent/Recover via the builder
            // (br-asupersync-gi61n1).
            obligation_leak_response: ObligationLeakResponse::Panic,
            leak_escalation: None,
            enable_governor: false,
            governor_interval: 32,
            enable_read_biased_region_snapshot: false,
            enable_adaptive_cancel_streak: true,
            adaptive_cancel_streak_epoch_steps: 128,
        }
    }
}

/// Objective used when selecting a host profile automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostProfilePlannerObjective {
    /// Prefer locality- and throughput-oriented bundles.
    LocalityFirst,
    /// Prefer latency-protection bundles under overload.
    TailProtectionFirst,
    /// Prefer observability retention bundles on large hosts.
    EvidenceRetentionFirst,
}

impl HostProfilePlannerObjective {
    /// Stable operator-facing name for the objective.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalityFirst => "locality_first",
            Self::TailProtectionFirst => "tail_protection_first",
            Self::EvidenceRetentionFirst => "evidence_retention_first",
        }
    }

    #[must_use]
    pub const fn candidate_order(self) -> &'static [HostProfileId] {
        match self {
            Self::LocalityFirst => &[
                HostProfileId::LocalityFirst64C256G,
                HostProfileId::TailProtectionFirst64C256G,
                HostProfileId::LargeMemoryEvidenceRetention256G,
                HostProfileId::ConservativeBaseline,
            ],
            Self::TailProtectionFirst => &[
                HostProfileId::TailProtectionFirst64C256G,
                HostProfileId::LocalityFirst64C256G,
                HostProfileId::LargeMemoryEvidenceRetention256G,
                HostProfileId::ConservativeBaseline,
            ],
            Self::EvidenceRetentionFirst => &[
                HostProfileId::LargeMemoryEvidenceRetention256G,
                HostProfileId::LocalityFirst64C256G,
                HostProfileId::TailProtectionFirst64C256G,
                HostProfileId::ConservativeBaseline,
            ],
        }
    }
}

impl fmt::Display for HostProfilePlannerObjective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Explicit runtime bundle identifiers for large-host planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostProfileId {
    /// Preserve the stock runtime defaults and conservative controller stances.
    ConservativeBaseline,
    /// Bias for cohort locality on 64-core / 256GB hosts.
    LocalityFirst64C256G,
    /// Bias for tail-latency protection under overload on large hosts.
    TailProtectionFirst64C256G,
    /// Bias for evidence retention on 256GB-class hosts.
    LargeMemoryEvidenceRetention256G,
}

impl HostProfileId {
    /// Stable operator-facing profile identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConservativeBaseline => "conservative_baseline",
            Self::LocalityFirst64C256G => "locality_first_64c_256g",
            Self::TailProtectionFirst64C256G => "tail_protection_first_64c_256g",
            Self::LargeMemoryEvidenceRetention256G => "large_memory_evidence_retention_256g",
        }
    }

    #[must_use]
    pub const fn required_cpu_cores(self) -> usize {
        match self {
            Self::ConservativeBaseline => 1,
            Self::LocalityFirst64C256G
            | Self::TailProtectionFirst64C256G
            | Self::LargeMemoryEvidenceRetention256G => 64,
        }
    }

    #[must_use]
    pub const fn required_memory_gib(self) -> usize {
        match self {
            Self::ConservativeBaseline => 1,
            Self::LocalityFirst64C256G
            | Self::TailProtectionFirst64C256G
            | Self::LargeMemoryEvidenceRetention256G => 256,
        }
    }

    #[must_use]
    pub const fn required_evidence(self) -> &'static [HostProfileEvidenceKind] {
        match self {
            Self::ConservativeBaseline => &[],
            Self::LocalityFirst64C256G
            | Self::TailProtectionFirst64C256G
            | Self::LargeMemoryEvidenceRetention256G => &[
                HostProfileEvidenceKind::Brownout,
                HostProfileEvidenceKind::OtlpBrownout,
                HostProfileEvidenceKind::AdmissionSteering,
                HostProfileEvidenceKind::AdaptiveBatchSizing,
                HostProfileEvidenceKind::BlockingPoolAffinity,
                HostProfileEvidenceKind::TraceStorageProfile,
            ],
        }
    }

    #[must_use]
    pub const fn rationale(self) -> &'static [&'static str] {
        match self {
            Self::ConservativeBaseline => &[
                "Preserve the stock runtime defaults until proof-backed large-host controls are available.",
                "Use this bundle when operator telemetry is incomplete or when any child proof drifts out of contract.",
            ],
            Self::LocalityFirst64C256G => &[
                "Exploit explicit worker cohorts and blocking-pool affinity to keep hot work local on 64-core / 256GB hosts.",
                "Widen capacity hints and trace retention together so the locality gains are not erased by avoidable reallocation or diagnostic churn.",
            ],
            Self::TailProtectionFirst64C256G => &[
                "Trade some throughput headroom for tighter queue pressure and smaller steal batches when overload latency is the primary operator concern.",
                "Keep proof-backed brownout, OTLP shedding, admission steering, adaptive batching, and blocking affinity in the same explainable bundle.",
            ],
            Self::LargeMemoryEvidenceRetention256G => &[
                "Spend 256GB-class memory budget on larger trace retention without reintroducing hidden runtime heuristics.",
                "Keep the same proof-backed controller set, but bias the config bundle toward richer postmortem evidence on large hosts.",
            ],
        }
    }

    #[must_use]
    pub const fn when_not_to_use(self) -> &'static [&'static str] {
        match self {
            Self::ConservativeBaseline => &[
                "Do not pin the conservative baseline on a large host once proof-backed locality, overload, and retention bundles are validated for your workload.",
            ],
            Self::LocalityFirst64C256G => &[
                "Do not use when the host has fewer than 64 cores or less than 256 GiB of RAM.",
                "Do not use when the shared controller proofs are missing, stale, or unvalidated.",
                "Do not use if operator policy requires the smallest possible queue envelope over locality wins.",
            ],
            Self::TailProtectionFirst64C256G => &[
                "Do not use when throughput maximization matters more than overload latency protection.",
                "Do not use when the shared controller proofs are missing, stale, or unvalidated.",
                "Do not use on hosts smaller than the 64-core / 256 GiB target class.",
            ],
            Self::LargeMemoryEvidenceRetention256G => &[
                "Do not use on hosts without a real 256 GiB memory envelope.",
                "Do not use when operator policy forbids the additional retention budget or when the retention proofs are missing.",
            ],
        }
    }
}

impl fmt::Display for HostProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Named proof surfaces consumed by the host-profile planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostProfileEvidenceKind {
    /// Brownout proof for optional runtime surfaces.
    Brownout,
    /// OTLP brownout/shedding proof.
    OtlpBrownout,
    /// Admission steering proof.
    AdmissionSteering,
    /// Adaptive batch sizing proof.
    AdaptiveBatchSizing,
    /// Blocking-pool affinity proof.
    BlockingPoolAffinity,
    /// Large-memory trace storage proof.
    TraceStorageProfile,
}

impl HostProfileEvidenceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Brownout => "brownout",
            Self::OtlpBrownout => "otlp_brownout",
            Self::AdmissionSteering => "admission_steering",
            Self::AdaptiveBatchSizing => "adaptive_batch_sizing",
            Self::BlockingPoolAffinity => "blocking_pool_affinity",
            Self::TraceStorageProfile => "trace_storage_profile",
        }
    }
}

impl fmt::Display for HostProfileEvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Proof artifact reference for one controller surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfileEvidenceArtifact {
    /// Stable artifact or contract identifier for the proof surface.
    pub artifact_id: String,
    /// Contract version used by the proof surface.
    pub contract_version: String,
    /// Whether the proof was validated successfully.
    pub validation_passed: bool,
}

impl HostProfileEvidenceArtifact {
    fn validate(&self) -> Result<(), String> {
        if self.artifact_id.is_empty() {
            return Err("artifact_id must not be empty".to_string());
        }
        if !self.artifact_id.ends_with(".json") {
            return Err("artifact_id must end with .json".to_string());
        }
        if self.artifact_id.contains("..") {
            return Err("artifact_id must not contain parent-directory traversals".to_string());
        }
        if self
            .artifact_id
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-')))
        {
            return Err("artifact_id contains unsupported characters".to_string());
        }
        if self.contract_version.trim().is_empty() {
            return Err("contract_version must not be empty".to_string());
        }
        if !self.validation_passed {
            return Err("validation_passed is false".to_string());
        }
        Ok(())
    }
}

/// The controller-proof ledger fed into the host-profile planner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostProfileEvidenceSet {
    /// Brownout smoke-contract proof.
    pub brownout: Option<HostProfileEvidenceArtifact>,
    /// OTLP brownout/shedding smoke-contract proof.
    pub otlp_brownout: Option<HostProfileEvidenceArtifact>,
    /// Cohort-admission steering smoke-contract proof.
    pub admission_steering: Option<HostProfileEvidenceArtifact>,
    /// Adaptive batch sizing smoke-contract proof.
    pub adaptive_batch_sizing: Option<HostProfileEvidenceArtifact>,
    /// Blocking-pool affinity smoke-contract proof.
    pub blocking_pool_affinity: Option<HostProfileEvidenceArtifact>,
    /// Trace-storage profile smoke-contract proof.
    pub trace_storage_profile: Option<HostProfileEvidenceArtifact>,
}

impl HostProfileEvidenceSet {
    #[must_use]
    pub fn input_artifact_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for kind in [
            HostProfileEvidenceKind::Brownout,
            HostProfileEvidenceKind::OtlpBrownout,
            HostProfileEvidenceKind::AdmissionSteering,
            HostProfileEvidenceKind::AdaptiveBatchSizing,
            HostProfileEvidenceKind::BlockingPoolAffinity,
            HostProfileEvidenceKind::TraceStorageProfile,
        ] {
            if let Some(artifact) = self.for_kind(kind) {
                ids.push(artifact.artifact_id.clone());
            }
        }
        ids
    }

    #[must_use]
    pub fn for_kind(&self, kind: HostProfileEvidenceKind) -> Option<&HostProfileEvidenceArtifact> {
        match kind {
            HostProfileEvidenceKind::Brownout => self.brownout.as_ref(),
            HostProfileEvidenceKind::OtlpBrownout => self.otlp_brownout.as_ref(),
            HostProfileEvidenceKind::AdmissionSteering => self.admission_steering.as_ref(),
            HostProfileEvidenceKind::AdaptiveBatchSizing => self.adaptive_batch_sizing.as_ref(),
            HostProfileEvidenceKind::BlockingPoolAffinity => self.blocking_pool_affinity.as_ref(),
            HostProfileEvidenceKind::TraceStorageProfile => self.trace_storage_profile.as_ref(),
        }
    }
}

/// Host resources supplied to the planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostProfileHostResources {
    /// Online CPU cores available to the runtime.
    pub cpu_cores: usize,
    /// Available RAM in GiB.
    pub memory_gib: usize,
}

/// Manual escape hatches applied after the profile bundle is composed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostProfileManualOverrides {
    /// Explicit worker-thread override.
    pub worker_threads: Option<usize>,
    /// Explicit worker-cohort override.
    pub worker_cohort_map: Option<WorkerCohortMapping>,
    /// Explicit global-queue limit override.
    pub global_queue_limit: Option<usize>,
    /// Explicit steal-batch override.
    pub steal_batch_size: Option<usize>,
    /// Explicit blocking-affinity override.
    pub blocking_affinity_profile: Option<BlockingPoolAffinityProfile>,
    /// Explicit capacity-hint override.
    pub capacity_hints: Option<RuntimeCapacityHints>,
    /// Explicit trace-storage profile override.
    pub trace_storage_profile: Option<TraceStorageProfile>,
    /// Explicit governor override.
    pub enable_governor: Option<bool>,
    /// Explicit read-biased snapshot override.
    pub enable_read_biased_region_snapshot: Option<bool>,
    /// Explicit adaptive cancel-streak override.
    pub enable_adaptive_cancel_streak: Option<bool>,
    /// Explicit browser ready-handoff override.
    pub browser_ready_handoff_limit: Option<usize>,
}

impl HostProfileManualOverrides {
    #[must_use]
    pub fn applied_field_names(&self) -> Vec<&'static str> {
        let mut fields = Vec::new();
        if self.worker_threads.is_some() {
            fields.push("worker_threads");
        }
        if self.worker_cohort_map.is_some() {
            fields.push("worker_cohort_map");
        }
        if self.global_queue_limit.is_some() {
            fields.push("global_queue_limit");
        }
        if self.steal_batch_size.is_some() {
            fields.push("steal_batch_size");
        }
        if self.blocking_affinity_profile.is_some() {
            fields.push("blocking.affinity_profile");
        }
        if self.capacity_hints.is_some() {
            fields.push("capacity_hints");
        }
        if self.trace_storage_profile.is_some() {
            fields.push("trace_storage_profile");
        }
        if self.enable_governor.is_some() {
            fields.push("enable_governor");
        }
        if self.enable_read_biased_region_snapshot.is_some() {
            fields.push("enable_read_biased_region_snapshot");
        }
        if self.enable_adaptive_cancel_streak.is_some() {
            fields.push("enable_adaptive_cancel_streak");
        }
        if self.browser_ready_handoff_limit.is_some() {
            fields.push("browser_ready_handoff_limit");
        }
        fields
    }

    pub fn apply_to_config(&self, config: &mut RuntimeConfig) {
        if let Some(worker_threads) = self.worker_threads {
            config.worker_threads = worker_threads;
        }
        if let Some(worker_cohort_map) = self.worker_cohort_map.clone() {
            config.worker_cohort_map = Some(worker_cohort_map);
        }
        if let Some(global_queue_limit) = self.global_queue_limit {
            config.global_queue_limit = global_queue_limit;
        }
        if let Some(steal_batch_size) = self.steal_batch_size {
            config.steal_batch_size = steal_batch_size;
        }
        if let Some(blocking_affinity_profile) = self.blocking_affinity_profile {
            config.blocking.affinity_profile = blocking_affinity_profile;
        }
        if let Some(capacity_hints) = self.capacity_hints {
            config.capacity_hints = Some(capacity_hints);
        }
        if let Some(trace_storage_profile) = self.trace_storage_profile {
            config.trace_storage_profile = trace_storage_profile;
        }
        if let Some(enable_governor) = self.enable_governor {
            config.enable_governor = enable_governor;
        }
        if let Some(enable_read_biased_region_snapshot) = self.enable_read_biased_region_snapshot {
            config.enable_read_biased_region_snapshot = enable_read_biased_region_snapshot;
        }
        if let Some(enable_adaptive_cancel_streak) = self.enable_adaptive_cancel_streak {
            config.enable_adaptive_cancel_streak = enable_adaptive_cancel_streak;
        }
        if let Some(browser_ready_handoff_limit) = self.browser_ready_handoff_limit {
            config.browser_ready_handoff_limit = browser_ready_handoff_limit;
        }
    }
}

/// Planner input for an explainable runtime host-profile bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfilePlannerRequest {
    /// Automatic recommendation objective.
    pub objective: HostProfilePlannerObjective,
    /// Optional explicit profile request. When set, the planner either selects
    /// it or falls back conservatively; it does not silently pick a sibling.
    pub requested_profile: Option<HostProfileId>,
    /// The host envelope the plan targets.
    pub host_resources: HostProfileHostResources,
    /// Proof surfaces available to justify a non-baseline bundle.
    pub controller_evidence: HostProfileEvidenceSet,
    /// Manual overrides that win over the bundle.
    pub manual_overrides: HostProfileManualOverrides,
    /// Optional operator note rendered through a secret scrubber.
    pub operator_note: Option<String>,
}

impl HostProfilePlannerRequest {
    /// Compute the explainable host-profile plan.
    #[must_use]
    pub fn plan(&self) -> HostProfilePlan {
        let baseline = RuntimeConfig::default();
        let candidate_profiles: Vec<HostProfileId> = if let Some(profile) = self.requested_profile {
            vec![profile]
        } else {
            self.objective.candidate_order().to_vec()
        };

        let fallback_profile = HostProfileId::ConservativeBaseline;
        let input_evidence_artifact_ids = self.controller_evidence.input_artifact_ids();
        let sanitized_operator_note = self.operator_note.as_deref().map(redact_sensitive_note);
        let manual_overrides_applied = self
            .manual_overrides
            .applied_field_names()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut refusal_reasons = Vec::new();

        for profile in candidate_profiles {
            match self.try_plan_profile(profile) {
                Ok(candidate) => {
                    let mut final_bundle = candidate.profile_bundle.clone();
                    self.manual_overrides.apply_to_config(&mut final_bundle);
                    final_bundle.normalize();
                    let config_diff = build_host_profile_config_diff(
                        &baseline,
                        &candidate.profile_bundle,
                        &final_bundle,
                    );
                    return HostProfilePlan {
                        objective: self.objective,
                        requested_profile: self.requested_profile,
                        selected_profile: profile,
                        fallback_profile,
                        profile_bundle: candidate.profile_bundle,
                        final_bundle,
                        rationale: candidate.rationale,
                        refusal_reasons,
                        when_not_to_use: candidate.when_not_to_use,
                        controller_ledger_state: candidate.controller_ledger_state,
                        input_evidence_artifact_ids,
                        manual_overrides_applied,
                        config_diff,
                        sanitized_operator_note,
                    };
                }
                Err(mut reasons) => refusal_reasons.append(&mut reasons),
            }
        }

        let mut final_bundle = baseline.clone();
        self.manual_overrides.apply_to_config(&mut final_bundle);
        final_bundle.normalize();
        let profile_bundle = host_profile_bundle(fallback_profile);
        let config_diff = build_host_profile_config_diff(&baseline, &profile_bundle, &final_bundle);
        HostProfilePlan {
            objective: self.objective,
            requested_profile: self.requested_profile,
            selected_profile: fallback_profile,
            fallback_profile,
            profile_bundle,
            final_bundle,
            rationale: HostProfileId::ConservativeBaseline
                .rationale()
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            refusal_reasons,
            when_not_to_use: HostProfileId::ConservativeBaseline
                .when_not_to_use()
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            controller_ledger_state: controller_ledger_entries(
                fallback_profile,
                &self.controller_evidence,
            ),
            input_evidence_artifact_ids,
            manual_overrides_applied,
            config_diff,
            sanitized_operator_note,
        }
    }

    fn try_plan_profile(
        &self,
        profile: HostProfileId,
    ) -> Result<HostProfileCandidate, Vec<String>> {
        let mut refusal_reasons = Vec::new();
        if self.host_resources.cpu_cores < profile.required_cpu_cores() {
            refusal_reasons.push(format!(
                "{} requires at least {} CPU cores, but the host only reports {}",
                profile,
                profile.required_cpu_cores(),
                self.host_resources.cpu_cores
            ));
        }
        if self.host_resources.memory_gib < profile.required_memory_gib() {
            refusal_reasons.push(format!(
                "{} requires at least {} GiB of RAM, but the host only reports {} GiB",
                profile,
                profile.required_memory_gib(),
                self.host_resources.memory_gib
            ));
        }
        for kind in profile.required_evidence() {
            match self.controller_evidence.for_kind(*kind) {
                Some(artifact) => {
                    if let Err(reason) = artifact.validate() {
                        refusal_reasons.push(format!("{kind} proof rejected: {reason}"));
                    }
                }
                None => refusal_reasons.push(format!("{kind} proof is missing")),
            }
        }
        if !refusal_reasons.is_empty() {
            return Err(refusal_reasons);
        }
        Ok(HostProfileCandidate {
            profile_bundle: host_profile_bundle(profile),
            rationale: profile
                .rationale()
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            when_not_to_use: profile
                .when_not_to_use()
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            controller_ledger_state: controller_ledger_entries(profile, &self.controller_evidence),
        })
    }
}

/// One composed plan ready for dry-run rendering or runtime adoption.
#[derive(Clone)]
pub struct HostProfilePlan {
    /// Objective that drove automatic ordering.
    pub objective: HostProfilePlannerObjective,
    /// Explicit requested profile, when one was supplied.
    pub requested_profile: Option<HostProfileId>,
    /// Selected named bundle.
    pub selected_profile: HostProfileId,
    /// Safe fallback profile when no proof-backed bundle is valid.
    pub fallback_profile: HostProfileId,
    /// Bundle before manual overrides are applied.
    pub profile_bundle: RuntimeConfig,
    /// Bundle after manual overrides are applied and normalized.
    pub final_bundle: RuntimeConfig,
    /// Positive explanation for why the planner picked this bundle.
    pub rationale: Vec<String>,
    /// Reasons a more aggressive bundle was refused before fallback.
    pub refusal_reasons: Vec<String>,
    /// Operator-facing warnings for when not to use the selected bundle.
    pub when_not_to_use: Vec<String>,
    /// Fixed-order controller ledger snapshot used by the planner.
    pub controller_ledger_state: Vec<HostProfileControllerLedgerEntry>,
    /// All input proof artifact IDs, in deterministic order.
    pub input_evidence_artifact_ids: Vec<String>,
    /// Manual overrides applied to the final bundle.
    pub manual_overrides_applied: Vec<String>,
    /// Dry-run config diff from baseline to profile to final bundle.
    pub config_diff: Vec<HostProfileConfigDiffEntry>,
    /// Optional operator note rendered through the secret scrubber.
    pub sanitized_operator_note: Option<String>,
}

impl HostProfilePlan {
    /// Whether the planner had to refuse the requested or preferred profile.
    #[must_use]
    pub fn used_safe_fallback(&self) -> bool {
        self.selected_profile == self.fallback_profile && !self.refusal_reasons.is_empty()
    }
}

/// One controller snapshot entry cited by the planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfileControllerLedgerEntry {
    /// Controller surface name.
    pub controller: String,
    /// Stance selected for the controller.
    pub stance: String,
    /// Proof artifact reference, when one was supplied.
    pub proof_artifact_id: Option<String>,
    /// Whether the proof validated cleanly.
    pub validation_passed: bool,
}

/// One line of explainable dry-run config diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfileConfigDiffEntry {
    /// Field name in `RuntimeConfig`.
    pub field_path: String,
    /// Baseline runtime value.
    pub baseline_value: String,
    /// Value from the selected named bundle.
    pub profile_value: String,
    /// Final value after manual overrides.
    pub final_value: String,
    /// Whether the final value came from the bundle or a manual override.
    pub source: HostProfileConfigDiffSource,
}

impl HostProfileConfigDiffEntry {
    /// Render a stable human-readable diff line.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{}: {} -> {} -> {} ({})",
            self.field_path, self.baseline_value, self.profile_value, self.final_value, self.source
        )
    }
}

/// Source of the final value in a config diff entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostProfileConfigDiffSource {
    /// Final value comes directly from the named profile bundle.
    ProfileBundle,
    /// Final value was overridden manually after bundle composition.
    ManualOverride,
}

impl HostProfileConfigDiffSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileBundle => "profile_bundle",
            Self::ManualOverride => "manual_override",
        }
    }
}

impl fmt::Display for HostProfileConfigDiffSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone)]
struct HostProfileCandidate {
    profile_bundle: RuntimeConfig,
    rationale: Vec<String>,
    when_not_to_use: Vec<String>,
    controller_ledger_state: Vec<HostProfileControllerLedgerEntry>,
}

fn host_profile_bundle(profile: HostProfileId) -> RuntimeConfig {
    match profile {
        HostProfileId::ConservativeBaseline => RuntimeConfig::default(),
        HostProfileId::LocalityFirst64C256G => {
            let mut config = RuntimeConfig::default();
            config.worker_threads = 64;
            config.worker_cohort_map = Some(large_host_worker_cohort_map());
            config.global_queue_limit = 65_536;
            config.steal_batch_size = 8;
            config.blocking.affinity_profile = BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 32,
                spill_check_interval: 4,
            };
            config.capacity_hints =
                Some(RuntimeCapacityHints::from_expected_concurrent_tasks(16_384));
            config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
            config.enable_governor = true;
            config.enable_read_biased_region_snapshot = true;
            config.enable_adaptive_cancel_streak = true;
            config.browser_ready_handoff_limit = 0;
            config.normalize();
            config
        }
        HostProfileId::TailProtectionFirst64C256G => {
            let mut config = RuntimeConfig::default();
            config.worker_threads = 64;
            config.worker_cohort_map = Some(large_host_worker_cohort_map());
            config.global_queue_limit = 32_768;
            config.steal_batch_size = 4;
            config.blocking.affinity_profile = BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 16,
                spill_check_interval: 2,
            };
            config.capacity_hints =
                Some(RuntimeCapacityHints::from_expected_concurrent_tasks(8_192));
            config.trace_storage_profile = TraceStorageProfile::Default;
            config.enable_governor = true;
            config.enable_read_biased_region_snapshot = true;
            config.enable_adaptive_cancel_streak = true;
            config.browser_ready_handoff_limit = 0;
            config.normalize();
            config
        }
        HostProfileId::LargeMemoryEvidenceRetention256G => {
            let mut config = RuntimeConfig::default();
            config.worker_threads = 64;
            config.worker_cohort_map = Some(large_host_worker_cohort_map());
            config.global_queue_limit = 65_536;
            config.steal_batch_size = 16;
            config.blocking.affinity_profile = BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 24,
                spill_check_interval: 4,
            };
            config.capacity_hints =
                Some(RuntimeCapacityHints::from_expected_concurrent_tasks(12_288));
            config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
            config.enable_governor = true;
            config.enable_read_biased_region_snapshot = true;
            config.enable_adaptive_cancel_streak = true;
            config.browser_ready_handoff_limit = 0;
            config.normalize();
            config
        }
    }
}

fn large_host_worker_cohort_map() -> WorkerCohortMapping {
    let mut worker_to_cohort = Vec::with_capacity(64);
    for cohort in 0..8 {
        for _ in 0..8 {
            worker_to_cohort.push(cohort);
        }
    }
    WorkerCohortMapping::new(worker_to_cohort)
}

fn controller_ledger_entries(
    profile: HostProfileId,
    evidence: &HostProfileEvidenceSet,
) -> Vec<HostProfileControllerLedgerEntry> {
    [
        HostProfileEvidenceKind::Brownout,
        HostProfileEvidenceKind::OtlpBrownout,
        HostProfileEvidenceKind::AdmissionSteering,
        HostProfileEvidenceKind::AdaptiveBatchSizing,
        HostProfileEvidenceKind::BlockingPoolAffinity,
        HostProfileEvidenceKind::TraceStorageProfile,
    ]
    .into_iter()
    .map(|kind| {
        let artifact = evidence.for_kind(kind);
        let proof_artifact_id = artifact.map(|item| item.artifact_id.clone());
        let validation_passed = artifact
            .map(|item| item.validation_passed && item.validate().is_ok())
            .unwrap_or(false);
        HostProfileControllerLedgerEntry {
            controller: kind.as_str().to_string(),
            stance: controller_stance(profile, kind).to_string(),
            proof_artifact_id,
            validation_passed,
        }
    })
    .collect()
}

fn controller_stance(profile: HostProfileId, kind: HostProfileEvidenceKind) -> &'static str {
    match (profile, kind) {
        (HostProfileId::ConservativeBaseline, HostProfileEvidenceKind::Brownout) => "full_surfaces",
        (HostProfileId::ConservativeBaseline, HostProfileEvidenceKind::OtlpBrownout) => {
            "standalone_fallback"
        }
        (HostProfileId::ConservativeBaseline, HostProfileEvidenceKind::AdmissionSteering) => {
            "conservative_global"
        }
        (HostProfileId::ConservativeBaseline, HostProfileEvidenceKind::AdaptiveBatchSizing) => {
            "conservative_fixed"
        }
        (HostProfileId::ConservativeBaseline, HostProfileEvidenceKind::BlockingPoolAffinity) => {
            "disabled"
        }
        (HostProfileId::ConservativeBaseline, HostProfileEvidenceKind::TraceStorageProfile) => {
            "default"
        }
        (HostProfileId::LocalityFirst64C256G, HostProfileEvidenceKind::Brownout)
        | (HostProfileId::TailProtectionFirst64C256G, HostProfileEvidenceKind::Brownout)
        | (HostProfileId::LargeMemoryEvidenceRetention256G, HostProfileEvidenceKind::Brownout) => {
            "optional_first"
        }
        (HostProfileId::LocalityFirst64C256G, HostProfileEvidenceKind::OtlpBrownout)
        | (HostProfileId::TailProtectionFirst64C256G, HostProfileEvidenceKind::OtlpBrownout)
        | (
            HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::OtlpBrownout,
        ) => "priority_gate",
        (HostProfileId::LocalityFirst64C256G, HostProfileEvidenceKind::AdmissionSteering) => {
            "cohort_locality"
        }
        (HostProfileId::TailProtectionFirst64C256G, HostProfileEvidenceKind::AdmissionSteering) => {
            "tail_risk_admission"
        }
        (
            HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::AdmissionSteering,
        ) => "cohort_locality",
        (HostProfileId::LocalityFirst64C256G, HostProfileEvidenceKind::AdaptiveBatchSizing)
        | (
            HostProfileId::TailProtectionFirst64C256G,
            HostProfileEvidenceKind::AdaptiveBatchSizing,
        )
        | (
            HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::AdaptiveBatchSizing,
        ) => "builtin_adaptive",
        (HostProfileId::LocalityFirst64C256G, HostProfileEvidenceKind::BlockingPoolAffinity)
        | (
            HostProfileId::TailProtectionFirst64C256G,
            HostProfileEvidenceKind::BlockingPoolAffinity,
        )
        | (
            HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::BlockingPoolAffinity,
        ) => "cohort_biased",
        (HostProfileId::LocalityFirst64C256G, HostProfileEvidenceKind::TraceStorageProfile)
        | (
            HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::TraceStorageProfile,
        ) => "large_memory_256g",
        (
            HostProfileId::TailProtectionFirst64C256G,
            HostProfileEvidenceKind::TraceStorageProfile,
        ) => "default",
    }
}

fn build_host_profile_config_diff(
    baseline: &RuntimeConfig,
    profile_bundle: &RuntimeConfig,
    final_bundle: &RuntimeConfig,
) -> Vec<HostProfileConfigDiffEntry> {
    let mut diff = Vec::new();
    maybe_push_diff_entry(
        &mut diff,
        "worker_threads",
        baseline.worker_threads.to_string(),
        profile_bundle.worker_threads.to_string(),
        final_bundle.worker_threads.to_string(),
    );
    maybe_push_diff_entry(
        &mut diff,
        "worker_cohort_map",
        format_worker_cohort_map(baseline.worker_cohort_map.as_ref()),
        format_worker_cohort_map(profile_bundle.worker_cohort_map.as_ref()),
        format_worker_cohort_map(final_bundle.worker_cohort_map.as_ref()),
    );
    maybe_push_diff_entry(
        &mut diff,
        "global_queue_limit",
        baseline.global_queue_limit.to_string(),
        profile_bundle.global_queue_limit.to_string(),
        final_bundle.global_queue_limit.to_string(),
    );
    maybe_push_diff_entry(
        &mut diff,
        "steal_batch_size",
        baseline.steal_batch_size.to_string(),
        profile_bundle.steal_batch_size.to_string(),
        final_bundle.steal_batch_size.to_string(),
    );
    maybe_push_diff_entry(
        &mut diff,
        "blocking.affinity_profile",
        format_blocking_affinity_profile(baseline.blocking.affinity_profile),
        format_blocking_affinity_profile(profile_bundle.blocking.affinity_profile),
        format_blocking_affinity_profile(final_bundle.blocking.affinity_profile),
    );
    maybe_push_diff_entry(
        &mut diff,
        "capacity_hints",
        format_capacity_hints(baseline.capacity_hints),
        format_capacity_hints(profile_bundle.capacity_hints),
        format_capacity_hints(final_bundle.capacity_hints),
    );
    maybe_push_diff_entry(
        &mut diff,
        "trace_storage_profile",
        baseline.trace_storage_profile.to_string(),
        profile_bundle.trace_storage_profile.to_string(),
        final_bundle.trace_storage_profile.to_string(),
    );
    maybe_push_diff_entry(
        &mut diff,
        "browser_ready_handoff_limit",
        baseline.browser_ready_handoff_limit.to_string(),
        profile_bundle.browser_ready_handoff_limit.to_string(),
        final_bundle.browser_ready_handoff_limit.to_string(),
    );
    maybe_push_diff_entry(
        &mut diff,
        "enable_governor",
        format_bool(baseline.enable_governor),
        format_bool(profile_bundle.enable_governor),
        format_bool(final_bundle.enable_governor),
    );
    maybe_push_diff_entry(
        &mut diff,
        "enable_read_biased_region_snapshot",
        format_bool(baseline.enable_read_biased_region_snapshot),
        format_bool(profile_bundle.enable_read_biased_region_snapshot),
        format_bool(final_bundle.enable_read_biased_region_snapshot),
    );
    maybe_push_diff_entry(
        &mut diff,
        "enable_adaptive_cancel_streak",
        format_bool(baseline.enable_adaptive_cancel_streak),
        format_bool(profile_bundle.enable_adaptive_cancel_streak),
        format_bool(final_bundle.enable_adaptive_cancel_streak),
    );
    diff
}

fn maybe_push_diff_entry(
    diff: &mut Vec<HostProfileConfigDiffEntry>,
    field_path: &str,
    baseline_value: String,
    profile_value: String,
    final_value: String,
) {
    if baseline_value == profile_value && profile_value == final_value {
        return;
    }
    let source = if profile_value == final_value {
        HostProfileConfigDiffSource::ProfileBundle
    } else {
        HostProfileConfigDiffSource::ManualOverride
    };
    diff.push(HostProfileConfigDiffEntry {
        field_path: field_path.to_string(),
        baseline_value,
        profile_value,
        final_value,
        source,
    });
}

fn format_bool(value: bool) -> String {
    if value {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

fn format_capacity_hints(value: Option<RuntimeCapacityHints>) -> String {
    match value {
        Some(hints) => format!(
            "tasks={},regions={},obligations={}",
            hints.task_capacity, hints.region_capacity, hints.obligation_capacity
        ),
        None => "auto".to_string(),
    }
}

fn format_worker_cohort_map(value: Option<&WorkerCohortMapping>) -> String {
    let Some(mapping) = value else {
        return "none".to_string();
    };
    if mapping.worker_to_cohort.is_empty() {
        return "[]".to_string();
    }
    let mut compressed = Vec::new();
    let mut current = mapping.worker_to_cohort[0];
    let mut count = 0usize;
    for cohort in &mapping.worker_to_cohort {
        if *cohort == current {
            count += 1;
        } else {
            compressed.push(format!("{current}x{count}"));
            current = *cohort;
            count = 1;
        }
    }
    compressed.push(format!("{current}x{count}"));
    format!("[{}]", compressed.join(","))
}

fn format_blocking_affinity_profile(profile: BlockingPoolAffinityProfile) -> String {
    match profile {
        BlockingPoolAffinityProfile::Disabled => "disabled".to_string(),
        BlockingPoolAffinityProfile::CohortBiased {
            local_queue_soft_limit,
            spill_check_interval,
        } => format!(
            "cohort_biased(local_queue_soft_limit={local_queue_soft_limit},spill_check_interval={spill_check_interval})"
        ),
    }
}

fn redact_sensitive_note(note: &str) -> String {
    note.split_whitespace()
        .map(|token| {
            let Some((key, _value)) = token.split_once('=') else {
                return token.to_string();
            };
            let key_lower = key.to_ascii_lowercase();
            if key_lower.contains("token")
                || key_lower.contains("secret")
                || key_lower.contains("password")
                || key_lower == "apikey"
                || key_lower == "api_key"
            {
                format!("{key}=[REDACTED]")
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_default_config_sane() {
        init_test("test_default_config_sane");
        let config = RuntimeConfig::default();
        crate::assert_with_log!(
            config.worker_threads >= 1,
            "worker_threads",
            true,
            config.worker_threads >= 1
        );
        crate::assert_with_log!(
            config.worker_cohort_map.is_none(),
            "worker_cohort_map",
            "None",
            format!("{:?}", config.worker_cohort_map)
        );
        crate::assert_with_log!(
            config.thread_stack_size == 2 * 1024 * 1024,
            "thread_stack_size",
            2 * 1024 * 1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            !config.thread_name_prefix.is_empty(),
            "thread_name_prefix",
            true,
            !config.thread_name_prefix.is_empty()
        );
        crate::assert_with_log!(
            config.poll_budget == 128,
            "poll_budget",
            128,
            config.poll_budget
        );
        crate::assert_with_log!(
            config.trace_storage_profile == TraceStorageProfile::Default,
            "trace_storage_profile",
            TraceStorageProfile::Default,
            config.trace_storage_profile
        );
        crate::assert_with_log!(
            config.browser_ready_handoff_limit == 0,
            "browser_ready_handoff_limit",
            0,
            config.browser_ready_handoff_limit
        );
        crate::assert_with_log!(
            !config.browser_worker_offload.enabled,
            "browser_worker_offload.enabled",
            false,
            config.browser_worker_offload.enabled
        );
        crate::assert_with_log!(
            config.browser_worker_offload.min_task_cost == 1024,
            "browser_worker_offload.min_task_cost",
            1024,
            config.browser_worker_offload.min_task_cost
        );
        crate::assert_with_log!(
            config.browser_worker_offload.max_in_flight == 16,
            "browser_worker_offload.max_in_flight",
            16,
            config.browser_worker_offload.max_in_flight
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 16,
            "cancel_lane_max_streak",
            16,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.enable_adaptive_cancel_streak,
            "enable_adaptive_cancel_streak",
            true,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 128,
            "adaptive_cancel_streak_epoch_steps",
            128,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::assert_with_log!(
            !config.enable_read_biased_region_snapshot,
            "enable_read_biased_region_snapshot",
            false,
            config.enable_read_biased_region_snapshot
        );
        crate::assert_with_log!(
            config.logical_clock_mode.is_none(),
            "logical_clock_mode",
            "None",
            format!("{:?}", config.logical_clock_mode)
        );
        crate::assert_with_log!(
            config.obligation_leak_response == ObligationLeakResponse::Panic,
            "obligation_leak_response",
            ObligationLeakResponse::Panic,
            config.obligation_leak_response
        );
        crate::assert_with_log!(
            config.cancel_attribution == CancelAttributionConfig::default(),
            "cancel_attribution default",
            CancelAttributionConfig::default(),
            config.cancel_attribution
        );
        crate::test_complete!("test_default_config_sane");
    }

    #[test]
    fn trace_storage_profile_text_roundtrip_is_stable() {
        init_test("trace_storage_profile_text_roundtrip_is_stable");
        crate::assert_with_log!(
            TraceStorageProfile::Default.as_str() == "default",
            "default as_str",
            "default",
            TraceStorageProfile::Default.as_str()
        );
        crate::assert_with_log!(
            TraceStorageProfile::LargeMemory256G.as_str() == "large-memory-256g",
            "large-memory as_str",
            "large-memory-256g",
            TraceStorageProfile::LargeMemory256G.as_str()
        );
        crate::assert_with_log!(
            TraceStorageProfile::Default.to_string() == "default",
            "default display",
            "default",
            TraceStorageProfile::Default.to_string()
        );
        crate::assert_with_log!(
            TraceStorageProfile::LargeMemory256G.to_string() == "large-memory-256g",
            "large-memory display",
            "large-memory-256g",
            TraceStorageProfile::LargeMemory256G.to_string()
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("default").expect("parse default")
                == TraceStorageProfile::Default,
            "default parse",
            TraceStorageProfile::Default,
            TraceStorageProfile::from_str("default").expect("parse default")
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("large-memory-256g").expect("parse large-memory kebab")
                == TraceStorageProfile::LargeMemory256G,
            "large-memory kebab parse",
            TraceStorageProfile::LargeMemory256G,
            TraceStorageProfile::from_str("large-memory-256g").expect("parse large-memory kebab")
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("large_memory_256g").expect("parse large-memory alias")
                == TraceStorageProfile::LargeMemory256G,
            "large-memory underscore parse",
            TraceStorageProfile::LargeMemory256G,
            TraceStorageProfile::from_str("large_memory_256g").expect("parse large-memory alias")
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("invalid-profile").is_err(),
            "invalid parse rejected",
            true,
            TraceStorageProfile::from_str("invalid-profile").is_err()
        );
        crate::test_complete!("trace_storage_profile_text_roundtrip_is_stable");
    }

    fn zero_minimums_config() -> RuntimeConfig {
        RuntimeConfig {
            worker_threads: 0,
            worker_cohort_map: None,
            thread_stack_size: 0,
            thread_name_prefix: String::new(),
            global_queue_limit: 0,
            steal_batch_size: 0,
            blocking: BlockingPoolConfig {
                min_threads: 4,
                max_threads: 1,
                affinity_profile: BlockingPoolAffinityProfile::Disabled,
            },
            enable_parking: true,
            poll_budget: 0,
            capacity_hints: Some(RuntimeCapacityHints::new(0, 0, 0)),
            trace_storage_profile: TraceStorageProfile::Default,
            browser_ready_handoff_limit: 0,
            browser_worker_offload: BrowserWorkerOffloadConfig {
                enabled: true,
                min_task_cost: 0,
                max_in_flight: 0,
                transfer_mode: WorkerTransferMode::CloneStructured,
                cancellation_mode: WorkerCancellationMode::BestEffortAbort,
                require_owned_payloads: false,
            },
            cancel_lane_max_streak: 0,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::new(1, 256),
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            logical_clock_mode: None,
            enable_governor: false,
            governor_interval: 0,
            enable_read_biased_region_snapshot: false,
            enable_adaptive_cancel_streak: false,
            adaptive_cancel_streak_epoch_steps: 0,
        }
    }

    fn assert_normalized_minimums(config: &RuntimeConfig) {
        crate::assert_with_log!(
            config.worker_threads == 1,
            "worker_threads",
            1,
            config.worker_threads
        );
        crate::assert_with_log!(
            config.thread_stack_size == 2 * 1024 * 1024,
            "thread_stack_size",
            2 * 1024 * 1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            config.steal_batch_size == 1,
            "steal_batch_size",
            1,
            config.steal_batch_size
        );
        crate::assert_with_log!(
            config.poll_budget == 1,
            "poll_budget",
            1,
            config.poll_budget
        );
        let capacity_hints = config
            .capacity_hints
            .expect("explicit capacity hints should remain configured");
        crate::assert_with_log!(
            capacity_hints.task_capacity == RuntimeCapacityHints::DEFAULT_TASK_CAPACITY,
            "capacity_hints.task_capacity",
            RuntimeCapacityHints::DEFAULT_TASK_CAPACITY,
            capacity_hints.task_capacity
        );
        crate::assert_with_log!(
            capacity_hints.region_capacity == RuntimeCapacityHints::DEFAULT_REGION_CAPACITY,
            "capacity_hints.region_capacity",
            RuntimeCapacityHints::DEFAULT_REGION_CAPACITY,
            capacity_hints.region_capacity
        );
        crate::assert_with_log!(
            capacity_hints.obligation_capacity == RuntimeCapacityHints::DEFAULT_OBLIGATION_CAPACITY,
            "capacity_hints.obligation_capacity",
            RuntimeCapacityHints::DEFAULT_OBLIGATION_CAPACITY,
            capacity_hints.obligation_capacity
        );
        crate::assert_with_log!(
            config.browser_ready_handoff_limit == 0,
            "browser_ready_handoff_limit",
            0,
            config.browser_ready_handoff_limit
        );
        crate::assert_with_log!(
            config.browser_worker_offload.min_task_cost == 1,
            "browser_worker_offload.min_task_cost",
            1,
            config.browser_worker_offload.min_task_cost
        );
        crate::assert_with_log!(
            config.browser_worker_offload.max_in_flight == 1,
            "browser_worker_offload.max_in_flight",
            1,
            config.browser_worker_offload.max_in_flight
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 1,
            "cancel_lane_max_streak",
            1,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.governor_interval == 1,
            "governor_interval",
            1,
            config.governor_interval
        );
        crate::assert_with_log!(
            !config.enable_adaptive_cancel_streak,
            "enable_adaptive_cancel_streak",
            false,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 1,
            "adaptive_cancel_streak_epoch_steps",
            1,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::assert_with_log!(
            config.thread_name_prefix == "asupersync-worker",
            "thread_name_prefix",
            "asupersync-worker",
            config.thread_name_prefix
        );
        crate::assert_with_log!(
            config.blocking.max_threads == config.blocking.min_threads,
            "blocking normalize",
            config.blocking.min_threads,
            config.blocking.max_threads
        );
    }

    #[test]
    fn test_normalize_enforces_minimums() {
        init_test("test_normalize_enforces_minimums");
        let mut config = zero_minimums_config();

        config.normalize();
        assert_normalized_minimums(&config);
        crate::test_complete!("test_normalize_enforces_minimums");
    }

    #[test]
    fn test_blocking_pool_normalize() {
        init_test("test_blocking_pool_normalize");
        let mut blocking = BlockingPoolConfig {
            min_threads: 2,
            max_threads: 1,
            affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 0,
                spill_check_interval: 0,
            },
        };
        blocking.normalize();
        crate::assert_with_log!(
            blocking.max_threads == blocking.min_threads,
            "blocking max>=min",
            blocking.min_threads,
            blocking.max_threads
        );
        crate::assert_with_log!(
            blocking.affinity_profile
                == BlockingPoolAffinityProfile::CohortBiased {
                    local_queue_soft_limit: 1,
                    spill_check_interval: 1,
                },
            "blocking affinity profile normalized",
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            blocking.affinity_profile
        );
        crate::test_complete!("test_blocking_pool_normalize");
    }

    #[test]
    fn worker_cohort_mapping_derives_cohort_count_from_labels() {
        init_test("worker_cohort_mapping_derives_cohort_count_from_labels");
        let mapping = WorkerCohortMapping::new(vec![0, 0, 2, 2]);
        crate::assert_with_log!(
            mapping.cohort_count() == 3,
            "cohort_count",
            3,
            mapping.cohort_count()
        );
        crate::test_complete!("worker_cohort_mapping_derives_cohort_count_from_labels");
    }

    #[test]
    fn worker_cohort_mapping_validation_checks_worker_count() {
        init_test("worker_cohort_mapping_validation_checks_worker_count");
        let mapping = WorkerCohortMapping::new(vec![0, 1, 1]);
        let err = mapping
            .validate_for_workers(4)
            .expect_err("length mismatch should be rejected");
        crate::assert_with_log!(
            err == "worker cohort map length must match worker_threads",
            "worker cohort map length mismatch",
            "worker cohort map length must match worker_threads",
            err
        );
        crate::test_complete!("worker_cohort_mapping_validation_checks_worker_count");
    }

    #[test]
    fn test_leak_escalation_new_clamps_zero_threshold() {
        init_test("test_leak_escalation_new_clamps_zero_threshold");
        let escalation = LeakEscalation::new(0, ObligationLeakResponse::Panic);
        crate::assert_with_log!(
            escalation.threshold == 1,
            "leak_escalation.threshold",
            1,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Panic,
            "leak_escalation.escalate_to",
            ObligationLeakResponse::Panic,
            escalation.escalate_to
        );
        crate::test_complete!("test_leak_escalation_new_clamps_zero_threshold");
    }

    #[test]
    fn test_normalize_clamps_zero_leak_escalation_threshold() {
        init_test("test_normalize_clamps_zero_leak_escalation_threshold");
        let mut config = RuntimeConfig {
            leak_escalation: Some(LeakEscalation {
                threshold: 0,
                escalate_to: ObligationLeakResponse::Recover,
            }),
            ..RuntimeConfig::default()
        };

        config.normalize();

        let escalation = config
            .leak_escalation
            .expect("leak escalation should remain configured");
        crate::assert_with_log!(
            escalation.threshold == 1,
            "leak_escalation.threshold",
            1,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Recover,
            "leak_escalation.escalate_to",
            ObligationLeakResponse::Recover,
            escalation.escalate_to
        );
        crate::test_complete!("test_normalize_clamps_zero_leak_escalation_threshold");
    }

    #[test]
    fn test_default_worker_threads_nonzero() {
        init_test("test_default_worker_threads_nonzero");
        let threads = RuntimeConfig::default_worker_threads();
        crate::assert_with_log!(threads >= 1, "default_worker_threads", true, threads >= 1);
        crate::test_complete!("test_default_worker_threads_nonzero");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_normalize_preserves_custom_values() {
        init_test("test_normalize_preserves_custom_values");
        let mut config = RuntimeConfig {
            worker_threads: 4,
            worker_cohort_map: None,
            thread_stack_size: 1024,
            thread_name_prefix: "custom".to_string(),
            global_queue_limit: 64,
            steal_batch_size: 8,
            blocking: BlockingPoolConfig {
                min_threads: 2,
                max_threads: 4,
                affinity_profile: BlockingPoolAffinityProfile::Disabled,
            },
            enable_parking: false,
            poll_budget: 32,
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            browser_ready_handoff_limit: 64,
            browser_worker_offload: BrowserWorkerOffloadConfig {
                enabled: true,
                min_task_cost: 4096,
                max_in_flight: 8,
                transfer_mode: WorkerTransferMode::TransferableOnly,
                cancellation_mode: WorkerCancellationMode::RequireAck,
                require_owned_payloads: true,
            },
            cancel_lane_max_streak: 16,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::new(8, 1024),
            obligation_leak_response: ObligationLeakResponse::Silent,
            leak_escalation: None,
            logical_clock_mode: None,
            enable_governor: false,
            governor_interval: 7,
            enable_read_biased_region_snapshot: true,
            enable_adaptive_cancel_streak: true,
            adaptive_cancel_streak_epoch_steps: 64,
        };

        config.normalize();
        crate::assert_with_log!(
            config.worker_threads == 4,
            "worker_threads",
            4,
            config.worker_threads
        );
        crate::assert_with_log!(
            config.thread_stack_size == 1024,
            "thread_stack_size",
            1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            config.thread_name_prefix == "custom",
            "thread_name_prefix",
            "custom",
            config.thread_name_prefix
        );
        crate::assert_with_log!(
            config.steal_batch_size == 8,
            "steal_batch_size",
            8,
            config.steal_batch_size
        );
        crate::assert_with_log!(
            config.poll_budget == 32,
            "poll_budget",
            32,
            config.poll_budget
        );
        crate::assert_with_log!(
            config.trace_storage_profile == TraceStorageProfile::LargeMemory256G,
            "trace_storage_profile",
            TraceStorageProfile::LargeMemory256G,
            config.trace_storage_profile
        );
        let capacity_hints = config
            .capacity_hints
            .expect("custom capacity hints should remain configured");
        crate::assert_with_log!(
            capacity_hints == RuntimeCapacityHints::new(4096, 1024, 2048),
            "capacity_hints",
            RuntimeCapacityHints::new(4096, 1024, 2048),
            capacity_hints
        );
        crate::assert_with_log!(
            config.browser_ready_handoff_limit == 64,
            "browser_ready_handoff_limit",
            64,
            config.browser_ready_handoff_limit
        );
        crate::assert_with_log!(
            config.browser_worker_offload.enabled,
            "browser_worker_offload.enabled",
            true,
            config.browser_worker_offload.enabled
        );
        crate::assert_with_log!(
            config.browser_worker_offload.min_task_cost == 4096,
            "browser_worker_offload.min_task_cost",
            4096,
            config.browser_worker_offload.min_task_cost
        );
        crate::assert_with_log!(
            config.browser_worker_offload.max_in_flight == 8,
            "browser_worker_offload.max_in_flight",
            8,
            config.browser_worker_offload.max_in_flight
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 16,
            "cancel_lane_max_streak",
            16,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.governor_interval == 7,
            "governor_interval",
            7,
            config.governor_interval
        );
        crate::assert_with_log!(
            config.enable_adaptive_cancel_streak,
            "enable_adaptive_cancel_streak",
            true,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 64,
            "adaptive_cancel_streak_epoch_steps",
            64,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::assert_with_log!(
            config.blocking.max_threads == 4,
            "blocking max",
            4,
            config.blocking.max_threads
        );
        crate::assert_with_log!(
            config.obligation_leak_response == ObligationLeakResponse::Silent,
            "obligation_leak_response",
            ObligationLeakResponse::Silent,
            config.obligation_leak_response
        );
        crate::test_complete!("test_normalize_preserves_custom_values");
    }

    #[test]
    fn test_browser_worker_offload_defaults() {
        init_test("test_browser_worker_offload_defaults");
        let cfg = BrowserWorkerOffloadConfig::default();
        crate::assert_with_log!(
            !cfg.enabled,
            "offload disabled by default",
            false,
            cfg.enabled
        );
        crate::assert_with_log!(
            cfg.min_task_cost == 1024,
            "default min task cost",
            1024,
            cfg.min_task_cost
        );
        crate::assert_with_log!(
            cfg.max_in_flight == 16,
            "default max in flight",
            16,
            cfg.max_in_flight
        );
        crate::assert_with_log!(
            cfg.transfer_mode == WorkerTransferMode::TransferableOnly,
            "default transfer mode",
            WorkerTransferMode::TransferableOnly,
            cfg.transfer_mode
        );
        crate::assert_with_log!(
            cfg.cancellation_mode == WorkerCancellationMode::RequireAck,
            "default cancellation mode",
            WorkerCancellationMode::RequireAck,
            cfg.cancellation_mode
        );
        crate::assert_with_log!(
            cfg.require_owned_payloads,
            "default require_owned_payloads",
            true,
            cfg.require_owned_payloads
        );
        crate::test_complete!("test_browser_worker_offload_defaults");
    }

    #[test]
    fn test_browser_worker_offload_normalize_clamps_zero_values() {
        init_test("test_browser_worker_offload_normalize_clamps_zero_values");
        let mut cfg = BrowserWorkerOffloadConfig {
            enabled: true,
            min_task_cost: 0,
            max_in_flight: 0,
            transfer_mode: WorkerTransferMode::CloneStructured,
            cancellation_mode: WorkerCancellationMode::BestEffortAbort,
            require_owned_payloads: false,
        };
        cfg.normalize();
        crate::assert_with_log!(
            cfg.min_task_cost == 1,
            "min_task_cost",
            1,
            cfg.min_task_cost
        );
        crate::assert_with_log!(
            cfg.max_in_flight == 1,
            "max_in_flight",
            1,
            cfg.max_in_flight
        );
        crate::test_complete!("test_browser_worker_offload_normalize_clamps_zero_values");
    }

    // ========================================================================
    // Pure data-type tests (wave 10 – CyanBarn)
    // ========================================================================

    #[test]
    fn obligation_leak_response_clone_copy() {
        let a = ObligationLeakResponse::Recover;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn leak_escalation_debug_eq() {
        let a = LeakEscalation::new(5, ObligationLeakResponse::Panic);
        let b = LeakEscalation::new(5, ObligationLeakResponse::Panic);
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("LeakEscalation"), "{dbg}");
    }

    #[test]
    fn leak_escalation_clone_copy() {
        let a = LeakEscalation::new(10, ObligationLeakResponse::Log);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn blocking_pool_config_default() {
        let bp = BlockingPoolConfig::default();
        assert_eq!(bp.min_threads, 0);
        assert_eq!(bp.max_threads, 0);
        assert_eq!(bp.affinity_profile, BlockingPoolAffinityProfile::Disabled);
    }

    #[test]
    fn blocking_pool_config_clone() {
        let bp = BlockingPoolConfig {
            min_threads: 2,
            max_threads: 8,
            affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 16,
                spill_check_interval: 4,
            },
        };
        let cloned = bp.clone();
        assert_eq!(cloned.min_threads, 2);
        assert_eq!(cloned.max_threads, 8);
        assert_eq!(cloned.affinity_profile, bp.affinity_profile);
    }

    #[test]
    fn runtime_config_clone() {
        let config = RuntimeConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.worker_threads, config.worker_threads);
        assert_eq!(cloned.poll_budget, config.poll_budget);
        assert_eq!(
            cloned.obligation_leak_response,
            config.obligation_leak_response
        );
    }

    /// Invariant: ObligationLeakResponse variants are distinct and Debug-printable.
    #[test]
    fn test_obligation_leak_response_variants() {
        init_test("test_obligation_leak_response_variants");
        let variants = [
            ObligationLeakResponse::Panic,
            ObligationLeakResponse::Log,
            ObligationLeakResponse::Silent,
            ObligationLeakResponse::Recover,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    crate::assert_with_log!(*a == *b, "same variant eq", true, *a == *b);
                } else {
                    crate::assert_with_log!(*a != *b, "diff variant ne", true, *a != *b);
                }
            }
            let dbg = format!("{a:?}");
            crate::assert_with_log!(!dbg.is_empty(), "Debug non-empty", true, !dbg.is_empty());
        }
        crate::test_complete!("test_obligation_leak_response_variants");
    }

    /// Invariant: LeakEscalation preserves non-zero threshold.
    #[test]
    fn test_leak_escalation_preserves_nonzero() {
        init_test("test_leak_escalation_preserves_nonzero");
        let escalation = LeakEscalation::new(10, ObligationLeakResponse::Recover);
        crate::assert_with_log!(
            escalation.threshold == 10,
            "threshold preserved",
            10,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Recover,
            "escalate_to",
            ObligationLeakResponse::Recover,
            escalation.escalate_to
        );
        crate::test_complete!("test_leak_escalation_preserves_nonzero");
    }

    /// Invariant: RuntimeConfig default governor settings are off with interval 32.
    #[test]
    fn test_default_governor_settings() {
        init_test("test_default_governor_settings");
        let config = RuntimeConfig::default();
        crate::assert_with_log!(
            !config.enable_governor,
            "governor disabled by default",
            false,
            config.enable_governor
        );
        crate::assert_with_log!(
            config.governor_interval == 32,
            "default governor interval",
            32,
            config.governor_interval
        );
        crate::assert_with_log!(
            !config.enable_read_biased_region_snapshot,
            "read-biased region snapshot disabled by default",
            false,
            config.enable_read_biased_region_snapshot
        );
        crate::assert_with_log!(
            config.enable_adaptive_cancel_streak,
            "adaptive cancel streak enabled by default",
            true,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 128,
            "adaptive cancel streak default epoch",
            128,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::test_complete!("test_default_governor_settings");
    }

    /// br-asupersync-ry2trw: `RuntimeConfig::default()` must produce a
    /// host-independent worker_threads value. Two defaults built on
    /// the same host must agree (sanity), and the value must equal
    /// `DEFAULT_WORKER_THREADS` (the deterministic constant) — NOT
    /// the host's `available_parallelism()`.
    #[test]
    fn ry2trw_default_worker_threads_is_host_independent_constant() {
        let a = RuntimeConfig::default();
        let b = RuntimeConfig::default();
        assert_eq!(a.worker_threads, b.worker_threads);
        assert_eq!(a.worker_threads, RuntimeConfig::DEFAULT_WORKER_THREADS);
    }

    /// br-asupersync-ry2trw: the explicit opt-in for host-scaled
    /// parallelism must remain available for production callers that
    /// genuinely want it. Asserts the function returns at least 1
    /// (clamp invariant).
    #[test]
    fn ry2trw_ambient_default_worker_threads_returns_positive() {
        let n = ambient_default_worker_threads();
        assert!(n >= 1, "ambient_default_worker_threads must clamp to >= 1");
    }

    #[test]
    fn runtime_capacity_hints_from_expected_tasks_adds_headroom() {
        init_test("runtime_capacity_hints_from_expected_tasks_adds_headroom");

        let small = RuntimeCapacityHints::from_expected_concurrent_tasks(64);
        assert_eq!(
            small,
            RuntimeCapacityHints::default(),
            "small explicit hints should clamp to the historical minimums"
        );

        let large = RuntimeCapacityHints::from_expected_concurrent_tasks(4096);
        assert_eq!(
            large,
            RuntimeCapacityHints::new(6144, 1024, 2048),
            "explicit task hints should add task headroom and proportionally scale sibling tables"
        );
    }

    #[test]
    fn runtime_capacity_hints_auto_scale_from_worker_threads() {
        init_test("runtime_capacity_hints_auto_scale_from_worker_threads");

        assert_eq!(
            RuntimeCapacityHints::for_worker_threads(RuntimeConfig::DEFAULT_WORKER_THREADS),
            RuntimeCapacityHints::default(),
            "4-worker baseline should preserve the historical default capacities"
        );
        assert_eq!(
            RuntimeCapacityHints::for_worker_threads(64),
            RuntimeCapacityHints::new(8192, 2048, 4096),
            "high-core runtimes should scale their initial table capacities linearly"
        );
    }

    #[test]
    fn resolved_capacity_hints_prefers_explicit_values_over_worker_scaling() {
        init_test("resolved_capacity_hints_prefers_explicit_values_over_worker_scaling");

        let mut config = RuntimeConfig {
            worker_threads: 64,
            capacity_hints: Some(RuntimeCapacityHints::new(900, 200, 600)),
            ..RuntimeConfig::default()
        };
        config.normalize();

        assert_eq!(
            config.resolved_capacity_hints(),
            RuntimeCapacityHints::new(900, 200, 600),
            "explicit capacity hints should win after normalization"
        );
    }
}
