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
//! | `enable_adaptive_cancel_streak` | `true` |
//! | `adaptive_cancel_streak_epoch_steps` | `128` |

use crate::observability::ObservabilityConfig;
use crate::observability::metrics::{MetricsProvider, NoOpMetrics};
use crate::record::RegionLimits;
use crate::runtime::deadline_monitor::{DeadlineWarning, MonitorConfig};
use crate::trace::distributed::LogicalClockMode;
use crate::types::CancelAttributionConfig;
use std::sync::Arc;

/// Configuration for the blocking pool.
#[derive(Clone, Default)]
pub struct BlockingPoolConfig {
    /// Minimum number of blocking threads.
    pub min_threads: usize,
    /// Maximum number of blocking threads.
    pub max_threads: usize,
}

impl BlockingPoolConfig {
    /// Normalize configuration values to safe defaults.
    pub fn normalize(&mut self) {
        if self.max_threads < self.min_threads {
            self.max_threads = self.min_threads;
        }
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

    const ASSUMED_TRACE_EVENT_BYTES: usize = 256;
    const ASSUMED_CANCELLATION_TRACE_BYTES: usize = 2_048;
    const ASSUMED_DISTRIBUTED_TRACE_BYTES: usize = 1_536;

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
            enable_adaptive_cancel_streak: true,
            adaptive_cancel_streak_epoch_steps: 128,
        }
    }
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
        };
        blocking.normalize();
        crate::assert_with_log!(
            blocking.max_threads == blocking.min_threads,
            "blocking max>=min",
            blocking.min_threads,
            blocking.max_threads
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
    }

    #[test]
    fn blocking_pool_config_clone() {
        let bp = BlockingPoolConfig {
            min_threads: 2,
            max_threads: 8,
        };
        let cloned = bp;
        assert_eq!(cloned.min_threads, 2);
        assert_eq!(cloned.max_threads, 8);
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
