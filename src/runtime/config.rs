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
//! | `arena_temperature_policy` | `ArenaTemperaturePolicy::Unified` |
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
use crate::record::{ObligationRecord, RegionLimits, RegionRecord, TaskRecord};
use crate::runtime::deadline_monitor::{DeadlineWarning, MonitorConfig};
use crate::trace::distributed::LogicalClockMode;
use crate::types::CancelAttributionConfig;
use crate::util::Arena;
use sha2::{Digest, Sha256};
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

/// Storage-temperature policy for runtime metadata and retained evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaTemperaturePolicy {
    /// Keep hot metadata and retained evidence on the unified allocator path.
    Unified,
    /// Separate retained evidence into a colder tier while keeping runtime metadata hot.
    TieredColdEvidence,
    /// Prefer large-page cold slabs for retained evidence when the host supports them.
    TieredColdEvidenceLargePages,
}

impl ArenaTemperaturePolicy {
    /// Returns the stable operator-facing name for the policy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unified => "unified",
            Self::TieredColdEvidence => "tiered-cold-evidence",
            Self::TieredColdEvidenceLargePages => "tiered-cold-evidence-large-pages",
        }
    }
}

impl Default for ArenaTemperaturePolicy {
    fn default() -> Self {
        Self::Unified
    }
}

impl fmt::Display for ArenaTemperaturePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse error for [`ArenaTemperaturePolicy`] text values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseArenaTemperaturePolicyError;

impl fmt::Display for ParseArenaTemperaturePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown arena temperature policy")
    }
}

impl std::error::Error for ParseArenaTemperaturePolicyError {}

impl FromStr for ArenaTemperaturePolicy {
    type Err = ParseArenaTemperaturePolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "unified" => Ok(Self::Unified),
            "tiered-cold-evidence" | "tiered_cold_evidence" => Ok(Self::TieredColdEvidence),
            "tiered-cold-evidence-large-pages" | "tiered_cold_evidence_large_pages" => {
                Ok(Self::TieredColdEvidenceLargePages)
            }
            _ => Err(ParseArenaTemperaturePolicyError),
        }
    }
}

/// Operator-visible cold-tier allocation source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaColdAllocationSource {
    /// All bytes stay on the unified allocator path.
    UnifiedAllocator,
    /// Retained evidence is routed to a colder allocator tier.
    ColdTier,
    /// Retained evidence is routed to a colder allocator tier using large pages.
    ColdTierLargePages,
}

impl ArenaColdAllocationSource {
    /// Returns the stable operator-facing name for the allocation source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnifiedAllocator => "unified_allocator",
            Self::ColdTier => "cold_tier",
            Self::ColdTierLargePages => "cold_tier_large_pages",
        }
    }
}

/// Conservative fallback reasons for arena-temperature planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaTemperatureFallbackReason {
    /// Large-page cold slabs were requested but are unavailable.
    LargePagesUnsupported,
}

impl ArenaTemperatureFallbackReason {
    /// Returns the stable operator-facing name for the fallback.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LargePagesUnsupported => "large_pages_unsupported",
        }
    }
}

/// Operator-facing accounting report for arena temperature planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaTemperatureReport {
    /// Requested runtime policy.
    pub requested_policy: ArenaTemperaturePolicy,
    /// Effective runtime policy after conservative fallback handling.
    pub effective_policy: ArenaTemperaturePolicy,
    /// Optional fallback reason if the effective policy differs from the requested policy.
    pub fallback_reason: Option<ArenaTemperatureFallbackReason>,
    /// Allocation source selected for retained evidence.
    pub cold_allocation_source: ArenaColdAllocationSource,
    /// Whether large-page cold slabs are active for retained evidence.
    pub large_page_cold_slabs_active: bool,
    /// Estimated hot bytes reserved for the task table.
    pub hot_task_table_bytes: usize,
    /// Estimated hot bytes reserved for the region table.
    pub hot_region_table_bytes: usize,
    /// Estimated hot bytes reserved for the obligation table.
    pub hot_obligation_table_bytes: usize,
    /// Estimated bytes reserved for the hot trace ring.
    pub hot_trace_ring_bytes: usize,
    /// Estimated retained evidence bytes across cancellation/distributed traces.
    pub retained_evidence_bytes: usize,
    /// Estimated retained evidence bytes explicitly routed into the cold tier.
    pub cold_evidence_bytes: usize,
}

impl ArenaTemperatureReport {
    /// Estimated bytes intentionally kept on the hot path.
    #[must_use]
    pub const fn estimated_hot_bytes(&self) -> usize {
        self.hot_task_table_bytes
            .saturating_add(self.hot_region_table_bytes)
            .saturating_add(self.hot_obligation_table_bytes)
            .saturating_add(self.hot_trace_ring_bytes)
    }

    /// Estimated total bytes across hot metadata and retained evidence.
    #[must_use]
    pub const fn estimated_total_bytes(&self) -> usize {
        self.estimated_hot_bytes()
            .saturating_add(self.retained_evidence_bytes)
    }

    /// Render the stable operator-facing report fields.
    #[must_use]
    pub fn render_report_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("requested_policy", self.requested_policy.to_string()),
            ("effective_policy", self.effective_policy.to_string()),
            (
                "fallback_reason",
                self.fallback_reason
                    .map_or_else(|| "none".to_string(), |reason| reason.as_str().to_string()),
            ),
            (
                "cold_allocation_source",
                self.cold_allocation_source.as_str().to_string(),
            ),
            (
                "large_page_cold_slabs_active",
                format_bool(self.large_page_cold_slabs_active),
            ),
            (
                "hot_task_table_bytes",
                self.hot_task_table_bytes.to_string(),
            ),
            (
                "hot_region_table_bytes",
                self.hot_region_table_bytes.to_string(),
            ),
            (
                "hot_obligation_table_bytes",
                self.hot_obligation_table_bytes.to_string(),
            ),
            (
                "hot_trace_ring_bytes",
                self.hot_trace_ring_bytes.to_string(),
            ),
            (
                "retained_evidence_bytes",
                self.retained_evidence_bytes.to_string(),
            ),
            ("cold_evidence_bytes", self.cold_evidence_bytes.to_string()),
            (
                "estimated_hot_bytes",
                self.estimated_hot_bytes().to_string(),
            ),
            (
                "estimated_total_bytes",
                self.estimated_total_bytes().to_string(),
            ),
        ]
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

fn build_arena_temperature_report(
    capacity_hints: RuntimeCapacityHints,
    trace_storage_budget: TraceStorageBudget,
    requested_policy: ArenaTemperaturePolicy,
    large_page_cold_slabs_supported: bool,
) -> ArenaTemperatureReport {
    let hot_task_table_bytes =
        Arena::<TaskRecord>::estimated_bytes_for_capacity(capacity_hints.task_capacity);
    let hot_region_table_bytes =
        Arena::<RegionRecord>::estimated_bytes_for_capacity(capacity_hints.region_capacity);
    let hot_obligation_table_bytes =
        Arena::<ObligationRecord>::estimated_bytes_for_capacity(capacity_hints.obligation_capacity);
    let retained_evidence_bytes = trace_storage_budget.estimated_cold_bytes();

    let (effective_policy, fallback_reason, cold_allocation_source, large_page_cold_slabs_active) =
        match requested_policy {
            ArenaTemperaturePolicy::Unified => (
                ArenaTemperaturePolicy::Unified,
                None,
                ArenaColdAllocationSource::UnifiedAllocator,
                false,
            ),
            ArenaTemperaturePolicy::TieredColdEvidence => (
                ArenaTemperaturePolicy::TieredColdEvidence,
                None,
                ArenaColdAllocationSource::ColdTier,
                false,
            ),
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages => {
                if large_page_cold_slabs_supported {
                    (
                        ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
                        None,
                        ArenaColdAllocationSource::ColdTierLargePages,
                        true,
                    )
                } else {
                    (
                        ArenaTemperaturePolicy::TieredColdEvidence,
                        Some(ArenaTemperatureFallbackReason::LargePagesUnsupported),
                        ArenaColdAllocationSource::ColdTier,
                        false,
                    )
                }
            }
        };

    let cold_evidence_bytes = if matches!(effective_policy, ArenaTemperaturePolicy::Unified) {
        0
    } else {
        retained_evidence_bytes
    };

    ArenaTemperatureReport {
        requested_policy,
        effective_policy,
        fallback_reason,
        cold_allocation_source,
        large_page_cold_slabs_active,
        hot_task_table_bytes,
        hot_region_table_bytes,
        hot_obligation_table_bytes,
        hot_trace_ring_bytes: trace_storage_budget.estimated_hot_bytes(),
        retained_evidence_bytes,
        cold_evidence_bytes,
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
    /// Storage-temperature policy for hot runtime metadata and retained evidence.
    pub arena_temperature_policy: ArenaTemperaturePolicy,
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

    /// Returns the operator-facing arena temperature report for the selected policy.
    ///
    /// The `large_page_cold_slabs_supported` flag lets callers fail closed on
    /// hosts where large-page cold slabs are unavailable. The default runtime
    /// path should pass real host support when that probe exists; until then
    /// tests and dry-run planners can drive the conservative branch explicitly.
    #[must_use]
    pub fn arena_temperature_report(
        &self,
        large_page_cold_slabs_supported: bool,
    ) -> ArenaTemperatureReport {
        build_arena_temperature_report(
            self.resolved_capacity_hints(),
            self.trace_storage_budget(),
            self.arena_temperature_policy,
            large_page_cold_slabs_supported,
        )
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
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
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

/// Brownout phase captured in the capacity-envelope evidence snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityEnvelopeBrownoutStage {
    /// No controller fallback has activated yet.
    FullSurfaces,
    /// Optional surfaces are already brownout-gated.
    OptionalFirst,
    /// Priority-gated observability shedding is active.
    PriorityGate,
    /// Conservative standalone fallback is active.
    StandaloneFallback,
}

impl CapacityEnvelopeBrownoutStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullSurfaces => "full_surfaces",
            Self::OptionalFirst => "optional_first",
            Self::PriorityGate => "priority_gate",
            Self::StandaloneFallback => "standalone_fallback",
        }
    }
}

impl fmt::Display for CapacityEnvelopeBrownoutStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Host fingerprint used to reject stale or mismatched capacity evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityEnvelopeHostFingerprint {
    /// Operator-visible host label.
    pub hostname: String,
    /// CPU architecture.
    pub arch: String,
    /// Online CPU cores for the measured host.
    pub cpu_cores: usize,
    /// Measured RAM envelope in GiB.
    pub memory_gib: usize,
}

impl CapacityEnvelopeHostFingerprint {
    fn validate_for_resources(
        &self,
        resources: &HostProfileHostResources,
        label: &str,
    ) -> Result<(), String> {
        if self.hostname.trim().is_empty() {
            return Err(format!("{label} hostname must not be empty"));
        }
        if self.arch.trim().is_empty() {
            return Err(format!("{label} arch must not be empty"));
        }
        if self.cpu_cores == 0 {
            return Err(format!("{label} cpu_cores must be positive"));
        }
        if self.memory_gib == 0 {
            return Err(format!("{label} memory_gib must be positive"));
        }
        if self.cpu_cores != resources.cpu_cores {
            return Err(format!(
                "{label} cpu_cores {} did not match requested host cpu_cores {}",
                self.cpu_cores, resources.cpu_cores
            ));
        }
        if self.memory_gib != resources.memory_gib {
            return Err(format!(
                "{label} memory_gib {} did not match requested host memory_gib {}",
                self.memory_gib, resources.memory_gib
            ));
        }
        Ok(())
    }
}

/// Performance and artifact evidence consumed by the capacity-envelope planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityEnvelopeEvidenceSnapshot {
    /// Scenario artifact identifier.
    pub scenario_artifact_id: String,
    /// Stable scenario artifact hash.
    pub scenario_artifact_hash: String,
    /// Scenario contract version.
    pub scenario_contract_version: String,
    /// Host fingerprint that produced the evidence.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Age of the evidence in hours.
    pub artifact_age_hours: u64,
    /// Worker count used for the measured scenario.
    pub measured_worker_count: usize,
    /// Agent count used for the measured scenario.
    pub measured_agent_count: usize,
    /// Queue depth observed in the measured scenario.
    pub measured_queue_depth: usize,
    /// Throughput observed during the measured scenario.
    pub throughput_ops_per_sec: u64,
    /// Wake-to-run p50 in nanoseconds.
    pub wake_to_run_p50_ns: u64,
    /// Wake-to-run p95 in nanoseconds.
    pub wake_to_run_p95_ns: u64,
    /// Wake-to-run p99 in nanoseconds.
    pub wake_to_run_p99_ns: u64,
    /// Cancellation debt units observed during the measured scenario.
    pub cancellation_debt_units: u64,
    /// Observed memory pressure in basis points.
    pub memory_pressure_basis_points: u16,
    /// Brownout stage active while the evidence was measured.
    pub brownout_stage: CapacityEnvelopeBrownoutStage,
    /// Brownout risk in basis points.
    pub brownout_risk_basis_points: u16,
    /// Retention budget already consumed by evidence storage on the host.
    pub retention_budget_gib: usize,
}

impl CapacityEnvelopeEvidenceSnapshot {
    fn validate(
        &self,
        max_artifact_age_hours: u64,
        resources: &HostProfileHostResources,
        request_fingerprint: &CapacityEnvelopeHostFingerprint,
    ) -> Result<(), String> {
        if self.scenario_artifact_id.trim().is_empty() {
            return Err("scenario_artifact_id must not be empty".to_string());
        }
        if !self.scenario_artifact_id.ends_with(".json") {
            return Err("scenario_artifact_id must end with .json".to_string());
        }
        if self.scenario_artifact_id.contains("..") {
            return Err(
                "scenario_artifact_id must not contain parent-directory traversals".to_string(),
            );
        }
        if !self
            .scenario_artifact_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
            || self.scenario_artifact_hash.len() < 16
        {
            return Err("scenario_artifact_hash must be a hexadecimal digest".to_string());
        }
        if self.scenario_contract_version.trim().is_empty() {
            return Err("scenario_contract_version must not be empty".to_string());
        }
        self.host_fingerprint
            .validate_for_resources(resources, "scenario host fingerprint")?;
        request_fingerprint.validate_for_resources(resources, "request host fingerprint")?;
        if self.host_fingerprint.hostname != request_fingerprint.hostname
            || self.host_fingerprint.arch != request_fingerprint.arch
        {
            return Err(
                "scenario host fingerprint did not match the requested host fingerprint"
                    .to_string(),
            );
        }
        if self.artifact_age_hours > max_artifact_age_hours {
            return Err(format!(
                "artifact_age_hours {} exceeded the freshness budget {}",
                self.artifact_age_hours, max_artifact_age_hours
            ));
        }
        if self.measured_worker_count == 0 {
            return Err("measured_worker_count must be positive".to_string());
        }
        if self.measured_agent_count == 0 {
            return Err("measured_agent_count must be positive".to_string());
        }
        if self.wake_to_run_p50_ns == 0
            || self.wake_to_run_p95_ns == 0
            || self.wake_to_run_p99_ns == 0
        {
            return Err("wake-to-run percentiles must be positive".to_string());
        }
        if self.wake_to_run_p50_ns > self.wake_to_run_p95_ns
            || self.wake_to_run_p95_ns > self.wake_to_run_p99_ns
        {
            return Err("wake-to-run percentiles must be monotonic".to_string());
        }
        if self.memory_pressure_basis_points > 10_000 {
            return Err("memory_pressure_basis_points must be <= 10000".to_string());
        }
        if self.brownout_risk_basis_points > 10_000 {
            return Err("brownout_risk_basis_points must be <= 10000".to_string());
        }
        Ok(())
    }
}

/// Capacity budgets the planner refuses to exceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityEnvelopeBudget {
    /// Maximum tolerated p99 wake-to-run latency in nanoseconds.
    pub target_p99_ns: u64,
    /// Maximum tolerated cancellation debt units.
    pub target_cancel_debt_units: u64,
    /// Maximum tolerated memory pressure in basis points.
    pub max_memory_pressure_basis_points: u16,
    /// Maximum tolerated brownout risk in basis points.
    pub max_brownout_risk_basis_points: u16,
    /// Maximum tolerated queue depth.
    pub max_queue_depth: usize,
    /// Maximum age for accepted evidence artifacts.
    pub max_artifact_age_hours: u64,
}

impl Default for CapacityEnvelopeBudget {
    fn default() -> Self {
        Self {
            target_p99_ns: 1_300_000,
            target_cancel_debt_units: 130,
            max_memory_pressure_basis_points: 7_000,
            max_brownout_risk_basis_points: 1_400,
            max_queue_depth: 45_000,
            max_artifact_age_hours: 48,
        }
    }
}

/// Manual SLO overrides that win over the default certificate budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapacityEnvelopeBudgetOverrides {
    /// Override for the p99 wake-to-run budget.
    pub target_p99_ns: Option<u64>,
    /// Override for the cancellation debt budget.
    pub target_cancel_debt_units: Option<u64>,
    /// Override for the memory pressure budget.
    pub max_memory_pressure_basis_points: Option<u16>,
    /// Override for the brownout risk budget.
    pub max_brownout_risk_basis_points: Option<u16>,
    /// Override for the queue depth budget.
    pub max_queue_depth: Option<usize>,
    /// Override for the evidence freshness budget.
    pub max_artifact_age_hours: Option<u64>,
}

impl CapacityEnvelopeBudget {
    #[must_use]
    pub const fn with_overrides(self, overrides: CapacityEnvelopeBudgetOverrides) -> Self {
        Self {
            target_p99_ns: match overrides.target_p99_ns {
                Some(value) => value,
                None => self.target_p99_ns,
            },
            target_cancel_debt_units: match overrides.target_cancel_debt_units {
                Some(value) => value,
                None => self.target_cancel_debt_units,
            },
            max_memory_pressure_basis_points: match overrides.max_memory_pressure_basis_points {
                Some(value) => value,
                None => self.max_memory_pressure_basis_points,
            },
            max_brownout_risk_basis_points: match overrides.max_brownout_risk_basis_points {
                Some(value) => value,
                None => self.max_brownout_risk_basis_points,
            },
            max_queue_depth: match overrides.max_queue_depth {
                Some(value) => value,
                None => self.max_queue_depth,
            },
            max_artifact_age_hours: match overrides.max_artifact_age_hours {
                Some(value) => value,
                None => self.max_artifact_age_hours,
            },
        }
    }
}

/// Request for a dry-run capacity envelope certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityEnvelopePlannerRequest {
    /// Objective used when no explicit profile is forced.
    pub objective: HostProfilePlannerObjective,
    /// Explicit requested profile, when one is supplied.
    pub requested_profile: Option<HostProfileId>,
    /// Host resources for the target deployment.
    pub host_resources: HostProfileHostResources,
    /// Controller evidence proving the profile is eligible.
    pub controller_evidence: HostProfileEvidenceSet,
    /// Manual config overrides that must be reflected in the certified plan.
    pub manual_overrides: HostProfileManualOverrides,
    /// Requested host fingerprint.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Measured evidence from the swarm scenario runner.
    pub evidence_snapshot: CapacityEnvelopeEvidenceSnapshot,
    /// Candidate worker counts to evaluate.
    pub candidate_worker_counts: Vec<usize>,
    /// Candidate agent counts to evaluate.
    pub candidate_agent_counts: Vec<usize>,
    /// Conservative certificate budget.
    pub budget: CapacityEnvelopeBudget,
    /// Manual SLO overrides applied to the certificate budget.
    pub budget_overrides: CapacityEnvelopeBudgetOverrides,
    /// Optional environment note that must be secret-scrubbed.
    pub environment_note: Option<String>,
    /// Optional validation command summary that must be secret-scrubbed.
    pub validation_command: Option<String>,
}

impl CapacityEnvelopePlannerRequest {
    /// Compute a dry-run capacity envelope certificate.
    #[must_use]
    pub fn plan(&self) -> CapacityEnvelopeCertificate {
        let effective_budget = self.budget.with_overrides(self.budget_overrides);
        let host_profile_plan = HostProfilePlannerRequest {
            objective: self.objective,
            requested_profile: self.requested_profile,
            host_resources: self.host_resources,
            controller_evidence: self.controller_evidence.clone(),
            manual_overrides: self.manual_overrides.clone(),
            operator_note: None,
        }
        .plan();
        let fallback_profile = HostProfileId::ConservativeBaseline;
        let sanitized_environment_note =
            self.environment_note.as_deref().map(redact_sensitive_note);
        let sanitized_validation_command = self
            .validation_command
            .as_deref()
            .map(redact_sensitive_note);
        let mut refusal_reasons = Vec::new();
        if let Err(reason) = self
            .host_fingerprint
            .validate_for_resources(&self.host_resources, "request host fingerprint")
        {
            refusal_reasons.push(reason);
        }
        if let Err(reason) = self.evidence_snapshot.validate(
            effective_budget.max_artifact_age_hours,
            &self.host_resources,
            &self.host_fingerprint,
        ) {
            refusal_reasons.push(format!("scenario evidence rejected: {reason}"));
        }
        if host_profile_plan.used_safe_fallback() {
            refusal_reasons.extend(host_profile_plan.refusal_reasons.clone());
        }

        let profile = if refusal_reasons.is_empty() {
            host_profile_plan.selected_profile
        } else {
            fallback_profile
        };
        let candidate_worker_counts = normalize_capacity_sweep(
            &self.candidate_worker_counts,
            host_profile_plan
                .final_bundle
                .worker_threads
                .min(self.host_resources.cpu_cores)
                .max(1),
        );
        let candidate_agent_counts =
            normalize_capacity_sweep(&self.candidate_agent_counts, usize::MAX);
        let assumptions_ledger =
            build_capacity_assumptions(profile, &self.evidence_snapshot, effective_budget);

        let mut evaluations = Vec::new();
        if refusal_reasons.is_empty() {
            for worker_count in &candidate_worker_counts {
                for agent_count in &candidate_agent_counts {
                    evaluations.push(evaluate_capacity_point(
                        profile,
                        &self.host_resources,
                        &self.evidence_snapshot,
                        effective_budget,
                        *worker_count,
                        *agent_count,
                    ));
                }
            }
        }

        let selected_safe_point = evaluations
            .iter()
            .filter(|point| point.status == CapacityEnvelopePointStatus::Safe)
            .max_by_key(|point| (point.agent_count, point.worker_count))
            .cloned();
        if refusal_reasons.is_empty() && selected_safe_point.is_none() {
            refusal_reasons.push(
                "no safe worker/agent combination satisfied the latency, cancellation, memory, and brownout budgets"
                    .to_string(),
            );
        }

        let selected_profile = if refusal_reasons.is_empty() {
            profile
        } else {
            fallback_profile
        };

        let safe_envelope = summarize_safe_envelope(selected_safe_point, &evaluations);
        let refused_envelope = summarize_refused_envelope(
            &self.host_resources,
            &candidate_worker_counts,
            &candidate_agent_counts,
            &evaluations,
        );

        CapacityEnvelopeCertificate {
            objective: self.objective,
            requested_profile: self.requested_profile,
            selected_profile,
            fallback_profile,
            profile_bundle: host_profile_plan.profile_bundle,
            final_bundle: host_profile_plan.final_bundle,
            assumptions_ledger,
            refusal_reasons,
            evidence_artifact_ids: host_profile_plan.input_evidence_artifact_ids,
            host_fingerprint: self.host_fingerprint.clone(),
            evidence_snapshot: self.evidence_snapshot.clone(),
            effective_budget,
            candidate_worker_counts,
            candidate_agent_counts,
            safe_envelope,
            refused_envelope,
            evaluations,
            sanitized_environment_note,
            sanitized_validation_command,
        }
    }
}

/// Summary of the safe or refused capacity envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityEnvelopeRange {
    /// Minimum worker count represented by this range.
    pub worker_min: usize,
    /// Maximum worker count represented by this range.
    pub worker_max: usize,
    /// Minimum agent count represented by this range.
    pub agent_min: usize,
    /// Maximum agent count represented by this range.
    pub agent_max: usize,
    /// Maximum predicted queue depth within the range.
    pub max_queue_depth: usize,
    /// Maximum predicted memory footprint within the range.
    pub max_memory_gib: usize,
}

/// Pass/fail verdict for one evaluated capacity point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityEnvelopePointStatus {
    /// The point is inside the safe envelope.
    Safe,
    /// The point is outside the safe envelope.
    Refused,
}

/// Evaluation of one worker/agent point in the capacity sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityEnvelopePointEvaluation {
    /// Candidate worker count.
    pub worker_count: usize,
    /// Candidate agent count.
    pub agent_count: usize,
    /// Predicted p50 wake-to-run in nanoseconds.
    pub predicted_p50_ns: u64,
    /// Predicted p95 wake-to-run in nanoseconds.
    pub predicted_p95_ns: u64,
    /// Predicted p99 wake-to-run in nanoseconds.
    pub predicted_p99_ns: u64,
    /// Predicted cancellation debt units.
    pub predicted_cancellation_debt_units: u64,
    /// Predicted queue depth.
    pub predicted_queue_depth: usize,
    /// Predicted memory footprint in GiB.
    pub predicted_memory_gib: usize,
    /// Predicted memory pressure in basis points.
    pub predicted_memory_pressure_basis_points: u16,
    /// Predicted brownout risk in basis points.
    pub predicted_brownout_risk_basis_points: u16,
    /// Safe/refused verdict for the point.
    pub status: CapacityEnvelopePointStatus,
    /// Reasons the point was refused, when applicable.
    pub refusal_reasons: Vec<String>,
}

/// Dry-run capacity certificate consumed by operator tooling and signoff.
#[derive(Clone)]
pub struct CapacityEnvelopeCertificate {
    /// Objective used for the certificate.
    pub objective: HostProfilePlannerObjective,
    /// Explicitly requested profile, when one was supplied.
    pub requested_profile: Option<HostProfileId>,
    /// Certified profile after fallback/refusal handling.
    pub selected_profile: HostProfileId,
    /// Conservative fallback profile.
    pub fallback_profile: HostProfileId,
    /// Profile bundle before manual overrides.
    pub profile_bundle: RuntimeConfig,
    /// Final bundle after manual overrides.
    pub final_bundle: RuntimeConfig,
    /// Assumptions ledger behind the certificate math.
    pub assumptions_ledger: Vec<String>,
    /// Reasons the requested or preferred certificate was refused.
    pub refusal_reasons: Vec<String>,
    /// Child evidence artifact IDs used by the certificate.
    pub evidence_artifact_ids: Vec<String>,
    /// Host fingerprint for the certified host.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Performance evidence snapshot used by the certificate.
    pub evidence_snapshot: CapacityEnvelopeEvidenceSnapshot,
    /// Effective SLO/capacity budget after overrides.
    pub effective_budget: CapacityEnvelopeBudget,
    /// Candidate worker counts considered by the planner.
    pub candidate_worker_counts: Vec<usize>,
    /// Candidate agent counts considered by the planner.
    pub candidate_agent_counts: Vec<usize>,
    /// Safe envelope summary, when one exists.
    pub safe_envelope: Option<CapacityEnvelopeRange>,
    /// Refused envelope summary.
    pub refused_envelope: CapacityEnvelopeRange,
    /// Point-by-point sweep evaluation.
    pub evaluations: Vec<CapacityEnvelopePointEvaluation>,
    /// Secret-scrubbed environment note.
    pub sanitized_environment_note: Option<String>,
    /// Secret-scrubbed validation command summary.
    pub sanitized_validation_command: Option<String>,
}

impl CapacityEnvelopeCertificate {
    /// Whether the certificate had to fall back conservatively.
    #[must_use]
    pub fn used_safe_fallback(&self) -> bool {
        self.selected_profile == self.fallback_profile && !self.refusal_reasons.is_empty()
    }
}

/// Integrity mode for operator-facing profile bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedProfileBundleIntegrityMode {
    /// Digest-only integrity; no asymmetric signing primitive is wired yet.
    DigestOnlySha256,
}

impl SignedProfileBundleIntegrityMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DigestOnlySha256 => "digest_only_sha256",
        }
    }
}

impl fmt::Display for SignedProfileBundleIntegrityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Execution posture requested by the bundle runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedProfileBundleExecutionMode {
    /// Emit the bundle and receipt only; do not model an apply step.
    DryRun,
    /// Verify the emitted bundle for tamper or structural drift.
    Verify,
    /// Compare the emitted bundle against the conservative baseline before promotion.
    ShadowRun,
}

impl SignedProfileBundleExecutionMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::Verify => "verify",
            Self::ShadowRun => "shadow_run",
        }
    }
}

impl fmt::Display for SignedProfileBundleExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One controller-version claim embedded in the bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleControllerVersion {
    /// Controller surface name.
    pub controller: String,
    /// Version string emitted by the controller proof surface.
    pub contract_version: String,
}

impl SignedProfileBundleControllerVersion {
    fn validate(&self, label: &str) -> Result<(), String> {
        validate_slug_like(&self.controller, &format!("{label} controller"))?;
        if self.contract_version.trim().is_empty() {
            return Err(format!("{label} contract_version must not be empty"));
        }
        Ok(())
    }
}

/// Deterministic digest of one child proof surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleChildEvidenceHash {
    /// Controller surface name.
    pub controller: String,
    /// Referenced artifact path.
    pub artifact_id: String,
    /// Stable digest of the child proof reference.
    pub digest_sha256: String,
}

impl SignedProfileBundleChildEvidenceHash {
    fn validate(&self) -> Result<(), String> {
        validate_slug_like(&self.controller, "child evidence controller")?;
        validate_artifact_json_path(&self.artifact_id, "child evidence artifact_id")?;
        if !is_hex_digest(&self.digest_sha256) {
            return Err(
                "child evidence digest_sha256 must be a 64-character hexadecimal digest"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Capacity certificate reference embedded in the signed bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleCapacityCertificateReference {
    /// Referenced artifact path.
    pub artifact_id: String,
    /// Contract version for the certificate runner.
    pub contract_version: String,
    /// Scenario identifier inside the certificate contract.
    pub scenario_id: String,
}

impl SignedProfileBundleCapacityCertificateReference {
    fn validate(&self) -> Result<(), String> {
        validate_artifact_json_path(&self.artifact_id, "capacity certificate artifact_id")?;
        if self.contract_version.trim().is_empty() {
            return Err("capacity certificate contract_version must not be empty".to_string());
        }
        if self.scenario_id.trim().is_empty() {
            return Err("capacity certificate scenario_id must not be empty".to_string());
        }
        Ok(())
    }
}

/// Canonical request for a profile-bundle manifest and rollback receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleManifestRequest {
    /// Automatic recommendation objective.
    pub objective: HostProfilePlannerObjective,
    /// Optional explicit profile request.
    pub requested_profile: Option<HostProfileId>,
    /// Host resources for the target deployment.
    pub host_resources: HostProfileHostResources,
    /// Controller proof surfaces available to the planner.
    pub controller_evidence: HostProfileEvidenceSet,
    /// Manual overrides that must win over the profile bundle.
    pub manual_overrides: HostProfileManualOverrides,
    /// Requested host fingerprint for the target host.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Measured evidence snapshot for the host.
    pub evidence_snapshot: CapacityEnvelopeEvidenceSnapshot,
    /// Capacity budget used by the downstream certificate planner.
    pub capacity_budget: CapacityEnvelopeBudget,
    /// Candidate worker counts for the capacity sweep.
    pub candidate_worker_counts: Vec<usize>,
    /// Candidate agent counts for the capacity sweep.
    pub candidate_agent_counts: Vec<usize>,
    /// Stable bundle identifier.
    pub bundle_id: String,
    /// Integrity mode exposed to operators.
    pub integrity_mode: SignedProfileBundleIntegrityMode,
    /// Classes of proof commands that justified the bundle.
    pub proof_command_classes: Vec<String>,
    /// Claimed controller versions for the manifest.
    pub controller_versions: Vec<SignedProfileBundleControllerVersion>,
    /// Supported-version allowlist used for verification.
    pub supported_controller_versions: Vec<SignedProfileBundleControllerVersion>,
    /// Referenced capacity certificate surface.
    pub capacity_certificate_reference: SignedProfileBundleCapacityCertificateReference,
    /// Previous runtime-config digest used for rollback.
    pub previous_config_digest: String,
    /// Rollback command template for the operator.
    pub rollback_command_template: String,
    /// Optional operator note, scrubbed before reporting.
    pub operator_note: Option<String>,
    /// Optional validation command summary, scrubbed before reporting.
    pub validation_command: Option<String>,
    /// Whether the operator must explicitly confirm application.
    pub require_operator_confirmation: bool,
    /// Requested execution posture.
    pub execute_mode: SignedProfileBundleExecutionMode,
    /// Optional field mutation used to prove tamper detection.
    pub tamper_field: Option<String>,
}

impl SignedProfileBundleManifestRequest {
    /// Build the canonical manifest, structural verification result, and rollback receipt.
    #[must_use]
    pub fn plan(&self) -> SignedProfileBundleBundle {
        let host_profile_plan = HostProfilePlannerRequest {
            objective: self.objective,
            requested_profile: self.requested_profile,
            host_resources: self.host_resources,
            controller_evidence: self.controller_evidence.clone(),
            manual_overrides: self.manual_overrides.clone(),
            operator_note: self.operator_note.clone(),
        }
        .plan();

        let capacity_certificate = CapacityEnvelopePlannerRequest {
            objective: self.objective,
            requested_profile: self.requested_profile,
            host_resources: self.host_resources,
            controller_evidence: self.controller_evidence.clone(),
            manual_overrides: self.manual_overrides.clone(),
            host_fingerprint: self.host_fingerprint.clone(),
            evidence_snapshot: self.evidence_snapshot.clone(),
            candidate_worker_counts: self.candidate_worker_counts.clone(),
            candidate_agent_counts: self.candidate_agent_counts.clone(),
            budget: self.capacity_budget,
            budget_overrides: CapacityEnvelopeBudgetOverrides::default(),
            environment_note: None,
            validation_command: None,
        }
        .plan();

        let bundle_plan =
            if capacity_certificate.selected_profile == host_profile_plan.selected_profile {
                host_profile_plan
            } else {
                HostProfilePlannerRequest {
                    objective: self.objective,
                    requested_profile: Some(capacity_certificate.selected_profile),
                    host_resources: self.host_resources,
                    controller_evidence: self.controller_evidence.clone(),
                    manual_overrides: self.manual_overrides.clone(),
                    operator_note: self.operator_note.clone(),
                }
                .plan()
            };

        let child_evidence_hashes =
            build_signed_profile_bundle_child_evidence_hashes(&self.controller_evidence);
        let feature_gates = build_signed_profile_bundle_feature_gates(&bundle_plan.final_bundle);
        let integrity_limitations = vec![
            "digest-only mode; no asymmetric signature primitive is currently wired for profile bundles"
                .to_string(),
        ];

        let mut manifest = SignedProfileBundleManifest {
            bundle_id: self.bundle_id.clone(),
            objective: self.objective,
            requested_profile: self.requested_profile,
            selected_profile: capacity_certificate.selected_profile,
            fallback_profile: capacity_certificate.fallback_profile,
            used_safe_fallback: capacity_certificate.used_safe_fallback(),
            planning_refusal_reasons: capacity_certificate.refusal_reasons.clone(),
            requested_host_resources: self.host_resources,
            host_fingerprint: self.host_fingerprint.clone(),
            integrity_mode: self.integrity_mode,
            integrity_limitations,
            proof_command_classes: self.proof_command_classes.clone(),
            feature_gates,
            manual_override_fields: bundle_plan.manual_overrides_applied.clone(),
            require_operator_confirmation: self.require_operator_confirmation,
            profile_bundle_digest: runtime_config_digest(&bundle_plan.profile_bundle),
            final_bundle_digest: runtime_config_digest(&bundle_plan.final_bundle),
            config_diff_digest: host_profile_config_diff_digest(&bundle_plan.config_diff),
            previous_config_digest: self.previous_config_digest.clone(),
            rollback_command_template: self.rollback_command_template.clone(),
            sanitized_operator_note: self.operator_note.as_deref().map(redact_sensitive_note),
            sanitized_validation_command: self
                .validation_command
                .as_deref()
                .map(redact_sensitive_note),
            manifest_digest_sha256: String::new(),
            capacity_certificate_reference: self.capacity_certificate_reference.clone(),
            controller_versions: self.controller_versions.clone(),
            supported_controller_versions: self.supported_controller_versions.clone(),
            child_evidence_hashes,
        };
        manifest.manifest_digest_sha256 = manifest.compute_manifest_digest();
        if let Some(field) = self.tamper_field.as_deref() {
            tamper_signed_profile_bundle_manifest(&mut manifest, field);
        }
        let verification = manifest.verify(self.execute_mode, self.tamper_field.clone());
        let shadow_run_evaluation =
            if self.execute_mode == SignedProfileBundleExecutionMode::ShadowRun {
                Some(build_signed_profile_bundle_shadow_run_evaluation(
                    self,
                    &capacity_certificate,
                    &manifest,
                    &verification,
                ))
            } else {
                None
            };
        let rollback_receipt = SignedProfileBundleRollbackReceipt::from_manifest(&manifest);
        SignedProfileBundleBundle {
            manifest,
            verification,
            shadow_run_evaluation,
            rollback_receipt,
        }
    }
}

/// Canonical bundle manifest consumed by operator tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleManifest {
    /// Stable bundle identifier.
    pub bundle_id: String,
    /// Automatic recommendation objective.
    pub objective: HostProfilePlannerObjective,
    /// Explicit requested profile, when supplied.
    pub requested_profile: Option<HostProfileId>,
    /// Selected profile after graceful fallback handling.
    pub selected_profile: HostProfileId,
    /// Conservative fallback profile.
    pub fallback_profile: HostProfileId,
    /// Whether the planner had to degrade to the fallback profile.
    pub used_safe_fallback: bool,
    /// Planning-time reasons for degrading conservatively.
    pub planning_refusal_reasons: Vec<String>,
    /// Requested host resources for the target deployment.
    pub requested_host_resources: HostProfileHostResources,
    /// Requested host fingerprint.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Integrity mode exposed to the operator.
    pub integrity_mode: SignedProfileBundleIntegrityMode,
    /// Explicit integrity limitations for the selected mode.
    pub integrity_limitations: Vec<String>,
    /// Proof command classes that justified the bundle.
    pub proof_command_classes: Vec<String>,
    /// Enabled runtime feature gates captured by the bundle.
    pub feature_gates: Vec<String>,
    /// Manual override metadata that changed the final bundle.
    pub manual_override_fields: Vec<String>,
    /// Whether operator confirmation is required before apply.
    pub require_operator_confirmation: bool,
    /// Digest of the bundle before manual overrides.
    pub profile_bundle_digest: String,
    /// Digest of the final bundle after manual overrides.
    pub final_bundle_digest: String,
    /// Digest of the dry-run config diff.
    pub config_diff_digest: String,
    /// Previous runtime-config digest used for rollback.
    pub previous_config_digest: String,
    /// Rollback command template for operators.
    pub rollback_command_template: String,
    /// Secret-scrubbed operator note.
    pub sanitized_operator_note: Option<String>,
    /// Secret-scrubbed validation command summary.
    pub sanitized_validation_command: Option<String>,
    /// Digest over the manifest contents.
    pub manifest_digest_sha256: String,
    /// Referenced capacity certificate surface.
    pub capacity_certificate_reference: SignedProfileBundleCapacityCertificateReference,
    /// Claimed controller versions for the bundle.
    pub controller_versions: Vec<SignedProfileBundleControllerVersion>,
    /// Supported-version allowlist for verification.
    pub supported_controller_versions: Vec<SignedProfileBundleControllerVersion>,
    /// Deterministic digests for each child proof reference.
    pub child_evidence_hashes: Vec<SignedProfileBundleChildEvidenceHash>,
}

impl SignedProfileBundleManifest {
    fn compute_manifest_digest(&self) -> String {
        stable_sha256_hex(&[
            ("bundle_id", self.bundle_id.clone()),
            ("objective", self.objective.as_str().to_string()),
            (
                "requested_profile",
                self.requested_profile.map_or_else(
                    || "none".to_string(),
                    |profile| profile.as_str().to_string(),
                ),
            ),
            (
                "selected_profile",
                self.selected_profile.as_str().to_string(),
            ),
            (
                "fallback_profile",
                self.fallback_profile.as_str().to_string(),
            ),
            ("used_safe_fallback", format_bool(self.used_safe_fallback)),
            (
                "planning_refusal_reasons",
                self.planning_refusal_reasons.join("|"),
            ),
            (
                "requested_host_resources",
                format!(
                    "{}x{}",
                    self.requested_host_resources.cpu_cores,
                    self.requested_host_resources.memory_gib
                ),
            ),
            (
                "host_fingerprint",
                format!(
                    "{}|{}|{}|{}",
                    self.host_fingerprint.hostname,
                    self.host_fingerprint.arch,
                    self.host_fingerprint.cpu_cores,
                    self.host_fingerprint.memory_gib
                ),
            ),
            ("integrity_mode", self.integrity_mode.as_str().to_string()),
            (
                "integrity_limitations",
                self.integrity_limitations.join("|"),
            ),
            (
                "proof_command_classes",
                self.proof_command_classes.join("|"),
            ),
            ("feature_gates", self.feature_gates.join("|")),
            (
                "manual_override_fields",
                self.manual_override_fields.join("|"),
            ),
            (
                "require_operator_confirmation",
                format_bool(self.require_operator_confirmation),
            ),
            ("profile_bundle_digest", self.profile_bundle_digest.clone()),
            ("final_bundle_digest", self.final_bundle_digest.clone()),
            ("config_diff_digest", self.config_diff_digest.clone()),
            (
                "previous_config_digest",
                self.previous_config_digest.clone(),
            ),
            (
                "rollback_command_template",
                self.rollback_command_template.clone(),
            ),
            (
                "sanitized_operator_note",
                self.sanitized_operator_note.clone().unwrap_or_default(),
            ),
            (
                "sanitized_validation_command",
                self.sanitized_validation_command
                    .clone()
                    .unwrap_or_default(),
            ),
            (
                "capacity_certificate_reference",
                format!(
                    "{}|{}|{}",
                    self.capacity_certificate_reference.artifact_id,
                    self.capacity_certificate_reference.contract_version,
                    self.capacity_certificate_reference.scenario_id
                ),
            ),
            (
                "controller_versions",
                self.controller_versions
                    .iter()
                    .map(|entry| format!("{}|{}", entry.controller, entry.contract_version))
                    .collect::<Vec<_>>()
                    .join(";"),
            ),
            (
                "supported_controller_versions",
                self.supported_controller_versions
                    .iter()
                    .map(|entry| format!("{}|{}", entry.controller, entry.contract_version))
                    .collect::<Vec<_>>()
                    .join(";"),
            ),
            (
                "child_evidence_hashes",
                self.child_evidence_hashes
                    .iter()
                    .map(|entry| {
                        format!(
                            "{}|{}|{}",
                            entry.controller, entry.artifact_id, entry.digest_sha256
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";"),
            ),
        ])
    }

    fn verify(
        &self,
        execute_mode: SignedProfileBundleExecutionMode,
        tamper_field: Option<String>,
    ) -> SignedProfileBundleVerificationResult {
        let mut refusal_reasons = Vec::new();
        if self.bundle_id.trim().is_empty() {
            refusal_reasons.push("bundle_id must not be empty".to_string());
        }
        if let Err(reason) = validate_slug_like(&self.bundle_id, "bundle_id") {
            refusal_reasons.push(reason);
        }
        if let Err(reason) = self
            .host_fingerprint
            .validate_for_resources(&self.requested_host_resources, "bundle host fingerprint")
        {
            refusal_reasons.push(reason);
        }
        if self.integrity_limitations.is_empty() {
            refusal_reasons.push(
                "integrity_limitations must describe the explicit limitation of digest-only mode"
                    .to_string(),
            );
        }
        if let Err(reason) =
            validate_token_list(&self.proof_command_classes, "proof_command_classes", false)
        {
            refusal_reasons.push(reason);
        }
        if let Err(reason) = validate_token_list(&self.feature_gates, "feature_gates", true) {
            refusal_reasons.push(reason);
        }
        if let Err(reason) =
            validate_token_list(&self.manual_override_fields, "manual_override_fields", true)
        {
            refusal_reasons.push(reason);
        }
        if !is_hex_digest(&self.profile_bundle_digest) {
            refusal_reasons.push(
                "profile_bundle_digest must be a 64-character hexadecimal digest".to_string(),
            );
        }
        if !is_hex_digest(&self.final_bundle_digest) {
            refusal_reasons
                .push("final_bundle_digest must be a 64-character hexadecimal digest".to_string());
        }
        if !is_hex_digest(&self.config_diff_digest) {
            refusal_reasons
                .push("config_diff_digest must be a 64-character hexadecimal digest".to_string());
        }
        if !is_hex_digest(&self.previous_config_digest) {
            refusal_reasons.push(
                "previous_config_digest must be a 64-character hexadecimal digest".to_string(),
            );
        }
        if !is_hex_digest(&self.manifest_digest_sha256) {
            refusal_reasons.push(
                "manifest_digest_sha256 must be a 64-character hexadecimal digest".to_string(),
            );
        }
        if self.rollback_command_template.trim().is_empty() {
            refusal_reasons.push("rollback_command_template must not be empty".to_string());
        }
        if let Err(reason) = self.capacity_certificate_reference.validate() {
            refusal_reasons.push(reason);
        }
        if self.controller_versions.is_empty() {
            refusal_reasons.push("controller_versions must not be empty".to_string());
        }
        if self.supported_controller_versions.is_empty() {
            refusal_reasons.push("supported_controller_versions must not be empty".to_string());
        }
        if self.child_evidence_hashes.is_empty() {
            refusal_reasons.push("child_evidence_hashes must not be empty".to_string());
        }
        for (index, entry) in self.controller_versions.iter().enumerate() {
            if let Err(reason) = entry.validate(&format!("controller_versions[{index}]")) {
                refusal_reasons.push(reason);
            }
        }
        for (index, entry) in self.supported_controller_versions.iter().enumerate() {
            if let Err(reason) = entry.validate(&format!("supported_controller_versions[{index}]"))
            {
                refusal_reasons.push(reason);
            }
        }
        for entry in &self.child_evidence_hashes {
            if let Err(reason) = entry.validate() {
                refusal_reasons.push(reason);
            }
        }
        if let Some(duplicate) =
            duplicate_controller_version(&self.controller_versions, "controller_versions")
        {
            refusal_reasons.push(duplicate);
        }
        if let Some(duplicate) = duplicate_controller_version(
            &self.supported_controller_versions,
            "supported_controller_versions",
        ) {
            refusal_reasons.push(duplicate);
        }
        if let Some(duplicate) = duplicate_child_evidence_controller(&self.child_evidence_hashes) {
            refusal_reasons.push(duplicate);
        }
        for entry in &self.controller_versions {
            if !self.supported_controller_versions.iter().any(|supported| {
                supported.controller == entry.controller
                    && supported.contract_version == entry.contract_version
            }) {
                refusal_reasons.push(format!(
                    "controller {} version {} is not present in the supported-version allowlist",
                    entry.controller, entry.contract_version
                ));
            }
            if !self
                .child_evidence_hashes
                .iter()
                .any(|hash| hash.controller == entry.controller)
            {
                refusal_reasons.push(format!(
                    "child evidence hash for controller {} is missing",
                    entry.controller
                ));
            }
        }
        let observed_manifest_digest_sha256 = self.compute_manifest_digest();
        if observed_manifest_digest_sha256 != self.manifest_digest_sha256 {
            refusal_reasons.push(format!(
                "manifest_digest_sha256 {} did not match recomputed digest {}",
                self.manifest_digest_sha256, observed_manifest_digest_sha256
            ));
        }
        SignedProfileBundleVerificationResult {
            accepted: refusal_reasons.is_empty(),
            refusal_reasons,
            tamper_field,
            execute_mode,
            expected_manifest_digest_sha256: self.manifest_digest_sha256.clone(),
            observed_manifest_digest_sha256,
        }
    }
}

/// Structural verification result for a bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleVerificationResult {
    /// Whether the bundle passed structural verification.
    pub accepted: bool,
    /// Reasons the bundle was structurally rejected.
    pub refusal_reasons: Vec<String>,
    /// Optional tamper field mutated for the scenario.
    pub tamper_field: Option<String>,
    /// Requested execution posture.
    pub execute_mode: SignedProfileBundleExecutionMode,
    /// Digest embedded in the bundle manifest.
    pub expected_manifest_digest_sha256: String,
    /// Recomputed digest over the manifest contents.
    pub observed_manifest_digest_sha256: String,
}

/// Promote-or-hold verdict from a deterministic shadow-run comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedProfileBundleShadowRunDecision {
    /// Candidate bundle beat the conservative baseline by a sufficient margin.
    Promote,
    /// Candidate bundle should remain in conservative hold mode.
    Hold,
}

impl SignedProfileBundleShadowRunDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Hold => "hold",
        }
    }
}

impl fmt::Display for SignedProfileBundleShadowRunDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Counterfactual comparison between the candidate bundle and conservative baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleShadowRunEvaluation {
    /// Decision emitted by the shadow-run gate.
    pub decision: SignedProfileBundleShadowRunDecision,
    /// Candidate profile evaluated by the shadow run.
    pub candidate_profile: HostProfileId,
    /// Conservative baseline profile.
    pub baseline_profile: HostProfileId,
    /// Candidate worker count at the best safe point.
    pub candidate_worker_count: usize,
    /// Candidate agent count at the best safe point.
    pub candidate_agent_count: usize,
    /// Baseline worker count at the best safe point.
    pub baseline_worker_count: usize,
    /// Baseline agent count at the best safe point.
    pub baseline_agent_count: usize,
    /// Weighted candidate loss score in basis points.
    pub candidate_loss_basis_points: u64,
    /// Weighted baseline loss score in basis points.
    pub baseline_loss_basis_points: u64,
    /// Baseline loss minus candidate loss. Positive means candidate improvement.
    pub regret_margin_basis_points: i64,
    /// Human-readable reasons the candidate was held.
    pub hold_reasons: Vec<String>,
    /// Human-readable dominant comparison reasons.
    pub dominant_reasons: Vec<String>,
}

/// Rollback receipt for a bundle application or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleRollbackReceipt {
    /// Previous runtime-config digest.
    pub previous_config_digest: String,
    /// Applied bundle digest.
    pub applied_bundle_digest: String,
    /// Rollback command template.
    pub rollback_command_template: String,
    /// Conservative fallback profile.
    pub fallback_profile: HostProfileId,
    /// Host fingerprint for the target host.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Artifact paths required to explain or replay the rollback decision.
    pub artifact_paths: Vec<String>,
    /// Digest over the rollback receipt contents.
    pub receipt_digest_sha256: String,
}

impl SignedProfileBundleRollbackReceipt {
    fn from_manifest(manifest: &SignedProfileBundleManifest) -> Self {
        let artifact_paths = signed_profile_bundle_artifact_paths(manifest);
        let receipt_digest_sha256 = stable_sha256_hex(&[
            (
                "previous_config_digest",
                manifest.previous_config_digest.clone(),
            ),
            (
                "applied_bundle_digest",
                manifest.manifest_digest_sha256.clone(),
            ),
            (
                "rollback_command_template",
                manifest.rollback_command_template.clone(),
            ),
            (
                "fallback_profile",
                manifest.fallback_profile.as_str().to_string(),
            ),
            (
                "host_fingerprint",
                format!(
                    "{}|{}|{}|{}",
                    manifest.host_fingerprint.hostname,
                    manifest.host_fingerprint.arch,
                    manifest.host_fingerprint.cpu_cores,
                    manifest.host_fingerprint.memory_gib
                ),
            ),
            ("artifact_paths", artifact_paths.join("|")),
        ]);
        Self {
            previous_config_digest: manifest.previous_config_digest.clone(),
            applied_bundle_digest: manifest.manifest_digest_sha256.clone(),
            rollback_command_template: manifest.rollback_command_template.clone(),
            fallback_profile: manifest.fallback_profile,
            host_fingerprint: manifest.host_fingerprint.clone(),
            artifact_paths,
            receipt_digest_sha256,
        }
    }
}

/// Full signed-bundle artifact pack returned by the request planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleBundle {
    /// Canonical manifest.
    pub manifest: SignedProfileBundleManifest,
    /// Structural verification result.
    pub verification: SignedProfileBundleVerificationResult,
    /// Optional shadow-run comparison against the conservative baseline.
    pub shadow_run_evaluation: Option<SignedProfileBundleShadowRunEvaluation>,
    /// Rollback receipt for the bundle.
    pub rollback_receipt: SignedProfileBundleRollbackReceipt,
}

const SIGNED_PROFILE_SHADOW_RUN_P99_WEIGHT: u64 = 4;
const SIGNED_PROFILE_SHADOW_RUN_CANCEL_WEIGHT: u64 = 2;
const SIGNED_PROFILE_SHADOW_RUN_QUEUE_WEIGHT: u64 = 1;
const SIGNED_PROFILE_SHADOW_RUN_MEMORY_WEIGHT: u64 = 3;
const SIGNED_PROFILE_SHADOW_RUN_BROWNOUT_WEIGHT: u64 = 3;
const SIGNED_PROFILE_SHADOW_RUN_AGENT_CREDIT_WEIGHT: u64 = 2;
const SIGNED_PROFILE_SHADOW_RUN_PROMOTE_MARGIN_BPS: i64 = 250;

fn build_signed_profile_bundle_child_evidence_hashes(
    evidence: &HostProfileEvidenceSet,
) -> Vec<SignedProfileBundleChildEvidenceHash> {
    let mut hashes = Vec::new();
    for kind in [
        HostProfileEvidenceKind::Brownout,
        HostProfileEvidenceKind::OtlpBrownout,
        HostProfileEvidenceKind::AdmissionSteering,
        HostProfileEvidenceKind::AdaptiveBatchSizing,
        HostProfileEvidenceKind::BlockingPoolAffinity,
        HostProfileEvidenceKind::TraceStorageProfile,
    ] {
        if let Some(artifact) = evidence.for_kind(kind) {
            let digest_sha256 = stable_sha256_hex(&[
                ("controller", kind.as_str().to_string()),
                ("artifact_id", artifact.artifact_id.clone()),
                ("contract_version", artifact.contract_version.clone()),
                ("validation_passed", format_bool(artifact.validation_passed)),
            ]);
            hashes.push(SignedProfileBundleChildEvidenceHash {
                controller: kind.as_str().to_string(),
                artifact_id: artifact.artifact_id.clone(),
                digest_sha256,
            });
        }
    }
    hashes
}

fn build_signed_profile_bundle_shadow_run_evaluation(
    request: &SignedProfileBundleManifestRequest,
    candidate_certificate: &CapacityEnvelopeCertificate,
    manifest: &SignedProfileBundleManifest,
    verification: &SignedProfileBundleVerificationResult,
) -> SignedProfileBundleShadowRunEvaluation {
    let mut baseline_manual_overrides = request.manual_overrides.clone();
    if baseline_manual_overrides.worker_threads.is_none() {
        let baseline_worker_ceiling = request
            .candidate_worker_counts
            .iter()
            .copied()
            .max()
            .unwrap_or(candidate_certificate.final_bundle.worker_threads)
            .min(request.host_resources.cpu_cores)
            .max(1);
        baseline_manual_overrides.worker_threads = Some(baseline_worker_ceiling);
    }
    let baseline_certificate = CapacityEnvelopePlannerRequest {
        objective: request.objective,
        requested_profile: Some(HostProfileId::ConservativeBaseline),
        host_resources: request.host_resources,
        controller_evidence: request.controller_evidence.clone(),
        manual_overrides: baseline_manual_overrides,
        host_fingerprint: request.host_fingerprint.clone(),
        evidence_snapshot: request.evidence_snapshot.clone(),
        candidate_worker_counts: request.candidate_worker_counts.clone(),
        candidate_agent_counts: request.candidate_agent_counts.clone(),
        budget: request.capacity_budget,
        budget_overrides: CapacityEnvelopeBudgetOverrides::default(),
        environment_note: None,
        validation_command: None,
    }
    .plan();
    let candidate_point = best_safe_capacity_point(candidate_certificate)
        .unwrap_or_else(|| synthetic_hold_capacity_point(candidate_certificate));
    let baseline_point = best_safe_capacity_point(&baseline_certificate)
        .unwrap_or_else(|| synthetic_hold_capacity_point(&baseline_certificate));
    let max_agent_count = request
        .candidate_agent_counts
        .iter()
        .copied()
        .max()
        .unwrap_or(request.evidence_snapshot.measured_agent_count.max(1));
    let candidate_loss_basis_points = signed_profile_bundle_shadow_run_loss_basis_points(
        &candidate_point,
        candidate_certificate.effective_budget,
        max_agent_count,
    );
    let baseline_loss_basis_points = signed_profile_bundle_shadow_run_loss_basis_points(
        &baseline_point,
        baseline_certificate.effective_budget,
        max_agent_count,
    );
    let regret_margin_basis_points =
        baseline_loss_basis_points as i64 - candidate_loss_basis_points as i64;
    let dominant_reasons = signed_profile_bundle_shadow_run_dominant_reasons(
        &candidate_point,
        &baseline_point,
        regret_margin_basis_points,
    );
    let mut hold_reasons = Vec::new();
    if !verification.accepted {
        hold_reasons.extend(verification.refusal_reasons.clone());
    }
    if manifest.used_safe_fallback {
        hold_reasons.extend(manifest.planning_refusal_reasons.clone());
    }
    if candidate_point.agent_count < baseline_point.agent_count {
        hold_reasons.push(format!(
            "candidate safe agent ceiling {} was below conservative baseline {}",
            candidate_point.agent_count, baseline_point.agent_count
        ));
    }
    if candidate_point.predicted_p99_ns > baseline_point.predicted_p99_ns {
        hold_reasons.push(format!(
            "candidate predicted p99 {}ns exceeded conservative baseline {}ns",
            candidate_point.predicted_p99_ns, baseline_point.predicted_p99_ns
        ));
    }
    if regret_margin_basis_points < SIGNED_PROFILE_SHADOW_RUN_PROMOTE_MARGIN_BPS {
        hold_reasons.push(format!(
            "candidate regret margin {}bps was below promote threshold {}bps",
            regret_margin_basis_points, SIGNED_PROFILE_SHADOW_RUN_PROMOTE_MARGIN_BPS
        ));
    }
    let decision = if hold_reasons.is_empty() {
        SignedProfileBundleShadowRunDecision::Promote
    } else {
        SignedProfileBundleShadowRunDecision::Hold
    };
    dedup_preserving_order(&mut hold_reasons);
    SignedProfileBundleShadowRunEvaluation {
        decision,
        candidate_profile: manifest.selected_profile,
        baseline_profile: HostProfileId::ConservativeBaseline,
        candidate_worker_count: candidate_point.worker_count,
        candidate_agent_count: candidate_point.agent_count,
        baseline_worker_count: baseline_point.worker_count,
        baseline_agent_count: baseline_point.agent_count,
        candidate_loss_basis_points,
        baseline_loss_basis_points,
        regret_margin_basis_points,
        hold_reasons,
        dominant_reasons,
    }
}

fn best_safe_capacity_point(
    certificate: &CapacityEnvelopeCertificate,
) -> Option<CapacityEnvelopePointEvaluation> {
    certificate
        .evaluations
        .iter()
        .filter(|point| point.status == CapacityEnvelopePointStatus::Safe)
        .max_by_key(|point| (point.agent_count, point.worker_count))
        .cloned()
}

fn synthetic_hold_capacity_point(
    certificate: &CapacityEnvelopeCertificate,
) -> CapacityEnvelopePointEvaluation {
    CapacityEnvelopePointEvaluation {
        worker_count: certificate
            .candidate_worker_counts
            .first()
            .copied()
            .unwrap_or(certificate.host_fingerprint.cpu_cores.max(1)),
        agent_count: certificate
            .candidate_agent_counts
            .first()
            .copied()
            .unwrap_or(certificate.evidence_snapshot.measured_agent_count.max(1)),
        predicted_p50_ns: certificate.evidence_snapshot.wake_to_run_p50_ns,
        predicted_p95_ns: certificate.evidence_snapshot.wake_to_run_p95_ns,
        predicted_p99_ns: certificate.evidence_snapshot.wake_to_run_p99_ns,
        predicted_cancellation_debt_units: certificate.evidence_snapshot.cancellation_debt_units,
        predicted_queue_depth: certificate.evidence_snapshot.measured_queue_depth,
        predicted_memory_gib: certificate.host_fingerprint.memory_gib,
        predicted_memory_pressure_basis_points: certificate
            .effective_budget
            .max_memory_pressure_basis_points,
        predicted_brownout_risk_basis_points: certificate
            .effective_budget
            .max_brownout_risk_basis_points,
        status: CapacityEnvelopePointStatus::Refused,
        refusal_reasons: certificate.refusal_reasons.clone(),
    }
}

fn signed_profile_bundle_shadow_run_loss_basis_points(
    point: &CapacityEnvelopePointEvaluation,
    budget: CapacityEnvelopeBudget,
    max_agent_count: usize,
) -> u64 {
    let p99 = normalize_capacity_metric_basis_points(
        u128::from(point.predicted_p99_ns),
        u128::from(budget.target_p99_ns.max(1)),
    );
    let cancellation = normalize_capacity_metric_basis_points(
        u128::from(point.predicted_cancellation_debt_units),
        u128::from(budget.target_cancel_debt_units.max(1)),
    );
    let queue = normalize_capacity_metric_basis_points(
        point.predicted_queue_depth as u128,
        budget.max_queue_depth.max(1) as u128,
    );
    let memory = normalize_capacity_metric_basis_points(
        u128::from(point.predicted_memory_pressure_basis_points),
        u128::from(budget.max_memory_pressure_basis_points.max(1)),
    );
    let brownout = normalize_capacity_metric_basis_points(
        u128::from(point.predicted_brownout_risk_basis_points),
        u128::from(budget.max_brownout_risk_basis_points.max(1)),
    );
    let agent_credit = normalize_capacity_metric_basis_points(
        point.agent_count as u128,
        max_agent_count.max(1) as u128,
    );
    p99.saturating_mul(SIGNED_PROFILE_SHADOW_RUN_P99_WEIGHT)
        .saturating_add(cancellation.saturating_mul(SIGNED_PROFILE_SHADOW_RUN_CANCEL_WEIGHT))
        .saturating_add(queue.saturating_mul(SIGNED_PROFILE_SHADOW_RUN_QUEUE_WEIGHT))
        .saturating_add(memory.saturating_mul(SIGNED_PROFILE_SHADOW_RUN_MEMORY_WEIGHT))
        .saturating_add(brownout.saturating_mul(SIGNED_PROFILE_SHADOW_RUN_BROWNOUT_WEIGHT))
        .saturating_sub(agent_credit.saturating_mul(SIGNED_PROFILE_SHADOW_RUN_AGENT_CREDIT_WEIGHT))
}

fn normalize_capacity_metric_basis_points(numerator: u128, denominator: u128) -> u64 {
    saturating_mul_div(numerator, 10_000, denominator.max(1)) as u64
}

fn signed_profile_bundle_shadow_run_dominant_reasons(
    candidate: &CapacityEnvelopePointEvaluation,
    baseline: &CapacityEnvelopePointEvaluation,
    regret_margin_basis_points: i64,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if candidate.predicted_p99_ns < baseline.predicted_p99_ns {
        reasons.push(format!(
            "candidate p99 improved by {}ns",
            baseline
                .predicted_p99_ns
                .saturating_sub(candidate.predicted_p99_ns)
        ));
    } else if candidate.predicted_p99_ns > baseline.predicted_p99_ns {
        reasons.push(format!(
            "candidate p99 regressed by {}ns",
            candidate
                .predicted_p99_ns
                .saturating_sub(baseline.predicted_p99_ns)
        ));
    }
    if candidate.agent_count > baseline.agent_count {
        reasons.push(format!(
            "candidate safe agent ceiling increased by {}",
            candidate.agent_count.saturating_sub(baseline.agent_count)
        ));
    } else if candidate.agent_count < baseline.agent_count {
        reasons.push(format!(
            "candidate safe agent ceiling dropped by {}",
            baseline.agent_count.saturating_sub(candidate.agent_count)
        ));
    }
    if candidate.predicted_memory_pressure_basis_points
        > baseline.predicted_memory_pressure_basis_points
    {
        reasons.push(format!(
            "candidate memory pressure increased by {}bps",
            candidate
                .predicted_memory_pressure_basis_points
                .saturating_sub(baseline.predicted_memory_pressure_basis_points)
        ));
    } else if candidate.predicted_memory_pressure_basis_points
        < baseline.predicted_memory_pressure_basis_points
    {
        reasons.push(format!(
            "candidate memory pressure decreased by {}bps",
            baseline
                .predicted_memory_pressure_basis_points
                .saturating_sub(candidate.predicted_memory_pressure_basis_points)
        ));
    }
    reasons.push(format!(
        "counterfactual regret margin {}bps",
        regret_margin_basis_points
    ));
    reasons
}

fn build_signed_profile_bundle_feature_gates(config: &RuntimeConfig) -> Vec<String> {
    let mut gates = Vec::new();
    if config.enable_governor {
        gates.push("governor".to_string());
    }
    if config.enable_read_biased_region_snapshot {
        gates.push("read_biased_region_snapshot".to_string());
    }
    if config.enable_adaptive_cancel_streak {
        gates.push("adaptive_cancel_streak".to_string());
    }
    if !matches!(
        config.blocking.affinity_profile,
        BlockingPoolAffinityProfile::Disabled
    ) {
        gates.push("blocking_pool_affinity".to_string());
    }
    if config.capacity_hints.is_some() {
        gates.push("capacity_hints".to_string());
    }
    if config.trace_storage_profile != TraceStorageProfile::Default {
        gates.push(format!("trace_storage_{}", config.trace_storage_profile));
    }
    if config.browser_ready_handoff_limit > 0 {
        gates.push("browser_ready_handoff".to_string());
    }
    gates
}

fn runtime_config_digest(config: &RuntimeConfig) -> String {
    stable_sha256_hex(&[
        ("worker_threads", config.worker_threads.to_string()),
        (
            "worker_cohort_map",
            format_worker_cohort_map(config.worker_cohort_map.as_ref()),
        ),
        ("global_queue_limit", config.global_queue_limit.to_string()),
        ("steal_batch_size", config.steal_batch_size.to_string()),
        (
            "blocking_affinity_profile",
            format_blocking_affinity_profile(config.blocking.affinity_profile),
        ),
        (
            "capacity_hints",
            format_capacity_hints(config.capacity_hints),
        ),
        (
            "trace_storage_profile",
            config.trace_storage_profile.to_string(),
        ),
        (
            "browser_ready_handoff_limit",
            config.browser_ready_handoff_limit.to_string(),
        ),
        ("enable_governor", format_bool(config.enable_governor)),
        (
            "enable_read_biased_region_snapshot",
            format_bool(config.enable_read_biased_region_snapshot),
        ),
        (
            "enable_adaptive_cancel_streak",
            format_bool(config.enable_adaptive_cancel_streak),
        ),
    ])
}

fn host_profile_config_diff_digest(entries: &[HostProfileConfigDiffEntry]) -> String {
    stable_sha256_hex(&[(
        "config_diff",
        entries
            .iter()
            .map(HostProfileConfigDiffEntry::render)
            .collect::<Vec<_>>()
            .join("|"),
    )])
}

fn signed_profile_bundle_artifact_paths(manifest: &SignedProfileBundleManifest) -> Vec<String> {
    let mut paths = vec![
        "signed_profile_bundle_manifest.json".to_string(),
        "signed_profile_bundle_report.json".to_string(),
        "rollback_receipt.json".to_string(),
        manifest.capacity_certificate_reference.artifact_id.clone(),
    ];
    paths.extend(
        manifest
            .child_evidence_hashes
            .iter()
            .map(|entry| entry.artifact_id.clone()),
    );
    dedup_preserving_order(&mut paths);
    paths
}

fn tamper_signed_profile_bundle_manifest(manifest: &mut SignedProfileBundleManifest, field: &str) {
    match field {
        "config_diff_digest" => {
            manifest.config_diff_digest = tamper_hex_digest(&manifest.config_diff_digest);
        }
        "final_bundle_digest" => {
            manifest.final_bundle_digest = tamper_hex_digest(&manifest.final_bundle_digest);
        }
        "profile_bundle_digest" => {
            manifest.profile_bundle_digest = tamper_hex_digest(&manifest.profile_bundle_digest);
        }
        "manifest_digest_sha256" => {
            manifest.manifest_digest_sha256 = tamper_hex_digest(&manifest.manifest_digest_sha256);
        }
        "capacity_certificate_reference.artifact_id" => {
            manifest
                .capacity_certificate_reference
                .artifact_id
                .push_str(".tampered");
        }
        _ => {
            manifest.bundle_id.push_str("-tampered");
        }
    }
}

fn stable_sha256_hex(fields: &[(&str, String)]) -> String {
    let mut hasher = Sha256::new();
    for (key, value) in fields {
        hasher.update(key.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0xff]);
    }
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn tamper_hex_digest(value: &str) -> String {
    if !is_hex_digest(value) {
        return stable_sha256_hex(&[("tampered", value.to_string())]);
    }
    let mut chars = value.chars().collect::<Vec<_>>();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

fn validate_artifact_json_path(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if !value.ends_with(".json") {
        return Err(format!("{label} must end with .json"));
    }
    if value.contains("..") {
        return Err(format!(
            "{label} must not contain parent-directory traversals"
        ));
    }
    if value
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-')))
    {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

fn validate_slug_like(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

fn validate_token_list(values: &[String], label: &str, allow_empty: bool) -> Result<(), String> {
    if values.is_empty() && !allow_empty {
        return Err(format!("{label} must not be empty"));
    }
    for value in values {
        validate_slug_like(value, label)?;
    }
    if let Some(duplicate) = duplicate_string(values) {
        return Err(format!("{label} contains a duplicate entry {duplicate}"));
    }
    Ok(())
}

fn duplicate_string(values: &[String]) -> Option<String> {
    for (index, value) in values.iter().enumerate() {
        if values.iter().skip(index + 1).any(|other| other == value) {
            return Some(value.clone());
        }
    }
    None
}

fn duplicate_controller_version(
    values: &[SignedProfileBundleControllerVersion],
    label: &str,
) -> Option<String> {
    for (index, value) in values.iter().enumerate() {
        if values.iter().skip(index + 1).any(|other| {
            other.controller == value.controller && other.contract_version == value.contract_version
        }) {
            return Some(format!(
                "{label} contains a duplicate {}@{}",
                value.controller, value.contract_version
            ));
        }
    }
    None
}

fn duplicate_child_evidence_controller(
    values: &[SignedProfileBundleChildEvidenceHash],
) -> Option<String> {
    for (index, value) in values.iter().enumerate() {
        if values
            .iter()
            .skip(index + 1)
            .any(|other| other.controller == value.controller)
        {
            return Some(format!(
                "child_evidence_hashes contains a duplicate controller {}",
                value.controller
            ));
        }
    }
    None
}

fn dedup_preserving_order(values: &mut Vec<String>) {
    let mut deduped = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        if !deduped.iter().any(|existing| existing == &value) {
            deduped.push(value);
        }
    }
    *values = deduped;
}

fn normalize_capacity_sweep(values: &[usize], max_value: usize) -> Vec<usize> {
    let mut normalized = values
        .iter()
        .copied()
        .filter(|value| *value > 0)
        .map(|value| value.min(max_value))
        .collect::<Vec<_>>();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

fn build_capacity_assumptions(
    profile: HostProfileId,
    evidence: &CapacityEnvelopeEvidenceSnapshot,
    budget: CapacityEnvelopeBudget,
) -> Vec<String> {
    vec![
        format!(
            "capacity certificate stays dry-run only; no runtime config is mutated for {}",
            profile
        ),
        format!(
            "queueing envelope uses linear underclaiming around measured {} workers / {} agents",
            evidence.measured_worker_count, evidence.measured_agent_count
        ),
        format!(
            "evidence freshness is capped at {} hours and currently observed at {} hours",
            budget.max_artifact_age_hours, evidence.artifact_age_hours
        ),
        format!(
            "p99 budget={}ns, cancellation budget={}, memory pressure budget={}bps, brownout budget={}bps",
            budget.target_p99_ns,
            budget.target_cancel_debt_units,
            budget.max_memory_pressure_basis_points,
            budget.max_brownout_risk_basis_points
        ),
    ]
}

fn evaluate_capacity_point(
    profile: HostProfileId,
    host_resources: &HostProfileHostResources,
    evidence: &CapacityEnvelopeEvidenceSnapshot,
    budget: CapacityEnvelopeBudget,
    worker_count: usize,
    agent_count: usize,
) -> CapacityEnvelopePointEvaluation {
    let measured_workers = evidence.measured_worker_count.max(1) as u128;
    let measured_agents = evidence.measured_agent_count.max(1) as u128;
    let workers = worker_count.max(1) as u128;
    let agents = agent_count.max(1) as u128;
    let raw_pressure = ((agents * measured_workers * 10_000) + (measured_agents * workers) - 1)
        / (measured_agents * workers);
    let pressure_basis_points = raw_pressure.max(10_000);
    let throughput_headroom_basis_points = profile_throughput_headroom_basis_points(profile);

    let predicted_p50_ns = saturating_mul_div(
        u128::from(evidence.wake_to_run_p50_ns),
        pressure_basis_points,
        throughput_headroom_basis_points,
    ) as u64;
    let predicted_p95_ns = saturating_mul_div(
        u128::from(evidence.wake_to_run_p95_ns),
        pressure_basis_points,
        throughput_headroom_basis_points,
    ) as u64;
    let predicted_p99_ns = saturating_mul_div(
        u128::from(evidence.wake_to_run_p99_ns),
        pressure_basis_points,
        throughput_headroom_basis_points,
    ) as u64;
    let predicted_cancellation_debt_units = saturating_mul_div(
        u128::from(evidence.cancellation_debt_units),
        pressure_basis_points,
        throughput_headroom_basis_points,
    ) as u64;
    let predicted_queue_depth = saturating_mul_div(
        evidence.measured_queue_depth as u128,
        pressure_basis_points,
        10_000,
    ) as usize;

    let observed_memory_gib = ceil_div_u128(
        (host_resources.memory_gib as u128) * u128::from(evidence.memory_pressure_basis_points),
        10_000,
    ) as usize;
    let scaled_observed_memory_gib =
        saturating_mul_div(observed_memory_gib as u128, pressure_basis_points, 10_000) as usize;
    let modeled_memory_gib = profile_fixed_memory_gib(profile, evidence.retention_budget_gib)
        + ceil_div_u128(
            (agent_count as u128) * u128::from(profile_agent_resident_mib(profile)),
            1024,
        ) as usize;
    let predicted_memory_gib = modeled_memory_gib.max(scaled_observed_memory_gib);
    let predicted_memory_pressure_basis_points = ((predicted_memory_gib as u128 * 10_000)
        / (host_resources.memory_gib.max(1) as u128))
        .min(10_000) as u16;

    let extra_pressure = pressure_basis_points.saturating_sub(10_000);
    let predicted_brownout_risk_basis_points = (u32::from(evidence.brownout_risk_basis_points)
        + brownout_stage_penalty_basis_points(evidence.brownout_stage)
        + ((extra_pressure.saturating_sub(1)) / 5) as u32)
        .min(10_000) as u16;

    let mut refusal_reasons = Vec::new();
    if predicted_p99_ns > budget.target_p99_ns {
        refusal_reasons.push(format!(
            "predicted p99 {}ns exceeded budget {}ns",
            predicted_p99_ns, budget.target_p99_ns
        ));
    }
    if predicted_cancellation_debt_units > budget.target_cancel_debt_units {
        refusal_reasons.push(format!(
            "predicted cancellation debt {} exceeded budget {}",
            predicted_cancellation_debt_units, budget.target_cancel_debt_units
        ));
    }
    if predicted_queue_depth > budget.max_queue_depth {
        refusal_reasons.push(format!(
            "predicted queue depth {} exceeded budget {}",
            predicted_queue_depth, budget.max_queue_depth
        ));
    }
    if predicted_memory_pressure_basis_points > budget.max_memory_pressure_basis_points {
        refusal_reasons.push(format!(
            "predicted memory pressure {}bps exceeded budget {}bps",
            predicted_memory_pressure_basis_points, budget.max_memory_pressure_basis_points
        ));
    }
    if predicted_brownout_risk_basis_points > budget.max_brownout_risk_basis_points {
        refusal_reasons.push(format!(
            "predicted brownout risk {}bps exceeded budget {}bps",
            predicted_brownout_risk_basis_points, budget.max_brownout_risk_basis_points
        ));
    }

    CapacityEnvelopePointEvaluation {
        worker_count,
        agent_count,
        predicted_p50_ns,
        predicted_p95_ns,
        predicted_p99_ns,
        predicted_cancellation_debt_units,
        predicted_queue_depth,
        predicted_memory_gib,
        predicted_memory_pressure_basis_points,
        predicted_brownout_risk_basis_points,
        status: if refusal_reasons.is_empty() {
            CapacityEnvelopePointStatus::Safe
        } else {
            CapacityEnvelopePointStatus::Refused
        },
        refusal_reasons,
    }
}

fn summarize_safe_envelope(
    selected_safe_point: Option<CapacityEnvelopePointEvaluation>,
    evaluations: &[CapacityEnvelopePointEvaluation],
) -> Option<CapacityEnvelopeRange> {
    let _ = selected_safe_point?;
    let safe_points = evaluations
        .iter()
        .filter(|point| point.status == CapacityEnvelopePointStatus::Safe)
        .collect::<Vec<_>>();
    Some(CapacityEnvelopeRange {
        worker_min: safe_points
            .iter()
            .map(|point| point.worker_count)
            .min()
            .unwrap_or(0),
        worker_max: safe_points
            .iter()
            .map(|point| point.worker_count)
            .max()
            .unwrap_or(0),
        agent_min: safe_points
            .iter()
            .map(|point| point.agent_count)
            .min()
            .unwrap_or(0),
        agent_max: safe_points
            .iter()
            .map(|point| point.agent_count)
            .max()
            .unwrap_or(0),
        max_queue_depth: safe_points
            .iter()
            .map(|point| point.predicted_queue_depth)
            .max()
            .unwrap_or(0),
        max_memory_gib: safe_points
            .iter()
            .map(|point| point.predicted_memory_gib)
            .max()
            .unwrap_or(0),
    })
}

fn summarize_refused_envelope(
    host_resources: &HostProfileHostResources,
    worker_counts: &[usize],
    agent_counts: &[usize],
    evaluations: &[CapacityEnvelopePointEvaluation],
) -> CapacityEnvelopeRange {
    let refused_points = evaluations
        .iter()
        .filter(|point| point.status == CapacityEnvelopePointStatus::Refused)
        .collect::<Vec<_>>();
    if refused_points.is_empty() {
        return CapacityEnvelopeRange {
            worker_min: worker_counts.first().copied().unwrap_or(0),
            worker_max: worker_counts.last().copied().unwrap_or(0),
            agent_min: agent_counts.first().copied().unwrap_or(0),
            agent_max: agent_counts.last().copied().unwrap_or(0),
            max_queue_depth: host_resources.cpu_cores.saturating_mul(1024),
            max_memory_gib: host_resources.memory_gib,
        };
    }
    CapacityEnvelopeRange {
        worker_min: refused_points
            .iter()
            .map(|point| point.worker_count)
            .min()
            .unwrap_or(0),
        worker_max: refused_points
            .iter()
            .map(|point| point.worker_count)
            .max()
            .unwrap_or(0),
        agent_min: refused_points
            .iter()
            .map(|point| point.agent_count)
            .min()
            .unwrap_or(0),
        agent_max: refused_points
            .iter()
            .map(|point| point.agent_count)
            .max()
            .unwrap_or(0),
        max_queue_depth: refused_points
            .iter()
            .map(|point| point.predicted_queue_depth)
            .max()
            .unwrap_or(0),
        max_memory_gib: refused_points
            .iter()
            .map(|point| point.predicted_memory_gib)
            .max()
            .unwrap_or(0),
    }
}

const fn profile_throughput_headroom_basis_points(profile: HostProfileId) -> u128 {
    match profile {
        HostProfileId::ConservativeBaseline => 9_000,
        HostProfileId::LocalityFirst64C256G => 11_000,
        HostProfileId::TailProtectionFirst64C256G => 9_500,
        HostProfileId::LargeMemoryEvidenceRetention256G => 10_000,
    }
}

const fn profile_agent_resident_mib(profile: HostProfileId) -> u64 {
    match profile {
        HostProfileId::ConservativeBaseline => 192,
        HostProfileId::LocalityFirst64C256G => 320,
        HostProfileId::TailProtectionFirst64C256G => 352,
        HostProfileId::LargeMemoryEvidenceRetention256G => 384,
    }
}

const fn profile_fixed_memory_gib(profile: HostProfileId, retention_budget_gib: usize) -> usize {
    let base = match profile {
        HostProfileId::ConservativeBaseline => 8,
        HostProfileId::LocalityFirst64C256G => 12,
        HostProfileId::TailProtectionFirst64C256G => 10,
        HostProfileId::LargeMemoryEvidenceRetention256G => 16,
    };
    base + retention_budget_gib
}

const fn brownout_stage_penalty_basis_points(stage: CapacityEnvelopeBrownoutStage) -> u32 {
    match stage {
        CapacityEnvelopeBrownoutStage::FullSurfaces => 0,
        CapacityEnvelopeBrownoutStage::OptionalFirst => 100,
        CapacityEnvelopeBrownoutStage::PriorityGate => 180,
        CapacityEnvelopeBrownoutStage::StandaloneFallback => 260,
    }
}

const fn ceil_div_u128(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        numerator.div_ceil(denominator)
    }
}

const fn saturating_mul_div(numerator: u128, multiplier: u128, divisor: u128) -> u128 {
    if divisor == 0 {
        0
    } else {
        numerator.saturating_mul(multiplier) / divisor
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
        crate::assert_with_log!(
            config.arena_temperature_policy == ArenaTemperaturePolicy::Unified,
            "arena_temperature_policy",
            ArenaTemperaturePolicy::Unified,
            config.arena_temperature_policy
        );
        crate::test_complete!("test_default_config_sane");
    }

    #[test]
    fn arena_temperature_policy_text_roundtrip_is_stable() {
        init_test("arena_temperature_policy_text_roundtrip_is_stable");
        crate::assert_with_log!(
            ArenaTemperaturePolicy::Unified.as_str() == "unified",
            "unified as_str",
            "unified",
            ArenaTemperaturePolicy::Unified.as_str()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::TieredColdEvidence.as_str() == "tiered-cold-evidence",
            "tiered-cold-evidence as_str",
            "tiered-cold-evidence",
            ArenaTemperaturePolicy::TieredColdEvidence.as_str()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages.as_str()
                == "tiered-cold-evidence-large-pages",
            "tiered-cold-evidence-large-pages as_str",
            "tiered-cold-evidence-large-pages",
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages.as_str()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("unified").expect("parse unified")
                == ArenaTemperaturePolicy::Unified,
            "parse unified",
            ArenaTemperaturePolicy::Unified,
            ArenaTemperaturePolicy::from_str("unified").expect("parse unified")
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("tiered-cold-evidence")
                .expect("parse tiered-cold-evidence")
                == ArenaTemperaturePolicy::TieredColdEvidence,
            "parse tiered-cold-evidence",
            ArenaTemperaturePolicy::TieredColdEvidence,
            ArenaTemperaturePolicy::from_str("tiered-cold-evidence")
                .expect("parse tiered-cold-evidence")
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("tiered_cold_evidence_large_pages")
                .expect("parse tiered_cold_evidence_large_pages")
                == ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            "parse tiered_cold_evidence_large_pages",
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            ArenaTemperaturePolicy::from_str("tiered_cold_evidence_large_pages")
                .expect("parse tiered_cold_evidence_large_pages")
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("nope").is_err(),
            "invalid parse rejected",
            true,
            ArenaTemperaturePolicy::from_str("nope").is_err()
        );
        crate::test_complete!("arena_temperature_policy_text_roundtrip_is_stable");
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
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
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
            config.arena_temperature_policy == ArenaTemperaturePolicy::Unified,
            "arena_temperature_policy",
            ArenaTemperaturePolicy::Unified,
            config.arena_temperature_policy
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
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
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
    fn arena_temperature_report_keeps_hot_metadata_out_of_cold_tier() {
        init_test("arena_temperature_report_keeps_hot_metadata_out_of_cold_tier");

        let config = RuntimeConfig {
            worker_threads: 64,
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        };
        let report = config.arena_temperature_report(false);

        assert_eq!(
            report.requested_policy,
            ArenaTemperaturePolicy::TieredColdEvidence
        );
        assert_eq!(
            report.effective_policy,
            ArenaTemperaturePolicy::TieredColdEvidence
        );
        assert_eq!(report.fallback_reason, None);
        assert_eq!(
            report.cold_allocation_source,
            ArenaColdAllocationSource::ColdTier
        );
        assert!(!report.large_page_cold_slabs_active);
        assert!(report.hot_task_table_bytes > 0);
        assert!(report.hot_region_table_bytes > 0);
        assert!(report.hot_obligation_table_bytes > 0);
        assert_eq!(
            report.retained_evidence_bytes,
            config.trace_storage_budget().estimated_cold_bytes()
        );
        assert_eq!(report.cold_evidence_bytes, report.retained_evidence_bytes);
        assert_eq!(
            report.estimated_total_bytes(),
            report
                .estimated_hot_bytes()
                .saturating_add(report.retained_evidence_bytes)
        );
    }

    #[test]
    fn arena_temperature_report_falls_back_when_large_pages_are_unavailable() {
        init_test("arena_temperature_report_falls_back_when_large_pages_are_unavailable");

        let config = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        };
        let report = config.arena_temperature_report(false);

        assert_eq!(
            report.requested_policy,
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages
        );
        assert_eq!(
            report.effective_policy,
            ArenaTemperaturePolicy::TieredColdEvidence
        );
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::LargePagesUnsupported)
        );
        assert_eq!(
            report.cold_allocation_source,
            ArenaColdAllocationSource::ColdTier
        );
        assert!(!report.large_page_cold_slabs_active);

        let rendered = report.render_report_fields();
        assert!(
            rendered.iter().any(|(key, value)| *key == "fallback_reason"
                && value == ArenaTemperatureFallbackReason::LargePagesUnsupported.as_str()),
            "rendered report should expose the conservative fallback reason"
        );
    }

    #[test]
    fn arena_temperature_report_restores_unified_mode_when_disabled_again() {
        init_test("arena_temperature_report_restores_unified_mode_when_disabled_again");

        let tiered = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report(false);
        let unified = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report(false);

        assert_eq!(unified.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(unified.cold_evidence_bytes, 0);
        assert_eq!(
            unified.retained_evidence_bytes,
            tiered.retained_evidence_bytes
        );
        assert_eq!(unified.hot_task_table_bytes, tiered.hot_task_table_bytes);
        assert_eq!(
            unified.hot_region_table_bytes,
            tiered.hot_region_table_bytes
        );
        assert_eq!(
            unified.hot_obligation_table_bytes,
            tiered.hot_obligation_table_bytes
        );
    }

    #[test]
    fn resolved_capacity_hints_prefers_explicit_values_over_worker_scaling() {
        init_test("resolved_capacity_hints_prefers_explicit_values_over_worker_scaling");

        let mut config = RuntimeConfig {
            worker_threads: 64,
            capacity_hints: Some(RuntimeCapacityHints::new(900, 200, 600)),
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
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
