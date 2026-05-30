//! Runtime configuration types.
//!
//! These types hold the concrete values that drive runtime behavior.
//!
//! Most callers should use [`RuntimeBuilder`](super::builder::RuntimeBuilder)
//! to construct a runtime rather than creating a [`RuntimeConfig`] directly.
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
//! | `adaptive_ready_batch` | disabled |

use crate::observability::ObservabilityConfig;
use crate::observability::metrics::{MetricsProvider, NoOpMetrics};
use crate::record::{ObligationRecord, RegionLimits, RegionRecord, TaskRecord};
use crate::runtime::TaskTable;
use crate::runtime::deadline_monitor::{DeadlineWarning, MonitorConfig};
use crate::trace::distributed::LogicalClockMode;
use crate::types::CancelAttributionConfig;
use crate::util::Arena;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use nkeys::KeyPair;
use sha2::{Digest, Sha256};
use std::fmt;

// Security imports for spawn authorization
use crate::security::key::AuthKey;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

/// Configuration for the blocking pool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockingPoolAffinityProfile {
    /// Do not apply cohort-aware queue routing.
    #[default]
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

/// Observe-first adaptive ready-lane batch sizing profile.
///
/// The default is disabled and preserves fixed `steal_batch_size` behavior.
/// When enabled, scheduler workers may temporarily choose a larger or smaller
/// ready-lane drain batch from deterministic local signals: ready depth,
/// global-ready combiner contention, and cancel-lane debt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveReadyBatchConfig {
    /// Enables adaptive ready-batch selection when `true`.
    pub enabled: bool,
    /// Smallest batch size allowed while the profile is active.
    pub min_batch_size: usize,
    /// Largest batch size allowed while the profile is active.
    pub max_batch_size: usize,
    /// Minimum ready depth required before the scheduler can scale up.
    pub scale_up_ready_depth: usize,
    /// Minimum observed combiner in-flight depth required before scale-up.
    pub scale_up_in_flight: usize,
    /// Minimum combiner claim-failure delta required before scale-up.
    pub scale_up_claim_failures: usize,
    /// Cancel-debt floor that forces the batch size down to `min_batch_size`.
    pub cancel_debt_floor: usize,
    /// Number of subsequent batch drains that should keep the scaled-up size.
    pub cooldown_steps: usize,
}

impl AdaptiveReadyBatchConfig {
    /// Conservative disabled profile.
    pub const DISABLED: Self = Self {
        enabled: false,
        min_batch_size: 1,
        max_batch_size: 16,
        scale_up_ready_depth: 64,
        scale_up_in_flight: 2,
        scale_up_claim_failures: 1,
        cancel_debt_floor: 16,
        cooldown_steps: 0,
    };

    /// Normalize profile parameters to safe non-zero bounds.
    pub fn normalize(&mut self, fixed_batch_size: usize) {
        let fixed_batch_size = fixed_batch_size.max(1);
        self.min_batch_size = self.min_batch_size.max(1);
        self.max_batch_size = self
            .max_batch_size
            .max(self.min_batch_size)
            .max(fixed_batch_size);
        if self.scale_up_ready_depth == 0 {
            self.scale_up_ready_depth = fixed_batch_size;
        }
        if self.scale_up_in_flight == 0 {
            self.scale_up_in_flight = 1;
        }
        if self.scale_up_claim_failures == 0 {
            self.scale_up_claim_failures = 1;
        }
        if self.cancel_debt_floor == 0 {
            self.cancel_debt_floor = 1;
        }
    }
}

impl Default for AdaptiveReadyBatchConfig {
    fn default() -> Self {
        Self::DISABLED
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ArenaTemperaturePolicy {
    /// Keep hot metadata and retained evidence on the unified allocator path.
    #[default]
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
    /// Hot/cold tiering was requested without a locality proof surface.
    LocalityProfileMissing,
    /// The supplied locality proof was stale and must be rejected.
    StaleLocalityProfile,
    /// The supplied locality proof stayed on the conservative baseline.
    LocalityProfileFallback,
}

impl ArenaTemperatureFallbackReason {
    /// Returns the stable operator-facing name for the fallback.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LargePagesUnsupported => "large_pages_unsupported",
            Self::LocalityProfileMissing => "locality_profile_missing",
            Self::StaleLocalityProfile => "stale_locality_profile",
            Self::LocalityProfileFallback => "locality_profile_fallback",
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
    /// Whether a locality proof surface was supplied.
    pub locality_profile_present: bool,
    /// Whether the supplied locality proof was rejected as stale.
    pub locality_profile_stale: bool,
    /// Whether the supplied locality proof stayed on the conservative baseline.
    pub locality_safe_fallback: bool,
    /// Selected remote-touch ratio from the locality proof surface.
    pub locality_selected_remote_touch_ratio_bps: u16,
    /// Whether the locality proof's own no-win trigger fired.
    pub locality_no_win_trigger: bool,
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
                "locality_profile_present",
                format_bool(self.locality_profile_present),
            ),
            (
                "locality_profile_stale",
                format_bool(self.locality_profile_stale),
            ),
            (
                "locality_safe_fallback",
                format_bool(self.locality_safe_fallback),
            ),
            (
                "locality_selected_remote_touch_ratio_bps",
                self.locality_selected_remote_touch_ratio_bps.to_string(),
            ),
            (
                "locality_no_win_trigger",
                format_bool(self.locality_no_win_trigger),
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

/// Runtime domain covered by the memory-tier slab/pool certification matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryTierRuntimeDomain {
    /// Hot task-record allocation and recycling surfaces.
    TaskRecords,
    /// Region-record capacity and locality planning surfaces.
    RegionRecords,
    /// Obligation-record capacity and locality planning surfaces.
    ObligationRecords,
    /// Runtime trace and retained evidence surfaces.
    TraceEvidence,
    /// Release proof-pack and artifact-retention surfaces.
    ProofArtifacts,
}

impl MemoryTierRuntimeDomain {
    /// Stable JSON identifier for this runtime domain.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskRecords => "task_records",
            Self::RegionRecords => "region_records",
            Self::ObligationRecords => "obligation_records",
            Self::TraceEvidence => "trace_evidence",
            Self::ProofArtifacts => "proof_artifacts",
        }
    }
}

/// Memory tier covered by the slab/pool certification matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryTierKind {
    /// Allocation-sensitive runtime records kept on the hot path.
    HotRuntimeRecords,
    /// Capacity and locality plans that select bounded allocation envelopes.
    WarmCapacityAndLocalityPlans,
    /// Retained evidence and proof artifacts kept off the hot path when proven safe.
    ColdEvidenceArtifacts,
    /// Conservative heap-backed fallback used when optimized tiering is not proven.
    SafeHeapFallback,
}

impl MemoryTierKind {
    /// Stable JSON identifier for this memory tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HotRuntimeRecords => "hot_runtime_records",
            Self::WarmCapacityAndLocalityPlans => "warm_capacity_and_locality_plans",
            Self::ColdEvidenceArtifacts => "cold_evidence_artifacts",
            Self::SafeHeapFallback => "safe_heap_fallback",
        }
    }
}

/// Fail-closed certification state for memory-tier rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryTierCertificationStatus {
    /// Live implementation and proof coverage are wired.
    ImplementedVerified,
    /// Contract and proof lanes guard the surface, but full runtime rollout is pending.
    ContractGuarded,
    /// Conservative fallback is the only supported runtime mode.
    FallbackOnly,
    /// Design-only declaration that must not render as passing.
    TemplateOnly,
}

impl MemoryTierCertificationStatus {
    /// Stable JSON identifier for this certification state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImplementedVerified => "implemented_verified",
            Self::ContractGuarded => "contract_guarded",
            Self::FallbackOnly => "fallback_only",
            Self::TemplateOnly => "template_only",
        }
    }
}

/// Source-owned row declaration for the memory-tier slab/pool matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryTierSlabPoolCertification {
    /// Stable row identifier.
    pub row_id: &'static str,
    /// Runtime domain covered by this row.
    pub runtime_domain: MemoryTierRuntimeDomain,
    /// Memory tier covered by this row.
    pub memory_tier: MemoryTierKind,
    /// Operator-facing verdict rendered by the matrix.
    pub operator_verdict: MemoryTierCertificationStatus,
    /// Fail-closed row status stored in the JSON contract.
    pub status: MemoryTierCertificationStatus,
    /// Source-owned files that back this row.
    pub source_files: &'static [&'static str],
    /// Existing lower-level contracts that this row composes.
    pub existing_contracts: &'static [&'static str],
    /// Proof commands required for this row.
    pub proof_commands: &'static [&'static str],
}

/// Canonical source declarations for memory-tier slab/pool certification.
pub const MEMORY_TIER_SLAB_POOL_CERTIFICATIONS: &[MemoryTierSlabPoolCertification] = &[
    MemoryTierSlabPoolCertification {
        row_id: "hot_task_record_pool",
        runtime_domain: MemoryTierRuntimeDomain::TaskRecords,
        memory_tier: MemoryTierKind::HotRuntimeRecords,
        operator_verdict: MemoryTierCertificationStatus::ImplementedVerified,
        status: MemoryTierCertificationStatus::ImplementedVerified,
        source_files: &[
            "src/runtime/task_table.rs",
            "src/record/task.rs",
            "src/util/pool.rs",
            "artifacts/task_record_pool_smoke_contract_v1.json",
            "tests/task_record_pool_contract.rs",
        ],
        existing_contracts: &["task-record-pool-smoke-contract-v1"],
        proof_commands: &[
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_task_record_pool_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test task_record_pool_contract --features test-internals -- --nocapture",
        ],
    },
    MemoryTierSlabPoolCertification {
        row_id: "warm_runtime_capacity_hints",
        runtime_domain: MemoryTierRuntimeDomain::RegionRecords,
        memory_tier: MemoryTierKind::WarmCapacityAndLocalityPlans,
        operator_verdict: MemoryTierCertificationStatus::ImplementedVerified,
        status: MemoryTierCertificationStatus::ImplementedVerified,
        source_files: &[
            "src/runtime/config.rs",
            "src/runtime/state.rs",
            "artifacts/runtime_capacity_hints_smoke_contract_v1.json",
            "tests/runtime_capacity_hints_contract.rs",
        ],
        existing_contracts: &["runtime-capacity-hints-smoke-contract-v1"],
        proof_commands: &[
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_runtime_capacity_hints_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test runtime_capacity_hints_contract --features test-internals -- --nocapture",
        ],
    },
    MemoryTierSlabPoolCertification {
        row_id: "warm_numa_arena_locality",
        runtime_domain: MemoryTierRuntimeDomain::ObligationRecords,
        memory_tier: MemoryTierKind::WarmCapacityAndLocalityPlans,
        operator_verdict: MemoryTierCertificationStatus::ImplementedVerified,
        status: MemoryTierCertificationStatus::ImplementedVerified,
        source_files: &[
            "src/runtime/config.rs",
            "artifacts/numa_arena_locality_smoke_contract_v1.json",
            "tests/numa_arena_locality_contract.rs",
        ],
        existing_contracts: &["numa-arena-locality-smoke-contract-v1"],
        proof_commands: &[
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_numa_arena_locality_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test numa_arena_locality_contract --features test-internals -- --nocapture",
        ],
    },
    MemoryTierSlabPoolCertification {
        row_id: "cold_trace_evidence_tiers",
        runtime_domain: MemoryTierRuntimeDomain::TraceEvidence,
        memory_tier: MemoryTierKind::ColdEvidenceArtifacts,
        operator_verdict: MemoryTierCertificationStatus::ImplementedVerified,
        status: MemoryTierCertificationStatus::ImplementedVerified,
        source_files: &[
            "src/runtime/config.rs",
            "src/trace/recorder.rs",
            "src/trace/distributed/collector.rs",
            "artifacts/hot_cold_arena_tiers_smoke_contract_v1.json",
            "tests/hot_cold_arena_tiers.rs",
        ],
        existing_contracts: &["hot-cold-arena-tiers-smoke-contract-v1"],
        proof_commands: &[
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_hot_cold_arena_tiers_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test hot_cold_arena_tiers --features test-internals -- --nocapture",
        ],
    },
    MemoryTierSlabPoolCertification {
        row_id: "cold_proof_artifact_retention",
        runtime_domain: MemoryTierRuntimeDomain::ProofArtifacts,
        memory_tier: MemoryTierKind::ColdEvidenceArtifacts,
        operator_verdict: MemoryTierCertificationStatus::ImplementedVerified,
        status: MemoryTierCertificationStatus::ImplementedVerified,
        source_files: &[
            "scripts/proof_runner.py",
            "artifacts/release_proof_pack_contract_v1.json",
            "tests/proof_runner_contract.rs",
        ],
        existing_contracts: &["release-proof-pack-v1"],
        proof_commands: &[
            "python3 -m py_compile scripts/proof_runner.py",
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_runner_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test proof_runner_contract -- --nocapture",
        ],
    },
    MemoryTierSlabPoolCertification {
        row_id: "scheduler_p999_latency_receipt",
        runtime_domain: MemoryTierRuntimeDomain::TaskRecords,
        memory_tier: MemoryTierKind::WarmCapacityAndLocalityPlans,
        operator_verdict: MemoryTierCertificationStatus::ImplementedVerified,
        status: MemoryTierCertificationStatus::ImplementedVerified,
        source_files: &[
            "artifacts/operator_proof_backlog_signoff_contract_v1.json",
            "artifacts/runtime_latency_budget_certificate_v1.json",
            "tests/artifacts/perf/asupersync-xeh8m0.3/three_lane_decision_baseline_v1.json",
            "tests/artifacts/perf/asupersync-h6pjqb/scheduler_p999_latency_receipt_v1.json",
            "tests/memory_tier_slab_pool_contract.rs",
        ],
        existing_contracts: &[
            "operator-proof-backlog-signoff-contract-v1",
            "runtime-latency-budget-certificate-v1",
            "asupersync-h6pjqb-scheduler-p999-latency-receipt-v1",
        ],
        proof_commands: &[
            "python3 -m json.tool artifacts/operator_proof_backlog_signoff_contract_v1.json >/dev/null",
            "python3 -m json.tool artifacts/runtime_latency_budget_certificate_v1.json >/dev/null",
            "python3 -m json.tool tests/artifacts/perf/asupersync-h6pjqb/scheduler_p999_latency_receipt_v1.json >/dev/null",
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_tier_slab_pool_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test memory_tier_slab_pool_contract --features test-internals -- --nocapture",
        ],
    },
    MemoryTierSlabPoolCertification {
        row_id: "safe_heap_fallback",
        runtime_domain: MemoryTierRuntimeDomain::TaskRecords,
        memory_tier: MemoryTierKind::SafeHeapFallback,
        operator_verdict: MemoryTierCertificationStatus::FallbackOnly,
        status: MemoryTierCertificationStatus::FallbackOnly,
        source_files: &[
            "src/util/arena.rs",
            "src/util/pool.rs",
            "src/runtime/task_table.rs",
            "tests/task_record_pool_contract.rs",
            "tests/hot_cold_arena_tiers.rs",
        ],
        existing_contracts: &[
            "task-record-pool-smoke-contract-v1",
            "hot-cold-arena-tiers-smoke-contract-v1",
        ],
        proof_commands: &[
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_tier_slab_pool_contract CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo test -p asupersync --test memory_tier_slab_pool_contract --features test-internals -- --nocapture",
        ],
    },
];

/// Find a memory-tier slab/pool declaration by row id.
#[must_use]
pub fn memory_tier_slab_pool_certification(
    row_id: &str,
) -> Option<&'static MemoryTierSlabPoolCertification> {
    MEMORY_TIER_SLAB_POOL_CERTIFICATIONS
        .iter()
        .find(|declaration| declaration.row_id == row_id)
}

fn cohort_local_touch_count(touches_by_cohort: &[u64]) -> u64 {
    let mut best = 0;
    for &touches in touches_by_cohort {
        if touches > best {
            best = touches;
        }
    }
    best
}

fn baseline_local_touch_count(total_touches: u64, cohort_count: usize) -> u64 {
    if cohort_count == 0 {
        0
    } else {
        total_touches / cohort_count as u64
    }
}

fn preferred_locality_cohort(touches_by_cohort: &[u64]) -> usize {
    let mut best_index = 0usize;
    let mut best_touches = 0u64;
    for (index, &touches) in touches_by_cohort.iter().enumerate() {
        if touches > best_touches {
            best_index = index;
            best_touches = touches;
        }
    }
    best_index
}

fn build_candidate_locality_placements(
    capacity_hints: RuntimeCapacityHints,
    task_record_pool_capacity: usize,
    access_model: &ArenaLocalityAccessModel,
) -> Vec<ArenaLocalityPlacement> {
    [
        (
            ArenaLocalityPlacementKind::TaskArena,
            capacity_hints.task_capacity,
        ),
        (
            ArenaLocalityPlacementKind::RegionArena,
            capacity_hints.region_capacity,
        ),
        (
            ArenaLocalityPlacementKind::ObligationArena,
            capacity_hints.obligation_capacity,
        ),
        (
            ArenaLocalityPlacementKind::TaskRecordPool,
            task_record_pool_capacity,
        ),
    ]
    .into_iter()
    .map(|(kind, slot_budget)| {
        let touches_by_cohort = access_model.touches_for_kind(kind);
        let total_touches = touches_by_cohort.iter().copied().sum::<u64>();
        let local_touch_count = cohort_local_touch_count(touches_by_cohort);
        ArenaLocalityPlacement {
            kind,
            preferred_cohort: preferred_locality_cohort(touches_by_cohort),
            slot_budget,
            local_touch_count,
            remote_touch_count: total_touches.saturating_sub(local_touch_count),
        }
    })
    .collect()
}

fn build_arena_locality_report(
    worker_threads: usize,
    worker_cohort_map: Option<&WorkerCohortMapping>,
    capacity_hints: RuntimeCapacityHints,
    requested_policy: ArenaLocalityPolicy,
    topology_confidence_percent: Option<u8>,
    access_model: &ArenaLocalityAccessModel,
) -> ArenaLocalityReport {
    let requested_policy = {
        let mut policy = requested_policy;
        policy.normalize();
        policy
    };
    let cohort_count = worker_cohort_map.map_or(0, WorkerCohortMapping::cohort_count);
    let accounting_epoch = requested_policy.accounting_epoch();
    let counter_epoch = if accounting_epoch == 0 {
        1
    } else {
        accounting_epoch
    };
    let mut baseline = ArenaRemoteTouchCounters::new(counter_epoch);
    let mut candidate = ArenaRemoteTouchCounters::new(counter_epoch);
    let task_record_pool_capacity =
        TaskTable::recommended_pool_limit_for_capacity(capacity_hints.task_capacity);
    let hot_task_table_bytes =
        Arena::<TaskRecord>::estimated_bytes_for_capacity(capacity_hints.task_capacity);
    let hot_region_table_bytes =
        Arena::<RegionRecord>::estimated_bytes_for_capacity(capacity_hints.region_capacity);
    let hot_obligation_table_bytes =
        Arena::<ObligationRecord>::estimated_bytes_for_capacity(capacity_hints.obligation_capacity);
    let task_record_pool_bytes =
        task_record_pool_capacity.saturating_mul(core::mem::size_of::<TaskRecord>());

    let inputs_valid = worker_cohort_map
        .is_some_and(|mapping| mapping.validate_for_workers(worker_threads).is_ok())
        && access_model.validate_for_cohort_count(cohort_count).is_ok();

    let placements = if inputs_valid {
        build_candidate_locality_placements(capacity_hints, task_record_pool_capacity, access_model)
    } else {
        Vec::new()
    };

    for kind in [
        ArenaLocalityPlacementKind::TaskArena,
        ArenaLocalityPlacementKind::RegionArena,
        ArenaLocalityPlacementKind::ObligationArena,
        ArenaLocalityPlacementKind::TaskRecordPool,
    ] {
        let touches_by_cohort = access_model.touches_for_kind(kind);
        let total_touches = touches_by_cohort.iter().copied().sum::<u64>();
        let baseline_local = baseline_local_touch_count(total_touches, cohort_count);
        baseline.record_sample(baseline_local, total_touches.saturating_sub(baseline_local));
    }

    for placement in &placements {
        candidate.record_sample(placement.local_touch_count, placement.remote_touch_count);
    }

    let baseline_snapshot = baseline.snapshot();
    let candidate_snapshot = candidate.snapshot();

    let mut fallback_reason = None;
    let mut effective_policy = requested_policy;
    let no_win_trigger = matches!(requested_policy, ArenaLocalityPolicy::CohortPinned { .. })
        && inputs_valid
        && candidate_snapshot.remote_touch_count >= baseline_snapshot.remote_touch_count;

    match requested_policy {
        ArenaLocalityPolicy::Disabled => {
            effective_policy = ArenaLocalityPolicy::Disabled;
        }
        ArenaLocalityPolicy::CohortPinned { .. } => {
            if worker_cohort_map.is_none() {
                fallback_reason = Some(ArenaLocalityFallbackReason::MissingWorkerCohortMap);
                effective_policy = ArenaLocalityPolicy::Disabled;
            } else if !inputs_valid {
                fallback_reason = Some(ArenaLocalityFallbackReason::UnsupportedTopologyEvidence);
                effective_policy = ArenaLocalityPolicy::Disabled;
            } else if topology_confidence_percent.unwrap_or(0)
                < requested_policy.min_topology_confidence_percent()
            {
                fallback_reason =
                    Some(ArenaLocalityFallbackReason::TopologyConfidenceBelowThreshold);
                effective_policy = ArenaLocalityPolicy::Disabled;
            } else if no_win_trigger {
                fallback_reason = Some(ArenaLocalityFallbackReason::NoRemoteTouchWin);
                effective_policy = ArenaLocalityPolicy::Disabled;
            } else if candidate_snapshot.remote_touch_ratio_bps()
                > requested_policy.remote_touch_budget_bps()
            {
                fallback_reason = Some(ArenaLocalityFallbackReason::RemoteTouchBudgetExceeded);
                effective_policy = ArenaLocalityPolicy::Disabled;
            }
        }
    }

    let selected = if matches!(effective_policy, ArenaLocalityPolicy::CohortPinned { .. }) {
        candidate_snapshot
    } else {
        baseline_snapshot
    };

    ArenaLocalityReport {
        requested_policy,
        effective_policy,
        fallback_reason,
        worker_threads,
        cohort_count,
        topology_confidence_percent,
        accounting_epoch,
        remote_touch_budget_bps: requested_policy.remote_touch_budget_bps(),
        task_capacity: capacity_hints.task_capacity,
        region_capacity: capacity_hints.region_capacity,
        obligation_capacity: capacity_hints.obligation_capacity,
        task_record_pool_capacity,
        hot_task_table_bytes,
        hot_region_table_bytes,
        hot_obligation_table_bytes,
        task_record_pool_bytes,
        placements,
        baseline: baseline_snapshot,
        candidate: candidate_snapshot,
        selected,
        no_win_trigger,
        ownership_preserved: true,
    }
}

fn build_arena_temperature_report(
    capacity_hints: RuntimeCapacityHints,
    trace_storage_budget: TraceStorageBudget,
    requested_policy: ArenaTemperaturePolicy,
    large_page_cold_slabs_supported: bool,
    locality_report: Option<&ArenaLocalityReport>,
    locality_profile_stale: bool,
) -> ArenaTemperatureReport {
    let hot_task_table_bytes =
        Arena::<TaskRecord>::estimated_bytes_for_capacity(capacity_hints.task_capacity);
    let hot_region_table_bytes =
        Arena::<RegionRecord>::estimated_bytes_for_capacity(capacity_hints.region_capacity);
    let hot_obligation_table_bytes =
        Arena::<ObligationRecord>::estimated_bytes_for_capacity(capacity_hints.obligation_capacity);
    let retained_evidence_bytes = trace_storage_budget.estimated_cold_bytes();
    let locality_profile_present = locality_report.is_some();
    let locality_safe_fallback =
        locality_report.is_some_and(ArenaLocalityReport::used_safe_fallback);
    let locality_selected_remote_touch_ratio_bps =
        locality_report.map_or(0, |report| report.selected.remote_touch_ratio_bps());
    let locality_no_win_trigger = locality_report.is_some_and(|report| report.no_win_trigger);

    let locality_gate_fallback = if matches!(requested_policy, ArenaTemperaturePolicy::Unified) {
        None
    } else if locality_profile_stale {
        Some(ArenaTemperatureFallbackReason::StaleLocalityProfile)
    } else if !locality_profile_present {
        Some(ArenaTemperatureFallbackReason::LocalityProfileMissing)
    } else if locality_safe_fallback || locality_no_win_trigger {
        Some(ArenaTemperatureFallbackReason::LocalityProfileFallback)
    } else {
        None
    };

    let (effective_policy, fallback_reason, cold_allocation_source, large_page_cold_slabs_active) =
        if let Some(reason) = locality_gate_fallback {
            (
                ArenaTemperaturePolicy::Unified,
                Some(reason),
                ArenaColdAllocationSource::UnifiedAllocator,
                false,
            )
        } else {
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
        locality_profile_present,
        locality_profile_stale,
        locality_safe_fallback,
        locality_selected_remote_touch_ratio_bps,
        locality_no_win_trigger,
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

/// Worker placement policy for topology-aware scheduler stealing.
///
/// The policy only changes deterministic victim ordering. It never creates
/// background tuning or host-probed ambient topology; callers must still supply
/// an explicit [`WorkerCohortMapping`] when they want cohort-aware behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SchedulerPlacementMode {
    /// Prefer same-cohort workers before crossing cohort boundaries.
    #[default]
    LocalityFirst,
    /// Prefer same-cohort workers, ordering peers by worker-slot proximity.
    LatencyFirst,
    /// Treat all peer workers as one randomized steal set for load balancing.
    ThroughputFirst,
}

impl SchedulerPlacementMode {
    /// Stable operator-facing mode name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalityFirst => "locality_first",
            Self::LatencyFirst => "latency_first",
            Self::ThroughputFirst => "throughput_first",
        }
    }
}

/// Policy surface for deterministic arena-locality planning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ArenaLocalityPolicy {
    /// Keep all runtime metadata on the conservative non-locality path.
    #[default]
    Disabled,
    /// Prefer cohort-local placement for hot metadata when topology evidence is good enough.
    CohortPinned {
        /// Minimum topology confidence required before locality may activate.
        min_topology_confidence_percent: u8,
        /// Maximum selected remote-touch ratio tolerated before falling back.
        remote_touch_budget_bps: u16,
        /// Accounting epoch identifier used to reset operator-visible counters.
        accounting_epoch: u64,
    },
}

impl ArenaLocalityPolicy {
    /// Returns the stable operator-facing policy name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::CohortPinned { .. } => "cohort_pinned",
        }
    }

    /// Normalize policy parameters to safe non-zero bounds.
    pub fn normalize(&mut self) {
        if let Self::CohortPinned {
            min_topology_confidence_percent,
            remote_touch_budget_bps,
            accounting_epoch,
        } = self
        {
            if *min_topology_confidence_percent == 0 {
                *min_topology_confidence_percent = 1;
            }
            if *remote_touch_budget_bps > 10_000 {
                *remote_touch_budget_bps = 10_000;
            }
            if *accounting_epoch == 0 {
                *accounting_epoch = 1;
            }
        }
    }

    #[must_use]
    const fn min_topology_confidence_percent(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::CohortPinned {
                min_topology_confidence_percent,
                ..
            } => {
                if min_topology_confidence_percent == 0 {
                    1
                } else {
                    min_topology_confidence_percent
                }
            }
        }
    }

    #[must_use]
    const fn remote_touch_budget_bps(self) -> u16 {
        match self {
            Self::Disabled => 10_000,
            Self::CohortPinned {
                remote_touch_budget_bps,
                ..
            } => {
                if remote_touch_budget_bps > 10_000 {
                    10_000
                } else {
                    remote_touch_budget_bps
                }
            }
        }
    }

    #[must_use]
    const fn accounting_epoch(self) -> u64 {
        match self {
            Self::Disabled => 0,
            Self::CohortPinned {
                accounting_epoch, ..
            } => {
                if accounting_epoch == 0 {
                    1
                } else {
                    accounting_epoch
                }
            }
        }
    }
}

impl fmt::Display for ArenaLocalityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Conservative fallback reasons for arena-locality planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaLocalityFallbackReason {
    /// The runtime does not have a validated worker/cohort mapping.
    MissingWorkerCohortMap,
    /// The supplied topology evidence cannot be trusted or is malformed.
    UnsupportedTopologyEvidence,
    /// The topology probe confidence is below the required policy threshold.
    TopologyConfidenceBelowThreshold,
    /// The candidate locality placement failed to beat the conservative baseline.
    NoRemoteTouchWin,
    /// The candidate locality placement exceeded the allowed remote-touch budget.
    RemoteTouchBudgetExceeded,
}

impl ArenaLocalityFallbackReason {
    /// Returns the stable operator-facing fallback identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingWorkerCohortMap => "missing_worker_cohort_map",
            Self::UnsupportedTopologyEvidence => "unsupported_topology_evidence",
            Self::TopologyConfidenceBelowThreshold => "topology_confidence_below_threshold",
            Self::NoRemoteTouchWin => "no_remote_touch_win",
            Self::RemoteTouchBudgetExceeded => "remote_touch_budget_exceeded",
        }
    }
}

/// Logical hot-metadata surfaces that can receive a preferred locality cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArenaLocalityPlacementKind {
    /// Task arena backing storage.
    TaskArena,
    /// Region arena backing storage.
    RegionArena,
    /// Obligation arena backing storage.
    ObligationArena,
    /// Recycled `TaskRecord` pool backing storage.
    TaskRecordPool,
}

impl ArenaLocalityPlacementKind {
    /// Returns the stable operator-facing placement kind name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskArena => "task_arena",
            Self::RegionArena => "region_arena",
            Self::ObligationArena => "obligation_arena",
            Self::TaskRecordPool => "task_record_pool",
        }
    }
}

/// Deterministic placement decision for one hot-metadata surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaLocalityPlacement {
    /// Metadata surface the placement applies to.
    pub kind: ArenaLocalityPlacementKind,
    /// Preferred cohort for the surface.
    pub preferred_cohort: usize,
    /// Slot budget attached to the surface.
    pub slot_budget: usize,
    /// Cohort-local touches preserved by the preferred placement.
    pub local_touch_count: u64,
    /// Cross-cohort touches that remain after the preferred placement.
    pub remote_touch_count: u64,
}

/// Deterministic access evidence for arena-locality planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaLocalityAccessModel {
    /// Task arena touches attributed to each cohort.
    pub task_arena_touches_by_cohort: Vec<u64>,
    /// Region arena touches attributed to each cohort.
    pub region_arena_touches_by_cohort: Vec<u64>,
    /// Obligation arena touches attributed to each cohort.
    pub obligation_arena_touches_by_cohort: Vec<u64>,
    /// Task-record recycler touches attributed to each cohort.
    pub task_record_pool_touches_by_cohort: Vec<u64>,
}

impl ArenaLocalityAccessModel {
    /// Returns the touch counts for the selected metadata surface.
    #[must_use]
    fn touches_for_kind(&self, kind: ArenaLocalityPlacementKind) -> &[u64] {
        match kind {
            ArenaLocalityPlacementKind::TaskArena => &self.task_arena_touches_by_cohort,
            ArenaLocalityPlacementKind::RegionArena => &self.region_arena_touches_by_cohort,
            ArenaLocalityPlacementKind::ObligationArena => &self.obligation_arena_touches_by_cohort,
            ArenaLocalityPlacementKind::TaskRecordPool => &self.task_record_pool_touches_by_cohort,
        }
    }

    /// Verifies that the access evidence exactly covers the requested cohorts.
    pub fn validate_for_cohort_count(&self, cohort_count: usize) -> Result<(), &'static str> {
        if cohort_count == 0 {
            return Err("cohort count must be non-zero");
        }
        for touches in [
            &self.task_arena_touches_by_cohort,
            &self.region_arena_touches_by_cohort,
            &self.obligation_arena_touches_by_cohort,
            &self.task_record_pool_touches_by_cohort,
        ] {
            if touches.len() != cohort_count {
                return Err("arena locality access vectors must match cohort count");
            }
        }
        Ok(())
    }
}

/// Snapshot of accumulated local vs remote touch accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaRemoteTouchCounterSnapshot {
    /// Epoch the snapshot belongs to.
    pub accounting_epoch: u64,
    /// Number of times the counters were reset for a new epoch/window.
    pub reset_count: u64,
    /// Touches that stayed on the selected local cohort.
    pub local_touch_count: u64,
    /// Touches that still crossed cohorts.
    pub remote_touch_count: u64,
}

impl ArenaRemoteTouchCounterSnapshot {
    /// Total touches observed by the counter.
    #[must_use]
    pub const fn total_touch_count(self) -> u64 {
        self.local_touch_count
            .saturating_add(self.remote_touch_count)
    }

    /// Remote-touch ratio in basis points.
    #[must_use]
    pub const fn remote_touch_ratio_bps(self) -> u16 {
        let total = self.total_touch_count();
        if total == 0 {
            0
        } else {
            let ratio = self.remote_touch_count.saturating_mul(10_000) / total;
            if ratio > u16::MAX as u64 {
                u16::MAX
            } else {
                ratio as u16
            }
        }
    }
}

/// Mutable accumulator for local vs remote touch accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaRemoteTouchCounters {
    accounting_epoch: u64,
    reset_count: u64,
    local_touch_count: u64,
    remote_touch_count: u64,
}

impl ArenaRemoteTouchCounters {
    /// Creates a new counter set for the selected accounting epoch.
    #[must_use]
    pub const fn new(accounting_epoch: u64) -> Self {
        Self {
            accounting_epoch: if accounting_epoch == 0 {
                1
            } else {
                accounting_epoch
            },
            reset_count: 0,
            local_touch_count: 0,
            remote_touch_count: 0,
        }
    }

    /// Records one local/remote sample with saturating arithmetic.
    pub fn record_sample(&mut self, local_touch_count: u64, remote_touch_count: u64) {
        self.local_touch_count = self.local_touch_count.saturating_add(local_touch_count);
        self.remote_touch_count = self.remote_touch_count.saturating_add(remote_touch_count);
    }

    /// Resets the counters for the next accounting epoch/window.
    pub fn reset_for_next_epoch(&mut self, next_epoch: u64) {
        let next_epoch = if next_epoch == 0 { 1 } else { next_epoch };
        if next_epoch != self.accounting_epoch {
            self.accounting_epoch = next_epoch;
            self.reset_count = self.reset_count.saturating_add(1);
            self.local_touch_count = 0;
            self.remote_touch_count = 0;
        }
    }

    /// Captures the current immutable counter snapshot.
    #[must_use]
    pub const fn snapshot(self) -> ArenaRemoteTouchCounterSnapshot {
        ArenaRemoteTouchCounterSnapshot {
            accounting_epoch: self.accounting_epoch,
            reset_count: self.reset_count,
            local_touch_count: self.local_touch_count,
            remote_touch_count: self.remote_touch_count,
        }
    }
}

/// Operator-facing accounting report for deterministic arena-locality planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaLocalityReport {
    /// Requested locality policy.
    pub requested_policy: ArenaLocalityPolicy,
    /// Effective locality policy after conservative fallback handling.
    pub effective_policy: ArenaLocalityPolicy,
    /// Optional conservative fallback reason when locality was not selected.
    pub fallback_reason: Option<ArenaLocalityFallbackReason>,
    /// Number of configured worker threads.
    pub worker_threads: usize,
    /// Number of cohorts implied by the worker map.
    pub cohort_count: usize,
    /// Optional topology confidence used during planning.
    pub topology_confidence_percent: Option<u8>,
    /// Accounting epoch attached to the planning decision.
    pub accounting_epoch: u64,
    /// Maximum allowed selected remote-touch ratio in basis points.
    pub remote_touch_budget_bps: u16,
    /// Task arena capacity used for the plan.
    pub task_capacity: usize,
    /// Region arena capacity used for the plan.
    pub region_capacity: usize,
    /// Obligation arena capacity used for the plan.
    pub obligation_capacity: usize,
    /// Derived `TaskRecord` recycler capacity.
    pub task_record_pool_capacity: usize,
    /// Estimated bytes reserved for the task arena.
    pub hot_task_table_bytes: usize,
    /// Estimated bytes reserved for the region arena.
    pub hot_region_table_bytes: usize,
    /// Estimated bytes reserved for the obligation arena.
    pub hot_obligation_table_bytes: usize,
    /// Estimated bytes reserved for the task-record recycler.
    pub task_record_pool_bytes: usize,
    /// Candidate preferred placements for each hot-metadata surface.
    pub placements: Vec<ArenaLocalityPlacement>,
    /// Conservative baseline accounting snapshot.
    pub baseline: ArenaRemoteTouchCounterSnapshot,
    /// Candidate locality-aware accounting snapshot.
    pub candidate: ArenaRemoteTouchCounterSnapshot,
    /// Selected accounting snapshot after fallback handling.
    pub selected: ArenaRemoteTouchCounterSnapshot,
    /// Whether the candidate failed to beat the conservative baseline.
    pub no_win_trigger: bool,
    /// Arena-locality planning must never change logical ownership invariants.
    pub ownership_preserved: bool,
}

impl ArenaLocalityReport {
    /// Estimated bytes intentionally kept on the hot path.
    #[must_use]
    pub const fn estimated_hot_bytes(&self) -> usize {
        self.hot_task_table_bytes
            .saturating_add(self.hot_region_table_bytes)
            .saturating_add(self.hot_obligation_table_bytes)
            .saturating_add(self.task_record_pool_bytes)
    }

    /// Whether the conservative fallback profile remained selected.
    #[must_use]
    pub const fn used_safe_fallback(&self) -> bool {
        !matches!(
            self.effective_policy,
            ArenaLocalityPolicy::CohortPinned { .. }
        )
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
            ("worker_threads", self.worker_threads.to_string()),
            ("cohort_count", self.cohort_count.to_string()),
            (
                "topology_confidence_percent",
                self.topology_confidence_percent
                    .map_or_else(|| "none".to_string(), |value| value.to_string()),
            ),
            ("accounting_epoch", self.accounting_epoch.to_string()),
            (
                "remote_touch_budget_bps",
                self.remote_touch_budget_bps.to_string(),
            ),
            ("task_capacity", self.task_capacity.to_string()),
            ("region_capacity", self.region_capacity.to_string()),
            ("obligation_capacity", self.obligation_capacity.to_string()),
            (
                "task_record_pool_capacity",
                self.task_record_pool_capacity.to_string(),
            ),
            (
                "baseline_remote_touch_count",
                self.baseline.remote_touch_count.to_string(),
            ),
            (
                "candidate_remote_touch_count",
                self.candidate.remote_touch_count.to_string(),
            ),
            (
                "selected_remote_touch_count",
                self.selected.remote_touch_count.to_string(),
            ),
            (
                "selected_remote_touch_ratio_bps",
                self.selected.remote_touch_ratio_bps().to_string(),
            ),
            ("placement_count", self.placements.len().to_string()),
            ("no_win_trigger", format_bool(self.no_win_trigger)),
            ("ownership_preserved", format_bool(self.ownership_preserved)),
            (
                "estimated_hot_bytes",
                self.estimated_hot_bytes().to_string(),
            ),
        ]
    }
}

/// Runtime configuration.
/// Backing-state shape selected by the runtime at build time.
///
/// br-asupersync-8fuxnt: ShardedState (`src/runtime/sharded_state.rs`,
/// 1556 lines, metamorphic-tested via `tests/metamorphic/sharded_state.rs`)
/// reduces lock contention on multi-worker schedulers by splitting the
/// unified RuntimeState into independently-locked Tasks/Regions/Obligations
/// shards. The shape switch is wired through this enum so consumers can
/// opt in once the scheduler-side integration lands.
///
/// Default is `Unified` — the historical single-mutex backing store —
/// to preserve current behavior. `Sharded` opt-in is gated at build
/// time until the `ThreeLaneScheduler` accepts an `&Arc<ShardedState>`
/// constructor (see br-asupersync-8fuxnt acceptance criteria).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeStateShape {
    /// Single-lock unified RuntimeState. Default; matches all behavior
    /// shipped before br-asupersync-8fuxnt.
    #[default]
    Unified,
    /// Independently-locked Tasks/Regions/Obligations shards. Production
    /// runtime path is currently gated on the matching scheduler
    /// integration (br-asupersync-8fuxnt); the build will return a
    /// ConfigError until that lands.
    Sharded,
}

/// Security configuration for runtime authorization.
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    /// Root authorization key for spawn capabilities.
    /// When None, authorization is disabled (fail-open for testing).
    pub spawn_authorization_key: Option<AuthKey>,
}

/// Concrete scheduler, blocking-pool, tracing, and policy settings for a runtime.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Number of worker threads (default: available parallelism).
    pub worker_threads: usize,
    /// Optional explicit worker-to-cohort mapping for locality-aware steals.
    pub worker_cohort_map: Option<WorkerCohortMapping>,
    /// Deterministic scheduler placement mode used with worker cohorts.
    pub scheduler_placement_mode: SchedulerPlacementMode,
    /// Stack size per worker thread (default: 2MB).
    pub thread_stack_size: usize,
    /// Name prefix for worker threads.
    pub thread_name_prefix: String,
    /// Global queue size limit (0 = unbounded).
    pub global_queue_limit: usize,
    /// Work stealing batch size.
    pub steal_batch_size: usize,
    /// Observe-first adaptive ready-lane batch sizing profile.
    pub adaptive_ready_batch: AdaptiveReadyBatchConfig,
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
    /// Backing-state shape (Unified vs Sharded). See [`RuntimeStateShape`].
    ///
    /// Default `Unified` matches all pre-br-asupersync-8fuxnt behavior.
    /// `Sharded` selection is currently gated at `RuntimeBuilder::build()`
    /// pending the scheduler-side integration (also tracked under
    /// br-asupersync-8fuxnt).
    pub runtime_state_shape: RuntimeStateShape,
    /// Security configuration for authorization.
    pub security: SecurityConfig,
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
        self.adaptive_ready_batch.normalize(self.steal_batch_size);
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
        self.arena_temperature_report_with_locality(large_page_cold_slabs_supported, None, false)
    }

    /// Returns the operator-facing arena temperature report composed with locality evidence.
    ///
    /// Hot/cold tiering is conservative: any non-unified policy requires a
    /// present, fresh, non-fallback locality proof before the cold tier may
    /// activate.
    #[must_use]
    pub fn arena_temperature_report_with_locality(
        &self,
        large_page_cold_slabs_supported: bool,
        locality_report: Option<&ArenaLocalityReport>,
        locality_profile_stale: bool,
    ) -> ArenaTemperatureReport {
        build_arena_temperature_report(
            self.resolved_capacity_hints(),
            self.trace_storage_budget(),
            self.arena_temperature_policy,
            large_page_cold_slabs_supported,
            locality_report,
            locality_profile_stale,
        )
    }

    /// Returns the operator-facing deterministic arena-locality report.
    ///
    /// This planner is policy-only: it computes the preferred hot-metadata
    /// placement and conservative fallback decision without changing logical
    /// task/region/obligation ownership semantics.
    #[must_use]
    pub fn arena_locality_report(
        &self,
        requested_policy: ArenaLocalityPolicy,
        topology_confidence_percent: Option<u8>,
        access_model: &ArenaLocalityAccessModel,
    ) -> ArenaLocalityReport {
        build_arena_locality_report(
            self.worker_threads,
            self.worker_cohort_map.as_ref(),
            self.resolved_capacity_hints(),
            requested_policy,
            topology_confidence_percent,
            access_model,
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
            scheduler_placement_mode: SchedulerPlacementMode::default(),
            thread_stack_size: 2 * 1024 * 1024,
            thread_name_prefix: "asupersync-worker".to_string(),
            global_queue_limit: 0,
            steal_batch_size: 16,
            adaptive_ready_batch: AdaptiveReadyBatchConfig::default(),
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
            // br-asupersync-8fuxnt: default is the unified single-mutex
            // backing store to preserve all pre-bead behavior. Opt in to
            // Sharded once the scheduler-side wire-up lands.
            runtime_state_shape: RuntimeStateShape::Unified,
            security: SecurityConfig::default(),
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

    /// Returns the deterministic profile preference order for this planner objective.
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

    /// Minimum CPU cores required before this profile is eligible.
    #[must_use]
    pub const fn required_cpu_cores(self) -> usize {
        match self {
            Self::ConservativeBaseline => 1,
            Self::LocalityFirst64C256G
            | Self::TailProtectionFirst64C256G
            | Self::LargeMemoryEvidenceRetention256G => 64,
        }
    }

    /// Minimum memory, in GiB, required before this profile is eligible.
    #[must_use]
    pub const fn required_memory_gib(self) -> usize {
        match self {
            Self::ConservativeBaseline => 1,
            Self::LocalityFirst64C256G
            | Self::TailProtectionFirst64C256G
            | Self::LargeMemoryEvidenceRetention256G => 256,
        }
    }

    /// Proof surfaces that must be present and current for this profile.
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

    /// Operator-facing reasons this profile may be selected.
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

    /// Operator-facing reasons to refuse this profile even if it is available.
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
    /// Stable operator-facing evidence kind identifier.
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

const HOST_PROFILE_MIN_EVIDENCE_CONFIDENCE_PERCENT: u8 = 80;
const COORDINATION_WORKLOAD_DEFAULT_MAX_ARTIFACT_AGE_HOURS: u64 = 48;
const COORDINATION_WORKLOAD_DEFAULT_MIN_SAMPLE_COUNT: usize = 32;

/// Freshness posture for host-profile child proof evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostProfileEvidenceCalibrationStatus {
    /// The child proof is current enough to justify profile planning.
    Current,
    /// The child proof is stale and must force a conservative refusal.
    Stale,
}

impl HostProfileEvidenceCalibrationStatus {
    /// Stable operator-facing status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
        }
    }
}

impl fmt::Display for HostProfileEvidenceCalibrationStatus {
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
    /// Confidence score from the child proof, in percent.
    pub confidence_percent: u8,
    /// Freshness/calibration posture for the child proof.
    pub calibration_status: HostProfileEvidenceCalibrationStatus,
}

impl HostProfileEvidenceArtifact {
    fn validate(&self) -> Result<(), String> {
        if self.artifact_id.is_empty() {
            return Err("artifact_id must not be empty".to_string());
        }
        if !has_json_artifact_extension(&self.artifact_id) {
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
        if self.confidence_percent < HOST_PROFILE_MIN_EVIDENCE_CONFIDENCE_PERCENT {
            return Err(format!(
                "confidence_percent {} is below required {}",
                self.confidence_percent, HOST_PROFILE_MIN_EVIDENCE_CONFIDENCE_PERCENT
            ));
        }
        if self.calibration_status != HostProfileEvidenceCalibrationStatus::Current {
            return Err(format!(
                "calibration_status {} requires conservative fallback",
                self.calibration_status
            ));
        }
        Ok(())
    }
}

/// Redaction posture for coordination-derived workload expansion packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinationWorkloadRedactionStatus {
    /// The pack passed the collector's redaction gate.
    Passed,
    /// The pack still contains data that cannot be surfaced to planners.
    Failed,
}

impl CoordinationWorkloadRedactionStatus {
    /// Stable operator-facing status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for CoordinationWorkloadRedactionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Trust posture for coordination-derived workload expansion packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinationWorkloadTrustStatus {
    /// The pack is allowed to narrow capacity envelopes.
    Trusted,
    /// The pack is present but cannot influence planner decisions.
    Untrusted,
}

impl CoordinationWorkloadTrustStatus {
    /// Stable operator-facing status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }
}

impl fmt::Display for CoordinationWorkloadTrustStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Optional coordination-pressure evidence synthesized from Agent Mail, Beads,
/// bv, rch, git-frontier, and proof-artifact workload packs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinationWorkloadExpansionEvidence {
    /// Stable expansion-pack artifact path.
    pub artifact_id: String,
    /// Contract version used by the synthesis runner.
    pub contract_version: String,
    /// Digest or digest-like identifier for the emitted expansion pack.
    pub pack_hash: String,
    /// Digest or digest-like identifier for the redacted source bundle.
    pub source_bundle_hash: String,
    /// Whether the synthesis runner validated the pack.
    pub validation_passed: bool,
    /// Redaction outcome for coordination-originating records.
    pub redaction_status: CoordinationWorkloadRedactionStatus,
    /// Trust outcome for the pack's signer/source policy.
    pub trust_status: CoordinationWorkloadTrustStatus,
    /// Independent coordination samples that backed the pack.
    pub sample_count: usize,
    /// Age of the pack in hours.
    pub artifact_age_hours: u64,
    /// Host fingerprint represented by the pack.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Coordination pressure multiplier in basis points. Values below 10000
    /// would widen capacity and are rejected instead of clamped silently.
    pub pressure_basis_points: u32,
}

impl CoordinationWorkloadExpansionEvidence {
    fn validate_for_resources(
        &self,
        max_artifact_age_hours: u64,
        min_sample_count: usize,
        resources: &HostProfileHostResources,
    ) -> Result<(), String> {
        validate_artifact_json_path(&self.artifact_id, "coordination artifact_id")?;
        validate_hashish(&self.pack_hash, "coordination pack_hash")?;
        validate_hashish(&self.source_bundle_hash, "coordination source_bundle_hash")?;
        if self.contract_version.trim().is_empty() {
            return Err("coordination contract_version must not be empty".to_string());
        }
        if !self.validation_passed {
            return Err("coordination validation_passed is false".to_string());
        }
        if self.redaction_status != CoordinationWorkloadRedactionStatus::Passed {
            return Err(format!(
                "coordination redaction_status {} requires refusal",
                self.redaction_status
            ));
        }
        if self.trust_status != CoordinationWorkloadTrustStatus::Trusted {
            return Err(format!(
                "coordination trust_status {} requires refusal",
                self.trust_status
            ));
        }
        if self.sample_count < min_sample_count.max(1) {
            return Err(format!(
                "coordination sample_count {} was below the minimum evidence budget {}",
                self.sample_count, min_sample_count
            ));
        }
        if self.artifact_age_hours > max_artifact_age_hours {
            return Err(format!(
                "coordination artifact_age_hours {} exceeded the freshness budget {}",
                self.artifact_age_hours, max_artifact_age_hours
            ));
        }
        self.host_fingerprint
            .validate_for_resources(resources, "coordination host fingerprint")?;
        if self.pressure_basis_points < 10_000 {
            return Err(format!(
                "coordination pressure_basis_points {} would widen capacity",
                self.pressure_basis_points
            ));
        }
        if self.pressure_basis_points > 100_000 {
            return Err(format!(
                "coordination pressure_basis_points {} exceeds the supported bound 100000",
                self.pressure_basis_points
            ));
        }
        Ok(())
    }

    fn validate_for_capacity(
        &self,
        max_artifact_age_hours: u64,
        min_sample_count: usize,
        resources: &HostProfileHostResources,
        request_fingerprint: &CapacityEnvelopeHostFingerprint,
    ) -> Result<(), String> {
        self.validate_for_resources(max_artifact_age_hours, min_sample_count, resources)?;
        request_fingerprint.validate_for_resources(resources, "request host fingerprint")?;
        if self.host_fingerprint.hostname != request_fingerprint.hostname
            || self.host_fingerprint.arch != request_fingerprint.arch
        {
            return Err(
                "coordination host fingerprint did not match the requested host fingerprint"
                    .to_string(),
            );
        }
        Ok(())
    }

    #[must_use]
    fn agent_ceiling(&self, measured_agent_count: usize) -> usize {
        let measured_agent_count = measured_agent_count.max(1);
        let pressure_basis_points = u128::from(self.pressure_basis_points.max(10_000));
        let ceiling =
            saturating_mul_div(measured_agent_count as u128, 10_000, pressure_basis_points)
                as usize;
        ceiling.max(1).min(measured_agent_count)
    }
}

/// Whether coordination evidence was absent, applied, or refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinationWorkloadExpansionVerdict {
    /// No coordination pack was supplied.
    Absent,
    /// A valid coordination pack narrowed planner inputs.
    Used,
    /// A supplied coordination pack was rejected before planning.
    Refused,
}

impl CoordinationWorkloadExpansionVerdict {
    /// Stable operator-facing verdict string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Used => "used",
            Self::Refused => "refused",
        }
    }
}

impl fmt::Display for CoordinationWorkloadExpansionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operator-facing status for the optional coordination workload pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinationWorkloadExpansionStatus {
    /// Final planner verdict for the coordination pack.
    pub verdict: CoordinationWorkloadExpansionVerdict,
    /// Expansion-pack artifact path, if present.
    pub artifact_id: Option<String>,
    /// Expansion-pack digest, if present.
    pub pack_hash: Option<String>,
    /// Source bundle digest, if present.
    pub source_bundle_hash: Option<String>,
    /// Pressure multiplier from the accepted pack.
    pub pressure_basis_points: Option<u32>,
    /// Maximum agent count allowed by the accepted pack.
    pub agent_ceiling: Option<usize>,
    /// Reasons a supplied pack was refused.
    pub refusal_reasons: Vec<String>,
}

impl CoordinationWorkloadExpansionStatus {
    #[must_use]
    fn absent() -> Self {
        Self {
            verdict: CoordinationWorkloadExpansionVerdict::Absent,
            artifact_id: None,
            pack_hash: None,
            source_bundle_hash: None,
            pressure_basis_points: None,
            agent_ceiling: None,
            refusal_reasons: Vec::new(),
        }
    }

    #[must_use]
    fn used(evidence: &CoordinationWorkloadExpansionEvidence, agent_ceiling: usize) -> Self {
        Self {
            verdict: CoordinationWorkloadExpansionVerdict::Used,
            artifact_id: Some(evidence.artifact_id.clone()),
            pack_hash: Some(evidence.pack_hash.clone()),
            source_bundle_hash: Some(evidence.source_bundle_hash.clone()),
            pressure_basis_points: Some(evidence.pressure_basis_points),
            agent_ceiling: Some(agent_ceiling),
            refusal_reasons: Vec::new(),
        }
    }

    #[must_use]
    fn refused(evidence: &CoordinationWorkloadExpansionEvidence, reason: String) -> Self {
        Self {
            verdict: CoordinationWorkloadExpansionVerdict::Refused,
            artifact_id: Some(evidence.artifact_id.clone()),
            pack_hash: Some(evidence.pack_hash.clone()),
            source_bundle_hash: Some(evidence.source_bundle_hash.clone()),
            pressure_basis_points: Some(evidence.pressure_basis_points),
            agent_ceiling: None,
            refusal_reasons: vec![reason],
        }
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
    /// Optional coordination-derived workload expansion proof.
    pub coordination_workload_expansion: Option<CoordinationWorkloadExpansionEvidence>,
}

impl HostProfileEvidenceSet {
    /// Artifact identifiers that become inputs to host-profile planning receipts.
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
        if let Some(evidence) = &self.coordination_workload_expansion {
            ids.push(evidence.artifact_id.clone());
        }
        ids
    }

    /// Looks up the proof artifact associated with one required evidence kind.
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
    /// Explicit arena-temperature policy override.
    pub arena_temperature_policy: Option<ArenaTemperaturePolicy>,
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
    /// Stable field names for every manual override present in this request.
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
        if self.arena_temperature_policy.is_some() {
            fields.push("arena_temperature_policy");
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

    /// Applies only explicitly configured manual overrides to a runtime config.
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
        if let Some(arena_temperature_policy) = self.arena_temperature_policy {
            config.arena_temperature_policy = arena_temperature_policy;
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
                    let conflict_matrix = build_host_profile_conflict_rows(
                        self.objective,
                        profile,
                        self.requested_profile,
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
                        evidence_sufficiency_score_percent: candidate
                            .evidence_evaluation
                            .score_percent,
                        evidence_confidence_status: candidate.evidence_evaluation.confidence_status,
                        unresolved_child_proof_ids: candidate
                            .evidence_evaluation
                            .unresolved_child_proof_ids,
                        dominant_risk_contributors: candidate
                            .evidence_evaluation
                            .dominant_risk_contributors,
                        conflict_matrix,
                        expected_impact_estimates: host_profile_expected_impact_estimates(profile),
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
        let report_profile = self
            .requested_profile
            .unwrap_or_else(|| self.objective.candidate_order()[0]);
        let evidence_evaluation = evaluate_host_profile_evidence(
            report_profile,
            &self.controller_evidence,
            &self.host_resources,
        );
        let conflict_matrix = build_host_profile_conflict_rows(
            self.objective,
            fallback_profile,
            self.requested_profile,
        );
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
                &self.host_resources,
            ),
            input_evidence_artifact_ids,
            manual_overrides_applied,
            config_diff,
            sanitized_operator_note,
            evidence_sufficiency_score_percent: evidence_evaluation.score_percent,
            evidence_confidence_status: evidence_evaluation.confidence_status,
            unresolved_child_proof_ids: evidence_evaluation.unresolved_child_proof_ids,
            dominant_risk_contributors: evidence_evaluation.dominant_risk_contributors,
            conflict_matrix,
            expected_impact_estimates: host_profile_expected_impact_estimates(fallback_profile),
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
        let evidence_evaluation = evaluate_host_profile_evidence(
            profile,
            &self.controller_evidence,
            &self.host_resources,
        );
        refusal_reasons.extend(evidence_evaluation.refusal_reasons.iter().cloned());
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
            controller_ledger_state: controller_ledger_entries(
                profile,
                &self.controller_evidence,
                &self.host_resources,
            ),
            evidence_evaluation,
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
    /// Percent of required child proofs that were current and high-confidence.
    pub evidence_sufficiency_score_percent: u8,
    /// Operator-facing confidence status for the child-proof set.
    pub evidence_confidence_status: String,
    /// Proof IDs or proof slots that kept a candidate from being selected.
    pub unresolved_child_proof_ids: Vec<String>,
    /// Deterministic dominant risks explaining refusal or conservative posture.
    pub dominant_risk_contributors: Vec<String>,
    /// Objective/profile conflict rows rendered for dry-run review.
    pub conflict_matrix: Vec<HostProfileConflictRow>,
    /// Estimated profile impact fields; these are not capacity certificates.
    pub expected_impact_estimates: Vec<HostProfileExpectedImpactEstimate>,
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

/// One deterministic row in the host-profile conflict report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfileConflictRow {
    /// Candidate profile considered by the planner.
    pub profile: HostProfileId,
    /// Planner verdict for this objective/profile pair.
    pub verdict: String,
    /// Operator-readable explanation for the verdict.
    pub reason: String,
}

/// Estimated impact field emitted by the planner dry run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfileExpectedImpactEstimate {
    /// Impact metric name.
    pub metric: String,
    /// Explicit label that prevents confusing estimates with certification.
    pub label: String,
    /// Deterministic estimate text.
    pub estimate: String,
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
    /// Stable operator-facing diff source identifier.
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
    evidence_evaluation: HostProfileEvidenceEvaluation,
}

#[derive(Clone)]
struct HostProfileEvidenceEvaluation {
    score_percent: u8,
    confidence_status: String,
    unresolved_child_proof_ids: Vec<String>,
    dominant_risk_contributors: Vec<String>,
    refusal_reasons: Vec<String>,
}

fn evaluate_host_profile_evidence(
    profile: HostProfileId,
    evidence: &HostProfileEvidenceSet,
    host_resources: &HostProfileHostResources,
) -> HostProfileEvidenceEvaluation {
    let required = profile.required_evidence();
    if required.is_empty() && evidence.coordination_workload_expansion.is_none() {
        return HostProfileEvidenceEvaluation {
            score_percent: 100,
            confidence_status: "baseline-no-child-proof-required".to_string(),
            unresolved_child_proof_ids: Vec::new(),
            dominant_risk_contributors: vec![
                "conservative baseline does not require child proof activation".to_string(),
            ],
            refusal_reasons: Vec::new(),
        };
    }

    let mut valid_count = 0usize;
    let mut unresolved_child_proof_ids = Vec::new();
    let mut dominant_risk_contributors = Vec::new();
    let mut refusal_reasons = Vec::new();
    let mut saw_low_confidence = false;
    let mut saw_stale = false;
    let mut evidence_count = required.len();

    for kind in required {
        match evidence.for_kind(*kind) {
            Some(artifact) => match artifact.validate() {
                Ok(()) => valid_count += 1,
                Err(reason) => {
                    if artifact.confidence_percent < HOST_PROFILE_MIN_EVIDENCE_CONFIDENCE_PERCENT {
                        saw_low_confidence = true;
                    }
                    if artifact.calibration_status != HostProfileEvidenceCalibrationStatus::Current
                    {
                        saw_stale = true;
                    }
                    unresolved_child_proof_ids.push(format!(
                        "{}:{}",
                        kind.as_str(),
                        artifact.artifact_id
                    ));
                    dominant_risk_contributors
                        .push(format!("{} proof rejected: {reason}", kind.as_str()));
                    refusal_reasons.push(format!("{kind} proof rejected: {reason}"));
                }
            },
            None => {
                unresolved_child_proof_ids.push(format!("{}:missing", kind.as_str()));
                dominant_risk_contributors.push(format!("{} proof is missing", kind.as_str()));
                refusal_reasons.push(format!("{kind} proof is missing"));
            }
        }
    }

    if let Some(coordination) = &evidence.coordination_workload_expansion {
        evidence_count += 1;
        match coordination.validate_for_resources(
            COORDINATION_WORKLOAD_DEFAULT_MAX_ARTIFACT_AGE_HOURS,
            COORDINATION_WORKLOAD_DEFAULT_MIN_SAMPLE_COUNT,
            host_resources,
        ) {
            Ok(()) => valid_count += 1,
            Err(reason) => {
                unresolved_child_proof_ids.push(format!(
                    "coordination_workload:{}",
                    coordination.artifact_id
                ));
                dominant_risk_contributors
                    .push(format!("coordination_workload proof rejected: {reason}"));
                refusal_reasons.push(format!("coordination_workload proof rejected: {reason}"));
            }
        }
    }

    let score_percent = if evidence_count == 0 {
        100
    } else {
        ((valid_count * 100) / evidence_count) as u8
    };
    let confidence_status = if unresolved_child_proof_ids.is_empty() {
        "high-confidence".to_string()
    } else if saw_stale {
        "stale-evidence".to_string()
    } else if saw_low_confidence {
        "low-confidence".to_string()
    } else {
        "insufficient-evidence".to_string()
    };

    if dominant_risk_contributors.is_empty() {
        dominant_risk_contributors
            .push("all required child proofs are current and high-confidence".to_string());
    }

    HostProfileEvidenceEvaluation {
        score_percent,
        confidence_status,
        unresolved_child_proof_ids,
        dominant_risk_contributors,
        refusal_reasons,
    }
}

fn build_host_profile_conflict_rows(
    objective: HostProfilePlannerObjective,
    selected_profile: HostProfileId,
    requested_profile: Option<HostProfileId>,
) -> Vec<HostProfileConflictRow> {
    objective
        .candidate_order()
        .iter()
        .copied()
        .map(|profile| {
            let (verdict, reason) = if Some(profile) == requested_profile {
                (
                    "requested",
                    "operator explicitly requested this profile before fallback checks",
                )
            } else if profile == selected_profile {
                (
                    "selected",
                    "profile matched the objective and passed child-proof gates",
                )
            } else if profile == HostProfileId::ConservativeBaseline {
                (
                    "safe_fallback",
                    "conservative fallback remains available when child proof confidence is weak",
                )
            } else {
                (
                    "conflicting_goal",
                    match (objective, profile) {
                        (
                            HostProfilePlannerObjective::LocalityFirst,
                            HostProfileId::LargeMemoryEvidenceRetention256G,
                        ) => "evidence retention keeps larger buffers than the locality-first objective prefers",
                        (
                            HostProfilePlannerObjective::EvidenceRetentionFirst,
                            HostProfileId::TailProtectionFirst64C256G,
                        ) => "tail protection uses tighter queues than the evidence-retention objective prefers",
                        (
                            HostProfilePlannerObjective::TailProtectionFirst,
                            HostProfileId::LocalityFirst64C256G,
                        ) => "locality-first keeps more queue headroom than the tail-protection objective prefers",
                        _ => "profile trades off against the active planner objective",
                    },
                )
            };
            HostProfileConflictRow {
                profile,
                verdict: verdict.to_string(),
                reason: reason.to_string(),
            }
        })
        .collect()
}

fn host_profile_expected_impact_estimates(
    profile: HostProfileId,
) -> Vec<HostProfileExpectedImpactEstimate> {
    let estimates = match profile {
        HostProfileId::ConservativeBaseline => [
            ("p95_wake_to_run", "baseline"),
            ("p99_wake_to_run", "baseline"),
            ("p999_wake_to_run", "baseline"),
        ],
        HostProfileId::LocalityFirst64C256G => [
            ("p95_wake_to_run", "locality-improved"),
            ("p99_wake_to_run", "cohort-sensitive"),
            ("p999_wake_to_run", "needs-capacity-certificate"),
        ],
        HostProfileId::TailProtectionFirst64C256G => [
            ("p95_wake_to_run", "queue-limited"),
            ("p99_wake_to_run", "tail-protected"),
            ("p999_wake_to_run", "needs-capacity-certificate"),
        ],
        HostProfileId::LargeMemoryEvidenceRetention256G => [
            ("p95_wake_to_run", "retention-neutral"),
            ("p99_wake_to_run", "retention-observed"),
            ("p999_wake_to_run", "needs-capacity-certificate"),
        ],
    };

    estimates
        .into_iter()
        .map(|(metric, estimate)| HostProfileExpectedImpactEstimate {
            metric: metric.to_string(),
            label: "estimate_not_capacity_certificate".to_string(),
            estimate: estimate.to_string(),
        })
        .collect()
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
            config.arena_temperature_policy = ArenaTemperaturePolicy::TieredColdEvidence;
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
    host_resources: &HostProfileHostResources,
) -> Vec<HostProfileControllerLedgerEntry> {
    let mut entries = [
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
        let validation_passed =
            artifact.is_some_and(|item| item.validation_passed && item.validate().is_ok());
        HostProfileControllerLedgerEntry {
            controller: kind.as_str().to_string(),
            stance: controller_stance(profile, kind).to_string(),
            proof_artifact_id,
            validation_passed,
        }
    })
    .collect::<Vec<_>>();
    if let Some(coordination) = &evidence.coordination_workload_expansion {
        let validation_passed = coordination
            .validate_for_resources(
                COORDINATION_WORKLOAD_DEFAULT_MAX_ARTIFACT_AGE_HOURS,
                COORDINATION_WORKLOAD_DEFAULT_MIN_SAMPLE_COUNT,
                host_resources,
            )
            .is_ok();
        entries.push(HostProfileControllerLedgerEntry {
            controller: "coordination_workload".to_string(),
            stance: coordination_workload_stance(profile).to_string(),
            proof_artifact_id: Some(coordination.artifact_id.clone()),
            validation_passed,
        });
    }
    entries
}

fn coordination_workload_stance(profile: HostProfileId) -> &'static str {
    match profile {
        HostProfileId::ConservativeBaseline => "absent_or_refused_conservative",
        HostProfileId::LocalityFirst64C256G
        | HostProfileId::TailProtectionFirst64C256G
        | HostProfileId::LargeMemoryEvidenceRetention256G => "capacity_pressure_gate",
    }
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
        (
            HostProfileId::LocalityFirst64C256G
            | HostProfileId::TailProtectionFirst64C256G
            | HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::Brownout,
        ) => "optional_first",
        (
            HostProfileId::LocalityFirst64C256G
            | HostProfileId::TailProtectionFirst64C256G
            | HostProfileId::LargeMemoryEvidenceRetention256G,
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
        (
            HostProfileId::LocalityFirst64C256G
            | HostProfileId::TailProtectionFirst64C256G
            | HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::AdaptiveBatchSizing,
        ) => "builtin_adaptive",
        (
            HostProfileId::LocalityFirst64C256G
            | HostProfileId::TailProtectionFirst64C256G
            | HostProfileId::LargeMemoryEvidenceRetention256G,
            HostProfileEvidenceKind::BlockingPoolAffinity,
        ) => "cohort_biased",
        (
            HostProfileId::LocalityFirst64C256G | HostProfileId::LargeMemoryEvidenceRetention256G,
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
        "arena_temperature_policy",
        baseline.arena_temperature_policy.to_string(),
        profile_bundle.arena_temperature_policy.to_string(),
        final_bundle.arena_temperature_policy.to_string(),
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
    /// Stable operator-facing brownout stage identifier.
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

/// Calibration posture for the evidence driving a capacity certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityEnvelopeCalibrationStatus {
    /// Tail and brownout evidence is current enough to certify against.
    Calibrated,
    /// Observed drift invalidated the certificate model; refuse conservatively.
    Drifted,
}

impl CapacityEnvelopeCalibrationStatus {
    /// Stable operator-facing calibration status identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Calibrated => "calibrated",
            Self::Drifted => "drifted",
        }
    }
}

impl fmt::Display for CapacityEnvelopeCalibrationStatus {
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
    /// Number of independent samples backing this evidence snapshot.
    pub sample_count: usize,
    /// Whether the evidence is still calibrated enough to extrapolate conservatively.
    pub calibration_status: CapacityEnvelopeCalibrationStatus,
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
        min_sample_count: usize,
        resources: &HostProfileHostResources,
        request_fingerprint: &CapacityEnvelopeHostFingerprint,
    ) -> Result<(), String> {
        if self.scenario_artifact_id.trim().is_empty() {
            return Err("scenario_artifact_id must not be empty".to_string());
        }
        if !has_json_artifact_extension(&self.scenario_artifact_id) {
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
        if self.sample_count < min_sample_count.max(1) {
            return Err(format!(
                "sample_count {} was below the minimum evidence budget {}",
                self.sample_count, min_sample_count
            ));
        }
        if self.calibration_status != CapacityEnvelopeCalibrationStatus::Calibrated {
            return Err(format!(
                "calibration_status {} requires conservative fallback",
                self.calibration_status
            ));
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
    /// Minimum number of measured samples required before extrapolation is allowed.
    pub min_sample_count: usize,
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
            min_sample_count: 32,
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
    /// Override for the minimum evidence sample count.
    pub min_sample_count: Option<usize>,
}

impl CapacityEnvelopeBudget {
    /// Returns this budget with every supplied optional override applied.
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
            min_sample_count: match overrides.min_sample_count {
                Some(value) => value,
                None => self.min_sample_count,
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
        let coordination_workload_status = match self
            .controller_evidence
            .coordination_workload_expansion
            .as_ref()
        {
            Some(evidence) => match evidence.validate_for_capacity(
                effective_budget.max_artifact_age_hours,
                effective_budget.min_sample_count,
                &self.host_resources,
                &self.host_fingerprint,
            ) {
                Ok(()) => CoordinationWorkloadExpansionStatus::used(
                    evidence,
                    evidence.agent_ceiling(self.evidence_snapshot.measured_agent_count),
                ),
                Err(reason) => CoordinationWorkloadExpansionStatus::refused(evidence, reason),
            },
            None => CoordinationWorkloadExpansionStatus::absent(),
        };
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
            effective_budget.min_sample_count,
            &self.host_resources,
            &self.host_fingerprint,
        ) {
            refusal_reasons.push(format!("scenario evidence rejected: {reason}"));
        }
        if host_profile_plan.used_safe_fallback() {
            refusal_reasons.extend(host_profile_plan.refusal_reasons.clone());
        }
        if coordination_workload_status.verdict == CoordinationWorkloadExpansionVerdict::Refused {
            refusal_reasons.extend(
                coordination_workload_status
                    .refusal_reasons
                    .iter()
                    .map(|reason| format!("coordination workload expansion rejected: {reason}")),
            );
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
        let assumptions_ledger = build_capacity_assumptions(
            profile,
            &self.evidence_snapshot,
            effective_budget,
            &coordination_workload_status,
        );

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
                        coordination_workload_status.agent_ceiling,
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
            coordination_workload_status,
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
    /// Coordination-workload expansion status used by the certificate.
    pub coordination_workload_status: CoordinationWorkloadExpansionStatus,
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

/// Schema version for mean-field capacity planner reports.
pub const MEAN_FIELD_CAPACITY_PLANNER_REPORT_SCHEMA_VERSION: &str =
    "mean-field-capacity-planner-report-v1";

const MEAN_FIELD_MIN_CONFIDENCE_PERCENT: u8 = HOST_PROFILE_MIN_EVIDENCE_CONFIDENCE_PERCENT;
const MEAN_FIELD_MAX_EXTRAPOLATION_BPS: u32 = 20_000;

/// Operator-facing verdict for a mean-field capacity plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeanFieldCapacityPlannerVerdict {
    /// Planner is disabled and retained the conservative baseline.
    Disabled,
    /// Planner produced a certificate-backed recommendation.
    Recommended,
    /// Inputs were valid, but conservative fallback was safer.
    NoWin,
    /// Inputs were invalid, unsupported, or outside the calibrated envelope.
    FailClosed,
}

impl MeanFieldCapacityPlannerVerdict {
    /// Stable operator-facing verdict string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Recommended => "recommended",
            Self::NoWin => "no_win",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl fmt::Display for MeanFieldCapacityPlannerVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Workload mix used by the mean-field planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeanFieldWorkloadMix {
    /// Coordination/control-plane share in basis points.
    pub coordination_basis_points: u16,
    /// I/O or network share in basis points.
    pub io_basis_points: u16,
    /// CPU-bound service share in basis points.
    pub cpu_basis_points: u16,
    /// Evidence-retention and diagnostics share in basis points.
    pub evidence_basis_points: u16,
    /// Background/other share in basis points.
    pub background_basis_points: u16,
}

impl MeanFieldWorkloadMix {
    /// Build an explicit workload mix. Values must sum to 10_000 basis points.
    #[must_use]
    pub const fn new(
        coordination_basis_points: u16,
        io_basis_points: u16,
        cpu_basis_points: u16,
        evidence_basis_points: u16,
        background_basis_points: u16,
    ) -> Self {
        Self {
            coordination_basis_points,
            io_basis_points,
            cpu_basis_points,
            evidence_basis_points,
            background_basis_points,
        }
    }

    /// Balanced default for mixed agent-swarm workloads.
    #[must_use]
    pub const fn balanced() -> Self {
        Self::new(2_500, 2_500, 2_500, 1_500, 1_000)
    }

    /// Total share represented by the mix.
    #[must_use]
    pub const fn total_basis_points(self) -> u32 {
        self.coordination_basis_points as u32
            + self.io_basis_points as u32
            + self.cpu_basis_points as u32
            + self.evidence_basis_points as u32
            + self.background_basis_points as u32
    }

    fn validate(self) -> Result<(), String> {
        let total = self.total_basis_points();
        if total != 10_000 {
            return Err(format!(
                "workload mix must sum to 10000 basis points, got {total}"
            ));
        }
        Ok(())
    }

    fn pressure_basis_points(self) -> u32 {
        10_000
            + u32::from(self.coordination_basis_points) / 5
            + u32::from(self.io_basis_points) / 10
            + u32::from(self.evidence_basis_points) / 8
            + u32::from(self.background_basis_points) / 20
    }

    fn dominant_class(self) -> &'static str {
        let rows = [
            ("coordination", self.coordination_basis_points),
            ("io", self.io_basis_points),
            ("cpu", self.cpu_basis_points),
            ("evidence", self.evidence_basis_points),
            ("background", self.background_basis_points),
        ];
        rows.into_iter()
            .max_by_key(|(_, value)| *value)
            .map_or("unknown", |(name, _)| name)
    }

    fn conflicts_with_objective(self, objective: HostProfilePlannerObjective) -> Option<String> {
        match objective {
            HostProfilePlannerObjective::EvidenceRetentionFirst
                if self.coordination_basis_points >= 4_000 =>
            {
                Some(
                    "conflicting_goals:evidence_retention_first_under_coordination_pressure"
                        .to_string(),
                )
            }
            HostProfilePlannerObjective::LocalityFirst if self.evidence_basis_points >= 5_000 => {
                Some("conflicting_goals:locality_first_under_evidence_retention_load".to_string())
            }
            HostProfilePlannerObjective::TailProtectionFirst if self.cpu_basis_points >= 7_000 => {
                Some("conflicting_goals:tail_protection_first_under_cpu_saturation".to_string())
            }
            _ => None,
        }
    }
}

/// Stable reference to a proof artifact consumed by the mean-field planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeanFieldCapacityCertificateRef {
    /// Certificate or artifact identifier.
    pub artifact_id: String,
    /// Certificate digest or digest-like reference.
    pub digest: String,
    /// Human-readable role for the proof.
    pub role: String,
}

/// One controller setting emitted by the mean-field planner report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeanFieldControllerSetting {
    /// Controller or runtime surface.
    pub controller: String,
    /// Deterministic setting value.
    pub setting: String,
    /// Evidence source behind this row.
    pub source: String,
}

/// Request for a dry-run mean-field capacity plan.
#[derive(Clone)]
pub struct MeanFieldCapacityPlannerRequest {
    /// Whether the planner is enabled.
    pub enabled: bool,
    /// Objective used to interpret controller tradeoffs.
    pub objective: HostProfilePlannerObjective,
    /// Target host resources.
    pub host_resources: HostProfileHostResources,
    /// Requested host fingerprint.
    pub host_fingerprint: CapacityEnvelopeHostFingerprint,
    /// Workload mix for the target swarm.
    pub workload_mix: MeanFieldWorkloadMix,
    /// Capacity certificate that bounds all recommendations.
    pub capacity_certificate: CapacityEnvelopeCertificate,
    /// Confidence in the child evidence set, in percent.
    pub evidence_confidence_percent: u8,
    /// Stable capacity certificate id or path.
    pub capacity_certificate_id: String,
    /// Digest for the capacity certificate projection.
    pub capacity_certificate_hash: String,
    /// Replay command for the evidence packet.
    pub replay_command: String,
}

impl MeanFieldCapacityPlannerRequest {
    /// Compute a dry-run capacity plan without mutating runtime state.
    #[must_use]
    pub fn plan(&self) -> MeanFieldCapacityPlan {
        if !self.enabled {
            return self.disabled_plan();
        }

        let mut fail_reasons = Vec::new();
        let mut no_win_reasons = Vec::new();
        if let Err(reason) = self.workload_mix.validate() {
            fail_reasons.push(reason);
        }
        if self.capacity_certificate_id.trim().is_empty() {
            fail_reasons.push("capacity_certificate_id must not be empty".to_string());
        }
        if let Err(reason) =
            validate_hashish(&self.capacity_certificate_hash, "capacity_certificate_hash")
        {
            fail_reasons.push(reason);
        }
        if self.replay_command.trim().is_empty() {
            fail_reasons.push("replay_command must not be empty".to_string());
        }
        if let Err(reason) = self
            .host_fingerprint
            .validate_for_resources(&self.host_resources, "request host fingerprint")
        {
            fail_reasons.push(reason);
        }
        if self.capacity_certificate.host_fingerprint.hostname != self.host_fingerprint.hostname
            || self.capacity_certificate.host_fingerprint.arch != self.host_fingerprint.arch
            || self.capacity_certificate.host_fingerprint.cpu_cores
                != self.host_fingerprint.cpu_cores
            || self.capacity_certificate.host_fingerprint.memory_gib
                != self.host_fingerprint.memory_gib
        {
            fail_reasons
                .push("capacity certificate host fingerprint did not match request".to_string());
        }
        if self.host_resources.cpu_cores
            < self
                .capacity_certificate
                .selected_profile
                .required_cpu_cores()
        {
            fail_reasons.push(format!(
                "unsupported topology: {} requires {} CPU cores, host has {}",
                self.capacity_certificate.selected_profile,
                self.capacity_certificate
                    .selected_profile
                    .required_cpu_cores(),
                self.host_resources.cpu_cores
            ));
        }
        if self.host_resources.memory_gib
            < self
                .capacity_certificate
                .selected_profile
                .required_memory_gib()
        {
            fail_reasons.push(format!(
                "unsupported memory envelope: {} requires {} GiB, host has {} GiB",
                self.capacity_certificate.selected_profile,
                self.capacity_certificate
                    .selected_profile
                    .required_memory_gib(),
                self.host_resources.memory_gib
            ));
        }
        if self.capacity_certificate.used_safe_fallback() {
            no_win_reasons
                .push("capacity certificate already selected conservative fallback".to_string());
            no_win_reasons.extend(self.capacity_certificate.refusal_reasons.clone());
        }
        if self.capacity_certificate.evidence_snapshot.sample_count
            < self.capacity_certificate.effective_budget.min_sample_count
        {
            fail_reasons.push(format!(
                "capacity certificate sample_count {} below minimum {}",
                self.capacity_certificate.evidence_snapshot.sample_count,
                self.capacity_certificate.effective_budget.min_sample_count
            ));
        }
        if self.evidence_confidence_percent < MEAN_FIELD_MIN_CONFIDENCE_PERCENT {
            no_win_reasons.push(format!(
                "evidence_confidence_percent {} below required {}",
                self.evidence_confidence_percent, MEAN_FIELD_MIN_CONFIDENCE_PERCENT
            ));
        }
        if let Some(reason) = self.workload_mix.conflicts_with_objective(self.objective) {
            no_win_reasons.push(reason);
        }

        let safe_envelope = match self.capacity_certificate.safe_envelope {
            Some(range) => range,
            None => {
                no_win_reasons
                    .push("capacity certificate did not expose a safe envelope".to_string());
                self.capacity_certificate.refused_envelope
            }
        };
        let measured_agents = self
            .capacity_certificate
            .evidence_snapshot
            .measured_agent_count
            .max(1);
        let extrapolation_bps = saturating_mul_div(
            safe_envelope.agent_max as u128,
            10_000,
            measured_agents as u128,
        ) as u32;
        if extrapolation_bps > MEAN_FIELD_MAX_EXTRAPOLATION_BPS {
            fail_reasons.push(format!(
                "safe agent ceiling extrapolated {}bps beyond measured evidence; max supported {}bps",
                extrapolation_bps, MEAN_FIELD_MAX_EXTRAPOLATION_BPS
            ));
        }

        if !fail_reasons.is_empty() {
            return self.fallback_plan(MeanFieldCapacityPlannerVerdict::FailClosed, fail_reasons);
        }
        if !no_win_reasons.is_empty() {
            return self.fallback_plan(MeanFieldCapacityPlannerVerdict::NoWin, no_win_reasons);
        }

        let pressure_basis_points = self.workload_mix.pressure_basis_points();
        let recommended_agent_ceiling = saturating_mul_div(
            safe_envelope.agent_max as u128,
            10_000,
            pressure_basis_points as u128,
        ) as usize;
        let recommended_agent_ceiling = recommended_agent_ceiling
            .max(safe_envelope.agent_min.max(1))
            .min(safe_envelope.agent_max.max(1));
        let recommended_worker_threads = safe_envelope
            .worker_max
            .min(self.host_resources.cpu_cores)
            .max(1);
        let recommended_global_queue_limit = safe_envelope
            .max_queue_depth
            .max(recommended_agent_ceiling.saturating_mul(2))
            .min(self.capacity_certificate.effective_budget.max_queue_depth);
        let recommended_capacity_hints = RuntimeCapacityHints::from_expected_concurrent_tasks(
            recommended_agent_ceiling
                .saturating_mul(32)
                .min(recommended_global_queue_limit.max(1)),
        );
        let recommended_trace_storage_profile = if self.workload_mix.evidence_basis_points >= 2_500
            && self.host_resources.memory_gib >= 256
        {
            TraceStorageProfile::LargeMemory256G
        } else {
            self.capacity_certificate.final_bundle.trace_storage_profile
        };
        let recommended_arena_temperature_policy =
            if self.workload_mix.evidence_basis_points >= 2_500 {
                ArenaTemperaturePolicy::TieredColdEvidence
            } else {
                self.capacity_certificate
                    .final_bundle
                    .arena_temperature_policy
            };
        let recommended_blocking_affinity_profile = self
            .capacity_certificate
            .final_bundle
            .blocking
            .affinity_profile;
        let mut final_bundle = self.capacity_certificate.final_bundle.clone();
        final_bundle.worker_threads = recommended_worker_threads;
        final_bundle.global_queue_limit = recommended_global_queue_limit;
        final_bundle.capacity_hints = Some(recommended_capacity_hints);
        final_bundle.trace_storage_profile = recommended_trace_storage_profile;
        final_bundle.arena_temperature_policy = recommended_arena_temperature_policy;
        final_bundle.normalize();

        MeanFieldCapacityPlan {
            schema_version: MEAN_FIELD_CAPACITY_PLANNER_REPORT_SCHEMA_VERSION.to_string(),
            verdict: MeanFieldCapacityPlannerVerdict::Recommended,
            objective: self.objective,
            selected_profile: self.capacity_certificate.selected_profile,
            fallback_profile: self.capacity_certificate.fallback_profile,
            host_fingerprint_class: host_fingerprint_class(&self.host_resources),
            cpu_bucket: cpu_bucket(self.host_resources.cpu_cores).to_string(),
            memory_bucket: memory_bucket(self.host_resources.memory_gib).to_string(),
            workload_mix: self.workload_mix,
            dominant_workload_class: self.workload_mix.dominant_class().to_string(),
            recommended_agent_ceiling,
            recommended_worker_threads,
            recommended_global_queue_limit,
            recommended_capacity_hints,
            recommended_trace_storage_profile,
            recommended_arena_temperature_policy,
            recommended_blocking_affinity_profile,
            recommended_bundle_digest: runtime_config_digest(&final_bundle),
            confidence_percent: self.evidence_confidence_percent,
            certificate_refs: self.certificate_refs(),
            controller_settings: self.controller_settings(
                recommended_worker_threads,
                recommended_global_queue_limit,
                recommended_capacity_hints,
                recommended_trace_storage_profile,
                recommended_arena_temperature_policy,
            ),
            refusal_reasons: Vec::new(),
            no_win: false,
            replay_command: self.replay_command.trim().to_string(),
        }
    }

    fn disabled_plan(&self) -> MeanFieldCapacityPlan {
        let baseline = RuntimeConfig::default();
        MeanFieldCapacityPlan {
            schema_version: MEAN_FIELD_CAPACITY_PLANNER_REPORT_SCHEMA_VERSION.to_string(),
            verdict: MeanFieldCapacityPlannerVerdict::Disabled,
            objective: self.objective,
            selected_profile: HostProfileId::ConservativeBaseline,
            fallback_profile: HostProfileId::ConservativeBaseline,
            host_fingerprint_class: host_fingerprint_class(&self.host_resources),
            cpu_bucket: cpu_bucket(self.host_resources.cpu_cores).to_string(),
            memory_bucket: memory_bucket(self.host_resources.memory_gib).to_string(),
            workload_mix: self.workload_mix,
            dominant_workload_class: self.workload_mix.dominant_class().to_string(),
            recommended_agent_ceiling: 0,
            recommended_worker_threads: baseline.worker_threads,
            recommended_global_queue_limit: baseline.global_queue_limit,
            recommended_capacity_hints: baseline.resolved_capacity_hints(),
            recommended_trace_storage_profile: baseline.trace_storage_profile,
            recommended_arena_temperature_policy: baseline.arena_temperature_policy,
            recommended_blocking_affinity_profile: baseline.blocking.affinity_profile,
            recommended_bundle_digest: runtime_config_digest(&baseline),
            confidence_percent: 0,
            certificate_refs: Vec::new(),
            controller_settings: Vec::new(),
            refusal_reasons: vec![
                "mean-field capacity planner disabled; conservative baseline retained".to_string(),
            ],
            no_win: false,
            replay_command: self.replay_command.trim().to_string(),
        }
    }

    fn fallback_plan(
        &self,
        verdict: MeanFieldCapacityPlannerVerdict,
        refusal_reasons: Vec<String>,
    ) -> MeanFieldCapacityPlan {
        let baseline = RuntimeConfig::default();
        MeanFieldCapacityPlan {
            schema_version: MEAN_FIELD_CAPACITY_PLANNER_REPORT_SCHEMA_VERSION.to_string(),
            verdict,
            objective: self.objective,
            selected_profile: HostProfileId::ConservativeBaseline,
            fallback_profile: HostProfileId::ConservativeBaseline,
            host_fingerprint_class: host_fingerprint_class(&self.host_resources),
            cpu_bucket: cpu_bucket(self.host_resources.cpu_cores).to_string(),
            memory_bucket: memory_bucket(self.host_resources.memory_gib).to_string(),
            workload_mix: self.workload_mix,
            dominant_workload_class: self.workload_mix.dominant_class().to_string(),
            recommended_agent_ceiling: 0,
            recommended_worker_threads: baseline.worker_threads,
            recommended_global_queue_limit: baseline.global_queue_limit,
            recommended_capacity_hints: baseline.resolved_capacity_hints(),
            recommended_trace_storage_profile: baseline.trace_storage_profile,
            recommended_arena_temperature_policy: baseline.arena_temperature_policy,
            recommended_blocking_affinity_profile: baseline.blocking.affinity_profile,
            recommended_bundle_digest: runtime_config_digest(&baseline),
            confidence_percent: self.evidence_confidence_percent,
            certificate_refs: self.certificate_refs(),
            controller_settings: Vec::new(),
            refusal_reasons,
            no_win: verdict == MeanFieldCapacityPlannerVerdict::NoWin,
            replay_command: self.replay_command.trim().to_string(),
        }
    }

    fn certificate_refs(&self) -> Vec<MeanFieldCapacityCertificateRef> {
        let mut refs = vec![MeanFieldCapacityCertificateRef {
            artifact_id: self.capacity_certificate_id.trim().to_string(),
            digest: self.capacity_certificate_hash.trim().to_string(),
            role: "capacity_envelope_certificate".to_string(),
        }];
        refs.extend(
            self.capacity_certificate
                .evidence_artifact_ids
                .iter()
                .map(|id| MeanFieldCapacityCertificateRef {
                    artifact_id: id.clone(),
                    digest: stable_sha256_hex(&[("artifact_id", id.clone())]),
                    role: "child_controller_evidence".to_string(),
                }),
        );
        refs
    }

    fn controller_settings(
        &self,
        worker_threads: usize,
        global_queue_limit: usize,
        capacity_hints: RuntimeCapacityHints,
        trace_storage_profile: TraceStorageProfile,
        arena_temperature_policy: ArenaTemperaturePolicy,
    ) -> Vec<MeanFieldControllerSetting> {
        vec![
            MeanFieldControllerSetting {
                controller: "worker_topology".to_string(),
                setting: format!("worker_threads={worker_threads}"),
                source: "mean_field_safe_envelope".to_string(),
            },
            MeanFieldControllerSetting {
                controller: "queue_admission".to_string(),
                setting: format!("global_queue_limit={global_queue_limit}"),
                source: "capacity_certificate_queue_budget".to_string(),
            },
            MeanFieldControllerSetting {
                controller: "arena_capacity".to_string(),
                setting: format!(
                    "task={} region={} obligation={}",
                    capacity_hints.task_capacity,
                    capacity_hints.region_capacity,
                    capacity_hints.obligation_capacity
                ),
                source: "mean_field_agent_ceiling".to_string(),
            },
            MeanFieldControllerSetting {
                controller: "trace_retention".to_string(),
                setting: trace_storage_profile.to_string(),
                source: "workload_mix_evidence_share".to_string(),
            },
            MeanFieldControllerSetting {
                controller: "arena_temperature".to_string(),
                setting: arena_temperature_policy.to_string(),
                source: "workload_mix_evidence_share".to_string(),
            },
        ]
    }
}

/// Dry-run report produced by the mean-field planner.
#[derive(Clone)]
pub struct MeanFieldCapacityPlan {
    /// Report schema version.
    pub schema_version: String,
    /// Planner verdict.
    pub verdict: MeanFieldCapacityPlannerVerdict,
    /// Objective that drove tradeoff handling.
    pub objective: HostProfilePlannerObjective,
    /// Recommended or fallback profile.
    pub selected_profile: HostProfileId,
    /// Conservative fallback profile.
    pub fallback_profile: HostProfileId,
    /// Host class label used by smoke reports.
    pub host_fingerprint_class: String,
    /// CPU bucket used by operator logs.
    pub cpu_bucket: String,
    /// Memory bucket used by operator logs.
    pub memory_bucket: String,
    /// Workload mix supplied to the planner.
    pub workload_mix: MeanFieldWorkloadMix,
    /// Dominant workload class.
    pub dominant_workload_class: String,
    /// Recommended safe agent ceiling.
    pub recommended_agent_ceiling: usize,
    /// Recommended worker count.
    pub recommended_worker_threads: usize,
    /// Recommended global queue limit.
    pub recommended_global_queue_limit: usize,
    /// Recommended arena capacity hints.
    pub recommended_capacity_hints: RuntimeCapacityHints,
    /// Recommended trace storage profile.
    pub recommended_trace_storage_profile: TraceStorageProfile,
    /// Recommended arena temperature policy.
    pub recommended_arena_temperature_policy: ArenaTemperaturePolicy,
    /// Recommended blocking affinity profile.
    pub recommended_blocking_affinity_profile: BlockingPoolAffinityProfile,
    /// Digest of the dry-run bundle projection.
    pub recommended_bundle_digest: String,
    /// Evidence confidence score used by the planner.
    pub confidence_percent: u8,
    /// Certificate references inspected by the planner.
    pub certificate_refs: Vec<MeanFieldCapacityCertificateRef>,
    /// Controller setting rows.
    pub controller_settings: Vec<MeanFieldControllerSetting>,
    /// Refusal or fallback reasons.
    pub refusal_reasons: Vec<String>,
    /// Whether the valid input produced a no-win fallback.
    pub no_win: bool,
    /// Replay command for the evidence packet.
    pub replay_command: String,
}

impl MeanFieldCapacityPlan {
    /// Whether this report contains a usable recommendation.
    #[must_use]
    pub const fn recommended(&self) -> bool {
        matches!(self.verdict, MeanFieldCapacityPlannerVerdict::Recommended)
    }
}

fn host_fingerprint_class(resources: &HostProfileHostResources) -> String {
    format!(
        "{}_{}",
        cpu_bucket(resources.cpu_cores),
        memory_bucket(resources.memory_gib)
    )
}

const fn cpu_bucket(cpu_cores: usize) -> &'static str {
    if cpu_cores >= 64 {
        "cpu_64_plus"
    } else if cpu_cores >= 32 {
        "cpu_32_63"
    } else {
        "cpu_lt_32"
    }
}

const fn memory_bucket(memory_gib: usize) -> &'static str {
    if memory_gib >= 256 {
        "mem_256_plus"
    } else if memory_gib >= 128 {
        "mem_128_255"
    } else {
        "mem_lt_128"
    }
}

/// Integrity mode for operator-facing profile bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedProfileBundleIntegrityMode {
    /// Digest-only integrity for explicit review-only bundle posture.
    DigestOnlySha256,
    /// Ed25519 signatures using the existing NKey signing primitive.
    NkeyEd25519,
}

impl SignedProfileBundleIntegrityMode {
    /// Stable operator-facing integrity mode identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DigestOnlySha256 => "digest_only_sha256",
            Self::NkeyEd25519 => "nkey_ed25519",
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
    /// Stable operator-facing execution mode identifier.
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

const SIGNED_PROFILE_BUNDLE_SIGNATURE_DOMAIN: &str = "asupersync.signed-profile-bundle.v1";
const SIGNED_PROFILE_BUNDLE_SIGNATURE_ALGORITHM: &str = "nkey_ed25519";

/// Trusted signing key metadata for signed profile bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleTrustedSigningKey {
    /// Stable operator-facing key identifier.
    pub key_id: String,
    /// NKey public key used for Ed25519 verification.
    pub public_key: String,
    /// Whether this key is revoked and must fail closed.
    pub revoked: bool,
}

/// Request-time signing policy used to emit a signed bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleSignaturePolicy {
    /// Required signing domain.
    pub signing_domain: String,
    /// Stable operator-facing key identifier.
    pub key_id: String,
    /// NKey public key expected to verify the signature.
    pub public_key: String,
    /// Signature algorithm identifier.
    pub algorithm: String,
    /// Optional NKey seed used by tests/offline tooling to emit the signature.
    pub signing_seed: Option<String>,
    /// Inclusive issuance timestamp in Unix seconds.
    pub issued_at_unix_seconds: i64,
    /// Exclusive expiry timestamp in Unix seconds.
    pub expires_at_unix_seconds: i64,
    /// Verification time in Unix seconds.
    pub verification_time_unix_seconds: i64,
    /// Monotone bundle epoch.
    pub bundle_epoch: u64,
    /// Lowest acceptable bundle epoch.
    pub minimum_bundle_epoch: u64,
    /// Whether signed mode is required and digest-only must be rejected.
    pub signed_mode_required: bool,
    /// Explicit trust store for verification.
    pub trusted_keys: Vec<SignedProfileBundleTrustedSigningKey>,
}

/// Signature metadata embedded in a signed profile bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProfileBundleSignature {
    /// Required signing domain.
    pub signing_domain: String,
    /// Stable operator-facing key identifier.
    pub key_id: String,
    /// NKey public key used for Ed25519 verification.
    pub public_key: String,
    /// Signature algorithm identifier.
    pub algorithm: String,
    /// Inclusive issuance timestamp in Unix seconds.
    pub issued_at_unix_seconds: i64,
    /// Exclusive expiry timestamp in Unix seconds.
    pub expires_at_unix_seconds: i64,
    /// Monotone bundle epoch.
    pub bundle_epoch: u64,
    /// Digest lock for the referenced capacity certificate.
    pub capacity_certificate_digest_sha256: String,
    /// Root digest for all child proof hashes.
    pub child_proof_graph_root_sha256: String,
    /// Digest lock for rollback receipt chain inputs.
    pub rollback_chain_digest_sha256: String,
    /// Base64 no-pad encoded Ed25519 signature.
    pub signature_base64: String,
}

impl SignedProfileBundleSignature {
    fn digest_material(&self) -> String {
        vec![
            self.signing_domain.clone(),
            self.key_id.clone(),
            self.public_key.clone(),
            self.algorithm.clone(),
            self.issued_at_unix_seconds.to_string(),
            self.expires_at_unix_seconds.to_string(),
            self.bundle_epoch.to_string(),
            self.capacity_certificate_digest_sha256.clone(),
            self.child_proof_graph_root_sha256.clone(),
            self.rollback_chain_digest_sha256.clone(),
        ]
        .join("|")
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
    /// Optional signed-mode policy.
    pub signature_policy: Option<SignedProfileBundleSignaturePolicy>,
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
        let integrity_limitations = match self.integrity_mode {
            SignedProfileBundleIntegrityMode::DigestOnlySha256 => vec![
                "digest-only mode; review-only integrity without asymmetric authentication"
                    .to_string(),
            ],
            SignedProfileBundleIntegrityMode::NkeyEd25519 => Vec::new(),
        };
        let signature = self.signature_policy.as_ref().map(|policy| {
            let capacity_certificate_digest_sha256 =
                signed_profile_bundle_capacity_certificate_digest(
                    &self.capacity_certificate_reference,
                );
            let child_proof_graph_root_sha256 =
                signed_profile_bundle_child_proof_graph_root(&child_evidence_hashes);
            let rollback_chain_digest_sha256 = signed_profile_bundle_rollback_chain_digest(
                &self.previous_config_digest,
                &self.rollback_command_template,
                capacity_certificate.fallback_profile,
                &capacity_certificate_digest_sha256,
                &child_proof_graph_root_sha256,
            );
            SignedProfileBundleSignature {
                signing_domain: policy.signing_domain.clone(),
                key_id: policy.key_id.clone(),
                public_key: policy.public_key.clone(),
                algorithm: policy.algorithm.clone(),
                issued_at_unix_seconds: policy.issued_at_unix_seconds,
                expires_at_unix_seconds: policy.expires_at_unix_seconds,
                bundle_epoch: policy.bundle_epoch,
                capacity_certificate_digest_sha256,
                child_proof_graph_root_sha256,
                rollback_chain_digest_sha256,
                signature_base64: String::new(),
            }
        });

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
            signed_mode_required: self
                .signature_policy
                .as_ref()
                .is_some_and(|policy| policy.signed_mode_required),
            verification_time_unix_seconds: self
                .signature_policy
                .as_ref()
                .map(|policy| policy.verification_time_unix_seconds),
            minimum_bundle_epoch: self
                .signature_policy
                .as_ref()
                .map(|policy| policy.minimum_bundle_epoch),
            trusted_signing_keys: self
                .signature_policy
                .as_ref()
                .map_or_else(Vec::new, |policy| policy.trusted_keys.clone()),
            signature,
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
        if let (Some(policy), Some(signature)) =
            (self.signature_policy.as_ref(), manifest.signature.as_mut())
        {
            if let Some(seed) = policy.signing_seed.as_deref() {
                if let Ok(key_pair) = KeyPair::from_seed(seed) {
                    let payload = signed_profile_bundle_signature_payload(
                        &manifest.manifest_digest_sha256,
                        signature,
                    );
                    if let Ok(signature_bytes) = key_pair.sign(&payload) {
                        signature.signature_base64 = STANDARD_NO_PAD.encode(signature_bytes);
                    }
                }
            }
        }
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
    /// Whether signed mode is mandatory and digest-only must fail closed.
    pub signed_mode_required: bool,
    /// Verification time used for deterministic signed-mode checks.
    pub verification_time_unix_seconds: Option<i64>,
    /// Lowest accepted bundle epoch for replay protection.
    pub minimum_bundle_epoch: Option<u64>,
    /// Trusted signing keys for signed-mode verification.
    pub trusted_signing_keys: Vec<SignedProfileBundleTrustedSigningKey>,
    /// Optional signed-mode metadata and signature.
    pub signature: Option<SignedProfileBundleSignature>,
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
                "signed_mode_required",
                format_bool(self.signed_mode_required),
            ),
            (
                "verification_time_unix_seconds",
                self.verification_time_unix_seconds
                    .map_or_else(|| "none".to_string(), |value| value.to_string()),
            ),
            (
                "minimum_bundle_epoch",
                self.minimum_bundle_epoch
                    .map_or_else(|| "none".to_string(), |value| value.to_string()),
            ),
            (
                "trusted_signing_keys",
                self.trusted_signing_keys
                    .iter()
                    .map(|key| {
                        format!(
                            "{}|{}|{}",
                            key.key_id,
                            key.public_key,
                            format_bool(key.revoked)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";"),
            ),
            (
                "signature_metadata",
                self.signature
                    .as_ref()
                    .map_or_else(String::new, SignedProfileBundleSignature::digest_material),
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
        match self.integrity_mode {
            SignedProfileBundleIntegrityMode::DigestOnlySha256 => {
                if self.integrity_limitations.is_empty() {
                    refusal_reasons.push(
                        "integrity_limitations must describe the explicit limitation of digest-only mode"
                            .to_string(),
                    );
                }
                if self.signed_mode_required {
                    refusal_reasons.push(
                        "signed mode is required; digest-only bundle is a downgrade".to_string(),
                    );
                }
            }
            SignedProfileBundleIntegrityMode::NkeyEd25519 => {
                if self
                    .integrity_limitations
                    .iter()
                    .any(|limitation| limitation.contains("digest-only"))
                {
                    refusal_reasons.push(
                        "signed mode must not hide behind digest-only limitation text".to_string(),
                    );
                }
            }
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
        if self.integrity_mode == SignedProfileBundleIntegrityMode::NkeyEd25519 {
            refusal_reasons.extend(self.verify_nkey_signature());
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

    fn verify_nkey_signature(&self) -> Vec<String> {
        let mut refusal_reasons = Vec::new();
        let Some(signature) = self.signature.as_ref() else {
            return vec!["nkey_ed25519 integrity requires a signature block".to_string()];
        };
        if signature.signing_domain != SIGNED_PROFILE_BUNDLE_SIGNATURE_DOMAIN {
            refusal_reasons.push(format!(
                "signing domain {} did not match required {}",
                signature.signing_domain, SIGNED_PROFILE_BUNDLE_SIGNATURE_DOMAIN
            ));
        }
        if signature.algorithm != SIGNED_PROFILE_BUNDLE_SIGNATURE_ALGORITHM {
            refusal_reasons.push(format!(
                "signature algorithm {} is unsupported; expected {}",
                signature.algorithm, SIGNED_PROFILE_BUNDLE_SIGNATURE_ALGORITHM
            ));
        }
        if signature.key_id.trim().is_empty() {
            refusal_reasons.push("signature key_id must not be empty".to_string());
        }
        if signature.public_key.trim().is_empty() {
            refusal_reasons.push("signature public_key must not be empty".to_string());
        }
        match self.verification_time_unix_seconds {
            Some(verification_time) => {
                if signature.issued_at_unix_seconds > verification_time {
                    refusal_reasons.push(format!(
                        "signature issued_at {} is after verification time {}",
                        signature.issued_at_unix_seconds, verification_time
                    ));
                }
                if verification_time >= signature.expires_at_unix_seconds {
                    refusal_reasons.push(format!(
                        "signature expired at {} before verification time {}",
                        signature.expires_at_unix_seconds, verification_time
                    ));
                }
            }
            None => refusal_reasons
                .push("verification_time_unix_seconds is required for signed mode".to_string()),
        }
        if signature.issued_at_unix_seconds >= signature.expires_at_unix_seconds {
            refusal_reasons.push("signature issued_at must be before expires_at".to_string());
        }
        match self.minimum_bundle_epoch {
            Some(minimum_epoch) if signature.bundle_epoch < minimum_epoch => {
                refusal_reasons.push(format!(
                    "bundle epoch {} is below minimum accepted epoch {}",
                    signature.bundle_epoch, minimum_epoch
                ));
            }
            Some(_) => {}
            None => {
                refusal_reasons
                    .push("minimum_bundle_epoch is required for signed mode".to_string());
            }
        }
        if signature.signature_base64.trim().is_empty() {
            refusal_reasons.push("signature_base64 must not be empty".to_string());
        }
        match self
            .trusted_signing_keys
            .iter()
            .find(|key| key.key_id == signature.key_id)
        {
            Some(key) if key.public_key != signature.public_key => {
                refusal_reasons.push(format!(
                    "key_id {} was bound to public key {}, not {}",
                    signature.key_id, key.public_key, signature.public_key
                ));
            }
            Some(key) if key.revoked => {
                refusal_reasons.push(format!("signing key {} is revoked", signature.key_id));
            }
            Some(_) => {}
            None => refusal_reasons.push(format!(
                "signing key {} is not present in the trusted key set",
                signature.key_id
            )),
        }
        let expected_capacity_digest =
            signed_profile_bundle_capacity_certificate_digest(&self.capacity_certificate_reference);
        if signature.capacity_certificate_digest_sha256 != expected_capacity_digest {
            refusal_reasons.push(format!(
                "capacity certificate digest lock {} did not match recomputed {}",
                signature.capacity_certificate_digest_sha256, expected_capacity_digest
            ));
        }
        let expected_child_root =
            signed_profile_bundle_child_proof_graph_root(&self.child_evidence_hashes);
        if signature.child_proof_graph_root_sha256 != expected_child_root {
            refusal_reasons.push(format!(
                "child proof graph root {} did not match recomputed {}",
                signature.child_proof_graph_root_sha256, expected_child_root
            ));
        }
        let expected_rollback_chain = signed_profile_bundle_rollback_chain_digest(
            &self.previous_config_digest,
            &self.rollback_command_template,
            self.fallback_profile,
            &expected_capacity_digest,
            &expected_child_root,
        );
        if signature.rollback_chain_digest_sha256 != expected_rollback_chain {
            refusal_reasons.push(format!(
                "rollback chain digest {} did not match recomputed {}",
                signature.rollback_chain_digest_sha256, expected_rollback_chain
            ));
        }
        let signature_bytes = match STANDARD_NO_PAD.decode(&signature.signature_base64) {
            Ok(bytes) => bytes,
            Err(err) => {
                refusal_reasons.push(format!("signature_base64 did not decode: {err}"));
                Vec::new()
            }
        };
        match KeyPair::from_public_key(&signature.public_key) {
            Ok(key_pair) if !signature_bytes.is_empty() => {
                let payload = signed_profile_bundle_signature_payload(
                    &self.manifest_digest_sha256,
                    signature,
                );
                if let Err(err) = key_pair.verify(&payload, &signature_bytes) {
                    refusal_reasons.push(format!("signature verification failed: {err}"));
                }
            }
            Ok(_) => {}
            Err(err) => refusal_reasons.push(format!("signature public_key is invalid: {err}")),
        }
        refusal_reasons
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
    /// Stable operator-facing shadow-run decision identifier.
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

/// Schema version for shadow promotion and rollback receipts.
pub const SHADOW_PROMOTE_ROLLBACK_RECEIPT_SCHEMA_VERSION: &str =
    "shadow-promote-rollback-receipt-v1";

/// Final decision emitted by the shadow promotion gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowPromoteRollbackDecision {
    /// Candidate beat the conservative baseline and can be promoted.
    Promote,
    /// Candidate is structurally valid but should remain in shadow hold.
    Hold,
    /// Candidate failed bundle verification and must be rolled back or rejected.
    Rollback,
    /// Evidence is insufficient or controllers conflict, so no safe winner exists.
    NoWin,
}

impl ShadowPromoteRollbackDecision {
    /// Stable report string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Hold => "hold",
            Self::Rollback => "rollback",
            Self::NoWin => "no_win",
        }
    }
}

impl fmt::Display for ShadowPromoteRollbackDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Request for a deterministic shadow promotion and rollback receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowPromoteRollbackReceiptRequest {
    /// Stable scenario or rollout identifier.
    pub scenario_id: String,
    /// Candidate signed-profile bundle, including its verifier, shadow evaluation, and rollback receipt.
    pub candidate_bundle: SignedProfileBundleBundle,
    /// Digest of the conservative baseline config under the same evidence snapshot.
    pub baseline_bundle_digest_sha256: String,
    /// Digest of the candidate config being considered for promotion.
    pub candidate_bundle_digest_sha256: String,
    /// Evidence hash consumed by the conservative baseline comparison.
    pub baseline_evidence_hash_sha256: String,
    /// Evidence hash consumed by the candidate comparison.
    pub candidate_evidence_hash_sha256: String,
    /// Capacity certificate artifact or identifier.
    pub capacity_certificate_id: String,
    /// Latency certificate artifact or identifier.
    pub latency_certificate_id: String,
    /// Candidate p99 latency minus conservative-baseline p99 latency.
    pub p99_delta_ns: i64,
    /// Candidate p999 latency minus conservative-baseline p999 latency.
    pub p999_delta_ns: i64,
    /// Evidence age for this shadow decision.
    pub evidence_age_hours: u64,
    /// Maximum accepted evidence age for promotion.
    pub max_evidence_age_hours: u64,
    /// Evidence sample count behind the paired comparison.
    pub sample_count: usize,
    /// Minimum sample count required before promotion.
    pub min_sample_count: usize,
    /// Combined-controller interference verdict, when available.
    pub controller_interference_verdict: Option<ControllerInterferenceTwinVerdict>,
    /// Dirty or unexplained artifacts observed during signoff.
    pub dirty_artifacts: Vec<String>,
    /// Path where operator tooling writes the receipt.
    pub receipt_path: String,
    /// Command that replays this exact decision.
    pub replay_command: String,
}

impl ShadowPromoteRollbackReceiptRequest {
    /// Evaluate the candidate bundle against the conservative baseline and emit a receipt.
    #[must_use]
    pub fn evaluate(&self) -> ShadowPromoteRollbackReceipt {
        let mut refusal_reasons = self.structural_refusal_reasons();
        let shadow_run_decision = self
            .candidate_bundle
            .shadow_run_evaluation
            .as_ref()
            .map(|shadow| shadow.decision);
        let regret_margin_basis_points = self
            .candidate_bundle
            .shadow_run_evaluation
            .as_ref()
            .map_or(0, |shadow| shadow.regret_margin_basis_points);
        let mut shadow_hold_reasons = self
            .candidate_bundle
            .shadow_run_evaluation
            .as_ref()
            .map_or_else(Vec::new, |shadow| shadow.hold_reasons.clone());
        dedup_preserving_order(&mut shadow_hold_reasons);

        if !self.candidate_bundle.verification.accepted {
            refusal_reasons.extend(
                self.candidate_bundle
                    .verification
                    .refusal_reasons
                    .iter()
                    .map(|reason| format!("bundle verification rejected candidate: {reason}")),
            );
        }
        if shadow_run_decision.is_none() {
            refusal_reasons
                .push("shadow_run_evaluation must be present before promotion".to_string());
        }
        if shadow_run_decision == Some(SignedProfileBundleShadowRunDecision::Hold) {
            refusal_reasons.push("shadow-run gate held the candidate".to_string());
        }
        if self.p99_delta_ns > 0 {
            refusal_reasons.push(format!(
                "candidate p99 regressed by {}ns against the conservative baseline",
                self.p99_delta_ns
            ));
        }
        if self.p999_delta_ns > 0 {
            refusal_reasons.push(format!(
                "candidate p999 regressed by {}ns against the conservative baseline",
                self.p999_delta_ns
            ));
        }
        if self.evidence_age_hours > self.max_evidence_age_hours {
            refusal_reasons.push(format!(
                "evidence age {}h exceeded promotion budget {}h",
                self.evidence_age_hours, self.max_evidence_age_hours
            ));
        }
        if self.sample_count < self.min_sample_count {
            refusal_reasons.push(format!(
                "sample count {} was below promotion floor {}",
                self.sample_count, self.min_sample_count
            ));
        }
        if self.baseline_evidence_hash_sha256 != self.candidate_evidence_hash_sha256 {
            refusal_reasons.push(
                "candidate and baseline must use the same evidence snapshot hash".to_string(),
            );
        }
        if self.controller_interference_verdict != Some(ControllerInterferenceTwinVerdict::Pass) {
            let verdict = self
                .controller_interference_verdict
                .map_or("missing".to_string(), |verdict| {
                    verdict.as_str().to_string()
                });
            refusal_reasons.push(format!(
                "controller interference verdict {verdict} does not allow promotion"
            ));
        }
        let dirty_artifacts = sorted_unique_strings(self.dirty_artifacts.clone());
        if !dirty_artifacts.is_empty() {
            refusal_reasons.push(format!(
                "unexplained dirty artifacts blocked promotion: {}",
                dirty_artifacts.join(",")
            ));
        }
        dedup_preserving_order(&mut refusal_reasons);

        let no_win_reason_present = refusal_reasons.iter().any(|reason| {
            !(reason.contains("shadow-run gate held")
                || reason.contains("candidate p99 regressed")
                || reason.contains("candidate p999 regressed"))
        });
        let decision = if !self.candidate_bundle.verification.accepted {
            ShadowPromoteRollbackDecision::Rollback
        } else if no_win_reason_present {
            ShadowPromoteRollbackDecision::NoWin
        } else if shadow_run_decision == Some(SignedProfileBundleShadowRunDecision::Hold)
            || self.p99_delta_ns > 0
            || self.p999_delta_ns > 0
        {
            ShadowPromoteRollbackDecision::Hold
        } else {
            ShadowPromoteRollbackDecision::Promote
        };
        let accepted = decision == ShadowPromoteRollbackDecision::Promote;
        let fallback_decision = match decision {
            ShadowPromoteRollbackDecision::Promote => "promote_candidate_bundle",
            ShadowPromoteRollbackDecision::Hold => "hold_conservative_baseline",
            ShadowPromoteRollbackDecision::Rollback => "rollback_candidate_bundle",
            ShadowPromoteRollbackDecision::NoWin => "no_win_preserve_conservative_baseline",
        }
        .to_string();

        let mut receipt = ShadowPromoteRollbackReceipt {
            schema_version: SHADOW_PROMOTE_ROLLBACK_RECEIPT_SCHEMA_VERSION.to_string(),
            scenario_id: self.scenario_id.clone(),
            decision,
            accepted,
            no_win: matches!(decision, ShadowPromoteRollbackDecision::NoWin),
            fallback_decision,
            baseline_bundle_digest_sha256: self.baseline_bundle_digest_sha256.clone(),
            candidate_bundle_digest_sha256: self.candidate_bundle_digest_sha256.clone(),
            candidate_manifest_digest_sha256: self
                .candidate_bundle
                .manifest
                .manifest_digest_sha256
                .clone(),
            baseline_evidence_hash_sha256: self.baseline_evidence_hash_sha256.clone(),
            candidate_evidence_hash_sha256: self.candidate_evidence_hash_sha256.clone(),
            capacity_certificate_id: self.capacity_certificate_id.clone(),
            latency_certificate_id: self.latency_certificate_id.clone(),
            shadow_run_decision,
            regret_margin_basis_points,
            p99_delta_ns: self.p99_delta_ns,
            p999_delta_ns: self.p999_delta_ns,
            shadow_hold_reasons,
            refusal_reasons,
            rollback_receipt_digest_sha256: self
                .candidate_bundle
                .rollback_receipt
                .receipt_digest_sha256
                .clone(),
            rollback_receipt_path: self.receipt_path.clone(),
            dirty_artifacts,
            replay_command: self.replay_command.clone(),
            promotion_receipt_digest_sha256: String::new(),
        };
        receipt.promotion_receipt_digest_sha256 = receipt.compute_digest();
        receipt
    }

    fn structural_refusal_reasons(&self) -> Vec<String> {
        let mut refusal_reasons = Vec::new();
        if let Err(reason) = validate_slug_like(&self.scenario_id, "scenario_id") {
            refusal_reasons.push(reason);
        }
        for (label, digest) in [
            (
                "baseline_bundle_digest_sha256",
                &self.baseline_bundle_digest_sha256,
            ),
            (
                "candidate_bundle_digest_sha256",
                &self.candidate_bundle_digest_sha256,
            ),
            (
                "baseline_evidence_hash_sha256",
                &self.baseline_evidence_hash_sha256,
            ),
            (
                "candidate_evidence_hash_sha256",
                &self.candidate_evidence_hash_sha256,
            ),
        ] {
            if !is_hex_digest(digest) {
                refusal_reasons.push(format!("{label} must be a 64-character hexadecimal digest"));
            }
        }
        if self.candidate_bundle_digest_sha256 != self.candidate_bundle.manifest.final_bundle_digest
        {
            refusal_reasons.push(
                "candidate_bundle_digest_sha256 must match the signed bundle final_bundle_digest"
                    .to_string(),
            );
        }
        if let Err(reason) =
            validate_artifact_json_path(&self.capacity_certificate_id, "capacity_certificate_id")
        {
            refusal_reasons.push(reason);
        }
        if let Err(reason) =
            validate_artifact_json_path(&self.latency_certificate_id, "latency_certificate_id")
        {
            refusal_reasons.push(reason);
        }
        if let Err(reason) = validate_artifact_json_path(&self.receipt_path, "receipt_path") {
            refusal_reasons.push(reason);
        }
        if self.replay_command.trim().is_empty() {
            refusal_reasons.push("replay_command must not be empty".to_string());
        }
        for artifact in &self.dirty_artifacts {
            if let Err(reason) = validate_artifact_json_path(artifact, "dirty_artifacts") {
                refusal_reasons.push(reason);
            }
        }
        refusal_reasons
    }
}

/// Deterministic receipt emitted before shadow promotion can recommend a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowPromoteRollbackReceipt {
    /// Receipt schema version.
    pub schema_version: String,
    /// Scenario or rollout identifier.
    pub scenario_id: String,
    /// Final promotion gate decision.
    pub decision: ShadowPromoteRollbackDecision,
    /// Whether the candidate can be promoted.
    pub accepted: bool,
    /// Whether the gate found no safe winner.
    pub no_win: bool,
    /// Deterministic fallback or promotion action.
    pub fallback_decision: String,
    /// Conservative-baseline config digest.
    pub baseline_bundle_digest_sha256: String,
    /// Candidate config digest.
    pub candidate_bundle_digest_sha256: String,
    /// Candidate signed manifest digest.
    pub candidate_manifest_digest_sha256: String,
    /// Conservative-baseline evidence snapshot digest.
    pub baseline_evidence_hash_sha256: String,
    /// Candidate evidence snapshot digest.
    pub candidate_evidence_hash_sha256: String,
    /// Capacity certificate artifact or identifier.
    pub capacity_certificate_id: String,
    /// Latency certificate artifact or identifier.
    pub latency_certificate_id: String,
    /// Underlying signed-bundle shadow decision.
    pub shadow_run_decision: Option<SignedProfileBundleShadowRunDecision>,
    /// Baseline loss minus candidate loss in basis points.
    pub regret_margin_basis_points: i64,
    /// Candidate p99 latency minus baseline p99 latency.
    pub p99_delta_ns: i64,
    /// Candidate p999 latency minus baseline p999 latency.
    pub p999_delta_ns: i64,
    /// Hold reasons from the signed-bundle shadow run.
    pub shadow_hold_reasons: Vec<String>,
    /// Reasons promotion was refused.
    pub refusal_reasons: Vec<String>,
    /// Digest of the rollback receipt chained to the candidate bundle.
    pub rollback_receipt_digest_sha256: String,
    /// Artifact path for the rollback receipt.
    pub rollback_receipt_path: String,
    /// Dirty or unexplained artifacts observed during signoff.
    pub dirty_artifacts: Vec<String>,
    /// Command that replays the receipt.
    pub replay_command: String,
    /// Digest over the promotion receipt contents.
    pub promotion_receipt_digest_sha256: String,
}

impl ShadowPromoteRollbackReceipt {
    fn compute_digest(&self) -> String {
        stable_sha256_hex(&[
            ("schema_version", self.schema_version.clone()),
            ("scenario_id", self.scenario_id.clone()),
            ("decision", self.decision.as_str().to_string()),
            ("accepted", format_bool(self.accepted)),
            ("no_win", format_bool(self.no_win)),
            ("fallback_decision", self.fallback_decision.clone()),
            (
                "baseline_bundle_digest_sha256",
                self.baseline_bundle_digest_sha256.clone(),
            ),
            (
                "candidate_bundle_digest_sha256",
                self.candidate_bundle_digest_sha256.clone(),
            ),
            (
                "candidate_manifest_digest_sha256",
                self.candidate_manifest_digest_sha256.clone(),
            ),
            (
                "baseline_evidence_hash_sha256",
                self.baseline_evidence_hash_sha256.clone(),
            ),
            (
                "candidate_evidence_hash_sha256",
                self.candidate_evidence_hash_sha256.clone(),
            ),
            (
                "capacity_certificate_id",
                self.capacity_certificate_id.clone(),
            ),
            (
                "latency_certificate_id",
                self.latency_certificate_id.clone(),
            ),
            (
                "shadow_run_decision",
                self.shadow_run_decision.map_or_else(
                    || "none".to_string(),
                    |decision| decision.as_str().to_string(),
                ),
            ),
            (
                "regret_margin_basis_points",
                self.regret_margin_basis_points.to_string(),
            ),
            ("p99_delta_ns", self.p99_delta_ns.to_string()),
            ("p999_delta_ns", self.p999_delta_ns.to_string()),
            ("shadow_hold_reasons", self.shadow_hold_reasons.join("|")),
            ("refusal_reasons", self.refusal_reasons.join("|")),
            (
                "rollback_receipt_digest_sha256",
                self.rollback_receipt_digest_sha256.clone(),
            ),
            ("rollback_receipt_path", self.rollback_receipt_path.clone()),
            ("dirty_artifacts", self.dirty_artifacts.join("|")),
            ("replay_command", self.replay_command.clone()),
        ])
    }
}

/// Schema version for controller provenance dashboards.
pub const CONTROLLER_PROVENANCE_DASHBOARD_SCHEMA_VERSION: &str =
    "controller-provenance-dashboard-v1";

/// Final verdict for a controller provenance dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerProvenanceDashboardVerdict {
    /// Every required child decision has inspectable provenance.
    Pass,
    /// At least one child decision is explicitly unsupported or no-win.
    NoWin,
    /// A child decision is missing, stale, proxy-only, or structurally invalid.
    FailClosed,
}

impl ControllerProvenanceDashboardVerdict {
    /// Stable report string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::NoWin => "no_win",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl fmt::Display for ControllerProvenanceDashboardVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Evidence class represented by a controller provenance row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerProvenanceEvidenceKind {
    /// Direct source evidence from a child controller artifact.
    SourceEvidence,
    /// Capacity or topology certificate evidence.
    CapacityCertificate,
    /// Latency or tail-risk certificate evidence.
    LatencyCertificate,
    /// Signed profile bundle signature and digest evidence.
    BundleSignature,
    /// Shadow promotion or rollback receipt evidence.
    ShadowReceipt,
    /// Digital-twin or interference report evidence.
    InterferenceReport,
    /// Explicit unsupported or no-win evidence row.
    UnsupportedNoWin,
}

impl ControllerProvenanceEvidenceKind {
    /// Stable report string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceEvidence => "source_evidence",
            Self::CapacityCertificate => "capacity_certificate",
            Self::LatencyCertificate => "latency_certificate",
            Self::BundleSignature => "bundle_signature",
            Self::ShadowReceipt => "shadow_receipt",
            Self::InterferenceReport => "interference_report",
            Self::UnsupportedNoWin => "unsupported_no_win",
        }
    }
}

impl fmt::Display for ControllerProvenanceEvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exact command class used to reproduce a provenance row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerProvenanceCommandClass {
    /// Rch-backed cargo test command.
    RchCargoTest,
    /// Repo smoke runner script.
    SmokeRunner,
    /// Replay command emitted by a child artifact.
    ReplayCommand,
}

impl ControllerProvenanceCommandClass {
    /// Stable report string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RchCargoTest => "rch_cargo_test",
            Self::SmokeRunner => "smoke_runner",
            Self::ReplayCommand => "replay_command",
        }
    }
}

impl fmt::Display for ControllerProvenanceCommandClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One inspectable controller provenance dashboard row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerProvenanceDashboardRow {
    /// Stable decision identifier.
    pub decision_id: String,
    /// Bead that owns the source decision.
    pub owner_bead: String,
    /// Controller or proof surface name.
    pub controller: String,
    /// Contract version emitted by the child surface.
    pub contract_version: String,
    /// Kind of evidence represented by this row.
    pub evidence_kind: ControllerProvenanceEvidenceKind,
    /// Primary child artifact path.
    pub source_artifact_path: String,
    /// Expected SHA-256 digest for the child artifact.
    pub expected_artifact_sha256: String,
    /// Observed SHA-256 digest for the child artifact.
    pub observed_artifact_sha256: String,
    /// Certificate artifact paths this decision depends on.
    pub certificate_artifact_ids: Vec<String>,
    /// Optional signed-bundle signature digest.
    pub bundle_signature_digest_sha256: Option<String>,
    /// Command class used by the replay command.
    pub command_class: ControllerProvenanceCommandClass,
    /// Exact command that reproduces or verifies this decision.
    pub replay_command: String,
    /// Explicit fallback or no-win reason when the row is not a pass row.
    pub fallback_reason: Option<String>,
    /// Whether this decision recorded a no-win outcome.
    pub no_win: bool,
    /// Whether this decision is explicitly unsupported by the current surface.
    pub unsupported: bool,
    /// Whether this row only proxies another green status without source evidence.
    pub proxy_only: bool,
}

impl ControllerProvenanceDashboardRow {
    fn normalized(mut self) -> Self {
        self.certificate_artifact_ids.sort();
        self.certificate_artifact_ids.dedup();
        self
    }

    fn validate(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if let Err(reason) = validate_slug_like(&self.decision_id, "decision_id") {
            reasons.push(reason);
        }
        if let Err(reason) = validate_slug_like(&self.owner_bead, "owner_bead") {
            reasons.push(reason);
        }
        if let Err(reason) = validate_slug_like(&self.controller, "controller") {
            reasons.push(reason);
        }
        if self.contract_version.trim().is_empty() {
            reasons.push(format!(
                "decision {} contract_version must not be empty",
                self.decision_id
            ));
        }
        if let Err(reason) =
            validate_artifact_json_path(&self.source_artifact_path, "source_artifact_path")
        {
            reasons.push(format!("decision {} {reason}", self.decision_id));
        }
        if !is_hex_digest(&self.expected_artifact_sha256) {
            reasons.push(format!(
                "decision {} expected_artifact_sha256 must be a 64-character hexadecimal digest",
                self.decision_id
            ));
        }
        if !is_hex_digest(&self.observed_artifact_sha256) {
            reasons.push(format!(
                "decision {} observed_artifact_sha256 must be a 64-character hexadecimal digest",
                self.decision_id
            ));
        }
        if self.expected_artifact_sha256 != self.observed_artifact_sha256 {
            reasons.push(format!(
                "decision {} artifact checksum mismatch for {}",
                self.decision_id, self.source_artifact_path
            ));
        }
        for artifact_id in &self.certificate_artifact_ids {
            if let Err(reason) = validate_artifact_json_path(artifact_id, "certificate_artifact_id")
            {
                reasons.push(format!("decision {} {reason}", self.decision_id));
            }
        }
        if let Some(reason) = duplicate_string(&self.certificate_artifact_ids) {
            reasons.push(format!(
                "decision {} certificate_artifact_ids contains a duplicate entry {reason}",
                self.decision_id
            ));
        }
        if self.evidence_kind == ControllerProvenanceEvidenceKind::BundleSignature
            && self
                .bundle_signature_digest_sha256
                .as_deref()
                .is_none_or(|digest| !is_hex_digest(digest))
        {
            reasons.push(format!(
                "decision {} bundle_signature_digest_sha256 must be present and valid",
                self.decision_id
            ));
        }
        if self.proxy_only {
            reasons.push(format!(
                "decision {} is proxy-only and lacks source evidence",
                self.decision_id
            ));
        }
        if self.replay_command.trim().is_empty() {
            reasons.push(format!(
                "decision {} replay_command must not be empty",
                self.decision_id
            ));
        } else if let Some(reason) =
            validate_controller_provenance_command(self.command_class, &self.replay_command)
        {
            reasons.push(format!("decision {} {reason}", self.decision_id));
        }
        if self.unsupported && !self.no_win {
            reasons.push(format!(
                "decision {} unsupported rows must also be no-win rows",
                self.decision_id
            ));
        }
        if (self.unsupported || self.no_win)
            && self
                .fallback_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            reasons.push(format!(
                "decision {} unsupported/no-win rows require an explicit fallback_reason",
                self.decision_id
            ));
        }
        reasons
    }

    fn render(&self) -> String {
        [
            self.decision_id.clone(),
            self.owner_bead.clone(),
            self.controller.clone(),
            self.contract_version.clone(),
            self.evidence_kind.as_str().to_string(),
            self.source_artifact_path.clone(),
            self.expected_artifact_sha256.clone(),
            self.observed_artifact_sha256.clone(),
            self.certificate_artifact_ids.join(","),
            self.bundle_signature_digest_sha256
                .clone()
                .unwrap_or_else(|| "none".to_string()),
            self.command_class.as_str().to_string(),
            self.replay_command.clone(),
            self.fallback_reason
                .clone()
                .unwrap_or_else(|| "none".to_string()),
            format_bool(self.no_win),
            format_bool(self.unsupported),
            format_bool(self.proxy_only),
        ]
        .join("|")
    }
}

/// Request used to build a controller provenance dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerProvenanceDashboardRequest {
    /// Stable scenario or signoff identifier.
    pub scenario_id: String,
    /// Owner beads that must have at least one provenance row.
    pub required_owner_beads: Vec<String>,
    /// Candidate rows gathered from child controller artifacts.
    pub rows: Vec<ControllerProvenanceDashboardRow>,
    /// Command that regenerates the dashboard.
    pub replay_command: String,
}

impl ControllerProvenanceDashboardRequest {
    /// Build a deterministic machine-readable and markdown dashboard.
    #[must_use]
    pub fn evaluate(&self) -> ControllerProvenanceDashboardReport {
        let mut required_owner_beads = sorted_unique_strings(self.required_owner_beads.clone());
        let mut rows = self
            .rows
            .clone()
            .into_iter()
            .map(ControllerProvenanceDashboardRow::normalized)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.decision_id
                .cmp(&right.decision_id)
                .then_with(|| left.owner_bead.cmp(&right.owner_bead))
                .then_with(|| left.controller.cmp(&right.controller))
                .then_with(|| left.source_artifact_path.cmp(&right.source_artifact_path))
        });

        let mut failure_reasons = self.structural_failures(&required_owner_beads, &rows);
        failure_reasons.sort();
        failure_reasons.dedup();

        let unsupported_rows = rows
            .iter()
            .filter(|row| row.unsupported || row.no_win)
            .map(|row| row.decision_id.clone())
            .collect::<Vec<_>>();
        let verdict = if failure_reasons.is_empty() {
            if unsupported_rows.is_empty() {
                ControllerProvenanceDashboardVerdict::Pass
            } else {
                ControllerProvenanceDashboardVerdict::NoWin
            }
        } else {
            ControllerProvenanceDashboardVerdict::FailClosed
        };
        let accepted = verdict == ControllerProvenanceDashboardVerdict::Pass;
        let fallback_decision = match verdict {
            ControllerProvenanceDashboardVerdict::Pass => "accept_controller_signoff_dashboard",
            ControllerProvenanceDashboardVerdict::NoWin => "hold_for_explicit_no_win_rows",
            ControllerProvenanceDashboardVerdict::FailClosed => {
                "fail_closed_reject_proxy_dashboard"
            }
        }
        .to_string();
        let owner_beads = sorted_unique_strings(
            rows.iter()
                .map(|row| row.owner_bead.clone())
                .collect::<Vec<_>>(),
        );
        let dashboard_digest_sha256 = controller_provenance_dashboard_digest(
            &self.scenario_id,
            &required_owner_beads,
            &rows,
            &failure_reasons,
            &self.replay_command,
        );
        let markdown = render_controller_provenance_dashboard_markdown(
            &self.scenario_id,
            verdict,
            &rows,
            &failure_reasons,
        );
        ControllerProvenanceDashboardReport {
            schema_version: CONTROLLER_PROVENANCE_DASHBOARD_SCHEMA_VERSION.to_string(),
            scenario_id: self.scenario_id.clone(),
            verdict,
            accepted,
            no_win: verdict == ControllerProvenanceDashboardVerdict::NoWin,
            fallback_decision,
            required_owner_beads: std::mem::take(&mut required_owner_beads),
            owner_beads,
            row_count: rows.len(),
            rows,
            unsupported_rows,
            failure_reasons,
            first_failure: None,
            dashboard_digest_sha256,
            markdown,
            replay_command: self.replay_command.clone(),
        }
        .with_first_failure()
    }

    fn structural_failures(
        &self,
        required_owner_beads: &[String],
        rows: &[ControllerProvenanceDashboardRow],
    ) -> Vec<String> {
        let mut reasons = Vec::new();
        if let Err(reason) = validate_slug_like(&self.scenario_id, "scenario_id") {
            reasons.push(reason);
        }
        if self.replay_command.trim().is_empty() {
            reasons.push("dashboard replay_command must not be empty".to_string());
        } else if !self
            .replay_command
            .contains("run_controller_provenance_dashboard_smoke.sh")
        {
            reasons.push(
                "dashboard replay_command must use run_controller_provenance_dashboard_smoke.sh"
                    .to_string(),
            );
        }
        if required_owner_beads.is_empty() {
            reasons.push("required_owner_beads must not be empty".to_string());
        }
        for owner in required_owner_beads {
            if let Err(reason) = validate_slug_like(owner, "required_owner_beads") {
                reasons.push(reason);
            }
            if !rows.iter().any(|row| row.owner_bead == *owner) {
                reasons.push(format!("required owner bead {owner} has no provenance row"));
            }
        }
        if rows.is_empty() {
            reasons.push("dashboard rows must not be empty".to_string());
        }
        for row in rows {
            reasons.extend(row.validate());
        }
        if let Some(duplicate) = duplicate_controller_provenance_decision(rows) {
            reasons.push(format!(
                "dashboard rows contain duplicate decision_id {duplicate}"
            ));
        }
        reasons
    }
}

/// Deterministic controller provenance dashboard report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerProvenanceDashboardReport {
    /// Report schema version.
    pub schema_version: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Final dashboard verdict.
    pub verdict: ControllerProvenanceDashboardVerdict,
    /// Whether all required rows were present and accepted.
    pub accepted: bool,
    /// Whether any row explicitly recorded a no-win outcome.
    pub no_win: bool,
    /// Deterministic fallback or acceptance action.
    pub fallback_decision: String,
    /// Required owner beads checked by the dashboard.
    pub required_owner_beads: Vec<String>,
    /// Owner beads present in the dashboard rows.
    pub owner_beads: Vec<String>,
    /// Number of sorted provenance rows.
    pub row_count: usize,
    /// Sorted provenance rows.
    pub rows: Vec<ControllerProvenanceDashboardRow>,
    /// Decision identifiers that explicitly reported unsupported or no-win.
    pub unsupported_rows: Vec<String>,
    /// Deterministically sorted validation failures.
    pub failure_reasons: Vec<String>,
    /// First validation failure, if any.
    pub first_failure: Option<String>,
    /// Digest over the stable dashboard contents.
    pub dashboard_digest_sha256: String,
    /// Markdown rendering with the same rows as the JSON report.
    pub markdown: String,
    /// Command that regenerates this dashboard.
    pub replay_command: String,
}

impl ControllerProvenanceDashboardReport {
    fn with_first_failure(mut self) -> Self {
        self.first_failure = self.failure_reasons.first().cloned();
        self
    }
}

fn validate_controller_provenance_command(
    command_class: ControllerProvenanceCommandClass,
    replay_command: &str,
) -> Option<String> {
    match command_class {
        ControllerProvenanceCommandClass::RchCargoTest => {
            if replay_command.contains("rch exec") && replay_command.contains("cargo test") {
                None
            } else {
                Some("rch_cargo_test command must contain `rch exec` and `cargo test`".to_string())
            }
        }
        ControllerProvenanceCommandClass::SmokeRunner => {
            if replay_command.starts_with("bash scripts/run_") && replay_command.contains(".sh") {
                None
            } else {
                Some("smoke_runner command must start with `bash scripts/run_`".to_string())
            }
        }
        ControllerProvenanceCommandClass::ReplayCommand => {
            if replay_command.contains("replay") || replay_command.contains("rch exec") {
                None
            } else {
                Some("replay_command must contain `replay` or `rch exec`".to_string())
            }
        }
    }
}

fn duplicate_controller_provenance_decision(
    rows: &[ControllerProvenanceDashboardRow],
) -> Option<String> {
    for (index, row) in rows.iter().enumerate() {
        if rows
            .iter()
            .skip(index + 1)
            .any(|other| other.decision_id == row.decision_id)
        {
            return Some(row.decision_id.clone());
        }
    }
    None
}

fn controller_provenance_dashboard_digest(
    scenario_id: &str,
    required_owner_beads: &[String],
    rows: &[ControllerProvenanceDashboardRow],
    failure_reasons: &[String],
    replay_command: &str,
) -> String {
    stable_sha256_hex(&[
        (
            "schema_version",
            CONTROLLER_PROVENANCE_DASHBOARD_SCHEMA_VERSION.to_string(),
        ),
        ("scenario_id", scenario_id.to_string()),
        ("required_owner_beads", required_owner_beads.join("|")),
        (
            "rows",
            rows.iter()
                .map(ControllerProvenanceDashboardRow::render)
                .collect::<Vec<_>>()
                .join(";"),
        ),
        ("failure_reasons", failure_reasons.join("|")),
        ("replay_command", replay_command.to_string()),
    ])
}

fn render_controller_provenance_dashboard_markdown(
    scenario_id: &str,
    verdict: ControllerProvenanceDashboardVerdict,
    rows: &[ControllerProvenanceDashboardRow],
    failure_reasons: &[String],
) -> String {
    let mut markdown = format!(
        "# Controller Provenance Dashboard: {scenario_id}\n\nVerdict: {verdict}\n\n| decision_id | owner_bead | controller | evidence_kind | artifact | command_class | status | fallback_reason |\n|---|---|---|---|---|---|---|---|\n"
    );
    for row in rows {
        let status = if row.unsupported {
            "unsupported"
        } else if row.no_win {
            "no_win"
        } else {
            "pass"
        };
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            row.decision_id,
            row.owner_bead,
            row.controller,
            row.evidence_kind,
            row.source_artifact_path,
            row.command_class,
            status,
            row.fallback_reason.as_deref().unwrap_or("none")
        ));
    }
    if !failure_reasons.is_empty() {
        markdown.push_str("\nFailures:\n");
        for reason in failure_reasons {
            markdown.push_str(&format!("- {reason}\n"));
        }
    }
    markdown
}

/// Schema version for controller-interference digital-twin signoff reports.
pub const CONTROLLER_INTERFERENCE_DIGITAL_TWIN_REPORT_SCHEMA_VERSION: &str =
    "controller-interference-digital-twin-report-v1";

/// Final signoff verdict for a combined-controller digital-twin replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerInterferenceTwinVerdict {
    /// The combined bundle had a clean deterministic replay.
    Pass,
    /// The replay found controller conflict and held on a conservative fallback.
    NoWin,
    /// The replay inputs were stale, incomplete, or structurally rejected.
    FailClosed,
}

impl ControllerInterferenceTwinVerdict {
    /// Stable report string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::NoWin => "no_win",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl fmt::Display for ControllerInterferenceTwinVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Interference class detected by the controller digital twin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerInterferenceFindingClass {
    /// Controller states moved back and forth instead of converging.
    Oscillation,
    /// A lower-priority shed path starved evidence or telemetry preservation.
    PriorityInversion,
    /// Pressure moved from one protected dimension into another hidden one.
    HiddenOverloadTransfer,
    /// One controller held no-win while another still attempted promotion.
    ConflictingNoWin,
    /// A controller reused stale, low-confidence, or unlisted evidence.
    StaleEvidenceReuse,
    /// Required controller state, version, evidence, or replay metadata was missing.
    MissingEvidence,
    /// The signed bundle gate rejected the candidate before interference replay.
    BundleRejected,
}

impl ControllerInterferenceFindingClass {
    /// Stable report string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oscillation => "oscillation",
            Self::PriorityInversion => "priority_inversion",
            Self::HiddenOverloadTransfer => "hidden_overload_transfer",
            Self::ConflictingNoWin => "conflicting_no_win",
            Self::StaleEvidenceReuse => "stale_evidence_reuse",
            Self::MissingEvidence => "missing_evidence",
            Self::BundleRejected => "bundle_rejected",
        }
    }
}

impl fmt::Display for ControllerInterferenceFindingClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Severity of a controller-interference finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerInterferenceFindingSeverity {
    /// Hold the combined policy and fall back conservatively.
    NoWin,
    /// Reject the combined policy before signoff.
    FailClosed,
}

impl ControllerInterferenceFindingSeverity {
    /// Stable report string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoWin => "no_win",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl fmt::Display for ControllerInterferenceFindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Thresholds used while replaying the combined-controller state vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerInterferenceTwinBudget {
    /// Maximum age accepted for child controller evidence.
    pub max_evidence_age_hours: u64,
    /// Minimum confidence accepted for child controller evidence.
    pub min_confidence_percent: u8,
    /// Minimum pressure delta treated as a meaningful controller movement.
    pub max_allowed_delta_basis_points: u16,
    /// Minimum telemetry preservation required during non-critical shedding.
    pub min_preserved_telemetry_basis_points: u16,
    /// Maximum hidden transfer from queue relief into memory or tail risk.
    pub max_overload_transfer_basis_points: u16,
    /// Agent-ceiling delta that turns a no-win hold into a conflict.
    pub conflicting_no_win_agent_delta: usize,
}

impl Default for ControllerInterferenceTwinBudget {
    fn default() -> Self {
        Self {
            max_evidence_age_hours: 24,
            min_confidence_percent: 80,
            max_allowed_delta_basis_points: 1_500,
            min_preserved_telemetry_basis_points: 8_500,
            max_overload_transfer_basis_points: 1_500,
            conflicting_no_win_agent_delta: 64,
        }
    }
}

/// One deterministic state vector emitted by a child controller in replay order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerInterferenceStateVector {
    /// Replay step index used for deterministic ordering.
    pub step_index: u32,
    /// Controller surface name.
    pub controller: String,
    /// Controller contract version.
    pub contract_version: String,
    /// Policy digest proposed by the controller at this step.
    pub policy_hash: String,
    /// Evidence digest consumed by the controller at this step.
    pub evidence_hash: String,
    /// Confidence score for the evidence consumed by this state.
    pub confidence_percent: u8,
    /// Age of the evidence consumed by this state.
    pub evidence_age_hours: u64,
    /// Queue pressure after this controller step.
    pub queue_pressure_basis_points: u16,
    /// Tail-risk pressure after this controller step.
    pub tail_risk_basis_points: u16,
    /// Memory pressure after this controller step.
    pub memory_pressure_basis_points: u16,
    /// Non-critical work shedding requested by this controller step.
    pub shed_noncritical_basis_points: u16,
    /// Telemetry/evidence preservation retained by this controller step.
    pub preserved_telemetry_basis_points: u16,
    /// Agent ceiling proposed by this controller step.
    pub target_agent_ceiling: usize,
    /// Host profile selected by this controller step.
    pub selected_profile: HostProfileId,
    /// Whether this controller emitted an explicit no-win decision.
    pub no_win: bool,
    /// Whether this controller step activated a conservative fallback.
    pub fallback_active: bool,
}

impl ControllerInterferenceStateVector {
    fn validate(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if let Err(reason) = validate_slug_like(&self.controller, "state_vector controller") {
            reasons.push(reason);
        }
        if self.contract_version.trim().is_empty() {
            reasons.push("state_vector contract_version must not be empty".to_string());
        }
        if let Err(reason) = validate_hashish(&self.policy_hash, "state_vector policy_hash") {
            reasons.push(reason);
        }
        if !is_hex_digest(&self.evidence_hash) {
            reasons.push(
                "state_vector evidence_hash must be a 64-character hexadecimal digest".to_string(),
            );
        }
        if self.confidence_percent > 100 {
            reasons.push("state_vector confidence_percent must be <= 100".to_string());
        }
        for (label, value) in [
            (
                "queue_pressure_basis_points",
                self.queue_pressure_basis_points,
            ),
            ("tail_risk_basis_points", self.tail_risk_basis_points),
            (
                "memory_pressure_basis_points",
                self.memory_pressure_basis_points,
            ),
            (
                "shed_noncritical_basis_points",
                self.shed_noncritical_basis_points,
            ),
            (
                "preserved_telemetry_basis_points",
                self.preserved_telemetry_basis_points,
            ),
        ] {
            if value > 10_000 {
                reasons.push(format!("state_vector {label} must be <= 10000"));
            }
        }
        if self.target_agent_ceiling == 0 {
            reasons.push("state_vector target_agent_ceiling must be non-zero".to_string());
        }
        reasons
    }

    fn render(&self) -> String {
        [
            self.step_index.to_string(),
            self.controller.clone(),
            self.contract_version.clone(),
            self.policy_hash.clone(),
            self.evidence_hash.clone(),
            self.confidence_percent.to_string(),
            self.evidence_age_hours.to_string(),
            self.queue_pressure_basis_points.to_string(),
            self.tail_risk_basis_points.to_string(),
            self.memory_pressure_basis_points.to_string(),
            self.shed_noncritical_basis_points.to_string(),
            self.preserved_telemetry_basis_points.to_string(),
            self.target_agent_ceiling.to_string(),
            self.selected_profile.as_str().to_string(),
            format_bool(self.no_win),
            format_bool(self.fallback_active),
        ]
        .join("|")
    }
}

/// One deterministic finding emitted by the digital twin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerInterferenceFinding {
    /// Interference class.
    pub class: ControllerInterferenceFindingClass,
    /// Finding severity.
    pub severity: ControllerInterferenceFindingSeverity,
    /// Controllers implicated by the finding.
    pub controllers: Vec<String>,
    /// Stable human-readable explanation.
    pub reason: String,
}

impl ControllerInterferenceFinding {
    fn no_win(
        class: ControllerInterferenceFindingClass,
        controllers: Vec<String>,
        reason: String,
    ) -> Self {
        Self {
            class,
            severity: ControllerInterferenceFindingSeverity::NoWin,
            controllers,
            reason,
        }
    }

    fn fail_closed(
        class: ControllerInterferenceFindingClass,
        controllers: Vec<String>,
        reason: String,
    ) -> Self {
        Self {
            class,
            severity: ControllerInterferenceFindingSeverity::FailClosed,
            controllers,
            reason,
        }
    }

    fn render(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.class,
            self.severity,
            self.controllers.join(","),
            self.reason
        )
    }
}

/// Digital-twin request for combined controller signoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerInterferenceDigitalTwinRequest {
    /// Stable smoke or rollout scenario identifier.
    pub scenario_id: String,
    /// Claimed child controller versions for the combined policy.
    pub controller_versions: Vec<SignedProfileBundleControllerVersion>,
    /// Input child evidence hashes consumed by the combined policy.
    pub input_evidence_hashes: Vec<SignedProfileBundleChildEvidenceHash>,
    /// Replay-ordered child controller state vectors.
    pub state_vectors: Vec<ControllerInterferenceStateVector>,
    /// Digest of the signed profile bundle manifest under review.
    pub bundle_manifest_digest_sha256: String,
    /// Whether the signed profile bundle verification gate accepted the candidate.
    pub bundle_verification_accepted: bool,
    /// Refusal reasons from the signed profile bundle verification gate.
    pub bundle_verification_refusal_reasons: Vec<String>,
    /// Whether signed mode was required for this combined policy.
    pub signed_mode_required: bool,
    /// Optional shadow-run decision from the signed bundle layer.
    pub shadow_run_decision: Option<SignedProfileBundleShadowRunDecision>,
    /// Optional shadow-run hold reasons from the signed bundle layer.
    pub shadow_run_hold_reasons: Vec<String>,
    /// Detection thresholds for this replay.
    pub budget: ControllerInterferenceTwinBudget,
    /// Command that replays this exact digital-twin proof.
    pub replay_command: String,
}

impl ControllerInterferenceDigitalTwinRequest {
    /// Evaluate the combined-controller replay and return a deterministic signoff report.
    #[must_use]
    pub fn evaluate(&self) -> ControllerInterferenceDigitalTwinReport {
        let mut controller_versions = self.controller_versions.clone();
        controller_versions.sort_by(|left, right| {
            left.controller
                .cmp(&right.controller)
                .then_with(|| left.contract_version.cmp(&right.contract_version))
        });
        let mut input_evidence_hashes = self.input_evidence_hashes.clone();
        input_evidence_hashes.sort_by(|left, right| {
            left.controller
                .cmp(&right.controller)
                .then_with(|| left.artifact_id.cmp(&right.artifact_id))
                .then_with(|| left.digest_sha256.cmp(&right.digest_sha256))
        });
        let mut state_vectors = self.state_vectors.clone();
        state_vectors.sort_by(|left, right| {
            left.step_index
                .cmp(&right.step_index)
                .then_with(|| left.controller.cmp(&right.controller))
                .then_with(|| left.contract_version.cmp(&right.contract_version))
                .then_with(|| left.policy_hash.cmp(&right.policy_hash))
                .then_with(|| left.evidence_hash.cmp(&right.evidence_hash))
        });

        let mut findings =
            self.structural_findings(&controller_versions, &input_evidence_hashes, &state_vectors);
        let structural_failure = findings
            .iter()
            .any(|finding| finding.severity == ControllerInterferenceFindingSeverity::FailClosed);

        if !structural_failure {
            findings.extend(self.interference_findings(&state_vectors));
        }
        findings.sort_by(|left, right| left.render().cmp(&right.render()));
        dedup_controller_interference_findings(&mut findings);

        let verdict = if findings
            .iter()
            .any(|finding| finding.severity == ControllerInterferenceFindingSeverity::FailClosed)
        {
            ControllerInterferenceTwinVerdict::FailClosed
        } else if findings.is_empty() {
            ControllerInterferenceTwinVerdict::Pass
        } else {
            ControllerInterferenceTwinVerdict::NoWin
        };
        let fallback_decision = match verdict {
            ControllerInterferenceTwinVerdict::Pass => "accept_combined_policy_bundle",
            ControllerInterferenceTwinVerdict::NoWin => "hold_conservative_baseline",
            ControllerInterferenceTwinVerdict::FailClosed => "fail_closed_reject_bundle",
        }
        .to_string();
        let state_vector_hash = controller_interference_state_vector_hash(&state_vectors);
        ControllerInterferenceDigitalTwinReport {
            schema_version: CONTROLLER_INTERFERENCE_DIGITAL_TWIN_REPORT_SCHEMA_VERSION.to_string(),
            scenario_id: self.scenario_id.clone(),
            verdict,
            accepted: verdict == ControllerInterferenceTwinVerdict::Pass,
            no_win: verdict != ControllerInterferenceTwinVerdict::Pass,
            fallback_decision,
            bundle_manifest_digest_sha256: self.bundle_manifest_digest_sha256.clone(),
            signed_mode_required: self.signed_mode_required,
            controller_versions,
            input_evidence_hashes,
            state_vectors,
            state_vector_hash,
            findings,
            replay_command: self.replay_command.clone(),
        }
    }

    fn structural_findings(
        &self,
        controller_versions: &[SignedProfileBundleControllerVersion],
        input_evidence_hashes: &[SignedProfileBundleChildEvidenceHash],
        state_vectors: &[ControllerInterferenceStateVector],
    ) -> Vec<ControllerInterferenceFinding> {
        let mut findings = Vec::new();
        if let Err(reason) = validate_slug_like(&self.scenario_id, "scenario_id") {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::MissingEvidence,
                Vec::new(),
                reason,
            ));
        }
        if self.replay_command.trim().is_empty() {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::MissingEvidence,
                Vec::new(),
                "replay_command must not be empty".to_string(),
            ));
        }
        if !is_hex_digest(&self.bundle_manifest_digest_sha256) {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::BundleRejected,
                Vec::new(),
                "bundle_manifest_digest_sha256 must be a 64-character hexadecimal digest"
                    .to_string(),
            ));
        }
        if !self.bundle_verification_accepted {
            let reason = if self.bundle_verification_refusal_reasons.is_empty() {
                "signed profile bundle verification rejected the candidate".to_string()
            } else {
                self.bundle_verification_refusal_reasons.join("; ")
            };
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::BundleRejected,
                Vec::new(),
                reason,
            ));
        }
        if controller_versions.is_empty() {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::MissingEvidence,
                Vec::new(),
                "controller_versions must not be empty".to_string(),
            ));
        }
        if input_evidence_hashes.is_empty() {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::MissingEvidence,
                Vec::new(),
                "input_evidence_hashes must not be empty".to_string(),
            ));
        }
        if state_vectors.is_empty() {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::MissingEvidence,
                Vec::new(),
                "state_vectors must not be empty".to_string(),
            ));
        }
        for (index, entry) in controller_versions.iter().enumerate() {
            if let Err(reason) = entry.validate(&format!("controller_versions[{index}]")) {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::MissingEvidence,
                    vec![entry.controller.clone()],
                    reason,
                ));
            }
        }
        if let Some(reason) =
            duplicate_controller_version(controller_versions, "controller_versions")
        {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::MissingEvidence,
                Vec::new(),
                reason,
            ));
        }
        for entry in input_evidence_hashes {
            if let Err(reason) = entry.validate() {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::MissingEvidence,
                    vec![entry.controller.clone()],
                    reason,
                ));
            }
            if !controller_versions
                .iter()
                .any(|version| version.controller == entry.controller)
            {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::MissingEvidence,
                    vec![entry.controller.clone()],
                    format!(
                        "input evidence hash for unclaimed controller {} is not listed in controller_versions",
                        entry.controller
                    ),
                ));
            }
        }
        if let Some(reason) = duplicate_child_evidence_controller(input_evidence_hashes) {
            findings.push(ControllerInterferenceFinding::fail_closed(
                ControllerInterferenceFindingClass::MissingEvidence,
                Vec::new(),
                reason.replace("child_evidence_hashes", "input_evidence_hashes"),
            ));
        }
        for state in state_vectors {
            for reason in state.validate() {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::MissingEvidence,
                    vec![state.controller.clone()],
                    reason,
                ));
            }
            if !controller_versions.iter().any(|version| {
                version.controller == state.controller
                    && version.contract_version == state.contract_version
            }) {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::MissingEvidence,
                    vec![state.controller.clone()],
                    format!(
                        "state vector for unclaimed controller {} version {} is not listed in controller_versions",
                        state.controller, state.contract_version
                    ),
                ));
            }
            if state.evidence_age_hours > self.budget.max_evidence_age_hours {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::StaleEvidenceReuse,
                    vec![state.controller.clone()],
                    format!(
                        "controller {} reused evidence aged {}h above budget {}h",
                        state.controller,
                        state.evidence_age_hours,
                        self.budget.max_evidence_age_hours
                    ),
                ));
            }
            if state.confidence_percent < self.budget.min_confidence_percent {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::StaleEvidenceReuse,
                    vec![state.controller.clone()],
                    format!(
                        "controller {} evidence confidence {}% was below budget {}%",
                        state.controller,
                        state.confidence_percent,
                        self.budget.min_confidence_percent
                    ),
                ));
            }
            if !input_evidence_hashes.iter().any(|hash| {
                let controller_matches = hash.controller == state.controller;
                let evidence_matches = hash.digest_sha256 == state.evidence_hash;
                controller_matches && evidence_matches
            }) {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::StaleEvidenceReuse,
                    vec![state.controller.clone()],
                    format!(
                        "controller {} state vector evidence hash was not listed in input_evidence_hashes",
                        state.controller
                    ),
                ));
            }
        }
        for entry in controller_versions {
            if !state_vectors.iter().any(|state| {
                state.controller == entry.controller
                    && state.contract_version == entry.contract_version
            }) {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::MissingEvidence,
                    vec![entry.controller.clone()],
                    format!(
                        "state vector for controller {} version {} is missing",
                        entry.controller, entry.contract_version
                    ),
                ));
            }
            if !input_evidence_hashes
                .iter()
                .any(|hash| hash.controller == entry.controller)
            {
                findings.push(ControllerInterferenceFinding::fail_closed(
                    ControllerInterferenceFindingClass::MissingEvidence,
                    vec![entry.controller.clone()],
                    format!(
                        "input evidence hash for controller {} is missing",
                        entry.controller
                    ),
                ));
            }
        }
        findings
    }

    fn interference_findings(
        &self,
        state_vectors: &[ControllerInterferenceStateVector],
    ) -> Vec<ControllerInterferenceFinding> {
        let mut findings = Vec::new();
        if let Some(finding) = self.detect_oscillation(state_vectors) {
            findings.push(finding);
        }
        findings.extend(self.detect_priority_inversion(state_vectors));
        findings.extend(self.detect_hidden_overload_transfer(state_vectors));
        if let Some(finding) = self.detect_conflicting_no_win(state_vectors) {
            findings.push(finding);
        }
        if self.shadow_run_decision == Some(SignedProfileBundleShadowRunDecision::Hold)
            && state_vectors
                .iter()
                .any(|state| !state.no_win && !state.fallback_active)
        {
            findings.push(ControllerInterferenceFinding::no_win(
                ControllerInterferenceFindingClass::ConflictingNoWin,
                state_vectors
                    .iter()
                    .filter(|state| !state.no_win && !state.fallback_active)
                    .map(|state| state.controller.clone())
                    .collect(),
                format!(
                    "shadow-run hold conflicted with promoting controller states: {}",
                    self.shadow_run_hold_reasons.join("; ")
                ),
            ));
        }
        findings
    }

    fn detect_oscillation(
        &self,
        state_vectors: &[ControllerInterferenceStateVector],
    ) -> Option<ControllerInterferenceFinding> {
        let mut direction = 0_i8;
        let mut direction_flips = 0_usize;
        let mut fallback_toggles = 0_usize;
        for pair in state_vectors.windows(2) {
            let previous = &pair[0];
            let current = &pair[1];
            let queue_delta = i32::from(current.queue_pressure_basis_points)
                - i32::from(previous.queue_pressure_basis_points);
            if queue_delta.unsigned_abs() >= u32::from(self.budget.max_allowed_delta_basis_points) {
                let next_direction = if queue_delta > 0 { 1 } else { -1 };
                if direction != 0 && next_direction != direction {
                    direction_flips += 1;
                }
                direction = next_direction;
            }
            if previous.fallback_active != current.fallback_active {
                fallback_toggles += 1;
            }
        }
        if direction_flips >= 2 || fallback_toggles >= 2 {
            return Some(ControllerInterferenceFinding::no_win(
                ControllerInterferenceFindingClass::Oscillation,
                state_vectors
                    .iter()
                    .map(|state| state.controller.clone())
                    .collect(),
                format!(
                    "controller replay did not converge: {direction_flips} queue direction flips and {fallback_toggles} fallback toggles"
                ),
            ));
        }
        None
    }

    fn detect_priority_inversion(
        &self,
        state_vectors: &[ControllerInterferenceStateVector],
    ) -> Vec<ControllerInterferenceFinding> {
        state_vectors
            .iter()
            .filter(|state| {
                state.preserved_telemetry_basis_points
                    < self.budget.min_preserved_telemetry_basis_points
                    && state.shed_noncritical_basis_points
                        >= self.budget.max_allowed_delta_basis_points
            })
            .map(|state| {
                ControllerInterferenceFinding::no_win(
                    ControllerInterferenceFindingClass::PriorityInversion,
                    vec![state.controller.clone()],
                    format!(
                        "controller {} shed {}bps while preserving only {}bps telemetry",
                        state.controller,
                        state.shed_noncritical_basis_points,
                        state.preserved_telemetry_basis_points
                    ),
                )
            })
            .collect()
    }

    fn detect_hidden_overload_transfer(
        &self,
        state_vectors: &[ControllerInterferenceStateVector],
    ) -> Vec<ControllerInterferenceFinding> {
        let mut findings = Vec::new();
        for pair in state_vectors.windows(2) {
            let previous = &pair[0];
            let current = &pair[1];
            let queue_drop = previous
                .queue_pressure_basis_points
                .saturating_sub(current.queue_pressure_basis_points);
            let memory_rise = current
                .memory_pressure_basis_points
                .saturating_sub(previous.memory_pressure_basis_points);
            let tail_rise = current
                .tail_risk_basis_points
                .saturating_sub(previous.tail_risk_basis_points);
            if queue_drop >= self.budget.max_allowed_delta_basis_points
                && (memory_rise >= self.budget.max_overload_transfer_basis_points
                    || tail_rise >= self.budget.max_overload_transfer_basis_points)
            {
                findings.push(ControllerInterferenceFinding::no_win(
                    ControllerInterferenceFindingClass::HiddenOverloadTransfer,
                    vec![previous.controller.clone(), current.controller.clone()],
                    format!(
                        "queue relief of {queue_drop}bps transferred into memory +{memory_rise}bps and tail +{tail_rise}bps"
                    ),
                ));
            }
        }
        findings
    }

    fn detect_conflicting_no_win(
        &self,
        state_vectors: &[ControllerInterferenceStateVector],
    ) -> Option<ControllerInterferenceFinding> {
        for hold in state_vectors.iter().filter(|state| state.no_win) {
            for promote in state_vectors.iter().filter(|state| !state.no_win) {
                let promoted_agent_ceiling = hold
                    .target_agent_ceiling
                    .saturating_add(self.budget.conflicting_no_win_agent_delta);
                if promote.target_agent_ceiling > promoted_agent_ceiling
                    || (!promote.fallback_active
                        && promote.selected_profile != HostProfileId::ConservativeBaseline)
                {
                    return Some(ControllerInterferenceFinding::no_win(
                        ControllerInterferenceFindingClass::ConflictingNoWin,
                        vec![hold.controller.clone(), promote.controller.clone()],
                        format!(
                            "controller {} held no-win at ceiling {}, but controller {} proposed {} with profile {}",
                            hold.controller,
                            hold.target_agent_ceiling,
                            promote.controller,
                            promote.target_agent_ceiling,
                            promote.selected_profile.as_str()
                        ),
                    ));
                }
            }
        }
        None
    }
}

/// Deterministic signoff report emitted by controller-interference digital twins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerInterferenceDigitalTwinReport {
    /// Report schema version.
    pub schema_version: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Final replay verdict.
    pub verdict: ControllerInterferenceTwinVerdict,
    /// Whether the combined controller bundle passed signoff.
    pub accepted: bool,
    /// Whether the combined controller bundle was held or rejected.
    pub no_win: bool,
    /// Deterministic fallback or acceptance decision.
    pub fallback_decision: String,
    /// Digest of the signed profile bundle manifest under review.
    pub bundle_manifest_digest_sha256: String,
    /// Whether signed mode was required for this combined policy.
    pub signed_mode_required: bool,
    /// Sorted controller-version rows used by the replay.
    pub controller_versions: Vec<SignedProfileBundleControllerVersion>,
    /// Sorted child evidence hashes used by the replay.
    pub input_evidence_hashes: Vec<SignedProfileBundleChildEvidenceHash>,
    /// Replay-ordered controller state vectors.
    pub state_vectors: Vec<ControllerInterferenceStateVector>,
    /// Digest of the replay-ordered state vectors.
    pub state_vector_hash: String,
    /// Deterministically sorted findings.
    pub findings: Vec<ControllerInterferenceFinding>,
    /// Command that replays this exact report.
    pub replay_command: String,
}

fn controller_interference_state_vector_hash(
    state_vectors: &[ControllerInterferenceStateVector],
) -> String {
    stable_sha256_hex(&[(
        "controller_interference_state_vectors",
        state_vectors
            .iter()
            .map(ControllerInterferenceStateVector::render)
            .collect::<Vec<_>>()
            .join(";"),
    )])
}

fn dedup_controller_interference_findings(findings: &mut Vec<ControllerInterferenceFinding>) {
    let mut deduped = Vec::with_capacity(findings.len());
    for finding in findings.drain(..) {
        if !deduped
            .iter()
            .any(|existing: &ControllerInterferenceFinding| existing == &finding)
        {
            deduped.push(finding);
        }
    }
    *findings = deduped;
}

fn sorted_unique_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
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
    if let Some(evidence) = &evidence.coordination_workload_expansion {
        let digest_sha256 = stable_sha256_hex(&[
            ("controller", "coordination_workload".to_string()),
            ("artifact_id", evidence.artifact_id.clone()),
            ("contract_version", evidence.contract_version.clone()),
            ("pack_hash", evidence.pack_hash.clone()),
            ("source_bundle_hash", evidence.source_bundle_hash.clone()),
            ("validation_passed", format_bool(evidence.validation_passed)),
            ("redaction_status", evidence.redaction_status.to_string()),
            ("trust_status", evidence.trust_status.to_string()),
            ("sample_count", evidence.sample_count.to_string()),
            (
                "artifact_age_hours",
                evidence.artifact_age_hours.to_string(),
            ),
            (
                "pressure_basis_points",
                evidence.pressure_basis_points.to_string(),
            ),
        ]);
        hashes.push(SignedProfileBundleChildEvidenceHash {
            controller: "coordination_workload".to_string(),
            artifact_id: evidence.artifact_id.clone(),
            digest_sha256,
        });
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
    let regret_margin_basis_points = signed_profile_bundle_shadow_run_regret_margin_basis_points(
        baseline_loss_basis_points,
        candidate_loss_basis_points,
    );
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

fn signed_profile_bundle_shadow_run_regret_margin_basis_points(
    baseline_loss_basis_points: u64,
    candidate_loss_basis_points: u64,
) -> i64 {
    if baseline_loss_basis_points >= candidate_loss_basis_points {
        loss_basis_points_delta_to_i64(
            baseline_loss_basis_points.saturating_sub(candidate_loss_basis_points),
        )
    } else {
        loss_basis_points_delta_to_i64(
            candidate_loss_basis_points.saturating_sub(baseline_loss_basis_points),
        )
        .saturating_neg()
    }
}

fn loss_basis_points_delta_to_i64(delta: u64) -> i64 {
    i64::try_from(delta).unwrap_or(i64::MAX)
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
        "signature.signature_base64" => {
            if let Some(signature) = manifest.signature.as_mut() {
                signature.signature_base64.push_str("tampered");
            }
        }
        "signature.capacity_certificate_digest_sha256" => {
            if let Some(signature) = manifest.signature.as_mut() {
                signature.capacity_certificate_digest_sha256 =
                    tamper_hex_digest(&signature.capacity_certificate_digest_sha256);
            }
        }
        "signature.child_proof_graph_root_sha256" => {
            if let Some(signature) = manifest.signature.as_mut() {
                signature.child_proof_graph_root_sha256 =
                    tamper_hex_digest(&signature.child_proof_graph_root_sha256);
            }
        }
        "signature.rollback_chain_digest_sha256" => {
            if let Some(signature) = manifest.signature.as_mut() {
                signature.rollback_chain_digest_sha256 =
                    tamper_hex_digest(&signature.rollback_chain_digest_sha256);
            }
        }
        _ => {
            manifest.bundle_id.push_str("-tampered");
        }
    }
}

fn signed_profile_bundle_signature_payload(
    manifest_digest_sha256: &str,
    signature: &SignedProfileBundleSignature,
) -> Vec<u8> {
    [
        SIGNED_PROFILE_BUNDLE_SIGNATURE_DOMAIN.to_string(),
        signature.signing_domain.clone(),
        signature.key_id.clone(),
        signature.public_key.clone(),
        signature.algorithm.clone(),
        signature.issued_at_unix_seconds.to_string(),
        signature.expires_at_unix_seconds.to_string(),
        signature.bundle_epoch.to_string(),
        signature.capacity_certificate_digest_sha256.clone(),
        signature.child_proof_graph_root_sha256.clone(),
        signature.rollback_chain_digest_sha256.clone(),
        manifest_digest_sha256.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

fn signed_profile_bundle_capacity_certificate_digest(
    reference: &SignedProfileBundleCapacityCertificateReference,
) -> String {
    stable_sha256_hex(&[
        ("artifact_id", reference.artifact_id.clone()),
        ("contract_version", reference.contract_version.clone()),
        ("scenario_id", reference.scenario_id.clone()),
    ])
}

fn signed_profile_bundle_child_proof_graph_root(
    hashes: &[SignedProfileBundleChildEvidenceHash],
) -> String {
    stable_sha256_hex(&[(
        "child_proof_graph",
        hashes
            .iter()
            .map(|entry| {
                format!(
                    "{}|{}|{}",
                    entry.controller, entry.artifact_id, entry.digest_sha256
                )
            })
            .collect::<Vec<_>>()
            .join(";"),
    )])
}

fn signed_profile_bundle_rollback_chain_digest(
    previous_config_digest: &str,
    rollback_command_template: &str,
    fallback_profile: HostProfileId,
    capacity_certificate_digest_sha256: &str,
    child_proof_graph_root_sha256: &str,
) -> String {
    stable_sha256_hex(&[
        ("previous_config_digest", previous_config_digest.to_string()),
        (
            "rollback_command_template",
            rollback_command_template.to_string(),
        ),
        ("fallback_profile", fallback_profile.as_str().to_string()),
        (
            "capacity_certificate_digest_sha256",
            capacity_certificate_digest_sha256.to_string(),
        ),
        (
            "child_proof_graph_root_sha256",
            child_proof_graph_root_sha256.to_string(),
        ),
    ])
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
    if !has_json_artifact_extension(value) {
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

fn has_json_artifact_extension(value: &str) -> bool {
    Path::new(value)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

fn validate_hashish(value: &str, label: &str) -> Result<(), String> {
    if is_hex_digest(value) {
        return Ok(());
    }
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return Err(format!("{label} must be a sha256 digest"));
    };
    validate_slug_like(suffix, label)
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
    coordination_status: &CoordinationWorkloadExpansionStatus,
) -> Vec<String> {
    let mut assumptions = vec![
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
            "sample_count={} against minimum {} with calibration_status={}",
            evidence.sample_count, budget.min_sample_count, evidence.calibration_status
        ),
        format!(
            "p99 budget={}ns, cancellation budget={}, memory pressure budget={}bps, brownout budget={}bps",
            budget.target_p99_ns,
            budget.target_cancel_debt_units,
            budget.max_memory_pressure_basis_points,
            budget.max_brownout_risk_basis_points
        ),
    ];
    match coordination_status.verdict {
        CoordinationWorkloadExpansionVerdict::Absent => assumptions.push(
            "coordination workload expansion pack absent; baseline capacity evidence is not widened"
                .to_string(),
        ),
        CoordinationWorkloadExpansionVerdict::Used => assumptions.push(format!(
            "coordination workload expansion pack {} applied pressure={}bps agent_ceiling={} pack_hash={} source_bundle_hash={}",
            coordination_status
                .artifact_id
                .as_deref()
                .unwrap_or("unknown"),
            coordination_status.pressure_basis_points.unwrap_or(0),
            coordination_status.agent_ceiling.unwrap_or(0),
            coordination_status.pack_hash.as_deref().unwrap_or("unknown"),
            coordination_status
                .source_bundle_hash
                .as_deref()
                .unwrap_or("unknown")
        )),
        CoordinationWorkloadExpansionVerdict::Refused => assumptions.push(format!(
            "coordination workload expansion pack refused before capacity planning: {}",
            coordination_status.refusal_reasons.join("; ")
        )),
    }
    assumptions
}

fn evaluate_capacity_point(
    profile: HostProfileId,
    host_resources: &HostProfileHostResources,
    evidence: &CapacityEnvelopeEvidenceSnapshot,
    budget: CapacityEnvelopeBudget,
    worker_count: usize,
    agent_count: usize,
    coordination_agent_ceiling: Option<usize>,
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
    if let Some(agent_ceiling) = coordination_agent_ceiling
        && agent_count > agent_ceiling
    {
        refusal_reasons.push(format!(
            "coordination workload pressure capped safe agents at {agent_ceiling}"
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
    fn derived_policy_defaults_preserve_existing_variants() {
        init_test("derived_policy_defaults_preserve_existing_variants");
        crate::assert_with_log!(
            BlockingPoolAffinityProfile::default() == BlockingPoolAffinityProfile::Disabled,
            "blocking affinity default",
            BlockingPoolAffinityProfile::Disabled,
            BlockingPoolAffinityProfile::default()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::default() == ArenaTemperaturePolicy::Unified,
            "arena temperature default",
            ArenaTemperaturePolicy::Unified,
            ArenaTemperaturePolicy::default()
        );
        crate::assert_with_log!(
            ArenaLocalityPolicy::default() == ArenaLocalityPolicy::Disabled,
            "arena locality default",
            ArenaLocalityPolicy::Disabled,
            ArenaLocalityPolicy::default()
        );
        crate::test_complete!("derived_policy_defaults_preserve_existing_variants");
    }

    #[test]
    fn artifact_json_path_validation_accepts_case_insensitive_json_paths() {
        init_test("artifact_json_path_validation_accepts_case_insensitive_json_paths");
        for value in [
            "evidence/controller.json",
            "evidence/controller.JSON",
            "evidence/controller.JsOn",
        ] {
            let result = validate_artifact_json_path(value, "artifact_id");
            crate::assert_with_log!(
                result.is_ok(),
                "case-insensitive json artifact path",
                "Ok",
                format!("{value}: {result:?}")
            );
        }
        crate::test_complete!("artifact_json_path_validation_accepts_case_insensitive_json_paths");
    }

    #[test]
    fn artifact_json_path_validation_rejects_unsafe_or_non_json_paths() {
        init_test("artifact_json_path_validation_rejects_unsafe_or_non_json_paths");
        for value in [
            "",
            "evidence/controller.txt",
            "../evidence/controller.json",
            "evidence/controller space.json",
        ] {
            let result = validate_artifact_json_path(value, "artifact_id");
            crate::assert_with_log!(
                result.is_err(),
                "unsafe or non-json artifact path rejected",
                "Err",
                format!("{value}: {result:?}")
            );
        }
        crate::test_complete!("artifact_json_path_validation_rejects_unsafe_or_non_json_paths");
    }

    #[test]
    fn shadow_run_regret_margin_saturates_without_wrapping() {
        init_test("shadow_run_regret_margin_saturates_without_wrapping");
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(150, 100) == 50,
            "positive regret margin",
            50,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(150, 100)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 150) == -50,
            "negative regret margin",
            -50,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 150)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 100) == 0,
            "zero regret margin",
            0,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 100)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(u64::MAX, 0) == i64::MAX,
            "positive regret margin saturates",
            i64::MAX,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(u64::MAX, 0)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(0, u64::MAX) == -i64::MAX,
            "negative regret margin saturates",
            -i64::MAX,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(0, u64::MAX)
        );
        crate::test_complete!("shadow_run_regret_margin_saturates_without_wrapping");
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
            scheduler_placement_mode: SchedulerPlacementMode::default(),
            thread_stack_size: 0,
            thread_name_prefix: String::new(),
            global_queue_limit: 0,
            steal_batch_size: 0,
            adaptive_ready_batch: AdaptiveReadyBatchConfig {
                enabled: true,
                min_batch_size: 0,
                max_batch_size: 0,
                scale_up_ready_depth: 0,
                scale_up_in_flight: 0,
                scale_up_claim_failures: 0,
                cancel_debt_floor: 0,
                cooldown_steps: 0,
            },
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
            runtime_state_shape: RuntimeStateShape::Unified,
            security: SecurityConfig::default(),
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
            scheduler_placement_mode: SchedulerPlacementMode::LatencyFirst,
            thread_stack_size: 1024,
            thread_name_prefix: "custom".to_string(),
            global_queue_limit: 64,
            steal_batch_size: 8,
            adaptive_ready_batch: AdaptiveReadyBatchConfig {
                enabled: true,
                min_batch_size: 2,
                max_batch_size: 32,
                scale_up_ready_depth: 128,
                scale_up_in_flight: 4,
                scale_up_claim_failures: 3,
                cancel_debt_floor: 6,
                cooldown_steps: 2,
            },
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
            runtime_state_shape: RuntimeStateShape::Unified,
            security: SecurityConfig::default(),
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
        crate::assert_with_log!(
            config.scheduler_placement_mode == SchedulerPlacementMode::LatencyFirst,
            "scheduler_placement_mode",
            SchedulerPlacementMode::LatencyFirst,
            config.scheduler_placement_mode
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
    fn runtime_capacity_hints_huge_expected_tasks_saturate_without_wrapping() {
        init_test("runtime_capacity_hints_huge_expected_tasks_saturate_without_wrapping");

        let huge = RuntimeCapacityHints::from_expected_concurrent_tasks(usize::MAX);

        assert_eq!(
            huge,
            RuntimeCapacityHints::new(usize::MAX / 2, usize::MAX / 4, usize::MAX / 2),
            "saturating arithmetic should preserve a conservative monotonic envelope for huge task hints"
        );
        assert!(
            huge.task_capacity >= huge.obligation_capacity
                && huge.obligation_capacity >= huge.region_capacity,
            "huge hints should keep sibling table sizing monotonic after saturation"
        );
    }

    #[test]
    fn resolved_capacity_hints_without_explicit_override_preserve_baseline_defaults() {
        init_test("resolved_capacity_hints_without_explicit_override_preserve_baseline_defaults");

        let mut config = RuntimeConfig {
            worker_threads: RuntimeConfig::DEFAULT_WORKER_THREADS,
            capacity_hints: None,
            ..RuntimeConfig::default()
        };
        config.normalize();

        assert_eq!(
            config.resolved_capacity_hints(),
            RuntimeCapacityHints::default(),
            "missing explicit capacity hints should stay equivalent to the historical default baseline"
        );
    }

    #[test]
    fn arena_temperature_report_keeps_hot_metadata_out_of_cold_tier() {
        init_test("arena_temperature_report_keeps_hot_metadata_out_of_cold_tier");

        let capacity_hints = RuntimeCapacityHints::new(4096, 1024, 2048);
        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let config = RuntimeConfig {
            worker_threads: 64,
            capacity_hints: Some(capacity_hints),
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        };
        let report = config.arena_temperature_report_with_locality(false, Some(&locality), false);

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
        assert!(report.locality_profile_present);
        assert!(!report.locality_profile_stale);
        assert!(!report.locality_safe_fallback);
        assert!(!report.locality_no_win_trigger);
        assert_eq!(
            report.locality_selected_remote_touch_ratio_bps,
            locality.selected.remote_touch_ratio_bps()
        );
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

        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let config = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        };
        let report = config.arena_temperature_report_with_locality(false, Some(&locality), false);

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

        let capacity_hints = RuntimeCapacityHints::new(4096, 1024, 2048);
        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let tiered = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), false);
        let unified = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), false);

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
    fn arena_temperature_report_requires_ready_locality_profile() {
        init_test("arena_temperature_report_requires_ready_locality_profile");

        let report = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, None, false);

        assert_eq!(report.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::LocalityProfileMissing)
        );
        assert_eq!(report.cold_evidence_bytes, 0);
        assert!(!report.locality_profile_present);
    }

    #[test]
    fn arena_temperature_report_rejects_stale_locality_profile() {
        init_test("arena_temperature_report_rejects_stale_locality_profile");

        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let report = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), true);

        assert_eq!(report.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::StaleLocalityProfile)
        );
        assert!(report.locality_profile_stale);
    }

    #[test]
    fn arena_temperature_report_falls_back_when_locality_no_win_triggers() {
        init_test("arena_temperature_report_falls_back_when_locality_no_win_triggers");

        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 9000,
                accounting_epoch: 13,
            },
            Some(95),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024],
                region_arena_touches_by_cohort: vec![256, 256, 256, 256, 256, 256, 256, 256],
                obligation_arena_touches_by_cohort: vec![512, 512, 512, 512, 512, 512, 512, 512],
                task_record_pool_touches_by_cohort: vec![
                    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                ],
            },
        );

        let report = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), false);

        assert_eq!(report.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::LocalityProfileFallback)
        );
        assert!(report.locality_safe_fallback);
        assert!(report.locality_no_win_trigger);
    }

    #[test]
    fn arena_locality_policy_normalize_clamps_bounds() {
        init_test("arena_locality_policy_normalize_clamps_bounds");

        let mut policy = ArenaLocalityPolicy::CohortPinned {
            min_topology_confidence_percent: 0,
            remote_touch_budget_bps: 20_000,
            accounting_epoch: 0,
        };
        policy.normalize();

        assert_eq!(
            policy,
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 1,
                remote_touch_budget_bps: 10_000,
                accounting_epoch: 1,
            }
        );
    }

    #[test]
    fn arena_remote_touch_counters_reset_and_saturate() {
        init_test("arena_remote_touch_counters_reset_and_saturate");

        let mut counters = ArenaRemoteTouchCounters::new(7);
        counters.record_sample(u64::MAX, 5);
        counters.record_sample(3, u64::MAX);

        let saturated = counters.snapshot();
        assert_eq!(saturated.accounting_epoch, 7);
        assert_eq!(saturated.reset_count, 0);
        assert_eq!(saturated.local_touch_count, u64::MAX);
        assert_eq!(saturated.remote_touch_count, u64::MAX);

        counters.reset_for_next_epoch(8);
        let reset = counters.snapshot();
        assert_eq!(reset.accounting_epoch, 8);
        assert_eq!(reset.reset_count, 1);
        assert_eq!(reset.local_touch_count, 0);
        assert_eq!(reset.remote_touch_count, 0);
    }

    #[test]
    fn arena_locality_report_prefers_skewed_cohorts_and_tracks_pool_budget() {
        init_test("arena_locality_report_prefers_skewed_cohorts_and_tracks_pool_budget");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
            obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
            task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        };

        let report = config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &access_model,
        );

        assert_eq!(
            report.effective_policy,
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            }
        );
        assert_eq!(report.fallback_reason, None);
        assert_eq!(report.cohort_count, 8);
        assert_eq!(
            report.task_record_pool_capacity,
            TaskTable::recommended_pool_limit_for_capacity(report.task_capacity)
        );
        assert_eq!(report.placements.len(), 4);
        assert_eq!(
            report.placements[0].preferred_cohort, 0,
            "task arena should pin to the busiest cohort"
        );
        assert!(
            report.candidate.remote_touch_count < report.baseline.remote_touch_count,
            "skewed locality evidence should beat the conservative baseline"
        );
        assert!(
            report.selected.remote_touch_ratio_bps() <= 6500,
            "selected placement must respect the remote-touch budget"
        );
        assert!(report.ownership_preserved);
    }

    #[test]
    fn arena_locality_report_falls_back_when_confidence_is_too_low() {
        init_test("arena_locality_report_falls_back_when_confidence_is_too_low");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
            obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
            task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        };

        let report = config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 90,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 12,
            },
            Some(40),
            &access_model,
        );

        assert_eq!(report.effective_policy, ArenaLocalityPolicy::Disabled);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaLocalityFallbackReason::TopologyConfidenceBelowThreshold)
        );
        assert_eq!(
            report.selected.remote_touch_count,
            report.baseline.remote_touch_count
        );
        assert!(report.used_safe_fallback());
    }

    #[test]
    fn arena_locality_report_no_win_trigger_keeps_baseline() {
        init_test("arena_locality_report_no_win_trigger_keeps_baseline");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![1024; 8],
            region_arena_touches_by_cohort: vec![256; 8],
            obligation_arena_touches_by_cohort: vec![512; 8],
            task_record_pool_touches_by_cohort: vec![1024; 8],
        };

        let report = config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 9000,
                accounting_epoch: 13,
            },
            Some(95),
            &access_model,
        );

        assert_eq!(report.effective_policy, ArenaLocalityPolicy::Disabled);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaLocalityFallbackReason::NoRemoteTouchWin)
        );
        assert!(report.no_win_trigger);
        assert_eq!(report.selected, report.baseline);
    }

    #[test]
    fn arena_locality_report_disabled_mode_preserves_baseline_projection() {
        init_test("arena_locality_report_disabled_mode_preserves_baseline_projection");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
            obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
            task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        };

        let report =
            config.arena_locality_report(ArenaLocalityPolicy::Disabled, Some(99), &access_model);

        assert_eq!(report.effective_policy, ArenaLocalityPolicy::Disabled);
        assert_eq!(report.fallback_reason, None);
        assert_eq!(report.selected, report.baseline);
        assert!(!report.no_win_trigger);
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

#[cfg(test)]
#[path = "config_metamorphic.rs"]
mod config_metamorphic;
