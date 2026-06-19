//! Pure opt-in memory-residency recommendation policy.
//!
//! This module does not mutate runtime state, allocator state, live tasks, or
//! artifact-cache entries. It folds already-collected evidence into a stable
//! recommendation for the later integration layer.

use crate::runtime::cache::ArtifactMemoryPressureSnapshot;
use crate::runtime::config::{
    ArenaLocalityReport, ArenaTemperaturePolicy, RuntimeCapacityHints, TraceStorageProfile,
};
use crate::runtime::resource_monitor::{RuntimePressureSnapshot, RuntimePressureVerdict};
use serde::{Deserialize, Serialize};

/// Stable schema for opt-in memory-residency policies.
pub const MEMORY_RESIDENCY_POLICY_SCHEMA_VERSION: &str = "asupersync.memory-residency-policy.v1";

/// Stable schema for opt-in memory-residency decisions.
pub const MEMORY_RESIDENCY_DECISION_SCHEMA_VERSION: &str =
    "asupersync.memory-residency-decision.v1";

/// Stable schema for read-only memory-residency accounting snapshots.
pub const MEMORY_RESIDENCY_ACCOUNTING_SNAPSHOT_SCHEMA_VERSION: &str =
    "asupersync.memory-residency-accounting-snapshot.v1";

/// Additive debug-server endpoint for memory-residency accounting snapshots.
pub const MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT: &str = "/debug/memory-residency";

const ESTIMATED_TASK_RECORD_BYTES: u64 = 256;
const ESTIMATED_REGION_RECORD_BYTES: u64 = 192;
const ESTIMATED_OBLIGATION_RECORD_BYTES: u64 = 160;

/// Runtime behavior profile for memory-residency recommendations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyProfile {
    /// Default profile. It emits a no-effect fallback recommendation.
    #[default]
    Disabled,
    /// Experimental opt-in profile for deterministic policy evaluation.
    ExperimentalOptIn,
}

/// Selected recommendation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyTier {
    /// Keep the candidate evidence on the hot resident path.
    Hot,
    /// Keep the candidate evidence resident but demoted from the hot tier.
    Warm,
    /// Assign the candidate evidence to an explicit cold/spillable tier.
    Cold,
    /// Keep current runtime behavior and do not enable residency behavior.
    Fallback,
    /// Refuse the change because the evidence shows no safe win.
    NoWin,
}

impl MemoryResidencyTier {
    /// Stable snake_case label matching the serialized tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Fallback => "fallback",
            Self::NoWin => "no_win",
        }
    }
}

/// Live-task action boundary for a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyLiveTaskAction {
    /// Recommendation-only output. The engine never drops, cancels, or migrates tasks.
    RecommendOnly,
}

impl MemoryResidencyLiveTaskAction {
    /// Stable snake_case label matching the serialized live-task action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecommendOnly => "recommend_only",
        }
    }
}

/// Stable reason codes emitted in deterministic priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyReasonCode {
    /// The default policy profile is disabled.
    PolicyDisabled,
    /// The input was evaluated by the opt-in profile.
    PolicyEnabled,
    /// Fresh locality evidence was present and selected a non-fallback profile.
    FreshTopology,
    /// Required locality evidence was missing.
    MissingTopology,
    /// Locality evidence was older than the policy freshness window.
    StaleTopology,
    /// Locality evidence showed no remote-touch win.
    NoWinLocality,
    /// Locality evidence fell back to the conservative baseline.
    LocalityFallback,
    /// The requested large-page cold tier is unsupported, so cold tiering is downgraded.
    UnsupportedLargePages,
    /// The cold evidence budget cannot fit the requested retained evidence under pressure.
    ColdEvidenceBudgetExhausted,
    /// Proof-pack warmth evidence is stale, cold, or keyed to a different proof.
    ProofPackWarmthMismatch,
    /// Runtime or artifact-cache pressure is critical.
    CriticalMemoryPressure,
    /// Runtime pressure is degraded but not critical.
    RuntimePressureDegraded,
    /// Runtime pressure evidence is missing or unknown.
    RuntimePressureUnknown,
    /// Artifact-cache pressure is high enough to bias away from hot residency.
    ArtifactCachePressure,
    /// Unified arena-temperature policy keeps all evidence on the baseline path.
    UnifiedTemperaturePolicy,
}

impl MemoryResidencyReasonCode {
    /// Stable snake_case label matching the serialized reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyDisabled => "policy_disabled",
            Self::PolicyEnabled => "policy_enabled",
            Self::FreshTopology => "fresh_topology",
            Self::MissingTopology => "missing_topology",
            Self::StaleTopology => "stale_topology",
            Self::NoWinLocality => "no_win_locality",
            Self::LocalityFallback => "locality_fallback",
            Self::UnsupportedLargePages => "unsupported_large_pages",
            Self::ColdEvidenceBudgetExhausted => "cold_evidence_budget_exhausted",
            Self::ProofPackWarmthMismatch => "proof_pack_warmth_mismatch",
            Self::CriticalMemoryPressure => "critical_memory_pressure",
            Self::RuntimePressureDegraded => "runtime_pressure_degraded",
            Self::RuntimePressureUnknown => "runtime_pressure_unknown",
            Self::ArtifactCachePressure => "artifact_cache_pressure",
            Self::UnifiedTemperaturePolicy => "unified_temperature_policy",
        }
    }
}

/// Stable no-claim boundary emitted with every decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyNoClaimBoundary {
    /// The engine does not change runtime defaults or builder behavior.
    DefaultRuntimeBehaviorUnchanged,
    /// The engine does not replace the allocator or claim allocator universality.
    NoAllocatorReplacement,
    /// The engine never drops, cancels, migrates, or reschedules live tasks.
    NoLiveTaskMutation,
    /// The engine does not claim throughput, latency, p999, NUMA, or memory-use wins.
    NoPerformanceClaim,
    /// The engine does not prove release readiness or broad workspace health.
    NoReleaseReadinessClaim,
}

impl MemoryResidencyNoClaimBoundary {
    /// Stable snake_case label matching the serialized no-claim boundary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DefaultRuntimeBehaviorUnchanged => "default_runtime_behavior_unchanged",
            Self::NoAllocatorReplacement => "no_allocator_replacement",
            Self::NoLiveTaskMutation => "no_live_task_mutation",
            Self::NoPerformanceClaim => "no_performance_claim",
            Self::NoReleaseReadinessClaim => "no_release_readiness_claim",
        }
    }
}

/// Optional proof-pack cache-warmth evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofPackWarmthTelemetry {
    /// Whether the observed cache key matches the proof lane.
    pub cache_key_matches: bool,
    /// Whether the candidate worker reports a warm cache for that key.
    pub worker_warm: bool,
    /// Age of the telemetry sample.
    pub telemetry_age_secs: u64,
    /// Maximum age declared by the telemetry source.
    pub max_age_secs: u64,
}

impl ProofPackWarmthTelemetry {
    /// Creates a proof-pack warmth telemetry row.
    #[must_use]
    pub const fn new(
        cache_key_matches: bool,
        worker_warm: bool,
        telemetry_age_secs: u64,
        max_age_secs: u64,
    ) -> Self {
        Self {
            cache_key_matches,
            worker_warm,
            telemetry_age_secs,
            max_age_secs,
        }
    }

    fn is_usable(self, policy_max_age_secs: u64) -> bool {
        let effective_max_age = self.max_age_secs.min(policy_max_age_secs);
        self.cache_key_matches && self.worker_warm && self.telemetry_age_secs <= effective_max_age
    }
}

/// Pure memory-residency policy knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryResidencyPolicy {
    /// Enabled/disabled profile.
    pub profile: MemoryResidencyProfile,
    /// Maximum accepted age for locality evidence.
    pub max_topology_age_secs: u64,
    /// Runtime or artifact pressure at/above this threshold fails closed.
    pub critical_memory_pressure_bps: u16,
    /// Artifact pressure at/above this threshold demotes hot residency.
    pub cache_pressure_bps: u16,
    /// Maximum accepted age for proof-pack warmth evidence.
    pub max_proof_warmth_age_secs: u64,
}

impl Default for MemoryResidencyPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl MemoryResidencyPolicy {
    /// Disabled profile preserving default runtime behavior.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            profile: MemoryResidencyProfile::Disabled,
            max_topology_age_secs: 900,
            critical_memory_pressure_bps: 9_300,
            cache_pressure_bps: 8_500,
            max_proof_warmth_age_secs: 900,
        }
    }

    /// Experimental opt-in profile. Callers must still integrate decisions explicitly.
    #[must_use]
    pub const fn experimental_opt_in() -> Self {
        Self {
            profile: MemoryResidencyProfile::ExperimentalOptIn,
            max_topology_age_secs: 900,
            critical_memory_pressure_bps: 9_300,
            cache_pressure_bps: 8_500,
            max_proof_warmth_age_secs: 900,
        }
    }

    /// Evaluates a deterministic recommendation without mutating runtime state.
    #[must_use]
    pub fn decide(&self, input: &MemoryResidencyPolicyInput<'_>) -> MemoryResidencyDecision {
        let mut reason_codes = Vec::new();
        let trace_budget = input.trace_storage_profile.budget();
        let estimated_hot_trace_bytes = usize_to_u64(trace_budget.estimated_hot_bytes());
        let candidate_cold_evidence_bytes = usize_to_u64(trace_budget.estimated_cold_bytes());
        let estimated_hot_runtime_slots = input
            .capacity_hints
            .task_capacity
            .saturating_add(input.capacity_hints.region_capacity)
            .saturating_add(input.capacity_hints.obligation_capacity);
        let policy_enabled = matches!(self.profile, MemoryResidencyProfile::ExperimentalOptIn);

        if !policy_enabled {
            push_reason(&mut reason_codes, MemoryResidencyReasonCode::PolicyDisabled);
            return MemoryResidencyDecision::new(
                policy_enabled,
                MemoryResidencyTier::Fallback,
                reason_codes,
                input,
                estimated_hot_runtime_slots,
                estimated_hot_trace_bytes,
                candidate_cold_evidence_bytes,
            );
        }

        push_reason(&mut reason_codes, MemoryResidencyReasonCode::PolicyEnabled);

        let mut critical_pressure = false;
        let mut degraded_pressure = false;
        if let Some(snapshot) = input.runtime_pressure {
            match snapshot.overall_verdict {
                RuntimePressureVerdict::Critical => {
                    critical_pressure = true;
                    push_reason(
                        &mut reason_codes,
                        MemoryResidencyReasonCode::CriticalMemoryPressure,
                    );
                }
                RuntimePressureVerdict::Degraded => {
                    degraded_pressure = true;
                    push_reason(
                        &mut reason_codes,
                        MemoryResidencyReasonCode::RuntimePressureDegraded,
                    );
                }
                RuntimePressureVerdict::Unknown => {
                    push_reason(
                        &mut reason_codes,
                        MemoryResidencyReasonCode::RuntimePressureUnknown,
                    );
                }
                RuntimePressureVerdict::Healthy => {}
            }
        }

        let mut artifact_pressure_high = false;
        let mut cold_budget_exhausted = false;
        if let Some(cache) = input.artifact_cache_pressure {
            artifact_pressure_high =
                cache.high_pressure || cache.pressure_bps >= self.cache_pressure_bps;
            if artifact_pressure_high {
                push_reason(
                    &mut reason_codes,
                    MemoryResidencyReasonCode::ArtifactCachePressure,
                );
            }
            if cache.pressure_bps >= self.critical_memory_pressure_bps {
                critical_pressure = true;
                push_reason(
                    &mut reason_codes,
                    MemoryResidencyReasonCode::CriticalMemoryPressure,
                );
            }
            if input.requests_cold_evidence()
                && cache.high_pressure
                && candidate_cold_evidence_bytes > cache.spill_eligible_bytes
            {
                cold_budget_exhausted = true;
                push_reason(
                    &mut reason_codes,
                    MemoryResidencyReasonCode::ColdEvidenceBudgetExhausted,
                );
            }
        }

        let mut no_win = false;
        let mut locality_blocked = false;
        if input.requests_cold_evidence() {
            match input.locality_report {
                None => {
                    locality_blocked = true;
                    push_reason(
                        &mut reason_codes,
                        MemoryResidencyReasonCode::MissingTopology,
                    );
                }
                Some(report) => {
                    if input.locality_age_secs.unwrap_or(u64::MAX) > self.max_topology_age_secs {
                        locality_blocked = true;
                        push_reason(&mut reason_codes, MemoryResidencyReasonCode::StaleTopology);
                    } else if report.no_win_trigger {
                        no_win = true;
                        push_reason(&mut reason_codes, MemoryResidencyReasonCode::NoWinLocality);
                    } else if report.used_safe_fallback() {
                        locality_blocked = true;
                        push_reason(
                            &mut reason_codes,
                            MemoryResidencyReasonCode::LocalityFallback,
                        );
                    } else {
                        push_reason(&mut reason_codes, MemoryResidencyReasonCode::FreshTopology);
                    }
                }
            }
        } else {
            push_reason(
                &mut reason_codes,
                MemoryResidencyReasonCode::UnifiedTemperaturePolicy,
            );
        }

        let mut unsupported_large_pages = false;
        if matches!(
            input.arena_temperature_policy,
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages
        ) && !input.large_page_cold_slabs_supported
        {
            unsupported_large_pages = true;
            push_reason(
                &mut reason_codes,
                MemoryResidencyReasonCode::UnsupportedLargePages,
            );
        }

        let mut warmth_mismatch = false;
        if let Some(warmth) = input.proof_pack_warmth
            && !warmth.is_usable(self.max_proof_warmth_age_secs)
        {
            warmth_mismatch = true;
            push_reason(
                &mut reason_codes,
                MemoryResidencyReasonCode::ProofPackWarmthMismatch,
            );
        }

        let selected_tier = if critical_pressure || no_win {
            MemoryResidencyTier::NoWin
        } else if cold_budget_exhausted
            || locality_blocked
            || unsupported_large_pages
            || warmth_mismatch
            || degraded_pressure
        {
            MemoryResidencyTier::Fallback
        } else if artifact_pressure_high && input.requests_cold_evidence() {
            MemoryResidencyTier::Cold
        } else if input.requests_cold_evidence() {
            MemoryResidencyTier::Warm
        } else {
            MemoryResidencyTier::Hot
        };

        MemoryResidencyDecision::new(
            policy_enabled,
            selected_tier,
            reason_codes,
            input,
            estimated_hot_runtime_slots,
            estimated_hot_trace_bytes,
            candidate_cold_evidence_bytes,
        )
    }
}

/// Input evidence for a pure memory-residency recommendation.
#[derive(Debug, Clone, Copy)]
pub struct MemoryResidencyPolicyInput<'a> {
    /// Runtime table capacity hints.
    pub capacity_hints: RuntimeCapacityHints,
    /// Trace storage profile used for hot/cold evidence sizing.
    pub trace_storage_profile: TraceStorageProfile,
    /// Requested arena-temperature policy.
    pub arena_temperature_policy: ArenaTemperaturePolicy,
    /// Optional arena-locality report.
    pub locality_report: Option<&'a ArenaLocalityReport>,
    /// Age of the locality report.
    pub locality_age_secs: Option<u64>,
    /// Whether large-page cold slabs are available.
    pub large_page_cold_slabs_supported: bool,
    /// Optional runtime pressure snapshot from `ResourceMonitor`.
    pub runtime_pressure: Option<&'a RuntimePressureSnapshot>,
    /// Optional artifact-cache pressure snapshot.
    pub artifact_cache_pressure: Option<&'a ArtifactMemoryPressureSnapshot>,
    /// Optional proof-pack cache-warmth telemetry.
    pub proof_pack_warmth: Option<ProofPackWarmthTelemetry>,
}

impl<'a> MemoryResidencyPolicyInput<'a> {
    /// Creates a policy input from the required deterministic inputs.
    #[must_use]
    pub const fn new(
        capacity_hints: RuntimeCapacityHints,
        trace_storage_profile: TraceStorageProfile,
        arena_temperature_policy: ArenaTemperaturePolicy,
    ) -> Self {
        Self {
            capacity_hints,
            trace_storage_profile,
            arena_temperature_policy,
            locality_report: None,
            locality_age_secs: None,
            large_page_cold_slabs_supported: false,
            runtime_pressure: None,
            artifact_cache_pressure: None,
            proof_pack_warmth: None,
        }
    }

    /// Adds locality evidence.
    #[must_use]
    pub fn with_locality_report(mut self, report: &'a ArenaLocalityReport, age_secs: u64) -> Self {
        self.locality_report = Some(report);
        self.locality_age_secs = Some(age_secs);
        self
    }

    /// Adds large-page support evidence.
    #[must_use]
    pub const fn with_large_page_cold_slabs_supported(mut self, supported: bool) -> Self {
        self.large_page_cold_slabs_supported = supported;
        self
    }

    /// Adds runtime pressure evidence.
    #[must_use]
    pub const fn with_runtime_pressure(mut self, snapshot: &'a RuntimePressureSnapshot) -> Self {
        self.runtime_pressure = Some(snapshot);
        self
    }

    /// Adds artifact-cache pressure evidence.
    #[must_use]
    pub const fn with_artifact_cache_pressure(
        mut self,
        snapshot: &'a ArtifactMemoryPressureSnapshot,
    ) -> Self {
        self.artifact_cache_pressure = Some(snapshot);
        self
    }

    /// Adds proof-pack warmth evidence.
    #[must_use]
    pub const fn with_proof_pack_warmth(mut self, warmth: ProofPackWarmthTelemetry) -> Self {
        self.proof_pack_warmth = Some(warmth);
        self
    }

    fn requests_cold_evidence(self) -> bool {
        matches!(
            self.arena_temperature_policy,
            ArenaTemperaturePolicy::TieredColdEvidence
                | ArenaTemperaturePolicy::TieredColdEvidenceLargePages
        )
    }
}

/// Deterministic policy output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryResidencyDecision {
    /// Stable schema version.
    pub schema_version: String,
    /// Whether the policy was explicitly enabled.
    pub policy_enabled: bool,
    /// Selected recommendation tier.
    pub selected_tier: MemoryResidencyTier,
    /// Live-task action boundary.
    pub live_task_action: MemoryResidencyLiveTaskAction,
    /// Explicit no-claim boundaries that keep this recommendation scoped.
    pub no_claim_boundaries: Vec<MemoryResidencyNoClaimBoundary>,
    /// Stable reason codes in deterministic priority order.
    pub reason_codes: Vec<MemoryResidencyReasonCode>,
    /// Stable trace-storage profile label.
    pub trace_storage_profile: String,
    /// Stable arena-temperature policy label.
    pub arena_temperature_policy: String,
    /// Runtime task capacity from the input.
    pub task_capacity: usize,
    /// Runtime region capacity from the input.
    pub region_capacity: usize,
    /// Runtime obligation capacity from the input.
    pub obligation_capacity: usize,
    /// Sum of hot runtime table slots.
    pub estimated_hot_runtime_slots: usize,
    /// Estimated hot trace bytes from the existing trace-storage budget.
    pub estimated_hot_trace_bytes: u64,
    /// Candidate retained evidence bytes before recommendation.
    pub candidate_cold_evidence_bytes: u64,
    /// Retained evidence bytes recommended for warm residency.
    pub recommended_warm_evidence_bytes: u64,
    /// Retained evidence bytes recommended for cold residency.
    pub recommended_cold_evidence_bytes: u64,
    /// Retained evidence bytes kept on baseline fallback behavior.
    pub fallback_evidence_bytes: u64,
    /// Retained evidence bytes refused by a no-win decision.
    pub no_win_evidence_bytes: u64,
    /// Runtime pressure verdict, when supplied.
    pub runtime_pressure_verdict: Option<String>,
    /// Artifact-cache pressure, when supplied.
    pub artifact_cache_pressure_bps: Option<u16>,
    /// Locality accounting epoch, when supplied.
    pub locality_accounting_epoch: Option<u64>,
    /// Selected locality remote-touch ratio, when supplied.
    pub locality_remote_touch_ratio_bps: Option<u16>,
}

impl MemoryResidencyDecision {
    fn new(
        policy_enabled: bool,
        selected_tier: MemoryResidencyTier,
        reason_codes: Vec<MemoryResidencyReasonCode>,
        input: &MemoryResidencyPolicyInput<'_>,
        estimated_hot_runtime_slots: usize,
        estimated_hot_trace_bytes: u64,
        candidate_cold_evidence_bytes: u64,
    ) -> Self {
        let recommended_warm_evidence_bytes = if selected_tier == MemoryResidencyTier::Warm {
            candidate_cold_evidence_bytes
        } else {
            0
        };
        let recommended_cold_evidence_bytes = if selected_tier == MemoryResidencyTier::Cold {
            candidate_cold_evidence_bytes
        } else {
            0
        };
        let fallback_evidence_bytes = if selected_tier == MemoryResidencyTier::Fallback {
            candidate_cold_evidence_bytes
        } else {
            0
        };
        let no_win_evidence_bytes = if selected_tier == MemoryResidencyTier::NoWin {
            candidate_cold_evidence_bytes
        } else {
            0
        };

        Self {
            schema_version: MEMORY_RESIDENCY_DECISION_SCHEMA_VERSION.to_string(),
            policy_enabled,
            selected_tier,
            live_task_action: MemoryResidencyLiveTaskAction::RecommendOnly,
            no_claim_boundaries: vec![
                MemoryResidencyNoClaimBoundary::DefaultRuntimeBehaviorUnchanged,
                MemoryResidencyNoClaimBoundary::NoAllocatorReplacement,
                MemoryResidencyNoClaimBoundary::NoLiveTaskMutation,
                MemoryResidencyNoClaimBoundary::NoPerformanceClaim,
                MemoryResidencyNoClaimBoundary::NoReleaseReadinessClaim,
            ],
            reason_codes,
            trace_storage_profile: input.trace_storage_profile.as_str().to_string(),
            arena_temperature_policy: input.arena_temperature_policy.as_str().to_string(),
            task_capacity: input.capacity_hints.task_capacity,
            region_capacity: input.capacity_hints.region_capacity,
            obligation_capacity: input.capacity_hints.obligation_capacity,
            estimated_hot_runtime_slots,
            estimated_hot_trace_bytes,
            candidate_cold_evidence_bytes,
            recommended_warm_evidence_bytes,
            recommended_cold_evidence_bytes,
            fallback_evidence_bytes,
            no_win_evidence_bytes,
            runtime_pressure_verdict: input
                .runtime_pressure
                .map(|snapshot| format!("{:?}", snapshot.overall_verdict).to_ascii_lowercase()),
            artifact_cache_pressure_bps: input
                .artifact_cache_pressure
                .map(|snapshot| snapshot.pressure_bps),
            locality_accounting_epoch: input.locality_report.map(|report| report.accounting_epoch),
            locality_remote_touch_ratio_bps: input
                .locality_report
                .map(|report| report.selected.remote_touch_ratio_bps()),
        }
    }
}

/// Freshness verdict for a read-only accounting snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyAccountingStatus {
    /// The policy is disabled and no live residency accounting loop is active.
    Disabled,
    /// Required evidence is present and fresh for this point-in-time snapshot.
    Fresh,
    /// Evidence was present but stale.
    Stale,
    /// Required evidence or optional counters were unavailable.
    Unknown,
}

impl MemoryResidencyAccountingStatus {
    /// Stable snake_case label matching the serialized status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

/// Stable source labels for accounting rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyAccountingSource {
    /// Runtime record-table capacity estimates.
    RuntimeRecordTables,
    /// Trace-storage budget estimates.
    TraceStorageBudget,
    /// Artifact-cache pressure snapshot.
    ArtifactCachePressure,
    /// Conservative fallback accounting.
    FallbackBoundary,
    /// Explicit no-win refusal accounting.
    NoWinBoundary,
    /// Data was unavailable to this snapshot.
    Unavailable,
}

impl MemoryResidencyAccountingSource {
    /// Stable snake_case label matching the serialized source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeRecordTables => "runtime_record_tables",
            Self::TraceStorageBudget => "trace_storage_budget",
            Self::ArtifactCachePressure => "artifact_cache_pressure",
            Self::FallbackBoundary => "fallback_boundary",
            Self::NoWinBoundary => "no_win_boundary",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Stable aggregation kinds emitted by accounting snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryResidencyAggregationKind {
    /// Runtime-wide total row.
    RuntimeTotal,
    /// Task-record table row.
    TaskRecords,
    /// Region-record table row.
    RegionRecords,
    /// Obligation-record table row.
    ObligationRecords,
    /// Retained trace/evidence row.
    RetainedEvidence,
    /// Artifact-cache row.
    ArtifactCache,
}

impl MemoryResidencyAggregationKind {
    /// Stable snake_case label matching the serialized aggregation kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeTotal => "runtime_total",
            Self::TaskRecords => "task_records",
            Self::RegionRecords => "region_records",
            Self::ObligationRecords => "obligation_records",
            Self::RetainedEvidence => "retained_evidence",
            Self::ArtifactCache => "artifact_cache",
        }
    }
}

/// Optional record-pool counters supplied by an inspector integration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryResidencyRecordPoolCounters {
    /// Task-record pool hits.
    pub task_hits: u64,
    /// Task-record pool misses.
    pub task_misses: u64,
    /// Task-record pool recycled slots.
    pub task_recycles: u64,
    /// Region-record pool hits.
    pub region_hits: u64,
    /// Region-record pool misses.
    pub region_misses: u64,
    /// Region-record pool recycled slots.
    pub region_recycles: u64,
    /// Obligation-record pool hits.
    pub obligation_hits: u64,
    /// Obligation-record pool misses.
    pub obligation_misses: u64,
    /// Obligation-record pool recycled slots.
    pub obligation_recycles: u64,
}

impl MemoryResidencyRecordPoolCounters {
    /// Total hits across all supplied record pools.
    #[must_use]
    pub const fn total_hits(self) -> u64 {
        self.task_hits
            .saturating_add(self.region_hits)
            .saturating_add(self.obligation_hits)
    }

    /// Total misses across all supplied record pools.
    #[must_use]
    pub const fn total_misses(self) -> u64 {
        self.task_misses
            .saturating_add(self.region_misses)
            .saturating_add(self.obligation_misses)
    }

    /// Total recycled slots across all supplied record pools.
    #[must_use]
    pub const fn total_recycles(self) -> u64 {
        self.task_recycles
            .saturating_add(self.region_recycles)
            .saturating_add(self.obligation_recycles)
    }
}

/// Resolved runtime capacity and byte-accounting estimates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryResidencyCapacitySnapshot {
    /// Runtime task capacity.
    pub task_capacity: usize,
    /// Runtime region capacity.
    pub region_capacity: usize,
    /// Runtime obligation capacity.
    pub obligation_capacity: usize,
    /// Sum of hot runtime table slots.
    pub estimated_hot_runtime_slots: usize,
    /// Estimated hot task-record bytes.
    pub estimated_hot_task_record_bytes: u64,
    /// Estimated hot region-record bytes.
    pub estimated_hot_region_record_bytes: u64,
    /// Estimated hot obligation-record bytes.
    pub estimated_hot_obligation_record_bytes: u64,
    /// Estimated hot runtime-record bytes.
    pub estimated_hot_runtime_record_bytes: u64,
    /// Estimated hot trace bytes.
    pub estimated_hot_trace_bytes: u64,
    /// Candidate retained evidence bytes.
    pub candidate_cold_evidence_bytes: u64,
}

/// One stable hot/warm/cold/fallback/no-win accounting row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryResidencyTierAccountingRow {
    /// Tier represented by this row.
    pub tier: MemoryResidencyTier,
    /// Whether this tier is the selected recommendation for this snapshot.
    pub active: bool,
    /// Runtime record slots associated with the row.
    pub record_slots: usize,
    /// Estimated bytes associated with the row.
    pub estimated_bytes: u64,
    /// Retained evidence bytes associated with the row.
    pub evidence_bytes: u64,
    /// Source of the row.
    pub source: MemoryResidencyAccountingSource,
}

/// One stable aggregation row for inspector/debug payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryResidencyAggregationRow {
    /// Aggregation kind.
    pub kind: MemoryResidencyAggregationKind,
    /// Number of rows/items represented.
    pub row_count: u64,
    /// Estimated bytes represented.
    pub estimated_bytes: u64,
    /// Freshness/status for this row.
    pub status: MemoryResidencyAccountingStatus,
    /// Source of the row.
    pub source: MemoryResidencyAccountingSource,
}

/// Read-only point-in-time memory-residency accounting payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryResidencyAccountingSnapshot {
    /// Stable schema version.
    pub schema_version: String,
    /// Capture timestamp in nanoseconds from the caller's deterministic clock.
    pub generated_at_nanos: u64,
    /// Additive debug-server endpoint path.
    pub debug_server_endpoint: String,
    /// Whether this payload is suitable for runtime-inspector transport.
    pub runtime_inspector_compatible: bool,
    /// Whether this payload is a point-in-time observation.
    pub point_in_time: bool,
    /// Whether a continuous accounting loop was active while capturing.
    pub continuous_accounting_loop: bool,
    /// Whether the policy was explicitly enabled.
    pub policy_enabled: bool,
    /// Selected recommendation tier.
    pub selected_tier: MemoryResidencyTier,
    /// Live-task action boundary.
    pub live_task_action: MemoryResidencyLiveTaskAction,
    /// Freshness verdict for this snapshot.
    pub status: MemoryResidencyAccountingStatus,
    /// Whether record-pool counters were supplied by the inspector.
    pub record_pool_counters_available: bool,
    /// Resolved capacity and byte estimates.
    pub capacity: MemoryResidencyCapacitySnapshot,
    /// Optional record-pool counters. Zeroed when unavailable.
    pub record_pool_counters: MemoryResidencyRecordPoolCounters,
    /// Hot/warm/cold/fallback/no-win rows in stable tier order.
    pub tier_rows: Vec<MemoryResidencyTierAccountingRow>,
    /// Stable aggregation rows for runtime/debug consumers.
    pub aggregation_rows: Vec<MemoryResidencyAggregationRow>,
    /// Explicit no-claim boundaries inherited from the policy decision.
    pub no_claim_boundaries: Vec<MemoryResidencyNoClaimBoundary>,
    /// Stable reason codes inherited from the policy decision.
    pub reason_codes: Vec<MemoryResidencyReasonCode>,
}

impl MemoryResidencyAccountingSnapshot {
    /// Builds a snapshot from policy inputs and optional inspector counters.
    #[must_use]
    pub fn from_policy_input(
        policy: &MemoryResidencyPolicy,
        input: &MemoryResidencyPolicyInput<'_>,
        generated_at_nanos: u64,
        record_pool_counters: Option<MemoryResidencyRecordPoolCounters>,
    ) -> Self {
        let decision = policy.decide(input);
        Self::from_decision(&decision, input, generated_at_nanos, record_pool_counters)
    }

    /// Builds a snapshot from an already evaluated decision.
    #[must_use]
    pub fn from_decision(
        decision: &MemoryResidencyDecision,
        input: &MemoryResidencyPolicyInput<'_>,
        generated_at_nanos: u64,
        record_pool_counters: Option<MemoryResidencyRecordPoolCounters>,
    ) -> Self {
        let capacity = capacity_snapshot(decision);
        let counters_available = record_pool_counters.is_some();
        let counters = record_pool_counters.unwrap_or_default();
        let status = accounting_status(decision, counters_available);
        let tier_rows = tier_accounting_rows(decision, &capacity);
        let aggregation_rows =
            aggregation_rows(decision, input, &capacity, counters_available, status);

        Self {
            schema_version: MEMORY_RESIDENCY_ACCOUNTING_SNAPSHOT_SCHEMA_VERSION.to_string(),
            generated_at_nanos,
            debug_server_endpoint: MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT.to_string(),
            runtime_inspector_compatible: true,
            point_in_time: true,
            continuous_accounting_loop: false,
            policy_enabled: decision.policy_enabled,
            selected_tier: decision.selected_tier,
            live_task_action: decision.live_task_action,
            status,
            record_pool_counters_available: counters_available,
            capacity,
            record_pool_counters: counters,
            tier_rows,
            aggregation_rows,
            no_claim_boundaries: decision.no_claim_boundaries.clone(),
            reason_codes: decision.reason_codes.clone(),
        }
    }

    /// Default fail-closed payload used when debug-server callers do not install a provider.
    #[must_use]
    pub fn unavailable(generated_at_nanos: u64) -> Self {
        let capacity = MemoryResidencyCapacitySnapshot {
            task_capacity: 0,
            region_capacity: 0,
            obligation_capacity: 0,
            estimated_hot_runtime_slots: 0,
            estimated_hot_task_record_bytes: 0,
            estimated_hot_region_record_bytes: 0,
            estimated_hot_obligation_record_bytes: 0,
            estimated_hot_runtime_record_bytes: 0,
            estimated_hot_trace_bytes: 0,
            candidate_cold_evidence_bytes: 0,
        };

        Self {
            schema_version: MEMORY_RESIDENCY_ACCOUNTING_SNAPSHOT_SCHEMA_VERSION.to_string(),
            generated_at_nanos,
            debug_server_endpoint: MEMORY_RESIDENCY_ACCOUNTING_DEBUG_ENDPOINT.to_string(),
            runtime_inspector_compatible: true,
            point_in_time: true,
            continuous_accounting_loop: false,
            policy_enabled: false,
            selected_tier: MemoryResidencyTier::Fallback,
            live_task_action: MemoryResidencyLiveTaskAction::RecommendOnly,
            status: MemoryResidencyAccountingStatus::Unknown,
            record_pool_counters_available: false,
            capacity,
            record_pool_counters: MemoryResidencyRecordPoolCounters::default(),
            tier_rows: unavailable_tier_rows(),
            aggregation_rows: unavailable_aggregation_rows(),
            no_claim_boundaries: vec![
                MemoryResidencyNoClaimBoundary::DefaultRuntimeBehaviorUnchanged,
                MemoryResidencyNoClaimBoundary::NoAllocatorReplacement,
                MemoryResidencyNoClaimBoundary::NoLiveTaskMutation,
                MemoryResidencyNoClaimBoundary::NoPerformanceClaim,
                MemoryResidencyNoClaimBoundary::NoReleaseReadinessClaim,
            ],
            reason_codes: vec![
                MemoryResidencyReasonCode::PolicyDisabled,
                MemoryResidencyReasonCode::MissingTopology,
                MemoryResidencyReasonCode::RuntimePressureUnknown,
            ],
        }
    }

    /// Stable line-oriented rendering for deterministic goldens and operator logs.
    #[must_use]
    pub fn stable_report_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("schema_version={}", self.schema_version),
            format!("generated_at_nanos={}", self.generated_at_nanos),
            format!("debug_server_endpoint={}", self.debug_server_endpoint),
            format!(
                "runtime_inspector_compatible={}",
                self.runtime_inspector_compatible
            ),
            format!("point_in_time={}", self.point_in_time),
            format!(
                "continuous_accounting_loop={}",
                self.continuous_accounting_loop
            ),
            format!("policy_enabled={}", self.policy_enabled),
            format!("selected_tier={}", self.selected_tier.as_str()),
            format!("live_task_action={}", self.live_task_action.as_str()),
            format!("status={}", self.status.as_str()),
            format!(
                "record_pool_counters_available={}",
                self.record_pool_counters_available
            ),
            format!("task_capacity={}", self.capacity.task_capacity),
            format!("region_capacity={}", self.capacity.region_capacity),
            format!("obligation_capacity={}", self.capacity.obligation_capacity),
            format!(
                "estimated_hot_runtime_record_bytes={}",
                self.capacity.estimated_hot_runtime_record_bytes
            ),
            format!(
                "estimated_hot_trace_bytes={}",
                self.capacity.estimated_hot_trace_bytes
            ),
            format!(
                "candidate_cold_evidence_bytes={}",
                self.capacity.candidate_cold_evidence_bytes
            ),
            format!(
                "record_pool_total_hits={}",
                self.record_pool_counters.total_hits()
            ),
            format!(
                "record_pool_total_misses={}",
                self.record_pool_counters.total_misses()
            ),
            format!(
                "record_pool_total_recycles={}",
                self.record_pool_counters.total_recycles()
            ),
        ];
        lines.extend(self.tier_rows.iter().map(|row| {
            format!(
                "tier={} active={} record_slots={} estimated_bytes={} evidence_bytes={} source={}",
                row.tier.as_str(),
                row.active,
                row.record_slots,
                row.estimated_bytes,
                row.evidence_bytes,
                row.source.as_str()
            )
        }));
        lines.extend(self.aggregation_rows.iter().map(|row| {
            format!(
                "aggregation={} row_count={} estimated_bytes={} status={} source={}",
                row.kind.as_str(),
                row.row_count,
                row.estimated_bytes,
                row.status.as_str(),
                row.source.as_str()
            )
        }));
        lines.extend(
            self.no_claim_boundaries
                .iter()
                .map(|boundary| format!("no_claim={}", boundary.as_str())),
        );
        lines.extend(
            self.reason_codes
                .iter()
                .map(|reason| format!("reason={}", reason.as_str())),
        );
        lines
    }
}

fn accounting_status(
    decision: &MemoryResidencyDecision,
    record_pool_counters_available: bool,
) -> MemoryResidencyAccountingStatus {
    if !decision.policy_enabled {
        return MemoryResidencyAccountingStatus::Disabled;
    }
    if decision
        .reason_codes
        .iter()
        .any(|reason| matches!(reason, MemoryResidencyReasonCode::StaleTopology))
    {
        return MemoryResidencyAccountingStatus::Stale;
    }
    if !record_pool_counters_available
        || decision.reason_codes.iter().any(|reason| {
            matches!(
                reason,
                MemoryResidencyReasonCode::MissingTopology
                    | MemoryResidencyReasonCode::RuntimePressureUnknown
            )
        })
    {
        return MemoryResidencyAccountingStatus::Unknown;
    }
    MemoryResidencyAccountingStatus::Fresh
}

fn capacity_snapshot(decision: &MemoryResidencyDecision) -> MemoryResidencyCapacitySnapshot {
    let task_bytes =
        usize_to_u64(decision.task_capacity).saturating_mul(ESTIMATED_TASK_RECORD_BYTES);
    let region_bytes =
        usize_to_u64(decision.region_capacity).saturating_mul(ESTIMATED_REGION_RECORD_BYTES);
    let obligation_bytes = usize_to_u64(decision.obligation_capacity)
        .saturating_mul(ESTIMATED_OBLIGATION_RECORD_BYTES);
    let runtime_record_bytes = task_bytes
        .saturating_add(region_bytes)
        .saturating_add(obligation_bytes);

    MemoryResidencyCapacitySnapshot {
        task_capacity: decision.task_capacity,
        region_capacity: decision.region_capacity,
        obligation_capacity: decision.obligation_capacity,
        estimated_hot_runtime_slots: decision.estimated_hot_runtime_slots,
        estimated_hot_task_record_bytes: task_bytes,
        estimated_hot_region_record_bytes: region_bytes,
        estimated_hot_obligation_record_bytes: obligation_bytes,
        estimated_hot_runtime_record_bytes: runtime_record_bytes,
        estimated_hot_trace_bytes: decision.estimated_hot_trace_bytes,
        candidate_cold_evidence_bytes: decision.candidate_cold_evidence_bytes,
    }
}

fn tier_accounting_rows(
    decision: &MemoryResidencyDecision,
    capacity: &MemoryResidencyCapacitySnapshot,
) -> Vec<MemoryResidencyTierAccountingRow> {
    vec![
        MemoryResidencyTierAccountingRow {
            tier: MemoryResidencyTier::Hot,
            active: decision.selected_tier == MemoryResidencyTier::Hot,
            record_slots: decision.estimated_hot_runtime_slots,
            estimated_bytes: capacity
                .estimated_hot_runtime_record_bytes
                .saturating_add(decision.estimated_hot_trace_bytes),
            evidence_bytes: 0,
            source: MemoryResidencyAccountingSource::RuntimeRecordTables,
        },
        MemoryResidencyTierAccountingRow {
            tier: MemoryResidencyTier::Warm,
            active: decision.selected_tier == MemoryResidencyTier::Warm,
            record_slots: 0,
            estimated_bytes: decision.recommended_warm_evidence_bytes,
            evidence_bytes: decision.recommended_warm_evidence_bytes,
            source: MemoryResidencyAccountingSource::TraceStorageBudget,
        },
        MemoryResidencyTierAccountingRow {
            tier: MemoryResidencyTier::Cold,
            active: decision.selected_tier == MemoryResidencyTier::Cold,
            record_slots: 0,
            estimated_bytes: decision.recommended_cold_evidence_bytes,
            evidence_bytes: decision.recommended_cold_evidence_bytes,
            source: MemoryResidencyAccountingSource::TraceStorageBudget,
        },
        MemoryResidencyTierAccountingRow {
            tier: MemoryResidencyTier::Fallback,
            active: decision.selected_tier == MemoryResidencyTier::Fallback,
            record_slots: 0,
            estimated_bytes: decision.fallback_evidence_bytes,
            evidence_bytes: decision.fallback_evidence_bytes,
            source: MemoryResidencyAccountingSource::FallbackBoundary,
        },
        MemoryResidencyTierAccountingRow {
            tier: MemoryResidencyTier::NoWin,
            active: decision.selected_tier == MemoryResidencyTier::NoWin,
            record_slots: 0,
            estimated_bytes: decision.no_win_evidence_bytes,
            evidence_bytes: decision.no_win_evidence_bytes,
            source: MemoryResidencyAccountingSource::NoWinBoundary,
        },
    ]
}

fn aggregation_rows(
    decision: &MemoryResidencyDecision,
    input: &MemoryResidencyPolicyInput<'_>,
    capacity: &MemoryResidencyCapacitySnapshot,
    counters_available: bool,
    status: MemoryResidencyAccountingStatus,
) -> Vec<MemoryResidencyAggregationRow> {
    let counter_status = if counters_available {
        status
    } else {
        MemoryResidencyAccountingStatus::Unknown
    };
    let artifact_status = if input.artifact_cache_pressure.is_some() {
        status
    } else {
        MemoryResidencyAccountingStatus::Unknown
    };
    let artifact = input.artifact_cache_pressure;
    vec![
        MemoryResidencyAggregationRow {
            kind: MemoryResidencyAggregationKind::RuntimeTotal,
            row_count: 1,
            estimated_bytes: capacity
                .estimated_hot_runtime_record_bytes
                .saturating_add(decision.estimated_hot_trace_bytes)
                .saturating_add(decision.candidate_cold_evidence_bytes),
            status,
            source: MemoryResidencyAccountingSource::RuntimeRecordTables,
        },
        MemoryResidencyAggregationRow {
            kind: MemoryResidencyAggregationKind::TaskRecords,
            row_count: usize_to_u64(decision.task_capacity),
            estimated_bytes: capacity.estimated_hot_task_record_bytes,
            status: counter_status,
            source: MemoryResidencyAccountingSource::RuntimeRecordTables,
        },
        MemoryResidencyAggregationRow {
            kind: MemoryResidencyAggregationKind::RegionRecords,
            row_count: usize_to_u64(decision.region_capacity),
            estimated_bytes: capacity.estimated_hot_region_record_bytes,
            status: counter_status,
            source: MemoryResidencyAccountingSource::RuntimeRecordTables,
        },
        MemoryResidencyAggregationRow {
            kind: MemoryResidencyAggregationKind::ObligationRecords,
            row_count: usize_to_u64(decision.obligation_capacity),
            estimated_bytes: capacity.estimated_hot_obligation_record_bytes,
            status: counter_status,
            source: MemoryResidencyAccountingSource::RuntimeRecordTables,
        },
        MemoryResidencyAggregationRow {
            kind: MemoryResidencyAggregationKind::RetainedEvidence,
            row_count: u64::from(decision.candidate_cold_evidence_bytes > 0),
            estimated_bytes: decision.candidate_cold_evidence_bytes,
            status,
            source: MemoryResidencyAccountingSource::TraceStorageBudget,
        },
        MemoryResidencyAggregationRow {
            kind: MemoryResidencyAggregationKind::ArtifactCache,
            row_count: artifact.map_or(0, |snapshot| u64::from(snapshot.artifact_count)),
            estimated_bytes: artifact.map_or(0, |snapshot| snapshot.resident_bytes),
            status: artifact_status,
            source: artifact.map_or(MemoryResidencyAccountingSource::Unavailable, |_| {
                MemoryResidencyAccountingSource::ArtifactCachePressure
            }),
        },
    ]
}

fn unavailable_tier_rows() -> Vec<MemoryResidencyTierAccountingRow> {
    [
        MemoryResidencyTier::Hot,
        MemoryResidencyTier::Warm,
        MemoryResidencyTier::Cold,
        MemoryResidencyTier::Fallback,
        MemoryResidencyTier::NoWin,
    ]
    .into_iter()
    .map(|tier| MemoryResidencyTierAccountingRow {
        tier,
        active: tier == MemoryResidencyTier::Fallback,
        record_slots: 0,
        estimated_bytes: 0,
        evidence_bytes: 0,
        source: MemoryResidencyAccountingSource::Unavailable,
    })
    .collect()
}

fn unavailable_aggregation_rows() -> Vec<MemoryResidencyAggregationRow> {
    [
        MemoryResidencyAggregationKind::RuntimeTotal,
        MemoryResidencyAggregationKind::TaskRecords,
        MemoryResidencyAggregationKind::RegionRecords,
        MemoryResidencyAggregationKind::ObligationRecords,
        MemoryResidencyAggregationKind::RetainedEvidence,
        MemoryResidencyAggregationKind::ArtifactCache,
    ]
    .into_iter()
    .map(|kind| MemoryResidencyAggregationRow {
        kind,
        row_count: 0,
        estimated_bytes: 0,
        status: MemoryResidencyAccountingStatus::Unknown,
        source: MemoryResidencyAccountingSource::Unavailable,
    })
    .collect()
}

impl MemoryResidencyDecision {
    /// Stable line-oriented rendering for deterministic goldens and operator logs.
    #[must_use]
    pub fn stable_report_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("schema_version={}", self.schema_version),
            format!("policy_enabled={}", self.policy_enabled),
            format!("selected_tier={}", self.selected_tier.as_str()),
            format!("live_task_action={}", self.live_task_action.as_str()),
            format!("trace_storage_profile={}", self.trace_storage_profile),
            format!("arena_temperature_policy={}", self.arena_temperature_policy),
            format!("task_capacity={}", self.task_capacity),
            format!("region_capacity={}", self.region_capacity),
            format!("obligation_capacity={}", self.obligation_capacity),
            format!(
                "estimated_hot_runtime_slots={}",
                self.estimated_hot_runtime_slots
            ),
            format!(
                "estimated_hot_trace_bytes={}",
                self.estimated_hot_trace_bytes
            ),
            format!(
                "candidate_cold_evidence_bytes={}",
                self.candidate_cold_evidence_bytes
            ),
            format!(
                "recommended_warm_evidence_bytes={}",
                self.recommended_warm_evidence_bytes
            ),
            format!(
                "recommended_cold_evidence_bytes={}",
                self.recommended_cold_evidence_bytes
            ),
            format!("fallback_evidence_bytes={}", self.fallback_evidence_bytes),
            format!("no_win_evidence_bytes={}", self.no_win_evidence_bytes),
            format!(
                "runtime_pressure_verdict={}",
                self.runtime_pressure_verdict.as_deref().unwrap_or("none")
            ),
            format!(
                "artifact_cache_pressure_bps={}",
                self.artifact_cache_pressure_bps
                    .map_or_else(|| "none".to_string(), |value| value.to_string())
            ),
            format!(
                "locality_accounting_epoch={}",
                self.locality_accounting_epoch
                    .map_or_else(|| "none".to_string(), |value| value.to_string())
            ),
            format!(
                "locality_remote_touch_ratio_bps={}",
                self.locality_remote_touch_ratio_bps
                    .map_or_else(|| "none".to_string(), |value| value.to_string())
            ),
        ];
        lines.extend(
            self.no_claim_boundaries
                .iter()
                .map(|boundary| format!("no_claim={}", boundary.as_str())),
        );
        lines.extend(
            self.reason_codes
                .iter()
                .map(|reason| format!("reason={}", reason.as_str())),
        );
        lines
    }
}

fn push_reason(
    reason_codes: &mut Vec<MemoryResidencyReasonCode>,
    reason: MemoryResidencyReasonCode,
) {
    if !reason_codes.contains(&reason) {
        reason_codes.push(reason);
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::config::{
        ArenaLocalityAccessModel, ArenaLocalityPolicy, RuntimeConfig, WorkerCohortMapping,
    };
    use crate::runtime::resource_monitor::{
        DegradationLevel, ResourceProbeOperatorVerdict, ResourceType,
        RuntimePressureEarlyWarningSeverity, RuntimePressureResourceSnapshot,
        RuntimePressureSignalSnapshot, RuntimePressureSignalStatus, RuntimePressureSpectralClass,
        RuntimePressureSpectralSnapshot,
    };

    fn large_host_config(policy: ArenaTemperaturePolicy) -> RuntimeConfig {
        let mut config = RuntimeConfig::default();
        config.worker_threads = 64;
        config.capacity_hints = Some(RuntimeCapacityHints::new(4_096, 1_024, 2_048));
        config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
        config.arena_temperature_policy = policy;
        let mut worker_to_cohort = Vec::with_capacity(64);
        for cohort in 0..8 {
            for _ in 0..8 {
                worker_to_cohort.push(cohort);
            }
        }
        config.worker_cohort_map = Some(WorkerCohortMapping::new(worker_to_cohort));
        config
    }

    fn access_model_with_win() -> ArenaLocalityAccessModel {
        ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![900, 10, 10, 10, 10, 10, 10, 10],
            region_arena_touches_by_cohort: vec![800, 20, 20, 20, 20, 20, 20, 20],
            obligation_arena_touches_by_cohort: vec![700, 30, 30, 30, 30, 30, 30, 30],
            task_record_pool_touches_by_cohort: vec![600, 40, 40, 40, 40, 40, 40, 40],
        }
    }

    fn access_model_no_win() -> ArenaLocalityAccessModel {
        ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![100; 8],
            region_arena_touches_by_cohort: vec![100; 8],
            obligation_arena_touches_by_cohort: vec![100; 8],
            task_record_pool_touches_by_cohort: vec![100; 8],
        }
    }

    fn locality_report(
        config: &RuntimeConfig,
        access_model: &ArenaLocalityAccessModel,
    ) -> ArenaLocalityReport {
        config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6_000,
                accounting_epoch: 1,
            },
            Some(95),
            access_model,
        )
    }

    fn warm_proof() -> ProofPackWarmthTelemetry {
        ProofPackWarmthTelemetry::new(true, true, 30, 300)
    }

    fn hot_artifact_snapshot() -> ArtifactMemoryPressureSnapshot {
        ArtifactMemoryPressureSnapshot {
            resident_bytes: 900,
            max_resident_bytes: 1_000,
            hot_resident_bytes: 300,
            cold_resident_bytes: 600,
            spill_eligible_bytes: 512,
            remote_numa_bytes: 0,
            pressure_bps: 8_700,
            high_pressure: true,
            duplicate_bytes_avoided: 0,
            artifact_count: 3,
        }
    }

    fn pressure_snapshot(verdict: RuntimePressureVerdict) -> RuntimePressureSnapshot {
        RuntimePressureSnapshot {
            schema_version: "test-runtime-pressure-v1".to_string(),
            overall_verdict: verdict,
            missing_signal_count: 0,
            degraded_signal_count: u64::from(verdict == RuntimePressureVerdict::Degraded),
            critical_signal_count: u64::from(verdict == RuntimePressureVerdict::Critical),
            resource_composite_degradation: if verdict == RuntimePressureVerdict::Critical {
                DegradationLevel::Emergency
            } else {
                DegradationLevel::None
            },
            platform_probe_operator_verdict: ResourceProbeOperatorVerdict::Complete,
            signal_statuses: vec![RuntimePressureSignalSnapshot {
                signal: crate::runtime::resource_monitor::RuntimePressureSignal::Resources,
                status: if verdict == RuntimePressureVerdict::Critical {
                    RuntimePressureSignalStatus::Critical
                } else {
                    RuntimePressureSignalStatus::Present
                },
                reason: "test".to_string(),
            }],
            resources: vec![RuntimePressureResourceSnapshot {
                resource_type: ResourceType::Memory,
                resource_label: "memory".to_string(),
                current: 98,
                soft_limit: 70,
                hard_limit: 85,
                max_limit: 100,
                usage_bps: 9_800,
                soft_limit_exceeded: true,
                hard_limit_exceeded: true,
                critical_limit_exceeded: verdict == RuntimePressureVerdict::Critical,
                degradation_level: DegradationLevel::Emergency,
            }],
            scheduler: None,
            spectral: RuntimePressureSpectralSnapshot {
                class: RuntimePressureSpectralClass::Healthy,
                fiedler_micro_units: None,
                spectral_gap_bps: None,
                spectral_radius_micro_units: None,
                bottleneck_count: 0,
                components: None,
                approaching_disconnect: false,
                trapped_wait_cycle: false,
                early_warning_severity: RuntimePressureEarlyWarningSeverity::None,
            },
            spectral_recommendations: Vec::new(),
            region_memory_budgets: Vec::new(),
            rch_proof_lanes: Vec::new(),
        }
    }

    fn base_input<'a>(
        config: &'a RuntimeConfig,
        locality: Option<&'a ArenaLocalityReport>,
    ) -> MemoryResidencyPolicyInput<'a> {
        let mut input = MemoryResidencyPolicyInput::new(
            config.resolved_capacity_hints(),
            config.trace_storage_profile,
            config.arena_temperature_policy,
        )
        .with_large_page_cold_slabs_supported(true)
        .with_proof_pack_warmth(warm_proof());
        if let Some(locality) = locality {
            input = input.with_locality_report(locality, 30);
        }
        input
    }

    #[test]
    fn default_policy_is_disabled_and_falls_back() {
        let config = RuntimeConfig::default();
        let input = MemoryResidencyPolicyInput::new(
            config.resolved_capacity_hints(),
            config.trace_storage_profile,
            config.arena_temperature_policy,
        );
        let decision = MemoryResidencyPolicy::default().decide(&input);

        assert!(!decision.policy_enabled);
        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::PolicyDisabled)
        );
        assert!(
            decision
                .no_claim_boundaries
                .contains(&MemoryResidencyNoClaimBoundary::DefaultRuntimeBehaviorUnchanged)
        );
        assert!(
            decision
                .no_claim_boundaries
                .contains(&MemoryResidencyNoClaimBoundary::NoLiveTaskMutation)
        );
    }

    #[test]
    fn fresh_topology_selects_warm_recommendation() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let input = base_input(&config, Some(&locality));
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Warm);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::FreshTopology)
        );
        assert!(decision.recommended_warm_evidence_bytes > 0);
        assert_eq!(
            decision.live_task_action,
            MemoryResidencyLiveTaskAction::RecommendOnly
        );
    }

    #[test]
    fn stale_topology_fails_closed_to_fallback() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let input = base_input(&config, Some(&locality)).with_locality_report(&locality, 901);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::StaleTopology)
        );
    }

    #[test]
    fn no_win_locality_refuses_the_policy() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_no_win());
        let input = base_input(&config, Some(&locality));
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::NoWin);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::NoWinLocality)
        );
    }

    #[test]
    fn cold_evidence_budget_exhaustion_falls_back() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let cache = ArtifactMemoryPressureSnapshot {
            spill_eligible_bytes: 1,
            ..hot_artifact_snapshot()
        };
        let input = base_input(&config, Some(&locality)).with_artifact_cache_pressure(&cache);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::ColdEvidenceBudgetExhausted)
        );
    }

    #[test]
    fn proof_pack_warmth_mismatch_falls_back() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let input = base_input(&config, Some(&locality))
            .with_proof_pack_warmth(ProofPackWarmthTelemetry::new(false, false, 1_000, 300));
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::ProofPackWarmthMismatch)
        );
    }

    #[test]
    fn critical_runtime_pressure_snapshot_refuses_the_policy() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let pressure = pressure_snapshot(RuntimePressureVerdict::Critical);
        let input = base_input(&config, Some(&locality)).with_runtime_pressure(&pressure);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::NoWin);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::CriticalMemoryPressure)
        );
    }

    #[test]
    fn unsupported_large_pages_fall_back() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidenceLargePages);
        let locality = locality_report(&config, &access_model_with_win());
        let input =
            base_input(&config, Some(&locality)).with_large_page_cold_slabs_supported(false);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::UnsupportedLargePages)
        );
    }

    #[test]
    fn artifact_cache_pressure_selects_cold_when_spill_is_available() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let cache = ArtifactMemoryPressureSnapshot {
            spill_eligible_bytes: u64::MAX,
            ..hot_artifact_snapshot()
        };
        let input = base_input(&config, Some(&locality)).with_artifact_cache_pressure(&cache);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Cold);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::ArtifactCachePressure)
        );
        assert!(decision.recommended_cold_evidence_bytes > 0);
    }

    #[test]
    fn stable_report_lines_are_byte_stable() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let cache = ArtifactMemoryPressureSnapshot {
            spill_eligible_bytes: u64::MAX,
            ..hot_artifact_snapshot()
        };
        let input = base_input(&config, Some(&locality)).with_artifact_cache_pressure(&cache);
        let policy = MemoryResidencyPolicy::experimental_opt_in();

        let first = policy.decide(&input).stable_report_lines();
        let second = policy.decide(&input).stable_report_lines();

        assert_eq!(first, second);
        assert!(first.iter().any(|line| line == "selected_tier=cold"));
        assert!(
            first
                .iter()
                .any(|line| line == "no_claim=no_performance_claim")
        );
    }
}
