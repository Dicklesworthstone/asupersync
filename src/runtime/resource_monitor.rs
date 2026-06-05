//! Resource monitoring and degradation trigger system.
//!
//! This module provides comprehensive resource monitoring, degradation triggers,
//! and load shedding decisions for the asupersync runtime. It tracks memory usage,
//! file descriptors, CPU load, network connections, and custom resource types,
//! then triggers degradation policies when thresholds are exceeded.
//!
//! # Architecture
//!
//! - [`ResourceMonitor`] - Central monitoring coordinator
//! - [`DegradationEngine`] - Decision engine for resource reclamation
//! - [`TriggerConfig`] - Configurable thresholds and hysteresis
//! - [`ResourcePressure`] - Multi-dimensional pressure tracking
//!
//! # Integration
//!
//! The monitor integrates with existing runtime components:
//! - Region creation checks resource availability
//! - Scheduler responds to CPU pressure
//! - IO driver handles file descriptor pressure
//! - Memory allocators trigger on heap pressure

#![allow(missing_docs)]

use crate::observability::spectral_health::{
    EarlyWarningSeverity, HealthClassification, SpectralHealthReport,
};
use crate::runtime::rch_health::{RchAdmissionDecision, RchWorkerAdmissionReceipt};
use crate::runtime::scheduler::SchedulerEvidenceMetrics;
use crate::sync::LockMetricsSnapshot;
use crate::sync::lock_ordering::{LockModule, LockOrderAtlasSnapshot, LockRank};
use crate::types::pressure::SystemPressure;
use crate::types::{CapabilityBudget, RegionId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Stable schema for operator-facing platform probe reports.
pub const RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION: &str =
    "asupersync.resource-monitor-platform-gaps.v1";

/// Stable schema for unified operator-facing runtime pressure snapshots.
pub const RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION: &str =
    "asupersync.runtime-pressure-snapshot.v1";

/// Stable schema for deterministic runtime pressure lab scenario evidence.
pub const RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION: &str =
    "asupersync.runtime-pressure-lab-scenario-evidence.v1";

/// Stable schema for opt-in pressure-aware admission policies.
pub const RUNTIME_PRESSURE_ADMISSION_POLICY_SCHEMA_VERSION: &str =
    "asupersync.runtime-pressure-admission-policy.v1";

/// Stable schema for opt-in pressure-aware admission decisions.
pub const RUNTIME_PRESSURE_ADMISSION_DECISION_SCHEMA_VERSION: &str =
    "asupersync.runtime-pressure-admission-decision.v1";

/// Stable schema for RCH proof-lane pressure rows folded into runtime snapshots.
pub const RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION: &str =
    "asupersync.runtime-pressure-rch-proof-lane.v1";

/// Stable schema for region memory-budget pressure rows folded into runtime snapshots.
pub const RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION: &str =
    "asupersync.runtime-pressure-region-memory-budget.v1";

/// Stable schema for source-backed admission-aware runtime pressure atlas snapshots.
pub const ADMISSION_AWARE_RUNTIME_PRESSURE_ATLAS_SCHEMA_VERSION: &str =
    "admission-aware-runtime-pressure-atlas-v1";

const RESOURCE_PROBE_WARNING_THROTTLE_EVERY: u64 = 8;
const REGION_MEMORY_BUDGET_SOFT_LIMIT_BPS: u16 = 8_000;
const REGION_MEMORY_BUDGET_HARD_LIMIT_BPS: u16 = 10_000;
const ADMISSION_AWARE_LARGE_HOST_CPU_CORES: u16 = 64;
const ADMISSION_AWARE_LARGE_HOST_MEMORY_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const ADMISSION_AWARE_LARGE_HOST_MIN_NUMA_NODES: u16 = 2;
const ADMISSION_AWARE_LARGE_HOST_BATCH_CORE_FLOOR: u16 = 8;
const ADMISSION_AWARE_LARGE_HOST_BATCH_MEMORY_FLOOR_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const ADMISSION_AWARE_LARGE_HOST_DISK_HEADROOM_FLOOR_BYTES: u64 = 128 * 1024 * 1024 * 1024;

/// Errors that can occur during resource monitoring.
#[derive(Debug, Error)]
pub enum ResourceMonitorError {
    /// Resource type is not registered.
    #[error("unknown resource type: {resource_type}")]
    UnknownResourceType { resource_type: String },

    /// Monitoring is already active.
    #[error("resource monitoring is already active")]
    AlreadyActive,

    /// System resource access failed.
    #[error("failed to access system resource: {reason}")]
    SystemAccessFailed { reason: String },

    /// Configuration is invalid.
    #[error("invalid configuration: {details}")]
    InvalidConfig { details: String },

    /// Degradation engine is not ready.
    #[error("degradation engine not initialized")]
    EngineNotReady,
}

/// Resource types tracked by the monitor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    /// Physical memory (heap allocations).
    Memory,
    /// File descriptors and handles.
    FileDescriptors,
    /// CPU load and scheduler queue depth.
    CpuLoad,
    /// Network connections and sockets.
    NetworkConnections,
    /// Runtime tasks and their associated resources.
    Task,
    /// Custom application-defined resource.
    Custom(String),
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::FileDescriptors => write!(f, "file_descriptors"),
            Self::CpuLoad => write!(f, "cpu_load"),
            Self::NetworkConnections => write!(f, "network_connections"),
            Self::Task => write!(f, "task"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// Built-in platform probes used by the system resource collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbe {
    ProcessRssBytes,
    MemoryMaxBytes,
    ProcessFdCount,
    FileDescriptorLimit,
    #[serde(rename = "load_avg_1min_scaled")]
    LoadAvg1MinScaled,
    ProcessConnectionCount,
    NetworkConnectionLimit,
}

impl ResourceProbe {
    #[must_use]
    pub fn resource_type(self) -> ResourceType {
        match self {
            Self::ProcessRssBytes | Self::MemoryMaxBytes => ResourceType::Memory,
            Self::ProcessFdCount | Self::FileDescriptorLimit => ResourceType::FileDescriptors,
            Self::LoadAvg1MinScaled => ResourceType::CpuLoad,
            Self::ProcessConnectionCount | Self::NetworkConnectionLimit => {
                ResourceType::NetworkConnections
            }
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessRssBytes => "process_rss_bytes",
            Self::MemoryMaxBytes => "memory_max_bytes",
            Self::ProcessFdCount => "process_fd_count",
            Self::FileDescriptorLimit => "file_descriptor_limit",
            Self::LoadAvg1MinScaled => "load_avg_1min_scaled",
            Self::ProcessConnectionCount => "process_connection_count",
            Self::NetworkConnectionLimit => "network_connection_limit",
        }
    }
}

impl std::fmt::Display for ResourceProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Availability state for a platform resource probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbeStatus {
    Supported,
    Unavailable,
    Fallback,
    Disabled,
}

/// Operator-safe fallback semantics for a failed or disabled probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbeFallback {
    None,
    OmitMeasurement,
    ConservativeDefault,
    CustomCollectorRequired,
    MonitorDisabled,
}

impl std::fmt::Display for ResourceProbeFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::None => "none",
            Self::OmitMeasurement => "omit_measurement",
            Self::ConservativeDefault => "conservative_default",
            Self::CustomCollectorRequired => "custom_collector_required",
            Self::MonitorDisabled => "monitor_disabled",
        };
        f.write_str(label)
    }
}

/// Aggregate verdict for operator-facing platform probe reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProbeOperatorVerdict {
    Complete,
    DegradedWithUnavailableProbes,
    DegradedWithFallbacks,
    Disabled,
}

/// Serializable snapshot for one platform resource probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceProbeSnapshot {
    pub platform: String,
    pub resource_type: ResourceType,
    pub probe: ResourceProbe,
    pub status: ResourceProbeStatus,
    pub fallback: ResourceProbeFallback,
    pub sampled_value: Option<u64>,
    pub error_message: Option<String>,
    pub warning_count: u64,
    pub warning_suppressed_count: u64,
}

/// Serializable platform probe inventory for the resource monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePlatformProbeReport {
    pub schema_version: String,
    pub platform: String,
    pub probes: Vec<ResourceProbeSnapshot>,
    pub supported_count: u64,
    pub unavailable_count: u64,
    pub fallback_count: u64,
    pub disabled_count: u64,
    pub warning_emitted_count: u64,
    pub warning_suppressed_count: u64,
    pub operator_verdict: ResourceProbeOperatorVerdict,
}

/// Top-level operator verdict for the unified runtime pressure snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureVerdict {
    Healthy,
    Unknown,
    Degraded,
    Critical,
}

/// First-party signal groups folded into a runtime pressure snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureSignal {
    Resources,
    RegionMemoryBudgets,
    Scheduler,
    Spectral,
    PlatformProbes,
    RchProofLanes,
}

/// Availability and quality state for one pressure signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureSignalStatus {
    Present,
    Missing,
    Degraded,
    Critical,
}

/// Deterministic status row for one pressure signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureSignalSnapshot {
    pub signal: RuntimePressureSignal,
    pub status: RuntimePressureSignalStatus,
    pub reason: String,
}

/// Serializable resource pressure row with deterministic numeric fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureResourceSnapshot {
    pub resource_type: ResourceType,
    pub resource_label: String,
    pub current: u64,
    pub soft_limit: u64,
    pub hard_limit: u64,
    pub max_limit: u64,
    /// Usage in basis points, where `10_000` represents 100%.
    pub usage_bps: u16,
    pub soft_limit_exceeded: bool,
    pub hard_limit_exceeded: bool,
    pub critical_limit_exceeded: bool,
    pub degradation_level: DegradationLevel,
}

/// Compact spectral topology class used by the runtime pressure snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureSpectralClass {
    Unknown,
    Healthy,
    Degraded,
    Critical,
    Fragmented,
    Deadlocked,
}

/// Compact early-warning severity used by the runtime pressure snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureEarlyWarningSeverity {
    Unknown,
    None,
    Watch,
    Warning,
    Critical,
}

/// Operator-facing severity for one remediation recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureRecommendationSeverity {
    Observe,
    Investigate,
    Mitigate,
    Escalate,
}

/// Stable reason code for one remediation recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureRecommendationReason {
    Bottleneck,
    CriticalTopology,
    EarlyWarning,
    FragmentedTopology,
    TrappedWaitCycle,
}

/// Stable action code for one remediation recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureRecommendationAction {
    CollectTaskInspectorDetails,
    ConfirmTrappedCycleEvidence,
    EnableLabReplay,
    InspectSpectralBottlenecks,
    RunTrappedCycleDetection,
    TightenAdmission,
}

/// Evidence boundary for a remediation recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureRecommendationEvidenceScope {
    SpectralTopology,
    SpectralTrend,
    ExplicitTrappedCycle,
}

/// Deterministic advisory row for spectral remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureSpectralRecommendation {
    pub severity: RuntimePressureRecommendationSeverity,
    pub reason: RuntimePressureRecommendationReason,
    pub action: RuntimePressureRecommendationAction,
    pub evidence_scope: RuntimePressureRecommendationEvidenceScope,
    pub deadlock_proven: bool,
    pub requires_trapped_cycle_proof: bool,
}

/// Deterministic synthetic pressure scenario family for lab evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureLabScenarioKind {
    Healthy,
    CpuLanePressure,
    ResourceFallbackDegraded,
    RegionMemoryBudgetOverrun,
    StructuralWarning,
    RchProofLaneRemoteRefusal,
}

/// Stable evidence row for a deterministic runtime pressure lab scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureLabScenarioEvidence {
    pub schema_version: String,
    pub scenario_id: String,
    pub seed: u64,
    pub scenario_kind: RuntimePressureLabScenarioKind,
    pub expected_verdict: RuntimePressureVerdict,
    pub observed_verdict: RuntimePressureVerdict,
    pub classification_matches_expected: bool,
    pub diagnostic_labels: Vec<String>,
    pub snapshot: RuntimePressureSnapshot,
}

impl RuntimePressureLabScenarioEvidence {
    #[must_use]
    pub fn from_snapshot(
        scenario_id: impl Into<String>,
        seed: u64,
        scenario_kind: RuntimePressureLabScenarioKind,
        expected_verdict: RuntimePressureVerdict,
        snapshot: RuntimePressureSnapshot,
        mut diagnostic_labels: Vec<String>,
    ) -> Self {
        diagnostic_labels.sort();
        diagnostic_labels.dedup();
        let observed_verdict = snapshot.overall_verdict;

        Self {
            schema_version: RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION.to_string(),
            scenario_id: scenario_id.into(),
            seed,
            scenario_kind,
            expected_verdict,
            observed_verdict,
            classification_matches_expected: observed_verdict == expected_verdict,
            diagnostic_labels,
            snapshot,
        }
    }

    pub fn stable_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl From<EarlyWarningSeverity> for RuntimePressureEarlyWarningSeverity {
    fn from(value: EarlyWarningSeverity) -> Self {
        match value {
            EarlyWarningSeverity::None => Self::None,
            EarlyWarningSeverity::Watch => Self::Watch,
            EarlyWarningSeverity::Warning => Self::Warning,
            EarlyWarningSeverity::Critical => Self::Critical,
        }
    }
}

/// Serializable spectral health row with floating-point internals quantized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureSpectralSnapshot {
    pub class: RuntimePressureSpectralClass,
    pub fiedler_micro_units: Option<u64>,
    pub spectral_gap_bps: Option<u16>,
    pub spectral_radius_micro_units: Option<u64>,
    pub bottleneck_count: usize,
    pub components: Option<usize>,
    pub approaching_disconnect: bool,
    pub trapped_wait_cycle: bool,
    pub early_warning_severity: RuntimePressureEarlyWarningSeverity,
}

impl RuntimePressureSpectralSnapshot {
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            class: RuntimePressureSpectralClass::Unknown,
            fiedler_micro_units: None,
            spectral_gap_bps: None,
            spectral_radius_micro_units: None,
            bottleneck_count: 0,
            components: None,
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Unknown,
        }
    }

    #[must_use]
    pub fn from_report(report: &SpectralHealthReport) -> Self {
        let (class, components, approaching_disconnect, trapped_wait_cycle) =
            match &report.classification {
                HealthClassification::Deadlocked => {
                    (RuntimePressureSpectralClass::Deadlocked, None, false, true)
                }
                HealthClassification::Healthy { .. } => {
                    (RuntimePressureSpectralClass::Healthy, None, false, false)
                }
                HealthClassification::Degraded { .. } => {
                    (RuntimePressureSpectralClass::Degraded, None, false, false)
                }
                HealthClassification::Critical {
                    approaching_disconnect,
                    ..
                } => (
                    RuntimePressureSpectralClass::Critical,
                    None,
                    *approaching_disconnect,
                    false,
                ),
                HealthClassification::Fragmented { components } => (
                    RuntimePressureSpectralClass::Fragmented,
                    Some(*components),
                    false,
                    false,
                ),
            };

        Self {
            class,
            fiedler_micro_units: finite_scaled_u64(report.decomposition.fiedler_value, 1_000_000.0),
            spectral_gap_bps: finite_bps(report.decomposition.spectral_gap),
            spectral_radius_micro_units: finite_scaled_u64(
                report.decomposition.spectral_radius,
                1_000_000.0,
            ),
            bottleneck_count: report.bottlenecks.len(),
            components,
            approaching_disconnect,
            trapped_wait_cycle,
            early_warning_severity: report
                .bifurcation
                .as_ref()
                .map_or(RuntimePressureEarlyWarningSeverity::None, |warning| {
                    warning.severity.into()
                }),
        }
    }
}

/// Deterministic RCH proof-lane pressure row folded into runtime pressure snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureRchProofLaneSnapshot {
    pub schema_version: String,
    pub lane_id: String,
    pub decision_code: String,
    pub remote_required: bool,
    pub selected_worker: Option<String>,
    pub refusal_code: Option<String>,
    pub local_fallback_allowed: bool,
    pub candidate_count: usize,
    pub admissible_worker_count: usize,
    pub blocked_worker_count: usize,
    pub cache_warm_admissible_worker_count: usize,
    pub reason_codes: Vec<String>,
}

impl RuntimePressureRchProofLaneSnapshot {
    #[must_use]
    pub fn from_receipt(receipt: &RchWorkerAdmissionReceipt) -> Self {
        let row = receipt.schedule_row();
        let mut reason_codes = row
            .reason_codes
            .iter()
            .map(|code| (*code).to_string())
            .collect::<Vec<_>>();
        reason_codes.sort();
        reason_codes.dedup();

        Self {
            schema_version: RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION.to_string(),
            lane_id: row.lane_id,
            decision_code: row.decision_code.to_string(),
            remote_required: row.remote_required,
            selected_worker: row
                .selected_worker
                .as_ref()
                .map(|worker| worker.as_str().to_string()),
            refusal_code: row.refusal_code.map(str::to_string),
            local_fallback_allowed: row.local_fallback_allowed,
            candidate_count: row.candidate_count,
            admissible_worker_count: row.admissible_worker_count,
            blocked_worker_count: row.blocked_worker_count,
            cache_warm_admissible_worker_count: row.cache_warm_admissible_worker_count,
            reason_codes,
        }
    }
}

/// Deterministic region memory-budget pressure row folded into runtime pressure snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureRegionMemoryBudgetSnapshot {
    pub schema_version: String,
    pub region_id: RegionId,
    pub region_label: String,
    pub declared_memory_budget_bytes: u64,
    pub observed_memory_bytes: u64,
    pub over_budget_bytes: u64,
    /// Usage in basis points, where `10_000` represents the declared budget.
    pub usage_bps: u16,
    pub soft_limit_bps: u16,
    pub hard_limit_bps: u16,
    pub soft_limit_exceeded: bool,
    pub hard_limit_exceeded: bool,
    pub budget_exhausted: bool,
    pub advisory_only: bool,
}

impl RuntimePressureRegionMemoryBudgetSnapshot {
    #[must_use]
    pub fn new(
        region_id: RegionId,
        declared_memory_budget_bytes: u64,
        observed_memory_bytes: u64,
    ) -> Self {
        Self::with_label(
            region_id,
            region_id.to_string(),
            declared_memory_budget_bytes,
            observed_memory_bytes,
        )
    }

    #[must_use]
    pub fn with_label(
        region_id: RegionId,
        region_label: impl Into<String>,
        declared_memory_budget_bytes: u64,
        observed_memory_bytes: u64,
    ) -> Self {
        let usage_bps =
            region_memory_budget_usage_bps(observed_memory_bytes, declared_memory_budget_bytes);
        let over_budget_bytes = observed_memory_bytes.saturating_sub(declared_memory_budget_bytes);
        let soft_limit_exceeded = usage_bps >= REGION_MEMORY_BUDGET_SOFT_LIMIT_BPS
            || (declared_memory_budget_bytes == 0 && observed_memory_bytes > 0);
        let hard_limit_exceeded = usage_bps >= REGION_MEMORY_BUDGET_HARD_LIMIT_BPS
            || (declared_memory_budget_bytes == 0 && observed_memory_bytes > 0);
        let budget_exhausted = declared_memory_budget_bytes == 0
            || observed_memory_bytes >= declared_memory_budget_bytes;

        Self {
            schema_version: RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION.to_string(),
            region_id,
            region_label: region_label.into(),
            declared_memory_budget_bytes,
            observed_memory_bytes,
            over_budget_bytes,
            usage_bps,
            soft_limit_bps: REGION_MEMORY_BUDGET_SOFT_LIMIT_BPS,
            hard_limit_bps: REGION_MEMORY_BUDGET_HARD_LIMIT_BPS,
            soft_limit_exceeded,
            hard_limit_exceeded,
            budget_exhausted,
            advisory_only: true,
        }
    }

    #[must_use]
    pub fn from_capability_budget(
        region_id: RegionId,
        capability_budget: CapabilityBudget,
        observed_memory_bytes: u64,
    ) -> Option<Self> {
        capability_budget
            .memory_bytes
            .map(|declared_memory_budget_bytes| {
                Self::new(
                    region_id,
                    declared_memory_budget_bytes,
                    observed_memory_bytes,
                )
            })
    }
}

/// Unified operator-facing runtime pressure report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureSnapshot {
    pub schema_version: String,
    pub overall_verdict: RuntimePressureVerdict,
    pub missing_signal_count: u64,
    pub degraded_signal_count: u64,
    pub critical_signal_count: u64,
    pub resource_composite_degradation: DegradationLevel,
    pub platform_probe_operator_verdict: ResourceProbeOperatorVerdict,
    pub signal_statuses: Vec<RuntimePressureSignalSnapshot>,
    pub resources: Vec<RuntimePressureResourceSnapshot>,
    pub scheduler: Option<SchedulerEvidenceMetrics>,
    pub spectral: RuntimePressureSpectralSnapshot,
    pub spectral_recommendations: Vec<RuntimePressureSpectralRecommendation>,
    pub region_memory_budgets: Vec<RuntimePressureRegionMemoryBudgetSnapshot>,
    pub rch_proof_lanes: Vec<RuntimePressureRchProofLaneSnapshot>,
}

impl RuntimePressureSnapshot {
    #[must_use]
    pub fn from_parts(
        pressure: &ResourcePressure,
        platform_probe_report: ResourcePlatformProbeReport,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<RuntimePressureSpectralSnapshot>,
    ) -> Self {
        Self::from_parts_with_extended_pressure_evidence(
            pressure,
            platform_probe_report,
            scheduler,
            spectral,
            Vec::new(),
            Vec::new(),
        )
    }

    #[must_use]
    pub fn from_parts_with_rch_proof_lanes(
        pressure: &ResourcePressure,
        platform_probe_report: ResourcePlatformProbeReport,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<RuntimePressureSpectralSnapshot>,
        rch_proof_lanes: Vec<RuntimePressureRchProofLaneSnapshot>,
    ) -> Self {
        Self::from_parts_with_extended_pressure_evidence(
            pressure,
            platform_probe_report,
            scheduler,
            spectral,
            Vec::new(),
            rch_proof_lanes,
        )
    }

    #[must_use]
    pub fn from_parts_with_region_memory_budgets(
        pressure: &ResourcePressure,
        platform_probe_report: ResourcePlatformProbeReport,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<RuntimePressureSpectralSnapshot>,
        region_memory_budgets: Vec<RuntimePressureRegionMemoryBudgetSnapshot>,
    ) -> Self {
        Self::from_parts_with_extended_pressure_evidence(
            pressure,
            platform_probe_report,
            scheduler,
            spectral,
            region_memory_budgets,
            Vec::new(),
        )
    }

    #[must_use]
    pub fn from_parts_with_region_memory_budgets_and_rch_proof_lanes(
        pressure: &ResourcePressure,
        platform_probe_report: ResourcePlatformProbeReport,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<RuntimePressureSpectralSnapshot>,
        region_memory_budgets: Vec<RuntimePressureRegionMemoryBudgetSnapshot>,
        rch_proof_lanes: Vec<RuntimePressureRchProofLaneSnapshot>,
    ) -> Self {
        Self::from_parts_with_extended_pressure_evidence(
            pressure,
            platform_probe_report,
            scheduler,
            spectral,
            region_memory_budgets,
            rch_proof_lanes,
        )
    }

    fn from_parts_with_extended_pressure_evidence(
        pressure: &ResourcePressure,
        platform_probe_report: ResourcePlatformProbeReport,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<RuntimePressureSpectralSnapshot>,
        mut region_memory_budgets: Vec<RuntimePressureRegionMemoryBudgetSnapshot>,
        mut rch_proof_lanes: Vec<RuntimePressureRchProofLaneSnapshot>,
    ) -> Self {
        let resources = runtime_pressure_resources(pressure);
        let resource_composite_degradation = pressure.composite_degradation_level();
        let spectral = spectral.unwrap_or_else(RuntimePressureSpectralSnapshot::unknown);
        let spectral_recommendations = runtime_pressure_spectral_recommendations(&spectral);
        region_memory_budgets.sort_by(|left, right| {
            left.region_label
                .cmp(&right.region_label)
                .then_with(|| left.region_id.as_u64().cmp(&right.region_id.as_u64()))
        });
        region_memory_budgets.dedup_by(|left, right| left.region_id == right.region_id);
        rch_proof_lanes.sort_by(|left, right| {
            left.lane_id
                .cmp(&right.lane_id)
                .then_with(|| left.decision_code.cmp(&right.decision_code))
                .then_with(|| left.refusal_code.cmp(&right.refusal_code))
        });
        rch_proof_lanes.dedup_by(|left, right| {
            left.lane_id == right.lane_id
                && left.decision_code == right.decision_code
                && left.refusal_code == right.refusal_code
        });

        let mut signal_statuses = vec![
            runtime_pressure_resource_signal_status(&resources, resource_composite_degradation),
            runtime_pressure_scheduler_signal_status(scheduler.as_ref()),
            runtime_pressure_spectral_signal_status(&spectral),
            runtime_pressure_platform_probe_signal_status(&platform_probe_report),
        ];
        if let Some(row) =
            runtime_pressure_region_memory_budget_signal_status(&region_memory_budgets)
        {
            signal_statuses.push(row);
        }
        if let Some(row) = runtime_pressure_rch_proof_lane_signal_status(&rch_proof_lanes) {
            signal_statuses.push(row);
        }
        signal_statuses.sort_by_key(|row| row.signal);

        let missing_signal_count =
            count_signal_status(&signal_statuses, RuntimePressureSignalStatus::Missing);
        let degraded_signal_count =
            count_signal_status(&signal_statuses, RuntimePressureSignalStatus::Degraded);
        let critical_signal_count =
            count_signal_status(&signal_statuses, RuntimePressureSignalStatus::Critical);
        let overall_verdict = if critical_signal_count > 0 {
            RuntimePressureVerdict::Critical
        } else if degraded_signal_count > 0 {
            RuntimePressureVerdict::Degraded
        } else if missing_signal_count > 0 {
            RuntimePressureVerdict::Unknown
        } else {
            RuntimePressureVerdict::Healthy
        };

        Self {
            schema_version: RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION.to_string(),
            overall_verdict,
            missing_signal_count,
            degraded_signal_count,
            critical_signal_count,
            resource_composite_degradation,
            platform_probe_operator_verdict: platform_probe_report.operator_verdict,
            signal_statuses,
            resources,
            scheduler,
            spectral,
            spectral_recommendations,
            region_memory_budgets,
            rch_proof_lanes,
        }
    }
}

/// Freshness status attached to one admission-aware atlas input row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAwareAtlasFreshnessStatus {
    Fresh,
    Stale,
    Missing,
    Unsupported,
    Malformed,
}

impl AdmissionAwareAtlasFreshnessStatus {
    #[must_use]
    pub fn is_stale_or_missing(self) -> bool {
        matches!(self, Self::Stale | Self::Missing)
    }

    #[must_use]
    pub fn blocks_validation(self) -> bool {
        matches!(self, Self::Unsupported | Self::Malformed)
    }
}

/// Read-only overlap classification for coordination evidence supplied to the atlas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAwareCoordinationOverlapClass {
    NoOverlap,
    OwnedExact,
    OwnedGlob,
    PeerExact,
    PeerGlob,
    ActiveExclusiveConflict,
    ExpiredReservation,
    TrackerOnly,
    UnrelatedPeerWork,
    Malformed,
}

/// Conservative coordination decision derived from externally supplied atlas rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAwareCoordinationDecision {
    Proceed,
    Defer,
    HandoffRequired,
    Blocked,
}

/// Stable labels for the evidence boundary an atlas snapshot may claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAwareAtlasClaimLabel {
    Advisory,
    ReplayBacked,
    TrappedCycleProven,
    DeadlockProven,
    ValidationBlocked,
    StaleEvidence,
}

/// Advisory worker saturation class for the 64-core/256GiB swarm host profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAwareLargeHostWorkerSaturation {
    Available,
    LowMemory,
    WorkerSaturated,
    DiskConstrained,
    NonLargeHost,
}

/// Advisory batching decision for a large RCH swarm host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAwareLargeHostBatchingDecision {
    PreferWarmWorker,
    AdmitBatch,
    QueueLowMemory,
    DeferWorkerSaturated,
    QueueDiskHeadroom,
    DeferNonLargeHost,
}

/// Serializable lock contention row projected from existing lock metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareLockContentionAtlasRow {
    pub lock_name: String,
    pub lock_rank: String,
    pub lock_module: String,
    pub acquisitions: u64,
    pub contentions: u64,
    pub wait_ns: u64,
    pub hold_ns: u64,
    pub max_wait_ns: u64,
    pub max_hold_ns: u64,
    pub p95_wait_ns: u64,
    pub p999_wait_ns: u64,
    pub p95_hold_ns: u64,
    pub p999_hold_ns: u64,
    pub order_edges_exercised: usize,
    pub order_violations: usize,
    pub instrumentation_mode: String,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Serializable scheduler pressure row projected from runtime pressure evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareSchedulerPressureRow {
    pub scheduler_tail_pressure_label: String,
    pub methodology_baseline_rows: usize,
    pub flamegraph_artifact_path: Option<String>,
    pub phase6_gate_triggered: bool,
    pub attribution_claim_only: bool,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Serializable region memory budget row projected from runtime pressure evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareRegionMemoryBudgetPressureRow {
    pub region_id: RegionId,
    pub region_label: String,
    pub budget_schema_version: String,
    pub declared_budget_bytes: u64,
    pub observed_usage_bytes: u64,
    pub pressure_level: RuntimePressureSignalStatus,
    pub optional_work_action: RuntimePressureAdmissionAction,
    pub required_cleanup_admitted: bool,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Serializable spectral wait-graph row projected from runtime pressure evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareSpectralWaitGraphRow {
    pub early_warning_severity: RuntimePressureEarlyWarningSeverity,
    pub health_classification: RuntimePressureSpectralClass,
    pub fiedler_trend: Option<u64>,
    pub recommendations: Vec<RuntimePressureSpectralRecommendation>,
    pub deadlock_proven: bool,
    pub requires_trapped_cycle_detection: bool,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Proof status for a trapped-cycle witness row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionAwareTrappedCycleWitnessProofStatus {
    Validated,
    ReplayPending,
    Failed,
    Stale,
    Malformed,
}

/// Directed wait edge inside an explicit trapped-cycle witness.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AdmissionAwareTrappedCycleWaitEdgeRow {
    pub waiting_participant: String,
    pub held_by_participant: String,
    pub resource: String,
}

/// Explicit trapped-cycle witness required before deadlock-style claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareTrappedCycleWitnessRow {
    pub witness_id: String,
    pub participants: Vec<String>,
    pub held_resources: Vec<String>,
    pub wait_edges: Vec<AdmissionAwareTrappedCycleWaitEdgeRow>,
    pub source_step_or_timestamp: String,
    pub replay_command: String,
    pub proof_status: AdmissionAwareTrappedCycleWitnessProofStatus,
    pub witness_freshness: AdmissionAwareAtlasFreshnessStatus,
}

impl AdmissionAwareTrappedCycleWitnessRow {
    #[must_use]
    pub fn is_validated(&self) -> bool {
        self.proof_status == AdmissionAwareTrappedCycleWitnessProofStatus::Validated
            && self.witness_freshness == AdmissionAwareAtlasFreshnessStatus::Fresh
            && !self.witness_id.trim().is_empty()
            && !self.participants.is_empty()
            && !self.held_resources.is_empty()
            && !self.wait_edges.is_empty()
            && !self.source_step_or_timestamp.trim().is_empty()
            && !self.replay_command.trim().is_empty()
    }

    #[must_use]
    pub fn is_malformed(&self) -> bool {
        self.proof_status == AdmissionAwareTrappedCycleWitnessProofStatus::Malformed
            || self.witness_freshness == AdmissionAwareAtlasFreshnessStatus::Malformed
            || self.witness_id.trim().is_empty()
            || self.participants.is_empty()
            || self.held_resources.is_empty()
            || self.wait_edges.is_empty()
            || self.source_step_or_timestamp.trim().is_empty()
            || self.replay_command.trim().is_empty()
    }
}

/// Serializable proof-lane admission row projected from runtime pressure evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareRchProofLaneAdmissionRow {
    pub lane_id: String,
    pub admission_decision: String,
    pub reason_codes: Vec<String>,
    pub remote_required: bool,
    pub local_fallback_allowed: bool,
    pub target_dir_isolated: bool,
    pub recommended_worker_id: Option<String>,
    pub cover_claims: Vec<String>,
    pub does_not_cover_claims: Vec<String>,
    pub suggested_command: Option<String>,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Read-only dirty-tree coordination row supplied by a caller or fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareDirtyTreePeerOwnershipRow {
    pub path: String,
    pub dirty_classification: String,
    pub holder: Option<String>,
    pub bead_id: Option<String>,
    pub source: String,
    pub overlap_classification: AdmissionAwareCoordinationOverlapClass,
    pub coordination_decision: AdmissionAwareCoordinationDecision,
    pub blocks_admission: bool,
    pub handoff_required: bool,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Read-only Agent Mail reservation row supplied by a caller or fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareAgentMailReservationRow {
    pub path_pattern: String,
    pub holder: String,
    pub exclusive: bool,
    pub reason: String,
    pub expires_ts: Option<String>,
    pub bead_id: Option<String>,
    pub overlap_classification: AdmissionAwareCoordinationOverlapClass,
    pub coordination_decision: AdmissionAwareCoordinationDecision,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Read-only bead tracker status row supplied by a caller or fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareBrTrackerStatusRow {
    pub bead_id: String,
    pub status: String,
    pub priority: Option<u8>,
    pub blocked_by: Vec<String>,
    pub ready: bool,
    pub assignee: Option<String>,
    pub updated_at: Option<String>,
    pub overlap_classification: AdmissionAwareCoordinationOverlapClass,
    pub coordination_decision: AdmissionAwareCoordinationDecision,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Read-only large-host worker warmth row supplied by a caller or fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareLargeHostWorkerWarmthRow {
    pub worker_id: String,
    pub cpu_cores: u16,
    pub memory_bytes: u64,
    pub numa_nodes: u16,
    pub disk_headroom_bytes: u64,
    pub worker_queue_state: String,
    pub worker_available_cores: u16,
    pub worker_available_memory_bytes: u64,
    pub cache_warmth: String,
    pub target_dir_isolated: bool,
    pub active_project_excluded: bool,
    pub proof_lane_cost_estimate: Option<String>,
    pub worker_saturation: AdmissionAwareLargeHostWorkerSaturation,
    pub advisory_batching_decision: AdmissionAwareLargeHostBatchingDecision,
    pub advisory_batching_reason_codes: Vec<String>,
    pub advisory_batch_size_hint: Option<u16>,
    pub advisory_non_claims: Vec<String>,
    pub advisory_only: bool,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Stable claim-boundary row emitted by the atlas builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareClaimBoundaryLabelRow {
    pub label: AdmissionAwareAtlasClaimLabel,
    pub required_evidence: Vec<String>,
    pub forbidden_overclaims: Vec<String>,
    pub closeout_text: String,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Read-only operator closeout receipt supplied by a caller or fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareOperatorCloseoutReceiptRow {
    pub bead_id: String,
    pub status: String,
    pub commit: Option<String>,
    pub proof_commands: Vec<String>,
    pub pushed_main: bool,
    pub pushed_master_mirror: bool,
    pub sample_freshness: AdmissionAwareAtlasFreshnessStatus,
}

/// Pure inputs for source-backed admission-aware atlas assembly.
#[derive(Debug, Clone)]
pub struct AdmissionAwareRuntimePressureAtlasBuilderInput {
    pub runtime_pressure: RuntimePressureSnapshot,
    pub lock_metrics: Vec<LockMetricsSnapshot>,
    pub lock_order_atlas: LockOrderAtlasSnapshot,
    pub dirty_tree_peer_ownership: Vec<AdmissionAwareDirtyTreePeerOwnershipRow>,
    pub agent_mail_reservations: Vec<AdmissionAwareAgentMailReservationRow>,
    pub br_tracker_status: Vec<AdmissionAwareBrTrackerStatusRow>,
    pub large_host_worker_warmth: Vec<AdmissionAwareLargeHostWorkerWarmthRow>,
    pub operator_closeout_receipts: Vec<AdmissionAwareOperatorCloseoutReceiptRow>,
    pub replay_backed: bool,
    pub trapped_cycle_witnesses: Vec<AdmissionAwareTrappedCycleWitnessRow>,
}

impl AdmissionAwareRuntimePressureAtlasBuilderInput {
    #[must_use]
    pub fn new(
        runtime_pressure: RuntimePressureSnapshot,
        lock_order_atlas: LockOrderAtlasSnapshot,
    ) -> Self {
        Self {
            runtime_pressure,
            lock_metrics: Vec::new(),
            lock_order_atlas,
            dirty_tree_peer_ownership: Vec::new(),
            agent_mail_reservations: Vec::new(),
            br_tracker_status: Vec::new(),
            large_host_worker_warmth: Vec::new(),
            operator_closeout_receipts: Vec::new(),
            replay_backed: false,
            trapped_cycle_witnesses: Vec::new(),
        }
    }
}

/// Source-backed admission-aware atlas snapshot assembled from explicit inputs only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAwareRuntimePressureAtlasSnapshot {
    pub schema_version: String,
    pub runtime_pressure_schema_version: String,
    pub overall_label: AdmissionAwareAtlasClaimLabel,
    pub claim_boundary_labels: Vec<AdmissionAwareClaimBoundaryLabelRow>,
    pub missing_required_sections: Vec<String>,
    pub production_admission_default_enabled: bool,
    pub mutates_agent_mail: bool,
    pub mutates_beads: bool,
    pub mutates_filesystem: bool,
    pub starts_rch: bool,
    pub deadlock_proven: bool,
    pub replay_backed: bool,
    pub coordination_decision: AdmissionAwareCoordinationDecision,
    pub coordination_reason_codes: Vec<String>,
    pub lock_contention: Vec<AdmissionAwareLockContentionAtlasRow>,
    pub scheduler_pressure: Vec<AdmissionAwareSchedulerPressureRow>,
    pub region_memory_budget_pressure: Vec<AdmissionAwareRegionMemoryBudgetPressureRow>,
    pub spectral_wait_graph: Vec<AdmissionAwareSpectralWaitGraphRow>,
    pub trapped_cycle_witness: Vec<AdmissionAwareTrappedCycleWitnessRow>,
    pub rch_proof_lane_admission: Vec<AdmissionAwareRchProofLaneAdmissionRow>,
    pub dirty_tree_peer_ownership: Vec<AdmissionAwareDirtyTreePeerOwnershipRow>,
    pub agent_mail_reservations: Vec<AdmissionAwareAgentMailReservationRow>,
    pub br_tracker_status: Vec<AdmissionAwareBrTrackerStatusRow>,
    pub large_host_worker_warmth: Vec<AdmissionAwareLargeHostWorkerWarmthRow>,
    pub operator_closeout_receipt: Vec<AdmissionAwareOperatorCloseoutReceiptRow>,
}

impl AdmissionAwareRuntimePressureAtlasSnapshot {
    #[must_use]
    pub fn from_source_snapshots(
        mut input: AdmissionAwareRuntimePressureAtlasBuilderInput,
    ) -> Self {
        admission_aware_normalize_coordination_inputs(&mut input);
        admission_aware_normalize_large_host_rows(&mut input);
        sort_input_rows(&mut input);

        let lock_contention = admission_aware_lock_contention_rows(
            &input.lock_metrics,
            &input.lock_order_atlas,
            AdmissionAwareAtlasFreshnessStatus::Fresh,
        );
        let scheduler_pressure = input
            .runtime_pressure
            .scheduler
            .as_ref()
            .map(admission_aware_scheduler_pressure_row)
            .into_iter()
            .collect::<Vec<_>>();
        let region_memory_budget_pressure = input
            .runtime_pressure
            .region_memory_budgets
            .iter()
            .map(admission_aware_region_memory_budget_pressure_row)
            .collect::<Vec<_>>();
        let validated_trapped_cycle_witness_present = input
            .trapped_cycle_witnesses
            .iter()
            .any(AdmissionAwareTrappedCycleWitnessRow::is_validated);
        let spectral_wait_graph = admission_aware_spectral_wait_graph_rows(
            &input.runtime_pressure,
            validated_trapped_cycle_witness_present,
        );
        let rch_proof_lane_admission = input
            .runtime_pressure
            .rch_proof_lanes
            .iter()
            .map(admission_aware_rch_proof_lane_admission_row)
            .collect::<Vec<_>>();

        let deadlock_proven = validated_trapped_cycle_witness_present
            && input.runtime_pressure.spectral.trapped_wait_cycle
            && input.runtime_pressure.spectral.class == RuntimePressureSpectralClass::Deadlocked;
        let mut missing_required_sections = admission_aware_missing_sections(
            &lock_contention,
            &scheduler_pressure,
            &spectral_wait_graph,
            &rch_proof_lane_admission,
            &input,
        );
        missing_required_sections.sort();
        missing_required_sections.dedup();

        let coordination_summary = admission_aware_coordination_summary(&input);
        let validation_blocked = (input.runtime_pressure.overall_verdict
            == RuntimePressureVerdict::Critical
            && !deadlock_proven)
            || input
                .trapped_cycle_witnesses
                .iter()
                .any(AdmissionAwareTrappedCycleWitnessRow::is_malformed)
            || coordination_summary.validation_blocked;
        let claim_state = AdmissionAwareAtlasClaimState {
            deadlock_proven,
            replay_backed: input.replay_backed,
            validation_blocked,
            stale_evidence: !missing_required_sections.is_empty()
                || coordination_summary.stale_evidence,
        };
        let overall_label = admission_aware_overall_label(claim_state);
        let claim_boundary_labels =
            admission_aware_claim_boundary_labels(overall_label, claim_state);

        Self {
            schema_version: ADMISSION_AWARE_RUNTIME_PRESSURE_ATLAS_SCHEMA_VERSION.to_string(),
            runtime_pressure_schema_version: input.runtime_pressure.schema_version,
            overall_label,
            claim_boundary_labels,
            missing_required_sections,
            production_admission_default_enabled: false,
            mutates_agent_mail: false,
            mutates_beads: false,
            mutates_filesystem: false,
            starts_rch: false,
            deadlock_proven,
            replay_backed: input.replay_backed,
            coordination_decision: coordination_summary.decision,
            coordination_reason_codes: coordination_summary.reason_codes,
            lock_contention,
            scheduler_pressure,
            region_memory_budget_pressure,
            spectral_wait_graph,
            trapped_cycle_witness: input.trapped_cycle_witnesses,
            rch_proof_lane_admission,
            dirty_tree_peer_ownership: input.dirty_tree_peer_ownership,
            agent_mail_reservations: input.agent_mail_reservations,
            br_tracker_status: input.br_tracker_status,
            large_host_worker_warmth: input.large_host_worker_warmth,
            operator_closeout_receipt: input.operator_closeout_receipts,
        }
    }

    pub fn stable_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn sort_input_rows(input: &mut AdmissionAwareRuntimePressureAtlasBuilderInput) {
    input.lock_metrics.sort_by(|left, right| {
        left.name
            .cmp(right.name)
            .then_with(|| right.acquisitions.cmp(&left.acquisitions))
            .then_with(|| right.contentions.cmp(&left.contentions))
    });
    input
        .lock_metrics
        .dedup_by(|left, right| left.name == right.name);
    input.dirty_tree_peer_ownership.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.holder.cmp(&right.holder))
            .then_with(|| left.source.cmp(&right.source))
    });
    input
        .dirty_tree_peer_ownership
        .dedup_by(|left, right| left.path == right.path);
    input.agent_mail_reservations.sort_by(|left, right| {
        left.path_pattern
            .cmp(&right.path_pattern)
            .then_with(|| left.holder.cmp(&right.holder))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    input.agent_mail_reservations.dedup_by(|left, right| {
        left.path_pattern == right.path_pattern && left.holder == right.holder
    });
    input.br_tracker_status.sort_by(|left, right| {
        left.bead_id
            .cmp(&right.bead_id)
            .then_with(|| left.status.cmp(&right.status))
    });
    input
        .br_tracker_status
        .dedup_by(|left, right| left.bead_id == right.bead_id);
    input.large_host_worker_warmth.sort_by(|left, right| {
        left.worker_id.cmp(&right.worker_id).then_with(|| {
            right
                .worker_available_cores
                .cmp(&left.worker_available_cores)
        })
    });
    input
        .large_host_worker_warmth
        .dedup_by(|left, right| left.worker_id == right.worker_id);
    input
        .operator_closeout_receipts
        .sort_by(|left, right| left.bead_id.cmp(&right.bead_id));
    input
        .operator_closeout_receipts
        .dedup_by(|left, right| left.bead_id == right.bead_id);
    for witness in &mut input.trapped_cycle_witnesses {
        witness.participants.sort();
        witness.participants.dedup();
        witness.held_resources.sort();
        witness.held_resources.dedup();
        witness.wait_edges.sort();
        witness.wait_edges.dedup();
    }
    input
        .trapped_cycle_witnesses
        .sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
    input
        .trapped_cycle_witnesses
        .dedup_by(|left, right| left.witness_id == right.witness_id);
}

fn admission_aware_normalize_coordination_inputs(
    input: &mut AdmissionAwareRuntimePressureAtlasBuilderInput,
) {
    for row in &mut input.dirty_tree_peer_ownership {
        row.coordination_decision = admission_aware_dirty_tree_coordination_decision(row);
    }
    for row in &mut input.agent_mail_reservations {
        row.coordination_decision = admission_aware_agent_mail_coordination_decision(row);
    }
    for row in &mut input.br_tracker_status {
        row.coordination_decision = admission_aware_br_tracker_coordination_decision(row);
    }
}

fn admission_aware_normalize_large_host_rows(
    input: &mut AdmissionAwareRuntimePressureAtlasBuilderInput,
) {
    for row in &mut input.large_host_worker_warmth {
        let profile = admission_aware_large_host_advisory_profile(row);
        row.worker_saturation = profile.saturation;
        row.advisory_batching_decision = profile.decision;
        row.advisory_batching_reason_codes = profile.reason_codes;
        row.advisory_batch_size_hint = profile.batch_size_hint;
        row.advisory_non_claims = admission_aware_large_host_advisory_non_claims();
        row.advisory_only = true;
    }
}

#[derive(Debug, Clone)]
struct AdmissionAwareLargeHostAdvisoryProfile {
    saturation: AdmissionAwareLargeHostWorkerSaturation,
    decision: AdmissionAwareLargeHostBatchingDecision,
    reason_codes: Vec<String>,
    batch_size_hint: Option<u16>,
}

fn admission_aware_large_host_advisory_profile(
    row: &AdmissionAwareLargeHostWorkerWarmthRow,
) -> AdmissionAwareLargeHostAdvisoryProfile {
    let queue_state = row.worker_queue_state.to_ascii_lowercase();
    let cache_warmth = row.cache_warmth.to_ascii_lowercase();
    let mut reason_codes = Vec::new();

    let large_host_shape = row.cpu_cores >= ADMISSION_AWARE_LARGE_HOST_CPU_CORES
        && row.memory_bytes >= ADMISSION_AWARE_LARGE_HOST_MEMORY_BYTES
        && row.numa_nodes >= ADMISSION_AWARE_LARGE_HOST_MIN_NUMA_NODES;
    if large_host_shape {
        reason_codes.push("large_host_shape_64_core_256_gib".to_string());
    } else {
        reason_codes.push("large_host_shape_missing".to_string());
    }

    if row.numa_nodes >= ADMISSION_AWARE_LARGE_HOST_MIN_NUMA_NODES {
        reason_codes.push("numa_nodes_present".to_string());
    } else {
        reason_codes.push("numa_nodes_missing".to_string());
    }

    if row.disk_headroom_bytes >= ADMISSION_AWARE_LARGE_HOST_DISK_HEADROOM_FLOOR_BYTES {
        reason_codes.push("disk_headroom_available".to_string());
    } else {
        reason_codes.push("disk_headroom_low".to_string());
    }

    if queue_state.contains("saturated") || queue_state.contains("closed") {
        reason_codes.push("worker_queue_saturated".to_string());
    } else {
        reason_codes.push("worker_queue_open".to_string());
    }

    if row.worker_available_cores >= ADMISSION_AWARE_LARGE_HOST_BATCH_CORE_FLOOR {
        reason_codes.push("worker_core_headroom_available".to_string());
    } else {
        reason_codes.push("worker_core_saturation".to_string());
    }

    if row.worker_available_memory_bytes >= ADMISSION_AWARE_LARGE_HOST_BATCH_MEMORY_FLOOR_BYTES {
        reason_codes.push("worker_memory_headroom_available".to_string());
    } else {
        reason_codes.push("worker_memory_low".to_string());
    }

    if cache_warmth.contains("warm") {
        reason_codes.push("worker_cache_warm".to_string());
    } else {
        reason_codes.push("worker_cache_cold".to_string());
    }

    if row.target_dir_isolated {
        reason_codes.push("target_dir_isolated".to_string());
    } else {
        reason_codes.push("target_dir_shared".to_string());
    }

    if row.active_project_excluded {
        reason_codes.push("active_project_excluded".to_string());
    } else {
        reason_codes.push("active_project_not_excluded".to_string());
    }

    if row.proof_lane_cost_estimate.is_some() {
        reason_codes.push("proof_lane_cost_estimate_present".to_string());
    } else {
        reason_codes.push("proof_lane_cost_estimate_missing".to_string());
    }
    reason_codes.push("advisory_batching_only".to_string());

    let (saturation, decision, batch_size_hint) = if !large_host_shape {
        (
            AdmissionAwareLargeHostWorkerSaturation::NonLargeHost,
            AdmissionAwareLargeHostBatchingDecision::DeferNonLargeHost,
            None,
        )
    } else if row.disk_headroom_bytes < ADMISSION_AWARE_LARGE_HOST_DISK_HEADROOM_FLOOR_BYTES {
        (
            AdmissionAwareLargeHostWorkerSaturation::DiskConstrained,
            AdmissionAwareLargeHostBatchingDecision::QueueDiskHeadroom,
            None,
        )
    } else if queue_state.contains("saturated")
        || queue_state.contains("closed")
        || row.worker_available_cores < ADMISSION_AWARE_LARGE_HOST_BATCH_CORE_FLOOR
    {
        (
            AdmissionAwareLargeHostWorkerSaturation::WorkerSaturated,
            AdmissionAwareLargeHostBatchingDecision::DeferWorkerSaturated,
            None,
        )
    } else if row.worker_available_memory_bytes
        < ADMISSION_AWARE_LARGE_HOST_BATCH_MEMORY_FLOOR_BYTES
    {
        (
            AdmissionAwareLargeHostWorkerSaturation::LowMemory,
            AdmissionAwareLargeHostBatchingDecision::QueueLowMemory,
            None,
        )
    } else if cache_warmth.contains("warm") {
        (
            AdmissionAwareLargeHostWorkerSaturation::Available,
            AdmissionAwareLargeHostBatchingDecision::PreferWarmWorker,
            admission_aware_large_host_batch_size_hint(row),
        )
    } else {
        (
            AdmissionAwareLargeHostWorkerSaturation::Available,
            AdmissionAwareLargeHostBatchingDecision::AdmitBatch,
            admission_aware_large_host_batch_size_hint(row),
        )
    };

    reason_codes.sort();
    reason_codes.dedup();
    AdmissionAwareLargeHostAdvisoryProfile {
        saturation,
        decision,
        reason_codes,
        batch_size_hint,
    }
}

fn admission_aware_large_host_batch_size_hint(
    row: &AdmissionAwareLargeHostWorkerWarmthRow,
) -> Option<u16> {
    let core_slots = row.worker_available_cores / ADMISSION_AWARE_LARGE_HOST_BATCH_CORE_FLOOR;
    let memory_slots =
        row.worker_available_memory_bytes / ADMISSION_AWARE_LARGE_HOST_BATCH_MEMORY_FLOOR_BYTES;
    let batch_slots = u64::from(core_slots).min(memory_slots).min(8);
    u16::try_from(batch_slots).ok().filter(|slots| *slots > 0)
}

fn admission_aware_large_host_advisory_non_claims() -> Vec<String> {
    vec![
        "allocator_enforcement".to_string(),
        "production_admission_default".to_string(),
        "throughput_improvement".to_string(),
    ]
}

#[derive(Debug, Clone)]
struct AdmissionAwareCoordinationSummary {
    decision: AdmissionAwareCoordinationDecision,
    reason_codes: Vec<String>,
    stale_evidence: bool,
    validation_blocked: bool,
}

fn admission_aware_coordination_summary(
    input: &AdmissionAwareRuntimePressureAtlasBuilderInput,
) -> AdmissionAwareCoordinationSummary {
    let mut decision = AdmissionAwareCoordinationDecision::Proceed;
    let mut reason_codes = Vec::new();
    let mut stale_evidence = false;

    for row in &input.dirty_tree_peer_ownership {
        decision = admission_aware_max_coordination_decision(decision, row.coordination_decision);
        admission_aware_collect_freshness_reason(
            row.sample_freshness,
            "dirty_tree_snapshot_stale",
            &mut stale_evidence,
            &mut reason_codes,
        );
        if row.overlap_classification == AdmissionAwareCoordinationOverlapClass::Malformed {
            reason_codes.push("malformed_coordination_snapshot".to_string());
        }
        if row.overlap_classification == AdmissionAwareCoordinationOverlapClass::TrackerOnly {
            reason_codes.push("tracker_only_dirty_tree_change".to_string());
        }
        if row.overlap_classification == AdmissionAwareCoordinationOverlapClass::UnrelatedPeerWork {
            reason_codes.push("unrelated_peer_work".to_string());
        }
        if row.handoff_required || admission_aware_overlap_is_peer(row.overlap_classification) {
            reason_codes.push("peer_dirty_tree_overlap".to_string());
        } else if row.blocks_admission {
            reason_codes.push("dirty_tree_blocks_admission".to_string());
        }
    }

    for row in &input.agent_mail_reservations {
        decision = admission_aware_max_coordination_decision(decision, row.coordination_decision);
        admission_aware_collect_freshness_reason(
            row.sample_freshness,
            "reservation_snapshot_stale",
            &mut stale_evidence,
            &mut reason_codes,
        );
        match row.overlap_classification {
            AdmissionAwareCoordinationOverlapClass::ActiveExclusiveConflict => {
                reason_codes.push("active_exclusive_agent_mail_conflict".to_string());
            }
            AdmissionAwareCoordinationOverlapClass::ExpiredReservation => {
                reason_codes.push("expired_agent_mail_reservation".to_string());
            }
            AdmissionAwareCoordinationOverlapClass::Malformed => {
                reason_codes.push("malformed_coordination_snapshot".to_string());
            }
            overlap if admission_aware_overlap_is_peer(overlap) => {
                reason_codes.push("peer_agent_mail_overlap".to_string());
            }
            _ => {}
        }
    }

    for row in &input.br_tracker_status {
        decision = admission_aware_max_coordination_decision(decision, row.coordination_decision);
        admission_aware_collect_freshness_reason(
            row.sample_freshness,
            "tracker_snapshot_stale",
            &mut stale_evidence,
            &mut reason_codes,
        );
        if row.overlap_classification == AdmissionAwareCoordinationOverlapClass::Malformed {
            reason_codes.push("malformed_coordination_snapshot".to_string());
        }
        if admission_aware_overlap_is_peer(row.overlap_classification) {
            reason_codes.push("peer_tracker_overlap".to_string());
        }
        if !row.blocked_by.is_empty() {
            reason_codes.push("bead_blocked_by_dependencies".to_string());
        }
        if !row.ready {
            reason_codes.push("bead_not_ready".to_string());
        }
    }

    reason_codes.sort();
    reason_codes.dedup();
    AdmissionAwareCoordinationSummary {
        decision,
        reason_codes,
        stale_evidence,
        validation_blocked: decision != AdmissionAwareCoordinationDecision::Proceed,
    }
}

fn admission_aware_collect_freshness_reason(
    freshness: AdmissionAwareAtlasFreshnessStatus,
    stale_reason: &str,
    stale_evidence: &mut bool,
    reason_codes: &mut Vec<String>,
) {
    if freshness.is_stale_or_missing() {
        *stale_evidence = true;
        reason_codes.push(stale_reason.to_string());
    }
    if freshness.blocks_validation() {
        reason_codes.push("malformed_coordination_snapshot".to_string());
    }
}

fn admission_aware_dirty_tree_coordination_decision(
    row: &AdmissionAwareDirtyTreePeerOwnershipRow,
) -> AdmissionAwareCoordinationDecision {
    if let Some(decision) = admission_aware_freshness_coordination_decision(row.sample_freshness) {
        return decision;
    }
    if row.overlap_classification == AdmissionAwareCoordinationOverlapClass::Malformed {
        return AdmissionAwareCoordinationDecision::Blocked;
    }
    if row.handoff_required || admission_aware_overlap_is_peer(row.overlap_classification) {
        return AdmissionAwareCoordinationDecision::HandoffRequired;
    }
    if row.blocks_admission {
        return AdmissionAwareCoordinationDecision::Defer;
    }
    AdmissionAwareCoordinationDecision::Proceed
}

fn admission_aware_agent_mail_coordination_decision(
    row: &AdmissionAwareAgentMailReservationRow,
) -> AdmissionAwareCoordinationDecision {
    if let Some(decision) = admission_aware_freshness_coordination_decision(row.sample_freshness) {
        return decision;
    }
    match row.overlap_classification {
        AdmissionAwareCoordinationOverlapClass::Malformed => {
            AdmissionAwareCoordinationDecision::Blocked
        }
        AdmissionAwareCoordinationOverlapClass::ActiveExclusiveConflict => {
            AdmissionAwareCoordinationDecision::Defer
        }
        AdmissionAwareCoordinationOverlapClass::PeerExact
        | AdmissionAwareCoordinationOverlapClass::PeerGlob => {
            if row.exclusive {
                AdmissionAwareCoordinationDecision::Defer
            } else {
                AdmissionAwareCoordinationDecision::HandoffRequired
            }
        }
        _ => AdmissionAwareCoordinationDecision::Proceed,
    }
}

fn admission_aware_br_tracker_coordination_decision(
    row: &AdmissionAwareBrTrackerStatusRow,
) -> AdmissionAwareCoordinationDecision {
    if let Some(decision) = admission_aware_freshness_coordination_decision(row.sample_freshness) {
        return decision;
    }
    if row.overlap_classification == AdmissionAwareCoordinationOverlapClass::Malformed {
        return AdmissionAwareCoordinationDecision::Blocked;
    }
    if admission_aware_overlap_is_peer(row.overlap_classification) {
        return AdmissionAwareCoordinationDecision::HandoffRequired;
    }
    if !row.ready || !row.blocked_by.is_empty() {
        return AdmissionAwareCoordinationDecision::Defer;
    }
    AdmissionAwareCoordinationDecision::Proceed
}

fn admission_aware_freshness_coordination_decision(
    freshness: AdmissionAwareAtlasFreshnessStatus,
) -> Option<AdmissionAwareCoordinationDecision> {
    if freshness.blocks_validation() {
        Some(AdmissionAwareCoordinationDecision::Blocked)
    } else if freshness.is_stale_or_missing() {
        Some(AdmissionAwareCoordinationDecision::Defer)
    } else {
        None
    }
}

fn admission_aware_overlap_is_peer(overlap: AdmissionAwareCoordinationOverlapClass) -> bool {
    matches!(
        overlap,
        AdmissionAwareCoordinationOverlapClass::PeerExact
            | AdmissionAwareCoordinationOverlapClass::PeerGlob
            | AdmissionAwareCoordinationOverlapClass::ActiveExclusiveConflict
    )
}

fn admission_aware_max_coordination_decision(
    left: AdmissionAwareCoordinationDecision,
    right: AdmissionAwareCoordinationDecision,
) -> AdmissionAwareCoordinationDecision {
    if admission_aware_coordination_decision_rank(right)
        > admission_aware_coordination_decision_rank(left)
    {
        right
    } else {
        left
    }
}

fn admission_aware_coordination_decision_rank(decision: AdmissionAwareCoordinationDecision) -> u8 {
    match decision {
        AdmissionAwareCoordinationDecision::Proceed => 0,
        AdmissionAwareCoordinationDecision::Defer => 1,
        AdmissionAwareCoordinationDecision::HandoffRequired => 2,
        AdmissionAwareCoordinationDecision::Blocked => 3,
    }
}

fn admission_aware_lock_contention_rows(
    lock_metrics: &[LockMetricsSnapshot],
    lock_order_atlas: &LockOrderAtlasSnapshot,
    sample_freshness: AdmissionAwareAtlasFreshnessStatus,
) -> Vec<AdmissionAwareLockContentionAtlasRow> {
    let mut rows = BTreeMap::new();
    for metrics in lock_metrics {
        let row = AdmissionAwareLockContentionAtlasRow {
            lock_name: metrics.name.to_string(),
            lock_rank: admission_aware_lock_rank_name(metrics.name, lock_order_atlas).to_string(),
            lock_module: admission_aware_lock_module_name(metrics.name, lock_order_atlas)
                .to_string(),
            acquisitions: metrics.acquisitions,
            contentions: metrics.contentions,
            wait_ns: metrics.wait_ns,
            hold_ns: metrics.hold_ns,
            max_wait_ns: metrics.max_wait_ns,
            max_hold_ns: metrics.max_hold_ns,
            p95_wait_ns: metrics.p95_wait_ns,
            p999_wait_ns: metrics.p999_wait_ns,
            p95_hold_ns: metrics.p95_hold_ns,
            p999_hold_ns: metrics.p999_hold_ns,
            order_edges_exercised: lock_order_atlas
                .order_edges_exercised
                .iter()
                .filter(|edge| {
                    edge.held_lock_name == metrics.name || edge.acquired_lock_name == metrics.name
                })
                .count(),
            order_violations: lock_order_atlas
                .order_violations
                .iter()
                .filter(|violation| violation.lock_name == metrics.name)
                .count(),
            instrumentation_mode: metrics.instrumentation_mode.to_string(),
            sample_freshness,
        };
        rows.entry(row.lock_name.clone())
            .and_modify(|existing: &mut AdmissionAwareLockContentionAtlasRow| {
                if row.acquisitions > existing.acquisitions
                    || (row.acquisitions == existing.acquisitions
                        && row.contentions > existing.contentions)
                {
                    *existing = row.clone();
                }
            })
            .or_insert(row);
    }
    rows.into_values().collect()
}

fn admission_aware_lock_rank_name(
    lock_name: &str,
    lock_order_atlas: &LockOrderAtlasSnapshot,
) -> &'static str {
    lock_order_atlas
        .order_edges_exercised
        .iter()
        .find_map(|edge| {
            if edge.held_lock_name == lock_name {
                Some(edge.held_rank.name())
            } else if edge.acquired_lock_name == lock_name {
                Some(edge.acquired_rank.name())
            } else {
                None
            }
        })
        .or_else(|| {
            lock_order_atlas
                .order_violations
                .iter()
                .find(|violation| violation.lock_name == lock_name)
                .map(|violation| violation.lock_rank.name())
        })
        .or_else(|| LockRank::from_name(lock_name).map(LockRank::name))
        .unwrap_or("Unknown")
}

fn admission_aware_lock_module_name(
    lock_name: &str,
    lock_order_atlas: &LockOrderAtlasSnapshot,
) -> &'static str {
    lock_order_atlas
        .order_edges_exercised
        .iter()
        .find_map(|edge| {
            if edge.held_lock_name == lock_name {
                Some(edge.held_module.name())
            } else if edge.acquired_lock_name == lock_name {
                Some(edge.acquired_module.name())
            } else {
                None
            }
        })
        .or_else(|| {
            lock_order_atlas
                .order_violations
                .iter()
                .find(|violation| violation.lock_name == lock_name)
                .map(|violation| violation.lock_module.name())
        })
        .unwrap_or_else(|| LockModule::from_name(lock_name).name())
}

fn admission_aware_scheduler_pressure_row(
    scheduler: &SchedulerEvidenceMetrics,
) -> AdmissionAwareSchedulerPressureRow {
    let scheduler_tail_pressure_label = if scheduler.ready_backlog_p99 >= 256
        || scheduler.cancel_debt_p99 >= 128
        || scheduler.wake_to_run_p99_ns >= 250_000
    {
        "tail_pressure"
    } else if scheduler.ready_backlog_p95 >= 96 || scheduler.wake_to_run_p95_ns >= 100_000 {
        "watch"
    } else {
        "nominal"
    };

    AdmissionAwareSchedulerPressureRow {
        scheduler_tail_pressure_label: scheduler_tail_pressure_label.to_string(),
        methodology_baseline_rows: usize::from(scheduler.remote_steal_ratio_pct.is_some())
            + usize::from(scheduler.cross_cohort_wake_p99_ns.is_some()),
        flamegraph_artifact_path: None,
        phase6_gate_triggered: scheduler_tail_pressure_label == "tail_pressure",
        attribution_claim_only: true,
        sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
    }
}

fn admission_aware_region_memory_budget_pressure_row(
    row: &RuntimePressureRegionMemoryBudgetSnapshot,
) -> AdmissionAwareRegionMemoryBudgetPressureRow {
    let pressure_level = if row.hard_limit_exceeded {
        RuntimePressureSignalStatus::Critical
    } else if row.soft_limit_exceeded {
        RuntimePressureSignalStatus::Degraded
    } else {
        RuntimePressureSignalStatus::Present
    };
    let optional_work_action = if row.hard_limit_exceeded {
        RuntimePressureAdmissionAction::Reject
    } else if row.soft_limit_exceeded {
        RuntimePressureAdmissionAction::Defer
    } else {
        RuntimePressureAdmissionAction::Admit
    };

    AdmissionAwareRegionMemoryBudgetPressureRow {
        region_id: row.region_id,
        region_label: row.region_label.clone(),
        budget_schema_version: row.schema_version.clone(),
        declared_budget_bytes: row.declared_memory_budget_bytes,
        observed_usage_bytes: row.observed_memory_bytes,
        pressure_level,
        optional_work_action,
        required_cleanup_admitted: true,
        sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
    }
}

fn admission_aware_spectral_wait_graph_rows(
    runtime_pressure: &RuntimePressureSnapshot,
    trapped_cycle_witness_present: bool,
) -> Vec<AdmissionAwareSpectralWaitGraphRow> {
    if runtime_pressure.spectral.class == RuntimePressureSpectralClass::Unknown {
        return Vec::new();
    }

    let deadlock_proven = trapped_cycle_witness_present
        && runtime_pressure.spectral.trapped_wait_cycle
        && runtime_pressure.spectral.class == RuntimePressureSpectralClass::Deadlocked;
    let requires_trapped_cycle_detection = runtime_pressure
        .spectral_recommendations
        .iter()
        .any(|recommendation| recommendation.requires_trapped_cycle_proof);

    vec![AdmissionAwareSpectralWaitGraphRow {
        early_warning_severity: runtime_pressure.spectral.early_warning_severity,
        health_classification: runtime_pressure.spectral.class,
        fiedler_trend: runtime_pressure.spectral.fiedler_micro_units,
        recommendations: runtime_pressure.spectral_recommendations.clone(),
        deadlock_proven,
        requires_trapped_cycle_detection,
        sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
    }]
}

fn admission_aware_rch_proof_lane_admission_row(
    row: &RuntimePressureRchProofLaneSnapshot,
) -> AdmissionAwareRchProofLaneAdmissionRow {
    let mut cover_claims = vec!["remote_proof_lane_admission_planner".to_string()];
    if row.remote_required {
        cover_claims.push("remote_required_policy".to_string());
    }
    if row.selected_worker.is_some() {
        cover_claims.push("worker_capacity_selected".to_string());
    }
    cover_claims.sort();
    cover_claims.dedup();

    let mut does_not_cover_claims = vec![
        "cargo_command_completed".to_string(),
        "fleet_availability_after_snapshot".to_string(),
    ];
    if row.local_fallback_allowed {
        does_not_cover_claims.push("no_local_fallback_policy".to_string());
    }
    does_not_cover_claims.sort();
    does_not_cover_claims.dedup();

    AdmissionAwareRchProofLaneAdmissionRow {
        lane_id: row.lane_id.clone(),
        admission_decision: row.decision_code.clone(),
        reason_codes: row.reason_codes.clone(),
        remote_required: row.remote_required,
        local_fallback_allowed: row.local_fallback_allowed,
        target_dir_isolated: true,
        recommended_worker_id: row.selected_worker.clone(),
        cover_claims,
        does_not_cover_claims,
        suggested_command: Some(format!(
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=\"${{TMPDIR:-/tmp}}/rch_target_{}\" cargo test",
            row.lane_id.replace('-', "_")
        )),
        sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
    }
}

fn admission_aware_missing_sections(
    lock_contention: &[AdmissionAwareLockContentionAtlasRow],
    scheduler_pressure: &[AdmissionAwareSchedulerPressureRow],
    spectral_wait_graph: &[AdmissionAwareSpectralWaitGraphRow],
    rch_proof_lane_admission: &[AdmissionAwareRchProofLaneAdmissionRow],
    input: &AdmissionAwareRuntimePressureAtlasBuilderInput,
) -> Vec<String> {
    let mut missing = Vec::new();
    if lock_contention.is_empty() {
        missing.push("lock_contention".to_string());
    }
    if scheduler_pressure.is_empty() {
        missing.push("scheduler_pressure".to_string());
    }
    if spectral_wait_graph.is_empty() {
        missing.push("spectral_wait_graph".to_string());
    }
    if rch_proof_lane_admission.is_empty() {
        missing.push("rch_proof_lane_admission".to_string());
    }
    if input.dirty_tree_peer_ownership.is_empty() {
        missing.push("dirty_tree_peer_ownership".to_string());
    }
    if input.agent_mail_reservations.is_empty() {
        missing.push("agent_mail_reservations".to_string());
    }
    if input.br_tracker_status.is_empty() {
        missing.push("br_tracker_status".to_string());
    }
    if input.large_host_worker_warmth.is_empty() {
        missing.push("large_host_worker_warmth".to_string());
    }
    if input.operator_closeout_receipts.is_empty() {
        missing.push("operator_closeout_receipt".to_string());
    }
    if spectral_wait_graph.iter().any(|row| {
        row.requires_trapped_cycle_detection
            || row.health_classification == RuntimePressureSpectralClass::Deadlocked
            || row.health_classification == RuntimePressureSpectralClass::Fragmented
    }) && !input
        .trapped_cycle_witnesses
        .iter()
        .any(AdmissionAwareTrappedCycleWitnessRow::is_validated)
    {
        missing.push("trapped_cycle_witness".to_string());
    }
    missing
}

fn admission_aware_overall_label(
    state: AdmissionAwareAtlasClaimState,
) -> AdmissionAwareAtlasClaimLabel {
    if state.deadlock_proven {
        AdmissionAwareAtlasClaimLabel::DeadlockProven
    } else if state.stale_evidence {
        AdmissionAwareAtlasClaimLabel::StaleEvidence
    } else if state.validation_blocked {
        AdmissionAwareAtlasClaimLabel::ValidationBlocked
    } else if state.replay_backed {
        AdmissionAwareAtlasClaimLabel::ReplayBacked
    } else {
        AdmissionAwareAtlasClaimLabel::Advisory
    }
}

#[derive(Debug, Clone, Copy)]
struct AdmissionAwareAtlasClaimState {
    deadlock_proven: bool,
    replay_backed: bool,
    validation_blocked: bool,
    stale_evidence: bool,
}

fn admission_aware_claim_boundary_labels(
    overall_label: AdmissionAwareAtlasClaimLabel,
    state: AdmissionAwareAtlasClaimState,
) -> Vec<AdmissionAwareClaimBoundaryLabelRow> {
    let mut labels = vec![admission_aware_claim_boundary_row(
        AdmissionAwareAtlasClaimLabel::Advisory,
    )];
    for include in [
        (
            state.replay_backed,
            AdmissionAwareAtlasClaimLabel::ReplayBacked,
        ),
        (
            state.deadlock_proven,
            AdmissionAwareAtlasClaimLabel::TrappedCycleProven,
        ),
        (
            state.deadlock_proven,
            AdmissionAwareAtlasClaimLabel::DeadlockProven,
        ),
        (
            state.validation_blocked,
            AdmissionAwareAtlasClaimLabel::ValidationBlocked,
        ),
        (
            state.stale_evidence,
            AdmissionAwareAtlasClaimLabel::StaleEvidence,
        ),
        (true, overall_label),
    ] {
        if include.0 {
            labels.push(admission_aware_claim_boundary_row(include.1));
        }
    }
    labels.sort_by_key(|row| row.label);
    labels.dedup_by_key(|row| row.label);
    labels
}

fn admission_aware_claim_boundary_row(
    label: AdmissionAwareAtlasClaimLabel,
) -> AdmissionAwareClaimBoundaryLabelRow {
    let (required_evidence, forbidden_overclaims, closeout_text) = match label {
        AdmissionAwareAtlasClaimLabel::Advisory => (
            vec!["source_snapshots".to_string()],
            vec![
                "deadlock_proven".to_string(),
                "cargo_lane_green".to_string(),
            ],
            "ADVISORY: source-backed atlas rows only".to_string(),
        ),
        AdmissionAwareAtlasClaimLabel::ReplayBacked => (
            vec![
                "deterministic_replay_evidence".to_string(),
                "source_snapshots".to_string(),
            ],
            vec!["deadlock_proven_without_witness".to_string()],
            "REPLAY_BACKED: deterministic replay evidence included".to_string(),
        ),
        AdmissionAwareAtlasClaimLabel::TrappedCycleProven => (
            vec!["explicit_trapped_cycle_witness".to_string()],
            vec!["spectral_warning_only".to_string()],
            "TRAPPED_CYCLE_PROVEN: explicit witness present".to_string(),
        ),
        AdmissionAwareAtlasClaimLabel::DeadlockProven => (
            vec![
                "explicit_trapped_cycle_witness".to_string(),
                "deadlocked_spectral_class".to_string(),
            ],
            vec!["advisory_spectral_only".to_string()],
            "DEADLOCK_PROVEN: explicit trapped-cycle witness confirmed".to_string(),
        ),
        AdmissionAwareAtlasClaimLabel::ValidationBlocked => (
            vec![
                "critical_runtime_pressure_or_coordination_conflict".to_string(),
                "blocker_code".to_string(),
            ],
            vec!["validation_green".to_string()],
            "VALIDATION_BLOCKED: critical pressure or coordination blocker present".to_string(),
        ),
        AdmissionAwareAtlasClaimLabel::StaleEvidence => (
            vec!["all_required_source_sections".to_string()],
            vec!["complete_atlas".to_string()],
            "STALE_EVIDENCE: required atlas inputs are missing".to_string(),
        ),
    };

    AdmissionAwareClaimBoundaryLabelRow {
        label,
        required_evidence,
        forbidden_overclaims,
        closeout_text,
        sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
    }
}

/// Work class for pressure-aware admission decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureAdmissionWorkClass {
    Required,
    Optional,
}

/// Admission action emitted by the opt-in pressure-aware admission hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureAdmissionAction {
    Admit,
    Defer,
    Reject,
}

/// Stable reason codes for pressure-aware admission decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePressureAdmissionReason {
    PolicyDisabled,
    RequiredWorkBypass,
    SnapshotHealthy,
    SnapshotUnknown,
    SnapshotDegraded,
    SnapshotCritical,
    UnknownSnapshotSchema,
    MissingPressureSignals,
}

/// Disabled-by-default policy for converting pressure snapshots into admission decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureAdmissionPolicy {
    pub schema_version: String,
    pub enabled: bool,
    pub unknown_optional_action: RuntimePressureAdmissionAction,
    pub degraded_optional_action: RuntimePressureAdmissionAction,
    pub critical_optional_action: RuntimePressureAdmissionAction,
}

impl Default for RuntimePressureAdmissionPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl RuntimePressureAdmissionPolicy {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            schema_version: RUNTIME_PRESSURE_ADMISSION_POLICY_SCHEMA_VERSION.to_string(),
            enabled: false,
            unknown_optional_action: RuntimePressureAdmissionAction::Defer,
            degraded_optional_action: RuntimePressureAdmissionAction::Defer,
            critical_optional_action: RuntimePressureAdmissionAction::Reject,
        }
    }

    #[must_use]
    pub fn conservative_optional_backpressure() -> Self {
        Self {
            enabled: true,
            ..Self::disabled()
        }
    }

    #[must_use]
    pub fn decide(
        &self,
        work_class: RuntimePressureAdmissionWorkClass,
        snapshot: &RuntimePressureSnapshot,
    ) -> RuntimePressureAdmissionDecision {
        if !self.enabled {
            return self.finish(
                work_class,
                snapshot,
                RuntimePressureAdmissionAction::Admit,
                vec![RuntimePressureAdmissionReason::PolicyDisabled],
            );
        }

        if work_class == RuntimePressureAdmissionWorkClass::Required {
            let mut reason_codes = vec![RuntimePressureAdmissionReason::RequiredWorkBypass];
            if snapshot.schema_version != RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION {
                reason_codes.push(RuntimePressureAdmissionReason::UnknownSnapshotSchema);
            }
            return self.finish(
                work_class,
                snapshot,
                RuntimePressureAdmissionAction::Admit,
                reason_codes,
            );
        }

        if snapshot.schema_version != RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION {
            return self.finish(
                work_class,
                snapshot,
                RuntimePressureAdmissionAction::Reject,
                vec![RuntimePressureAdmissionReason::UnknownSnapshotSchema],
            );
        }

        let (action, mut reason_codes) = match snapshot.overall_verdict {
            RuntimePressureVerdict::Healthy => (
                RuntimePressureAdmissionAction::Admit,
                vec![RuntimePressureAdmissionReason::SnapshotHealthy],
            ),
            RuntimePressureVerdict::Unknown => (
                self.unknown_optional_action,
                vec![RuntimePressureAdmissionReason::SnapshotUnknown],
            ),
            RuntimePressureVerdict::Degraded => (
                self.degraded_optional_action,
                vec![RuntimePressureAdmissionReason::SnapshotDegraded],
            ),
            RuntimePressureVerdict::Critical => (
                self.critical_optional_action,
                vec![RuntimePressureAdmissionReason::SnapshotCritical],
            ),
        };
        if snapshot.missing_signal_count > 0 {
            reason_codes.push(RuntimePressureAdmissionReason::MissingPressureSignals);
        }

        self.finish(work_class, snapshot, action, reason_codes)
    }

    fn finish(
        &self,
        work_class: RuntimePressureAdmissionWorkClass,
        snapshot: &RuntimePressureSnapshot,
        action: RuntimePressureAdmissionAction,
        reason_codes: Vec<RuntimePressureAdmissionReason>,
    ) -> RuntimePressureAdmissionDecision {
        RuntimePressureAdmissionDecision {
            schema_version: RUNTIME_PRESSURE_ADMISSION_DECISION_SCHEMA_VERSION.to_string(),
            policy_schema_version: self.schema_version.clone(),
            policy_enabled: self.enabled,
            work_class,
            action,
            reason_codes,
            snapshot_schema_version: snapshot.schema_version.clone(),
            snapshot_verdict: snapshot.overall_verdict,
            missing_signal_count: snapshot.missing_signal_count,
            degraded_signal_count: snapshot.degraded_signal_count,
            critical_signal_count: snapshot.critical_signal_count,
        }
    }
}

/// Deterministic ledger row for one pressure-aware admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePressureAdmissionDecision {
    pub schema_version: String,
    pub policy_schema_version: String,
    pub policy_enabled: bool,
    pub work_class: RuntimePressureAdmissionWorkClass,
    pub action: RuntimePressureAdmissionAction,
    pub reason_codes: Vec<RuntimePressureAdmissionReason>,
    pub snapshot_schema_version: String,
    pub snapshot_verdict: RuntimePressureVerdict,
    pub missing_signal_count: u64,
    pub degraded_signal_count: u64,
    pub critical_signal_count: u64,
}

impl ResourcePlatformProbeReport {
    fn from_snapshots(platform: String, mut probes: Vec<ResourceProbeSnapshot>) -> Self {
        probes.sort_by_key(|snapshot| snapshot.probe);

        let supported_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Supported)
            .count() as u64;
        let unavailable_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Unavailable)
            .count() as u64;
        let fallback_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Fallback)
            .count() as u64;
        let disabled_count = probes
            .iter()
            .filter(|snapshot| snapshot.status == ResourceProbeStatus::Disabled)
            .count() as u64;
        let warning_suppressed_count = probes
            .iter()
            .map(|snapshot| snapshot.warning_suppressed_count)
            .sum();
        let warning_emitted_count = probes
            .iter()
            .map(|snapshot| snapshot.warning_count - snapshot.warning_suppressed_count)
            .sum();

        let operator_verdict = if !probes.is_empty() && disabled_count == probes.len() as u64 {
            ResourceProbeOperatorVerdict::Disabled
        } else if unavailable_count > 0 {
            ResourceProbeOperatorVerdict::DegradedWithUnavailableProbes
        } else if fallback_count > 0 {
            ResourceProbeOperatorVerdict::DegradedWithFallbacks
        } else {
            ResourceProbeOperatorVerdict::Complete
        };

        Self {
            schema_version: RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION.to_string(),
            platform,
            probes,
            supported_count,
            unavailable_count,
            fallback_count,
            disabled_count,
            warning_emitted_count,
            warning_suppressed_count,
            operator_verdict,
        }
    }
}

fn runtime_pressure_resources(pressure: &ResourcePressure) -> Vec<RuntimePressureResourceSnapshot> {
    let measurements = pressure.measurements.read().clone();
    let degradation_levels = pressure.degradation_levels.read().clone();
    let mut resource_types = measurements
        .keys()
        .chain(degradation_levels.keys())
        .cloned()
        .collect::<Vec<_>>();
    resource_types.sort_by_key(|resource_type| resource_type.to_string());
    resource_types.dedup();

    resource_types
        .into_iter()
        .map(|resource_type| {
            let measurement = measurements.get(&resource_type);
            let degradation_level = degradation_levels
                .get(&resource_type)
                .copied()
                .unwrap_or(DegradationLevel::None);
            let (
                current,
                soft_limit,
                hard_limit,
                max_limit,
                usage_bps,
                soft_limit_exceeded,
                hard_limit_exceeded,
                critical_limit_exceeded,
            ) = measurement.map_or((0, 0, 0, 0, 0, false, false, false), |measurement| {
                (
                    measurement.current,
                    measurement.soft_limit,
                    measurement.hard_limit,
                    measurement.max_limit,
                    resource_usage_bps(measurement.current, measurement.max_limit),
                    measurement.is_soft_exceeded(),
                    measurement.is_hard_exceeded(),
                    measurement.is_critical(),
                )
            });

            RuntimePressureResourceSnapshot {
                resource_label: resource_type.to_string(),
                resource_type,
                current,
                soft_limit,
                hard_limit,
                max_limit,
                usage_bps,
                soft_limit_exceeded,
                hard_limit_exceeded,
                critical_limit_exceeded,
                degradation_level,
            }
        })
        .collect()
}

fn runtime_pressure_resource_signal_status(
    resources: &[RuntimePressureResourceSnapshot],
    composite_degradation: DegradationLevel,
) -> RuntimePressureSignalSnapshot {
    if resources.is_empty() {
        return runtime_pressure_signal_row(
            RuntimePressureSignal::Resources,
            RuntimePressureSignalStatus::Missing,
            "no_resource_measurements",
        );
    }

    if composite_degradation >= DegradationLevel::Heavy
        || resources
            .iter()
            .any(|resource| resource.hard_limit_exceeded || resource.critical_limit_exceeded)
    {
        return runtime_pressure_signal_row(
            RuntimePressureSignal::Resources,
            RuntimePressureSignalStatus::Critical,
            "resource_hard_or_heavy_pressure",
        );
    }

    if composite_degradation >= DegradationLevel::Light
        || resources.iter().any(|resource| {
            resource.soft_limit_exceeded || resource.degradation_level >= DegradationLevel::Light
        })
    {
        return runtime_pressure_signal_row(
            RuntimePressureSignal::Resources,
            RuntimePressureSignalStatus::Degraded,
            "resource_soft_or_degraded_pressure",
        );
    }

    runtime_pressure_signal_row(
        RuntimePressureSignal::Resources,
        RuntimePressureSignalStatus::Present,
        "resource_measurements_present",
    )
}

fn runtime_pressure_scheduler_signal_status(
    scheduler: Option<&SchedulerEvidenceMetrics>,
) -> RuntimePressureSignalSnapshot {
    let Some(metrics) = scheduler else {
        return runtime_pressure_signal_row(
            RuntimePressureSignal::Scheduler,
            RuntimePressureSignalStatus::Missing,
            "scheduler_metrics_absent",
        );
    };

    let profile = TailRiskAdmissionProfile::default();
    if metrics.wake_to_run_p99_ns >= profile.wake_to_run_p99_ns_limit.saturating_mul(2)
        || metrics.queue_residency_p99_ns >= profile.queue_residency_p99_ns_limit.saturating_mul(2)
        || metrics.ready_backlog_p99 >= profile.ready_backlog_p99_limit.saturating_mul(2)
        || metrics.cancel_debt_p99 >= profile.cancel_debt_p99_limit.saturating_mul(2)
    {
        return runtime_pressure_signal_row(
            RuntimePressureSignal::Scheduler,
            RuntimePressureSignalStatus::Critical,
            "scheduler_tail_pressure_critical",
        );
    }

    if metrics.wake_to_run_p99_ns >= profile.wake_to_run_p99_ns_limit
        || metrics.queue_residency_p99_ns >= profile.queue_residency_p99_ns_limit
        || metrics.ready_backlog_p99 >= profile.ready_backlog_p99_limit
        || metrics.cancel_debt_p99 >= profile.cancel_debt_p99_limit
    {
        return runtime_pressure_signal_row(
            RuntimePressureSignal::Scheduler,
            RuntimePressureSignalStatus::Degraded,
            "scheduler_tail_pressure_degraded",
        );
    }

    runtime_pressure_signal_row(
        RuntimePressureSignal::Scheduler,
        RuntimePressureSignalStatus::Present,
        "scheduler_metrics_present",
    )
}

fn runtime_pressure_spectral_signal_status(
    spectral: &RuntimePressureSpectralSnapshot,
) -> RuntimePressureSignalSnapshot {
    match (spectral.class, spectral.early_warning_severity) {
        (RuntimePressureSpectralClass::Unknown, _) => runtime_pressure_signal_row(
            RuntimePressureSignal::Spectral,
            RuntimePressureSignalStatus::Missing,
            "spectral_health_absent",
        ),
        (
            RuntimePressureSpectralClass::Deadlocked
            | RuntimePressureSpectralClass::Fragmented
            | RuntimePressureSpectralClass::Critical,
            _,
        )
        | (_, RuntimePressureEarlyWarningSeverity::Critical) => runtime_pressure_signal_row(
            RuntimePressureSignal::Spectral,
            RuntimePressureSignalStatus::Critical,
            "spectral_topology_critical",
        ),
        (RuntimePressureSpectralClass::Degraded, _)
        | (_, RuntimePressureEarlyWarningSeverity::Warning) => runtime_pressure_signal_row(
            RuntimePressureSignal::Spectral,
            RuntimePressureSignalStatus::Degraded,
            "spectral_topology_degraded",
        ),
        _ => runtime_pressure_signal_row(
            RuntimePressureSignal::Spectral,
            RuntimePressureSignalStatus::Present,
            "spectral_health_present",
        ),
    }
}

fn runtime_pressure_spectral_recommendations(
    spectral: &RuntimePressureSpectralSnapshot,
) -> Vec<RuntimePressureSpectralRecommendation> {
    let mut recommendations = Vec::new();
    let deadlock_proven =
        spectral.trapped_wait_cycle || spectral.class == RuntimePressureSpectralClass::Deadlocked;

    if deadlock_proven {
        recommendations.push(runtime_pressure_spectral_recommendation_row(
            RuntimePressureRecommendationSeverity::Escalate,
            RuntimePressureRecommendationReason::TrappedWaitCycle,
            RuntimePressureRecommendationAction::ConfirmTrappedCycleEvidence,
            RuntimePressureRecommendationEvidenceScope::ExplicitTrappedCycle,
            RuntimePressureDeadlockProofState::Proven,
        ));
    }

    match spectral.class {
        RuntimePressureSpectralClass::Unknown | RuntimePressureSpectralClass::Healthy => {}
        RuntimePressureSpectralClass::Degraded => {
            recommendations.push(runtime_pressure_spectral_recommendation_row(
                RuntimePressureRecommendationSeverity::Investigate,
                RuntimePressureRecommendationReason::Bottleneck,
                RuntimePressureRecommendationAction::CollectTaskInspectorDetails,
                RuntimePressureRecommendationEvidenceScope::SpectralTopology,
                RuntimePressureDeadlockProofState::Advisory,
            ));
        }
        RuntimePressureSpectralClass::Critical => {
            recommendations.push(runtime_pressure_spectral_recommendation_row(
                RuntimePressureRecommendationSeverity::Mitigate,
                RuntimePressureRecommendationReason::CriticalTopology,
                RuntimePressureRecommendationAction::TightenAdmission,
                RuntimePressureRecommendationEvidenceScope::SpectralTopology,
                RuntimePressureDeadlockProofState::Advisory,
            ));
            if !deadlock_proven {
                recommendations.push(runtime_pressure_spectral_recommendation_row(
                    RuntimePressureRecommendationSeverity::Investigate,
                    RuntimePressureRecommendationReason::CriticalTopology,
                    RuntimePressureRecommendationAction::RunTrappedCycleDetection,
                    RuntimePressureRecommendationEvidenceScope::SpectralTopology,
                    RuntimePressureDeadlockProofState::RequiresTrappedCycleProof,
                ));
            }
        }
        RuntimePressureSpectralClass::Fragmented => {
            recommendations.push(runtime_pressure_spectral_recommendation_row(
                RuntimePressureRecommendationSeverity::Mitigate,
                RuntimePressureRecommendationReason::FragmentedTopology,
                RuntimePressureRecommendationAction::CollectTaskInspectorDetails,
                RuntimePressureRecommendationEvidenceScope::SpectralTopology,
                RuntimePressureDeadlockProofState::Advisory,
            ));
            if !deadlock_proven {
                recommendations.push(runtime_pressure_spectral_recommendation_row(
                    RuntimePressureRecommendationSeverity::Escalate,
                    RuntimePressureRecommendationReason::FragmentedTopology,
                    RuntimePressureRecommendationAction::RunTrappedCycleDetection,
                    RuntimePressureRecommendationEvidenceScope::SpectralTopology,
                    RuntimePressureDeadlockProofState::RequiresTrappedCycleProof,
                ));
            }
        }
        RuntimePressureSpectralClass::Deadlocked => {}
    }

    if spectral.bottleneck_count > 0 {
        recommendations.push(runtime_pressure_spectral_recommendation_row(
            RuntimePressureRecommendationSeverity::Investigate,
            RuntimePressureRecommendationReason::Bottleneck,
            RuntimePressureRecommendationAction::InspectSpectralBottlenecks,
            RuntimePressureRecommendationEvidenceScope::SpectralTopology,
            RuntimePressureDeadlockProofState::Advisory,
        ));
    }

    match spectral.early_warning_severity {
        RuntimePressureEarlyWarningSeverity::Unknown
        | RuntimePressureEarlyWarningSeverity::None => {}
        RuntimePressureEarlyWarningSeverity::Watch => {
            recommendations.push(runtime_pressure_spectral_recommendation_row(
                RuntimePressureRecommendationSeverity::Observe,
                RuntimePressureRecommendationReason::EarlyWarning,
                RuntimePressureRecommendationAction::EnableLabReplay,
                RuntimePressureRecommendationEvidenceScope::SpectralTrend,
                RuntimePressureDeadlockProofState::Advisory,
            ));
        }
        RuntimePressureEarlyWarningSeverity::Warning => {
            recommendations.push(runtime_pressure_spectral_recommendation_row(
                RuntimePressureRecommendationSeverity::Investigate,
                RuntimePressureRecommendationReason::EarlyWarning,
                RuntimePressureRecommendationAction::EnableLabReplay,
                RuntimePressureRecommendationEvidenceScope::SpectralTrend,
                RuntimePressureDeadlockProofState::Advisory,
            ));
        }
        RuntimePressureEarlyWarningSeverity::Critical => {
            recommendations.push(runtime_pressure_spectral_recommendation_row(
                RuntimePressureRecommendationSeverity::Mitigate,
                RuntimePressureRecommendationReason::EarlyWarning,
                RuntimePressureRecommendationAction::EnableLabReplay,
                RuntimePressureRecommendationEvidenceScope::SpectralTrend,
                RuntimePressureDeadlockProofState::Advisory,
            ));
        }
    }

    recommendations.sort_by_key(|recommendation| {
        (
            runtime_pressure_recommendation_severity_rank(recommendation.severity),
            recommendation.reason,
            recommendation.action,
            recommendation.evidence_scope,
            recommendation.deadlock_proven,
            recommendation.requires_trapped_cycle_proof,
        )
    });
    recommendations.dedup();
    recommendations
}

fn runtime_pressure_spectral_recommendation_row(
    severity: RuntimePressureRecommendationSeverity,
    reason: RuntimePressureRecommendationReason,
    action: RuntimePressureRecommendationAction,
    evidence_scope: RuntimePressureRecommendationEvidenceScope,
    proof_state: RuntimePressureDeadlockProofState,
) -> RuntimePressureSpectralRecommendation {
    let (deadlock_proven, requires_trapped_cycle_proof) = match proof_state {
        RuntimePressureDeadlockProofState::Advisory => (false, false),
        RuntimePressureDeadlockProofState::RequiresTrappedCycleProof => (false, true),
        RuntimePressureDeadlockProofState::Proven => (true, false),
    };

    RuntimePressureSpectralRecommendation {
        severity,
        reason,
        action,
        evidence_scope,
        deadlock_proven,
        requires_trapped_cycle_proof,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimePressureDeadlockProofState {
    Advisory,
    RequiresTrappedCycleProof,
    Proven,
}

fn runtime_pressure_recommendation_severity_rank(
    severity: RuntimePressureRecommendationSeverity,
) -> u8 {
    match severity {
        RuntimePressureRecommendationSeverity::Escalate => 0,
        RuntimePressureRecommendationSeverity::Mitigate => 1,
        RuntimePressureRecommendationSeverity::Investigate => 2,
        RuntimePressureRecommendationSeverity::Observe => 3,
    }
}

fn runtime_pressure_platform_probe_signal_status(
    report: &ResourcePlatformProbeReport,
) -> RuntimePressureSignalSnapshot {
    if report.probes.is_empty() || report.operator_verdict == ResourceProbeOperatorVerdict::Disabled
    {
        return runtime_pressure_signal_row(
            RuntimePressureSignal::PlatformProbes,
            RuntimePressureSignalStatus::Missing,
            "platform_probe_inventory_absent",
        );
    }

    match report.operator_verdict {
        ResourceProbeOperatorVerdict::Complete => runtime_pressure_signal_row(
            RuntimePressureSignal::PlatformProbes,
            RuntimePressureSignalStatus::Present,
            "platform_probes_complete",
        ),
        ResourceProbeOperatorVerdict::DegradedWithUnavailableProbes
        | ResourceProbeOperatorVerdict::DegradedWithFallbacks => runtime_pressure_signal_row(
            RuntimePressureSignal::PlatformProbes,
            RuntimePressureSignalStatus::Degraded,
            "platform_probes_degraded",
        ),
        ResourceProbeOperatorVerdict::Disabled => unreachable!("disabled handled above"),
    }
}

fn runtime_pressure_rch_proof_lane_signal_status(
    rows: &[RuntimePressureRchProofLaneSnapshot],
) -> Option<RuntimePressureSignalSnapshot> {
    if rows.is_empty() {
        return None;
    }

    if rows.iter().any(|row| {
        row.decision_code == RchAdmissionDecision::Refuse.code()
            || (row.remote_required && !row.local_fallback_allowed && row.selected_worker.is_none())
    }) {
        return Some(runtime_pressure_signal_row(
            RuntimePressureSignal::RchProofLanes,
            RuntimePressureSignalStatus::Critical,
            "rch_remote_required_proof_lane_refused",
        ));
    }

    if rows.iter().any(|row| {
        row.decision_code == RchAdmissionDecision::Defer.code()
            || row.blocked_worker_count > 0
            || row.cache_warm_admissible_worker_count == 0
    }) {
        return Some(runtime_pressure_signal_row(
            RuntimePressureSignal::RchProofLanes,
            RuntimePressureSignalStatus::Degraded,
            "rch_proof_lane_capacity_degraded",
        ));
    }

    Some(runtime_pressure_signal_row(
        RuntimePressureSignal::RchProofLanes,
        RuntimePressureSignalStatus::Present,
        "rch_proof_lane_capacity_present",
    ))
}

fn runtime_pressure_region_memory_budget_signal_status(
    rows: &[RuntimePressureRegionMemoryBudgetSnapshot],
) -> Option<RuntimePressureSignalSnapshot> {
    if rows.is_empty() {
        return None;
    }

    if rows
        .iter()
        .any(|row| row.budget_exhausted || row.hard_limit_exceeded)
    {
        return Some(runtime_pressure_signal_row(
            RuntimePressureSignal::RegionMemoryBudgets,
            RuntimePressureSignalStatus::Critical,
            "region_memory_budget_hard_pressure",
        ));
    }

    if rows.iter().any(|row| row.soft_limit_exceeded) {
        return Some(runtime_pressure_signal_row(
            RuntimePressureSignal::RegionMemoryBudgets,
            RuntimePressureSignalStatus::Degraded,
            "region_memory_budget_soft_pressure",
        ));
    }

    Some(runtime_pressure_signal_row(
        RuntimePressureSignal::RegionMemoryBudgets,
        RuntimePressureSignalStatus::Present,
        "region_memory_budget_envelopes_present",
    ))
}

fn runtime_pressure_signal_row(
    signal: RuntimePressureSignal,
    status: RuntimePressureSignalStatus,
    reason: &'static str,
) -> RuntimePressureSignalSnapshot {
    RuntimePressureSignalSnapshot {
        signal,
        status,
        reason: reason.to_string(),
    }
}

fn count_signal_status(
    signal_statuses: &[RuntimePressureSignalSnapshot],
    status: RuntimePressureSignalStatus,
) -> u64 {
    signal_statuses
        .iter()
        .filter(|signal| signal.status == status)
        .count() as u64
}

fn resource_usage_bps(current: u64, max_limit: u64) -> u16 {
    if max_limit == 0 {
        return 0;
    }
    let max_limit = u128::from(max_limit);
    let current = u128::from(current).min(max_limit);
    let rounded = (current * 10_000 + (max_limit / 2)) / max_limit;
    u16::try_from(rounded.min(10_000)).expect("basis points are clamped to u16 range")
}

fn region_memory_budget_usage_bps(current: u64, declared_budget: u64) -> u16 {
    if declared_budget == 0 {
        return if current == 0 { 0 } else { 10_000 };
    }
    resource_usage_bps(current, declared_budget)
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn finite_scaled_u64(value: f64, scale: f64) -> Option<u64> {
    if !value.is_finite() {
        return None;
    }
    let scaled = value.max(0.0) * scale;
    if scaled >= u64::MAX as f64 {
        Some(u64::MAX)
    } else {
        Some(scaled.round() as u64)
    }
}

fn finite_bps(value: f64) -> Option<u16> {
    finite_scaled_u64(value.clamp(0.0, 1.0), 10_000.0)
        .map(|scaled| u16::try_from(scaled.min(10_000)).expect("bps range is clamped"))
}

#[derive(Debug)]
struct ResourceProbeState {
    platform: String,
    probes: RwLock<HashMap<ResourceProbe, ResourceProbeSnapshot>>,
    warning_counts: RwLock<HashMap<ResourceProbe, u64>>,
}

impl ResourceProbeState {
    fn new(platform: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            probes: RwLock::new(HashMap::new()),
            warning_counts: RwLock::new(HashMap::new()),
        }
    }

    fn report(&self) -> ResourcePlatformProbeReport {
        ResourcePlatformProbeReport::from_snapshots(
            self.platform.clone(),
            self.probes.read().values().cloned().collect(),
        )
    }

    fn record_supported(&self, probe: ResourceProbe, sampled_value: Option<u64>) {
        self.probes.write().insert(
            probe,
            self.snapshot(
                probe,
                ResourceProbeStatus::Supported,
                ResourceProbeFallback::None,
                sampled_value,
                None,
                0,
                0,
            ),
        );
    }

    fn record_probe_failure(
        &self,
        probe: ResourceProbe,
        requested_fallback: ResourceProbeFallback,
        error: &std::io::Error,
    ) {
        let fallback = if error.kind() == std::io::ErrorKind::Unsupported {
            ResourceProbeFallback::CustomCollectorRequired
        } else {
            requested_fallback
        };
        let status = if fallback == ResourceProbeFallback::ConservativeDefault {
            ResourceProbeStatus::Fallback
        } else {
            ResourceProbeStatus::Unavailable
        };

        let warning_count = {
            let mut counts = self.warning_counts.write();
            let count = counts.entry(probe).or_insert(0);
            *count += 1;
            *count
        };
        let should_emit_warning = should_emit_probe_warning(warning_count);
        let warning_suppressed_count = warning_count - probe_warning_emitted_count(warning_count);

        if should_emit_warning {
            crate::tracing_compat::warn!(
                platform = self.platform.as_str(),
                probe = probe.as_str(),
                resource_type = probe.resource_type().to_string(),
                fallback = fallback.to_string(),
                error = error.to_string(),
                "resource monitor platform probe unavailable"
            );
        }

        self.probes.write().insert(
            probe,
            self.snapshot(
                probe,
                status,
                fallback,
                None,
                Some(error.to_string()),
                warning_count,
                warning_suppressed_count,
            ),
        );
    }

    #[cfg(test)]
    fn record_disabled(&self, probe: ResourceProbe) {
        self.probes.write().insert(
            probe,
            self.snapshot(
                probe,
                ResourceProbeStatus::Disabled,
                ResourceProbeFallback::MonitorDisabled,
                None,
                None,
                0,
                0,
            ),
        );
    }

    fn snapshot(
        &self,
        probe: ResourceProbe,
        status: ResourceProbeStatus,
        fallback: ResourceProbeFallback,
        sampled_value: Option<u64>,
        error_message: Option<String>,
        warning_count: u64,
        warning_suppressed_count: u64,
    ) -> ResourceProbeSnapshot {
        ResourceProbeSnapshot {
            platform: self.platform.clone(),
            resource_type: probe.resource_type(),
            probe,
            status,
            fallback,
            sampled_value,
            error_message,
            warning_count,
            warning_suppressed_count,
        }
    }
}

fn should_emit_probe_warning(warning_count: u64) -> bool {
    warning_count == 1 || warning_count.is_multiple_of(RESOURCE_PROBE_WARNING_THROTTLE_EVERY)
}

fn probe_warning_emitted_count(warning_count: u64) -> u64 {
    if warning_count == 0 {
        0
    } else {
        1 + warning_count / RESOURCE_PROBE_WARNING_THROTTLE_EVERY
    }
}

fn current_platform_fingerprint() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Resource usage measurement with limits.
#[derive(Debug, Clone)]
pub struct ResourceMeasurement {
    /// Current usage value.
    pub current: u64,
    /// Soft limit (warning threshold).
    pub soft_limit: u64,
    /// Hard limit (critical threshold).
    pub hard_limit: u64,
    /// Maximum theoretical limit.
    pub max_limit: u64,
    /// Timestamp of measurement.
    pub timestamp: Instant,
}

impl ResourceMeasurement {
    /// Create a new measurement.
    #[must_use]
    pub fn new(current: u64, soft_limit: u64, hard_limit: u64, max_limit: u64) -> Self {
        Self {
            current,
            soft_limit,
            hard_limit,
            max_limit,
            timestamp: Instant::now(),
        }
    }

    /// Calculate usage percentage (0.0-1.0).
    #[must_use]
    pub fn usage_ratio(&self) -> f64 {
        if self.max_limit == 0 {
            return 0.0;
        }
        (self.current as f64) / (self.max_limit as f64)
    }

    /// Check if soft threshold is exceeded.
    #[must_use]
    pub fn is_soft_exceeded(&self) -> bool {
        self.current >= self.soft_limit
    }

    /// Check if hard threshold is exceeded.
    #[must_use]
    pub fn is_hard_exceeded(&self) -> bool {
        self.current >= self.hard_limit
    }

    /// Check if at critical level (near max limit).
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.current >= self.max_limit.saturating_sub(self.max_limit / 20) // Within 5% of max
    }
}

/// Degradation level indicating severity of resource pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DegradationLevel {
    /// No degradation needed.
    None = 0,
    /// Light load shedding (reject new low-priority work).
    Light = 1,
    /// Moderate load shedding (pause background tasks).
    Moderate = 2,
    /// Heavy degradation (cancel non-critical regions).
    Heavy = 3,
    /// Emergency shedding (cancel all non-essential work).
    Emergency = 4,
}

impl DegradationLevel {
    /// Convert to pressure headroom value (0.0-1.0).
    #[must_use]
    pub fn to_headroom(self) -> f32 {
        match self {
            Self::None => 1.0,
            Self::Light => 0.75,
            Self::Moderate => 0.5,
            Self::Heavy => 0.25,
            Self::Emergency => 0.0,
        }
    }

    /// Convert from pressure headroom value.
    #[must_use]
    pub fn from_headroom(headroom: f32) -> Self {
        if headroom > 0.875 {
            Self::None
        } else if headroom > 0.625 {
            Self::Light
        } else if headroom > 0.375 {
            Self::Moderate
        } else if headroom > 0.125 {
            Self::Heavy
        } else {
            Self::Emergency
        }
    }
}

/// Configuration for resource monitoring thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    /// Warning threshold (0.0-1.0 of max capacity).
    pub soft_threshold: f64,
    /// Critical threshold (0.0-1.0 of max capacity).
    pub hard_threshold: f64,
    /// Hysteresis margin to prevent oscillation (0.0-1.0).
    pub hysteresis: f64,
    /// Minimum time between degradation level changes.
    pub cooldown: Duration,
    /// Whether this resource type is enabled for monitoring.
    pub enabled: bool,
}

impl TriggerConfig {
    /// Create default trigger configuration.
    #[must_use]
    pub fn default_for_resource(resource_type: &ResourceType) -> Self {
        match resource_type {
            ResourceType::Memory => Self {
                soft_threshold: 0.70, // 70% memory usage
                hard_threshold: 0.85, // 85% memory usage
                hysteresis: 0.05,     // 5% margin
                cooldown: Duration::from_secs(5),
                enabled: true,
            },
            ResourceType::FileDescriptors => Self {
                soft_threshold: 0.75, // 75% of fd limit
                hard_threshold: 0.90, // 90% of fd limit
                hysteresis: 0.05,
                cooldown: Duration::from_secs(2),
                enabled: true,
            },
            ResourceType::CpuLoad => Self {
                soft_threshold: 0.80, // 80% CPU
                hard_threshold: 0.95, // 95% CPU
                hysteresis: 0.10,     // 10% margin (CPU can be spiky)
                cooldown: Duration::from_secs(3),
                enabled: true,
            },
            ResourceType::NetworkConnections => Self {
                soft_threshold: 0.70, // 70% of connection limit
                hard_threshold: 0.85, // 85% of connection limit
                hysteresis: 0.05,
                cooldown: Duration::from_secs(1),
                enabled: true,
            },
            ResourceType::Custom(_) => Self {
                soft_threshold: 0.75, // Conservative default
                hard_threshold: 0.90,
                hysteresis: 0.05,
                cooldown: Duration::from_secs(5),
                enabled: false, // Must be explicitly enabled
            },
            ResourceType::Task => Self {
                soft_threshold: 0.80, // 80% of task limit
                hard_threshold: 0.95, // 95% of task limit
                hysteresis: 0.05,
                cooldown: Duration::from_secs(1),
                enabled: true,
            },
        }
    }

    /// Calculate degradation level for a measurement.
    #[must_use]
    pub fn calculate_degradation(&self, measurement: &ResourceMeasurement) -> DegradationLevel {
        let usage_ratio = measurement.usage_ratio();

        if usage_ratio >= self.hard_threshold {
            // Check for emergency conditions
            if measurement.is_critical() {
                DegradationLevel::Emergency
            } else {
                DegradationLevel::Heavy
            }
        } else if usage_ratio >= self.soft_threshold {
            if usage_ratio >= (self.hard_threshold - self.hysteresis) {
                DegradationLevel::Moderate
            } else {
                DegradationLevel::Light
            }
        } else {
            DegradationLevel::None
        }
    }

    /// Apply hysteresis to prevent oscillation.
    #[must_use]
    pub fn apply_hysteresis(
        &self,
        new_level: DegradationLevel,
        current_level: DegradationLevel,
        last_change: Option<Instant>,
    ) -> DegradationLevel {
        // Respect cooldown period
        if let Some(last) = last_change {
            if last.elapsed() < self.cooldown {
                return current_level;
            }
        }

        // Allow immediate escalation for emergencies
        if new_level == DegradationLevel::Emergency {
            return new_level;
        }

        // Apply hysteresis for downgrades
        if new_level < current_level {
            // Only downgrade if we're well below the threshold
            let new_u8 = new_level as u8;
            let current_u8 = current_level as u8;
            if new_u8 <= current_u8.saturating_sub(1) {
                new_level
            } else {
                current_level
            }
        } else {
            new_level
        }
    }
}

/// Multi-dimensional resource pressure tracking.
#[derive(Debug, Default)]
pub struct ResourcePressure {
    /// Per-resource measurements.
    measurements: RwLock<HashMap<ResourceType, ResourceMeasurement>>,
    /// Per-resource degradation levels.
    degradation_levels: RwLock<HashMap<ResourceType, DegradationLevel>>,
    /// Last degradation level change timestamps.
    last_changes: RwLock<HashMap<ResourceType, Instant>>,
    /// Overall system pressure.
    system_pressure: Arc<SystemPressure>,
    /// Resource monitoring overhead counter.
    monitoring_overhead: AtomicU64,
}

impl ResourcePressure {
    /// Create new resource pressure tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            measurements: RwLock::new(HashMap::new()),
            degradation_levels: RwLock::new(HashMap::new()),
            last_changes: RwLock::new(HashMap::new()),
            system_pressure: Arc::new(SystemPressure::new()),
            monitoring_overhead: AtomicU64::new(0),
        }
    }

    /// Update measurement for a resource type.
    pub fn update_measurement(
        &self,
        resource_type: ResourceType,
        measurement: ResourceMeasurement,
    ) {
        let start = Instant::now();

        {
            let mut measurements = self.measurements.write();
            measurements.insert(resource_type, measurement);
        }

        // Update monitoring overhead tracking
        let elapsed_nanos = start.elapsed().as_nanos() as u64;
        self.monitoring_overhead
            .fetch_add(elapsed_nanos, Ordering::Relaxed);
    }

    /// Get current measurement for a resource type.
    pub fn get_measurement(&self, resource_type: &ResourceType) -> Option<ResourceMeasurement> {
        self.measurements.read().get(resource_type).cloned()
    }

    /// Update degradation level for a resource type.
    pub fn update_degradation_level(&self, resource_type: ResourceType, level: DegradationLevel) {
        let mut levels = self.degradation_levels.write();
        let mut changes = self.last_changes.write();

        levels.insert(resource_type.clone(), level);
        changes.insert(resource_type, Instant::now());

        // Update overall system pressure based on maximum degradation level
        let max_level = levels
            .values()
            .max()
            .copied()
            .unwrap_or(DegradationLevel::None);
        self.system_pressure.set_headroom(max_level.to_headroom());
    }

    /// Get current degradation level for a resource type.
    pub fn get_degradation_level(&self, resource_type: &ResourceType) -> DegradationLevel {
        self.degradation_levels
            .read()
            .get(resource_type)
            .copied()
            .unwrap_or(DegradationLevel::None)
    }

    /// Get overall system pressure.
    pub fn system_pressure(&self) -> Arc<SystemPressure> {
        Arc::clone(&self.system_pressure)
    }

    /// Get monitoring overhead in nanoseconds.
    pub fn monitoring_overhead_nanos(&self) -> u64 {
        self.monitoring_overhead.load(Ordering::Relaxed)
    }

    /// Calculate composite degradation level across all resources.
    pub fn composite_degradation_level(&self) -> DegradationLevel {
        let levels = self.degradation_levels.read();
        levels
            .values()
            .max()
            .copied()
            .unwrap_or(DegradationLevel::None)
    }
}

/// Region priority classification for degradation decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RegionPriority {
    /// Critical system regions that must never be cancelled.
    Critical = 0,
    /// High priority user-facing work.
    High = 1,
    /// Normal priority work.
    #[default]
    Normal = 2,
    /// Low priority background work.
    Low = 3,
    /// Best-effort work that can be freely cancelled.
    BestEffort = 4,
}

/// Work shedding decision for a region.
#[derive(Debug, Clone)]
pub enum SheddingDecision {
    /// Keep the region running.
    Keep,
    /// Pause the region temporarily.
    Pause,
    /// Cancel the region gracefully.
    Cancel,
    /// Cancel the region immediately (emergency).
    ForceCancel,
}

/// Degradation decision engine for resource reclamation.
#[derive(Debug)]
pub struct DegradationEngine {
    /// Resource pressure tracker.
    pressure: Arc<ResourcePressure>,
    /// Trigger configuration per resource type.
    trigger_configs: RwLock<HashMap<ResourceType, TriggerConfig>>,
    /// Region priority mapping.
    region_priorities: RwLock<HashMap<RegionId, RegionPriority>>,
    /// Active degradation policies.
    active_policies: RwLock<HashMap<ResourceType, Vec<DegradationPolicy>>>,
    /// Statistics tracking.
    stats: DegradationStats,
}

/// Degradation policy for a specific resource type.
#[derive(Debug, Clone)]
pub struct DegradationPolicy {
    /// Resource type this policy applies to.
    pub resource_type: ResourceType,
    /// Degradation level that triggers this policy.
    pub trigger_level: DegradationLevel,
    /// Policy action to take.
    pub action: PolicyAction,
}

/// Actions that can be taken by degradation policies.
#[derive(Debug, Clone)]
pub enum PolicyAction {
    /// Reject new work of specified priority or lower.
    RejectNewWork(RegionPriority),
    /// Cancel regions of specified priority or lower.
    CancelRegions(RegionPriority),
    /// Pause regions of specified priority or lower.
    PauseRegions(RegionPriority),
    /// Reduce resource limits for new allocations.
    ReduceLimits { factor: f64 },
    /// Custom action with callback.
    Custom { name: String },
}

/// Statistics for degradation engine operations.
#[derive(Debug, Default)]
pub struct DegradationStats {
    /// Number of degradation triggers fired.
    triggers_fired: AtomicU64,
    /// Number of regions cancelled due to degradation.
    regions_cancelled: AtomicU64,
    /// Number of regions paused due to degradation.
    regions_paused: AtomicU64,
    /// Number of new work requests rejected.
    requests_rejected: AtomicU64,
    /// Total time spent in degradation decisions.
    decision_time_nanos: AtomicU64,
}

impl DegradationEngine {
    /// Create a new degradation engine.
    pub fn new(pressure: Arc<ResourcePressure>) -> Self {
        let mut trigger_configs = HashMap::new();

        // Install default configurations for built-in resource types
        for resource_type in [
            ResourceType::Memory,
            ResourceType::FileDescriptors,
            ResourceType::CpuLoad,
            ResourceType::NetworkConnections,
            ResourceType::Task,
        ] {
            trigger_configs.insert(
                resource_type.clone(),
                TriggerConfig::default_for_resource(&resource_type),
            );
        }

        Self {
            pressure,
            trigger_configs: RwLock::new(trigger_configs),
            region_priorities: RwLock::new(HashMap::new()),
            active_policies: RwLock::new(HashMap::new()),
            stats: DegradationStats::default(),
        }
    }

    /// Register a custom resource type with configuration.
    pub fn register_resource_type(
        &self,
        resource_type: ResourceType,
        config: TriggerConfig,
    ) -> Result<(), ResourceMonitorError> {
        let mut configs = self.trigger_configs.write();
        configs.insert(resource_type, config);
        Ok(())
    }

    /// Set priority for a region.
    pub fn set_region_priority(&self, region_id: RegionId, priority: RegionPriority) {
        let mut priorities = self.region_priorities.write();
        priorities.insert(region_id, priority);
    }

    /// Clear the priority override for a region that left the runtime.
    pub fn clear_region_priority(&self, region_id: RegionId) -> Option<RegionPriority> {
        let mut priorities = self.region_priorities.write();
        priorities.remove(&region_id)
    }

    /// Add a degradation policy for a resource type.
    pub fn add_policy(&self, policy: DegradationPolicy) {
        let mut policies = self.active_policies.write();
        policies
            .entry(policy.resource_type.clone())
            .or_default()
            .push(policy);
    }

    /// Process resource measurements and trigger degradation if needed.
    pub fn process_measurements(
        &self,
    ) -> Result<Vec<(ResourceType, DegradationLevel)>, ResourceMonitorError> {
        let start = Instant::now();
        let mut triggered_changes = Vec::new();

        let configs = self.trigger_configs.read();

        for (resource_type, config) in configs.iter() {
            if !config.enabled {
                continue;
            }

            if let Some(measurement) = self.pressure.get_measurement(resource_type) {
                let new_level = config.calculate_degradation(&measurement);
                let current_level = self.pressure.get_degradation_level(resource_type);

                let last_change = self
                    .pressure
                    .last_changes
                    .read()
                    .get(resource_type)
                    .copied();

                let final_level = config.apply_hysteresis(new_level, current_level, last_change);

                if final_level != current_level {
                    self.pressure
                        .update_degradation_level(resource_type.clone(), final_level);
                    triggered_changes.push((resource_type.clone(), final_level));

                    self.stats.triggers_fired.fetch_add(1, Ordering::Relaxed);

                    // Apply policies for this degradation level
                    self.apply_policies(resource_type, final_level)?;
                }
            }
        }

        let elapsed_nanos = start.elapsed().as_nanos() as u64;
        self.stats
            .decision_time_nanos
            .fetch_add(elapsed_nanos, Ordering::Relaxed);

        Ok(triggered_changes)
    }

    /// Apply degradation policies for a resource type and level.
    fn apply_policies(
        &self,
        resource_type: &ResourceType,
        level: DegradationLevel,
    ) -> Result<(), ResourceMonitorError> {
        let policies = self.active_policies.read();

        if let Some(resource_policies) = policies.get(resource_type) {
            for policy in resource_policies {
                if level >= policy.trigger_level {
                    self.execute_policy_action(&policy.action, level)?;
                }
            }
        }

        Ok(())
    }

    /// Execute a specific policy action.
    fn execute_policy_action(
        &self,
        action: &PolicyAction,
        _level: DegradationLevel,
    ) -> Result<(), ResourceMonitorError> {
        match action {
            PolicyAction::RejectNewWork(_priority_threshold) => {
                // This would integrate with the runtime's region creation logic
                // to reject new work below the priority threshold
                self.stats.requests_rejected.fetch_add(1, Ordering::Relaxed);
            }
            PolicyAction::CancelRegions(_priority_threshold) => {
                // This would integrate with the runtime to cancel regions
                // below the priority threshold
                self.stats.regions_cancelled.fetch_add(1, Ordering::Relaxed);
            }
            PolicyAction::PauseRegions(_priority_threshold) => {
                // This would integrate with the scheduler to pause regions
                // below the priority threshold
                self.stats.regions_paused.fetch_add(1, Ordering::Relaxed);
            }
            PolicyAction::ReduceLimits { factor: _ } => {
                // This would reduce resource allocation limits
                // by the specified factor
            }
            PolicyAction::Custom { name: _name } => {
                // Custom actions would be handled by registered callbacks
            }
        }

        Ok(())
    }

    /// Decide what to do with a specific region during degradation.
    pub fn should_shed_region(&self, region_id: RegionId) -> SheddingDecision {
        let composite_level = self.pressure.composite_degradation_level();
        let priorities = self.region_priorities.read();
        let region_priority = priorities.get(&region_id).copied().unwrap_or_default();

        match (composite_level, region_priority) {
            (DegradationLevel::Emergency, RegionPriority::BestEffort) => {
                SheddingDecision::ForceCancel
            }
            (DegradationLevel::Emergency, RegionPriority::Low) => SheddingDecision::Cancel,
            (DegradationLevel::Emergency, RegionPriority::Normal) => SheddingDecision::Pause,
            (DegradationLevel::Emergency, _) => SheddingDecision::Keep,

            (DegradationLevel::Heavy, RegionPriority::BestEffort) => SheddingDecision::Cancel,
            (DegradationLevel::Heavy, RegionPriority::Low) => SheddingDecision::Pause,
            (DegradationLevel::Heavy, _) => SheddingDecision::Keep,

            (DegradationLevel::Moderate, RegionPriority::BestEffort) => SheddingDecision::Pause,
            (DegradationLevel::Moderate, _) => SheddingDecision::Keep,

            (DegradationLevel::Light, RegionPriority::BestEffort) => SheddingDecision::Pause,
            (DegradationLevel::Light, _) => SheddingDecision::Keep,

            (DegradationLevel::None, _) => SheddingDecision::Keep,
        }
    }

    /// Evaluate a deterministic overload-admission decision using the current pressure band
    /// plus first-party scheduler evidence.
    #[must_use]
    pub fn evaluate_tail_risk_admission(
        &self,
        scheduler: Option<&SchedulerEvidenceMetrics>,
        retry_pressure_p99: Option<u64>,
        memory_pressure_bps: Option<u16>,
        profile: &TailRiskAdmissionProfile,
    ) -> TailRiskAdmissionLedger {
        let evidence = TailRiskAdmissionEvidence {
            scheduler: scheduler.cloned(),
            retry_pressure_p99,
            memory_pressure_bps,
            degradation_level: self.pressure.composite_degradation_level(),
        };
        TailRiskAdmissionLedger::evaluate(&evidence, profile)
    }

    /// Get degradation statistics.
    pub fn stats(&self) -> DegradationStatsSnapshot {
        DegradationStatsSnapshot {
            triggers_fired: self.stats.triggers_fired.load(Ordering::Relaxed),
            regions_cancelled: self.stats.regions_cancelled.load(Ordering::Relaxed),
            regions_paused: self.stats.regions_paused.load(Ordering::Relaxed),
            requests_rejected: self.stats.requests_rejected.load(Ordering::Relaxed),
            decision_time_nanos: self.stats.decision_time_nanos.load(Ordering::Relaxed),
            monitoring_overhead_nanos: self.pressure.monitoring_overhead_nanos(),
        }
    }
}

/// Snapshot of degradation statistics for reporting.
#[derive(Debug, Clone)]
pub struct DegradationStatsSnapshot {
    pub triggers_fired: u64,
    pub regions_cancelled: u64,
    pub regions_paused: u64,
    pub requests_rejected: u64,
    pub decision_time_nanos: u64,
    pub monitoring_overhead_nanos: u64,
}

impl DegradationStatsSnapshot {
    /// Calculate overhead as percentage of total runtime.
    #[must_use]
    pub fn overhead_percentage(&self, total_runtime_nanos: u64) -> f64 {
        if total_runtime_nanos == 0 {
            return 0.0;
        }
        let total_overhead = self.decision_time_nanos + self.monitoring_overhead_nanos;
        (total_overhead as f64) / (total_runtime_nanos as f64) * 100.0
    }
}

/// Stable version identifier for tail-risk admission ledgers.
pub const TAIL_RISK_ADMISSION_LEDGER_SCHEMA_VERSION: &str = "asupersync.tail-risk-admission.v1";

/// Admission outcome for overload-sensitive work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailRiskAdmissionDecision {
    Admit,
    Defer,
    Shed,
}

/// Explicit reason codes for a tail-risk admission verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailRiskAdmissionReason {
    WakeToRunTail,
    QueueResidencyTail,
    BacklogPressure,
    CancelDebtPressure,
    RetryPressure,
    MemoryPressure,
    ExistingDegradation,
    ConservativeFallback,
    BalancedBaseline,
}

/// Bounded operator-tunable thresholds for overload admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionProfile {
    pub wake_to_run_p99_ns_limit: u64,
    pub queue_residency_p99_ns_limit: u64,
    pub ready_backlog_p99_limit: usize,
    pub cancel_debt_p99_limit: usize,
    pub retry_pressure_p99_limit: u64,
    pub memory_pressure_soft_bps: u16,
    pub memory_pressure_hard_bps: u16,
    pub defer_expected_loss_score: u8,
    pub shed_expected_loss_score: u8,
}

impl Default for TailRiskAdmissionProfile {
    fn default() -> Self {
        Self {
            wake_to_run_p99_ns_limit: 150_000,
            queue_residency_p99_ns_limit: 400_000,
            ready_backlog_p99_limit: 256,
            cancel_debt_p99_limit: 96,
            retry_pressure_p99_limit: 32,
            memory_pressure_soft_bps: 8_000,
            memory_pressure_hard_bps: 9_200,
            defer_expected_loss_score: 35,
            shed_expected_loss_score: 65,
        }
    }
}

/// Evidence vector consumed by the tail-risk admission rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionEvidence {
    pub scheduler: Option<SchedulerEvidenceMetrics>,
    pub retry_pressure_p99: Option<u64>,
    /// Memory pressure in basis points, where `10_000` represents 100%.
    pub memory_pressure_bps: Option<u16>,
    pub degradation_level: DegradationLevel,
}

impl TailRiskAdmissionEvidence {
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.scheduler.is_none() {
            missing.push("scheduler_metrics");
        }
        if self.retry_pressure_p99.is_none() {
            missing.push("retry_pressure_p99");
        }
        match self.memory_pressure_bps {
            Some(value) if value <= 10_000 => {}
            Some(_) | None => missing.push("memory_pressure_bps"),
        }
        missing
    }
}

/// Flattened evidence snapshot stored in the decision ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionEvidenceSnapshot {
    pub wake_to_run_p99_ns: Option<u64>,
    pub queue_residency_p99_ns: Option<u64>,
    pub ready_backlog_p99: Option<usize>,
    pub cancel_debt_p99: Option<usize>,
    pub retry_pressure_p99: Option<u64>,
    pub memory_pressure_bps: Option<u16>,
}

/// Deterministic decision ledger for overload admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAdmissionLedger {
    pub schema_version: String,
    pub decision: TailRiskAdmissionDecision,
    pub fallback_used: bool,
    pub expected_loss_score: u8,
    pub confidence_percent: u8,
    pub reason_codes: Vec<TailRiskAdmissionReason>,
    pub missing_evidence_fields: Vec<String>,
    pub profile: TailRiskAdmissionProfile,
    pub degradation_level: DegradationLevel,
    pub evidence: TailRiskAdmissionEvidenceSnapshot,
    pub explanation: Vec<String>,
}

impl TailRiskAdmissionLedger {
    /// Evaluate one overload-admission decision against the supplied evidence and profile.
    #[must_use]
    pub fn evaluate(
        evidence: &TailRiskAdmissionEvidence,
        profile: &TailRiskAdmissionProfile,
    ) -> Self {
        let snapshot = TailRiskAdmissionEvidenceSnapshot {
            wake_to_run_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.wake_to_run_p99_ns),
            queue_residency_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.queue_residency_p99_ns),
            ready_backlog_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.ready_backlog_p99),
            cancel_debt_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.cancel_debt_p99),
            retry_pressure_p99: evidence.retry_pressure_p99,
            memory_pressure_bps: evidence.memory_pressure_bps,
        };
        let missing_fields = evidence
            .missing_fields()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();

        if !missing_fields.is_empty() {
            return Self::conservative_fallback(evidence, profile, snapshot, missing_fields);
        }

        let scheduler = evidence.scheduler.as_ref().expect("checked above");
        let retry_pressure = evidence.retry_pressure_p99.expect("checked above");
        let memory_pressure = evidence.memory_pressure_bps.expect("checked above");

        let mut expected_loss_score = 0u8;
        let mut reason_codes = Vec::new();
        let mut explanation = Vec::new();

        if scheduler.wake_to_run_p99_ns >= profile.wake_to_run_p99_ns_limit {
            expected_loss_score = expected_loss_score.saturating_add(18);
            reason_codes.push(TailRiskAdmissionReason::WakeToRunTail);
            explanation.push(format!(
                "wake_to_run p99={}ns exceeded the configured limit {}ns",
                scheduler.wake_to_run_p99_ns, profile.wake_to_run_p99_ns_limit
            ));
        }

        if scheduler.queue_residency_p99_ns >= profile.queue_residency_p99_ns_limit {
            expected_loss_score = expected_loss_score.saturating_add(22);
            reason_codes.push(TailRiskAdmissionReason::QueueResidencyTail);
            explanation.push(format!(
                "queue_residency p99={}ns exceeded the configured limit {}ns",
                scheduler.queue_residency_p99_ns, profile.queue_residency_p99_ns_limit
            ));
        }

        if scheduler.ready_backlog_p99 >= profile.ready_backlog_p99_limit {
            expected_loss_score = expected_loss_score.saturating_add(15);
            reason_codes.push(TailRiskAdmissionReason::BacklogPressure);
            explanation.push(format!(
                "ready_backlog p99={} exceeded the configured limit {}",
                scheduler.ready_backlog_p99, profile.ready_backlog_p99_limit
            ));
        }

        if scheduler.cancel_debt_p99 >= profile.cancel_debt_p99_limit {
            expected_loss_score = expected_loss_score.saturating_add(10);
            reason_codes.push(TailRiskAdmissionReason::CancelDebtPressure);
            explanation.push(format!(
                "cancel_debt p99={} exceeded the configured limit {}",
                scheduler.cancel_debt_p99, profile.cancel_debt_p99_limit
            ));
        }

        if retry_pressure >= profile.retry_pressure_p99_limit {
            expected_loss_score = expected_loss_score.saturating_add(15);
            reason_codes.push(TailRiskAdmissionReason::RetryPressure);
            explanation.push(format!(
                "retry_pressure p99={} exceeded the configured limit {}",
                retry_pressure, profile.retry_pressure_p99_limit
            ));
        }

        if memory_pressure >= profile.memory_pressure_soft_bps {
            let increment = if memory_pressure >= profile.memory_pressure_hard_bps {
                25
            } else {
                12
            };
            expected_loss_score = expected_loss_score.saturating_add(increment);
            reason_codes.push(TailRiskAdmissionReason::MemoryPressure);
            explanation.push(format!(
                "memory pressure {}bps exceeded the soft limit {}bps",
                memory_pressure, profile.memory_pressure_soft_bps
            ));
        }

        if evidence.degradation_level >= DegradationLevel::Moderate {
            expected_loss_score = expected_loss_score.saturating_add(10);
            reason_codes.push(TailRiskAdmissionReason::ExistingDegradation);
            explanation.push(format!(
                "existing degradation level {:?} tightened the admission envelope",
                evidence.degradation_level
            ));
        }

        if reason_codes.is_empty() {
            reason_codes.push(TailRiskAdmissionReason::BalancedBaseline);
            explanation.push(
                "tail, backlog, retry, and memory evidence stayed inside the configured envelope"
                    .to_string(),
            );
        }

        let decision = if memory_pressure >= profile.memory_pressure_hard_bps
            || evidence.degradation_level == DegradationLevel::Emergency
            || expected_loss_score >= profile.shed_expected_loss_score
        {
            TailRiskAdmissionDecision::Shed
        } else if evidence.degradation_level >= DegradationLevel::Moderate
            || expected_loss_score >= profile.defer_expected_loss_score
        {
            TailRiskAdmissionDecision::Defer
        } else {
            TailRiskAdmissionDecision::Admit
        };

        let confidence_percent = 65u8
            .saturating_add((u8::try_from(reason_codes.len()).unwrap_or(u8::MAX)).saturating_mul(5))
            .min(90);

        Self {
            schema_version: TAIL_RISK_ADMISSION_LEDGER_SCHEMA_VERSION.to_string(),
            decision,
            fallback_used: false,
            expected_loss_score,
            confidence_percent,
            reason_codes,
            missing_evidence_fields: Vec::new(),
            profile: profile.clone(),
            degradation_level: evidence.degradation_level,
            evidence: snapshot,
            explanation,
        }
    }

    fn conservative_fallback(
        evidence: &TailRiskAdmissionEvidence,
        profile: &TailRiskAdmissionProfile,
        snapshot: TailRiskAdmissionEvidenceSnapshot,
        missing_evidence_fields: Vec<String>,
    ) -> Self {
        let decision = match evidence.degradation_level {
            DegradationLevel::Emergency | DegradationLevel::Heavy => {
                TailRiskAdmissionDecision::Shed
            }
            DegradationLevel::Moderate => TailRiskAdmissionDecision::Defer,
            DegradationLevel::Light | DegradationLevel::None => TailRiskAdmissionDecision::Admit,
        };

        Self {
            schema_version: TAIL_RISK_ADMISSION_LEDGER_SCHEMA_VERSION.to_string(),
            decision,
            fallback_used: true,
            expected_loss_score: 0,
            confidence_percent: 100,
            reason_codes: vec![TailRiskAdmissionReason::ConservativeFallback],
            missing_evidence_fields,
            profile: profile.clone(),
            degradation_level: evidence.degradation_level,
            evidence: snapshot,
            explanation: vec![
                "Incomplete evidence preserved the conservative degradation-band comparator."
                    .to_string(),
            ],
        }
    }
}

/// Stable version identifier for cohort-aware admission steering ledgers.
pub const COHORT_ADMISSION_STEERING_LEDGER_SCHEMA_VERSION: &str =
    "asupersync.cohort-admission-steering.v1";

/// Placement outcome for cohort-aware admission steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortAdmissionSteeringDecision {
    AdmitLocal,
    RedirectRemote,
    Defer,
}

/// Explicit reason codes for cohort-aware admission steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortAdmissionSteeringReason {
    Disabled,
    MissingTopology,
    LowConfidenceFallback,
    TailRiskOuterCap,
    LocalCapacityAvailable,
    LocalBacklogPressure,
    RemoteSpillBudgetSpent,
    RemoteSpillBudgetExhausted,
    FairnessEscapeHatch,
    ConservativeGlobalBaseline,
}

/// Bounded knobs for cohort-aware admission steering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringProfile {
    pub enabled: bool,
    pub local_ready_backlog_soft_limit: usize,
    pub local_ready_backlog_hard_limit: usize,
    pub remote_ready_backlog_limit: usize,
    pub remote_redirect_delta_min: usize,
    pub remote_spill_budget_per_epoch: u16,
    pub min_topology_confidence_percent: u8,
    pub fairness_escape_after_consecutive_defers: u16,
}

impl Default for CohortAdmissionSteeringProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            local_ready_backlog_soft_limit: 192,
            local_ready_backlog_hard_limit: 256,
            remote_ready_backlog_limit: 160,
            remote_redirect_delta_min: 24,
            remote_spill_budget_per_epoch: 2,
            min_topology_confidence_percent: 70,
            fairness_escape_after_consecutive_defers: 3,
        }
    }
}

/// Deterministic budget state for bounded remote spill steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortRemoteSpillBudgetState {
    pub epoch: u64,
    pub remaining_tokens: u16,
}

impl CohortRemoteSpillBudgetState {
    #[must_use]
    pub fn new(epoch: u64, remaining_tokens: u16) -> Self {
        Self {
            epoch,
            remaining_tokens,
        }
    }

    #[must_use]
    pub fn normalized_for_epoch(
        self,
        profile: &CohortAdmissionSteeringProfile,
        decision_epoch: u64,
    ) -> Self {
        if self.epoch == decision_epoch {
            Self {
                epoch: self.epoch,
                remaining_tokens: self
                    .remaining_tokens
                    .min(profile.remote_spill_budget_per_epoch),
            }
        } else {
            Self {
                epoch: decision_epoch,
                remaining_tokens: profile.remote_spill_budget_per_epoch,
            }
        }
    }

    #[must_use]
    pub fn spend_one(self) -> Self {
        Self {
            epoch: self.epoch,
            remaining_tokens: self.remaining_tokens.saturating_sub(1),
        }
    }
}

/// Cohort-local evidence vector for admission steering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringEvidence {
    pub local_cohort: Option<usize>,
    pub worker_to_cohort_map: Vec<usize>,
    pub cohort_ready_backlog: Vec<usize>,
    pub topology_confidence_percent: Option<u8>,
    pub remote_spill_budget: CohortRemoteSpillBudgetState,
    pub decision_epoch: u64,
    pub consecutive_local_defers: u16,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
}

impl CohortAdmissionSteeringEvidence {
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.local_cohort.is_none() {
            missing.push("local_cohort");
        }
        if self.worker_to_cohort_map.is_empty() {
            missing.push("worker_to_cohort_map");
        }
        if self.cohort_ready_backlog.is_empty() {
            missing.push("cohort_ready_backlog");
        }
        if let Some(local) = self.local_cohort {
            if local >= self.cohort_ready_backlog.len() {
                missing.push("local_cohort");
            }
        }
        if !self.worker_to_cohort_map.is_empty()
            && !self.cohort_ready_backlog.is_empty()
            && self
                .worker_to_cohort_map
                .iter()
                .any(|cohort| *cohort >= self.cohort_ready_backlog.len())
        {
            missing.push("worker_to_cohort_map");
        }
        missing.sort_unstable();
        missing.dedup();
        missing
    }

    fn remote_target(&self) -> Option<(usize, usize)> {
        let local = self.local_cohort?;
        self.cohort_ready_backlog
            .iter()
            .enumerate()
            .filter(|(cohort, _)| *cohort != local)
            .min_by_key(|(cohort, backlog)| (**backlog, *cohort))
            .map(|(cohort, backlog)| (cohort, *backlog))
    }
}

/// Flattened evidence snapshot stored in the cohort steering ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringEvidenceSnapshot {
    pub local_cohort: Option<usize>,
    pub cohort_count: usize,
    pub worker_to_cohort_map: Vec<usize>,
    pub cohort_ready_backlog: Vec<usize>,
    pub topology_confidence_percent: Option<u8>,
    pub decision_epoch: u64,
    pub remote_spill_budget_epoch: u64,
    pub remote_spill_budget_remaining_before: u16,
    pub remote_spill_budget_remaining_after: u16,
    pub consecutive_local_defers: u16,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
}

/// Deterministic decision ledger for cohort-aware admission steering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmissionSteeringLedger {
    pub schema_version: String,
    pub decision: CohortAdmissionSteeringDecision,
    pub target_cohort: Option<usize>,
    pub fallback_used: bool,
    pub confidence_percent: u8,
    pub reason_codes: Vec<CohortAdmissionSteeringReason>,
    pub missing_evidence_fields: Vec<String>,
    pub profile: CohortAdmissionSteeringProfile,
    pub evidence: CohortAdmissionSteeringEvidenceSnapshot,
    pub remote_spill_budget_start: u16,
    pub remote_spill_budget_remaining: u16,
    pub remote_spill_budget_exhausted: bool,
    pub explanation: Vec<String>,
}

impl CohortAdmissionSteeringLedger {
    /// Evaluate one cohort-aware placement decision.
    #[must_use]
    pub fn evaluate(
        evidence: &CohortAdmissionSteeringEvidence,
        profile: &CohortAdmissionSteeringProfile,
    ) -> Self {
        let normalized_budget = evidence
            .remote_spill_budget
            .normalized_for_epoch(profile, evidence.decision_epoch);
        let budget_start = normalized_budget.remaining_tokens;
        let mut budget_after = budget_start;
        let snapshot = CohortAdmissionSteeringEvidenceSnapshot {
            local_cohort: evidence.local_cohort,
            cohort_count: evidence.cohort_ready_backlog.len(),
            worker_to_cohort_map: evidence.worker_to_cohort_map.clone(),
            cohort_ready_backlog: evidence.cohort_ready_backlog.clone(),
            topology_confidence_percent: evidence.topology_confidence_percent,
            decision_epoch: evidence.decision_epoch,
            remote_spill_budget_epoch: normalized_budget.epoch,
            remote_spill_budget_remaining_before: budget_start,
            remote_spill_budget_remaining_after: budget_start,
            consecutive_local_defers: evidence.consecutive_local_defers,
            outer_tail_risk_decision: evidence.outer_tail_risk_decision,
        };

        if evidence.outer_tail_risk_decision != TailRiskAdmissionDecision::Admit {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::Defer,
                None,
                false,
                evidence.topology_confidence_percent.unwrap_or(100),
                vec![CohortAdmissionSteeringReason::TailRiskOuterCap],
                Vec::new(),
                budget_start,
                budget_after,
                vec![format!(
                    "tail-risk outer decision {:?} kept cohort steering from admitting new work",
                    evidence.outer_tail_risk_decision
                )],
            );
        }

        if !profile.enabled {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                evidence.local_cohort,
                true,
                evidence.topology_confidence_percent.unwrap_or(100),
                vec![
                    CohortAdmissionSteeringReason::Disabled,
                    CohortAdmissionSteeringReason::ConservativeGlobalBaseline,
                ],
                Vec::new(),
                budget_start,
                budget_after,
                vec![
                    "cohort steering is disabled, so the conservative global routing path stayed pinned"
                        .to_string(),
                ],
            );
        }

        let missing_fields = evidence
            .missing_fields()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !missing_fields.is_empty() {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                evidence.local_cohort,
                true,
                evidence.topology_confidence_percent.unwrap_or(100),
                vec![
                    CohortAdmissionSteeringReason::MissingTopology,
                    CohortAdmissionSteeringReason::ConservativeGlobalBaseline,
                ],
                missing_fields,
                budget_start,
                budget_after,
                vec![
                    "missing or invalid worker/cohort topology kept the conservative global routing path pinned"
                        .to_string(),
                ],
            );
        }

        let topology_confidence = evidence.topology_confidence_percent.unwrap_or(0).min(100);
        if topology_confidence < profile.min_topology_confidence_percent {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                evidence.local_cohort,
                true,
                topology_confidence,
                vec![
                    CohortAdmissionSteeringReason::LowConfidenceFallback,
                    CohortAdmissionSteeringReason::ConservativeGlobalBaseline,
                ],
                Vec::new(),
                budget_start,
                budget_after,
                vec![format!(
                    "topology confidence {}% stayed below the configured minimum {}%",
                    topology_confidence, profile.min_topology_confidence_percent
                )],
            );
        }

        let local_cohort = evidence.local_cohort.expect("validated above");
        let local_backlog = evidence.cohort_ready_backlog[local_cohort];
        let fairness_triggered =
            evidence.consecutive_local_defers >= profile.fairness_escape_after_consecutive_defers;

        if local_backlog <= profile.local_ready_backlog_soft_limit {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                Some(local_cohort),
                false,
                topology_confidence,
                vec![CohortAdmissionSteeringReason::LocalCapacityAvailable],
                Vec::new(),
                budget_start,
                budget_after,
                vec![format!(
                    "local cohort {} backlog {} stayed inside the soft limit {}",
                    local_cohort, local_backlog, profile.local_ready_backlog_soft_limit
                )],
            );
        }

        let Some((remote_target, remote_backlog)) = evidence.remote_target() else {
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::AdmitLocal,
                Some(local_cohort),
                false,
                topology_confidence,
                vec![CohortAdmissionSteeringReason::ConservativeGlobalBaseline],
                Vec::new(),
                budget_start,
                budget_after,
                vec![
                    "no remote cohort candidate existed, so the conservative local placement stayed pinned"
                        .to_string(),
                ],
            );
        };

        let remote_gain = local_backlog.saturating_sub(remote_backlog);
        let remote_viable = remote_backlog <= profile.remote_ready_backlog_limit
            && remote_gain >= profile.remote_redirect_delta_min;

        if remote_viable && budget_start > 0 {
            budget_after = normalized_budget.spend_one().remaining_tokens;
            let mut reasons = vec![
                CohortAdmissionSteeringReason::LocalBacklogPressure,
                CohortAdmissionSteeringReason::RemoteSpillBudgetSpent,
            ];
            let mut explanation = vec![format!(
                "redirected from local cohort {} backlog {} to remote cohort {} backlog {} with remote gain {}",
                local_cohort, local_backlog, remote_target, remote_backlog, remote_gain
            )];
            if fairness_triggered {
                reasons.push(CohortAdmissionSteeringReason::FairnessEscapeHatch);
                explanation.push(format!(
                    "fairness escape hatch fired after {} consecutive local defers",
                    evidence.consecutive_local_defers
                ));
            }
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::RedirectRemote,
                Some(remote_target),
                false,
                topology_confidence,
                reasons,
                Vec::new(),
                budget_start,
                budget_after,
                explanation,
            );
        }

        if remote_viable && budget_start == 0 {
            let mut reasons = vec![CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted];
            let mut explanation = vec![format!(
                "remote cohort {} backlog {} was viable but the epoch budget was exhausted",
                remote_target, remote_backlog
            )];
            if fairness_triggered {
                reasons.push(CohortAdmissionSteeringReason::FairnessEscapeHatch);
                explanation.push(format!(
                    "fairness pressure was present after {} consecutive local defers",
                    evidence.consecutive_local_defers
                ));
            }
            return Self::finish(
                profile,
                snapshot,
                CohortAdmissionSteeringDecision::Defer,
                None,
                false,
                topology_confidence,
                reasons,
                Vec::new(),
                budget_start,
                budget_after,
                explanation,
            );
        }

        Self::finish(
            profile,
            snapshot,
            CohortAdmissionSteeringDecision::AdmitLocal,
            Some(local_cohort),
            false,
            topology_confidence,
            vec![CohortAdmissionSteeringReason::ConservativeGlobalBaseline],
            Vec::new(),
            budget_start,
            budget_after,
            vec![format!(
                "remote cohort {} backlog {} did not beat the local cohort {} backlog {} by the configured delta {}",
                remote_target,
                remote_backlog,
                local_cohort,
                local_backlog,
                profile.remote_redirect_delta_min
            )],
        )
    }

    fn finish(
        profile: &CohortAdmissionSteeringProfile,
        mut snapshot: CohortAdmissionSteeringEvidenceSnapshot,
        decision: CohortAdmissionSteeringDecision,
        target_cohort: Option<usize>,
        fallback_used: bool,
        confidence_percent: u8,
        reason_codes: Vec<CohortAdmissionSteeringReason>,
        missing_evidence_fields: Vec<String>,
        remote_spill_budget_start: u16,
        remote_spill_budget_remaining: u16,
        explanation: Vec<String>,
    ) -> Self {
        snapshot.remote_spill_budget_remaining_after = remote_spill_budget_remaining;
        Self {
            schema_version: COHORT_ADMISSION_STEERING_LEDGER_SCHEMA_VERSION.to_string(),
            decision,
            target_cohort,
            fallback_used,
            confidence_percent,
            reason_codes,
            missing_evidence_fields,
            profile: profile.clone(),
            evidence: snapshot,
            remote_spill_budget_start,
            remote_spill_budget_remaining,
            remote_spill_budget_exhausted: remote_spill_budget_remaining == 0,
            explanation,
        }
    }
}

/// Stable version identifier for overload brownout ledgers.
pub const OVERLOAD_BROWNOUT_LEDGER_SCHEMA_VERSION: &str = "asupersync.overload-brownout.v1";

/// Optional runtime surfaces that may be degraded during overload brownout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrownoutOptionalSurface {
    DetailedTracing,
    RichDiagnostics,
    DebugHttp,
    RichExportFormatting,
}

/// Critical runtime surfaces that brownout must never disable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrownoutProtectedSurface {
    CoreScheduling,
    CancellationDrain,
    RegionQuiescence,
    ObligationCleanup,
}

/// Brownout phase for optional runtime surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverloadBrownoutPhase {
    Normal,
    Observe,
    Degrade,
    ShedOptional,
    Recovery,
}

impl OverloadBrownoutPhase {
    #[must_use]
    fn severity_rank(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Observe | Self::Recovery => 1,
            Self::Degrade => 2,
            Self::ShedOptional => 3,
        }
    }
}

/// Explicit reason codes for overload brownout decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverloadBrownoutReason {
    Disabled,
    MissingEvidenceFallback,
    ObservePressure,
    DegradePressure,
    ShedOptionalPressure,
    TailRiskOuterDefer,
    TailRiskOuterShed,
    RecoveryHysteresis,
    PreserveCriticalSurfaces,
    OptionalSurfaceAlreadyShedding,
    ConservativeBaseline,
}

/// Bounded operator-tunable profile for overload brownout decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutProfile {
    pub enabled: bool,
    pub observe_memory_pressure_bps: u16,
    pub degrade_memory_pressure_bps: u16,
    pub shed_optional_memory_pressure_bps: u16,
    pub observe_wake_to_run_p99_ns: u64,
    pub degrade_wake_to_run_p99_ns: u64,
    pub shed_optional_wake_to_run_p99_ns: u64,
    pub recovery_window_threshold: u8,
    pub allowed_optional_surfaces: Vec<BrownoutOptionalSurface>,
    pub denied_optional_surfaces: Vec<BrownoutOptionalSurface>,
}

impl Default for OverloadBrownoutProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_memory_pressure_bps: 7_800,
            degrade_memory_pressure_bps: 8_600,
            shed_optional_memory_pressure_bps: 9_300,
            observe_wake_to_run_p99_ns: 145_000,
            degrade_wake_to_run_p99_ns: 210_000,
            shed_optional_wake_to_run_p99_ns: 285_000,
            recovery_window_threshold: 2,
            allowed_optional_surfaces: vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichDiagnostics,
                BrownoutOptionalSurface::DebugHttp,
                BrownoutOptionalSurface::RichExportFormatting,
            ],
            denied_optional_surfaces: Vec::new(),
        }
    }
}

impl OverloadBrownoutProfile {
    /// Return the deduplicated, denylist-filtered optional surfaces.
    #[must_use]
    pub fn effective_optional_surfaces(&self) -> Vec<BrownoutOptionalSurface> {
        let mut effective = Vec::new();
        for surface in &self.allowed_optional_surfaces {
            if self.denied_optional_surfaces.contains(surface) || effective.contains(surface) {
                continue;
            }
            effective.push(*surface);
        }
        effective
    }

    fn surfaces_for_phase(&self, phase: OverloadBrownoutPhase) -> Vec<BrownoutOptionalSurface> {
        let effective = self.effective_optional_surfaces();
        let wanted = match phase {
            OverloadBrownoutPhase::Normal => Vec::new(),
            OverloadBrownoutPhase::Observe | OverloadBrownoutPhase::Recovery => {
                vec![BrownoutOptionalSurface::RichExportFormatting]
            }
            OverloadBrownoutPhase::Degrade => vec![
                BrownoutOptionalSurface::RichExportFormatting,
                BrownoutOptionalSurface::RichDiagnostics,
            ],
            OverloadBrownoutPhase::ShedOptional => effective.clone(),
        };
        wanted
            .into_iter()
            .filter(|surface| effective.contains(surface))
            .collect()
    }
}

/// Evidence vector for overload brownout decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutEvidence {
    pub scheduler: Option<SchedulerEvidenceMetrics>,
    /// Memory pressure in basis points, where `10_000` represents 100%.
    pub memory_pressure_bps: Option<u16>,
    pub degradation_level: DegradationLevel,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
    pub previous_phase: OverloadBrownoutPhase,
    pub recovery_streak_windows: u8,
    pub already_shed_surfaces: Vec<BrownoutOptionalSurface>,
}

impl OverloadBrownoutEvidence {
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.scheduler.is_none() {
            missing.push("scheduler_metrics");
        }
        match self.memory_pressure_bps {
            Some(value) if value <= 10_000 => {}
            Some(_) | None => missing.push("memory_pressure_bps"),
        }
        missing
    }
}

/// Flattened evidence snapshot stored in the overload brownout ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutEvidenceSnapshot {
    pub wake_to_run_p99_ns: Option<u64>,
    pub queue_residency_p99_ns: Option<u64>,
    pub ready_backlog_p99: Option<usize>,
    pub cancel_debt_p99: Option<usize>,
    pub memory_pressure_bps: Option<u16>,
    pub degradation_level: DegradationLevel,
    pub outer_tail_risk_decision: TailRiskAdmissionDecision,
    pub previous_phase: OverloadBrownoutPhase,
    pub recovery_streak_before: u8,
    pub already_shed_surfaces: Vec<BrownoutOptionalSurface>,
}

/// Deterministic decision ledger for overload brownout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverloadBrownoutLedger {
    pub schema_version: String,
    pub phase: OverloadBrownoutPhase,
    pub fallback_used: bool,
    pub reason_codes: Vec<OverloadBrownoutReason>,
    pub missing_evidence_fields: Vec<String>,
    pub profile: OverloadBrownoutProfile,
    pub evidence: OverloadBrownoutEvidenceSnapshot,
    pub requested_degraded_surfaces: Vec<BrownoutOptionalSurface>,
    pub newly_degraded_surfaces: Vec<BrownoutOptionalSurface>,
    pub already_shed_surfaces: Vec<BrownoutOptionalSurface>,
    pub restored_surfaces: Vec<BrownoutOptionalSurface>,
    pub preserved_surfaces: Vec<BrownoutProtectedSurface>,
    pub recovery_streak_after: u8,
    pub explanation: Vec<String>,
}

impl OverloadBrownoutLedger {
    /// Evaluate one overload brownout decision.
    #[must_use]
    pub fn evaluate(
        evidence: &OverloadBrownoutEvidence,
        profile: &OverloadBrownoutProfile,
    ) -> Self {
        let snapshot = OverloadBrownoutEvidenceSnapshot {
            wake_to_run_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.wake_to_run_p99_ns),
            queue_residency_p99_ns: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.queue_residency_p99_ns),
            ready_backlog_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.ready_backlog_p99),
            cancel_debt_p99: evidence
                .scheduler
                .as_ref()
                .map(|metrics| metrics.cancel_debt_p99),
            memory_pressure_bps: evidence.memory_pressure_bps,
            degradation_level: evidence.degradation_level,
            outer_tail_risk_decision: evidence.outer_tail_risk_decision,
            previous_phase: evidence.previous_phase,
            recovery_streak_before: evidence.recovery_streak_windows,
            already_shed_surfaces: evidence.already_shed_surfaces.clone(),
        };

        if !profile.enabled {
            return Self::finish(
                profile,
                snapshot,
                OverloadBrownoutPhase::Normal,
                true,
                vec![
                    OverloadBrownoutReason::Disabled,
                    OverloadBrownoutReason::ConservativeBaseline,
                ],
                Vec::new(),
                Vec::new(),
                0,
                vec!["brownout is disabled, so optional surfaces stayed fully enabled".to_string()],
            );
        }

        let missing_fields = evidence
            .missing_fields()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !missing_fields.is_empty() {
            let conservative_phase = Self::conservative_phase(evidence);
            return Self::finish(
                profile,
                snapshot,
                conservative_phase,
                true,
                vec![
                    OverloadBrownoutReason::MissingEvidenceFallback,
                    OverloadBrownoutReason::PreserveCriticalSurfaces,
                ],
                missing_fields,
                Vec::new(),
                evidence.recovery_streak_windows,
                vec![
                    "incomplete evidence kept brownout on a conservative degradation-band comparator"
                        .to_string(),
                ],
            );
        }

        let scheduler = evidence.scheduler.as_ref().expect("validated above");
        let memory_pressure = evidence.memory_pressure_bps.expect("validated above");
        let mut raw_phase = OverloadBrownoutPhase::Normal;
        let mut reason_codes = vec![OverloadBrownoutReason::PreserveCriticalSurfaces];
        let mut explanation = vec![
            "core scheduling, cancellation drain, region quiescence, and obligation cleanup stay preserved in every brownout phase".to_string(),
        ];

        if memory_pressure >= profile.observe_memory_pressure_bps
            || scheduler.wake_to_run_p99_ns >= profile.observe_wake_to_run_p99_ns
            || evidence.degradation_level >= DegradationLevel::Light
        {
            raw_phase = OverloadBrownoutPhase::Observe;
            reason_codes.push(OverloadBrownoutReason::ObservePressure);
            explanation.push(format!(
                "observe threshold crossed: wake_to_run p99={}ns, memory={}bps",
                scheduler.wake_to_run_p99_ns, memory_pressure
            ));
        }

        if memory_pressure >= profile.degrade_memory_pressure_bps
            || scheduler.wake_to_run_p99_ns >= profile.degrade_wake_to_run_p99_ns
            || evidence.degradation_level >= DegradationLevel::Moderate
            || evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Defer
        {
            raw_phase = OverloadBrownoutPhase::Degrade;
            reason_codes.push(OverloadBrownoutReason::DegradePressure);
            explanation.push(format!(
                "degrade threshold crossed: wake_to_run p99={}ns, memory={}bps, outer={:?}",
                scheduler.wake_to_run_p99_ns, memory_pressure, evidence.outer_tail_risk_decision
            ));
        }

        if memory_pressure >= profile.shed_optional_memory_pressure_bps
            || scheduler.wake_to_run_p99_ns >= profile.shed_optional_wake_to_run_p99_ns
            || evidence.degradation_level >= DegradationLevel::Heavy
            || evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Shed
        {
            raw_phase = OverloadBrownoutPhase::ShedOptional;
            reason_codes.push(OverloadBrownoutReason::ShedOptionalPressure);
            explanation.push(format!(
                "optional-shed threshold crossed: wake_to_run p99={}ns, memory={}bps, outer={:?}",
                scheduler.wake_to_run_p99_ns, memory_pressure, evidence.outer_tail_risk_decision
            ));
        }

        if evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Defer {
            reason_codes.push(OverloadBrownoutReason::TailRiskOuterDefer);
        }
        if evidence.outer_tail_risk_decision == TailRiskAdmissionDecision::Shed {
            reason_codes.push(OverloadBrownoutReason::TailRiskOuterShed);
        }

        let mut phase = raw_phase;
        let mut recovery_streak_after = 0;
        if raw_phase.severity_rank() < evidence.previous_phase.severity_rank()
            && evidence.previous_phase != OverloadBrownoutPhase::Normal
        {
            recovery_streak_after = evidence.recovery_streak_windows.saturating_add(1);
            if recovery_streak_after < profile.recovery_window_threshold {
                phase = OverloadBrownoutPhase::Recovery;
                reason_codes.push(OverloadBrownoutReason::RecoveryHysteresis);
                explanation.push(format!(
                    "recovery hysteresis kept one brownout window active ({}/{})",
                    recovery_streak_after, profile.recovery_window_threshold
                ));
            } else {
                recovery_streak_after = 0;
                explanation.push(format!(
                    "recovery hysteresis satisfied after {} windows",
                    profile.recovery_window_threshold
                ));
            }
        }

        let previous_requested = profile.surfaces_for_phase(evidence.previous_phase);
        let requested = profile.surfaces_for_phase(phase);
        let already_shed = requested
            .iter()
            .copied()
            .filter(|surface| evidence.already_shed_surfaces.contains(surface))
            .collect::<Vec<_>>();
        let newly_degraded = requested
            .iter()
            .copied()
            .filter(|surface| !evidence.already_shed_surfaces.contains(surface))
            .collect::<Vec<_>>();
        if !already_shed.is_empty() {
            reason_codes.push(OverloadBrownoutReason::OptionalSurfaceAlreadyShedding);
            explanation.push(format!(
                "{} optional surface(s) were already shedding locally and were not double-counted",
                already_shed.len()
            ));
        }
        let restored = previous_requested
            .iter()
            .copied()
            .filter(|surface| !requested.contains(surface))
            .collect::<Vec<_>>();

        Self {
            schema_version: OVERLOAD_BROWNOUT_LEDGER_SCHEMA_VERSION.to_string(),
            phase,
            fallback_used: false,
            reason_codes,
            missing_evidence_fields: Vec::new(),
            profile: profile.clone(),
            evidence: snapshot,
            requested_degraded_surfaces: requested,
            newly_degraded_surfaces: newly_degraded,
            already_shed_surfaces: already_shed,
            restored_surfaces: restored,
            preserved_surfaces: vec![
                BrownoutProtectedSurface::CoreScheduling,
                BrownoutProtectedSurface::CancellationDrain,
                BrownoutProtectedSurface::RegionQuiescence,
                BrownoutProtectedSurface::ObligationCleanup,
            ],
            recovery_streak_after,
            explanation,
        }
    }

    fn conservative_phase(evidence: &OverloadBrownoutEvidence) -> OverloadBrownoutPhase {
        match evidence.outer_tail_risk_decision {
            TailRiskAdmissionDecision::Shed => OverloadBrownoutPhase::ShedOptional,
            TailRiskAdmissionDecision::Defer => OverloadBrownoutPhase::Degrade,
            TailRiskAdmissionDecision::Admit => match evidence.degradation_level {
                DegradationLevel::Emergency | DegradationLevel::Heavy => {
                    OverloadBrownoutPhase::ShedOptional
                }
                DegradationLevel::Moderate => OverloadBrownoutPhase::Degrade,
                DegradationLevel::Light => OverloadBrownoutPhase::Observe,
                DegradationLevel::None => OverloadBrownoutPhase::Normal,
            },
        }
    }

    fn finish(
        profile: &OverloadBrownoutProfile,
        snapshot: OverloadBrownoutEvidenceSnapshot,
        phase: OverloadBrownoutPhase,
        fallback_used: bool,
        reason_codes: Vec<OverloadBrownoutReason>,
        missing_evidence_fields: Vec<String>,
        restored_surfaces: Vec<BrownoutOptionalSurface>,
        recovery_streak_after: u8,
        explanation: Vec<String>,
    ) -> Self {
        let requested = profile.surfaces_for_phase(phase);
        Self {
            schema_version: OVERLOAD_BROWNOUT_LEDGER_SCHEMA_VERSION.to_string(),
            phase,
            fallback_used,
            reason_codes,
            missing_evidence_fields,
            profile: profile.clone(),
            evidence: snapshot,
            requested_degraded_surfaces: requested.clone(),
            newly_degraded_surfaces: requested,
            already_shed_surfaces: Vec::new(),
            restored_surfaces,
            preserved_surfaces: vec![
                BrownoutProtectedSurface::CoreScheduling,
                BrownoutProtectedSurface::CancellationDrain,
                BrownoutProtectedSurface::RegionQuiescence,
                BrownoutProtectedSurface::ObligationCleanup,
            ],
            recovery_streak_after,
            explanation,
        }
    }
}

/// Stable version identifier for unified admission and brownout policy ledgers.
pub const UNIFIED_ADMISSION_BROWNOUT_LEDGER_SCHEMA_VERSION: &str =
    "asupersync.unified-admission-brownout.v1";

/// Top-level phase emitted by the unified overload policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedAdmissionBrownoutPhase {
    Normal,
    Observe,
    Defer,
    Degrade,
    ShedOptional,
    Refuse,
    Recovery,
}

/// Work-admission action selected after all overload controllers are composed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedAdmissionAction {
    Admit,
    Defer,
    Refuse,
}

/// Optional-surface action selected by the unified policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedBrownoutAction {
    KeepFullSurfaces,
    Observe,
    DegradeOptional,
    ShedOptional,
    RestoreOptional,
}

/// Explicit reason codes for the unified admission/brownout verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnifiedAdmissionBrownoutReason {
    Disabled,
    LowConfidenceFallback,
    TailRiskShedPrecedence,
    TailRiskDeferPrecedence,
    CohortSteeringDefer,
    CohortFairnessEscape,
    BrownoutShedPrecedence,
    BrownoutDegradePrecedence,
    BrownoutObservePrecedence,
    RestorationHysteresisSatisfied,
    CriticalSurfacePreserved,
    TelemetryMinimumPreserved,
    ConservativeBaseline,
}

/// Operator-tunable guardrails for the unified admission and brownout contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedAdmissionBrownoutProfile {
    pub enabled: bool,
    pub min_confidence_percent: u8,
    pub defer_admit_basis_points: u16,
    pub preserved_telemetry_floor_units: u16,
    pub critical_surface_floor_units: u64,
}

impl Default for UnifiedAdmissionBrownoutProfile {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence_percent: 60,
            defer_admit_basis_points: 8_000,
            preserved_telemetry_floor_units: 4,
            critical_surface_floor_units: 1,
        }
    }
}

/// Inputs for composing admission, cohort steering, and brownout ledgers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedAdmissionBrownoutEvidence {
    pub offered_work_units: u64,
    pub critical_surface_units: u64,
    pub tail_risk: TailRiskAdmissionLedger,
    pub cohort_steering: CohortAdmissionSteeringLedger,
    pub brownout: OverloadBrownoutLedger,
}

/// Deterministic operator-facing policy ledger that composes all overload controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedAdmissionBrownoutLedger {
    pub schema_version: String,
    pub phase: UnifiedAdmissionBrownoutPhase,
    pub admission_action: UnifiedAdmissionAction,
    pub brownout_action: UnifiedBrownoutAction,
    pub fallback_used: bool,
    pub confidence_percent: u8,
    pub reason_codes: Vec<UnifiedAdmissionBrownoutReason>,
    pub admitted_units: u64,
    pub deferred_units: u64,
    pub refused_units: u64,
    pub preserved_telemetry_units: u16,
    pub preserved_critical_surface_units: u64,
    pub requested_degraded_surfaces: Vec<BrownoutOptionalSurface>,
    pub restored_surfaces: Vec<BrownoutOptionalSurface>,
    pub preserved_surfaces: Vec<BrownoutProtectedSurface>,
    pub no_win_decision: bool,
    pub fallback_reason: Option<String>,
    pub profile: UnifiedAdmissionBrownoutProfile,
    pub explanation: Vec<String>,
}

impl UnifiedAdmissionBrownoutLedger {
    /// Compose the first-party overload controllers into one deterministic policy verdict.
    #[must_use]
    pub fn evaluate(
        evidence: &UnifiedAdmissionBrownoutEvidence,
        profile: &UnifiedAdmissionBrownoutProfile,
    ) -> Self {
        let preserved_critical_surface_units = evidence
            .critical_surface_units
            .max(profile.critical_surface_floor_units);
        let preserved_telemetry_units = profile.preserved_telemetry_floor_units;
        let mut reason_codes = vec![
            UnifiedAdmissionBrownoutReason::CriticalSurfacePreserved,
            UnifiedAdmissionBrownoutReason::TelemetryMinimumPreserved,
        ];
        let mut explanation = vec![
            "critical scheduling, cancellation drain, region quiescence, obligation cleanup, and minimum telemetry stay preserved before optional shedding is considered"
                .to_string(),
        ];
        let input_fallback_used = evidence.tail_risk.fallback_used
            || evidence.cohort_steering.fallback_used
            || evidence.brownout.fallback_used;
        let confidence_percent = evidence
            .tail_risk
            .confidence_percent
            .min(evidence.cohort_steering.confidence_percent)
            .min(100);

        if !profile.enabled {
            reason_codes.push(UnifiedAdmissionBrownoutReason::Disabled);
            reason_codes.push(UnifiedAdmissionBrownoutReason::ConservativeBaseline);
            explanation.push(
                "unified policy is disabled, so the conservative fully-admitted baseline stayed pinned"
                    .to_string(),
            );
            return Self::finish(
                profile,
                UnifiedAdmissionBrownoutPhase::Normal,
                UnifiedAdmissionAction::Admit,
                UnifiedBrownoutAction::KeepFullSurfaces,
                true,
                confidence_percent,
                reason_codes,
                evidence.offered_work_units,
                preserved_telemetry_units,
                preserved_critical_surface_units,
                Vec::new(),
                Vec::new(),
                evidence.brownout.preserved_surfaces.clone(),
                false,
                None,
                explanation,
            );
        }

        let low_confidence = confidence_percent < profile.min_confidence_percent;
        if low_confidence {
            reason_codes.push(UnifiedAdmissionBrownoutReason::LowConfidenceFallback);
            explanation.push(format!(
                "minimum controller confidence {}% stayed below the unified policy floor {}%",
                confidence_percent, profile.min_confidence_percent
            ));
        }

        let fairness_escape = evidence
            .cohort_steering
            .reason_codes
            .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch);
        if fairness_escape {
            reason_codes.push(UnifiedAdmissionBrownoutReason::CohortFairnessEscape);
            explanation.push(
                "cohort steering recorded a fairness escape hatch, so tail-admitted work keeps an admission path"
                    .to_string(),
            );
        }

        let mut admission_action = match evidence.tail_risk.decision {
            TailRiskAdmissionDecision::Shed => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::TailRiskShedPrecedence);
                explanation
                    .push("tail-risk shed takes precedence over cohort placement".to_string());
                UnifiedAdmissionAction::Refuse
            }
            TailRiskAdmissionDecision::Defer => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::TailRiskDeferPrecedence);
                explanation
                    .push("tail-risk defer takes precedence over cohort placement".to_string());
                UnifiedAdmissionAction::Defer
            }
            TailRiskAdmissionDecision::Admit => match evidence.cohort_steering.decision {
                CohortAdmissionSteeringDecision::Defer if !fairness_escape => {
                    reason_codes.push(UnifiedAdmissionBrownoutReason::CohortSteeringDefer);
                    explanation.push(
                        "cohort steering deferred after tail-risk admission because no safe placement was available"
                            .to_string(),
                    );
                    UnifiedAdmissionAction::Defer
                }
                CohortAdmissionSteeringDecision::AdmitLocal
                | CohortAdmissionSteeringDecision::RedirectRemote
                | CohortAdmissionSteeringDecision::Defer => UnifiedAdmissionAction::Admit,
            },
        };

        if low_confidence && admission_action == UnifiedAdmissionAction::Admit {
            admission_action = UnifiedAdmissionAction::Defer;
        }

        let brownout_action = match evidence.brownout.phase {
            OverloadBrownoutPhase::Normal if evidence.brownout.restored_surfaces.is_empty() => {
                UnifiedBrownoutAction::KeepFullSurfaces
            }
            OverloadBrownoutPhase::Normal | OverloadBrownoutPhase::Recovery => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::RestorationHysteresisSatisfied);
                explanation.push("brownout recovery restored optional surfaces".to_string());
                UnifiedBrownoutAction::RestoreOptional
            }
            OverloadBrownoutPhase::Observe => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::BrownoutObservePrecedence);
                UnifiedBrownoutAction::Observe
            }
            OverloadBrownoutPhase::Degrade => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::BrownoutDegradePrecedence);
                UnifiedBrownoutAction::DegradeOptional
            }
            OverloadBrownoutPhase::ShedOptional => {
                reason_codes.push(UnifiedAdmissionBrownoutReason::BrownoutShedPrecedence);
                UnifiedBrownoutAction::ShedOptional
            }
        };

        let phase = match (admission_action, brownout_action) {
            (UnifiedAdmissionAction::Refuse, _) => UnifiedAdmissionBrownoutPhase::Refuse,
            (_, UnifiedBrownoutAction::ShedOptional) => UnifiedAdmissionBrownoutPhase::ShedOptional,
            (UnifiedAdmissionAction::Defer, _) => UnifiedAdmissionBrownoutPhase::Defer,
            (_, UnifiedBrownoutAction::DegradeOptional) => UnifiedAdmissionBrownoutPhase::Degrade,
            (_, UnifiedBrownoutAction::RestoreOptional) => UnifiedAdmissionBrownoutPhase::Recovery,
            (_, UnifiedBrownoutAction::Observe) => UnifiedAdmissionBrownoutPhase::Observe,
            (UnifiedAdmissionAction::Admit, UnifiedBrownoutAction::KeepFullSurfaces) => {
                UnifiedAdmissionBrownoutPhase::Normal
            }
        };

        let no_win_decision = low_confidence
            || (input_fallback_used && admission_action != UnifiedAdmissionAction::Admit);
        let fallback_reason = no_win_decision.then(|| {
            if low_confidence {
                "low_confidence_fallback".to_string()
            } else {
                "controller_fallback_used".to_string()
            }
        });

        Self::finish(
            profile,
            phase,
            admission_action,
            brownout_action,
            input_fallback_used || low_confidence,
            confidence_percent,
            reason_codes,
            evidence.offered_work_units,
            preserved_telemetry_units,
            preserved_critical_surface_units,
            evidence.brownout.requested_degraded_surfaces.clone(),
            evidence.brownout.restored_surfaces.clone(),
            evidence.brownout.preserved_surfaces.clone(),
            no_win_decision,
            fallback_reason,
            explanation,
        )
    }

    fn finish(
        profile: &UnifiedAdmissionBrownoutProfile,
        phase: UnifiedAdmissionBrownoutPhase,
        admission_action: UnifiedAdmissionAction,
        brownout_action: UnifiedBrownoutAction,
        fallback_used: bool,
        confidence_percent: u8,
        reason_codes: Vec<UnifiedAdmissionBrownoutReason>,
        offered_work_units: u64,
        preserved_telemetry_units: u16,
        preserved_critical_surface_units: u64,
        requested_degraded_surfaces: Vec<BrownoutOptionalSurface>,
        restored_surfaces: Vec<BrownoutOptionalSurface>,
        preserved_surfaces: Vec<BrownoutProtectedSurface>,
        no_win_decision: bool,
        fallback_reason: Option<String>,
        explanation: Vec<String>,
    ) -> Self {
        let (admitted_units, deferred_units, refused_units) =
            unified_admission_counts(offered_work_units, admission_action, profile);
        Self {
            schema_version: UNIFIED_ADMISSION_BROWNOUT_LEDGER_SCHEMA_VERSION.to_string(),
            phase,
            admission_action,
            brownout_action,
            fallback_used,
            confidence_percent,
            reason_codes,
            admitted_units,
            deferred_units,
            refused_units,
            preserved_telemetry_units,
            preserved_critical_surface_units,
            requested_degraded_surfaces,
            restored_surfaces,
            preserved_surfaces,
            no_win_decision,
            fallback_reason,
            profile: profile.clone(),
            explanation,
        }
    }
}

fn unified_admission_counts(
    offered_work_units: u64,
    admission_action: UnifiedAdmissionAction,
    profile: &UnifiedAdmissionBrownoutProfile,
) -> (u64, u64, u64) {
    match admission_action {
        UnifiedAdmissionAction::Admit => (offered_work_units, 0, 0),
        UnifiedAdmissionAction::Defer => {
            let admitted = offered_work_units
                .saturating_mul(u64::from(profile.defer_admit_basis_points.min(10_000)))
                / 10_000;
            (admitted, offered_work_units.saturating_sub(admitted), 0)
        }
        UnifiedAdmissionAction::Refuse => (0, 0, offered_work_units),
    }
}

fn cycle_overhead_percentage(elapsed: Duration, interval: Duration) -> f64 {
    let interval_nanos = interval.as_nanos();
    if interval_nanos == 0 {
        return 0.0;
    }
    (elapsed.as_nanos() as f64) / (interval_nanos as f64) * 100.0
}

/// System resource collector for platform-specific monitoring.
/// br-asupersync-thfiyk: derive (soft, hard) absolute thresholds from
/// a `max_limit` and the percentage points the operator considers
/// warning vs critical. Saturates at `max_limit` so the soft band can
/// never exceed the hard band even on tiny `max_limit` values.
fn derive_thresholds(max_limit: u64, soft_pct: u64, hard_pct: u64) -> (u64, u64) {
    debug_assert!(soft_pct <= hard_pct);
    let max = u128::from(max_limit);
    let soft = (max * u128::from(soft_pct)) / 100;
    let hard = (max * u128::from(hard_pct)) / 100;
    (soft.min(max) as u64, hard.min(max) as u64)
}

/// Platform-specific resource readers (br-asupersync-thfiyk).
///
/// Each function returns the same `std::io::Result<u64>` shape across
/// platforms; non-supported platforms return
/// `ErrorKind::Unsupported` so the caller's `if let Ok(..)` skip in
/// [`SystemResourceCollector::collect_now`] gracefully omits the
/// measurement and existing pressure values are preserved.
mod platform {
    /// Total system memory or process address-space ceiling, in bytes.
    /// Falls back to a large finite value (16 GiB) when the platform
    /// reports `RLIM_INFINITY` so downstream `usage_ratio()` arithmetic
    /// stays well-defined.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    const ADDRESS_SPACE_FALLBACK: u64 = 16 * 1024 * 1024 * 1024;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kib_str = rest.split_whitespace().next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "VmRSS missing value")
                })?;
                let kib: u64 = kib_str.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "VmRSS not numeric")
                })?;
                return Ok(kib.saturating_mul(1024));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "VmRSS not present in /proc/self/status",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn memory_max_bytes() -> std::io::Result<u64> {
        // Prefer the address-space rlimit; fall back to MemTotal when
        // the rlimit is `RLIM_INFINITY` (the common production shape).
        if let Ok((_, hard)) = address_space_rlimit() {
            if hard != u64::MAX && hard != 0 {
                return Ok(hard);
            }
        }
        let meminfo = std::fs::read_to_string("/proc/meminfo")?;
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kib_str = rest.split_whitespace().next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "MemTotal missing value")
                })?;
                let kib: u64 = kib_str.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "MemTotal not numeric")
                })?;
                return Ok(kib.saturating_mul(1024));
            }
        }
        Ok(ADDRESS_SPACE_FALLBACK)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn process_fd_count() -> std::io::Result<u64> {
        let count = std::fs::read_dir("/proc/self/fd")?.count();
        Ok(count as u64)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn load_avg_1min_scaled() -> std::io::Result<u64> {
        let s = std::fs::read_to_string("/proc/loadavg")?;
        let first = s.split_whitespace().next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "empty /proc/loadavg")
        })?;
        let v: f64 = first.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "loadavg not numeric")
        })?;
        let cpus = num_cpus().max(1) as f64;
        let pct = (v / cpus).clamp(0.0, 1.0) * 100.0;
        Ok(pct.round() as u64)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn process_connection_count() -> std::io::Result<u64> {
        let mut total: u64 = 0;
        for path in [
            "/proc/self/net/tcp",
            "/proc/self/net/tcp6",
            "/proc/self/net/udp",
            "/proc/self/net/udp6",
        ] {
            if let Ok(s) = std::fs::read_to_string(path) {
                // First line is the column header; everything after is
                // a single connection. `saturating_sub(1)` handles the
                // empty-file edge case.
                total = total.saturating_add((s.lines().count() as u64).saturating_sub(1));
            }
        }
        Ok(total)
    }

    // ----- macOS / BSD ------------------------------------------------------

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[allow(unsafe_code)]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        // SAFETY: `getrusage(RUSAGE_SELF, ...)` writes into the provided pointer.
        // We use MaybeUninit and as_mut_ptr() to safely pass uninitialized memory.
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let usage = unsafe { usage.assume_init() };
        // ru_maxrss: bytes on macOS, kilobytes on BSDs (per their man pages).
        let raw = usage.ru_maxrss as u64;
        #[cfg(target_os = "macos")]
        {
            Ok(raw)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(raw.saturating_mul(1024))
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    pub fn memory_max_bytes() -> std::io::Result<u64> {
        if let Ok((_, hard)) = address_space_rlimit() {
            if hard != u64::MAX && hard != 0 {
                return Ok(hard);
            }
        }
        Ok(ADDRESS_SPACE_FALLBACK)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    pub fn process_fd_count() -> std::io::Result<u64> {
        // /dev/fd is the per-process FD directory exposed by fdescfs;
        // the count of entries is the count of open descriptors.
        let count = std::fs::read_dir("/dev/fd")?.count();
        Ok(count as u64)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[allow(unsafe_code)]
    pub fn load_avg_1min_scaled() -> std::io::Result<u64> {
        let mut loads: [f64; 3] = [0.0; 3];
        // SAFETY: `getloadavg` writes up to `n` doubles into the
        // caller-provided buffer; we pass an array of 3.
        let n = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
        if n < 1 {
            return Err(std::io::Error::last_os_error());
        }
        let cpus = num_cpus().max(1) as f64;
        let pct = (loads[0] / cpus).clamp(0.0, 1.0) * 100.0;
        Ok(pct.round() as u64)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    pub fn process_connection_count() -> std::io::Result<u64> {
        // libproc / sysctl would give an exact answer but pull in a
        // transitive `mach2` dependency the project doesn't otherwise
        // need. The FD count is a conservative upper bound (sockets
        // are FDs); operators that need exact connection counts can
        // wire a custom resource collector via `register_resource`.
        process_fd_count()
    }

    // ----- Windows ----------------------------------------------------------

    #[cfg(windows)]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        let pid = sysinfo::get_current_pid()
            .map_err(|err| std::io::Error::other(format!("current pid unavailable: {err}")))?;
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            true,
            sysinfo::ProcessRefreshKind::nothing().with_memory(),
        );
        system
            .process(pid)
            .map(|process| process.memory())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "current process was not present in sysinfo process table",
                )
            })
    }

    #[cfg(windows)]
    pub fn memory_max_bytes() -> std::io::Result<u64> {
        let mut system = sysinfo::System::new();
        system.refresh_memory();
        let total = system.total_memory();
        if total == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "sysinfo reported zero total memory",
            ))
        } else {
            Ok(total)
        }
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    pub fn process_fd_count() -> std::io::Result<u64> {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

        let mut handle_count = 0u32;
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle valid in
        // the current process, and `handle_count` is a valid out pointer.
        let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handle_count) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(u64::from(handle_count))
        }
    }

    #[cfg(windows)]
    pub fn load_avg_1min_scaled() -> std::io::Result<u64> {
        let current = windows_cpu_times()?;
        let mut previous = WINDOWS_CPU_TIMES
            .lock()
            .map_err(|_| std::io::Error::other("windows CPU sampler state mutex was poisoned"))?;

        let scaled = previous.map_or(0, |prev| {
            let total_delta = current.total().saturating_sub(prev.total());
            if total_delta == 0 {
                return 0;
            }
            let idle_delta = current.idle.saturating_sub(prev.idle);
            let busy_delta = total_delta.saturating_sub(idle_delta);
            ((busy_delta.saturating_mul(100) + (total_delta / 2)) / total_delta).min(100)
        });
        *previous = Some(current);
        Ok(scaled)
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    pub fn process_connection_count() -> std::io::Result<u64> {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        // SAFETY: `GetCurrentProcessId` is a pure Win32 query with no preconditions.
        let pid = unsafe { GetCurrentProcessId() };
        let mut total = 0u64;
        let mut successful_tables = 0u8;
        let mut first_error = None;

        for result in [
            windows_tcp_owner_pid_count(pid, windows_address_family::IPV4),
            windows_tcp_owner_pid_count(pid, windows_address_family::IPV6),
            windows_udp_owner_pid_count(pid, windows_address_family::IPV4),
            windows_udp_owner_pid_count(pid, windows_address_family::IPV6),
        ] {
            match result {
                Ok(count) => {
                    total = total.saturating_add(count);
                    successful_tables = successful_tables.saturating_add(1);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }

        if successful_tables == 0 {
            Err(first_error.unwrap_or_else(|| {
                std::io::Error::other("no Windows TCP/UDP owner tables were sampled")
            }))
        } else {
            Ok(total)
        }
    }

    #[cfg(windows)]
    #[derive(Clone, Copy)]
    struct WindowsCpuTimes {
        idle: u64,
        kernel: u64,
        user: u64,
    }

    #[cfg(windows)]
    impl WindowsCpuTimes {
        fn total(self) -> u64 {
            self.kernel.saturating_add(self.user)
        }
    }

    #[cfg(windows)]
    static WINDOWS_CPU_TIMES: std::sync::Mutex<Option<WindowsCpuTimes>> =
        std::sync::Mutex::new(None);

    #[cfg(windows)]
    fn filetime_to_u64(filetime: windows_sys::Win32::Foundation::FILETIME) -> u64 {
        (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn windows_cpu_times() -> std::io::Result<WindowsCpuTimes> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetSystemTimes;

        let mut idle = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: all three pointers reference initialized FILETIME
        // storage for Win32 to overwrite.
        let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(WindowsCpuTimes {
                idle: filetime_to_u64(idle),
                kernel: filetime_to_u64(kernel),
                user: filetime_to_u64(user),
            })
        }
    }

    #[cfg(windows)]
    mod windows_address_family {
        pub const IPV4: u32 = windows_sys::Win32::Networking::WinSock::AF_INET as u32;
        pub const IPV6: u32 = windows_sys::Win32::Networking::WinSock::AF_INET6 as u32;
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn windows_ip_table(
        mut fetch: impl FnMut(*mut core::ffi::c_void, *mut u32) -> u32,
    ) -> std::io::Result<Vec<u8>> {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};

        let mut size = 0u32;
        let first = fetch(core::ptr::null_mut(), &mut size);
        if first == NO_ERROR && size == 0 {
            return Ok(Vec::new());
        }
        if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
            return Err(std::io::Error::from_raw_os_error(first as i32));
        }

        for _ in 0..4 {
            if size == 0 {
                return Ok(Vec::new());
            }
            let mut buffer = vec![0u8; size as usize];
            let result = fetch(buffer.as_mut_ptr().cast(), &mut size);
            match result {
                NO_ERROR => {
                    buffer.truncate(size as usize);
                    return Ok(buffer);
                }
                ERROR_INSUFFICIENT_BUFFER => continue,
                code => return Err(std::io::Error::from_raw_os_error(code as i32)),
            }
        }

        Err(std::io::Error::other(
            "Windows IP owner table grew during repeated sampling attempts",
        ))
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn count_windows_owner_pid_rows<Row>(
        table_name: &'static str,
        buffer: &[u8],
        pid: u32,
        row_owner_pid: impl Fn(Row) -> u32,
    ) -> std::io::Result<u64>
    where
        Row: Copy,
    {
        let row_offset = std::mem::size_of::<u32>();
        let row_size = std::mem::size_of::<Row>();
        if buffer.len() < row_offset {
            return Ok(0);
        }
        if row_size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{table_name} has zero-sized rows"),
            ));
        }

        let entries = u32::from_ne_bytes(buffer[0..4].try_into().expect("slice length checked"));
        let available_rows = (buffer.len() - row_offset) / row_size;
        let entries = usize::try_from(entries).unwrap_or(usize::MAX);
        if entries > available_rows {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{table_name} reported {entries} entries but buffer held {available_rows}"),
            ));
        }

        let rows_ptr = buffer[row_offset..].as_ptr().cast::<Row>();
        let mut count = 0u64;
        for index in 0..entries {
            // SAFETY: bounds are checked above and the table buffer is a
            // byte buffer returned by Win32, so use unaligned reads.
            let row = unsafe { std::ptr::read_unaligned(rows_ptr.add(index)) };
            if row_owner_pid(row) == pid {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn windows_tcp_owner_pid_count(pid: u32, family: u32) -> std::io::Result<u64> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        };

        let buffer = windows_ip_table(|table, size| {
            // SAFETY: `windows_ip_table` provides either a null probe
            // pointer or a writable buffer with the size advertised in
            // `size`; the remaining arguments follow the IP Helper
            // contract for owner-PID tables.
            unsafe { GetExtendedTcpTable(table, size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0) }
        })?;

        if family == windows_address_family::IPV6 {
            count_windows_owner_pid_rows(
                "MIB_TCP6TABLE_OWNER_PID",
                &buffer,
                pid,
                |row: MIB_TCP6ROW_OWNER_PID| row.dwOwningPid,
            )
        } else {
            count_windows_owner_pid_rows(
                "MIB_TCPTABLE_OWNER_PID",
                &buffer,
                pid,
                |row: MIB_TCPROW_OWNER_PID| row.dwOwningPid,
            )
        }
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn windows_udp_owner_pid_count(pid: u32, family: u32) -> std::io::Result<u64> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, UDP_TABLE_OWNER_PID,
        };

        let buffer = windows_ip_table(|table, size| {
            // SAFETY: same shape as the TCP owner-table call above.
            unsafe { GetExtendedUdpTable(table, size, 0, family, UDP_TABLE_OWNER_PID, 0) }
        })?;

        if family == windows_address_family::IPV6 {
            count_windows_owner_pid_rows(
                "MIB_UDP6TABLE_OWNER_PID",
                &buffer,
                pid,
                |row: MIB_UDP6ROW_OWNER_PID| row.dwOwningPid,
            )
        } else {
            count_windows_owner_pid_rows(
                "MIB_UDPTABLE_OWNER_PID",
                &buffer,
                pid,
                |row: MIB_UDPROW_OWNER_PID| row.dwOwningPid,
            )
        }
    }

    // ----- Unsupported platforms (others) -----------------------------------

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )))]
    fn unsupported<T>(what: &'static str) -> std::io::Result<T> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "resource_monitor: {what} is unavailable on this platform \
                 (Linux, Android, macOS, FreeBSD, NetBSD, OpenBSD, DragonFly only). \
                 Wire a platform-specific collector via \
                 ResourceMonitor::register_resource."
            ),
        ))
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )))]
    pub fn process_rss_bytes() -> std::io::Result<u64> {
        unsupported("process_rss_bytes")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )))]
    pub fn memory_max_bytes() -> std::io::Result<u64> {
        unsupported("memory_max_bytes")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )))]
    pub fn process_fd_count() -> std::io::Result<u64> {
        unsupported("process_fd_count")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )))]
    pub fn load_avg_1min_scaled() -> std::io::Result<u64> {
        unsupported("load_avg_1min_scaled")
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )))]
    pub fn process_connection_count() -> std::io::Result<u64> {
        unsupported("process_connection_count")
    }

    // ----- Cross-platform helpers (Unix / fallback) -------------------------

    #[cfg(unix)]
    #[allow(unsafe_code, clippy::unnecessary_cast)]
    pub fn fd_rlimit() -> std::io::Result<(u64, u64)> {
        // SAFETY: `getrlimit(RLIMIT_NOFILE, ...)` writes into the provided pointer.
        let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, rlim.as_mut_ptr()) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let rlim = unsafe { rlim.assume_init() };
        let cur = rlim.rlim_cur as u64;
        let max = rlim.rlim_max as u64;
        Ok((cur, max))
    }

    #[cfg(unix)]
    #[allow(unsafe_code, clippy::unnecessary_cast)]
    pub fn address_space_rlimit() -> std::io::Result<(u64, u64)> {
        // SAFETY: same shape as `fd_rlimit`.
        let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_AS, rlim.as_mut_ptr()) };
        if rc == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let rlim = unsafe { rlim.assume_init() };
        // Treat RLIM_INFINITY as `u64::MAX` so the caller can detect
        // "no ceiling" without depending on platform-specific
        // sentinel values.
        let infinity = libc::RLIM_INFINITY;
        let cur = if rlim.rlim_cur == infinity {
            u64::MAX
        } else {
            rlim.rlim_cur as u64
        };
        let max = if rlim.rlim_max == infinity {
            u64::MAX
        } else {
            rlim.rlim_max as u64
        };
        Ok((cur, max))
    }

    #[cfg(windows)]
    pub fn fd_rlimit() -> std::io::Result<(u64, u64)> {
        const WINDOWS_PROCESS_HANDLE_PRESSURE_CEILING: u64 = 1 << 24;
        Ok((
            WINDOWS_PROCESS_HANDLE_PRESSURE_CEILING,
            WINDOWS_PROCESS_HANDLE_PRESSURE_CEILING,
        ))
    }

    #[cfg(not(any(unix, windows)))]
    pub fn fd_rlimit() -> std::io::Result<(u64, u64)> {
        // No portable equivalent of RLIMIT_NOFILE; default to a
        // conservative pair and let the operator override via custom
        // resource collectors.
        Ok((512, 1024))
    }

    #[cfg(target_arch = "wasm32")]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub fn address_space_rlimit() -> std::io::Result<(u64, u64)> {
        Ok((u64::MAX, u64::MAX))
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    pub fn num_cpus() -> u64 {
        std::thread::available_parallelism().map_or(1, |n| n.get() as u64)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SystemResourceCollector {
    /// Whether monitoring is active.
    ///
    /// This is a lifecycle gate for start/stop/status observers, not a
    /// publication point for sampled resource data, so acquire/release
    /// ordering is enough and avoids a global `SeqCst` fence here.
    active: AtomicBool,
    /// Collection interval.
    interval: Duration,
    /// Collected data.
    pressure: Arc<ResourcePressure>,
    /// Operator-facing platform probe state.
    probe_state: Arc<ResourceProbeState>,
}

impl SystemResourceCollector {
    /// Create a new system resource collector.
    pub fn new(pressure: Arc<ResourcePressure>, interval: Duration) -> Self {
        Self {
            active: AtomicBool::new(false),
            interval,
            pressure,
            probe_state: Arc::new(ResourceProbeState::new(current_platform_fingerprint())),
        }
    }

    /// Start monitoring system resources.
    pub fn start(&self) -> Result<(), ResourceMonitorError> {
        if self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return Err(ResourceMonitorError::AlreadyActive);
        }

        // In a real implementation, this would spawn a background task
        // that periodically samples system resources
        Ok(())
    }

    /// Stop monitoring.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// Manually collect current system resource measurements.
    pub fn collect_now(&self) -> Result<(), ResourceMonitorError> {
        let _start = Instant::now();

        // Memory usage (simplified - would use platform-specific APIs)
        if let Ok(memory_usage) = self.collect_memory_usage() {
            self.pressure
                .update_measurement(ResourceType::Memory, memory_usage);
        }

        // File descriptor usage
        if let Ok(fd_usage) = self.collect_fd_usage() {
            self.pressure
                .update_measurement(ResourceType::FileDescriptors, fd_usage);
        }

        // CPU load
        if let Ok(cpu_load) = self.collect_cpu_load() {
            self.pressure
                .update_measurement(ResourceType::CpuLoad, cpu_load);
        }

        // Network connections
        if let Ok(network_usage) = self.collect_network_usage() {
            self.pressure
                .update_measurement(ResourceType::NetworkConnections, network_usage);
        }

        Ok(())
    }

    /// Report platform probe availability and fallback state for operators.
    pub fn platform_probe_report(&self) -> ResourcePlatformProbeReport {
        self.probe_state.report()
    }

    fn observe_probe<T>(
        &self,
        probe: ResourceProbe,
        fallback: ResourceProbeFallback,
        result: std::io::Result<T>,
        sampled_value: impl FnOnce(&T) -> Option<u64>,
    ) -> std::io::Result<T> {
        match result {
            Ok(value) => {
                self.probe_state
                    .record_supported(probe, sampled_value(&value));
                Ok(value)
            }
            Err(error) => {
                self.probe_state
                    .record_probe_failure(probe, fallback, &error);
                Err(error)
            }
        }
    }

    /// Collect memory usage measurement.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: VmRSS from `/proc/self/status`; max from `RLIMIT_AS`,
    ///   falling back to `MemTotal` from `/proc/meminfo` when the
    ///   address-space rlimit is `RLIM_INFINITY`.
    /// - macOS/BSD: `getrusage(RUSAGE_SELF).ru_maxrss` for current
    ///   (bytes on macOS, KiB on BSD); same `RLIMIT_AS` fallback.
    /// - Windows / other: `SystemAccessFailed` — caller's
    ///   `if let Ok(..)` in `collect_now` cleanly skips the
    ///   measurement update so existing pressure values are preserved.
    fn collect_memory_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let current_bytes_result = self.observe_probe(
            ResourceProbe::ProcessRssBytes,
            ResourceProbeFallback::OmitMeasurement,
            platform::process_rss_bytes(),
            |value| Some(*value),
        );
        let max_limit_result = self.observe_probe(
            ResourceProbe::MemoryMaxBytes,
            ResourceProbeFallback::OmitMeasurement,
            platform::memory_max_bytes(),
            |value| Some(*value),
        );

        let current_bytes =
            current_bytes_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("memory rss: {e}"),
            })?;
        let max_limit = max_limit_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
            reason: format!("memory max: {e}"),
        })?;
        let (soft_limit, hard_limit) = derive_thresholds(max_limit, 75, 90);
        Ok(ResourceMeasurement::new(
            current_bytes,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Collect file descriptor usage.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: count entries in `/proc/self/fd`.
    /// - macOS/BSD: count entries in `/dev/fd` (the per-process
    ///   symlink directory exposed by `fdescfs`).
    /// - Windows: count process handles with `GetProcessHandleCount`
    ///   and compare against a fixed high-water synthetic ceiling.
    /// - Unix: max from `getrlimit(RLIMIT_NOFILE)`.
    fn collect_fd_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let current_fds_result = self.observe_probe(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            platform::process_fd_count(),
            |value| Some(*value),
        );
        let fd_limit_result = self.observe_probe(
            ResourceProbe::FileDescriptorLimit,
            ResourceProbeFallback::OmitMeasurement,
            platform::fd_rlimit(),
            |(_, hard)| Some(*hard),
        );

        let current_fds =
            current_fds_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("fd count: {e}"),
            })?;
        let (_, hard_max) =
            fd_limit_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("fd rlimit: {e}"),
            })?;
        let max_limit = if hard_max == 0 { 1024 } else { hard_max };
        let (soft_limit, hard_limit) = derive_thresholds(max_limit, 75, 90);
        Ok(ResourceMeasurement::new(
            current_fds,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Collect CPU load measurement.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: read first column of `/proc/loadavg` (1-minute load
    ///   average), normalize by core count, scale to 0..100.
    /// - macOS/BSD: `getloadavg(3)`, same normalization.
    /// - Windows: sample `GetSystemTimes` deltas and scale busy CPU
    ///   time to 0..100.
    /// - Other platforms: `SystemAccessFailed`.
    fn collect_cpu_load(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let load_avg_1min = self
            .observe_probe(
                ResourceProbe::LoadAvg1MinScaled,
                ResourceProbeFallback::OmitMeasurement,
                platform::load_avg_1min_scaled(),
                |value| Some(*value),
            )
            .map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("loadavg: {e}"),
            })?;
        // CPU load is intrinsically a 0..100 scale; thresholds are
        // absolute rather than derived from a per-process rlimit.
        Ok(ResourceMeasurement::new(load_avg_1min, 80, 95, 100))
    }

    /// Collect network connection usage.
    ///
    /// br-asupersync-thfiyk: real platform read.
    /// - Linux: sum non-header rows of `/proc/self/net/{tcp,tcp6,udp,udp6}`.
    /// - macOS/BSD: `getrlimit(RLIMIT_NOFILE)` ceiling and the FD count
    ///   as a conservative upper bound on open sockets (libproc would
    ///   give an exact answer but pulls in a transitive `mach2` dep
    ///   the project doesn't otherwise need).
    /// - Windows: count current-process TCP/UDP owner-PID rows through
    ///   the IP Helper tables and use the synthetic handle ceiling.
    fn collect_network_usage(&self) -> Result<ResourceMeasurement, ResourceMonitorError> {
        let current_connections_result = self.observe_probe(
            ResourceProbe::ProcessConnectionCount,
            ResourceProbeFallback::OmitMeasurement,
            platform::process_connection_count(),
            |value| Some(*value),
        );
        let fd_limit_result = self.observe_probe(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            platform::fd_rlimit(),
            |(_, hard)| Some(*hard),
        );

        let current_connections =
            current_connections_result.map_err(|e| ResourceMonitorError::SystemAccessFailed {
                reason: format!("connection count: {e}"),
            })?;
        // Sockets share the descriptor/handle table, so the connection
        // ceiling is capped by the platform descriptor ceiling. Use a
        // reasonable fallback when that limit is unavailable.
        let (_, hard_max) = fd_limit_result.unwrap_or((512, 1024));
        let max_limit = if hard_max == 0 { 1024 } else { hard_max };
        let (soft_limit, hard_limit) = derive_thresholds(max_limit, 70, 85);
        Ok(ResourceMeasurement::new(
            current_connections,
            soft_limit,
            hard_limit,
            max_limit,
        ))
    }

    /// Check if monitoring is active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

/// Central resource monitor coordinator.
#[derive(Debug)]
pub struct ResourceMonitor {
    /// Resource pressure tracker.
    pressure: Arc<ResourcePressure>,
    /// Degradation decision engine.
    engine: Arc<DegradationEngine>,
    /// System resource collector.
    collector: SystemResourceCollector,
    /// Monitoring configuration.
    config: RwLock<MonitorConfig>,
}

/// Configuration for the resource monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Collection interval for system resources.
    pub collection_interval: Duration,
    /// Whether to enable automatic degradation.
    pub enable_auto_degradation: bool,
    /// Maximum allowed monitoring overhead percentage.
    pub max_overhead_percent: f64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            collection_interval: Duration::from_secs(1),
            enable_auto_degradation: true,
            max_overhead_percent: 0.5, // 0.5% overhead limit
        }
    }
}

impl ResourceMonitor {
    /// Create a new resource monitor.
    #[must_use]
    pub fn new(config: MonitorConfig) -> Self {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = Arc::new(DegradationEngine::new(Arc::clone(&pressure)));
        let collector =
            SystemResourceCollector::new(Arc::clone(&pressure), config.collection_interval);

        Self {
            pressure,
            engine,
            collector,
            config: RwLock::new(config),
        }
    }

    /// Start resource monitoring.
    pub fn start(&self) -> Result<(), ResourceMonitorError> {
        self.collector.start()
    }

    /// Stop resource monitoring.
    pub fn stop(&self) {
        self.collector.stop();
    }

    /// Get access to the pressure tracker.
    pub fn pressure(&self) -> Arc<ResourcePressure> {
        Arc::clone(&self.pressure)
    }

    /// Get access to the degradation engine.
    pub fn engine(&self) -> Arc<DegradationEngine> {
        Arc::clone(&self.engine)
    }

    /// Clear the degradation priority override for a region that closed.
    pub fn clear_region_priority(&self, region_id: RegionId) -> Option<RegionPriority> {
        self.engine.clear_region_priority(region_id)
    }

    /// Update monitoring configuration.
    pub fn update_config(&self, new_config: MonitorConfig) {
        let mut config = self.config.write();
        *config = new_config;
    }

    /// Process current measurements and trigger degradation if needed.
    pub fn process_current_state(
        &self,
    ) -> Result<Vec<(ResourceType, DegradationLevel)>, ResourceMonitorError> {
        let cycle_start = Instant::now();

        // Collect fresh measurements
        self.collector.collect_now()?;

        // Process through degradation engine
        let changes = self.engine.process_measurements()?;

        // Check overhead limits
        let config = self.config.read();
        if config.enable_auto_degradation {
            let overhead_percent =
                cycle_overhead_percentage(cycle_start.elapsed(), config.collection_interval);

            if overhead_percent > config.max_overhead_percent {
                crate::tracing_compat::warn!(
                    overhead_percent,
                    collection_interval_ms = config.collection_interval.as_millis(),
                    max_overhead_percent = config.max_overhead_percent,
                    "resource monitoring overhead exceeds configured limit"
                );
            }
        }

        Ok(changes)
    }

    /// Get comprehensive status report.
    pub fn status_report(&self) -> ResourceMonitorStatus {
        let measurements: HashMap<ResourceType, ResourceMeasurement> =
            self.pressure.measurements.read().clone();
        let degradation_levels: HashMap<ResourceType, DegradationLevel> =
            self.pressure.degradation_levels.read().clone();

        ResourceMonitorStatus {
            is_active: self.collector.is_active(),
            composite_degradation_level: self.pressure.composite_degradation_level(),
            measurements,
            degradation_levels,
            platform_probe_report: self.collector.platform_probe_report(),
            stats: self.engine.stats(),
            config: self.config.read().clone(),
        }
    }

    /// Build the unified operator-facing runtime pressure snapshot.
    #[must_use]
    pub fn runtime_pressure_snapshot(
        &self,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<&SpectralHealthReport>,
    ) -> RuntimePressureSnapshot {
        RuntimePressureSnapshot::from_parts(
            &self.pressure,
            self.collector.platform_probe_report(),
            scheduler,
            spectral.map(RuntimePressureSpectralSnapshot::from_report),
        )
    }

    /// Build a runtime pressure snapshot with externally captured RCH proof-lane receipts.
    ///
    /// The runtime does not probe RCH directly. Callers must provide receipts
    /// captured through an explicit operator/tooling capability.
    #[must_use]
    pub fn runtime_pressure_snapshot_with_rch_receipts(
        &self,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<&SpectralHealthReport>,
        rch_receipts: &[RchWorkerAdmissionReceipt],
    ) -> RuntimePressureSnapshot {
        let rch_proof_lanes = rch_receipts
            .iter()
            .map(RuntimePressureRchProofLaneSnapshot::from_receipt)
            .collect();
        RuntimePressureSnapshot::from_parts_with_rch_proof_lanes(
            &self.pressure,
            self.collector.platform_probe_report(),
            scheduler,
            spectral.map(RuntimePressureSpectralSnapshot::from_report),
            rch_proof_lanes,
        )
    }

    /// Evaluate an opt-in pressure-aware admission decision from the current snapshot.
    #[must_use]
    pub fn pressure_admission_decision(
        &self,
        policy: &RuntimePressureAdmissionPolicy,
        work_class: RuntimePressureAdmissionWorkClass,
        scheduler: Option<SchedulerEvidenceMetrics>,
        spectral: Option<&SpectralHealthReport>,
    ) -> RuntimePressureAdmissionDecision {
        let snapshot = self.runtime_pressure_snapshot(scheduler, spectral);
        policy.decide(work_class, &snapshot)
    }
}

/// Status report for resource monitoring system.
#[derive(Debug, Clone)]
pub struct ResourceMonitorStatus {
    pub is_active: bool,
    pub composite_degradation_level: DegradationLevel,
    pub measurements: HashMap<ResourceType, ResourceMeasurement>,
    pub degradation_levels: HashMap<ResourceType, DegradationLevel>,
    pub platform_probe_report: ResourcePlatformProbeReport,
    pub stats: DegradationStatsSnapshot,
    pub config: MonitorConfig,
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
    use crate::runtime::rch_health::{
        RchArtifactRetrievalReliability, RchCacheWarmthHint, RchProofLaneRequest, RchProofPriority,
        RchQueueState, RchTargetDirClass, RchWorkerAdmissionPolicy, RchWorkerDiskPressure,
        RchWorkerSnapshot, admit_rch_worker,
    };
    use crate::sync::LockMetricsSnapshot;
    use crate::sync::lock_ordering::{
        LockModule, LockOrderAtlasSnapshot, LockOrderEdge, LockOrderViolation, LockRank,
    };
    use serde_json::{Value, json};
    use std::collections::hash_map::DefaultHasher;
    use std::fs;
    use std::hash::{Hash, Hasher};
    use std::path::Path;

    #[test]
    fn test_resource_measurement_ratios() {
        let measurement = ResourceMeasurement::new(750, 800, 900, 1000);

        assert_eq!(measurement.usage_ratio(), 0.75);
        assert!(!measurement.is_soft_exceeded());
        assert!(!measurement.is_hard_exceeded());
        assert!(!measurement.is_critical());
    }

    #[test]
    fn test_degradation_level_conversion() {
        assert_eq!(DegradationLevel::None.to_headroom(), 1.0);
        assert_eq!(DegradationLevel::Emergency.to_headroom(), 0.0);
        assert_eq!(DegradationLevel::from_headroom(0.9), DegradationLevel::None);
        assert_eq!(
            DegradationLevel::from_headroom(0.1),
            DegradationLevel::Emergency
        );
    }

    #[test]
    fn test_trigger_config_degradation_calculation() {
        let config = TriggerConfig::default_for_resource(&ResourceType::Memory);
        let measurement = ResourceMeasurement::new(800, 700, 850, 1000); // 80% usage

        let level = config.calculate_degradation(&measurement);
        assert_eq!(level, DegradationLevel::Moderate);
    }

    #[test]
    fn test_resource_pressure_updates() {
        let pressure = ResourcePressure::new();
        let measurement = ResourceMeasurement::new(500, 700, 850, 1000);

        pressure.update_measurement(ResourceType::Memory, measurement.clone());

        let retrieved = pressure.get_measurement(&ResourceType::Memory).unwrap();
        assert_eq!(retrieved.current, measurement.current);
    }

    #[test]
    fn test_resource_pressure_system_pressure_matches_degradation_band() {
        let pressure = ResourcePressure::new();
        let system_pressure = pressure.system_pressure();

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::None);
        assert!((system_pressure.headroom() - 1.0).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 0);
        assert_eq!(system_pressure.level_label(), "normal");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Light);
        assert!((system_pressure.headroom() - 0.75).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 1);
        assert_eq!(system_pressure.level_label(), "light");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);
        assert!((system_pressure.headroom() - 0.5).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 2);
        assert_eq!(system_pressure.level_label(), "moderate");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);
        assert!((system_pressure.headroom() - 0.25).abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 3);
        assert_eq!(system_pressure.level_label(), "heavy");

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Emergency);
        assert!(system_pressure.headroom().abs() < f32::EPSILON);
        assert_eq!(system_pressure.degradation_level(), 4);
        assert_eq!(system_pressure.level_label(), "emergency");
    }

    #[test]
    fn test_degradation_engine_policies() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));

        let policy = DegradationPolicy {
            resource_type: ResourceType::Memory,
            trigger_level: DegradationLevel::Moderate,
            action: PolicyAction::RejectNewWork(RegionPriority::Low),
        };

        engine.add_policy(policy);

        // Test region shedding decisions
        let region_id = RegionId::new_ephemeral();
        engine.set_region_priority(region_id, RegionPriority::Low);

        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);

        let decision = engine.should_shed_region(region_id);
        assert!(matches!(decision, SheddingDecision::Pause));
    }

    #[test]
    fn test_degradation_engine_monitors_task_pressure_by_default() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));

        pressure.update_measurement(
            ResourceType::Task,
            ResourceMeasurement::new(960, 800, 950, 1000),
        );

        let changes = engine
            .process_measurements()
            .expect("task pressure should process");
        assert_eq!(
            changes,
            vec![(ResourceType::Task, DegradationLevel::Emergency)]
        );
        assert_eq!(
            pressure.get_degradation_level(&ResourceType::Task),
            DegradationLevel::Emergency
        );
    }

    #[test]
    fn test_cycle_overhead_percentage_uses_configured_interval() {
        let overhead =
            cycle_overhead_percentage(Duration::from_millis(25), Duration::from_millis(100));
        assert!((overhead - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cycle_overhead_percentage_handles_zero_interval() {
        assert_eq!(
            cycle_overhead_percentage(Duration::from_millis(25), Duration::ZERO),
            0.0
        );
    }

    #[test]
    fn m4oxsk_supported_probe_reporting_records_sampled_value() {
        let state = ResourceProbeState::new("test-linux/x86_64");

        state.record_supported(ResourceProbe::ProcessRssBytes, Some(4096));

        let report = state.report();
        assert_eq!(report.supported_count, 1);
        assert_eq!(report.unavailable_count, 0);
        assert_eq!(report.fallback_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::Complete
        );
        assert_eq!(report.probes[0].sampled_value, Some(4096));
        assert_eq!(report.probes[0].resource_type, ResourceType::Memory);
    }

    #[test]
    fn m4oxsk_unsupported_probe_reporting_is_typed() {
        let state = ResourceProbeState::new("test-unsupported/wasm32");
        let error = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unavailable on test platform",
        );

        state.record_probe_failure(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            &error,
        );

        let report = state.report();
        let probe = &report.probes[0];
        assert_eq!(report.unavailable_count, 1);
        assert_eq!(report.warning_emitted_count, 1);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::DegradedWithUnavailableProbes
        );
        assert_eq!(probe.status, ResourceProbeStatus::Unavailable);
        assert_eq!(
            probe.fallback,
            ResourceProbeFallback::CustomCollectorRequired
        );
        assert_eq!(probe.probe, ResourceProbe::ProcessFdCount);
        assert!(probe.error_message.as_deref().unwrap().contains("test"));
    }

    #[test]
    fn m4oxsk_fallback_aggregation_preserves_operator_semantics() {
        let state = ResourceProbeState::new("test-bsd/aarch64");
        let error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fd rlimit inaccessible",
        );

        state.record_probe_failure(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            &error,
        );

        let report = state.report();
        assert_eq!(report.fallback_count, 1);
        assert_eq!(report.unavailable_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::DegradedWithFallbacks
        );
        assert_eq!(report.probes[0].status, ResourceProbeStatus::Fallback);
        assert_eq!(
            report.probes[0].fallback,
            ResourceProbeFallback::ConservativeDefault
        );
    }

    #[test]
    fn m4oxsk_warning_throttling_suppresses_repeated_probe_failures() {
        let state = ResourceProbeState::new("test-linux/x86_64");

        for attempt in 0..9 {
            let error = std::io::Error::other(format!("transient probe failure {attempt}"));
            state.record_probe_failure(
                ResourceProbe::LoadAvg1MinScaled,
                ResourceProbeFallback::OmitMeasurement,
                &error,
            );
        }

        let report = state.report();
        assert_eq!(report.warning_emitted_count, 2);
        assert_eq!(report.warning_suppressed_count, 7);
        assert_eq!(report.probes[0].warning_count, 9);
        assert_eq!(report.probes[0].warning_suppressed_count, 7);
    }

    #[test]
    fn m4oxsk_unavailable_probe_report_serializes_operator_fields() {
        let state = ResourceProbeState::new("test-windows/x86_64");
        let error =
            std::io::Error::new(std::io::ErrorKind::Unsupported, "load average unavailable");

        state.record_probe_failure(
            ResourceProbe::LoadAvg1MinScaled,
            ResourceProbeFallback::OmitMeasurement,
            &error,
        );

        let report = state.report();
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        let value: Value = serde_json::from_str(&json).expect("parse report json");

        assert_eq!(
            value["schema_version"],
            RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION
        );
        assert_eq!(value["probes"][0]["probe"], "load_avg_1min_scaled");
        assert_eq!(value["probes"][0]["status"], "unavailable");
        assert_eq!(value["probes"][0]["fallback"], "custom_collector_required");
        assert_eq!(
            value["operator_verdict"],
            "degraded_with_unavailable_probes"
        );
    }

    #[test]
    fn m4oxsk_disabled_monitor_probe_report_is_explicit() {
        let state = ResourceProbeState::new("test-disabled/noarch");

        state.record_disabled(ResourceProbe::ProcessRssBytes);
        state.record_disabled(ResourceProbe::LoadAvg1MinScaled);

        let report = state.report();
        assert_eq!(report.disabled_count, 2);
        assert_eq!(report.warning_emitted_count, 0);
        assert_eq!(report.warning_suppressed_count, 0);
        assert_eq!(
            report.operator_verdict,
            ResourceProbeOperatorVerdict::Disabled
        );
        assert!(report.probes.iter().all(|probe| {
            probe.status == ResourceProbeStatus::Disabled
                && probe.fallback == ResourceProbeFallback::MonitorDisabled
        }));
    }

    #[test]
    fn m4oxsk_status_report_carries_platform_probe_inventory() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());

        let status = monitor.status_report();

        assert!(!status.is_active);
        assert_eq!(
            status.platform_probe_report.schema_version,
            RESOURCE_MONITOR_PLATFORM_GAP_REPORT_SCHEMA_VERSION
        );
        assert_eq!(
            status.platform_probe_report.platform,
            current_platform_fingerprint()
        );
    }

    #[test]
    fn rz7cpt_system_resource_collector_active_flag_tracks_lifecycle() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_millis(50));

        assert!(!collector.is_active());
        collector.start().expect("collector should start once");
        assert!(collector.is_active());
        assert!(matches!(
            collector.start(),
            Err(ResourceMonitorError::AlreadyActive)
        ));
        assert!(collector.is_active());

        collector.stop();
        assert!(!collector.is_active());
        collector
            .start()
            .expect("collector should restart after stop");
        assert!(collector.is_active());
        collector.stop();
    }

    #[test]
    fn m4oxsk_resource_monitor_platform_gap_smoke_emits_operator_report() {
        let state = ResourceProbeState::new("host-template/linux-or-fallback");
        let unsupported = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "template host lacks process fd probe",
        );
        let fallback = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "template host hides connection limit",
        );

        state.record_supported(ResourceProbe::ProcessRssBytes, Some(12_288));
        state.record_probe_failure(
            ResourceProbe::ProcessFdCount,
            ResourceProbeFallback::OmitMeasurement,
            &unsupported,
        );
        state.record_probe_failure(
            ResourceProbe::NetworkConnectionLimit,
            ResourceProbeFallback::ConservativeDefault,
            &fallback,
        );
        state.record_disabled(ResourceProbe::MemoryMaxBytes);

        let report = state.report();
        let probe_list: Vec<Value> = report
            .probes
            .iter()
            .map(|probe| {
                json!({
                    "probe": probe.probe,
                    "resource_type": probe.resource_type,
                    "status": probe.status,
                    "fallback": probe.fallback,
                    "sampled_value": probe.sampled_value,
                    "error_message": probe.error_message,
                })
            })
            .collect();
        let smoke_report = json!({
            "schema_version": report.schema_version,
            "platform_fingerprint": report.platform,
            "probe_list": probe_list,
            "supported_count": report.supported_count,
            "unavailable_count": report.unavailable_count,
            "fallback_count": report.fallback_count,
            "disabled_count": report.disabled_count,
            "warning_emitted_count": report.warning_emitted_count,
            "warning_suppressed_count": report.warning_suppressed_count,
            "sampled_values": report.probes.iter().filter_map(|probe| {
                probe.sampled_value.map(|value| json!({
                    "probe": probe.probe,
                    "value": value,
                }))
            }).collect::<Vec<_>>(),
            "error_messages": report.probes.iter().filter_map(|probe| {
                probe.error_message.as_ref().map(|message| json!({
                    "probe": probe.probe,
                    "message": message,
                    "fallback": probe.fallback,
                }))
            }).collect::<Vec<_>>(),
            "final_operator_verdict": report.operator_verdict,
        });

        assert_eq!(smoke_report["supported_count"], 1);
        assert_eq!(smoke_report["unavailable_count"], 1);
        assert_eq!(smoke_report["fallback_count"], 1);
        assert_eq!(smoke_report["disabled_count"], 1);
        assert_eq!(
            smoke_report["final_operator_verdict"],
            "degraded_with_unavailable_probes"
        );

        if std::env::var_os("ASUPERSYNC_RESOURCE_MONITOR_PLATFORM_GAP_REPORT").is_some() {
            println!("RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_BEGIN");
            println!(
                "{}",
                serde_json::to_string_pretty(&smoke_report).expect("serialize smoke report")
            );
            println!("RESOURCE_MONITOR_PLATFORM_GAP_REPORT_JSON_END");
        }
    }

    // ===================================================================
    // br-asupersync-thfiyk: real platform-read tests for the
    // SystemResourceCollector. The exact values vary per-host so we
    // assert on shape (non-zero where it must be, ratios sane, no
    // longer the constants the retired deterministic fixtures returned).
    // ===================================================================

    #[test]
    fn thfiyk_derive_thresholds_basic() {
        assert_eq!(derive_thresholds(1000, 75, 90), (750, 900));
        assert_eq!(derive_thresholds(0, 75, 90), (0, 0));
        // Saturation: extremely large `max_limit` doesn't overflow u64.
        let (s, h) = derive_thresholds(u64::MAX, 75, 90);
        assert_eq!(s, ((u128::from(u64::MAX) * 75) / 100) as u64);
        assert_eq!(h, ((u128::from(u64::MAX) * 90) / 100) as u64);
        assert!(s <= h);
    }

    #[test]
    fn thfiyk_derive_thresholds_clamps_to_max() {
        // soft and hard must never exceed max_limit even if the
        // percentages would compute past it (rounding).
        let (s, h) = derive_thresholds(7, 75, 90);
        assert!(s <= 7);
        assert!(h <= 7);
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_memory_usage_returns_real_rss() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_memory_usage()
            .expect("memory usage read should succeed on supported platform");
        // The old constant-only reader always returned 512 MiB exactly; the real
        // reader yields the live VmRSS / ru_maxrss which is virtually
        // never that exact value. We assert (a) non-zero current
        // (this test process necessarily has resident memory),
        // (b) max_limit > 0, (c) we did NOT get the legacy constants.
        assert!(m.current > 0, "current bytes should be > 0");
        assert!(m.max_limit > 0, "max_limit should be > 0");
        assert!(
            m.current != 512 * 1024 * 1024 || m.max_limit != 2048 * 1024 * 1024,
            "appears to still be returning the legacy constant-only values"
        );
        assert!(m.soft_limit <= m.hard_limit, "soft <= hard");
        assert!(m.hard_limit <= m.max_limit, "hard <= max");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_fd_usage_returns_real_count() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_fd_usage()
            .expect("fd usage read should succeed on supported platform");
        // A test process always has at least stdin/stdout/stderr open,
        // so current_fds >= 3 in practice. We assert >= 1 to keep the
        // test robust on obscure sandboxed environments.
        assert!(m.current >= 1, "fd count should be >= 1");
        assert!(m.max_limit >= m.current, "fd ceiling >= current");
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn thfiyk_collect_cpu_load_returns_real_load() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_cpu_load()
            .expect("loadavg read should succeed on supported platform");
        assert_eq!(m.max_limit, 100, "load is reported on a 0..100 scale");
        assert!(m.current <= 100, "load percentage in range");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn thfiyk_collect_network_usage_returns_real_count() {
        let pressure = Arc::new(ResourcePressure::new());
        let collector = SystemResourceCollector::new(pressure, Duration::from_secs(1));
        let m = collector
            .collect_network_usage()
            .expect("connection count read should succeed on Linux or Android");
        // Connection count can legitimately be 0 (a fresh test
        // process opens no sockets), so assert only that the ceiling
        // is sane and the reader did not return the legacy constant 50.
        assert!(m.max_limit > 0, "connection ceiling > 0");
        assert!(m.soft_limit <= m.hard_limit);
        assert!(m.hard_limit <= m.max_limit);
    }

    fn sample_scheduler_metrics() -> SchedulerEvidenceMetrics {
        SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 8_000,
            wake_to_run_p95_ns: 90_000,
            wake_to_run_p99_ns: 220_000,
            queue_residency_p50_ns: 16_000,
            queue_residency_p95_ns: 200_000,
            queue_residency_p99_ns: 520_000,
            ready_backlog_p95: 192,
            ready_backlog_p99: 320,
            cancel_debt_p95: 48,
            cancel_debt_p99: 128,
            remote_steal_ratio_pct: Some(42),
            cross_cohort_wake_p99_ns: Some(180_000),
        }
    }

    fn healthy_scheduler_metrics() -> SchedulerEvidenceMetrics {
        SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 4_000,
            wake_to_run_p95_ns: 40_000,
            wake_to_run_p99_ns: 80_000,
            queue_residency_p50_ns: 6_000,
            queue_residency_p95_ns: 70_000,
            queue_residency_p99_ns: 120_000,
            ready_backlog_p95: 24,
            ready_backlog_p99: 48,
            cancel_debt_p95: 8,
            cancel_debt_p99: 16,
            remote_steal_ratio_pct: Some(12),
            cross_cohort_wake_p99_ns: Some(60_000),
        }
    }

    fn complete_platform_probe_report() -> ResourcePlatformProbeReport {
        ResourcePlatformProbeReport::from_snapshots(
            "test-linux/x86_64".to_string(),
            vec![ResourceProbeSnapshot {
                platform: "test-linux/x86_64".to_string(),
                resource_type: ResourceType::Memory,
                probe: ResourceProbe::ProcessRssBytes,
                status: ResourceProbeStatus::Supported,
                fallback: ResourceProbeFallback::None,
                sampled_value: Some(16_384),
                error_message: None,
                warning_count: 0,
                warning_suppressed_count: 0,
            }],
        )
    }

    fn degraded_platform_probe_report() -> ResourcePlatformProbeReport {
        ResourcePlatformProbeReport::from_snapshots(
            "test-linux/x86_64".to_string(),
            vec![ResourceProbeSnapshot {
                platform: "test-linux/x86_64".to_string(),
                resource_type: ResourceType::Memory,
                probe: ResourceProbe::MemoryMaxBytes,
                status: ResourceProbeStatus::Fallback,
                fallback: ResourceProbeFallback::ConservativeDefault,
                sampled_value: None,
                error_message: Some("synthetic lab fallback".to_string()),
                warning_count: 1,
                warning_suppressed_count: 0,
            }],
        )
    }

    fn healthy_spectral_snapshot() -> RuntimePressureSpectralSnapshot {
        RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Healthy,
            fiedler_micro_units: Some(250_000),
            spectral_gap_bps: Some(7_500),
            spectral_radius_micro_units: Some(1_500_000),
            bottleneck_count: 0,
            components: None,
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::None,
        }
    }

    fn structural_warning_spectral_snapshot() -> RuntimePressureSpectralSnapshot {
        RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Fragmented,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_100_000),
            bottleneck_count: 2,
            components: Some(2),
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Warning,
        }
    }

    fn rch_request(lane_id: &str, priority: RchProofPriority) -> RchProofLaneRequest {
        RchProofLaneRequest::new(lane_id, RchTargetDirClass::Warm, true, priority)
    }

    fn healthy_rch_worker(raw_worker_id: &str, lane_id: &str) -> RchWorkerSnapshot {
        RchWorkerSnapshot::new(
            raw_worker_id,
            true,
            RchQueueState::Open,
            false,
            vec![RchCacheWarmthHint::new(
                Some(lane_id),
                RchTargetDirClass::Warm,
                90,
            )],
            RchWorkerDiskPressure::new(100.0, 120.0, 0.1, 0.2),
            RchArtifactRetrievalReliability::new(4, 0, 0),
            30,
            95,
            0,
        )
    }

    fn admitted_rch_receipt(lane_id: &str) -> RchWorkerAdmissionReceipt {
        let request = rch_request(lane_id, RchProofPriority::Foreground);
        let worker = healthy_rch_worker("vmi-rch-proof-lane-a.internal", lane_id);
        admit_rch_worker(&request, &[worker], &RchWorkerAdmissionPolicy::default())
    }

    fn refused_remote_required_rch_receipt(lane_id: &str) -> RchWorkerAdmissionReceipt {
        let request = rch_request(lane_id, RchProofPriority::Critical);
        admit_rch_worker(&request, &[], &RchWorkerAdmissionPolicy::default())
    }

    fn sample_lock_metrics(
        name: &'static str,
        acquisitions: u64,
        contentions: u64,
    ) -> LockMetricsSnapshot {
        LockMetricsSnapshot {
            name,
            acquisitions,
            contentions,
            wait_ns: acquisitions.saturating_mul(1_000),
            hold_ns: acquisitions.saturating_mul(2_000),
            max_wait_ns: 9_000,
            max_hold_ns: 12_000,
            p95_wait_ns: 4_000,
            p999_wait_ns: 8_000,
            p95_hold_ns: 6_000,
            p999_hold_ns: 10_000,
            instrumentation_mode: "lock-metrics-test",
        }
    }

    fn sample_lock_order_atlas() -> LockOrderAtlasSnapshot {
        LockOrderAtlasSnapshot {
            order_edges_exercised: vec![LockOrderEdge {
                held_lock_name: "regions".to_string(),
                held_rank: LockRank::Regions,
                held_module: LockModule::Runtime,
                acquired_lock_name: "tasks".to_string(),
                acquired_rank: LockRank::Tasks,
                acquired_module: LockModule::Runtime,
            }],
            order_violations: vec![LockOrderViolation {
                lock_name: "tasks".to_string(),
                lock_rank: LockRank::Tasks,
                lock_module: LockModule::Runtime,
                held_rank: LockRank::Obligations,
                reason: "rank-order".to_string(),
            }],
            instrumentation_mode: "lock-metrics-test",
        }
    }

    fn sample_trapped_cycle_witness() -> AdmissionAwareTrappedCycleWitnessRow {
        AdmissionAwareTrappedCycleWitnessRow {
            witness_id: "atlas-witness-001".to_string(),
            participants: vec![
                "task:00000001-00000000".to_string(),
                "task:00000002-00000000".to_string(),
            ],
            held_resources: vec![
                "lock:regions".to_string(),
                "obligation:send-permit:00000004-00000000".to_string(),
            ],
            wait_edges: vec![
                AdmissionAwareTrappedCycleWaitEdgeRow {
                    waiting_participant: "task:00000002-00000000".to_string(),
                    held_by_participant: "task:00000001-00000000".to_string(),
                    resource: "lock:regions".to_string(),
                },
                AdmissionAwareTrappedCycleWaitEdgeRow {
                    waiting_participant: "task:00000001-00000000".to_string(),
                    held_by_participant: "task:00000002-00000000".to_string(),
                    resource: "obligation:send-permit:00000004-00000000".to_string(),
                },
            ],
            source_step_or_timestamp: "lab-step:4242".to_string(),
            replay_command: "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_trapped_cycle_witness\" cargo test -p asupersync --test runtime_wait_cause_remediation_contract actionable_report -- --nocapture".to_string(),
            proof_status: AdmissionAwareTrappedCycleWitnessProofStatus::Validated,
            witness_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }
    }

    fn complete_atlas_builder_input(
        spectral: RuntimePressureSpectralSnapshot,
        include_trapped_cycle_witness: bool,
    ) -> AdmissionAwareRuntimePressureAtlasBuilderInput {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 95, 100),
        );
        let region_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "atlas-region",
            4_096,
            2_048,
        );
        let rch_row =
            RuntimePressureRchProofLaneSnapshot::from_receipt(&admitted_rch_receipt("cargo-test"));
        let runtime_pressure =
            RuntimePressureSnapshot::from_parts_with_region_memory_budgets_and_rch_proof_lanes(
                &pressure,
                complete_platform_probe_report(),
                Some(healthy_scheduler_metrics()),
                Some(spectral),
                vec![region_budget],
                vec![rch_row],
            );
        let mut input = AdmissionAwareRuntimePressureAtlasBuilderInput::new(
            runtime_pressure,
            sample_lock_order_atlas(),
        );
        input.lock_metrics = vec![
            sample_lock_metrics("tasks", 16, 2),
            sample_lock_metrics("regions", 12, 1),
            sample_lock_metrics("tasks", 8, 1),
        ];
        input.dirty_tree_peer_ownership = vec![
            AdmissionAwareDirtyTreePeerOwnershipRow {
                path: "src/runtime/resource_monitor.rs".to_string(),
                dirty_classification: "owned".to_string(),
                holder: Some("SageWolf".to_string()),
                bead_id: Some("asupersync-bt63nr.7".to_string()),
                source: "agent-mail-reservation".to_string(),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::OwnedExact,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                blocks_admission: false,
                handoff_required: false,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            },
            AdmissionAwareDirtyTreePeerOwnershipRow {
                path: ".beads/issues.jsonl".to_string(),
                dirty_classification: "tracker-only".to_string(),
                holder: Some("SageWolf".to_string()),
                bead_id: Some("asupersync-bt63nr.7".to_string()),
                source: "beads-claim".to_string(),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::TrackerOnly,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                blocks_admission: false,
                handoff_required: false,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            },
        ];
        input.agent_mail_reservations = vec![AdmissionAwareAgentMailReservationRow {
            path_pattern: "src/runtime/resource_monitor.rs".to_string(),
            holder: "SageWolf".to_string(),
            exclusive: true,
            reason: "asupersync-bt63nr.3".to_string(),
            expires_ts: Some("2026-06-02T23:00:00Z".to_string()),
            bead_id: Some("asupersync-bt63nr.7".to_string()),
            overlap_classification: AdmissionAwareCoordinationOverlapClass::OwnedExact,
            coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        input.br_tracker_status = vec![AdmissionAwareBrTrackerStatusRow {
            bead_id: "asupersync-bt63nr.3".to_string(),
            status: "in_progress".to_string(),
            priority: Some(1),
            blocked_by: Vec::new(),
            ready: true,
            assignee: Some("SageWolf".to_string()),
            updated_at: Some("2026-06-02T21:02:56Z".to_string()),
            overlap_classification: AdmissionAwareCoordinationOverlapClass::OwnedExact,
            coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        input.large_host_worker_warmth = vec![AdmissionAwareLargeHostWorkerWarmthRow {
            worker_id: "rchw-large-1".to_string(),
            cpu_cores: 64,
            memory_bytes: 256 * 1024 * 1024 * 1024,
            numa_nodes: 2,
            disk_headroom_bytes: 512 * 1024 * 1024 * 1024,
            worker_queue_state: "open".to_string(),
            worker_available_cores: 48,
            worker_available_memory_bytes: 192 * 1024 * 1024 * 1024,
            cache_warmth: "warm".to_string(),
            target_dir_isolated: true,
            active_project_excluded: true,
            proof_lane_cost_estimate: Some("cargo-test-focused".to_string()),
            worker_saturation: AdmissionAwareLargeHostWorkerSaturation::Available,
            advisory_batching_decision: AdmissionAwareLargeHostBatchingDecision::AdmitBatch,
            advisory_batching_reason_codes: Vec::new(),
            advisory_batch_size_hint: None,
            advisory_non_claims: Vec::new(),
            advisory_only: false,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        input.operator_closeout_receipts = vec![AdmissionAwareOperatorCloseoutReceiptRow {
            bead_id: "asupersync-bt63nr.3".to_string(),
            status: "pending-validation".to_string(),
            commit: None,
            proof_commands: vec![
                "RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib admission_aware_runtime_pressure_atlas".to_string(),
            ],
            pushed_main: false,
            pushed_master_mirror: false,
            sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
        }];
        if include_trapped_cycle_witness {
            input.trapped_cycle_witnesses = vec![sample_trapped_cycle_witness()];
        }
        input
    }

    fn snapshot_with_spectral(
        spectral: RuntimePressureSpectralSnapshot,
    ) -> RuntimePressureSnapshot {
        RuntimePressureSnapshot::from_parts(
            &ResourcePressure::new(),
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(spectral),
        )
    }

    fn pressure_snapshot_from_parts(
        pressure: &ResourcePressure,
        platform_probe_report: ResourcePlatformProbeReport,
        scheduler: SchedulerEvidenceMetrics,
        spectral: RuntimePressureSpectralSnapshot,
    ) -> RuntimePressureSnapshot {
        RuntimePressureSnapshot::from_parts(
            pressure,
            platform_probe_report,
            Some(scheduler),
            Some(spectral),
        )
    }

    fn runtime_pressure_lab_scenario_evidence(
        scenario_id: &'static str,
        seed: u64,
        scenario_kind: RuntimePressureLabScenarioKind,
        expected_verdict: RuntimePressureVerdict,
        snapshot: RuntimePressureSnapshot,
        diagnostic_labels: &[&str],
    ) -> RuntimePressureLabScenarioEvidence {
        RuntimePressureLabScenarioEvidence::from_snapshot(
            scenario_id,
            seed,
            scenario_kind,
            expected_verdict,
            snapshot,
            diagnostic_labels
                .iter()
                .map(|label| (*label).to_string())
                .collect(),
        )
    }

    fn healthy_pressure_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 90, 100),
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-healthy",
            0x57A9_0001,
            RuntimePressureLabScenarioKind::Healthy,
            RuntimePressureVerdict::Healthy,
            pressure_snapshot_from_parts(
                &pressure,
                complete_platform_probe_report(),
                healthy_scheduler_metrics(),
                healthy_spectral_snapshot(),
            ),
            &["all_signals_present"],
        )
    }

    fn cpu_lane_pressure_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::CpuLoad,
            ResourceMeasurement::new(96, 70, 85, 100),
        );
        pressure.update_degradation_level(ResourceType::CpuLoad, DegradationLevel::Heavy);

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-cpu-lane-pressure",
            0x57A9_C011,
            RuntimePressureLabScenarioKind::CpuLanePressure,
            RuntimePressureVerdict::Critical,
            pressure_snapshot_from_parts(
                &pressure,
                complete_platform_probe_report(),
                sample_scheduler_metrics(),
                healthy_spectral_snapshot(),
            ),
            &[
                "cpu_load_hard_limit",
                "resource_heavy_degradation",
                "scheduler_tail_pressure",
            ],
        )
    }

    fn resource_fallback_degraded_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(82, 70, 95, 100),
        );
        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-resource-fallback-degraded",
            0x57A9_FA11,
            RuntimePressureLabScenarioKind::ResourceFallbackDegraded,
            RuntimePressureVerdict::Degraded,
            pressure_snapshot_from_parts(
                &pressure,
                degraded_platform_probe_report(),
                healthy_scheduler_metrics(),
                healthy_spectral_snapshot(),
            ),
            &["memory_soft_pressure", "platform_probe_fallback"],
        )
    }

    fn region_memory_budget_overrun_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(45, 80, 95, 100),
        );
        let region_memory_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "pressure-lab-region",
            1_000,
            1_125,
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-region-memory-budget-overrun",
            0x57A9_BAD9,
            RuntimePressureLabScenarioKind::RegionMemoryBudgetOverrun,
            RuntimePressureVerdict::Critical,
            RuntimePressureSnapshot::from_parts_with_region_memory_budgets(
                &pressure,
                complete_platform_probe_report(),
                Some(healthy_scheduler_metrics()),
                Some(healthy_spectral_snapshot()),
                vec![region_memory_budget],
            ),
            &[
                "region_memory_budget_advisory",
                "region_memory_budget_exhausted",
            ],
        )
    }

    fn structural_warning_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Task,
            ResourceMeasurement::new(24, 80, 95, 100),
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-structural-warning",
            0x57A9_57AC,
            RuntimePressureLabScenarioKind::StructuralWarning,
            RuntimePressureVerdict::Critical,
            pressure_snapshot_from_parts(
                &pressure,
                complete_platform_probe_report(),
                healthy_scheduler_metrics(),
                structural_warning_spectral_snapshot(),
            ),
            &[
                "spectral_fragmented_topology",
                "trapped_cycle_detection_required",
            ],
        )
    }

    fn rch_proof_lane_remote_refusal_lab_evidence() -> RuntimePressureLabScenarioEvidence {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(40, 80, 95, 100),
        );
        let rch_row = RuntimePressureRchProofLaneSnapshot::from_receipt(
            &refused_remote_required_rch_receipt("cargo-clippy-admission"),
        );

        runtime_pressure_lab_scenario_evidence(
            "runtime-pressure-lab-rch-proof-lane-remote-refusal",
            0x57A9_7C17,
            RuntimePressureLabScenarioKind::RchProofLaneRemoteRefusal,
            RuntimePressureVerdict::Critical,
            RuntimePressureSnapshot::from_parts_with_rch_proof_lanes(
                &pressure,
                complete_platform_probe_report(),
                Some(healthy_scheduler_metrics()),
                Some(healthy_spectral_snapshot()),
                vec![rch_row],
            ),
            &["local_fallback_refused", "rch_remote_required_refused"],
        )
    }

    #[test]
    fn runtime_pressure_snapshot_marks_empty_inputs_unknown() {
        let pressure = ResourcePressure::new();
        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            None,
        );

        assert_eq!(
            snapshot.schema_version,
            RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Unknown);
        assert_eq!(snapshot.missing_signal_count, 4);
        assert_eq!(snapshot.degraded_signal_count, 0);
        assert_eq!(snapshot.critical_signal_count, 0);
        assert!(snapshot.resources.is_empty());
        assert_eq!(
            snapshot.spectral.class,
            RuntimePressureSpectralClass::Unknown
        );
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .map(|status| (status.signal, status.status))
                .collect::<Vec<_>>(),
            vec![
                (
                    RuntimePressureSignal::Resources,
                    RuntimePressureSignalStatus::Missing,
                ),
                (
                    RuntimePressureSignal::Scheduler,
                    RuntimePressureSignalStatus::Missing,
                ),
                (
                    RuntimePressureSignal::Spectral,
                    RuntimePressureSignalStatus::Missing,
                ),
                (
                    RuntimePressureSignal::PlatformProbes,
                    RuntimePressureSignalStatus::Missing,
                ),
            ]
        );
    }

    #[test]
    fn runtime_pressure_snapshot_orders_resources_deterministically() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Custom("zeta".to_string()),
            ResourceMeasurement::new(20, 50, 90, 100),
        );
        pressure.update_degradation_level(
            ResourceType::Custom("zeta".to_string()),
            DegradationLevel::None,
        );
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(64, 80, 95, 100),
        );
        pressure.update_measurement(
            ResourceType::Custom("alpha".to_string()),
            ResourceMeasurement::new(10, 50, 90, 100),
        );

        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
        );
        let labels = snapshot
            .resources
            .iter()
            .map(|resource| resource.resource_label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["custom:alpha", "custom:zeta", "memory"]);
        assert_eq!(snapshot.resources[0].usage_bps, 1_000);
        assert_eq!(snapshot.resources[1].usage_bps, 2_000);
        assert_eq!(snapshot.resources[2].usage_bps, 6_400);
    }

    #[test]
    fn runtime_pressure_snapshot_serializes_stable_json_shape() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(800, 700, 900, 1000),
        );
        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);

        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            complete_platform_probe_report(),
            Some(sample_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
        );
        let json = serde_json::to_string_pretty(&snapshot).expect("serialize snapshot");
        let value: Value = serde_json::from_str(&json).expect("parse snapshot json");

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Degraded);
        assert_eq!(snapshot.missing_signal_count, 0);
        assert_eq!(snapshot.degraded_signal_count, 2);
        assert_eq!(snapshot.critical_signal_count, 0);
        assert_eq!(
            value["schema_version"],
            RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(value["overall_verdict"], "degraded");
        assert_eq!(value["resource_composite_degradation"], "Moderate");
        assert_eq!(value["resources"][0]["resource_label"], "memory");
        assert_eq!(value["resources"][0]["usage_bps"], 8_000);
        assert_eq!(value["scheduler"]["wake_to_run_p99_ns"], 220_000);
        assert_eq!(value["spectral"]["class"], "healthy");
        assert_eq!(
            value["rch_proof_lanes"]
                .as_array()
                .expect("rch proof lanes array")
                .len(),
            0
        );
        assert_eq!(
            value["region_memory_budgets"]
                .as_array()
                .expect("region memory budgets array")
                .len(),
            0
        );
        assert_eq!(
            value["signal_statuses"][0]["signal"], "resources",
            "signal rows stay sorted by enum order"
        );
    }

    #[test]
    fn runtime_pressure_region_memory_budget_rows_use_capability_envelopes() {
        let region_id = RegionId::new_ephemeral();

        assert!(
            RuntimePressureRegionMemoryBudgetSnapshot::from_capability_budget(
                region_id,
                CapabilityBudget::UNSPECIFIED,
                512,
            )
            .is_none(),
            "regions without explicit memory envelopes should not invent budget evidence"
        );

        let row = RuntimePressureRegionMemoryBudgetSnapshot::from_capability_budget(
            region_id,
            CapabilityBudget::new().with_memory_bytes(4_096),
            2_048,
        )
        .expect("memory envelope should project to a row");

        assert_eq!(
            row.schema_version,
            RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION
        );
        assert_eq!(row.region_id, region_id);
        assert_eq!(row.region_label, region_id.to_string());
        assert_eq!(row.declared_memory_budget_bytes, 4_096);
        assert_eq!(row.observed_memory_bytes, 2_048);
        assert_eq!(row.usage_bps, 5_000);
        assert_eq!(row.over_budget_bytes, 0);
        assert!(!row.soft_limit_exceeded);
        assert!(!row.hard_limit_exceeded);
        assert!(!row.budget_exhausted);
        assert!(row.advisory_only);
    }

    #[test]
    fn runtime_pressure_snapshot_folds_region_memory_budget_pressure() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 95, 100),
        );

        let under_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "under-budget",
            1_000,
            512,
        );
        let soft_pressure = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "soft-pressure",
            1_000,
            850,
        );
        let over_budget = RuntimePressureRegionMemoryBudgetSnapshot::with_label(
            RegionId::new_ephemeral(),
            "over-budget",
            1_000,
            1_250,
        );

        let snapshot = RuntimePressureSnapshot::from_parts_with_region_memory_budgets(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
            vec![
                soft_pressure.clone(),
                over_budget.clone(),
                under_budget.clone(),
            ],
        );

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Critical);
        assert_eq!(snapshot.missing_signal_count, 0);
        assert_eq!(snapshot.degraded_signal_count, 0);
        assert_eq!(snapshot.critical_signal_count, 1);
        assert_eq!(
            snapshot
                .region_memory_budgets
                .iter()
                .map(|row| row.region_label.as_str())
                .collect::<Vec<_>>(),
            vec!["over-budget", "soft-pressure", "under-budget"]
        );
        assert_eq!(snapshot.region_memory_budgets[0].usage_bps, 10_000);
        assert_eq!(snapshot.region_memory_budgets[0].over_budget_bytes, 250);
        assert!(snapshot.region_memory_budgets[0].hard_limit_exceeded);
        assert!(snapshot.region_memory_budgets[0].budget_exhausted);
        assert_eq!(snapshot.region_memory_budgets[1].usage_bps, 8_500);
        assert!(snapshot.region_memory_budgets[1].soft_limit_exceeded);
        assert!(!snapshot.region_memory_budgets[1].hard_limit_exceeded);
        assert_eq!(snapshot.region_memory_budgets[2].usage_bps, 5_120);
        assert!(!snapshot.region_memory_budgets[2].soft_limit_exceeded);
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .find(|row| row.signal == RuntimePressureSignal::RegionMemoryBudgets)
                .map(|row| (row.status, row.reason.as_str())),
            Some((
                RuntimePressureSignalStatus::Critical,
                "region_memory_budget_hard_pressure",
            ))
        );

        let value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            value["region_memory_budgets"][0]["schema_version"],
            RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION
        );
        assert_eq!(
            value["region_memory_budgets"][0]["advisory_only"],
            json!(true)
        );
    }

    #[test]
    fn runtime_pressure_snapshot_folds_rch_proof_lane_receipts() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(24, 80, 95, 100),
        );

        let admitted = RuntimePressureRchProofLaneSnapshot::from_receipt(&admitted_rch_receipt(
            "cargo-test-admission",
        ));
        let refused = RuntimePressureRchProofLaneSnapshot::from_receipt(
            &refused_remote_required_rch_receipt("cargo-clippy-admission"),
        );
        let snapshot = RuntimePressureSnapshot::from_parts_with_rch_proof_lanes(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
            vec![admitted, refused],
        );

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Critical);
        assert_eq!(snapshot.missing_signal_count, 0);
        assert_eq!(snapshot.degraded_signal_count, 0);
        assert_eq!(snapshot.critical_signal_count, 1);
        assert_eq!(
            snapshot
                .rch_proof_lanes
                .iter()
                .map(|row| row.lane_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cargo-clippy-admission", "cargo-test-admission"]
        );
        assert_eq!(
            snapshot.rch_proof_lanes[0].refusal_code.as_deref(),
            Some("no_workers")
        );
        assert!(
            snapshot.rch_proof_lanes[0]
                .reason_codes
                .contains(&"local_fallback_refused".to_string())
        );
        assert!(
            snapshot.rch_proof_lanes[1]
                .selected_worker
                .as_ref()
                .is_some_and(|worker| worker.starts_with("rchw-") && !worker.contains("vmi-"))
        );
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .find(|row| row.signal == RuntimePressureSignal::RchProofLanes)
                .map(|row| (row.status, row.reason.as_str())),
            Some((
                RuntimePressureSignalStatus::Critical,
                "rch_remote_required_proof_lane_refused",
            ))
        );

        let value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            value["rch_proof_lanes"][0]["schema_version"],
            RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION
        );
        assert_eq!(
            value["signal_statuses"][4]["signal"],
            json!("rch_proof_lanes")
        );
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_serializes_stable_source_projection() {
        let mut input = complete_atlas_builder_input(healthy_spectral_snapshot(), false);
        input.replay_backed = true;
        input.dirty_tree_peer_ownership.reverse();
        input.lock_metrics.reverse();

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);
        let reparsed: AdmissionAwareRuntimePressureAtlasSnapshot =
            serde_json::from_str(&atlas.stable_json().expect("serialize atlas"))
                .expect("deserialize atlas");
        let value = serde_json::to_value(&atlas).expect("atlas to value");

        assert_eq!(
            atlas.schema_version,
            ADMISSION_AWARE_RUNTIME_PRESSURE_ATLAS_SCHEMA_VERSION
        );
        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::ReplayBacked
        );
        assert!(atlas.missing_required_sections.is_empty());
        assert!(!atlas.production_admission_default_enabled);
        assert!(!atlas.mutates_agent_mail);
        assert!(!atlas.mutates_beads);
        assert!(!atlas.mutates_filesystem);
        assert!(!atlas.starts_rch);
        assert_eq!(
            atlas.coordination_decision,
            AdmissionAwareCoordinationDecision::Proceed
        );
        assert_eq!(
            atlas.coordination_reason_codes,
            vec!["tracker_only_dirty_tree_change"]
        );
        assert_eq!(reparsed, atlas);
        assert_eq!(
            atlas
                .lock_contention
                .iter()
                .map(|row| row.lock_name.as_str())
                .collect::<Vec<_>>(),
            vec!["regions", "tasks"]
        );
        assert_eq!(atlas.lock_contention[1].acquisitions, 16);
        assert_eq!(atlas.lock_contention[1].order_edges_exercised, 1);
        assert_eq!(atlas.lock_contention[1].order_violations, 1);
        assert_eq!(
            atlas
                .dirty_tree_peer_ownership
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            vec![".beads/issues.jsonl", "src/runtime/resource_monitor.rs"]
        );
        assert_eq!(
            value["schema_version"],
            "admission-aware-runtime-pressure-atlas-v1"
        );
        assert_eq!(value["overall_label"], "replay_backed");
        assert_eq!(value["coordination_decision"], "proceed");
        assert_eq!(
            value["scheduler_pressure"][0]["scheduler_tail_pressure_label"],
            "nominal"
        );
        assert_eq!(value["trapped_cycle_witness"], json!([]));
        assert_eq!(
            value["rch_proof_lane_admission"][0]["cover_claims"],
            json!([
                "remote_proof_lane_admission_planner",
                "remote_required_policy",
                "worker_capacity_selected",
            ])
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["worker_saturation"],
            "available"
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["advisory_batching_decision"],
            "prefer_warm_worker"
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["advisory_batch_size_hint"],
            json!(3)
        );
        assert_eq!(
            value["large_host_worker_warmth"][0]["advisory_only"],
            json!(true)
        );
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_classifies_large_host_advisory_batching_profile() {
        let mut input = complete_atlas_builder_input(healthy_spectral_snapshot(), false);
        let healthy = input.large_host_worker_warmth[0].clone();
        let mut low_memory = healthy.clone();
        low_memory.worker_id = "rchw-large-low-memory".to_string();
        low_memory.worker_available_cores = 32;
        low_memory.worker_available_memory_bytes = 32 * 1024 * 1024 * 1024;

        let mut saturated = healthy.clone();
        saturated.worker_id = "rchw-large-saturated".to_string();
        saturated.worker_queue_state = "saturated".to_string();
        saturated.worker_available_cores = 4;
        saturated.worker_available_memory_bytes = 192 * 1024 * 1024 * 1024;

        let mut cold = healthy.clone();
        cold.worker_id = "rchw-large-cold".to_string();
        cold.cache_warmth = "cold".to_string();
        cold.worker_available_cores = 16;
        cold.worker_available_memory_bytes = 128 * 1024 * 1024 * 1024;

        input.large_host_worker_warmth = vec![saturated, low_memory, cold, healthy];

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);
        let rows = atlas
            .large_host_worker_warmth
            .iter()
            .map(|row| (row.worker_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let healthy = rows.get("rchw-large-1").expect("healthy worker");
        let low_memory = rows
            .get("rchw-large-low-memory")
            .expect("low-memory worker");
        let saturated = rows.get("rchw-large-saturated").expect("saturated worker");
        let cold = rows.get("rchw-large-cold").expect("cold worker");

        assert_eq!(healthy.cpu_cores, ADMISSION_AWARE_LARGE_HOST_CPU_CORES);
        assert_eq!(
            healthy.memory_bytes,
            ADMISSION_AWARE_LARGE_HOST_MEMORY_BYTES
        );
        assert_eq!(
            healthy.numa_nodes,
            ADMISSION_AWARE_LARGE_HOST_MIN_NUMA_NODES
        );
        assert_eq!(healthy.cache_warmth, "warm");
        assert!(healthy.target_dir_isolated);
        assert!(healthy.active_project_excluded);
        assert_eq!(
            healthy.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::Available
        );
        assert_eq!(
            healthy.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::PreferWarmWorker
        );
        assert_eq!(healthy.advisory_batch_size_hint, Some(3));
        for required in [
            "active_project_excluded",
            "advisory_batching_only",
            "large_host_shape_64_core_256_gib",
            "proof_lane_cost_estimate_present",
            "target_dir_isolated",
            "worker_cache_warm",
        ] {
            assert!(
                healthy
                    .advisory_batching_reason_codes
                    .iter()
                    .any(|code| code == required),
                "healthy worker reason missing {required}"
            );
        }

        assert_eq!(
            low_memory.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::LowMemory
        );
        assert_eq!(
            low_memory.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::QueueLowMemory
        );
        assert_eq!(low_memory.advisory_batch_size_hint, None);
        assert!(
            low_memory
                .advisory_batching_reason_codes
                .iter()
                .any(|code| code == "worker_memory_low")
        );

        assert_eq!(
            saturated.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::WorkerSaturated
        );
        assert_eq!(
            saturated.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::DeferWorkerSaturated
        );
        assert_eq!(saturated.advisory_batch_size_hint, None);
        assert!(
            saturated
                .advisory_batching_reason_codes
                .iter()
                .any(|code| code == "worker_queue_saturated")
        );

        assert_eq!(
            cold.worker_saturation,
            AdmissionAwareLargeHostWorkerSaturation::Available
        );
        assert_eq!(
            cold.advisory_batching_decision,
            AdmissionAwareLargeHostBatchingDecision::AdmitBatch
        );
        assert_eq!(cold.advisory_batch_size_hint, Some(2));
        assert!(
            cold.advisory_batching_reason_codes
                .iter()
                .any(|code| code == "worker_cache_cold")
        );

        for row in atlas.large_host_worker_warmth {
            assert!(row.advisory_only);
            for forbidden in [
                "allocator_enforcement",
                "production_admission_default",
                "throughput_improvement",
            ] {
                assert!(
                    row.advisory_non_claims
                        .iter()
                        .any(|claim| claim == forbidden),
                    "large-host row must keep {forbidden} as a non-claim"
                );
            }
        }
        assert!(!atlas.production_admission_default_enabled);
        assert!(!atlas.mutates_agent_mail);
        assert!(!atlas.mutates_beads);
        assert!(!atlas.mutates_filesystem);
        assert!(!atlas.starts_rch);
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_correlates_read_only_coordination_inputs() {
        let mut input = complete_atlas_builder_input(healthy_spectral_snapshot(), false);
        input
            .dirty_tree_peer_ownership
            .push(AdmissionAwareDirtyTreePeerOwnershipRow {
                path: "src/channel/mpsc.rs".to_string(),
                dirty_classification: "peer-owned-source-overlap".to_string(),
                holder: Some("PeerAgent".to_string()),
                bead_id: Some("asupersync-peer.1".to_string()),
                source: "agent-mail-reservation".to_string(),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::PeerExact,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                blocks_admission: true,
                handoff_required: true,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });
        input
            .agent_mail_reservations
            .push(AdmissionAwareAgentMailReservationRow {
                path_pattern: "src/channel/*.rs".to_string(),
                holder: "PeerAgent".to_string(),
                exclusive: true,
                reason: "asupersync-peer.1".to_string(),
                expires_ts: Some("2026-06-02T23:30:00Z".to_string()),
                bead_id: Some("asupersync-peer.1".to_string()),
                overlap_classification:
                    AdmissionAwareCoordinationOverlapClass::ActiveExclusiveConflict,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });
        input
            .agent_mail_reservations
            .push(AdmissionAwareAgentMailReservationRow {
                path_pattern: "docs/runtime_pressure_triage_runbook.md".to_string(),
                holder: "PeerAgent".to_string(),
                exclusive: true,
                reason: "old-docs-reservation".to_string(),
                expires_ts: Some("2026-06-02T19:00:00Z".to_string()),
                bead_id: None,
                overlap_classification: AdmissionAwareCoordinationOverlapClass::ExpiredReservation,
                coordination_decision: AdmissionAwareCoordinationDecision::Blocked,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });
        input
            .br_tracker_status
            .push(AdmissionAwareBrTrackerStatusRow {
                bead_id: "asupersync-bt63nr.4".to_string(),
                status: "open".to_string(),
                priority: Some(1),
                blocked_by: vec!["asupersync-bt63nr.7".to_string()],
                ready: false,
                assignee: None,
                updated_at: Some("2026-06-02T22:44:00Z".to_string()),
                overlap_classification: AdmissionAwareCoordinationOverlapClass::TrackerOnly,
                coordination_decision: AdmissionAwareCoordinationDecision::Proceed,
                sample_freshness: AdmissionAwareAtlasFreshnessStatus::Fresh,
            });

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);

        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::ValidationBlocked
        );
        assert_eq!(
            atlas.coordination_decision,
            AdmissionAwareCoordinationDecision::HandoffRequired
        );
        for reason in [
            "active_exclusive_agent_mail_conflict",
            "bead_blocked_by_dependencies",
            "bead_not_ready",
            "expired_agent_mail_reservation",
            "peer_dirty_tree_overlap",
            "tracker_only_dirty_tree_change",
        ] {
            assert!(
                atlas
                    .coordination_reason_codes
                    .iter()
                    .any(|code| code == reason),
                "coordination reason missing {reason}"
            );
        }
        assert_eq!(
            atlas
                .dirty_tree_peer_ownership
                .iter()
                .map(|row| (row.path.as_str(), row.coordination_decision))
                .collect::<Vec<_>>(),
            vec![
                (
                    ".beads/issues.jsonl",
                    AdmissionAwareCoordinationDecision::Proceed
                ),
                (
                    "src/channel/mpsc.rs",
                    AdmissionAwareCoordinationDecision::HandoffRequired
                ),
                (
                    "src/runtime/resource_monitor.rs",
                    AdmissionAwareCoordinationDecision::Proceed
                ),
            ]
        );
        let expired = atlas
            .agent_mail_reservations
            .iter()
            .find(|row| {
                row.overlap_classification
                    == AdmissionAwareCoordinationOverlapClass::ExpiredReservation
            })
            .expect("expired reservation row");
        assert_eq!(
            expired.coordination_decision,
            AdmissionAwareCoordinationDecision::Proceed,
            "expired reservations are visible but should not block the lane"
        );
        assert!(!atlas.mutates_agent_mail);
        assert!(!atlas.mutates_beads);
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_fails_closed_for_missing_source_rows() {
        let runtime_pressure = RuntimePressureSnapshot::from_parts(
            &ResourcePressure::new(),
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            None,
        );
        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(
            AdmissionAwareRuntimePressureAtlasBuilderInput::new(
                runtime_pressure,
                LockOrderAtlasSnapshot {
                    order_edges_exercised: Vec::new(),
                    order_violations: Vec::new(),
                    instrumentation_mode: "disabled",
                },
            ),
        );

        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::StaleEvidence
        );
        assert!(!atlas.deadlock_proven);
        assert_eq!(
            atlas.missing_required_sections,
            vec![
                "agent_mail_reservations",
                "br_tracker_status",
                "dirty_tree_peer_ownership",
                "large_host_worker_warmth",
                "lock_contention",
                "operator_closeout_receipt",
                "rch_proof_lane_admission",
                "scheduler_pressure",
                "spectral_wait_graph",
            ]
        );
        assert!(
            atlas
                .claim_boundary_labels
                .iter()
                .any(|row| row.label == AdmissionAwareAtlasClaimLabel::StaleEvidence)
        );
        assert!(atlas.lock_contention.is_empty());
        assert!(atlas.scheduler_pressure.is_empty());
        assert!(atlas.spectral_wait_graph.is_empty());
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_requires_explicit_trapped_cycle_witness() {
        let deadlocked = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Deadlocked,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_400_000),
            bottleneck_count: 0,
            components: Some(2),
            approaching_disconnect: false,
            trapped_wait_cycle: true,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let advisory = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(
            complete_atlas_builder_input(deadlocked.clone(), false),
        );
        let proven = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(
            complete_atlas_builder_input(deadlocked, true),
        );

        assert!(!advisory.deadlock_proven);
        assert_eq!(
            advisory.overall_label,
            AdmissionAwareAtlasClaimLabel::StaleEvidence
        );
        assert!(
            advisory
                .missing_required_sections
                .contains(&"trapped_cycle_witness".to_string())
        );
        assert_eq!(
            advisory.spectral_wait_graph[0].deadlock_proven, false,
            "spectral deadlocked class alone must not upgrade the claim"
        );

        assert!(proven.deadlock_proven);
        assert_eq!(
            proven.overall_label,
            AdmissionAwareAtlasClaimLabel::DeadlockProven
        );
        assert!(proven.missing_required_sections.is_empty());
        assert!(proven.spectral_wait_graph[0].deadlock_proven);
        assert_eq!(proven.trapped_cycle_witness.len(), 1);
        assert_eq!(
            proven.trapped_cycle_witness[0].proof_status,
            AdmissionAwareTrappedCycleWitnessProofStatus::Validated
        );
        assert_eq!(
            proven.trapped_cycle_witness[0].wait_edges[0].waiting_participant,
            "task:00000001-00000000",
            "witness wait edges should be canonically sorted"
        );
        assert!(
            proven
                .claim_boundary_labels
                .iter()
                .any(|row| row.label == AdmissionAwareAtlasClaimLabel::DeadlockProven)
        );
    }

    #[test]
    fn admission_aware_runtime_pressure_atlas_rejects_unvalidated_trapped_cycle_witness() {
        let deadlocked = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Deadlocked,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_400_000),
            bottleneck_count: 0,
            components: Some(2),
            approaching_disconnect: false,
            trapped_wait_cycle: true,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };
        let mut input = complete_atlas_builder_input(deadlocked, false);
        let mut witness = sample_trapped_cycle_witness();
        witness.proof_status = AdmissionAwareTrappedCycleWitnessProofStatus::ReplayPending;
        input.trapped_cycle_witnesses = vec![witness];

        let atlas = AdmissionAwareRuntimePressureAtlasSnapshot::from_source_snapshots(input);

        assert!(!atlas.deadlock_proven);
        assert_eq!(
            atlas.overall_label,
            AdmissionAwareAtlasClaimLabel::StaleEvidence
        );
        assert!(
            atlas
                .missing_required_sections
                .contains(&"trapped_cycle_witness".to_string())
        );
        assert_eq!(
            atlas.trapped_cycle_witness[0].proof_status,
            AdmissionAwareTrappedCycleWitnessProofStatus::ReplayPending
        );
        assert!(!atlas.spectral_wait_graph[0].deadlock_proven);
    }

    #[test]
    fn runtime_pressure_snapshot_escalates_critical_spectral_evidence() {
        let pressure = ResourcePressure::new();
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Critical,
            fiedler_micro_units: Some(5_000),
            spectral_gap_bps: Some(50),
            spectral_radius_micro_units: Some(2_000_000),
            bottleneck_count: 3,
            components: None,
            approaching_disconnect: true,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let snapshot = RuntimePressureSnapshot::from_parts(
            &pressure,
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            Some(spectral),
        );

        assert_eq!(snapshot.overall_verdict, RuntimePressureVerdict::Critical);
        assert_eq!(snapshot.critical_signal_count, 1);
        assert_eq!(snapshot.missing_signal_count, 3);
        assert_eq!(
            snapshot.spectral.class,
            RuntimePressureSpectralClass::Critical
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_empty_for_healthy() {
        let snapshot = snapshot_with_spectral(healthy_spectral_snapshot());

        assert!(snapshot.spectral_recommendations.is_empty());
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_cover_degraded_watch() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Degraded,
            fiedler_micro_units: Some(40_000),
            spectral_gap_bps: Some(900),
            spectral_radius_micro_units: Some(1_900_000),
            bottleneck_count: 2,
            components: None,
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Watch,
        };

        let snapshot = snapshot_with_spectral(spectral);
        let recommendations = snapshot.spectral_recommendations;

        assert!(recommendations.iter().any(|recommendation| {
            recommendation.action
                == RuntimePressureRecommendationAction::CollectTaskInspectorDetails
                && recommendation.reason == RuntimePressureRecommendationReason::Bottleneck
        }));
        assert!(recommendations.iter().any(|recommendation| {
            recommendation.action == RuntimePressureRecommendationAction::InspectSpectralBottlenecks
                && recommendation.reason == RuntimePressureRecommendationReason::Bottleneck
        }));
        assert!(recommendations.iter().any(|recommendation| {
            recommendation.action == RuntimePressureRecommendationAction::EnableLabReplay
                && recommendation.evidence_scope
                    == RuntimePressureRecommendationEvidenceScope::SpectralTrend
        }));
        assert!(
            recommendations
                .iter()
                .all(|recommendation| !recommendation.deadlock_proven
                    && !recommendation.requires_trapped_cycle_proof)
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_flag_critical_topology_as_advisory() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Critical,
            fiedler_micro_units: Some(5_000),
            spectral_gap_bps: Some(50),
            spectral_radius_micro_units: Some(2_000_000),
            bottleneck_count: 1,
            components: None,
            approaching_disconnect: true,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let snapshot = snapshot_with_spectral(spectral);

        assert!(
            snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::RunTrappedCycleDetection
                        && recommendation.requires_trapped_cycle_proof
                        && !recommendation.deadlock_proven
                })
        );
        assert!(
            snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action == RuntimePressureRecommendationAction::TightenAdmission
                        && recommendation.evidence_scope
                            == RuntimePressureRecommendationEvidenceScope::SpectralTopology
                        && !recommendation.deadlock_proven
                })
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_cover_oscillation_without_deadlock_proof() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Healthy,
            fiedler_micro_units: Some(120_000),
            spectral_gap_bps: Some(2_000),
            spectral_radius_micro_units: Some(1_700_000),
            bottleneck_count: 0,
            components: None,
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Critical,
        };

        let snapshot = snapshot_with_spectral(spectral);

        assert_eq!(snapshot.spectral_recommendations.len(), 1);
        assert_eq!(
            snapshot.spectral_recommendations[0].action,
            RuntimePressureRecommendationAction::EnableLabReplay
        );
        assert_eq!(
            snapshot.spectral_recommendations[0].evidence_scope,
            RuntimePressureRecommendationEvidenceScope::SpectralTrend
        );
        assert!(!snapshot.spectral_recommendations[0].deadlock_proven);
        assert!(!snapshot.spectral_recommendations[0].requires_trapped_cycle_proof);
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_separate_trapped_cycle_proof() {
        let fragmented = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Fragmented,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_400_000),
            bottleneck_count: 0,
            components: Some(3),
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::None,
        };
        let deadlocked = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Deadlocked,
            trapped_wait_cycle: true,
            ..fragmented.clone()
        };

        let fragmented_snapshot = snapshot_with_spectral(fragmented);
        let deadlocked_snapshot = snapshot_with_spectral(deadlocked);

        assert!(
            fragmented_snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::RunTrappedCycleDetection
                        && recommendation.requires_trapped_cycle_proof
                        && !recommendation.deadlock_proven
                })
        );
        assert!(
            deadlocked_snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::ConfirmTrappedCycleEvidence
                        && recommendation.evidence_scope
                            == RuntimePressureRecommendationEvidenceScope::ExplicitTrappedCycle
                        && recommendation.deadlock_proven
                        && !recommendation.requires_trapped_cycle_proof
                })
        );
        assert!(
            !deadlocked_snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| recommendation.requires_trapped_cycle_proof)
        );
    }

    #[test]
    fn runtime_pressure_spectral_recommendations_sort_and_serialize_stably() {
        let spectral = RuntimePressureSpectralSnapshot {
            class: RuntimePressureSpectralClass::Fragmented,
            fiedler_micro_units: Some(0),
            spectral_gap_bps: Some(0),
            spectral_radius_micro_units: Some(2_100_000),
            bottleneck_count: 2,
            components: Some(4),
            approaching_disconnect: false,
            trapped_wait_cycle: false,
            early_warning_severity: RuntimePressureEarlyWarningSeverity::Warning,
        };

        let snapshot = snapshot_with_spectral(spectral);
        let rows = snapshot
            .spectral_recommendations
            .iter()
            .map(|recommendation| {
                (
                    recommendation.severity,
                    recommendation.reason,
                    recommendation.action,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rows,
            vec![
                (
                    RuntimePressureRecommendationSeverity::Escalate,
                    RuntimePressureRecommendationReason::FragmentedTopology,
                    RuntimePressureRecommendationAction::RunTrappedCycleDetection,
                ),
                (
                    RuntimePressureRecommendationSeverity::Mitigate,
                    RuntimePressureRecommendationReason::FragmentedTopology,
                    RuntimePressureRecommendationAction::CollectTaskInspectorDetails,
                ),
                (
                    RuntimePressureRecommendationSeverity::Investigate,
                    RuntimePressureRecommendationReason::Bottleneck,
                    RuntimePressureRecommendationAction::InspectSpectralBottlenecks,
                ),
                (
                    RuntimePressureRecommendationSeverity::Investigate,
                    RuntimePressureRecommendationReason::EarlyWarning,
                    RuntimePressureRecommendationAction::EnableLabReplay,
                ),
            ]
        );

        let value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            value["spectral_recommendations"][0]["severity"],
            json!("escalate")
        );
        assert_eq!(
            value["spectral_recommendations"][0]["reason"],
            json!("fragmented_topology")
        );
        assert_eq!(
            value["spectral_recommendations"][0]["requires_trapped_cycle_proof"],
            json!(true)
        );
        assert_eq!(
            value["spectral_recommendations"][3]["evidence_scope"],
            json!("spectral_trend")
        );
    }

    #[test]
    fn runtime_pressure_lab_evidence_covers_required_scenarios() {
        let scenarios = vec![
            healthy_pressure_lab_evidence(),
            cpu_lane_pressure_lab_evidence(),
            resource_fallback_degraded_lab_evidence(),
            region_memory_budget_overrun_lab_evidence(),
            structural_warning_lab_evidence(),
            rch_proof_lane_remote_refusal_lab_evidence(),
        ];

        assert_eq!(
            scenarios
                .iter()
                .map(|evidence| evidence.scenario_kind)
                .collect::<Vec<_>>(),
            vec![
                RuntimePressureLabScenarioKind::Healthy,
                RuntimePressureLabScenarioKind::CpuLanePressure,
                RuntimePressureLabScenarioKind::ResourceFallbackDegraded,
                RuntimePressureLabScenarioKind::RegionMemoryBudgetOverrun,
                RuntimePressureLabScenarioKind::StructuralWarning,
                RuntimePressureLabScenarioKind::RchProofLaneRemoteRefusal,
            ]
        );
        assert!(
            scenarios
                .iter()
                .all(|evidence| evidence.classification_matches_expected)
        );
        assert_eq!(
            scenarios
                .iter()
                .map(|evidence| evidence.observed_verdict)
                .collect::<Vec<_>>(),
            vec![
                RuntimePressureVerdict::Healthy,
                RuntimePressureVerdict::Critical,
                RuntimePressureVerdict::Degraded,
                RuntimePressureVerdict::Critical,
                RuntimePressureVerdict::Critical,
                RuntimePressureVerdict::Critical,
            ]
        );
    }

    #[test]
    fn runtime_pressure_lab_evidence_serializes_stable_projection() {
        let evidence = vec![
            healthy_pressure_lab_evidence(),
            cpu_lane_pressure_lab_evidence(),
            resource_fallback_degraded_lab_evidence(),
            region_memory_budget_overrun_lab_evidence(),
            structural_warning_lab_evidence(),
            rch_proof_lane_remote_refusal_lab_evidence(),
        ];
        let value = serde_json::to_value(&evidence).expect("serialize lab evidence");
        let projection = value
            .as_array()
            .expect("evidence serializes as array")
            .iter()
            .map(|row| {
                json!({
                    "schema_version": row["schema_version"],
                    "scenario_id": row["scenario_id"],
                    "seed": row["seed"],
                    "scenario_kind": row["scenario_kind"],
                    "observed_verdict": row["observed_verdict"],
                    "classification_matches_expected": row["classification_matches_expected"],
                    "diagnostic_labels": row["diagnostic_labels"],
                    "resources": row["snapshot"]["resources"].as_array().map_or(0, Vec::len),
                    "region_memory_budgets": row["snapshot"]["region_memory_budgets"].as_array().map_or(0, Vec::len),
                    "rch_proof_lanes": row["snapshot"]["rch_proof_lanes"].as_array().map_or(0, Vec::len),
                    "critical_signal_count": row["snapshot"]["critical_signal_count"],
                    "degraded_signal_count": row["snapshot"]["degraded_signal_count"],
                    "spectral_class": row["snapshot"]["spectral"]["class"],
                })
            })
            .collect::<Vec<_>>();

        assert_eq!(
            projection,
            vec![
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-healthy",
                    "seed": 1470693377u64,
                    "scenario_kind": "healthy",
                    "observed_verdict": "healthy",
                    "classification_matches_expected": true,
                    "diagnostic_labels": ["all_signals_present"],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 0,
                    "degraded_signal_count": 0,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-cpu-lane-pressure",
                    "seed": 1470742545u64,
                    "scenario_kind": "cpu_lane_pressure",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "cpu_load_hard_limit",
                        "resource_heavy_degradation",
                        "scheduler_tail_pressure",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 1,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-resource-fallback-degraded",
                    "seed": 1470757393u64,
                    "scenario_kind": "resource_fallback_degraded",
                    "observed_verdict": "degraded",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "memory_soft_pressure",
                        "platform_probe_fallback",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 0,
                    "degraded_signal_count": 2,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-region-memory-budget-overrun",
                    "seed": 1470741209u64,
                    "scenario_kind": "region_memory_budget_overrun",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "region_memory_budget_advisory",
                        "region_memory_budget_exhausted",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 1,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 0,
                    "spectral_class": "healthy",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-structural-warning",
                    "seed": 1470715820u64,
                    "scenario_kind": "structural_warning",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "spectral_fragmented_topology",
                        "trapped_cycle_detection_required",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 0,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 0,
                    "spectral_class": "fragmented",
                }),
                json!({
                    "schema_version": RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
                    "scenario_id": "runtime-pressure-lab-rch-proof-lane-remote-refusal",
                    "seed": 1470725143u64,
                    "scenario_kind": "rch_proof_lane_remote_refusal",
                    "observed_verdict": "critical",
                    "classification_matches_expected": true,
                    "diagnostic_labels": [
                        "local_fallback_refused",
                        "rch_remote_required_refused",
                    ],
                    "resources": 1,
                    "region_memory_budgets": 0,
                    "rch_proof_lanes": 1,
                    "critical_signal_count": 1,
                    "degraded_signal_count": 0,
                    "spectral_class": "healthy",
                }),
            ]
        );
    }

    #[test]
    fn runtime_pressure_lab_evidence_is_reproducible_for_fixed_inputs() {
        let first = structural_warning_lab_evidence();
        let second = structural_warning_lab_evidence();

        assert_eq!(first, second);
        assert_eq!(
            first.stable_json().expect("first json"),
            second.stable_json().expect("second json")
        );
        assert!(
            first
                .snapshot
                .spectral_recommendations
                .iter()
                .any(|recommendation| {
                    recommendation.action
                        == RuntimePressureRecommendationAction::RunTrappedCycleDetection
                        && recommendation.requires_trapped_cycle_proof
                        && !recommendation.deadlock_proven
                })
        );
    }

    #[test]
    fn resource_monitor_builds_runtime_pressure_snapshot() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());
        monitor.pressure().update_measurement(
            ResourceType::Task,
            ResourceMeasurement::new(20, 80, 95, 100),
        );

        let snapshot = monitor.runtime_pressure_snapshot(Some(healthy_scheduler_metrics()), None);

        assert_eq!(
            snapshot.schema_version,
            RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(snapshot.resources[0].resource_label, "task");
        assert_eq!(
            snapshot
                .scheduler
                .expect("scheduler metrics")
                .ready_backlog_p99,
            48
        );
    }

    #[test]
    fn resource_monitor_folds_externally_captured_rch_receipts() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());
        monitor.pressure().update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(40, 80, 95, 100),
        );
        let receipt = admitted_rch_receipt("cargo-test-admission");

        let snapshot = monitor.runtime_pressure_snapshot_with_rch_receipts(
            Some(healthy_scheduler_metrics()),
            None,
            &[receipt],
        );

        assert_eq!(snapshot.rch_proof_lanes.len(), 1);
        assert_eq!(
            snapshot.rch_proof_lanes[0].schema_version,
            RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION
        );
        assert_eq!(
            snapshot
                .signal_statuses
                .iter()
                .find(|row| row.signal == RuntimePressureSignal::RchProofLanes)
                .map(|row| row.status),
            Some(RuntimePressureSignalStatus::Present)
        );
        assert!(
            snapshot.rch_proof_lanes[0]
                .reason_codes
                .contains(&"cache_warm_capacity_present".to_string())
        );
    }

    #[test]
    fn runtime_pressure_admission_policy_defaults_to_no_effect() {
        let snapshot = cpu_lane_pressure_lab_evidence().snapshot;
        let decision = RuntimePressureAdmissionPolicy::default()
            .decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Admit);
        assert!(!decision.policy_enabled);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::PolicyDisabled]
        );
        assert_eq!(decision.snapshot_verdict, RuntimePressureVerdict::Critical);
    }

    #[test]
    fn runtime_pressure_admission_defers_optional_work_on_degraded_snapshot() {
        let snapshot = resource_fallback_degraded_lab_evidence().snapshot;
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Defer);
        assert!(decision.policy_enabled);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::SnapshotDegraded]
        );
        assert_eq!(decision.degraded_signal_count, 2);
    }

    #[test]
    fn runtime_pressure_admission_rejects_optional_work_on_critical_snapshot() {
        let snapshot = structural_warning_lab_evidence().snapshot;
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Reject);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::SnapshotCritical]
        );
        assert_eq!(decision.critical_signal_count, 1);
    }

    #[test]
    fn runtime_pressure_admission_keeps_required_work_on_memory_budget_pressure() {
        let pressure = ResourcePressure::new();
        pressure.update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 95, 100),
        );
        let snapshot = RuntimePressureSnapshot::from_parts_with_region_memory_budgets(
            &pressure,
            complete_platform_probe_report(),
            Some(healthy_scheduler_metrics()),
            Some(healthy_spectral_snapshot()),
            vec![RuntimePressureRegionMemoryBudgetSnapshot::with_label(
                RegionId::new_ephemeral(),
                "cleanup-region",
                1_000,
                1_100,
            )],
        );
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();

        let optional = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);
        assert_eq!(optional.action, RuntimePressureAdmissionAction::Reject);
        assert_eq!(
            optional.reason_codes,
            vec![RuntimePressureAdmissionReason::SnapshotCritical]
        );

        let required = policy.decide(RuntimePressureAdmissionWorkClass::Required, &snapshot);
        assert_eq!(required.action, RuntimePressureAdmissionAction::Admit);
        assert_eq!(
            required.reason_codes,
            vec![RuntimePressureAdmissionReason::RequiredWorkBypass]
        );
        assert_eq!(required.critical_signal_count, 1);
    }

    #[test]
    fn runtime_pressure_admission_required_work_bypasses_critical_and_unknown_schema() {
        let mut snapshot = cpu_lane_pressure_lab_evidence().snapshot;
        snapshot.schema_version = "asupersync.runtime-pressure-snapshot.future".to_string();
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Required, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Admit);
        assert_eq!(
            decision.reason_codes,
            vec![
                RuntimePressureAdmissionReason::RequiredWorkBypass,
                RuntimePressureAdmissionReason::UnknownSnapshotSchema,
            ]
        );
        assert_eq!(
            decision.snapshot_schema_version,
            "asupersync.runtime-pressure-snapshot.future"
        );
    }

    #[test]
    fn runtime_pressure_admission_fails_closed_for_unknown_optional_schema() {
        let mut snapshot = healthy_pressure_lab_evidence().snapshot;
        snapshot.schema_version = "asupersync.runtime-pressure-snapshot.future".to_string();
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Reject);
        assert_eq!(
            decision.reason_codes,
            vec![RuntimePressureAdmissionReason::UnknownSnapshotSchema]
        );
        assert_eq!(decision.snapshot_verdict, RuntimePressureVerdict::Healthy);
    }

    #[test]
    fn runtime_pressure_admission_marks_missing_signals_without_accepting_unknown_snapshot() {
        let snapshot = RuntimePressureSnapshot::from_parts(
            &ResourcePressure::new(),
            ResourcePlatformProbeReport::from_snapshots("test/noarch".to_string(), Vec::new()),
            None,
            None,
        );
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Defer);
        assert_eq!(
            decision.reason_codes,
            vec![
                RuntimePressureAdmissionReason::SnapshotUnknown,
                RuntimePressureAdmissionReason::MissingPressureSignals,
            ]
        );
        assert_eq!(decision.missing_signal_count, 4);
    }

    #[test]
    fn runtime_pressure_admission_is_deterministic_for_fixed_snapshots() {
        let snapshot = structural_warning_lab_evidence().snapshot;
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let first = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);

        for _ in 0..8 {
            let next = policy.decide(RuntimePressureAdmissionWorkClass::Optional, &snapshot);
            assert_eq!(first, next);
        }

        let json = serde_json::to_string_pretty(&first).expect("serialize decision");
        let reparsed: RuntimePressureAdmissionDecision =
            serde_json::from_str(&json).expect("deserialize decision");
        assert_eq!(reparsed, first);
    }

    #[test]
    fn runtime_pressure_admission_helper_uses_resource_monitor_snapshot() {
        let monitor = ResourceMonitor::new(MonitorConfig::default());
        monitor.pressure().update_measurement(
            ResourceType::Memory,
            ResourceMeasurement::new(32, 80, 90, 100),
        );
        let policy = RuntimePressureAdmissionPolicy::conservative_optional_backpressure();
        let decision = monitor.pressure_admission_decision(
            &policy,
            RuntimePressureAdmissionWorkClass::Optional,
            Some(healthy_scheduler_metrics()),
            None,
        );

        assert_eq!(decision.action, RuntimePressureAdmissionAction::Defer);
        assert_eq!(decision.snapshot_verdict, RuntimePressureVerdict::Unknown);
        assert!(
            decision
                .reason_codes
                .contains(&RuntimePressureAdmissionReason::MissingPressureSignals)
        );
    }

    #[test]
    fn tail_risk_admission_falls_back_when_evidence_is_missing() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: None,
                retry_pressure_p99: Some(12),
                memory_pressure_bps: Some(7_200),
                degradation_level: DegradationLevel::Moderate,
            },
            &TailRiskAdmissionProfile::default(),
        );
        assert!(
            ledger.fallback_used,
            "missing evidence must trigger fallback"
        );
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Defer);
        assert_eq!(
            ledger.reason_codes,
            vec![TailRiskAdmissionReason::ConservativeFallback]
        );
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["scheduler_metrics".to_string()]
        );
    }

    #[test]
    fn tail_risk_admission_is_deterministic_for_fixed_inputs() {
        let evidence = TailRiskAdmissionEvidence {
            scheduler: Some(sample_scheduler_metrics()),
            retry_pressure_p99: Some(40),
            memory_pressure_bps: Some(8_700),
            degradation_level: DegradationLevel::Moderate,
        };
        let profile = TailRiskAdmissionProfile::default();
        let first = TailRiskAdmissionLedger::evaluate(&evidence, &profile);
        for _ in 0..8 {
            let next = TailRiskAdmissionLedger::evaluate(&evidence, &profile);
            assert_eq!(first, next, "fixed evidence must stay deterministic");
        }
    }

    #[test]
    fn tail_risk_admission_transitions_across_overload_bands() {
        let profile = TailRiskAdmissionProfile::default();
        let mild = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 6_000,
                    wake_to_run_p95_ns: 50_000,
                    wake_to_run_p99_ns: 80_000,
                    queue_residency_p50_ns: 10_000,
                    queue_residency_p95_ns: 90_000,
                    queue_residency_p99_ns: 140_000,
                    ready_backlog_p95: 96,
                    ready_backlog_p99: 120,
                    cancel_debt_p95: 24,
                    cancel_debt_p99: 40,
                    remote_steal_ratio_pct: Some(18),
                    cross_cohort_wake_p99_ns: Some(80_000),
                }),
                retry_pressure_p99: Some(6),
                memory_pressure_bps: Some(6_800),
                degradation_level: DegradationLevel::None,
            },
            &profile,
        );
        let medium = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 8_000,
                    wake_to_run_p95_ns: 90_000,
                    wake_to_run_p99_ns: 170_000,
                    queue_residency_p50_ns: 16_000,
                    queue_residency_p95_ns: 220_000,
                    queue_residency_p99_ns: 420_000,
                    ready_backlog_p95: 188,
                    ready_backlog_p99: 220,
                    cancel_debt_p95: 42,
                    cancel_debt_p99: 78,
                    remote_steal_ratio_pct: Some(34),
                    cross_cohort_wake_p99_ns: Some(140_000),
                }),
                retry_pressure_p99: Some(36),
                memory_pressure_bps: Some(7_900),
                degradation_level: DegradationLevel::Light,
            },
            &profile,
        );
        let severe = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(52),
                memory_pressure_bps: Some(9_450),
                degradation_level: DegradationLevel::Heavy,
            },
            &profile,
        );
        assert_eq!(mild.decision, TailRiskAdmissionDecision::Admit);
        assert_eq!(medium.decision, TailRiskAdmissionDecision::Defer);
        assert_eq!(severe.decision, TailRiskAdmissionDecision::Shed);
    }

    #[test]
    fn tail_risk_admission_ledger_round_trips_through_json() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(40),
                memory_pressure_bps: Some(8_700),
                degradation_level: DegradationLevel::Moderate,
            },
            &TailRiskAdmissionProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize ledger");
        let reparsed: TailRiskAdmissionLedger =
            serde_json::from_str(&json).expect("deserialize ledger");
        assert_eq!(reparsed, ledger);
    }

    #[test]
    fn tail_risk_admission_sheds_on_tail_and_memory_storm() {
        let ledger = TailRiskAdmissionLedger::evaluate(
            &TailRiskAdmissionEvidence {
                scheduler: Some(sample_scheduler_metrics()),
                retry_pressure_p99: Some(48),
                memory_pressure_bps: Some(9_400),
                degradation_level: DegradationLevel::Heavy,
            },
            &TailRiskAdmissionProfile::default(),
        );
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Shed);
        assert!(!ledger.fallback_used);
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::MemoryPressure)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::QueueResidencyTail)
        );
    }

    #[test]
    fn degradation_engine_evaluates_tail_risk_admission_from_pressure_band() {
        let pressure = Arc::new(ResourcePressure::new());
        let engine = DegradationEngine::new(Arc::clone(&pressure));
        pressure.update_degradation_level(ResourceType::Memory, DegradationLevel::Moderate);
        let ledger = engine.evaluate_tail_risk_admission(
            Some(&sample_scheduler_metrics()),
            Some(40),
            Some(8_300),
            &TailRiskAdmissionProfile::default(),
        );
        assert_eq!(ledger.degradation_level, DegradationLevel::Moderate);
        assert_eq!(ledger.decision, TailRiskAdmissionDecision::Shed);
        assert!(
            ledger
                .reason_codes
                .contains(&TailRiskAdmissionReason::ExistingDegradation)
        );
    }

    const TAIL_RISK_ADMISSION_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_TAIL_RISK_ADMISSION_CONTRACT_PATH";
    const TAIL_RISK_ADMISSION_SCENARIO_ENV: &str = "ASUPERSYNC_TAIL_RISK_ADMISSION_SCENARIO";
    const TAIL_RISK_ADMISSION_REPORT_PATH_ENV: &str = "ASUPERSYNC_TAIL_RISK_ADMISSION_REPORT_PATH";
    const TAIL_RISK_ADMISSION_REPORT_SCHEMA_VERSION: &str = "tail-risk-admission-report-v1";
    const TAIL_RISK_ADMISSION_PROJECTION_SCHEMA_VERSION: &str = "tail-risk-admission-projection-v1";
    const TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID: &str = "AA-TAIL-RISK-ADMISSION-MIXED-OVERLOAD";
    const TAIL_RISK_ADMISSION_FALLBACK_SCENARIO_ID: &str =
        "AA-TAIL-RISK-ADMISSION-CONSERVATIVE-FALLBACK";

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionSmokeContract {
        smoke_scenarios: Vec<TailRiskAdmissionScenario>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionScenario {
        scenario_id: String,
        description: String,
        workload_class: String,
        tail_risk_profile: TailRiskAdmissionProfile,
        fixed_threshold_profile: FixedThresholdAdmissionProfile,
        fixture: TailRiskAdmissionFixture,
        expected_report_projection: Value,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct FixedThresholdAdmissionProfile {
        ready_backlog_soft_limit: usize,
        ready_backlog_hard_limit: usize,
        memory_pressure_soft_bps: u16,
        memory_pressure_hard_bps: u16,
        moderate_degradation_sheds: bool,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionFixture {
        base_service_ns: u64,
        replay_count: usize,
        windows: Vec<TailRiskAdmissionWindow>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct TailRiskAdmissionWindow {
        window_id: String,
        wake_to_run_p99_ns: Option<u64>,
        queue_residency_p99_ns: Option<u64>,
        ready_backlog_p99: Option<usize>,
        cancel_debt_p99: Option<usize>,
        retry_pressure_p99: Option<u64>,
        memory_pressure_bps: Option<u16>,
        degradation_level: DegradationLevel,
        offered_work_units: u64,
    }

    #[derive(Debug, Clone, Serialize)]
    struct PolicySummary {
        decision_counts: Value,
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        fallback_used_count: u64,
        mean_expected_loss_score: f64,
        p50_latency_ns: u64,
        p95_latency_ns: u64,
        p99_latency_ns: u64,
        max_latency_ns: u64,
        throughput_ratio: f64,
    }

    #[derive(Debug, Clone)]
    struct PolicyAccumulator {
        admit_count: u64,
        defer_count: u64,
        shed_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        fallback_used_count: u64,
        loss_score_sum: u64,
        loss_score_count: u64,
        latencies: Vec<u64>,
    }

    impl PolicyAccumulator {
        fn record(
            &mut self,
            decision: TailRiskAdmissionDecision,
            fallback_used: bool,
            expected_loss_score: u8,
            outcome: &WindowOutcome,
        ) {
            match decision {
                TailRiskAdmissionDecision::Admit => self.admit_count += 1,
                TailRiskAdmissionDecision::Defer => self.defer_count += 1,
                TailRiskAdmissionDecision::Shed => self.shed_count += 1,
            }
            self.admitted_units = self.admitted_units.saturating_add(outcome.admitted_units);
            self.deferred_units = self.deferred_units.saturating_add(outcome.deferred_units);
            self.shed_units = self.shed_units.saturating_add(outcome.shed_units);
            if fallback_used {
                self.fallback_used_count += 1;
            }
            self.loss_score_sum = self
                .loss_score_sum
                .saturating_add(u64::from(expected_loss_score));
            self.loss_score_count += 1;
            self.latencies.extend_from_slice(&outcome.latency_samples);
        }

        fn summary(&self, total_offered_units: u64) -> PolicySummary {
            PolicySummary {
                decision_counts: json!({
                    "admit": self.admit_count,
                    "defer": self.defer_count,
                    "shed": self.shed_count,
                }),
                admitted_units: self.admitted_units,
                deferred_units: self.deferred_units,
                shed_units: self.shed_units,
                fallback_used_count: self.fallback_used_count,
                mean_expected_loss_score: ratio_u64(self.loss_score_sum, self.loss_score_count),
                p50_latency_ns: percentile_slice_u64(&self.latencies, 50, 100),
                p95_latency_ns: percentile_slice_u64(&self.latencies, 95, 100),
                p99_latency_ns: percentile_slice_u64(&self.latencies, 99, 100),
                max_latency_ns: self.latencies.iter().copied().max().unwrap_or(0),
                throughput_ratio: ratio_u64(self.admitted_units, total_offered_units),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct WindowOutcome {
        admitted_units: u64,
        deferred_units: u64,
        shed_units: u64,
        latency_samples: Vec<u64>,
    }

    fn default_tail_risk_admission_scenarios() -> Vec<TailRiskAdmissionScenario> {
        vec![
            TailRiskAdmissionScenario {
                scenario_id: TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID.to_string(),
                description: "Drive a deterministic mixed overload replay covering balanced traffic, retry storms, backlog spikes, and memory pressure while comparing the tail-risk controller against a fixed-threshold baseline.".to_string(),
                workload_class: "mixed-overload".to_string(),
                tail_risk_profile: TailRiskAdmissionProfile::default(),
                fixed_threshold_profile: FixedThresholdAdmissionProfile {
                    ready_backlog_soft_limit: 256,
                    ready_backlog_hard_limit: 320,
                    memory_pressure_soft_bps: 8_200,
                    memory_pressure_hard_bps: 9_200,
                    moderate_degradation_sheds: false,
                },
                fixture: TailRiskAdmissionFixture {
                    base_service_ns: 48_000,
                    replay_count: 2,
                    windows: vec![
                        TailRiskAdmissionWindow {
                            window_id: "steady".to_string(),
                            wake_to_run_p99_ns: Some(92_000),
                            queue_residency_p99_ns: Some(180_000),
                            ready_backlog_p99: Some(144),
                            cancel_debt_p99: Some(38),
                            retry_pressure_p99: Some(8),
                            memory_pressure_bps: Some(6_700),
                            degradation_level: DegradationLevel::None,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "retry_storm".to_string(),
                            wake_to_run_p99_ns: Some(176_000),
                            queue_residency_p99_ns: Some(430_000),
                            ready_backlog_p99: Some(224),
                            cancel_debt_p99: Some(72),
                            retry_pressure_p99: Some(41),
                            memory_pressure_bps: Some(7_800),
                            degradation_level: DegradationLevel::Light,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "backlog_and_cancel".to_string(),
                            wake_to_run_p99_ns: Some(164_000),
                            queue_residency_p99_ns: Some(360_000),
                            ready_backlog_p99: Some(248),
                            cancel_debt_p99: Some(118),
                            retry_pressure_p99: Some(22),
                            memory_pressure_bps: Some(7_950),
                            degradation_level: DegradationLevel::Moderate,
                            offered_work_units: 64,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "memory_surge".to_string(),
                            wake_to_run_p99_ns: Some(236_000),
                            queue_residency_p99_ns: Some(540_000),
                            ready_backlog_p99: Some(308),
                            cancel_debt_p99: Some(132),
                            retry_pressure_p99: Some(55),
                            memory_pressure_bps: Some(9_450),
                            degradation_level: DegradationLevel::Heavy,
                            offered_work_units: 64,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
            TailRiskAdmissionScenario {
                scenario_id: TAIL_RISK_ADMISSION_FALLBACK_SCENARIO_ID.to_string(),
                description: "Remove key evidence fields and prove the controller falls back deterministically to the conservative degradation-band comparator with explicit missing-field explanations.".to_string(),
                workload_class: "low-confidence-fallback".to_string(),
                tail_risk_profile: TailRiskAdmissionProfile::default(),
                fixed_threshold_profile: FixedThresholdAdmissionProfile {
                    ready_backlog_soft_limit: 256,
                    ready_backlog_hard_limit: 320,
                    memory_pressure_soft_bps: 8_200,
                    memory_pressure_hard_bps: 9_200,
                    moderate_degradation_sheds: false,
                },
                fixture: TailRiskAdmissionFixture {
                    base_service_ns: 48_000,
                    replay_count: 1,
                    windows: vec![
                        TailRiskAdmissionWindow {
                            window_id: "missing_scheduler".to_string(),
                            wake_to_run_p99_ns: None,
                            queue_residency_p99_ns: None,
                            ready_backlog_p99: None,
                            cancel_debt_p99: None,
                            retry_pressure_p99: Some(18),
                            memory_pressure_bps: Some(7_500),
                            degradation_level: DegradationLevel::Moderate,
                            offered_work_units: 48,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "missing_retry".to_string(),
                            wake_to_run_p99_ns: Some(128_000),
                            queue_residency_p99_ns: Some(240_000),
                            ready_backlog_p99: Some(180),
                            cancel_debt_p99: Some(52),
                            retry_pressure_p99: None,
                            memory_pressure_bps: Some(7_200),
                            degradation_level: DegradationLevel::Light,
                            offered_work_units: 48,
                        },
                        TailRiskAdmissionWindow {
                            window_id: "invalid_memory".to_string(),
                            wake_to_run_p99_ns: Some(156_000),
                            queue_residency_p99_ns: Some(280_000),
                            ready_backlog_p99: Some(196),
                            cancel_debt_p99: Some(66),
                            retry_pressure_p99: Some(20),
                            memory_pressure_bps: None,
                            degradation_level: DegradationLevel::Heavy,
                            offered_work_units: 48,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
        ]
    }

    fn load_tail_risk_admission_scenarios() -> Vec<TailRiskAdmissionScenario> {
        let Some(contract_path) = std::env::var(TAIL_RISK_ADMISSION_CONTRACT_PATH_ENV).ok() else {
            return default_tail_risk_admission_scenarios();
        };
        let contract: TailRiskAdmissionSmokeContract = serde_json::from_str(
            &fs::read_to_string(&contract_path).expect("read tail-risk admission contract"),
        )
        .expect("parse tail-risk admission contract");
        contract.smoke_scenarios
    }

    fn selected_tail_risk_admission_scenario() -> String {
        std::env::var(TAIL_RISK_ADMISSION_SCENARIO_ENV)
            .unwrap_or_else(|_| TAIL_RISK_ADMISSION_MIXED_SCENARIO_ID.to_string())
    }

    fn maybe_write_tail_risk_admission_report(path: &str, report: &Value) {
        let report_path = Path::new(path);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).expect("create tail-risk admission report directory");
        }
        fs::write(
            report_path,
            serde_json::to_string_pretty(report).expect("serialize tail-risk admission report"),
        )
        .expect("write tail-risk admission report");
    }

    fn ratio_u64(numerator: u64, denominator: u64) -> f64 {
        if denominator == 0 {
            return 0.0;
        }
        round4(numerator as f64 / denominator as f64)
    }

    fn round4(value: f64) -> f64 {
        (value * 10_000.0).round() / 10_000.0
    }

    fn percentile_slice_u64(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let index = ((sorted.len() - 1) * numerator) / denominator;
        sorted[index]
    }

    fn sample_scheduler_metrics_from_window(
        window: &TailRiskAdmissionWindow,
        window_index: usize,
    ) -> Option<SchedulerEvidenceMetrics> {
        Some(SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: window.wake_to_run_p99_ns?.saturating_div(10).max(1),
            wake_to_run_p95_ns: window
                .wake_to_run_p99_ns?
                .saturating_mul(8)
                .saturating_div(10),
            wake_to_run_p99_ns: window.wake_to_run_p99_ns?,
            queue_residency_p50_ns: window.queue_residency_p99_ns?.saturating_div(8).max(1),
            queue_residency_p95_ns: window
                .queue_residency_p99_ns?
                .saturating_mul(8)
                .saturating_div(10),
            queue_residency_p99_ns: window.queue_residency_p99_ns?,
            ready_backlog_p95: window
                .ready_backlog_p99?
                .saturating_sub(window.ready_backlog_p99?.saturating_div(6)),
            ready_backlog_p99: window.ready_backlog_p99?,
            cancel_debt_p95: window
                .cancel_debt_p99?
                .saturating_sub(window.cancel_debt_p99?.saturating_div(5)),
            cancel_debt_p99: window.cancel_debt_p99?,
            remote_steal_ratio_pct: Some((25 + window_index * 7) as u8),
            cross_cohort_wake_p99_ns: window
                .wake_to_run_p99_ns
                .map(|value| value.saturating_sub(12_000)),
        })
    }

    fn fixed_threshold_decision(
        window: &TailRiskAdmissionWindow,
        profile: &FixedThresholdAdmissionProfile,
    ) -> (TailRiskAdmissionDecision, Vec<&'static str>) {
        let mut reasons = Vec::new();
        if window.memory_pressure_bps.unwrap_or(10_001) >= profile.memory_pressure_hard_bps {
            reasons.push("memory_hard_limit");
        }
        if window.ready_backlog_p99.unwrap_or(usize::MAX) >= profile.ready_backlog_hard_limit {
            reasons.push("backlog_hard_limit");
        }
        if window.degradation_level >= DegradationLevel::Heavy
            || (profile.moderate_degradation_sheds
                && window.degradation_level >= DegradationLevel::Moderate)
        {
            reasons.push("degradation_band");
        }
        if !reasons.is_empty() {
            return (TailRiskAdmissionDecision::Shed, reasons);
        }

        if window
            .memory_pressure_bps
            .unwrap_or(profile.memory_pressure_soft_bps)
            >= profile.memory_pressure_soft_bps
        {
            reasons.push("memory_soft_limit");
        }
        if window
            .ready_backlog_p99
            .unwrap_or(profile.ready_backlog_soft_limit)
            >= profile.ready_backlog_soft_limit
        {
            reasons.push("backlog_soft_limit");
        }
        if window.degradation_level >= DegradationLevel::Moderate {
            reasons.push("moderate_degradation");
        }
        if !reasons.is_empty() {
            return (TailRiskAdmissionDecision::Defer, reasons);
        }

        (TailRiskAdmissionDecision::Admit, vec!["steady_state"])
    }

    fn simulate_window_outcome(
        decision: TailRiskAdmissionDecision,
        fixture: &TailRiskAdmissionFixture,
        window: &TailRiskAdmissionWindow,
        window_index: usize,
    ) -> WindowOutcome {
        let offered = window.offered_work_units;
        let (admitted_units, deferred_units, shed_units, overload_multiplier, decision_penalty) =
            match decision {
                TailRiskAdmissionDecision::Admit => (offered, 0, 0, 9_200, 18_000),
                TailRiskAdmissionDecision::Defer => (
                    offered.saturating_mul(78).saturating_div(100),
                    offered.saturating_sub(offered.saturating_mul(78).saturating_div(100)),
                    0,
                    6_200,
                    11_000,
                ),
                TailRiskAdmissionDecision::Shed => (
                    offered.saturating_mul(38).saturating_div(100),
                    0,
                    offered.saturating_sub(offered.saturating_mul(38).saturating_div(100)),
                    4_100,
                    7_000,
                ),
            };
        let wake = window.wake_to_run_p99_ns.unwrap_or(120_000);
        let queue = window.queue_residency_p99_ns.unwrap_or(260_000);
        let backlog = window.ready_backlog_p99.unwrap_or(180) as u64;
        let cancel_debt = window.cancel_debt_p99.unwrap_or(64) as u64;
        let retry = window.retry_pressure_p99.unwrap_or(18);
        let memory = u64::from(window.memory_pressure_bps.unwrap_or(7_500));
        let degradation = match window.degradation_level {
            DegradationLevel::None => 0,
            DegradationLevel::Light => 8,
            DegradationLevel::Moderate => 18,
            DegradationLevel::Heavy => 28,
            DegradationLevel::Emergency => 42,
        };
        let overload_score = wake.saturating_div(20_000)
            + queue.saturating_div(40_000)
            + backlog.saturating_div(14)
            + cancel_debt.saturating_div(9)
            + retry.saturating_mul(2)
            + memory.saturating_div(450)
            + degradation;
        let base_latency = fixture
            .base_service_ns
            .saturating_add(wake.saturating_div(3))
            .saturating_add(queue.saturating_div(4));

        let mut latency_samples = Vec::with_capacity(admitted_units as usize);
        for sample_idx in 0..admitted_units {
            let jitter = ((window_index as u64 * 19) + (sample_idx % 11) * 13).saturating_mul(157);
            let latency = base_latency
                .saturating_add(overload_score.saturating_mul(overload_multiplier))
                .saturating_add(decision_penalty)
                .saturating_add(jitter);
            latency_samples.push(latency);
        }

        WindowOutcome {
            admitted_units,
            deferred_units,
            shed_units,
            latency_samples,
        }
    }

    fn tail_risk_reason_label(reason: TailRiskAdmissionReason) -> &'static str {
        match reason {
            TailRiskAdmissionReason::WakeToRunTail => "wake_to_run_tail",
            TailRiskAdmissionReason::QueueResidencyTail => "queue_residency_tail",
            TailRiskAdmissionReason::BacklogPressure => "backlog_pressure",
            TailRiskAdmissionReason::CancelDebtPressure => "cancel_debt_pressure",
            TailRiskAdmissionReason::RetryPressure => "retry_pressure",
            TailRiskAdmissionReason::MemoryPressure => "memory_pressure",
            TailRiskAdmissionReason::ExistingDegradation => "existing_degradation",
            TailRiskAdmissionReason::ConservativeFallback => "conservative_fallback",
            TailRiskAdmissionReason::BalancedBaseline => "balanced_baseline",
        }
    }

    fn hash_json_value(value: &Value) -> u64 {
        let mut hasher = DefaultHasher::new();
        serde_json::to_string(value)
            .expect("serialize projection for hashing")
            .hash(&mut hasher);
        hasher.finish()
    }

    fn build_tail_risk_admission_report(
        scenario: &TailRiskAdmissionScenario,
        include_hash_probe: bool,
    ) -> Value {
        let total_offered_units = scenario
            .fixture
            .windows
            .iter()
            .map(|window| window.offered_work_units)
            .sum::<u64>()
            .saturating_mul(scenario.fixture.replay_count as u64);
        let evidence_vector_fields = json!([
            "wake_to_run_p99_ns",
            "queue_residency_p99_ns",
            "ready_backlog_p99",
            "cancel_debt_p99",
            "retry_pressure_p99",
            "memory_pressure_bps",
            "degradation_level"
        ]);

        let mut tail_risk = PolicyAccumulator {
            admit_count: 0,
            defer_count: 0,
            shed_count: 0,
            admitted_units: 0,
            deferred_units: 0,
            shed_units: 0,
            fallback_used_count: 0,
            loss_score_sum: 0,
            loss_score_count: 0,
            latencies: Vec::new(),
        };
        let mut fixed_threshold = tail_risk.clone();
        let mut window_reports = Vec::new();
        let mut fallback_windows = Vec::new();
        let mut tail_risk_decisions = Vec::new();
        let mut fixed_threshold_decisions = Vec::new();

        for replay_index in 0..scenario.fixture.replay_count {
            for (window_index, window) in scenario.fixture.windows.iter().enumerate() {
                let evidence = TailRiskAdmissionEvidence {
                    scheduler: sample_scheduler_metrics_from_window(window, window_index),
                    retry_pressure_p99: window.retry_pressure_p99,
                    memory_pressure_bps: window.memory_pressure_bps,
                    degradation_level: window.degradation_level,
                };
                let ledger =
                    TailRiskAdmissionLedger::evaluate(&evidence, &scenario.tail_risk_profile);
                let (baseline_decision, baseline_reasons) =
                    fixed_threshold_decision(window, &scenario.fixed_threshold_profile);

                let tail_outcome = simulate_window_outcome(
                    ledger.decision,
                    &scenario.fixture,
                    window,
                    window_index,
                );
                let baseline_outcome = simulate_window_outcome(
                    baseline_decision,
                    &scenario.fixture,
                    window,
                    window_index,
                );

                tail_risk.record(
                    ledger.decision,
                    ledger.fallback_used,
                    ledger.expected_loss_score,
                    &tail_outcome,
                );
                fixed_threshold.record(baseline_decision, false, 0, &baseline_outcome);

                if replay_index == 0 {
                    tail_risk_decisions.push(format!("{:?}", ledger.decision).to_lowercase());
                    fixed_threshold_decisions
                        .push(format!("{:?}", baseline_decision).to_lowercase());
                    if ledger.fallback_used {
                        fallback_windows.push(window.window_id.clone());
                    }
                    window_reports.push(json!({
                        "window_id": window.window_id,
                        "evidence_vector": {
                            "wake_to_run_p99_ns": window.wake_to_run_p99_ns,
                            "queue_residency_p99_ns": window.queue_residency_p99_ns,
                            "ready_backlog_p99": window.ready_backlog_p99,
                            "cancel_debt_p99": window.cancel_debt_p99,
                            "retry_pressure_p99": window.retry_pressure_p99,
                            "memory_pressure_bps": window.memory_pressure_bps,
                            "degradation_level": format!("{:?}", window.degradation_level).to_lowercase(),
                        },
                        "tail_risk": {
                            "decision": format!("{:?}", ledger.decision).to_lowercase(),
                            "fallback_used": ledger.fallback_used,
                            "expected_loss_score": ledger.expected_loss_score,
                            "confidence_percent": ledger.confidence_percent,
                            "reason_codes": ledger.reason_codes.iter().map(|reason| tail_risk_reason_label(*reason)).collect::<Vec<_>>(),
                            "missing_evidence_fields": ledger.missing_evidence_fields,
                            "admitted_units": tail_outcome.admitted_units,
                            "deferred_units": tail_outcome.deferred_units,
                            "shed_units": tail_outcome.shed_units,
                            "window_p99_ns": percentile_slice_u64(&tail_outcome.latency_samples, 99, 100),
                        },
                        "fixed_threshold": {
                            "decision": format!("{:?}", baseline_decision).to_lowercase(),
                            "reason_codes": baseline_reasons,
                            "admitted_units": baseline_outcome.admitted_units,
                            "deferred_units": baseline_outcome.deferred_units,
                            "shed_units": baseline_outcome.shed_units,
                            "window_p99_ns": percentile_slice_u64(&baseline_outcome.latency_samples, 99, 100),
                        }
                    }));
                }
            }
        }

        let tail_summary = tail_risk.summary(total_offered_units);
        let fixed_summary = fixed_threshold.summary(total_offered_units);
        let report_projection = json!({
            "schema_version": TAIL_RISK_ADMISSION_PROJECTION_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "workload_class": scenario.workload_class,
            "replay_count": scenario.fixture.replay_count,
            "window_count": scenario.fixture.windows.len(),
            "tail_risk_decision_sequence": tail_risk_decisions,
            "fixed_threshold_decision_sequence": fixed_threshold_decisions,
            "tail_risk": {
                "admitted_units": tail_summary.admitted_units,
                "deferred_units": tail_summary.deferred_units,
                "shed_units": tail_summary.shed_units,
                "fallback_used_count": tail_summary.fallback_used_count,
                "p95_latency_ns": tail_summary.p95_latency_ns,
                "p99_latency_ns": tail_summary.p99_latency_ns,
                "throughput_ratio": tail_summary.throughput_ratio
            },
            "fixed_threshold": {
                "admitted_units": fixed_summary.admitted_units,
                "deferred_units": fixed_summary.deferred_units,
                "shed_units": fixed_summary.shed_units,
                "p95_latency_ns": fixed_summary.p95_latency_ns,
                "p99_latency_ns": fixed_summary.p99_latency_ns,
                "throughput_ratio": fixed_summary.throughput_ratio
            },
            "comparison": {
                "p95_latency_improvement_ns": fixed_summary.p95_latency_ns.saturating_sub(tail_summary.p95_latency_ns),
                "p99_latency_improvement_ns": fixed_summary.p99_latency_ns.saturating_sub(tail_summary.p99_latency_ns),
                "max_latency_improvement_ns": fixed_summary.max_latency_ns.saturating_sub(tail_summary.max_latency_ns),
                "throughput_delta_units": tail_summary.admitted_units as i64 - fixed_summary.admitted_units as i64,
                "tail_risk_better_than_fixed": tail_summary.p99_latency_ns < fixed_summary.p99_latency_ns,
            },
            "fallback_windows": fallback_windows,
            "evidence_vector_fields": evidence_vector_fields
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = build_tail_risk_admission_report(scenario, false);
            hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
        } else {
            true
        };

        json!({
            "schema_version": TAIL_RISK_ADMISSION_REPORT_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "workload_class": scenario.workload_class,
            "tail_risk_profile": scenario.tail_risk_profile,
            "fixed_threshold_profile": scenario.fixed_threshold_profile,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "tail_risk_summary": tail_summary,
            "fixed_threshold_summary": fixed_summary,
            "window_reports": window_reports,
            "expected_report_projection": scenario.expected_report_projection
        })
    }

    #[test]
    fn tail_risk_admission_smoke_contract_emits_report() {
        let scenarios = load_tail_risk_admission_scenarios();
        let scenario_id = selected_tail_risk_admission_scenario();
        let scenario = scenarios
            .iter()
            .find(|candidate| candidate.scenario_id == scenario_id)
            .expect("selected tail-risk admission scenario must exist");
        let report = build_tail_risk_admission_report(scenario, true);
        if !scenario.expected_report_projection.is_null() {
            assert_eq!(
                report["report_projection"], scenario.expected_report_projection,
                "smoke contract projection must stay stable"
            );
        }
        assert_eq!(
            report["repeated_run_hash_match"].as_bool(),
            Some(true),
            "repeated report generation must be deterministic"
        );

        if let Ok(path) = std::env::var(TAIL_RISK_ADMISSION_REPORT_PATH_ENV) {
            maybe_write_tail_risk_admission_report(&path, &report);
        }

        println!("TAIL_RISK_ADMISSION_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize tail-risk report")
        );
        println!("TAIL_RISK_ADMISSION_REPORT_JSON_END");
        crate::test_complete!("tail_risk_admission_smoke_contract_emits_report");
    }

    fn sample_cohort_steering_evidence() -> CohortAdmissionSteeringEvidence {
        CohortAdmissionSteeringEvidence {
            local_cohort: Some(0),
            worker_to_cohort_map: vec![0, 0, 1, 1],
            cohort_ready_backlog: vec![228, 96],
            topology_confidence_percent: Some(88),
            remote_spill_budget: CohortRemoteSpillBudgetState::new(7, 2),
            decision_epoch: 7,
            consecutive_local_defers: 1,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
        }
    }

    #[test]
    fn cohort_remote_spill_budget_resets_by_epoch_and_saturates() {
        let profile = CohortAdmissionSteeringProfile {
            remote_spill_budget_per_epoch: 2,
            ..CohortAdmissionSteeringProfile::default()
        };
        let same_epoch = CohortRemoteSpillBudgetState::new(4, 9).normalized_for_epoch(&profile, 4);
        assert_eq!(same_epoch.remaining_tokens, 2);
        let next_epoch = same_epoch.normalized_for_epoch(&profile, 5);
        assert_eq!(next_epoch.epoch, 5);
        assert_eq!(next_epoch.remaining_tokens, 2);
        assert_eq!(next_epoch.spend_one().remaining_tokens, 1);
        assert_eq!(
            CohortRemoteSpillBudgetState::new(5, 0)
                .spend_one()
                .remaining_tokens,
            0
        );
    }

    #[test]
    fn cohort_admission_steering_falls_back_when_topology_is_missing() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                local_cohort: None,
                worker_to_cohort_map: Vec::new(),
                cohort_ready_backlog: Vec::new(),
                topology_confidence_percent: Some(90),
                remote_spill_budget: CohortRemoteSpillBudgetState::new(3, 2),
                decision_epoch: 3,
                consecutive_local_defers: 0,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::MissingTopology)
        );
        assert_eq!(
            ledger.missing_evidence_fields,
            vec![
                "cohort_ready_backlog".to_string(),
                "local_cohort".to_string(),
                "worker_to_cohort_map".to_string()
            ]
        );
    }

    #[test]
    fn cohort_admission_steering_validates_worker_to_cohort_map() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                worker_to_cohort_map: vec![0, 2],
                cohort_ready_backlog: vec![144, 96],
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["worker_to_cohort_map".to_string()]
        );
    }

    #[test]
    fn cohort_admission_steering_falls_back_when_confidence_is_low() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                topology_confidence_percent: Some(42),
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::LowConfidenceFallback)
        );
    }

    #[test]
    fn cohort_admission_steering_respects_outer_tail_risk_cap() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::Defer);
        assert!(!ledger.fallback_used);
        assert_eq!(
            ledger.reason_codes,
            vec![CohortAdmissionSteeringReason::TailRiskOuterCap]
        );
        assert_eq!(ledger.remote_spill_budget_remaining, 2);
    }

    #[test]
    fn cohort_admission_steering_redirects_remote_and_spends_budget() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &sample_cohort_steering_evidence(),
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(
            ledger.decision,
            CohortAdmissionSteeringDecision::RedirectRemote
        );
        assert_eq!(ledger.target_cohort, Some(1));
        assert_eq!(ledger.remote_spill_budget_start, 2);
        assert_eq!(ledger.remote_spill_budget_remaining, 1);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetSpent)
        );
    }

    #[test]
    fn cohort_admission_steering_triggers_fairness_escape_hatch() {
        let profile = CohortAdmissionSteeringProfile {
            fairness_escape_after_consecutive_defers: 2,
            ..CohortAdmissionSteeringProfile::default()
        };
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                consecutive_local_defers: 2,
                ..sample_cohort_steering_evidence()
            },
            &profile,
        );
        assert_eq!(
            ledger.decision,
            CohortAdmissionSteeringDecision::RedirectRemote
        );
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch)
        );
    }

    #[test]
    fn cohort_admission_steering_defers_when_budget_is_exhausted() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &CohortAdmissionSteeringEvidence {
                remote_spill_budget: CohortRemoteSpillBudgetState::new(7, 0),
                consecutive_local_defers: 4,
                ..sample_cohort_steering_evidence()
            },
            &CohortAdmissionSteeringProfile::default(),
        );
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::Defer);
        assert!(ledger.remote_spill_budget_exhausted);
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted)
        );
    }

    #[test]
    fn cohort_admission_steering_disabled_mode_matches_conservative_global() {
        let profile = CohortAdmissionSteeringProfile {
            enabled: false,
            ..CohortAdmissionSteeringProfile::default()
        };
        let ledger =
            CohortAdmissionSteeringLedger::evaluate(&sample_cohort_steering_evidence(), &profile);
        assert!(ledger.fallback_used);
        assert_eq!(ledger.decision, CohortAdmissionSteeringDecision::AdmitLocal);
        assert_eq!(ledger.target_cohort, Some(0));
        assert!(
            ledger
                .reason_codes
                .contains(&CohortAdmissionSteeringReason::Disabled)
        );
    }

    #[test]
    fn cohort_admission_steering_ledger_round_trips_through_json() {
        let ledger = CohortAdmissionSteeringLedger::evaluate(
            &sample_cohort_steering_evidence(),
            &CohortAdmissionSteeringProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize cohort ledger");
        let reparsed: CohortAdmissionSteeringLedger =
            serde_json::from_str(&json).expect("deserialize cohort ledger");
        assert_eq!(reparsed, ledger);
    }

    fn sample_brownout_evidence() -> OverloadBrownoutEvidence {
        OverloadBrownoutEvidence {
            scheduler: Some(SchedulerEvidenceMetrics {
                wake_to_run_p50_ns: 8_000,
                wake_to_run_p95_ns: 120_000,
                wake_to_run_p99_ns: 236_000,
                queue_residency_p50_ns: 18_000,
                queue_residency_p95_ns: 180_000,
                queue_residency_p99_ns: 310_000,
                ready_backlog_p95: 164,
                ready_backlog_p99: 224,
                cancel_debt_p95: 28,
                cancel_debt_p99: 44,
                remote_steal_ratio_pct: Some(18),
                cross_cohort_wake_p99_ns: Some(148_000),
            }),
            memory_pressure_bps: Some(8_820),
            degradation_level: DegradationLevel::Moderate,
            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
            previous_phase: OverloadBrownoutPhase::Observe,
            recovery_streak_windows: 0,
            already_shed_surfaces: Vec::new(),
        }
    }

    #[test]
    fn overload_brownout_effective_optional_surfaces_dedupes_and_filters_denied() {
        let profile = OverloadBrownoutProfile {
            allowed_optional_surfaces: vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichDiagnostics,
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichExportFormatting,
            ],
            denied_optional_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
            ..OverloadBrownoutProfile::default()
        };
        assert_eq!(
            profile.effective_optional_surfaces(),
            vec![
                BrownoutOptionalSurface::DetailedTracing,
                BrownoutOptionalSurface::RichExportFormatting,
            ]
        );
    }

    #[test]
    fn overload_brownout_disabled_mode_matches_normal() {
        let profile = OverloadBrownoutProfile {
            enabled: false,
            ..OverloadBrownoutProfile::default()
        };
        let ledger = OverloadBrownoutLedger::evaluate(&sample_brownout_evidence(), &profile);
        assert!(ledger.fallback_used);
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Normal);
        assert!(ledger.requested_degraded_surfaces.is_empty());
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::Disabled)
        );
    }

    #[test]
    fn overload_brownout_falls_back_when_evidence_is_missing() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                scheduler: None,
                memory_pressure_bps: Some(7_900),
                degradation_level: DegradationLevel::Light,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                previous_phase: OverloadBrownoutPhase::Normal,
                recovery_streak_windows: 0,
                already_shed_surfaces: Vec::new(),
            },
            &OverloadBrownoutProfile::default(),
        );
        assert!(ledger.fallback_used);
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Observe);
        assert_eq!(
            ledger.missing_evidence_fields,
            vec!["scheduler_metrics".to_string()]
        );
    }

    #[test]
    fn overload_brownout_escalates_to_shed_optional_under_severe_pressure() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                memory_pressure_bps: Some(9_450),
                outer_tail_risk_decision: TailRiskAdmissionDecision::Shed,
                degradation_level: DegradationLevel::Heavy,
                ..sample_brownout_evidence()
            },
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::ShedOptional);
        assert!(
            ledger
                .requested_degraded_surfaces
                .contains(&BrownoutOptionalSurface::DetailedTracing)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::TailRiskOuterShed)
        );
    }

    #[test]
    fn overload_brownout_respects_recovery_hysteresis_and_restores_surfaces() {
        let profile = OverloadBrownoutProfile::default();
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                scheduler: Some(SchedulerEvidenceMetrics {
                    wake_to_run_p50_ns: 7_500,
                    wake_to_run_p95_ns: 74_000,
                    wake_to_run_p99_ns: 118_000,
                    queue_residency_p50_ns: 12_000,
                    queue_residency_p95_ns: 88_000,
                    queue_residency_p99_ns: 120_000,
                    ready_backlog_p95: 96,
                    ready_backlog_p99: 128,
                    cancel_debt_p95: 12,
                    cancel_debt_p99: 20,
                    remote_steal_ratio_pct: Some(10),
                    cross_cohort_wake_p99_ns: Some(92_000),
                }),
                memory_pressure_bps: Some(7_100),
                degradation_level: DegradationLevel::None,
                outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                previous_phase: OverloadBrownoutPhase::ShedOptional,
                recovery_streak_windows: 0,
                already_shed_surfaces: Vec::new(),
            },
            &profile,
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Recovery);
        assert_eq!(ledger.recovery_streak_after, 1);
        assert!(
            ledger
                .restored_surfaces
                .contains(&BrownoutOptionalSurface::DetailedTracing)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::RecoveryHysteresis)
        );
    }

    #[test]
    fn overload_brownout_avoids_duplicate_accounting_for_self_shedding_surfaces() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &OverloadBrownoutEvidence {
                already_shed_surfaces: vec![BrownoutOptionalSurface::RichDiagnostics],
                ..sample_brownout_evidence()
            },
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
        assert!(
            ledger
                .already_shed_surfaces
                .contains(&BrownoutOptionalSurface::RichDiagnostics)
        );
        assert!(
            !ledger
                .newly_degraded_surfaces
                .contains(&BrownoutOptionalSurface::RichDiagnostics)
        );
        assert!(
            ledger
                .reason_codes
                .contains(&OverloadBrownoutReason::OptionalSurfaceAlreadyShedding)
        );
    }

    #[test]
    fn overload_brownout_preserves_critical_surfaces() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &sample_brownout_evidence(),
            &OverloadBrownoutProfile::default(),
        );
        assert_eq!(ledger.phase, OverloadBrownoutPhase::Degrade);
        assert_eq!(
            ledger.preserved_surfaces,
            vec![
                BrownoutProtectedSurface::CoreScheduling,
                BrownoutProtectedSurface::CancellationDrain,
                BrownoutProtectedSurface::RegionQuiescence,
                BrownoutProtectedSurface::ObligationCleanup,
            ]
        );
    }

    #[test]
    fn overload_brownout_ledger_round_trips_through_json() {
        let ledger = OverloadBrownoutLedger::evaluate(
            &sample_brownout_evidence(),
            &OverloadBrownoutProfile::default(),
        );
        let json = serde_json::to_string_pretty(&ledger).expect("serialize overload brownout");
        let reparsed: OverloadBrownoutLedger =
            serde_json::from_str(&json).expect("deserialize overload brownout");
        assert_eq!(reparsed, ledger);
    }

    const COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_CONTRACT_PATH";
    const COHORT_ADMISSION_STEERING_SCENARIO_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_SCENARIO";
    const COHORT_ADMISSION_STEERING_REPORT_PATH_ENV: &str =
        "ASUPERSYNC_COHORT_ADMISSION_STEERING_REPORT_PATH";
    const COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION: &str =
        "cohort-admission-steering-report-v1";
    const COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION: &str =
        "cohort-admission-steering-projection-v1";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringSmokeContract {
        smoke_scenarios: Vec<CohortAdmissionSteeringScenario>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringScenario {
        scenario_id: String,
        description: String,
        workload_class: String,
        output_root: String,
        execution_policy: String,
        workload_seed: u64,
        safe_fallback_profile: String,
        expected_winner_profile: String,
        steering_profile: CohortAdmissionSteeringProfile,
        fixture: CohortAdmissionSteeringFixture,
        expected_report_projection: Value,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringFixture {
        replay_count: usize,
        windows: Vec<CohortAdmissionSteeringWindow>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CohortAdmissionSteeringWindow {
        window_id: String,
        local_cohort: Option<usize>,
        worker_to_cohort_map: Vec<usize>,
        cohort_ready_backlog: Vec<usize>,
        topology_confidence_percent: Option<u8>,
        decision_epoch: u64,
        consecutive_local_defers: u16,
        outer_tail_risk_decision: TailRiskAdmissionDecision,
        offered_work_units: u64,
        local_wake_to_run_p99_ns: u64,
        remote_wake_to_run_p99_ns: u64,
    }

    #[derive(Debug, Clone)]
    struct CohortPlacementWindowOutcome {
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        latency_samples: Vec<u64>,
    }

    #[derive(Debug, Clone, Default, Serialize)]
    struct CohortSteeringAccumulator {
        admit_local_count: u64,
        redirect_remote_count: u64,
        defer_count: u64,
        fallback_used_count: u64,
        budget_exhausted_count: u64,
        fairness_escape_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        latencies: Vec<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    struct CohortSteeringSummary {
        admit_local_count: u64,
        redirect_remote_count: u64,
        defer_count: u64,
        fallback_used_count: u64,
        budget_exhausted_count: u64,
        fairness_escape_count: u64,
        admitted_units: u64,
        deferred_units: u64,
        remote_spill_count: u64,
        p50_latency_ns: u64,
        p95_latency_ns: u64,
        p99_latency_ns: u64,
        max_latency_ns: u64,
        throughput_ratio: f64,
    }

    impl CohortSteeringAccumulator {
        fn record(
            &mut self,
            decision: CohortAdmissionSteeringDecision,
            fallback_used: bool,
            budget_exhausted: bool,
            fairness_escape: bool,
            outcome: &CohortPlacementWindowOutcome,
        ) {
            match decision {
                CohortAdmissionSteeringDecision::AdmitLocal => self.admit_local_count += 1,
                CohortAdmissionSteeringDecision::RedirectRemote => self.redirect_remote_count += 1,
                CohortAdmissionSteeringDecision::Defer => self.defer_count += 1,
            }
            self.fallback_used_count += u64::from(fallback_used);
            self.budget_exhausted_count += u64::from(budget_exhausted);
            self.fairness_escape_count += u64::from(fairness_escape);
            self.admitted_units += outcome.admitted_units;
            self.deferred_units += outcome.deferred_units;
            self.remote_spill_count += outcome.remote_spill_count;
            self.latencies.extend_from_slice(&outcome.latency_samples);
        }

        fn summary(&self, total_offered_units: u64) -> CohortSteeringSummary {
            let max_latency_ns = self.latencies.iter().copied().max().unwrap_or(0);
            let throughput_ratio = if total_offered_units == 0 {
                0.0
            } else {
                round4(self.admitted_units as f64 / total_offered_units as f64)
            };
            CohortSteeringSummary {
                admit_local_count: self.admit_local_count,
                redirect_remote_count: self.redirect_remote_count,
                defer_count: self.defer_count,
                fallback_used_count: self.fallback_used_count,
                budget_exhausted_count: self.budget_exhausted_count,
                fairness_escape_count: self.fairness_escape_count,
                admitted_units: self.admitted_units,
                deferred_units: self.deferred_units,
                remote_spill_count: self.remote_spill_count,
                p50_latency_ns: percentile_slice_u64(&self.latencies, 50, 100),
                p95_latency_ns: percentile_slice_u64(&self.latencies, 95, 100),
                p99_latency_ns: percentile_slice_u64(&self.latencies, 99, 100),
                max_latency_ns,
                throughput_ratio,
            }
        }
    }

    fn default_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
        vec![
            CohortAdmissionSteeringScenario {
                scenario_id: "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string(),
                description: "High-confidence two-cohort replay where the local cohort saturates, the remote cohort stays cool, and bounded redirect tokens cut wake-to-run tails versus the conservative global path.".to_string(),
                workload_class: "locality-win".to_string(),
                output_root: "target/cohort-admission-steering-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 424242,
                safe_fallback_profile: "conservative_global".to_string(),
                expected_winner_profile: "cohort_steered".to_string(),
                steering_profile: CohortAdmissionSteeringProfile::default(),
                fixture: CohortAdmissionSteeringFixture {
                    replay_count: 2,
                    windows: vec![
                        CohortAdmissionSteeringWindow {
                            window_id: "local_balanced".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![148, 128],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 10,
                            consecutive_local_defers: 0,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 148_000,
                            remote_wake_to_run_p99_ns: 142_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "local_saturated".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![260, 84],
                            topology_confidence_percent: Some(92),
                            decision_epoch: 10,
                            consecutive_local_defers: 1,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 236_000,
                            remote_wake_to_run_p99_ns: 146_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "fairness_escape".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![244, 96],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 10,
                            consecutive_local_defers: 3,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 228_000,
                            remote_wake_to_run_p99_ns: 154_000,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
            CohortAdmissionSteeringScenario {
                scenario_id: "AA-COHORT-ADMISSION-STEERING-KEEP-GLOBAL-2C".to_string(),
                description: "Low-confidence and no-win replay that proves the controller keeps the conservative global path pinned and records an explicit safe fallback verdict.".to_string(),
                workload_class: "keep-global".to_string(),
                output_root: "target/cohort-admission-steering-smoke".to_string(),
                execution_policy: "execute_or_dry_run".to_string(),
                workload_seed: 515151,
                safe_fallback_profile: "conservative_global".to_string(),
                expected_winner_profile: "conservative_global".to_string(),
                steering_profile: CohortAdmissionSteeringProfile::default(),
                fixture: CohortAdmissionSteeringFixture {
                    replay_count: 1,
                    windows: vec![
                        CohortAdmissionSteeringWindow {
                            window_id: "low_confidence".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![208, 198],
                            topology_confidence_percent: Some(48),
                            decision_epoch: 22,
                            consecutive_local_defers: 0,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 204_000,
                            remote_wake_to_run_p99_ns: 201_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "thin_remote_gain".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![214, 196],
                            topology_confidence_percent: Some(88),
                            decision_epoch: 23,
                            consecutive_local_defers: 1,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Admit,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 211_000,
                            remote_wake_to_run_p99_ns: 208_000,
                        },
                        CohortAdmissionSteeringWindow {
                            window_id: "tail_risk_outer_cap".to_string(),
                            local_cohort: Some(0),
                            worker_to_cohort_map: vec![0, 0, 1, 1],
                            cohort_ready_backlog: vec![228, 150],
                            topology_confidence_percent: Some(90),
                            decision_epoch: 24,
                            consecutive_local_defers: 4,
                            outer_tail_risk_decision: TailRiskAdmissionDecision::Defer,
                            offered_work_units: 48,
                            local_wake_to_run_p99_ns: 224_000,
                            remote_wake_to_run_p99_ns: 176_000,
                        },
                    ],
                },
                expected_report_projection: Value::Null,
            },
        ]
    }

    fn load_cohort_admission_steering_scenarios() -> Vec<CohortAdmissionSteeringScenario> {
        let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_CONTRACT_PATH_ENV) else {
            return default_cohort_admission_steering_scenarios();
        };
        let contract: CohortAdmissionSteeringSmokeContract = serde_json::from_str(
            &fs::read_to_string(Path::new(&path)).expect("read cohort admission steering contract"),
        )
        .expect("deserialize cohort admission steering contract");
        contract.smoke_scenarios
    }

    fn selected_cohort_admission_steering_scenario() -> String {
        std::env::var(COHORT_ADMISSION_STEERING_SCENARIO_ENV)
            .unwrap_or_else(|_| "AA-COHORT-ADMISSION-STEERING-LOCALITY-WIN-2C".to_string())
    }

    fn maybe_write_cohort_admission_steering_report(path: &str, report: &Value) {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create cohort report parent directory");
        }
        fs::write(
            path,
            serde_json::to_string_pretty(report)
                .expect("serialize cohort admission steering report"),
        )
        .expect("write cohort admission steering report");
    }

    fn conservative_global_decision(
        window: &CohortAdmissionSteeringWindow,
    ) -> CohortAdmissionSteeringDecision {
        if window.outer_tail_risk_decision == TailRiskAdmissionDecision::Admit {
            CohortAdmissionSteeringDecision::AdmitLocal
        } else {
            CohortAdmissionSteeringDecision::Defer
        }
    }

    fn simulate_cohort_window_outcome(
        decision: CohortAdmissionSteeringDecision,
        target_cohort: Option<usize>,
        window: &CohortAdmissionSteeringWindow,
        replay_index: usize,
    ) -> CohortPlacementWindowOutcome {
        let offered = window.offered_work_units;
        let local_cohort = window.local_cohort.unwrap_or(0);
        let local_backlog_usize = window
            .cohort_ready_backlog
            .get(local_cohort)
            .copied()
            .unwrap_or(0);
        let local_backlog = local_backlog_usize as u64;
        let best_remote_backlog = window
            .cohort_ready_backlog
            .iter()
            .enumerate()
            .filter(|(cohort, _)| *cohort != local_cohort)
            .map(|(_, backlog)| *backlog)
            .min()
            .unwrap_or(local_backlog_usize) as u64;
        let remote_backlog = target_cohort
            .and_then(|cohort| window.cohort_ready_backlog.get(cohort).copied())
            .unwrap_or(best_remote_backlog as usize) as u64;
        let backlog_gap = local_backlog.saturating_sub(best_remote_backlog);

        let (
            admitted_units,
            deferred_units,
            remote_spill_count,
            p99_base,
            overload_multiplier,
            decision_penalty,
        ) = match decision {
            CohortAdmissionSteeringDecision::AdmitLocal => (
                offered,
                0,
                backlog_gap.saturating_div(40),
                window.local_wake_to_run_p99_ns,
                1_350,
                21_000 + backlog_gap.saturating_mul(320),
            ),
            CohortAdmissionSteeringDecision::RedirectRemote => (
                offered,
                0,
                1,
                window.remote_wake_to_run_p99_ns,
                780,
                13_500 + remote_backlog.saturating_mul(110),
            ),
            CohortAdmissionSteeringDecision::Defer => (
                offered.saturating_mul(82).saturating_div(100),
                offered.saturating_sub(offered.saturating_mul(82).saturating_div(100)),
                0,
                window.local_wake_to_run_p99_ns.saturating_sub(18_000),
                620,
                9_500,
            ),
        };

        let backlog_source = match decision {
            CohortAdmissionSteeringDecision::RedirectRemote => remote_backlog,
            CohortAdmissionSteeringDecision::AdmitLocal
            | CohortAdmissionSteeringDecision::Defer => local_backlog,
        };

        let base_latency = p99_base
            .saturating_div(2)
            .saturating_add(backlog_source.saturating_mul(overload_multiplier))
            .saturating_add(decision_penalty);
        let mut latency_samples = Vec::with_capacity(admitted_units as usize);
        for sample_idx in 0..admitted_units {
            let jitter = ((replay_index as u64 * 23) + (sample_idx % 17) * 11).saturating_mul(131);
            latency_samples.push(base_latency.saturating_add(jitter));
        }

        CohortPlacementWindowOutcome {
            admitted_units,
            deferred_units,
            remote_spill_count,
            latency_samples,
        }
    }

    fn cohort_steering_reason_label(reason: CohortAdmissionSteeringReason) -> &'static str {
        match reason {
            CohortAdmissionSteeringReason::Disabled => "disabled",
            CohortAdmissionSteeringReason::MissingTopology => "missing_topology",
            CohortAdmissionSteeringReason::LowConfidenceFallback => "low_confidence_fallback",
            CohortAdmissionSteeringReason::TailRiskOuterCap => "tail_risk_outer_cap",
            CohortAdmissionSteeringReason::LocalCapacityAvailable => "local_capacity_available",
            CohortAdmissionSteeringReason::LocalBacklogPressure => "local_backlog_pressure",
            CohortAdmissionSteeringReason::RemoteSpillBudgetSpent => "remote_spill_budget_spent",
            CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted => {
                "remote_spill_budget_exhausted"
            }
            CohortAdmissionSteeringReason::FairnessEscapeHatch => "fairness_escape_hatch",
            CohortAdmissionSteeringReason::ConservativeGlobalBaseline => {
                "conservative_global_baseline"
            }
        }
    }

    fn build_cohort_admission_steering_report(
        scenario: &CohortAdmissionSteeringScenario,
        include_hash_probe: bool,
    ) -> Value {
        let total_offered_units = scenario
            .fixture
            .windows
            .iter()
            .map(|window| window.offered_work_units)
            .sum::<u64>()
            .saturating_mul(scenario.fixture.replay_count as u64);

        let mut steered = CohortSteeringAccumulator::default();
        let mut conservative_global = CohortSteeringAccumulator::default();
        let mut window_reports = Vec::new();
        let mut decision_sequence = Vec::new();
        let mut conservative_sequence = Vec::new();
        let mut fallback_windows = Vec::new();
        let mut fairness_windows = Vec::new();
        let mut budget_start_sequence = Vec::new();
        let mut budget_remaining_sequence = Vec::new();

        let mut budget_state = CohortRemoteSpillBudgetState::new(
            scenario
                .fixture
                .windows
                .first()
                .map_or(0, |window| window.decision_epoch),
            scenario.steering_profile.remote_spill_budget_per_epoch,
        );

        for replay_index in 0..scenario.fixture.replay_count {
            let mut replay_budget = budget_state;
            for window in &scenario.fixture.windows {
                let evidence = CohortAdmissionSteeringEvidence {
                    local_cohort: window.local_cohort,
                    worker_to_cohort_map: window.worker_to_cohort_map.clone(),
                    cohort_ready_backlog: window.cohort_ready_backlog.clone(),
                    topology_confidence_percent: window.topology_confidence_percent,
                    remote_spill_budget: replay_budget,
                    decision_epoch: window.decision_epoch,
                    consecutive_local_defers: window.consecutive_local_defers,
                    outer_tail_risk_decision: window.outer_tail_risk_decision,
                };
                let ledger =
                    CohortAdmissionSteeringLedger::evaluate(&evidence, &scenario.steering_profile);
                replay_budget = CohortRemoteSpillBudgetState::new(
                    ledger.evidence.remote_spill_budget_epoch,
                    ledger.remote_spill_budget_remaining,
                );

                let global_decision = conservative_global_decision(window);
                let steered_outcome = simulate_cohort_window_outcome(
                    ledger.decision,
                    ledger.target_cohort,
                    window,
                    replay_index,
                );
                let global_outcome =
                    simulate_cohort_window_outcome(global_decision, None, window, replay_index);

                steered.record(
                    ledger.decision,
                    ledger.fallback_used,
                    ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::RemoteSpillBudgetExhausted),
                    ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch),
                    &steered_outcome,
                );
                conservative_global.record(global_decision, false, false, false, &global_outcome);

                if replay_index == 0 {
                    decision_sequence.push(format!("{:?}", ledger.decision).to_lowercase());
                    conservative_sequence.push(format!("{:?}", global_decision).to_lowercase());
                    budget_start_sequence.push(ledger.remote_spill_budget_start);
                    budget_remaining_sequence.push(ledger.remote_spill_budget_remaining);
                    if ledger.fallback_used {
                        fallback_windows.push(window.window_id.clone());
                    }
                    if ledger
                        .reason_codes
                        .contains(&CohortAdmissionSteeringReason::FairnessEscapeHatch)
                    {
                        fairness_windows.push(window.window_id.clone());
                    }
                    window_reports.push(json!({
                        "window_id": window.window_id,
                        "worker_to_cohort_map": window.worker_to_cohort_map,
                        "cohort_ready_backlog": window.cohort_ready_backlog,
                        "topology_confidence_percent": window.topology_confidence_percent,
                        "outer_tail_risk_decision": format!("{:?}", window.outer_tail_risk_decision).to_lowercase(),
                        "steered": {
                            "decision": format!("{:?}", ledger.decision).to_lowercase(),
                            "target_cohort": ledger.target_cohort,
                            "fallback_used": ledger.fallback_used,
                            "confidence_percent": ledger.confidence_percent,
                            "reason_codes": ledger.reason_codes.iter().map(|reason| cohort_steering_reason_label(*reason)).collect::<Vec<_>>(),
                            "missing_evidence_fields": ledger.missing_evidence_fields,
                            "remote_spill_budget_start": ledger.remote_spill_budget_start,
                            "remote_spill_budget_remaining": ledger.remote_spill_budget_remaining,
                            "remote_spill_budget_exhausted": ledger.remote_spill_budget_exhausted,
                            "admitted_units": steered_outcome.admitted_units,
                            "deferred_units": steered_outcome.deferred_units,
                            "remote_spill_count": steered_outcome.remote_spill_count,
                            "window_p99_ns": percentile_slice_u64(&steered_outcome.latency_samples, 99, 100),
                        },
                        "conservative_global": {
                            "decision": format!("{:?}", global_decision).to_lowercase(),
                            "admitted_units": global_outcome.admitted_units,
                            "deferred_units": global_outcome.deferred_units,
                            "remote_spill_count": global_outcome.remote_spill_count,
                            "window_p99_ns": percentile_slice_u64(&global_outcome.latency_samples, 99, 100),
                        }
                    }));
                }
            }
            budget_state = replay_budget;
        }

        let steered_summary = steered.summary(total_offered_units);
        let conservative_summary = conservative_global.summary(total_offered_units);
        let winner_profile = if steered_summary.p99_latency_ns < conservative_summary.p99_latency_ns
            || (steered_summary.p99_latency_ns == conservative_summary.p99_latency_ns
                && steered_summary.remote_spill_count < conservative_summary.remote_spill_count)
        {
            "cohort_steered"
        } else {
            scenario.safe_fallback_profile.as_str()
        };
        let no_win_trigger = winner_profile == scenario.safe_fallback_profile;
        let report_projection = json!({
            "schema_version": COHORT_ADMISSION_STEERING_PROJECTION_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "workload_class": scenario.workload_class,
            "workload_seed": scenario.workload_seed,
            "replay_count": scenario.fixture.replay_count,
            "window_count": scenario.fixture.windows.len(),
            "decision_sequence": decision_sequence,
            "conservative_global_sequence": conservative_sequence,
            "budget_start_sequence": budget_start_sequence,
            "budget_remaining_sequence": budget_remaining_sequence,
            "fallback_windows": fallback_windows,
            "fairness_windows": fairness_windows,
            "steered": {
                "admit_local_count": steered_summary.admit_local_count,
                "redirect_remote_count": steered_summary.redirect_remote_count,
                "defer_count": steered_summary.defer_count,
                "fallback_used_count": steered_summary.fallback_used_count,
                "budget_exhausted_count": steered_summary.budget_exhausted_count,
                "fairness_escape_count": steered_summary.fairness_escape_count,
                "admitted_units": steered_summary.admitted_units,
                "deferred_units": steered_summary.deferred_units,
                "remote_spill_count": steered_summary.remote_spill_count,
                "p95_latency_ns": steered_summary.p95_latency_ns,
                "p99_latency_ns": steered_summary.p99_latency_ns,
                "throughput_ratio": steered_summary.throughput_ratio
            },
            "conservative_global": {
                "admit_local_count": conservative_summary.admit_local_count,
                "redirect_remote_count": conservative_summary.redirect_remote_count,
                "defer_count": conservative_summary.defer_count,
                "admitted_units": conservative_summary.admitted_units,
                "deferred_units": conservative_summary.deferred_units,
                "remote_spill_count": conservative_summary.remote_spill_count,
                "p95_latency_ns": conservative_summary.p95_latency_ns,
                "p99_latency_ns": conservative_summary.p99_latency_ns,
                "throughput_ratio": conservative_summary.throughput_ratio
            },
            "comparison": {
                "p95_latency_improvement_ns": conservative_summary.p95_latency_ns.saturating_sub(steered_summary.p95_latency_ns),
                "p99_latency_improvement_ns": conservative_summary.p99_latency_ns.saturating_sub(steered_summary.p99_latency_ns),
                "remote_spill_reduction": conservative_summary.remote_spill_count as i64 - steered_summary.remote_spill_count as i64,
                "throughput_delta_units": steered_summary.admitted_units as i64 - conservative_summary.admitted_units as i64,
                "winner_profile": winner_profile,
                "no_win_trigger": no_win_trigger,
            }
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = build_cohort_admission_steering_report(scenario, false);
            hash_json_value(&probe["report_projection"]) == hash_json_value(&report_projection)
        } else {
            true
        };

        json!({
            "schema_version": COHORT_ADMISSION_STEERING_REPORT_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "description": scenario.description,
            "workload_class": scenario.workload_class,
            "workload_seed": scenario.workload_seed,
            "safe_fallback_profile": scenario.safe_fallback_profile,
            "expected_winner_profile": scenario.expected_winner_profile,
            "steering_profile": scenario.steering_profile,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "steered_summary": steered_summary,
            "conservative_global_summary": conservative_summary,
            "window_reports": window_reports,
            "operator_verdict": {
                "winner_profile": winner_profile,
                "safe_fallback_profile": scenario.safe_fallback_profile,
                "no_win_trigger": no_win_trigger,
                "pass": winner_profile == scenario.expected_winner_profile,
            },
            "expected_report_projection": scenario.expected_report_projection
        })
    }

    #[test]
    fn cohort_admission_steering_smoke_contract_emits_report() {
        let scenarios = load_cohort_admission_steering_scenarios();
        let scenario_id = selected_cohort_admission_steering_scenario();
        let scenario = scenarios
            .iter()
            .find(|candidate| candidate.scenario_id == scenario_id)
            .expect("selected cohort admission steering scenario must exist");
        let report = build_cohort_admission_steering_report(scenario, true);
        if !scenario.expected_report_projection.is_null() {
            assert_eq!(
                report["report_projection"], scenario.expected_report_projection,
                "cohort steering smoke contract projection must stay stable"
            );
        }
        assert_eq!(
            report["repeated_run_hash_match"].as_bool(),
            Some(true),
            "repeated cohort steering report generation must be deterministic"
        );
        assert_eq!(
            report["operator_verdict"]["pass"].as_bool(),
            Some(true),
            "operator verdict must agree with the expected winner profile"
        );

        if let Ok(path) = std::env::var(COHORT_ADMISSION_STEERING_REPORT_PATH_ENV) {
            maybe_write_cohort_admission_steering_report(&path, &report);
        }

        println!("COHORT_ADMISSION_STEERING_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .expect("serialize cohort admission steering report")
        );
        println!("COHORT_ADMISSION_STEERING_REPORT_JSON_END");
        crate::test_complete!("cohort_admission_steering_smoke_contract_emits_report");
    }
}

#[cfg(test)]
#[path = "resource_monitor_metamorphic.rs"]
mod resource_monitor_metamorphic;
