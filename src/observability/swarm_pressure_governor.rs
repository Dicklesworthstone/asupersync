//! Swarm-aware admission control and resource envelope management.
//!
//! This module implements production-ready swarm pressure governance by combining
//! the existing pressure governor with resource monitoring and cross-runtime
//! coordination. It provides:
//!
//! - **Admission Control**: Enforced region creation throttling
//! - **Resource Envelopes**: Budget tracking and enforcement
//! - **Backpressure Propagation**: Cross-component pressure signaling
//! - **Swarm Coordination**: Multi-runtime pressure awareness
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │ Region Creation │───▶│ SwarmPressure    │───▶│ ResourceEnvelope│
//! │ Request         │    │ Governor         │    │ Enforcement     │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//!                               │
//!                               ▼
//!                        ┌──────────────────┐
//!                        │ Admission        │
//!                        │ Decision         │
//!                        └──────────────────┘
//! ```
//!
//! # Integration
//!
//! Integrates with existing runtime components:
//! - Builds on `PressureGovernor` for internal runtime pressure
//! - Uses `ResourceMonitor` for system-level resource tracking
//! - Enforces decisions in `RuntimeState::create_child_region()`
//! - Propagates pressure signals across swarm instances

use crate::cx::Cx;
use crate::error::Error;
use crate::observability::pressure_governor::{
    AdmissionDecision, PressureGovernor, PressureGovernorConfig, PressureSnapshot,
};
use crate::runtime::resource_monitor::{DegradationLevel, RegionPriority, ResourceMonitor};
use crate::types::{RegionId, id::next_bootstrap_region_id};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

const DEFAULT_PEER_PRESSURE_BACKPRESSURE_THRESHOLD: f64 = 0.80;
const DEFAULT_WORKLOAD_FEEDBACK_BACKPRESSURE_THRESHOLD: f64 = 0.80;
const DEFAULT_WORKLOAD_LEASE_STARVATION_AGING_STEP: Duration = Duration::from_secs(5 * 60);
const FOURTH_WAVE_GOVERNOR_POLICY_VERSION: &str = "fourth-wave-governor-policy-v1";
const FOURTH_WAVE_PRESSURE_SNAPSHOT_SCHEMA_VERSION: &str =
    "asupersync.fourth-wave.pressure-snapshot.v1";
const FOURTH_WAVE_DECISION_RECEIPT_SCHEMA_VERSION: &str =
    "asupersync.fourth-wave.governor-decision-receipt.v1";
const FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS: u64 = 900;
const FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS: u16 = 9_000;

/// Errors specific to swarm pressure governance.
#[derive(Debug, Error)]
pub enum SwarmPressureError {
    /// Resource envelope budget exceeded.
    #[error("resource envelope budget exceeded: {resource} usage {current} exceeds limit {limit}")]
    EnvelopeBudgetExceeded {
        /// Budget class that exceeded its envelope.
        resource: String,
        /// Usage after applying the attempted reservation.
        current: u64,
        /// Configured maximum for the resource envelope.
        limit: u64,
    },

    /// Swarm coordination failed.
    #[error("swarm coordination error: {reason}")]
    SwarmCoordinationFailed {
        /// Coordination failure detail.
        reason: String,
    },

    /// Admission rejected due to pressure.
    #[error("admission rejected: {reason}")]
    AdmissionRejected {
        /// Human-readable rejection reason.
        reason: String,
    },

    /// Workload lease lifecycle operation failed.
    #[error("workload lease error: {reason}")]
    WorkloadLease {
        /// Human-readable lease failure reason.
        reason: String,
    },

    /// Underlying pressure governor error.
    #[error("pressure governor error: {0}")]
    PressureGovernor(#[from] Error),
}

/// Resource envelope tracking for a region.
#[derive(Debug, Clone)]
pub struct ResourceEnvelope {
    /// Region this envelope tracks.
    pub region_id: RegionId,
    /// Memory budget in bytes.
    pub memory_budget: u64,
    /// Current memory usage in bytes.
    pub memory_used: Arc<AtomicU64>,
    /// CPU budget in nanoseconds per second.
    pub cpu_budget_ns_per_sec: u64,
    /// Current CPU usage tracking.
    pub cpu_used_ns: Arc<AtomicU64>,
    /// IO budget in operations per second.
    pub io_budget_ops_per_sec: u64,
    /// Current IO operations count.
    pub io_ops_used: Arc<AtomicU64>,
    /// Envelope creation timestamp.
    pub created_at: Instant,
}

impl ResourceEnvelope {
    /// Creates a new resource envelope for the given region.
    pub fn new(
        region_id: RegionId,
        memory_budget: u64,
        cpu_budget_ns_per_sec: u64,
        io_budget_ops_per_sec: u64,
    ) -> Self {
        Self {
            region_id,
            memory_budget,
            memory_used: Arc::new(AtomicU64::new(0)),
            cpu_budget_ns_per_sec,
            cpu_used_ns: Arc::new(AtomicU64::new(0)),
            io_budget_ops_per_sec,
            io_ops_used: Arc::new(AtomicU64::new(0)),
            created_at: Instant::now(),
        }
    }

    /// Checks if the envelope has sufficient budget for the requested allocation.
    pub fn check_memory_budget(&self, requested: u64) -> Result<(), SwarmPressureError> {
        check_envelope_budget(
            "memory",
            self.memory_used.load(Ordering::Relaxed),
            requested,
            self.memory_budget,
        )
    }

    /// Reserves memory from the envelope budget.
    pub fn reserve_memory(&self, amount: u64) -> Result<(), SwarmPressureError> {
        reserve_envelope_budget("memory", &self.memory_used, amount, self.memory_budget)
    }

    /// Releases memory back to the envelope budget.
    pub fn release_memory(&self, amount: u64) {
        release_envelope_budget(&self.memory_used, amount);
    }

    /// Returns current memory utilization as a ratio (0.0 to 1.0+).
    pub fn memory_utilization(&self) -> f64 {
        if self.memory_budget == 0 {
            return 0.0;
        }
        let used = self.memory_used.load(Ordering::Relaxed);
        used as f64 / self.memory_budget as f64
    }

    /// Checks if the envelope has sufficient CPU budget for the requested nanoseconds.
    pub fn check_cpu_budget(&self, requested_ns: u64) -> Result<(), SwarmPressureError> {
        check_envelope_budget(
            "cpu",
            self.cpu_used_ns.load(Ordering::Relaxed),
            requested_ns,
            self.cpu_budget_ns_per_sec,
        )
    }

    /// Reserves CPU nanoseconds from this envelope's per-second budget.
    pub fn reserve_cpu(&self, amount_ns: u64) -> Result<(), SwarmPressureError> {
        reserve_envelope_budget(
            "cpu",
            &self.cpu_used_ns,
            amount_ns,
            self.cpu_budget_ns_per_sec,
        )
    }

    /// Releases CPU nanoseconds back to the envelope budget.
    pub fn release_cpu(&self, amount_ns: u64) {
        release_envelope_budget(&self.cpu_used_ns, amount_ns);
    }

    /// Returns current CPU utilization as a ratio (0.0 to 1.0+).
    pub fn cpu_utilization(&self) -> f64 {
        if self.cpu_budget_ns_per_sec == 0 {
            return 0.0;
        }
        let used = self.cpu_used_ns.load(Ordering::Relaxed);
        used as f64 / self.cpu_budget_ns_per_sec as f64
    }

    /// Checks if the envelope has sufficient IO budget for the requested operations.
    pub fn check_io_budget(&self, requested_ops: u64) -> Result<(), SwarmPressureError> {
        check_envelope_budget(
            "io",
            self.io_ops_used.load(Ordering::Relaxed),
            requested_ops,
            self.io_budget_ops_per_sec,
        )
    }

    /// Reserves IO operations from this envelope's per-second budget.
    pub fn reserve_io(&self, amount_ops: u64) -> Result<(), SwarmPressureError> {
        reserve_envelope_budget(
            "io",
            &self.io_ops_used,
            amount_ops,
            self.io_budget_ops_per_sec,
        )
    }

    /// Releases IO operations back to the envelope budget.
    pub fn release_io(&self, amount_ops: u64) {
        release_envelope_budget(&self.io_ops_used, amount_ops);
    }

    /// Returns current IO utilization as a ratio (0.0 to 1.0+).
    pub fn io_utilization(&self) -> f64 {
        if self.io_budget_ops_per_sec == 0 {
            return 0.0;
        }
        let used = self.io_ops_used.load(Ordering::Relaxed);
        used as f64 / self.io_budget_ops_per_sec as f64
    }
}

fn check_envelope_budget(
    resource: &str,
    current: u64,
    requested: u64,
    limit: u64,
) -> Result<(), SwarmPressureError> {
    let next = current.saturating_add(requested);
    if next > limit {
        return Err(SwarmPressureError::EnvelopeBudgetExceeded {
            resource: resource.to_string(),
            current: next,
            limit,
        });
    }
    Ok(())
}

fn reserve_envelope_budget(
    resource: &str,
    used: &AtomicU64,
    requested: u64,
    limit: u64,
) -> Result<(), SwarmPressureError> {
    let mut current = used.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(requested);
        if next > limit {
            return Err(SwarmPressureError::EnvelopeBudgetExceeded {
                resource: resource.to_string(),
                current: next,
                limit,
            });
        }

        match used.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn release_envelope_budget(used: &AtomicU64, amount: u64) {
    let _ = used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(amount))
    });
}

/// Configuration for swarm pressure governance.
#[derive(Debug, Clone)]
pub struct SwarmPressureGovernorConfig {
    /// Enable swarm pressure governance.
    pub enabled: bool,
    /// Underlying pressure governor configuration.
    pub pressure_config: PressureGovernorConfig,
    /// Maximum regions per swarm instance.
    pub max_regions_per_instance: usize,
    /// Default memory budget per region in bytes.
    pub default_memory_budget_bytes: u64,
    /// Default CPU budget per region in nanoseconds per second.
    pub default_cpu_budget_ns_per_sec: u64,
    /// Default IO budget per region in operations per second.
    pub default_io_budget_ops_per_sec: u64,
    /// Envelope budget enforcement enabled.
    pub envelope_enforcement_enabled: bool,
    /// Swarm coordination timeout.
    pub swarm_coordination_timeout: Duration,
    /// Maximum age for a peer pressure report to influence admission.
    pub peer_pressure_max_age: Duration,
    /// Peer pressure ratio that triggers swarm-wide backpressure rules.
    pub peer_pressure_backpressure_threshold: f64,
    /// Default lease time-to-live for workload admission leases.
    pub default_workload_lease_ttl: Duration,
    /// Maximum lease time-to-live that a workload may hold after any renewal.
    pub max_workload_lease_ttl: Duration,
    /// Maximum age for workload pressure feedback to influence admission.
    pub workload_feedback_max_age: Duration,
    /// Workload pressure ratio that triggers admission backpressure rules.
    pub workload_feedback_backpressure_threshold: f64,
    /// Maximum live workload leases allowed per proof lane; zero means unlimited.
    pub max_live_workload_leases_per_proof_lane: usize,
    /// Maximum live workload leases allowed per owner agent; zero means unlimited.
    pub max_live_workload_leases_per_owner: usize,
    /// Maximum live workload leases allowed per bead id; zero means unlimited.
    pub max_live_workload_leases_per_bead: usize,
    /// Wait time per priority-rank aging step for live workload leases.
    pub workload_lease_starvation_aging_step: Duration,
}

impl Default for SwarmPressureGovernorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pressure_config: PressureGovernorConfig::default(),
            max_regions_per_instance: 1000,
            default_memory_budget_bytes: 100 * 1024 * 1024, // 100MB per region
            default_cpu_budget_ns_per_sec: 100_000_000,     // 100ms per second
            default_io_budget_ops_per_sec: 1000,            // 1000 ops per second
            envelope_enforcement_enabled: true,
            swarm_coordination_timeout: Duration::from_millis(50),
            peer_pressure_max_age: Duration::from_secs(5),
            peer_pressure_backpressure_threshold: DEFAULT_PEER_PRESSURE_BACKPRESSURE_THRESHOLD,
            default_workload_lease_ttl: Duration::from_secs(30 * 60),
            max_workload_lease_ttl: Duration::from_secs(2 * 60 * 60),
            workload_feedback_max_age: Duration::from_secs(5),
            workload_feedback_backpressure_threshold:
                DEFAULT_WORKLOAD_FEEDBACK_BACKPRESSURE_THRESHOLD,
            max_live_workload_leases_per_proof_lane: 0,
            max_live_workload_leases_per_owner: 0,
            max_live_workload_leases_per_bead: 0,
            workload_lease_starvation_aging_step: DEFAULT_WORKLOAD_LEASE_STARVATION_AGING_STEP,
        }
    }
}

/// Pressure report received from another runtime instance in the swarm.
#[derive(Debug, Clone)]
pub struct SwarmPeerPressureReport {
    /// Stable runtime/swarm instance identifier.
    pub instance_id: String,
    /// Peer-reported overall pressure ratio.
    pub overall_pressure: f64,
    /// Peer-reported degradation band.
    pub degradation_level: DegradationLevel,
    /// Local timestamp when this report was accepted.
    pub reported_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct SwarmPeerPressureSummary {
    live_report_count: u64,
    max_overall_pressure: f64,
    max_degradation_level: DegradationLevel,
}

impl SwarmPeerPressureSummary {
    const EMPTY: Self = Self {
        live_report_count: 0,
        max_overall_pressure: 0.0,
        max_degradation_level: DegradationLevel::None,
    };

    #[must_use]
    fn has_live_pressure(self) -> bool {
        self.live_report_count > 0
    }
}

/// Explicit workload pressure axis that dominated an admission or schedule decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmWorkloadPressureSource {
    /// No live workload feedback pressure was present.
    None,
    /// Runtime queue pressure was the dominant workload feedback axis.
    Queue,
    /// Disk or artifact-cache IO pressure was the dominant workload feedback axis.
    DiskIo,
    /// RCH or remote-worker queue pressure was the dominant workload feedback axis.
    RchQueue,
    /// Validation-frontier blocker pressure was the dominant workload feedback axis.
    ValidationFrontier,
    /// Cancellation/drain tail-latency pressure was the dominant workload feedback axis.
    CancellationTail,
}

impl SwarmWorkloadPressureSource {
    /// Stable snake-case label for structured logs and proof artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Queue => "queue",
            Self::DiskIo => "disk_io",
            Self::RchQueue => "rch_queue",
            Self::ValidationFrontier => "validation_frontier",
            Self::CancellationTail => "cancellation_tail",
        }
    }
}

/// Explicit pressure feedback for one agent-swarm workload.
#[derive(Debug, Clone)]
pub struct SwarmWorkloadPressureFeedback {
    /// Workload id that this feedback describes.
    pub workload_id: String,
    /// Owner metadata for accountability and audit traces.
    pub owner: SwarmAdmissionOwner,
    /// Proof or validation lane associated with the workload.
    pub proof_lane: SwarmProofLaneKind,
    /// Runtime queue pressure ratio reported by the workload controller.
    pub queue_pressure: f64,
    /// Disk or artifact-cache IO pressure ratio.
    pub disk_io_pressure: f64,
    /// RCH or remote-worker queue pressure ratio.
    pub rch_queue_pressure: f64,
    /// Validation-frontier blocker pressure ratio.
    pub validation_frontier_pressure: f64,
    /// Cancellation/drain tail-latency pressure ratio.
    pub cancellation_tail_pressure: f64,
    /// Local timestamp when this feedback was recorded.
    pub reported_at: Instant,
}

impl SwarmWorkloadPressureFeedback {
    /// Build zero-pressure feedback for a workload.
    #[must_use]
    pub fn new(
        workload_id: impl Into<String>,
        owner: SwarmAdmissionOwner,
        proof_lane: SwarmProofLaneKind,
    ) -> Self {
        Self {
            workload_id: workload_id.into(),
            owner,
            proof_lane,
            queue_pressure: 0.0,
            disk_io_pressure: 0.0,
            rch_queue_pressure: 0.0,
            validation_frontier_pressure: 0.0,
            cancellation_tail_pressure: 0.0,
            reported_at: Instant::now(),
        }
    }

    /// Set all explicit pressure ratios.
    #[must_use]
    pub fn with_pressures(
        mut self,
        queue_pressure: f64,
        disk_io_pressure: f64,
        rch_queue_pressure: f64,
        validation_frontier_pressure: f64,
        cancellation_tail_pressure: f64,
    ) -> Self {
        self.queue_pressure = queue_pressure;
        self.disk_io_pressure = disk_io_pressure;
        self.rch_queue_pressure = rch_queue_pressure;
        self.validation_frontier_pressure = validation_frontier_pressure;
        self.cancellation_tail_pressure = cancellation_tail_pressure;
        self
    }

    /// Override the local feedback timestamp.
    #[must_use]
    pub fn with_reported_at(mut self, reported_at: Instant) -> Self {
        self.reported_at = reported_at;
        self
    }

    /// Highest reported pressure ratio across all explicit feedback dimensions.
    #[must_use]
    pub fn max_pressure(&self) -> f64 {
        self.queue_pressure
            .max(self.disk_io_pressure)
            .max(self.rch_queue_pressure)
            .max(self.validation_frontier_pressure)
            .max(self.cancellation_tail_pressure)
    }

    /// Dominant pressure axis for structured decision and schedule receipts.
    #[must_use]
    pub fn dominant_pressure_source(&self) -> SwarmWorkloadPressureSource {
        dominant_workload_pressure_source_from_values(
            self.queue_pressure,
            self.disk_io_pressure,
            self.rch_queue_pressure,
            self.validation_frontier_pressure,
            self.cancellation_tail_pressure,
        )
    }

    fn validate(&self) -> Option<String> {
        if self.workload_id.trim().is_empty() {
            return Some("workload pressure feedback workload_id must be non-empty".to_string());
        }
        if let Some(reason) = self.owner.validate() {
            return Some(reason);
        }
        for (name, pressure) in [
            ("queue_pressure", self.queue_pressure),
            ("disk_io_pressure", self.disk_io_pressure),
            ("rch_queue_pressure", self.rch_queue_pressure),
            (
                "validation_frontier_pressure",
                self.validation_frontier_pressure,
            ),
            (
                "cancellation_tail_pressure",
                self.cancellation_tail_pressure,
            ),
        ] {
            if !pressure.is_finite() || pressure < 0.0 {
                return Some(format!("{name} must be finite and non-negative"));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy)]
struct SwarmWorkloadPressureSummary {
    live_report_count: u64,
    max_queue_pressure: f64,
    max_disk_io_pressure: f64,
    max_rch_queue_pressure: f64,
    max_validation_frontier_pressure: f64,
    max_cancellation_tail_pressure: f64,
    max_overall_pressure: f64,
    dominant_pressure_source: SwarmWorkloadPressureSource,
}

impl SwarmWorkloadPressureSummary {
    const EMPTY: Self = Self {
        live_report_count: 0,
        max_queue_pressure: 0.0,
        max_disk_io_pressure: 0.0,
        max_rch_queue_pressure: 0.0,
        max_validation_frontier_pressure: 0.0,
        max_cancellation_tail_pressure: 0.0,
        max_overall_pressure: 0.0,
        dominant_pressure_source: SwarmWorkloadPressureSource::None,
    };

    #[must_use]
    fn has_live_pressure(self) -> bool {
        self.live_report_count > 0
    }
}

/// Required evidence classes for the fourth-wave governor contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FourthWaveEvidenceClass {
    /// Agent Mail and Beads workload coordination context.
    BeadMailContext,
    /// Large-host capacity or topology snapshot.
    CapacitySnapshot,
    /// Deterministic lab replay evidence.
    LabReplay,
    /// Runtime obligation pressure row.
    ObligationPressure,
    /// RCH proof-lane worker admission row.
    RchProofLane,
    /// Runtime region pressure row.
    RegionPressure,
    /// Worker and agent envelope row.
    WorkerEnvelope,
}

impl FourthWaveEvidenceClass {
    /// Stable schema label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeadMailContext => "bead_mail_context",
            Self::CapacitySnapshot => "capacity_snapshot",
            Self::LabReplay => "lab_replay",
            Self::ObligationPressure => "obligation_pressure",
            Self::RchProofLane => "rch_proof_lane",
            Self::RegionPressure => "region_pressure",
            Self::WorkerEnvelope => "worker_envelope",
        }
    }
}

const FOURTH_WAVE_REQUIRED_EVIDENCE_CLASSES: [FourthWaveEvidenceClass; 7] = [
    FourthWaveEvidenceClass::BeadMailContext,
    FourthWaveEvidenceClass::CapacitySnapshot,
    FourthWaveEvidenceClass::LabReplay,
    FourthWaveEvidenceClass::ObligationPressure,
    FourthWaveEvidenceClass::RchProofLane,
    FourthWaveEvidenceClass::RegionPressure,
    FourthWaveEvidenceClass::WorkerEnvelope,
];

/// Evidence claim quality for fourth-wave governor rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FourthWaveEvidenceClaimStatus {
    /// Coordination-only evidence; useful context but not behavior proof.
    CoordinationEvidence,
    /// Schema-only evidence.
    SchemaContract,
    /// Deterministic replay-backed evidence.
    ReplayBacked,
    /// Remote RCH proof admission or success evidence.
    RemoteProof,
    /// Remote RCH worker refusal evidence.
    RemoteRefusal,
    /// Local RCH fallback marker.
    LocalFallback,
    /// Advisory-only signal that cannot drive control without replay evidence.
    AdvisoryOnly,
}

impl FourthWaveEvidenceClaimStatus {
    /// Stable schema label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoordinationEvidence => "coordination_evidence",
            Self::SchemaContract => "schema_contract",
            Self::ReplayBacked => "replay_backed",
            Self::RemoteProof => "remote_proof",
            Self::RemoteRefusal => "remote_refusal",
            Self::LocalFallback => "local_fallback",
            Self::AdvisoryOnly => "advisory_only",
        }
    }

    #[must_use]
    const fn is_advisory_only(self) -> bool {
        matches!(self, Self::AdvisoryOnly)
    }
}

/// Snapshot parser status for fourth-wave governor inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FourthWaveInputStatus {
    /// All required snapshot sections parsed.
    Complete,
    /// Parser detected malformed or incompatible snapshot data.
    Malformed,
}

impl FourthWaveInputStatus {
    /// Stable schema label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Malformed => "malformed",
        }
    }
}

/// Workload class for the fourth-wave governor objective row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FourthWaveWorkloadClass {
    /// Required release/proof/cleanup work that must not be silently shed.
    Required,
    /// Optional work that may be browned out under pressure.
    Optional,
}

impl FourthWaveWorkloadClass {
    /// Stable schema label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

/// Configured objective row attached to a fourth-wave governor input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveGovernorObjective {
    /// Stable objective identifier.
    pub objective_id: String,
    /// Workload class evaluated by this objective.
    pub workload_class: FourthWaveWorkloadClass,
    /// Target confidence floor for evidence-driven action.
    pub target_confidence_bps: u16,
}

impl FourthWaveGovernorObjective {
    /// Build a required-work objective.
    #[must_use]
    pub fn required(objective_id: impl Into<String>, target_confidence_bps: u16) -> Self {
        Self {
            objective_id: objective_id.into(),
            workload_class: FourthWaveWorkloadClass::Required,
            target_confidence_bps,
        }
    }

    /// Build an optional-work objective.
    #[must_use]
    pub fn optional(objective_id: impl Into<String>, target_confidence_bps: u16) -> Self {
        Self {
            objective_id: objective_id.into(),
            workload_class: FourthWaveWorkloadClass::Optional,
            target_confidence_bps,
        }
    }
}

/// Normalized host capacity row for fourth-wave governor snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveHostCapacity {
    /// Stable host profile id.
    pub host_profile_id: String,
    /// Physical core count.
    pub physical_core_count: u16,
    /// Effective available parallelism.
    pub available_parallelism: u16,
    /// NUMA node count.
    pub numa_node_count: u16,
    /// Total memory in MiB.
    pub memory_total_mib: u64,
    /// Cgroup CPU quota in milliseconds.
    pub cgroup_cpu_quota_millis: u64,
}

/// Worker and agent envelope row for fourth-wave governor snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourthWaveWorkerEnvelope {
    /// Local agent slots.
    pub local_agent_slots: u16,
    /// Maximum admitted agent count.
    pub max_agent_count: u16,
    /// Currently active agent count.
    pub active_agent_count: u16,
    /// Remote RCH worker slots.
    pub remote_worker_slots: u16,
    /// Cache-warm remote workers.
    pub cache_warm_remote_workers: u16,
}

/// Core-pressure envelope row for fourth-wave governor snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourthWaveCoreEnvelope {
    /// Local core pressure in basis points.
    pub local_core_pressure_bps: u16,
    /// Remote core pressure in basis points.
    pub remote_core_pressure_bps: u16,
    /// Cores reserved for critical work.
    pub reserved_critical_cores: u16,
    /// Core pressure budget for admitting more work.
    pub admit_core_budget_bps: u16,
}

/// Memory envelope row for fourth-wave governor snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourthWaveMemoryEnvelope {
    /// Total memory in MiB.
    pub total_mib: u64,
    /// Available memory in MiB.
    pub available_mib: u64,
    /// Memory reserved for validation in MiB.
    pub reserved_validation_mib: u64,
    /// Artifact-cache memory in MiB.
    pub artifact_cache_mib: u64,
    /// Memory pressure in basis points.
    pub memory_pressure_bps: u16,
}

/// Active-region pressure row for fourth-wave governor snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourthWaveActiveRegionPressure {
    /// Number of active regions.
    pub active_region_count: u64,
    /// Region limit.
    pub region_limit: u64,
    /// Runnable queue depth.
    pub queue_depth: u64,
    /// Region pressure in basis points.
    pub region_pressure_bps: u16,
}

/// Obligation pressure row for fourth-wave governor snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourthWaveObligationPressure {
    /// Live obligation count.
    pub live_obligation_count: u64,
    /// Drain backlog.
    pub drain_backlog: u64,
    /// Suspected leak count.
    pub leak_suspect_count: u64,
    /// Obligation pressure in basis points.
    pub obligation_pressure_bps: u16,
}

/// RCH admission row for fourth-wave governor snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveRchAdmissionState {
    /// Whether this proof lane requires remote RCH execution.
    pub remote_required: bool,
    /// Whether at least one remote worker is admissible.
    pub workers_admissible: bool,
    /// Redacted selected worker id, when any.
    pub selected_worker: Option<String>,
    /// Whether any local fallback marker was detected.
    pub local_fallback_marker_detected: bool,
    /// First blocker, when worker admission failed.
    pub first_blocker: Option<String>,
}

/// Agent Mail and Beads workload context for fourth-wave governor snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourthWaveBeadMailWorkloadContext {
    /// Ready bead count.
    pub ready_beads: u64,
    /// In-progress bead count.
    pub in_progress_beads: u64,
    /// Reserved path count.
    pub reserved_path_count: u64,
    /// Ack-required message backlog.
    pub ack_required_backlog: u64,
    /// Whether the tracker is writable.
    pub tracker_writable: bool,
}

/// Lab replay metadata for fourth-wave governor snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveLabReplayMetadata {
    /// Scenario family.
    pub scenario_family: String,
    /// Deterministic scenario seed.
    pub seed: u64,
    /// Replay artifact path, when present.
    pub replay_artifact: Option<String>,
    /// Whether the snapshot is backed by deterministic replay evidence.
    pub replay_backed: bool,
}

/// One evidence row consumed by the fourth-wave governor policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveEvidenceRow {
    /// Required evidence class.
    pub source_class: FourthWaveEvidenceClass,
    /// Stable source id.
    pub source_id: String,
    /// Source schema version.
    pub source_schema_version: String,
    /// Evidence age in seconds.
    pub evidence_age_seconds: u64,
    /// Stable evidence hash.
    pub evidence_hash: String,
    /// Confidence in basis points.
    pub confidence_bps: u16,
    /// Evidence claim status.
    pub claim_status: FourthWaveEvidenceClaimStatus,
    /// Whether this row carries a local fallback marker.
    pub local_fallback_marker_detected: bool,
    /// Redacted source subject for logs.
    pub redacted_subject: String,
    /// Rejection/blocker reason, when any.
    pub rejected_reason: String,
}

impl FourthWaveEvidenceRow {
    /// Build a fresh evidence row for tests and deterministic replay fixtures.
    #[must_use]
    pub fn new(
        source_class: FourthWaveEvidenceClass,
        source_id: impl Into<String>,
        claim_status: FourthWaveEvidenceClaimStatus,
        confidence_bps: u16,
    ) -> Self {
        let source_id = source_id.into();
        Self {
            source_class,
            source_schema_version: "fourth-wave-test-schema-v1".to_string(),
            evidence_age_seconds: 0,
            evidence_hash: format!("sha256:{source_id:0<64}"),
            confidence_bps,
            claim_status,
            local_fallback_marker_detected: claim_status
                == FourthWaveEvidenceClaimStatus::LocalFallback,
            redacted_subject: format!("fourth-wave://{}", source_class.as_str()),
            rejected_reason: String::new(),
            source_id,
        }
    }

    /// Override evidence age.
    #[must_use]
    pub fn with_age_seconds(mut self, evidence_age_seconds: u64) -> Self {
        self.evidence_age_seconds = evidence_age_seconds;
        self
    }

    /// Mark this row as a local fallback marker.
    #[must_use]
    pub fn with_local_fallback_marker(mut self, rejected_reason: impl Into<String>) -> Self {
        self.local_fallback_marker_detected = true;
        self.claim_status = FourthWaveEvidenceClaimStatus::LocalFallback;
        self.rejected_reason = rejected_reason.into();
        self
    }

    /// Set the row rejection reason.
    #[must_use]
    pub fn with_rejected_reason(mut self, rejected_reason: impl Into<String>) -> Self {
        self.rejected_reason = rejected_reason.into();
        self
    }
}

/// Complete fourth-wave governor pressure snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWavePressureSnapshot {
    /// Snapshot schema version.
    pub schema_version: String,
    /// Stable snapshot id.
    pub snapshot_id: String,
    /// Parser status.
    pub input_status: FourthWaveInputStatus,
    /// Policy version.
    pub policy_version: String,
    /// Input artifact hashes.
    pub input_artifact_hashes: Vec<String>,
    /// Normalized host capacity row.
    pub normalized_host_capacity: FourthWaveHostCapacity,
    /// Worker envelope row.
    pub worker_envelope: FourthWaveWorkerEnvelope,
    /// Core envelope row.
    pub core_envelope: FourthWaveCoreEnvelope,
    /// Memory envelope row.
    pub memory_envelope: FourthWaveMemoryEnvelope,
    /// Active region pressure row.
    pub active_region_pressure: FourthWaveActiveRegionPressure,
    /// Obligation pressure row.
    pub obligation_pressure: FourthWaveObligationPressure,
    /// RCH admission row.
    pub rch_admission_state: FourthWaveRchAdmissionState,
    /// Agent Mail and Beads context row.
    pub bead_mail_workload_context: FourthWaveBeadMailWorkloadContext,
    /// Lab replay metadata.
    pub lab_replay_metadata: FourthWaveLabReplayMetadata,
    /// Evidence rows in any caller order.
    pub evidence_rows: Vec<FourthWaveEvidenceRow>,
}

/// Full input to the fourth-wave governor policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveGovernorInput {
    /// Bead id or policy owner id used in logs.
    pub bead_id: String,
    /// Scenario id used for deterministic receipts.
    pub scenario_id: String,
    /// Objective row.
    pub objective: FourthWaveGovernorObjective,
    /// Pressure snapshot.
    pub pressure_snapshot: FourthWavePressureSnapshot,
}

/// Deterministic fourth-wave governor action vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FourthWaveGovernorAction {
    /// Fresh supported evidence admits required work.
    AdmitRequiredWork,
    /// Pressure sheds optional work but does not enable a runtime bridge.
    BrownoutOptionalWork,
    /// Remote-required proof work is deferred because no remote worker is admissible.
    DeferNoRemoteWorker,
    /// Advisory-only evidence fails closed.
    FailClosedAdvisoryOnly,
    /// Local RCH fallback marker fails closed.
    FailClosedLocalRchFallback,
    /// Malformed input fails closed.
    FailClosedMalformedInput,
    /// Missing required evidence fails closed.
    FailClosedMissingEvidence,
    /// Stale evidence fails closed.
    FailClosedStaleEvidence,
}

impl FourthWaveGovernorAction {
    /// Stable schema label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdmitRequiredWork => "admit_required_work",
            Self::BrownoutOptionalWork => "brownout_optional_work",
            Self::DeferNoRemoteWorker => "defer_no_remote_worker",
            Self::FailClosedAdvisoryOnly => "fail_closed_advisory_only",
            Self::FailClosedLocalRchFallback => "fail_closed_local_rch_fallback",
            Self::FailClosedMalformedInput => "fail_closed_malformed_input",
            Self::FailClosedMissingEvidence => "fail_closed_missing_evidence",
            Self::FailClosedStaleEvidence => "fail_closed_stale_evidence",
        }
    }

    /// Whether the action fails closed before any control behavior.
    #[must_use]
    pub const fn fail_closed(self) -> bool {
        matches!(
            self,
            Self::FailClosedAdvisoryOnly
                | Self::FailClosedLocalRchFallback
                | Self::FailClosedMalformedInput
                | Self::FailClosedMissingEvidence
                | Self::FailClosedStaleEvidence
        )
    }
}

/// Deterministic fourth-wave governor rule id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FourthWaveGovernorRule {
    /// Malformed input rule.
    MalformedInput,
    /// Missing required evidence rule.
    MissingRequiredEvidence,
    /// Local RCH fallback rule.
    LocalRchFallback,
    /// Stale evidence rule.
    StaleEvidence,
    /// Advisory-only evidence rule.
    AdvisoryOnlyEvidence,
    /// Remote-required no-worker rule.
    RemoteRequiredNoWorker,
    /// Optional-work brownout rule.
    BrownoutOptionalWork,
    /// Required-work admit rule.
    AdmitRequiredWork,
}

impl FourthWaveGovernorRule {
    /// Stable rule id.
    #[must_use]
    pub const fn rule_id(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed-input",
            Self::MissingRequiredEvidence => "missing-required-evidence",
            Self::LocalRchFallback => "local-rch-fallback",
            Self::StaleEvidence => "stale-evidence",
            Self::AdvisoryOnlyEvidence => "advisory-only-evidence",
            Self::RemoteRequiredNoWorker => "remote-required-no-worker",
            Self::BrownoutOptionalWork => "brownout-optional-work",
            Self::AdmitRequiredWork => "admit-required-work",
        }
    }

    /// Stable priority from the schema contract.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::MalformedInput => 10,
            Self::MissingRequiredEvidence => 20,
            Self::LocalRchFallback => 30,
            Self::StaleEvidence => 40,
            Self::AdvisoryOnlyEvidence => 50,
            Self::RemoteRequiredNoWorker => 60,
            Self::BrownoutOptionalWork => 70,
            Self::AdmitRequiredWork => 80,
        }
    }

    /// Action selected by this rule.
    #[must_use]
    pub const fn action(self) -> FourthWaveGovernorAction {
        match self {
            Self::MalformedInput => FourthWaveGovernorAction::FailClosedMalformedInput,
            Self::MissingRequiredEvidence => FourthWaveGovernorAction::FailClosedMissingEvidence,
            Self::LocalRchFallback => FourthWaveGovernorAction::FailClosedLocalRchFallback,
            Self::StaleEvidence => FourthWaveGovernorAction::FailClosedStaleEvidence,
            Self::AdvisoryOnlyEvidence => FourthWaveGovernorAction::FailClosedAdvisoryOnly,
            Self::RemoteRequiredNoWorker => FourthWaveGovernorAction::DeferNoRemoteWorker,
            Self::BrownoutOptionalWork => FourthWaveGovernorAction::BrownoutOptionalWork,
            Self::AdmitRequiredWork => FourthWaveGovernorAction::AdmitRequiredWork,
        }
    }
}

const FOURTH_WAVE_RULE_PRIORITY_ORDER: [FourthWaveGovernorRule; 8] = [
    FourthWaveGovernorRule::MalformedInput,
    FourthWaveGovernorRule::MissingRequiredEvidence,
    FourthWaveGovernorRule::LocalRchFallback,
    FourthWaveGovernorRule::StaleEvidence,
    FourthWaveGovernorRule::AdvisoryOnlyEvidence,
    FourthWaveGovernorRule::RemoteRequiredNoWorker,
    FourthWaveGovernorRule::BrownoutOptionalWork,
    FourthWaveGovernorRule::AdmitRequiredWork,
];

/// Evidence-quality summary captured in fourth-wave decision receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveEvidenceQuality {
    /// Total evidence rows.
    pub row_count: u64,
    /// Required evidence classes present.
    pub required_input_classes_present: u64,
    /// Minimum row confidence in basis points.
    pub min_confidence_bps: u16,
    /// Maximum evidence age in seconds.
    pub max_evidence_age_seconds: u64,
    /// Advisory-only evidence row count.
    pub advisory_only_row_count: u64,
    /// Whether lab metadata is replay-backed.
    pub replay_backed: bool,
    /// Whether any local fallback marker was present.
    pub local_fallback_marker_detected: bool,
    /// Dominant pressure class that would trigger brownout, when any.
    pub dominant_pressure_class: Option<String>,
}

impl FourthWaveEvidenceQuality {
    #[must_use]
    fn as_log_value(&self) -> String {
        format!(
            "rows={} required_present={} min_confidence_bps={} max_age_seconds={} advisory_only_rows={} replay_backed={} local_fallback_marker_detected={} dominant_pressure_class={}",
            self.row_count,
            self.required_input_classes_present,
            self.min_confidence_bps,
            self.max_evidence_age_seconds,
            self.advisory_only_row_count,
            self.replay_backed,
            self.local_fallback_marker_detected,
            self.dominant_pressure_class.as_deref().unwrap_or("none")
        )
    }
}

/// Candidate rule not selected by the fourth-wave governor evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveRejectedAlternative {
    /// Candidate rule id.
    pub rule_id: &'static str,
    /// Candidate action.
    pub selected_action: FourthWaveGovernorAction,
    /// Deterministic reason the candidate was not selected.
    pub reason: String,
}

/// Log fields required by the fourth-wave decision receipt contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveGovernorLogFields {
    /// Bead id.
    pub bead_id: String,
    /// Scenario id.
    pub scenario_id: String,
    /// Snapshot id.
    pub snapshot_id: String,
    /// Decision id.
    pub decision_id: String,
    /// Policy version.
    pub policy_version: String,
    /// Selected action label.
    pub selected_action: String,
    /// Input artifact hashes joined in deterministic order.
    pub input_artifact_hashes: String,
    /// Rejected row count.
    pub rejected_row_count: u64,
    /// First rejected row reason.
    pub first_rejected_row_reason: String,
    /// Objective id.
    pub objective_id: String,
    /// Workload class.
    pub workload_class: String,
    /// Evidence quality summary.
    pub evidence_quality: String,
}

/// Replayable fourth-wave governor decision receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveGovernorDecisionReceipt {
    /// Receipt schema version.
    pub schema_version: &'static str,
    /// Deterministic decision id.
    pub decision_id: String,
    /// Policy version.
    pub policy_version: String,
    /// Snapshot id.
    pub snapshot_id: String,
    /// Selected action.
    pub selected_action: FourthWaveGovernorAction,
    /// Non-action reason, when no action can be claimed.
    pub non_action_reason: String,
    /// Whether this decision fails closed.
    pub fail_closed: bool,
    /// Selected rule id.
    pub rule_id: &'static str,
    /// Confidence in basis points.
    pub confidence_bps: u16,
    /// Input artifact hashes.
    pub input_artifact_hashes: Vec<String>,
    /// Evidence row ids in deterministic order.
    pub evidence_rows: Vec<String>,
    /// Rejected row ids or missing class labels.
    pub rejected_rows: Vec<String>,
    /// Rejected candidate alternatives.
    pub rejected_alternatives: Vec<FourthWaveRejectedAlternative>,
    /// Objective row copied into the receipt.
    pub objective_row: FourthWaveGovernorObjective,
    /// Evidence quality summary.
    pub evidence_quality: FourthWaveEvidenceQuality,
    /// Structured log fields.
    pub log_fields: FourthWaveGovernorLogFields,
    /// Claims explicitly not made by this policy layer.
    pub non_claims: Vec<&'static str>,
}

/// Evaluate the pure fourth-wave governor policy layer.
///
/// The evaluator is side-effect-free and advisory-only: it emits a replayable
/// receipt, but it does not admit, reject, brown out, or defer runtime work.
#[must_use]
pub fn evaluate_fourth_wave_governor(
    input: &FourthWaveGovernorInput,
) -> FourthWaveGovernorDecisionReceipt {
    let snapshot = &input.pressure_snapshot;
    let evidence_rows = fourth_wave_sorted_evidence_row_ids(&snapshot.evidence_rows);
    let input_artifact_hashes = fourth_wave_sorted_strings(&snapshot.input_artifact_hashes);
    let pressure_trigger = fourth_wave_brownout_pressure_trigger(snapshot);
    let evidence_quality = fourth_wave_evidence_quality(snapshot, pressure_trigger.as_deref());

    let selected = fourth_wave_select_rule(input, pressure_trigger.as_deref());
    let rule = selected.rule;
    let action = rule.action();
    let rejected_rows = fourth_wave_rejected_rows_for_rule(snapshot, rule, &selected.reason);
    let confidence_bps = fourth_wave_receipt_confidence(snapshot, rule);
    let decision_id = format!(
        "fw-governor-decision/{}/policy-v1",
        fourth_wave_scenario_slug(&input.scenario_id)
    );
    let first_rejected_row_reason = fourth_wave_first_rejected_row_reason(snapshot, &rejected_rows)
        .unwrap_or_else(|| {
            if rejected_rows.is_empty() {
                String::new()
            } else {
                selected.reason.clone()
            }
        });
    let log_fields = FourthWaveGovernorLogFields {
        bead_id: input.bead_id.trim().to_string(),
        scenario_id: input.scenario_id.trim().to_string(),
        snapshot_id: snapshot.snapshot_id.trim().to_string(),
        decision_id: decision_id.clone(),
        policy_version: snapshot.policy_version.trim().to_string(),
        selected_action: action.as_str().to_string(),
        input_artifact_hashes: input_artifact_hashes.join(","),
        rejected_row_count: rejected_rows.len() as u64,
        first_rejected_row_reason,
        objective_id: input.objective.objective_id.trim().to_string(),
        workload_class: input.objective.workload_class.as_str().to_string(),
        evidence_quality: evidence_quality.as_log_value(),
    };

    FourthWaveGovernorDecisionReceipt {
        schema_version: FOURTH_WAVE_DECISION_RECEIPT_SCHEMA_VERSION,
        decision_id,
        policy_version: snapshot.policy_version.trim().to_string(),
        snapshot_id: snapshot.snapshot_id.trim().to_string(),
        selected_action: action,
        non_action_reason: selected.reason,
        fail_closed: action.fail_closed(),
        rule_id: rule.rule_id(),
        confidence_bps,
        input_artifact_hashes,
        evidence_rows,
        rejected_rows,
        rejected_alternatives: fourth_wave_rejected_alternatives(rule),
        objective_row: input.objective.clone(),
        evidence_quality,
        log_fields,
        non_claims: vec![
            "policy engine only",
            "no runtime bridge enabled",
            "local cargo fallback not authorized",
        ],
    }
}

#[derive(Debug, Clone)]
struct FourthWaveSelectedRule {
    rule: FourthWaveGovernorRule,
    reason: String,
}

fn fourth_wave_select_rule(
    input: &FourthWaveGovernorInput,
    pressure_trigger: Option<&str>,
) -> FourthWaveSelectedRule {
    let snapshot = &input.pressure_snapshot;
    if let Some(reason) = fourth_wave_malformed_reason(input) {
        return FourthWaveSelectedRule {
            rule: FourthWaveGovernorRule::MalformedInput,
            reason,
        };
    }

    let missing = fourth_wave_missing_required_evidence_classes(snapshot);
    if !missing.is_empty() {
        return FourthWaveSelectedRule {
            rule: FourthWaveGovernorRule::MissingRequiredEvidence,
            reason: format!("missing required evidence classes: {}", missing.join(",")),
        };
    }

    if fourth_wave_local_fallback_marker_detected(snapshot) {
        return FourthWaveSelectedRule {
            rule: FourthWaveGovernorRule::LocalRchFallback,
            reason: "local RCH fallback marker detected".to_string(),
        };
    }

    if let Some(stale_row) = snapshot
        .evidence_rows
        .iter()
        .filter(|row| row.evidence_age_seconds > FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS)
        .min_by(|left, right| {
            (
                left.evidence_age_seconds,
                left.source_class.as_str(),
                left.source_id.as_str(),
            )
                .cmp(&(
                    right.evidence_age_seconds,
                    right.source_class.as_str(),
                    right.source_id.as_str(),
                ))
        })
    {
        return FourthWaveSelectedRule {
            rule: FourthWaveGovernorRule::StaleEvidence,
            reason: format!(
                "evidence older than {FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS} seconds: {}",
                stale_row.source_id.trim()
            ),
        };
    }

    if !snapshot.lab_replay_metadata.replay_backed
        && !snapshot.evidence_rows.is_empty()
        && snapshot
            .evidence_rows
            .iter()
            .all(|row| row.claim_status.is_advisory_only())
    {
        return FourthWaveSelectedRule {
            rule: FourthWaveGovernorRule::AdvisoryOnlyEvidence,
            reason: "advisory evidence lacks lab or replay backing".to_string(),
        };
    }

    if snapshot.rch_admission_state.remote_required
        && !snapshot.rch_admission_state.workers_admissible
    {
        return FourthWaveSelectedRule {
            rule: FourthWaveGovernorRule::RemoteRequiredNoWorker,
            reason: "remote-required lane has no admissible remote worker; local fallback refused"
                .to_string(),
        };
    }

    if let Some(reason) = pressure_trigger {
        return FourthWaveSelectedRule {
            rule: FourthWaveGovernorRule::BrownoutOptionalWork,
            reason: reason.to_string(),
        };
    }

    FourthWaveSelectedRule {
        rule: FourthWaveGovernorRule::AdmitRequiredWork,
        reason: String::new(),
    }
}

fn fourth_wave_malformed_reason(input: &FourthWaveGovernorInput) -> Option<String> {
    let snapshot = &input.pressure_snapshot;
    if input.scenario_id.trim().is_empty() {
        return Some("scenario_id is empty".to_string());
    }
    if input.bead_id.trim().is_empty() {
        return Some("bead_id is empty".to_string());
    }
    if input.objective.objective_id.trim().is_empty() {
        return Some("objective_id is empty".to_string());
    }
    if input.objective.target_confidence_bps > 10_000 {
        return Some("objective target_confidence_bps exceeds 10000".to_string());
    }
    if snapshot.input_status != FourthWaveInputStatus::Complete {
        return Some(format!(
            "snapshot input_status is {}",
            snapshot.input_status.as_str()
        ));
    }
    if snapshot.schema_version.trim() != FOURTH_WAVE_PRESSURE_SNAPSHOT_SCHEMA_VERSION {
        return Some("snapshot schema_version is unsupported".to_string());
    }
    if snapshot.policy_version.trim() != FOURTH_WAVE_GOVERNOR_POLICY_VERSION {
        return Some("snapshot policy_version is unsupported".to_string());
    }
    if snapshot.snapshot_id.trim().is_empty() {
        return Some("snapshot_id is empty".to_string());
    }
    if snapshot
        .input_artifact_hashes
        .iter()
        .any(|hash| hash.trim().is_empty())
    {
        return Some("input_artifact_hashes contains an empty hash".to_string());
    }
    if snapshot
        .evidence_rows
        .iter()
        .any(|row| row.source_id.trim().is_empty())
    {
        return Some("evidence row source_id is empty".to_string());
    }
    if snapshot
        .evidence_rows
        .iter()
        .any(|row| row.source_schema_version.trim().is_empty())
    {
        return Some("evidence row source_schema_version is empty".to_string());
    }
    if snapshot
        .evidence_rows
        .iter()
        .any(|row| row.evidence_hash.trim().is_empty())
    {
        return Some("evidence row evidence_hash is empty".to_string());
    }
    if snapshot
        .evidence_rows
        .iter()
        .any(|row| row.confidence_bps > 10_000)
    {
        return Some("evidence row confidence_bps exceeds 10000".to_string());
    }
    None
}

fn fourth_wave_missing_required_evidence_classes(
    snapshot: &FourthWavePressureSnapshot,
) -> Vec<String> {
    let present: BTreeSet<_> = snapshot
        .evidence_rows
        .iter()
        .map(|row| row.source_class)
        .collect();
    FOURTH_WAVE_REQUIRED_EVIDENCE_CLASSES
        .iter()
        .copied()
        .filter(|class| !present.contains(class))
        .map(|class| class.as_str().to_string())
        .collect()
}

fn fourth_wave_local_fallback_marker_detected(snapshot: &FourthWavePressureSnapshot) -> bool {
    snapshot.rch_admission_state.local_fallback_marker_detected
        || snapshot
            .evidence_rows
            .iter()
            .any(|row| row.local_fallback_marker_detected)
}

fn fourth_wave_brownout_pressure_trigger(snapshot: &FourthWavePressureSnapshot) -> Option<String> {
    if snapshot.memory_envelope.memory_pressure_bps >= FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS {
        return Some("optional work exceeds memory pressure budget".to_string());
    }
    if snapshot.core_envelope.admit_core_budget_bps > 0
        && (snapshot.core_envelope.local_core_pressure_bps
            > snapshot.core_envelope.admit_core_budget_bps
            || snapshot.core_envelope.remote_core_pressure_bps
                > snapshot.core_envelope.admit_core_budget_bps)
    {
        return Some("optional work exceeds core pressure budget".to_string());
    }
    if snapshot.active_region_pressure.region_pressure_bps
        >= FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS
        || (snapshot.active_region_pressure.region_limit > 0
            && snapshot.active_region_pressure.active_region_count
                >= snapshot.active_region_pressure.region_limit)
    {
        return Some("optional work exceeds region pressure budget".to_string());
    }
    if snapshot.obligation_pressure.obligation_pressure_bps
        >= FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS
        || snapshot.obligation_pressure.leak_suspect_count > 0
    {
        return Some("optional work exceeds obligation pressure budget".to_string());
    }
    None
}

fn fourth_wave_evidence_quality(
    snapshot: &FourthWavePressureSnapshot,
    pressure_trigger: Option<&str>,
) -> FourthWaveEvidenceQuality {
    let present: BTreeSet<_> = snapshot
        .evidence_rows
        .iter()
        .map(|row| row.source_class)
        .collect();
    FourthWaveEvidenceQuality {
        row_count: snapshot.evidence_rows.len() as u64,
        required_input_classes_present: FOURTH_WAVE_REQUIRED_EVIDENCE_CLASSES
            .iter()
            .filter(|class| present.contains(class))
            .count() as u64,
        min_confidence_bps: snapshot
            .evidence_rows
            .iter()
            .map(|row| row.confidence_bps)
            .min()
            .unwrap_or(0),
        max_evidence_age_seconds: snapshot
            .evidence_rows
            .iter()
            .map(|row| row.evidence_age_seconds)
            .max()
            .unwrap_or(0),
        advisory_only_row_count: snapshot
            .evidence_rows
            .iter()
            .filter(|row| row.claim_status.is_advisory_only())
            .count() as u64,
        replay_backed: snapshot.lab_replay_metadata.replay_backed,
        local_fallback_marker_detected: fourth_wave_local_fallback_marker_detected(snapshot),
        dominant_pressure_class: pressure_trigger.map(ToOwned::to_owned),
    }
}

fn fourth_wave_receipt_confidence(
    snapshot: &FourthWavePressureSnapshot,
    rule: FourthWaveGovernorRule,
) -> u16 {
    match rule {
        FourthWaveGovernorRule::AdmitRequiredWork
        | FourthWaveGovernorRule::BrownoutOptionalWork
        | FourthWaveGovernorRule::RemoteRequiredNoWorker => snapshot
            .evidence_rows
            .iter()
            .map(|row| row.confidence_bps)
            .min()
            .unwrap_or(0),
        FourthWaveGovernorRule::MalformedInput
        | FourthWaveGovernorRule::MissingRequiredEvidence
        | FourthWaveGovernorRule::LocalRchFallback
        | FourthWaveGovernorRule::StaleEvidence
        | FourthWaveGovernorRule::AdvisoryOnlyEvidence => 0,
    }
}

fn fourth_wave_rejected_rows_for_rule(
    snapshot: &FourthWavePressureSnapshot,
    rule: FourthWaveGovernorRule,
    selected_reason: &str,
) -> Vec<String> {
    match rule {
        FourthWaveGovernorRule::MalformedInput => vec![snapshot.snapshot_id.trim().to_string()],
        FourthWaveGovernorRule::MissingRequiredEvidence => {
            fourth_wave_missing_required_evidence_classes(snapshot)
        }
        FourthWaveGovernorRule::LocalRchFallback => snapshot
            .evidence_rows
            .iter()
            .filter(|row| row.local_fallback_marker_detected)
            .map(|row| row.source_id.trim().to_string())
            .collect(),
        FourthWaveGovernorRule::StaleEvidence => snapshot
            .evidence_rows
            .iter()
            .filter(|row| row.evidence_age_seconds > FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS)
            .map(|row| row.source_id.trim().to_string())
            .collect(),
        FourthWaveGovernorRule::AdvisoryOnlyEvidence => snapshot
            .evidence_rows
            .iter()
            .filter(|row| row.claim_status.is_advisory_only())
            .map(|row| row.source_id.trim().to_string())
            .collect(),
        FourthWaveGovernorRule::RemoteRequiredNoWorker => {
            let mut rows: Vec<String> = snapshot
                .evidence_rows
                .iter()
                .filter(|row| row.source_class == FourthWaveEvidenceClass::RchProofLane)
                .map(|row| row.source_id.trim().to_string())
                .collect();
            if rows.is_empty() {
                rows.push(
                    snapshot
                        .rch_admission_state
                        .first_blocker
                        .as_deref()
                        .map(str::trim)
                        .filter(|blocker| !blocker.is_empty())
                        .unwrap_or(selected_reason)
                        .to_string(),
                );
            }
            rows
        }
        FourthWaveGovernorRule::BrownoutOptionalWork
        | FourthWaveGovernorRule::AdmitRequiredWork => Vec::new(),
    }
}

fn fourth_wave_first_rejected_row_reason(
    snapshot: &FourthWavePressureSnapshot,
    rejected_rows: &[String],
) -> Option<String> {
    for rejected_row in rejected_rows {
        if let Some(reason) = snapshot
            .evidence_rows
            .iter()
            .find(|row| row.source_id.trim() == rejected_row.trim())
            .and_then(|row| normalized_optional_string(Some(&row.rejected_reason)))
        {
            return Some(reason);
        }
    }
    None
}

fn fourth_wave_rejected_alternatives(
    selected_rule: FourthWaveGovernorRule,
) -> Vec<FourthWaveRejectedAlternative> {
    FOURTH_WAVE_RULE_PRIORITY_ORDER
        .iter()
        .copied()
        .filter(|rule| *rule != selected_rule)
        .map(|rule| {
            let reason = if rule.priority() < selected_rule.priority() {
                format!(
                    "{} did not trigger before {}",
                    rule.rule_id(),
                    selected_rule.rule_id()
                )
            } else {
                format!(
                    "{} skipped because {} selected first",
                    rule.rule_id(),
                    selected_rule.rule_id()
                )
            };
            FourthWaveRejectedAlternative {
                rule_id: rule.rule_id(),
                selected_action: rule.action(),
                reason,
            }
        })
        .collect()
}

fn fourth_wave_sorted_evidence_row_ids(rows: &[FourthWaveEvidenceRow]) -> Vec<String> {
    let mut ids: Vec<_> = rows
        .iter()
        .map(|row| (row.source_class.as_str(), row.source_id.trim().to_string()))
        .collect();
    ids.sort();
    ids.into_iter().map(|(_, source_id)| source_id).collect()
}

fn fourth_wave_sorted_strings(values: &[String]) -> Vec<String> {
    let mut values: Vec<_> = values
        .iter()
        .map(|value| value.trim().to_string())
        .collect();
    values.sort();
    values
}

fn fourth_wave_scenario_slug(scenario_id: &str) -> String {
    let mut slug = String::with_capacity(scenario_id.len());
    let mut previous_dash = false;
    for ch in scenario_id.trim().chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }
    let slug = slug.trim_matches('-');
    let slug = slug.strip_prefix("fw-governor-").unwrap_or(slug);
    if slug.is_empty() {
        "unknown".to_string()
    } else {
        slug.to_string()
    }
}

/// Proof or validation lane associated with an admitted swarm workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmProofLaneKind {
    /// Source-only work that does not claim validation proof.
    SourceOnly,
    /// Focused library check lane.
    CargoCheckLib,
    /// All-target compiler check lane.
    CargoCheckAllTargets,
    /// Clippy all-target lint lane.
    ClippyAllTargets,
    /// Rustfmt formatting lane.
    RustfmtCheck,
    /// Rustdoc generation/check lane.
    Rustdoc,
    /// Focused test lane.
    Test,
    /// Release proof bundle or release-gate lane.
    ReleaseProof,
    /// Project-specific lane not covered by the built-in classes.
    Other,
}

impl SwarmProofLaneKind {
    /// Stable snake-case label for logs, receipts, and decision reasons.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceOnly => "source_only",
            Self::CargoCheckLib => "cargo_check_lib",
            Self::CargoCheckAllTargets => "cargo_check_all_targets",
            Self::ClippyAllTargets => "clippy_all_targets",
            Self::RustfmtCheck => "rustfmt_check",
            Self::Rustdoc => "rustdoc",
            Self::Test => "test",
            Self::ReleaseProof => "release_proof",
            Self::Other => "other",
        }
    }
}

/// Owner metadata attached to a swarm workload admission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmAdmissionOwner {
    /// Agent or runtime component requesting admission.
    pub agent_name: String,
    /// Optional bead id that motivated the workload.
    pub bead_id: Option<String>,
    /// Optional reservation or file-frontier label.
    pub reservation_scope: Option<String>,
}

impl SwarmAdmissionOwner {
    /// Build owner metadata from the requesting agent/component name.
    #[must_use]
    pub fn new(agent_name: impl Into<String>) -> Self {
        Self {
            agent_name: agent_name.into(),
            bead_id: None,
            reservation_scope: None,
        }
    }

    /// Attach the motivating bead id.
    #[must_use]
    pub fn with_bead_id(mut self, bead_id: impl Into<String>) -> Self {
        self.bead_id = Some(bead_id.into());
        self
    }

    /// Attach a reservation or file-frontier label.
    #[must_use]
    pub fn with_reservation_scope(mut self, reservation_scope: impl Into<String>) -> Self {
        self.reservation_scope = Some(reservation_scope.into());
        self
    }

    fn validate(&self) -> Option<String> {
        if self.agent_name.trim().is_empty() {
            return Some("owner agent_name must be non-empty".to_string());
        }
        if self
            .bead_id
            .as_deref()
            .is_some_and(|bead_id| bead_id.trim().is_empty())
        {
            return Some("owner bead_id must be non-empty when present".to_string());
        }
        if self
            .reservation_scope
            .as_deref()
            .is_some_and(|scope| scope.trim().is_empty())
        {
            return Some("owner reservation_scope must be non-empty when present".to_string());
        }
        None
    }
}

/// Structured admission request for agent-swarm work.
#[derive(Debug, Clone)]
pub struct SwarmWorkloadAdmissionRequest {
    /// Stable workload id used in logs and replay receipts.
    pub workload_id: String,
    /// Owner metadata for accountability and bead/file-reservation linking.
    pub owner: SwarmAdmissionOwner,
    /// Priority used by pressure and shedding decisions.
    pub priority: RegionPriority,
    /// Requested memory charged against the returned resource envelope.
    pub requested_memory_bytes: Option<u64>,
    /// Requested CPU nanoseconds per second charged against the envelope.
    pub requested_cpu_ns_per_sec: Option<u64>,
    /// Requested IO operations per second charged against the envelope.
    pub requested_io_ops_per_sec: Option<u64>,
    /// Proof or validation lane class for this workload.
    pub proof_lane: SwarmProofLaneKind,
    /// Optional absolute deadline for admission.
    pub deadline: Option<Instant>,
    /// Optional cancellation budget for cleanup/drain if the workload is refused or cancelled.
    pub cancellation_budget: Option<Duration>,
}

impl SwarmWorkloadAdmissionRequest {
    /// Build a normal-priority source-only admission request.
    #[must_use]
    pub fn new(workload_id: impl Into<String>, owner: SwarmAdmissionOwner) -> Self {
        Self {
            workload_id: workload_id.into(),
            owner,
            priority: RegionPriority::Normal,
            requested_memory_bytes: None,
            requested_cpu_ns_per_sec: None,
            requested_io_ops_per_sec: None,
            proof_lane: SwarmProofLaneKind::SourceOnly,
            deadline: None,
            cancellation_budget: None,
        }
    }

    /// Set pressure priority.
    #[must_use]
    pub fn with_priority(mut self, priority: RegionPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set declared resource reservations.
    #[must_use]
    pub fn with_declared_resources(
        mut self,
        memory_bytes: Option<u64>,
        cpu_ns_per_sec: Option<u64>,
        io_ops_per_sec: Option<u64>,
    ) -> Self {
        self.requested_memory_bytes = memory_bytes;
        self.requested_cpu_ns_per_sec = cpu_ns_per_sec;
        self.requested_io_ops_per_sec = io_ops_per_sec;
        self
    }

    /// Set proof-lane class.
    #[must_use]
    pub fn with_proof_lane(mut self, proof_lane: SwarmProofLaneKind) -> Self {
        self.proof_lane = proof_lane;
        self
    }

    /// Set an absolute deadline.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Set cancellation/drain budget.
    #[must_use]
    pub fn with_cancellation_budget(mut self, cancellation_budget: Duration) -> Self {
        self.cancellation_budget = Some(cancellation_budget);
        self
    }

    fn validate(&self, now: Instant) -> Option<String> {
        if self.workload_id.trim().is_empty() {
            return Some("workload_id must be non-empty".to_string());
        }
        if let Some(reason) = self.owner.validate() {
            return Some(reason);
        }
        if self.deadline.is_some_and(|deadline| deadline <= now) {
            return Some("deadline has already expired".to_string());
        }
        if self
            .cancellation_budget
            .is_some_and(|budget| budget.is_zero())
        {
            return Some("cancellation_budget must be non-zero when present".to_string());
        }
        None
    }

    fn context_reason(&self, base: &str) -> String {
        let owner = normalized_owner_metadata(&self.owner);
        format!(
            "workload_id={} owner_agent={} bead_id={} reservation_scope={} priority={:?} proof_lane={} requested_memory_bytes={} requested_cpu_ns_per_sec={} requested_io_ops_per_sec={} deadline_set={} cancellation_budget_ms={}: {base}",
            self.workload_id.trim(),
            owner.agent_name.as_str(),
            optional_reason_field(owner.bead_id.as_deref()),
            optional_reason_field(owner.reservation_scope.as_deref()),
            self.priority,
            self.proof_lane.as_str(),
            optional_u64_reason_field(self.requested_memory_bytes),
            optional_u64_reason_field(self.requested_cpu_ns_per_sec),
            optional_u64_reason_field(self.requested_io_ops_per_sec),
            self.deadline.is_some(),
            self.cancellation_budget
                .map(duration_as_u64_ms)
                .map_or_else(|| "unset".to_string(), |value| value.to_string())
        )
    }
}

/// Stable identifier for a swarm workload lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SwarmWorkloadLeaseId(u64);

impl SwarmWorkloadLeaseId {
    /// Build a lease id for deterministic tests and replay fixtures.
    #[must_use]
    pub const fn new_for_test(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw numeric lease id.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Lifecycle state for a linear swarm workload lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmWorkloadLeaseState {
    /// Lease was granted but not yet committed to a caller-owned region.
    Active,
    /// Lease was committed to a caller-owned region and remains renewable.
    Committed,
    /// Lease was explicitly released after normal completion or region close.
    Released,
    /// Lease was aborted because admission or execution was cancelled.
    Aborted,
    /// Lease reached its deadline before explicit release.
    Expired,
}

impl SwarmWorkloadLeaseState {
    /// Stable snake-case label for receipts and decision reasons.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Committed => "committed",
            Self::Released => "released",
            Self::Aborted => "aborted",
            Self::Expired => "expired",
        }
    }

    /// Returns true when the lease can still be renewed or completed.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::Committed)
    }

    /// Returns true once the lease no longer represents a live obligation.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !self.is_live()
    }
}

/// Typed lifecycle transition represented by a workload lease receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmWorkloadLeaseTransition {
    /// Lease was acquired from an admitted workload decision.
    Acquired,
    /// Lease was committed to the caller-owned region.
    Committed,
    /// Lease deadline was extended.
    Renewed,
    /// Lease was explicitly released after successful completion.
    Released,
    /// Lease was released because its region closed.
    ReleasedByRegionClose,
    /// Lease was explicitly aborted.
    Aborted,
    /// Lease expired before explicit completion.
    Expired,
}

impl SwarmWorkloadLeaseTransition {
    /// Stable snake-case label for structured receipts and replay logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acquired => "acquired",
            Self::Committed => "committed",
            Self::Renewed => "renewed",
            Self::Released => "released",
            Self::ReleasedByRegionClose => "released_by_region_close",
            Self::Aborted => "aborted",
            Self::Expired => "expired",
        }
    }
}

/// Linear workload lease bound to an admitted region envelope.
#[derive(Debug, Clone)]
pub struct SwarmWorkloadLease {
    /// Unique lease id assigned by the governor.
    pub lease_id: SwarmWorkloadLeaseId,
    /// Workload id from the admission request.
    pub workload_id: String,
    /// Owner metadata carried from admission.
    pub owner: SwarmAdmissionOwner,
    /// Proof or validation lane associated with the lease.
    pub proof_lane: SwarmProofLaneKind,
    /// Pressure priority associated with the admitted workload.
    pub priority: RegionPriority,
    /// Region currently bound to this lease.
    pub region_id: RegionId,
    /// Current lifecycle state.
    pub state: SwarmWorkloadLeaseState,
    /// Memory reserved by the workload admission request.
    pub reserved_memory_bytes: Option<u64>,
    /// CPU budget reserved by the workload admission request.
    pub reserved_cpu_ns_per_sec: Option<u64>,
    /// IO budget reserved by the workload admission request.
    pub reserved_io_ops_per_sec: Option<u64>,
    /// Cancellation/drain budget reserved by the workload admission request.
    pub cancellation_budget: Option<Duration>,
    /// Time at which the lease was granted.
    pub issued_at: Instant,
    /// Time at which the lease expires if not renewed or completed.
    pub expires_at: Instant,
    /// Most recent successful renewal time.
    pub last_renewed_at: Option<Instant>,
    /// Terminal transition time for released, aborted, or expired leases.
    pub terminal_at: Option<Instant>,
    /// Number of successful renewals.
    pub renewal_count: u64,
}

impl SwarmWorkloadLease {
    fn context_reason(&self, base: &str) -> String {
        format!(
            "lease_id={} workload_id={} region_id={:?} owner_agent={} bead_id={} reservation_scope={} proof_lane={} priority={:?} state={} reserved_memory_bytes={} reserved_cpu_ns_per_sec={} reserved_io_ops_per_sec={} cancellation_budget_ms={} renewals={}: {base}",
            self.lease_id.as_u64(),
            self.workload_id.trim(),
            self.region_id,
            self.owner.agent_name.trim(),
            optional_reason_field(self.owner.bead_id.as_deref()),
            optional_reason_field(self.owner.reservation_scope.as_deref()),
            self.proof_lane.as_str(),
            self.priority,
            self.state.as_str(),
            optional_u64_reason_field(self.reserved_memory_bytes),
            optional_u64_reason_field(self.reserved_cpu_ns_per_sec),
            optional_u64_reason_field(self.reserved_io_ops_per_sec),
            optional_u64_reason_field(self.cancellation_budget.map(duration_as_u64_ms)),
            self.renewal_count
        )
    }
}

/// Receipt returned by workload lease lifecycle operations.
#[derive(Debug, Clone)]
pub struct SwarmWorkloadLeaseReceipt {
    /// Lease id affected by the operation.
    pub lease_id: SwarmWorkloadLeaseId,
    /// Stable replay/audit pointer for this lifecycle transition.
    pub replay_pointer: String,
    /// Workload id affected by the operation.
    pub workload_id: String,
    /// Owner metadata bound to the lease.
    pub owner: SwarmAdmissionOwner,
    /// Proof or validation lane bound to the lease.
    pub proof_lane: SwarmProofLaneKind,
    /// Region bound to the lease.
    pub region_id: RegionId,
    /// Priority bound to the lease.
    pub priority: RegionPriority,
    /// Memory reservation carried by the lease.
    pub reserved_memory_bytes: Option<u64>,
    /// CPU reservation carried by the lease.
    pub reserved_cpu_ns_per_sec: Option<u64>,
    /// IO reservation carried by the lease.
    pub reserved_io_ops_per_sec: Option<u64>,
    /// Cancellation/drain budget carried by the lease.
    pub cancellation_budget: Option<Duration>,
    /// Lease state after the operation.
    pub state: SwarmWorkloadLeaseState,
    /// Time at which the lease was granted.
    pub issued_at: Instant,
    /// Lease expiry after the operation.
    pub expires_at: Instant,
    /// Terminal transition time, when the operation completed the lease.
    pub terminal_at: Option<Instant>,
    /// Typed lifecycle transition represented by this receipt.
    pub transition: SwarmWorkloadLeaseTransition,
    /// Caller-facing transition reason before contextual lease fields are added.
    pub transition_reason: String,
    /// Structured explanation for logs and replay receipts.
    pub reason: String,
}

/// Deterministic live-lease scheduling row for swarm workload execution.
#[derive(Debug, Clone)]
pub struct SwarmWorkloadLeaseScheduleEntry {
    /// Zero-based rank after deterministic scheduling order is applied.
    pub scheduling_rank: u64,
    /// Stable replay/audit pointer for this scheduled lease row.
    pub replay_pointer: String,
    /// Lease id represented by the row.
    pub lease_id: SwarmWorkloadLeaseId,
    /// Workload id represented by the row.
    pub workload_id: String,
    /// Owner metadata bound to the lease.
    pub owner: SwarmAdmissionOwner,
    /// Proof or validation lane associated with the lease.
    pub proof_lane: SwarmProofLaneKind,
    /// Pressure priority used by the scheduler.
    pub priority: RegionPriority,
    /// Priority rank after bounded starvation aging is applied.
    pub effective_priority_rank: u8,
    /// Number of priority-rank steps discounted because the lease has waited.
    pub starvation_aging_discount: u8,
    /// Region currently bound to this lease.
    pub region_id: RegionId,
    /// Live lifecycle state used by the scheduler.
    pub state: SwarmWorkloadLeaseState,
    /// Memory reservation carried by the lease.
    pub reserved_memory_bytes: Option<u64>,
    /// CPU reservation carried by the lease.
    pub reserved_cpu_ns_per_sec: Option<u64>,
    /// IO reservation carried by the lease.
    pub reserved_io_ops_per_sec: Option<u64>,
    /// Cancellation/drain budget carried by the lease, in milliseconds.
    pub cancellation_budget_ms: Option<u64>,
    /// Time at which the lease was granted.
    pub issued_at: Instant,
    /// Time at which the lease expires if not renewed or completed.
    pub expires_at: Instant,
    /// Most recent renewal timestamp, when any.
    pub last_renewed_at: Option<Instant>,
    /// Number of successful renewals.
    pub renewal_count: u64,
    /// Milliseconds elapsed since the lease was granted.
    pub wait_age_ms: u64,
    /// Milliseconds remaining until this live lease expires.
    pub time_to_expiry_ms: u64,
    /// Whether live pressure feedback was attached to this schedule row.
    pub pressure_feedback_present: bool,
    /// Runtime queue pressure ratio scaled by 10_000.
    pub queue_pressure_scaled: i64,
    /// Disk or artifact-cache IO pressure ratio scaled by 10_000.
    pub disk_io_pressure_scaled: i64,
    /// RCH or remote-worker queue pressure ratio scaled by 10_000.
    pub rch_queue_pressure_scaled: i64,
    /// Validation-frontier blocker pressure ratio scaled by 10_000.
    pub validation_frontier_pressure_scaled: i64,
    /// Cancellation/drain tail-latency pressure ratio scaled by 10_000.
    pub cancellation_tail_pressure_scaled: i64,
    /// Maximum live workload pressure ratio scaled by 10_000.
    pub max_pressure_scaled: i64,
    /// Whether workload feedback pressure is deferring this lease behind cooler peer work.
    pub workload_pressure_deferral: bool,
    /// Dominant live workload pressure axis used by schedule ordering.
    pub dominant_pressure_source: SwarmWorkloadPressureSource,
    /// Runtime resource-monitor degradation level observed for this schedule pass.
    pub resource_degradation_level: DegradationLevel,
    /// Runtime resource-monitor pressure derived from degradation, scaled by 10_000.
    pub resource_pressure_scaled: i64,
    /// Whether resource pressure is deferring this background lease behind foreground work.
    pub resource_pressure_deferral: bool,
    /// Structured explanation for logs and replay receipts.
    pub reason: String,
}

/// Read-only audit snapshot for linear workload-lease invariants.
#[derive(Debug, Clone)]
pub struct SwarmWorkloadLeaseAuditSnapshot {
    /// Total live leases in `Active` or `Committed` state.
    pub live_lease_count: u64,
    /// Live leases still awaiting explicit commit.
    pub active_lease_count: u64,
    /// Live leases committed to caller-owned regions.
    pub committed_lease_count: u64,
    /// Total terminal leases retained for audit.
    pub terminal_lease_count: u64,
    /// Terminal leases released normally or by region close.
    pub released_lease_count: u64,
    /// Terminal leases aborted after cancellation or failed startup.
    pub aborted_lease_count: u64,
    /// Terminal leases expired by deadline.
    pub expired_lease_count: u64,
    /// Live leases whose bound region no longer has a registered envelope.
    pub live_unregistered_region_count: u64,
    /// Live leases whose expiry has already passed and need expiry processing.
    pub live_expired_count: u64,
    /// Terminal leases missing a terminal timestamp.
    pub terminal_missing_terminal_at_count: u64,
    /// Extra live leases sharing a workload id with another live lease.
    pub duplicate_live_workload_id_count: u64,
    /// Extra live leases sharing an owner agent with another live lease.
    pub duplicate_live_owner_agent_count: u64,
    /// Extra live leases sharing a bead id with another live lease.
    pub duplicate_live_bead_id_count: u64,
    /// Extra live leases sharing a reservation scope with another live lease.
    pub duplicate_live_reservation_scope_count: u64,
    /// True when any linear-obligation invariant violation is present.
    pub leak_detected: bool,
    /// Structured audit reason for logs and proof artifacts.
    pub reason: String,
}

/// Typed workload context bound to an admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmAdmissionWorkloadReceipt {
    /// Workload id used when the admission decision was computed.
    pub workload_id: String,
    /// Owner metadata used when the admission decision was computed.
    pub owner: SwarmAdmissionOwner,
    /// Proof or validation lane used when the admission decision was computed.
    pub proof_lane: SwarmProofLaneKind,
    /// Requested memory bytes charged to the admission decision.
    pub requested_memory_bytes: Option<u64>,
    /// Requested CPU nanoseconds per second charged to the admission decision.
    pub requested_cpu_ns_per_sec: Option<u64>,
    /// Requested IO operations per second charged to the admission decision.
    pub requested_io_ops_per_sec: Option<u64>,
    /// Deadline used for the admission decision.
    pub deadline: Option<Instant>,
    /// Cancellation budget used for the admission decision.
    pub cancellation_budget: Option<Duration>,
}

impl SwarmAdmissionWorkloadReceipt {
    fn from_request(request: &SwarmWorkloadAdmissionRequest) -> Self {
        Self {
            workload_id: request.workload_id.trim().to_string(),
            owner: normalized_owner_metadata(&request.owner),
            proof_lane: request.proof_lane,
            requested_memory_bytes: request.requested_memory_bytes,
            requested_cpu_ns_per_sec: request.requested_cpu_ns_per_sec,
            requested_io_ops_per_sec: request.requested_io_ops_per_sec,
            deadline: request.deadline,
            cancellation_budget: request.cancellation_budget,
        }
    }

    fn matches_request(&self, request: &SwarmWorkloadAdmissionRequest) -> bool {
        self == &Self::from_request(request)
    }
}

/// Structured audit receipt for an admission decision.
#[derive(Debug, Clone)]
pub struct SwarmAdmissionDecisionReceipt {
    /// Monotonic decision id assigned by this governor instance.
    pub decision_id: u64,
    /// Stable replay/audit pointer for logs and proof artifacts.
    pub replay_pointer: String,
    /// Admission outcome.
    pub decision: AdmissionDecision,
    /// System degradation level used by the decision.
    pub degradation_level: DegradationLevel,
    /// Final human-readable decision reason.
    pub reason: String,
    /// Workload id, when the decision came from workload admission.
    pub workload_id: Option<String>,
    /// Owner agent, when the decision came from workload admission.
    pub owner_agent: Option<String>,
    /// Bead id, when supplied by workload owner metadata.
    pub bead_id: Option<String>,
    /// Reservation/file-frontier scope, when supplied by workload owner metadata.
    pub reservation_scope: Option<String>,
    /// Proof lane, when the decision came from workload admission.
    pub proof_lane: Option<SwarmProofLaneKind>,
    /// Requested memory bytes charged to the decision.
    pub requested_memory_bytes: Option<u64>,
    /// Requested CPU nanoseconds per second charged to the decision.
    pub requested_cpu_ns_per_sec: Option<u64>,
    /// Requested IO operations per second charged to the decision.
    pub requested_io_ops_per_sec: Option<u64>,
    /// Whether the request included an admission deadline.
    pub deadline_set: bool,
    /// Cancellation budget in milliseconds, when supplied.
    pub cancellation_budget_ms: Option<u64>,
    /// Overall pressure ratio scaled by 10_000 for deterministic structured logs.
    pub overall_pressure_scaled: i64,
    /// Runnable queue pressure ratio scaled by 10_000.
    pub runnable_queue_pressure_scaled: i64,
    /// Blocking pool pressure ratio scaled by 10_000.
    pub blocking_pool_pressure_scaled: i64,
    /// Channel backlog pressure ratio scaled by 10_000.
    pub channel_backlog_pressure_scaled: i64,
    /// Cleanup debt pressure ratio scaled by 10_000.
    pub cleanup_debt_pressure_scaled: i64,
    /// Memory budget pressure ratio scaled by 10_000.
    pub memory_budget_pressure_scaled: i64,
    /// Live peer pressure reports considered by this decision.
    pub peer_pressure_report_count: u64,
    /// Maximum peer-reported pressure ratio scaled by 10_000.
    pub peer_pressure_max_pressure_scaled: i64,
    /// Peer pressure backpressure threshold scaled by 10_000.
    pub peer_pressure_backpressure_threshold_scaled: i64,
    /// Whether peer pressure crossed the configured backpressure threshold.
    pub peer_pressure_backpressure_triggered: bool,
    /// Maximum peer-reported degradation level represented as its stable enum rank.
    pub peer_pressure_max_degradation_level: u8,
    /// Live workload feedback reports considered by this decision.
    pub workload_feedback_report_count: u64,
    /// Maximum workload feedback pressure ratio scaled by 10_000.
    pub workload_feedback_max_pressure_scaled: i64,
    /// Workload feedback backpressure threshold scaled by 10_000.
    pub workload_feedback_backpressure_threshold_scaled: i64,
    /// Whether workload feedback crossed the configured backpressure threshold.
    pub workload_feedback_backpressure_triggered: bool,
    /// Dominant workload feedback axis used by this admission decision.
    pub workload_feedback_dominant_pressure_source: SwarmWorkloadPressureSource,
    /// Workload queue feedback pressure ratio scaled by 10_000.
    pub workload_queue_pressure_scaled: i64,
    /// Workload disk or artifact-cache IO feedback pressure ratio scaled by 10_000.
    pub workload_disk_io_pressure_scaled: i64,
    /// Workload RCH or remote-worker queue feedback pressure ratio scaled by 10_000.
    pub workload_rch_queue_pressure_scaled: i64,
    /// Workload validation-frontier feedback pressure ratio scaled by 10_000.
    pub workload_validation_frontier_pressure_scaled: i64,
    /// Workload cancellation/drain tail feedback pressure ratio scaled by 10_000.
    pub workload_cancellation_tail_pressure_scaled: i64,
}

/// Enhanced admission decision with resource envelope information.
#[derive(Debug, Clone)]
pub struct SwarmAdmissionDecision {
    /// Core admission decision.
    pub decision: AdmissionDecision,
    /// Resource envelope for the admitted region (if approved).
    pub envelope: Option<ResourceEnvelope>,
    /// Pressure snapshot at decision time.
    pub pressure_snapshot: PressureSnapshot,
    /// System degradation level at decision time.
    pub degradation_level: DegradationLevel,
    /// Decision latency in nanoseconds.
    pub decision_latency_ns: u64,
    /// Reason for the decision.
    pub reason: String,
    /// Structured audit receipt for logs and replayable proof artifacts.
    pub decision_receipt: SwarmAdmissionDecisionReceipt,
    /// Workload request context bound to this decision, when it came from workload admission.
    pub workload_receipt: Option<SwarmAdmissionWorkloadReceipt>,
}

/// Swarm-aware pressure governor with resource envelope management.
pub struct SwarmPressureGovernor {
    config: SwarmPressureGovernorConfig,
    pressure_governor: Option<PressureGovernor>,
    resource_monitor: Arc<ResourceMonitor>,

    // Metrics
    total_admission_checks: AtomicU64,
    regions_admitted: AtomicU64,
    regions_rejected: AtomicU64,
    envelope_budget_violations: AtomicU64,
    max_decision_latency_ns: AtomicU64,
    workload_leases_acquired: AtomicU64,
    workload_leases_committed: AtomicU64,
    workload_leases_renewed: AtomicU64,
    workload_leases_released: AtomicU64,
    workload_leases_aborted: AtomicU64,
    workload_leases_expired: AtomicU64,
    workload_lease_conflicts: AtomicU64,
    workload_feedback_reports_recorded: AtomicU64,
    next_admission_decision_id: AtomicU64,
    next_workload_lease_id: AtomicU64,

    // Resource envelope and workload lease tracking.
    active_regions: std::sync::Mutex<HashMap<RegionId, ResourceEnvelope>>,
    workload_leases: std::sync::Mutex<HashMap<SwarmWorkloadLeaseId, SwarmWorkloadLease>>,
    workload_pressure_feedback: std::sync::Mutex<HashMap<String, SwarmWorkloadPressureFeedback>>,
    peer_pressure_reports: std::sync::Mutex<HashMap<String, SwarmPeerPressureReport>>,
}

impl SwarmPressureGovernor {
    /// Creates a new swarm pressure governor.
    pub fn new(
        config: SwarmPressureGovernorConfig,
        resource_monitor: Arc<ResourceMonitor>,
        pressure_governor: PressureGovernor,
    ) -> Self {
        Self {
            config,
            pressure_governor: Some(pressure_governor),
            resource_monitor,
            total_admission_checks: AtomicU64::new(0),
            regions_admitted: AtomicU64::new(0),
            regions_rejected: AtomicU64::new(0),
            envelope_budget_violations: AtomicU64::new(0),
            max_decision_latency_ns: AtomicU64::new(0),
            workload_leases_acquired: AtomicU64::new(0),
            workload_leases_committed: AtomicU64::new(0),
            workload_leases_renewed: AtomicU64::new(0),
            workload_leases_released: AtomicU64::new(0),
            workload_leases_aborted: AtomicU64::new(0),
            workload_leases_expired: AtomicU64::new(0),
            workload_lease_conflicts: AtomicU64::new(0),
            workload_feedback_reports_recorded: AtomicU64::new(0),
            next_admission_decision_id: AtomicU64::new(1),
            next_workload_lease_id: AtomicU64::new(1),
            active_regions: std::sync::Mutex::new(HashMap::new()),
            workload_leases: std::sync::Mutex::new(HashMap::new()),
            workload_pressure_feedback: std::sync::Mutex::new(HashMap::new()),
            peer_pressure_reports: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Creates a new swarm pressure governor without an underlying pressure governor.
    ///
    /// This is used during runtime initialization when the PressureGovernor
    /// would create a circular dependency. The SwarmPressureGovernor will use
    /// only resource monitor data and swarm coordination for admission decisions.
    pub fn new_without_pressure_governor(
        config: SwarmPressureGovernorConfig,
        resource_monitor: Arc<ResourceMonitor>,
    ) -> Self {
        Self {
            config,
            pressure_governor: None,
            resource_monitor,
            total_admission_checks: AtomicU64::new(0),
            regions_admitted: AtomicU64::new(0),
            regions_rejected: AtomicU64::new(0),
            envelope_budget_violations: AtomicU64::new(0),
            max_decision_latency_ns: AtomicU64::new(0),
            workload_leases_acquired: AtomicU64::new(0),
            workload_leases_committed: AtomicU64::new(0),
            workload_leases_renewed: AtomicU64::new(0),
            workload_leases_released: AtomicU64::new(0),
            workload_leases_aborted: AtomicU64::new(0),
            workload_leases_expired: AtomicU64::new(0),
            workload_lease_conflicts: AtomicU64::new(0),
            workload_feedback_reports_recorded: AtomicU64::new(0),
            next_admission_decision_id: AtomicU64::new(1),
            next_workload_lease_id: AtomicU64::new(1),
            active_regions: std::sync::Mutex::new(HashMap::new()),
            workload_leases: std::sync::Mutex::new(HashMap::new()),
            workload_pressure_feedback: std::sync::Mutex::new(HashMap::new()),
            peer_pressure_reports: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns the active swarm pressure governor configuration.
    #[must_use]
    pub fn config(&self) -> &SwarmPressureGovernorConfig {
        &self.config
    }

    /// Make a comprehensive admission decision for a new region.
    pub fn check_region_admission(
        &self,
        cx: &Cx,
        priority: RegionPriority,
        requested_memory: Option<u64>,
    ) -> Result<SwarmAdmissionDecision, SwarmPressureError> {
        self.check_region_admission_with_declared_resources(
            cx,
            priority,
            requested_memory,
            None,
            None,
            None,
        )
    }

    /// Make a comprehensive admission decision for an agent-swarm workload.
    pub fn check_workload_admission(
        &self,
        cx: &Cx,
        request: &SwarmWorkloadAdmissionRequest,
    ) -> Result<SwarmAdmissionDecision, SwarmPressureError> {
        let decision_start = Instant::now();
        if let Some(reason) = request.validate(decision_start) {
            return Ok(self.rejected_workload_decision(decision_start, request, reason));
        }

        let workload_pressure =
            self.workload_pressure_summary(decision_start, Some(request.workload_id.trim()));
        self.check_region_admission_with_feedback(
            cx,
            request.priority,
            request.requested_memory_bytes,
            request.requested_cpu_ns_per_sec,
            request.requested_io_ops_per_sec,
            workload_pressure,
            Some(request),
        )
    }

    fn check_region_admission_with_declared_resources(
        &self,
        cx: &Cx,
        priority: RegionPriority,
        requested_memory: Option<u64>,
        requested_cpu_ns_per_sec: Option<u64>,
        requested_io_ops_per_sec: Option<u64>,
        workload_request: Option<&SwarmWorkloadAdmissionRequest>,
    ) -> Result<SwarmAdmissionDecision, SwarmPressureError> {
        self.check_region_admission_with_feedback(
            cx,
            priority,
            requested_memory,
            requested_cpu_ns_per_sec,
            requested_io_ops_per_sec,
            SwarmWorkloadPressureSummary::EMPTY,
            workload_request,
        )
    }

    fn check_region_admission_with_feedback(
        &self,
        cx: &Cx,
        priority: RegionPriority,
        requested_memory: Option<u64>,
        requested_cpu_ns_per_sec: Option<u64>,
        requested_io_ops_per_sec: Option<u64>,
        workload_pressure: SwarmWorkloadPressureSummary,
        workload_request: Option<&SwarmWorkloadAdmissionRequest>,
    ) -> Result<SwarmAdmissionDecision, SwarmPressureError> {
        let decision_start = Instant::now();
        self.total_admission_checks.fetch_add(1, Ordering::Relaxed);

        if !self.config.enabled {
            // Swarm governance disabled, always admit while still preserving
            // requested resource accounting in the returned envelope.
            let envelope = self.create_disabled_governance_envelope(
                next_bootstrap_region_id(),
                requested_memory,
                requested_cpu_ns_per_sec,
                requested_io_ops_per_sec,
            )?;
            let pressure_snapshot = self.get_default_pressure_snapshot();
            let reason = Self::contextual_admission_reason(
                workload_request,
                "Swarm governance disabled".to_string(),
            );
            let decision_receipt = self.build_admission_decision_receipt(
                AdmissionDecision::Admit,
                DegradationLevel::None,
                &pressure_snapshot,
                &reason,
                SwarmPeerPressureSummary::EMPTY,
                workload_pressure,
                workload_request,
            );
            self.regions_admitted.fetch_add(1, Ordering::Relaxed);
            return Ok(SwarmAdmissionDecision {
                decision: AdmissionDecision::Admit,
                envelope: Some(envelope),
                pressure_snapshot,
                degradation_level: DegradationLevel::None,
                decision_latency_ns: self.record_decision_latency(decision_start),
                reason,
                decision_receipt,
                workload_receipt: workload_request.map(SwarmAdmissionWorkloadReceipt::from_request),
            });
        }

        // Check system-level resource pressure
        let degradation_level = self
            .resource_monitor
            .pressure()
            .composite_degradation_level();

        // Check runtime-internal pressure via pressure governor
        let (pressure_snapshot, pressure_decision) =
            if let Some(pressure_governor) = &self.pressure_governor {
                let snapshot = pressure_governor.sample_pressure(cx)?;
                let decision = pressure_governor.check_admission(cx)?;
                (snapshot, decision)
            } else {
                // No pressure governor available, use defaults based on resource monitor
                let default_snapshot = self.get_default_pressure_snapshot();
                let default_decision = self.get_default_admission_decision(degradation_level);
                (default_snapshot, default_decision)
            };
        let peer_pressure = self.peer_pressure_summary(decision_start);

        if let Some(requested_memory) = requested_memory
            && self.config.envelope_enforcement_enabled
            && requested_memory > self.config.default_memory_budget_bytes
        {
            self.regions_rejected.fetch_add(1, Ordering::Relaxed);
            self.envelope_budget_violations
                .fetch_add(1, Ordering::Relaxed);
            let reason = Self::contextual_admission_reason(
                workload_request,
                format!(
                    "Requested memory {requested_memory} exceeds region envelope budget {}",
                    self.config.default_memory_budget_bytes
                ),
            );
            let decision_receipt = self.build_admission_decision_receipt(
                AdmissionDecision::Reject,
                degradation_level,
                &pressure_snapshot,
                &reason,
                peer_pressure,
                workload_pressure,
                workload_request,
            );
            return Ok(SwarmAdmissionDecision {
                decision: AdmissionDecision::Reject,
                envelope: None,
                pressure_snapshot,
                degradation_level,
                decision_latency_ns: self.record_decision_latency(decision_start),
                reason,
                decision_receipt,
                workload_receipt: workload_request.map(SwarmAdmissionWorkloadReceipt::from_request),
            });
        }
        if let Some((resource, requested, limit)) =
            self.first_envelope_budget_excess(requested_cpu_ns_per_sec, requested_io_ops_per_sec)
        {
            self.regions_rejected.fetch_add(1, Ordering::Relaxed);
            self.envelope_budget_violations
                .fetch_add(1, Ordering::Relaxed);
            let reason = Self::contextual_admission_reason(
                workload_request,
                format!("Requested {resource} {requested} exceeds region envelope budget {limit}"),
            );
            let decision_receipt = self.build_admission_decision_receipt(
                AdmissionDecision::Reject,
                degradation_level,
                &pressure_snapshot,
                &reason,
                peer_pressure,
                workload_pressure,
                workload_request,
            );
            return Ok(SwarmAdmissionDecision {
                decision: AdmissionDecision::Reject,
                envelope: None,
                pressure_snapshot,
                degradation_level,
                decision_latency_ns: self.record_decision_latency(decision_start),
                reason,
                decision_receipt,
                workload_receipt: workload_request.map(SwarmAdmissionWorkloadReceipt::from_request),
            });
        }

        // Apply swarm-specific logic
        let swarm_decision = self.evaluate_swarm_admission(
            priority,
            &pressure_decision,
            degradation_level,
            requested_memory,
            peer_pressure,
            workload_pressure,
        )?;

        // Create resource envelope if admitted
        let envelope = if matches!(
            swarm_decision.decision,
            AdmissionDecision::Admit | AdmissionDecision::AdmitWithBackpressure
        ) {
            let region_id = next_bootstrap_region_id(); // Will be filled in by caller
            Some(self.create_envelope_for_region(
                region_id,
                requested_memory,
                requested_cpu_ns_per_sec,
                requested_io_ops_per_sec,
            )?)
        } else {
            None
        };

        // Update metrics
        match swarm_decision.decision {
            AdmissionDecision::Admit => {
                self.regions_admitted.fetch_add(1, Ordering::Relaxed);
            }
            AdmissionDecision::Reject => {
                self.regions_rejected.fetch_add(1, Ordering::Relaxed);
            }
            AdmissionDecision::AdmitWithBackpressure => {
                self.regions_admitted.fetch_add(1, Ordering::Relaxed);
            }
        }

        let reason = Self::contextual_admission_reason(workload_request, swarm_decision.reason);
        let decision_receipt = self.build_admission_decision_receipt(
            swarm_decision.decision,
            degradation_level,
            &pressure_snapshot,
            &reason,
            peer_pressure,
            workload_pressure,
            workload_request,
        );

        Ok(SwarmAdmissionDecision {
            decision: swarm_decision.decision,
            envelope,
            pressure_snapshot,
            degradation_level,
            decision_latency_ns: self.record_decision_latency(decision_start),
            reason,
            decision_receipt,
            workload_receipt: workload_request.map(SwarmAdmissionWorkloadReceipt::from_request),
        })
    }

    /// Register a resource envelope for an active region.
    pub fn register_region_envelope(&self, region_id: RegionId, mut envelope: ResourceEnvelope) {
        envelope.region_id = region_id;
        let mut envelopes = self.active_regions.lock().unwrap();
        envelopes.insert(region_id, envelope);
    }

    /// Remove a region's resource envelope when the region closes.
    pub fn unregister_region_envelope(&self, region_id: RegionId) -> Option<ResourceEnvelope> {
        let removed = {
            let mut envelopes = self.active_regions.lock().unwrap();
            envelopes.remove(&region_id)
        };
        if removed.is_some() {
            let _ = self.release_region_workload_leases(region_id);
        }
        removed
    }

    /// Get resource envelope for a region.
    pub fn get_region_envelope(&self, region_id: RegionId) -> Option<ResourceEnvelope> {
        let envelopes = self.active_regions.lock().unwrap();
        envelopes.get(&region_id).cloned()
    }

    /// Acquire a linear workload lease for an admitted workload decision.
    pub fn acquire_workload_lease(
        &self,
        region_id: RegionId,
        request: &SwarmWorkloadAdmissionRequest,
        decision: &SwarmAdmissionDecision,
    ) -> Result<SwarmWorkloadLeaseReceipt, SwarmPressureError> {
        let now = Instant::now();
        if let Some(reason) = request.validate(now) {
            return Err(workload_lease_error(reason));
        }
        if !matches!(
            decision.decision,
            AdmissionDecision::Admit | AdmissionDecision::AdmitWithBackpressure
        ) {
            return Err(workload_lease_error(
                "cannot acquire a lease for a rejected workload",
            ));
        }
        if decision.envelope.is_none() {
            return Err(workload_lease_error(
                "admitted workload decision must include a resource envelope",
            ));
        }
        if let Some(reason) = Self::workload_admission_receipt_mismatch_reason(decision, request) {
            return Err(workload_lease_error(reason));
        }

        let expires_at = self.workload_lease_expiry(now, request.deadline)?;
        let (receipt, expired_receipts) = {
            let mut leases = self.workload_leases.lock().unwrap();
            let expired_receipts = self.expire_stale_workload_leases_locked(&mut leases, now);
            if let Some(reason) = leases
                .values()
                .find_map(|existing| Self::workload_lease_conflict_reason(existing, request))
            {
                self.workload_lease_conflicts
                    .fetch_add(1, Ordering::Relaxed);
                drop(leases);
                self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
                return Err(workload_lease_error(reason));
            }
            if let Some(reason) = self.workload_lease_proof_lane_capacity_reason(&leases, request) {
                self.workload_lease_conflicts
                    .fetch_add(1, Ordering::Relaxed);
                drop(leases);
                self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
                return Err(workload_lease_error(reason));
            }
            if let Some(reason) = self.workload_lease_owner_capacity_reason(&leases, request) {
                self.workload_lease_conflicts
                    .fetch_add(1, Ordering::Relaxed);
                drop(leases);
                self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
                return Err(workload_lease_error(reason));
            }
            if let Some(reason) = self.workload_lease_bead_capacity_reason(&leases, request) {
                self.workload_lease_conflicts
                    .fetch_add(1, Ordering::Relaxed);
                drop(leases);
                self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
                return Err(workload_lease_error(reason));
            }

            let lease_id =
                SwarmWorkloadLeaseId(self.next_workload_lease_id.fetch_add(1, Ordering::Relaxed));
            let lease = SwarmWorkloadLease {
                lease_id,
                workload_id: request.workload_id.trim().to_string(),
                owner: normalized_owner_metadata(&request.owner),
                proof_lane: request.proof_lane,
                priority: request.priority,
                region_id,
                state: SwarmWorkloadLeaseState::Active,
                reserved_memory_bytes: request.requested_memory_bytes,
                reserved_cpu_ns_per_sec: request.requested_cpu_ns_per_sec,
                reserved_io_ops_per_sec: request.requested_io_ops_per_sec,
                cancellation_budget: request.cancellation_budget,
                issued_at: now,
                expires_at,
                last_renewed_at: None,
                terminal_at: None,
                renewal_count: 0,
            };
            let receipt = Self::lease_receipt(
                &lease,
                SwarmWorkloadLeaseTransition::Acquired,
                "workload lease acquired",
            );
            leases.insert(lease_id, lease);
            (receipt, expired_receipts)
        };
        self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
        self.workload_leases_acquired
            .fetch_add(1, Ordering::Relaxed);
        Ok(receipt)
    }

    /// Commit a live workload lease to its caller-owned region.
    pub fn commit_workload_lease(
        &self,
        lease_id: SwarmWorkloadLeaseId,
    ) -> Result<SwarmWorkloadLeaseReceipt, SwarmPressureError> {
        let now = Instant::now();
        let (result, expired_receipts) = {
            let mut leases = self.workload_leases.lock().unwrap();
            let expired_receipts = self.expire_stale_workload_leases_locked(&mut leases, now);
            let result = match leases.get_mut(&lease_id) {
                Some(lease) if lease.state.is_terminal() => Err(workload_lease_error(format!(
                    "cannot commit terminal lease in state {}",
                    lease.state.as_str()
                ))),
                Some(lease) => {
                    if lease.state == SwarmWorkloadLeaseState::Active {
                        lease.state = SwarmWorkloadLeaseState::Committed;
                        self.workload_leases_committed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Self::lease_receipt(
                        lease,
                        SwarmWorkloadLeaseTransition::Committed,
                        "workload lease committed",
                    ))
                }
                None => Err(workload_lease_error("unknown workload lease")),
            };
            (result, expired_receipts)
        };
        self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
        result
    }

    /// Renew a live workload lease by extending from the later of now or its current expiry.
    pub fn renew_workload_lease(
        &self,
        lease_id: SwarmWorkloadLeaseId,
        extension: Duration,
    ) -> Result<SwarmWorkloadLeaseReceipt, SwarmPressureError> {
        if extension.is_zero() {
            return Err(workload_lease_error(
                "lease renewal extension must be non-zero",
            ));
        }

        let now = Instant::now();
        let max_expires_at = self.max_workload_lease_expiry(now)?;
        let (result, expired_receipts) = {
            let mut leases = self.workload_leases.lock().unwrap();
            let expired_receipts = self.expire_stale_workload_leases_locked(&mut leases, now);
            let result = match leases.get_mut(&lease_id) {
                Some(lease) if lease.state.is_terminal() => Err(workload_lease_error(format!(
                    "cannot renew terminal lease in state {}",
                    lease.state.as_str()
                ))),
                Some(lease) => {
                    let renewal_base = lease.expires_at.max(now);
                    match renewal_base.checked_add(extension) {
                        Some(requested_expires_at) => {
                            lease.expires_at = requested_expires_at.min(max_expires_at);
                            lease.last_renewed_at = Some(now);
                            lease.renewal_count = lease.renewal_count.saturating_add(1);
                            self.workload_leases_renewed.fetch_add(1, Ordering::Relaxed);
                            Ok(Self::lease_receipt(
                                lease,
                                SwarmWorkloadLeaseTransition::Renewed,
                                "workload lease renewed",
                            ))
                        }
                        None => Err(workload_lease_error("lease renewal deadline overflow")),
                    }
                }
                None => Err(workload_lease_error("unknown workload lease")),
            };
            (result, expired_receipts)
        };
        self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
        result
    }

    /// Release a live workload lease after successful completion.
    pub fn release_workload_lease(
        &self,
        lease_id: SwarmWorkloadLeaseId,
    ) -> Result<SwarmWorkloadLeaseReceipt, SwarmPressureError> {
        self.complete_workload_lease(
            lease_id,
            SwarmWorkloadLeaseState::Released,
            SwarmWorkloadLeaseTransition::Released,
            "workload lease released",
        )
    }

    /// Abort a live workload lease after cancellation or failed startup.
    pub fn abort_workload_lease(
        &self,
        lease_id: SwarmWorkloadLeaseId,
        reason: impl AsRef<str>,
    ) -> Result<SwarmWorkloadLeaseReceipt, SwarmPressureError> {
        let reason = reason.as_ref().trim();
        let reason = if reason.is_empty() {
            "workload lease aborted"
        } else {
            reason
        };
        self.complete_workload_lease(
            lease_id,
            SwarmWorkloadLeaseState::Aborted,
            SwarmWorkloadLeaseTransition::Aborted,
            reason,
        )
    }

    /// Expire all live workload leases whose deadlines have passed.
    pub fn expire_stale_workload_leases(&self) -> Vec<SwarmWorkloadLeaseReceipt> {
        let now = Instant::now();
        let receipts = {
            let mut leases = self.workload_leases.lock().unwrap();
            self.expire_stale_workload_leases_locked(&mut leases, now)
        };
        self.clear_workload_pressure_feedback_for_receipts(&receipts);
        receipts
    }

    /// Release all live workload leases bound to a closing region.
    pub fn release_region_workload_leases(
        &self,
        region_id: RegionId,
    ) -> Vec<SwarmWorkloadLeaseReceipt> {
        let now = Instant::now();
        let (receipts, expired_receipts) = {
            let mut receipts = Vec::new();
            let mut leases = self.workload_leases.lock().unwrap();
            let expired_receipts = self.expire_stale_workload_leases_locked(&mut leases, now);
            for lease in leases.values_mut() {
                if lease.region_id == region_id && lease.state.is_live() {
                    lease.state = SwarmWorkloadLeaseState::Released;
                    lease.terminal_at = Some(now);
                    self.workload_leases_released
                        .fetch_add(1, Ordering::Relaxed);
                    receipts.push(Self::lease_receipt(
                        lease,
                        SwarmWorkloadLeaseTransition::ReleasedByRegionClose,
                        "workload lease released by region close",
                    ));
                }
            }
            (receipts, expired_receipts)
        };
        self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
        self.clear_workload_pressure_feedback_for_receipts(&receipts);
        receipts
    }

    /// Abort all live workload leases bound to a cancelled region/admission attempt.
    pub fn abort_region_workload_leases(
        &self,
        region_id: RegionId,
        reason: impl AsRef<str>,
    ) -> Vec<SwarmWorkloadLeaseReceipt> {
        let now = Instant::now();
        let reason = reason.as_ref().trim();
        let reason = if reason.is_empty() {
            "workload leases aborted by region cancellation"
        } else {
            reason
        };
        let (receipts, expired_receipts) = {
            let mut receipts = Vec::new();
            let mut leases = self.workload_leases.lock().unwrap();
            let expired_receipts = self.expire_stale_workload_leases_locked(&mut leases, now);
            for lease in leases.values_mut() {
                if lease.region_id == region_id && lease.state.is_live() {
                    lease.state = SwarmWorkloadLeaseState::Aborted;
                    lease.terminal_at = Some(now);
                    self.workload_leases_aborted.fetch_add(1, Ordering::Relaxed);
                    receipts.push(Self::lease_receipt(
                        lease,
                        SwarmWorkloadLeaseTransition::Aborted,
                        reason,
                    ));
                }
            }
            (receipts, expired_receipts)
        };
        self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
        self.clear_workload_pressure_feedback_for_receipts(&receipts);
        receipts
    }

    /// Get a workload lease by id.
    pub fn get_workload_lease(&self, lease_id: SwarmWorkloadLeaseId) -> Option<SwarmWorkloadLease> {
        let leases = self.workload_leases.lock().unwrap();
        leases.get(&lease_id).cloned()
    }

    /// Return a deterministic schedule snapshot of all currently live workload leases.
    pub fn workload_lease_schedule(&self) -> Vec<SwarmWorkloadLeaseScheduleEntry> {
        let now = Instant::now();
        let (mut live_leases, expired_receipts): (Vec<_>, Vec<_>) = {
            let mut leases = self.workload_leases.lock().unwrap();
            let expired_receipts = self.expire_stale_workload_leases_locked(&mut leases, now);
            let live_leases = leases
                .values()
                .filter(|lease| lease.state.is_live())
                .cloned()
                .collect();
            (live_leases, expired_receipts)
        };
        self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
        let feedback_by_workload = self.live_workload_feedback_by_id(now);
        let resource_degradation_level = self
            .resource_monitor
            .pressure()
            .composite_degradation_level();
        let resource_pressure_scaled =
            resource_pressure_scaled_from_degradation(resource_degradation_level);
        let aging_step = self.workload_lease_starvation_aging_step();
        let workload_pressure_threshold = self.workload_feedback_backpressure_threshold();
        live_leases.sort_by_key(|lease| {
            Self::workload_lease_schedule_key(
                lease,
                feedback_by_workload.get(lease.workload_id.as_str()),
                resource_degradation_level,
                now,
                aging_step,
            )
        });
        live_leases
            .iter()
            .enumerate()
            .map(|(rank, lease)| {
                Self::workload_lease_schedule_entry(
                    lease,
                    rank as u64,
                    feedback_by_workload.get(lease.workload_id.as_str()),
                    resource_degradation_level,
                    resource_pressure_scaled,
                    workload_pressure_threshold,
                    now,
                    aging_step,
                )
            })
            .collect()
    }

    /// Return a read-only audit snapshot for workload lease linearity.
    ///
    /// This deliberately does not mutate stale leases. Callers can use
    /// `expire_stale_workload_leases` or region-close release paths after
    /// observing the snapshot.
    pub fn workload_lease_audit_snapshot(&self) -> SwarmWorkloadLeaseAuditSnapshot {
        let now = Instant::now();
        let mut active_lease_count = 0u64;
        let mut committed_lease_count = 0u64;
        let mut released_lease_count = 0u64;
        let mut aborted_lease_count = 0u64;
        let mut expired_lease_count = 0u64;
        let mut live_unregistered_region_count = 0u64;
        let mut live_expired_count = 0u64;
        let mut terminal_missing_terminal_at_count = 0u64;
        let mut live_workload_ids: HashMap<String, u64> = HashMap::new();
        let mut live_owner_agents: HashMap<String, u64> = HashMap::new();
        let mut live_bead_ids: HashMap<String, u64> = HashMap::new();
        let mut live_reservation_scopes: HashMap<String, u64> = HashMap::new();

        {
            let active_regions = self.active_regions.lock().unwrap();
            let leases = self.workload_leases.lock().unwrap();
            for lease in leases.values() {
                match lease.state {
                    SwarmWorkloadLeaseState::Active => active_lease_count += 1,
                    SwarmWorkloadLeaseState::Committed => committed_lease_count += 1,
                    SwarmWorkloadLeaseState::Released => released_lease_count += 1,
                    SwarmWorkloadLeaseState::Aborted => aborted_lease_count += 1,
                    SwarmWorkloadLeaseState::Expired => expired_lease_count += 1,
                }

                if lease.state.is_live() {
                    if !active_regions.contains_key(&lease.region_id) {
                        live_unregistered_region_count += 1;
                    }
                    if lease.expires_at <= now {
                        live_expired_count += 1;
                    }
                    *live_workload_ids
                        .entry(lease.workload_id.trim().to_string())
                        .or_insert(0) += 1;
                    if let Some(agent_name) =
                        normalized_optional_string(Some(&lease.owner.agent_name))
                    {
                        *live_owner_agents.entry(agent_name).or_insert(0) += 1;
                    }
                    if let Some(bead_id) =
                        normalized_optional_string(lease.owner.bead_id.as_deref())
                    {
                        *live_bead_ids.entry(bead_id).or_insert(0) += 1;
                    }
                    if let Some(scope) = lease
                        .owner
                        .reservation_scope
                        .as_deref()
                        .map(str::trim)
                        .filter(|scope| !scope.is_empty())
                    {
                        *live_reservation_scopes
                            .entry(scope.to_string())
                            .or_insert(0) += 1;
                    }
                } else if lease.terminal_at.is_none() {
                    terminal_missing_terminal_at_count += 1;
                }
            }
        }

        let duplicate_live_workload_id_count =
            duplicate_count_from_group_counts(live_workload_ids.values());
        let duplicate_live_owner_agent_count =
            duplicate_count_from_group_counts(live_owner_agents.values());
        let duplicate_live_bead_id_count =
            duplicate_count_from_group_counts(live_bead_ids.values());
        let duplicate_live_reservation_scope_count =
            duplicate_count_from_group_counts(live_reservation_scopes.values());
        let live_lease_count = active_lease_count + committed_lease_count;
        let terminal_lease_count = released_lease_count + aborted_lease_count + expired_lease_count;
        let leak_detected = live_unregistered_region_count > 0
            || live_expired_count > 0
            || terminal_missing_terminal_at_count > 0
            || duplicate_live_workload_id_count > 0
            || duplicate_live_reservation_scope_count > 0;
        let reason = format!(
            "workload_lease_audit live_lease_count={live_lease_count} active_lease_count={active_lease_count} committed_lease_count={committed_lease_count} terminal_lease_count={terminal_lease_count} released_lease_count={released_lease_count} aborted_lease_count={aborted_lease_count} expired_lease_count={expired_lease_count} live_unregistered_region_count={live_unregistered_region_count} live_expired_count={live_expired_count} terminal_missing_terminal_at_count={terminal_missing_terminal_at_count} duplicate_live_workload_id_count={duplicate_live_workload_id_count} duplicate_live_owner_agent_count={duplicate_live_owner_agent_count} duplicate_live_bead_id_count={duplicate_live_bead_id_count} duplicate_live_reservation_scope_count={duplicate_live_reservation_scope_count} leak_detected={leak_detected}"
        );

        SwarmWorkloadLeaseAuditSnapshot {
            live_lease_count,
            active_lease_count,
            committed_lease_count,
            terminal_lease_count,
            released_lease_count,
            aborted_lease_count,
            expired_lease_count,
            live_unregistered_region_count,
            live_expired_count,
            terminal_missing_terminal_at_count,
            duplicate_live_workload_id_count,
            duplicate_live_owner_agent_count,
            duplicate_live_bead_id_count,
            duplicate_live_reservation_scope_count,
            leak_detected,
            reason,
        }
    }

    /// Record the latest pressure report from a peer runtime instance.
    pub fn record_peer_pressure(
        &self,
        instance_id: impl Into<String>,
        overall_pressure: f64,
        degradation_level: DegradationLevel,
    ) -> Result<(), SwarmPressureError> {
        let instance_id = instance_id.into().trim().to_string();
        if instance_id.is_empty() {
            return Err(SwarmPressureError::SwarmCoordinationFailed {
                reason: "peer instance id must be non-empty".to_string(),
            });
        }
        if !overall_pressure.is_finite() || overall_pressure < 0.0 {
            return Err(SwarmPressureError::SwarmCoordinationFailed {
                reason: "peer pressure must be finite and non-negative".to_string(),
            });
        }

        let report = SwarmPeerPressureReport {
            instance_id: instance_id.clone(),
            overall_pressure,
            degradation_level,
            reported_at: Instant::now(),
        };
        let mut reports = self.peer_pressure_reports.lock().unwrap();
        prune_stale_peer_pressure_reports_locked(
            &mut reports,
            self.config.peer_pressure_max_age,
            report.reported_at,
        );
        reports.insert(instance_id, report);
        Ok(())
    }

    /// Remove a peer pressure report.
    pub fn clear_peer_pressure(&self, instance_id: &str) -> Option<SwarmPeerPressureReport> {
        let mut reports = self.peer_pressure_reports.lock().unwrap();
        reports.remove(instance_id.trim())
    }

    /// Remove stale peer pressure reports and return the number pruned.
    pub fn prune_stale_peer_pressure_reports(&self) -> usize {
        let mut reports = self.peer_pressure_reports.lock().unwrap();
        prune_stale_peer_pressure_reports_locked(
            &mut reports,
            self.config.peer_pressure_max_age,
            Instant::now(),
        )
    }

    /// Record explicit pressure feedback for a workload.
    pub fn record_workload_pressure_feedback(
        &self,
        mut feedback: SwarmWorkloadPressureFeedback,
    ) -> Result<(), SwarmPressureError> {
        if let Some(reason) = feedback.validate() {
            return Err(SwarmPressureError::SwarmCoordinationFailed { reason });
        }

        feedback.workload_id = feedback.workload_id.trim().to_string();
        feedback.owner = normalized_owner_metadata(&feedback.owner);
        let now = Instant::now();
        let mut reports = self.workload_pressure_feedback.lock().unwrap();
        prune_stale_workload_pressure_feedback_locked(
            &mut reports,
            self.config.workload_feedback_max_age,
            now,
        );
        reports.insert(feedback.workload_id.clone(), feedback);
        self.workload_feedback_reports_recorded
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Remove pressure feedback for a workload.
    pub fn clear_workload_pressure_feedback(
        &self,
        workload_id: &str,
    ) -> Option<SwarmWorkloadPressureFeedback> {
        let mut reports = self.workload_pressure_feedback.lock().unwrap();
        reports.remove(workload_id.trim())
    }

    /// Remove stale workload pressure feedback and return the number pruned.
    pub fn prune_stale_workload_pressure_feedback(&self) -> usize {
        let mut reports = self.workload_pressure_feedback.lock().unwrap();
        prune_stale_workload_pressure_feedback_locked(
            &mut reports,
            self.config.workload_feedback_max_age,
            Instant::now(),
        )
    }

    /// Returns current swarm governance metrics.
    pub fn metrics(&self) -> SwarmPressureMetrics {
        let (
            active_region_count,
            max_memory_utilization_scaled,
            max_cpu_utilization_scaled,
            max_io_utilization_scaled,
        ) = {
            let envelopes = self.active_regions.lock().unwrap();
            (
                envelopes.len() as u64,
                envelopes
                    .values()
                    .map(|envelope| scale_pressure_for_metrics(envelope.memory_utilization()))
                    .max()
                    .unwrap_or(0),
                envelopes
                    .values()
                    .map(|envelope| scale_pressure_for_metrics(envelope.cpu_utilization()))
                    .max()
                    .unwrap_or(0),
                envelopes
                    .values()
                    .map(|envelope| scale_pressure_for_metrics(envelope.io_utilization()))
                    .max()
                    .unwrap_or(0),
            )
        };
        let (active_workload_lease_count, terminal_workload_lease_count) = {
            let leases = self.workload_leases.lock().unwrap();
            let active = leases
                .values()
                .filter(|lease| lease.state.is_live())
                .count() as u64;
            (active, leases.len() as u64 - active)
        };
        let peer_pressure = self.peer_pressure_summary(Instant::now());
        let workload_pressure = self.workload_pressure_summary(Instant::now(), None);
        SwarmPressureMetrics {
            total_admission_checks: self.total_admission_checks.load(Ordering::Relaxed),
            regions_admitted: self.regions_admitted.load(Ordering::Relaxed),
            regions_rejected: self.regions_rejected.load(Ordering::Relaxed),
            envelope_budget_violations: self.envelope_budget_violations.load(Ordering::Relaxed),
            max_decision_latency_ns: self.max_decision_latency_ns.load(Ordering::Relaxed),
            active_region_count,
            max_memory_utilization_scaled,
            max_cpu_utilization_scaled,
            max_io_utilization_scaled,
            workload_leases_acquired: self.workload_leases_acquired.load(Ordering::Relaxed),
            workload_leases_committed: self.workload_leases_committed.load(Ordering::Relaxed),
            workload_leases_renewed: self.workload_leases_renewed.load(Ordering::Relaxed),
            workload_leases_released: self.workload_leases_released.load(Ordering::Relaxed),
            workload_leases_aborted: self.workload_leases_aborted.load(Ordering::Relaxed),
            workload_leases_expired: self.workload_leases_expired.load(Ordering::Relaxed),
            workload_lease_conflicts: self.workload_lease_conflicts.load(Ordering::Relaxed),
            active_workload_lease_count,
            terminal_workload_lease_count,
            workload_feedback_reports_recorded: self
                .workload_feedback_reports_recorded
                .load(Ordering::Relaxed),
            live_workload_feedback_reports: workload_pressure.live_report_count,
            max_workload_feedback_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_overall_pressure,
            ),
            workload_feedback_dominant_pressure_source: workload_pressure.dominant_pressure_source,
            max_workload_feedback_queue_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_queue_pressure,
            ),
            max_workload_feedback_disk_io_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_disk_io_pressure,
            ),
            max_workload_feedback_rch_queue_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_rch_queue_pressure,
            ),
            max_workload_feedback_validation_frontier_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_validation_frontier_pressure,
            ),
            max_workload_feedback_cancellation_tail_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_cancellation_tail_pressure,
            ),
            live_peer_pressure_reports: peer_pressure.live_report_count,
            max_peer_pressure_scaled: scale_pressure_for_metrics(
                peer_pressure.max_overall_pressure,
            ),
            max_peer_degradation_level: peer_pressure.max_degradation_level as u8,
        }
    }

    // Private helper methods

    fn complete_workload_lease(
        &self,
        lease_id: SwarmWorkloadLeaseId,
        terminal_state: SwarmWorkloadLeaseState,
        transition: SwarmWorkloadLeaseTransition,
        reason: impl AsRef<str>,
    ) -> Result<SwarmWorkloadLeaseReceipt, SwarmPressureError> {
        debug_assert!(terminal_state.is_terminal());
        let now = Instant::now();
        let (result, workload_id, expired_receipts) = {
            let mut leases = self.workload_leases.lock().unwrap();
            let expired_receipts = self.expire_stale_workload_leases_locked(&mut leases, now);
            let mut completed_workload_id = None;
            let result = match leases.get_mut(&lease_id) {
                Some(lease) if lease.state.is_terminal() => Err(workload_lease_error(format!(
                    "cannot complete terminal lease in state {}",
                    lease.state.as_str()
                ))),
                Some(lease) => {
                    lease.state = terminal_state;
                    lease.terminal_at = Some(now);
                    match terminal_state {
                        SwarmWorkloadLeaseState::Released => {
                            self.workload_leases_released
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        SwarmWorkloadLeaseState::Aborted => {
                            self.workload_leases_aborted.fetch_add(1, Ordering::Relaxed);
                        }
                        SwarmWorkloadLeaseState::Expired => {
                            self.workload_leases_expired.fetch_add(1, Ordering::Relaxed);
                        }
                        SwarmWorkloadLeaseState::Active | SwarmWorkloadLeaseState::Committed => {}
                    }
                    completed_workload_id = Some(lease.workload_id.clone());
                    Ok(Self::lease_receipt(lease, transition, reason.as_ref()))
                }
                None => Err(workload_lease_error("unknown workload lease")),
            };
            (result, completed_workload_id, expired_receipts)
        };
        self.clear_workload_pressure_feedback_for_receipts(&expired_receipts);
        if let Some(workload_id) = workload_id {
            self.clear_workload_pressure_feedback_for_workload(&workload_id);
        }
        result
    }

    fn workload_lease_conflict_reason(
        existing: &SwarmWorkloadLease,
        request: &SwarmWorkloadAdmissionRequest,
    ) -> Option<String> {
        if !existing.state.is_live() {
            return None;
        }

        let requested_workload_id = request.workload_id.trim();
        if existing.workload_id == requested_workload_id {
            return Some(format!(
                "workload {requested_workload_id} already has a live lease"
            ));
        }

        let existing_scope = existing
            .owner
            .reservation_scope
            .as_deref()
            .and_then(|scope| normalized_reservation_scope(Some(scope)));
        let requested_scope =
            normalized_reservation_scope(request.owner.reservation_scope.as_deref());
        if let (Some(existing_scope), Some(requested_scope)) =
            (existing_scope.as_deref(), requested_scope.as_deref())
            && existing_scope == requested_scope
        {
            return Some(format!(
                "reservation_scope {requested_scope} already has a live workload lease \
                 for workload {} live proof_lane={} requested proof_lane={}",
                existing.workload_id,
                existing.proof_lane.as_str(),
                request.proof_lane.as_str()
            ));
        }

        None
    }

    fn workload_lease_proof_lane_capacity_reason(
        &self,
        leases: &HashMap<SwarmWorkloadLeaseId, SwarmWorkloadLease>,
        request: &SwarmWorkloadAdmissionRequest,
    ) -> Option<String> {
        let limit = self.config.max_live_workload_leases_per_proof_lane;
        if limit == 0 {
            return None;
        }

        let live_lane_count = leases
            .values()
            .filter(|lease| lease.state.is_live() && lease.proof_lane == request.proof_lane)
            .count();
        if live_lane_count < limit {
            return None;
        }

        Some(format!(
            "proof_lane {} already has {live_lane_count} live workload leases; \
             max_live_workload_leases_per_proof_lane={limit}",
            request.proof_lane.as_str()
        ))
    }

    fn workload_lease_owner_capacity_reason(
        &self,
        leases: &HashMap<SwarmWorkloadLeaseId, SwarmWorkloadLease>,
        request: &SwarmWorkloadAdmissionRequest,
    ) -> Option<String> {
        let limit = self.config.max_live_workload_leases_per_owner;
        if limit == 0 {
            return None;
        }

        let owner_agent = request.owner.agent_name.trim();
        let live_owner_count = leases
            .values()
            .filter(|lease| lease.state.is_live() && lease.owner.agent_name == owner_agent)
            .count();
        if live_owner_count < limit {
            return None;
        }

        Some(format!(
            "owner_agent {owner_agent} already has {live_owner_count} live workload leases; \
             max_live_workload_leases_per_owner={limit}"
        ))
    }

    fn workload_lease_bead_capacity_reason(
        &self,
        leases: &HashMap<SwarmWorkloadLeaseId, SwarmWorkloadLease>,
        request: &SwarmWorkloadAdmissionRequest,
    ) -> Option<String> {
        let limit = self.config.max_live_workload_leases_per_bead;
        if limit == 0 {
            return None;
        }

        let bead_id = normalized_optional_string(request.owner.bead_id.as_deref())?;
        let live_bead_count = leases
            .values()
            .filter(|lease| {
                lease.state.is_live() && lease.owner.bead_id.as_deref() == Some(bead_id.as_str())
            })
            .count();
        if live_bead_count < limit {
            return None;
        }

        Some(format!(
            "bead_id {bead_id} already has {live_bead_count} live workload leases; \
             max_live_workload_leases_per_bead={limit}"
        ))
    }

    fn workload_admission_receipt_mismatch_reason(
        decision: &SwarmAdmissionDecision,
        request: &SwarmWorkloadAdmissionRequest,
    ) -> Option<String> {
        let receipt = match &decision.workload_receipt {
            Some(receipt) => receipt,
            None => {
                return Some(
                    "admitted workload decision must include a workload admission receipt"
                        .to_string(),
                );
            }
        };

        if receipt.matches_request(request) {
            return None;
        }

        Some(format!(
            "admission workload receipt does not match request: \
             decision_workload_id={} request_workload_id={} \
             decision_owner_agent={} request_owner_agent={} \
             decision_proof_lane={} request_proof_lane={}",
            receipt.workload_id,
            request.workload_id.trim(),
            receipt.owner.agent_name,
            request.owner.agent_name.trim(),
            receipt.proof_lane.as_str(),
            request.proof_lane.as_str()
        ))
    }

    fn expire_stale_workload_leases_locked(
        &self,
        leases: &mut HashMap<SwarmWorkloadLeaseId, SwarmWorkloadLease>,
        now: Instant,
    ) -> Vec<SwarmWorkloadLeaseReceipt> {
        let mut receipts = Vec::new();
        for lease in leases.values_mut() {
            if lease.state.is_live() && lease.expires_at <= now {
                lease.state = SwarmWorkloadLeaseState::Expired;
                lease.terminal_at = Some(now);
                self.workload_leases_expired.fetch_add(1, Ordering::Relaxed);
                receipts.push(Self::lease_receipt(
                    lease,
                    SwarmWorkloadLeaseTransition::Expired,
                    "workload lease expired",
                ));
            }
        }
        receipts
    }

    fn workload_lease_expiry(
        &self,
        now: Instant,
        requested_deadline: Option<Instant>,
    ) -> Result<Instant, SwarmPressureError> {
        let max_expires_at = self.max_workload_lease_expiry(now)?;
        if let Some(deadline) = requested_deadline {
            if deadline <= now {
                return Err(workload_lease_error("lease deadline has already expired"));
            }
            return Ok(deadline.min(max_expires_at));
        }

        let default_ttl = self
            .config
            .default_workload_lease_ttl
            .min(self.config.max_workload_lease_ttl);
        if default_ttl.is_zero() {
            return Err(workload_lease_error(
                "default_workload_lease_ttl must be non-zero without an explicit deadline",
            ));
        }
        now.checked_add(default_ttl)
            .ok_or_else(|| workload_lease_error("lease default deadline overflow"))
    }

    fn max_workload_lease_expiry(&self, now: Instant) -> Result<Instant, SwarmPressureError> {
        if self.config.max_workload_lease_ttl.is_zero() {
            return Err(workload_lease_error(
                "max_workload_lease_ttl must be non-zero",
            ));
        }
        now.checked_add(self.config.max_workload_lease_ttl)
            .ok_or_else(|| workload_lease_error("lease max deadline overflow"))
    }

    fn lease_receipt(
        lease: &SwarmWorkloadLease,
        transition: SwarmWorkloadLeaseTransition,
        reason: impl AsRef<str>,
    ) -> SwarmWorkloadLeaseReceipt {
        let transition_reason = reason.as_ref().to_string();
        let reason = lease.context_reason(&transition_reason);
        let replay_pointer = format!(
            "swarm-workload-lease://lease/{}/transition/{}",
            lease.lease_id.as_u64(),
            transition.as_str()
        );
        SwarmWorkloadLeaseReceipt {
            lease_id: lease.lease_id,
            replay_pointer,
            workload_id: lease.workload_id.clone(),
            owner: lease.owner.clone(),
            proof_lane: lease.proof_lane,
            region_id: lease.region_id,
            priority: lease.priority,
            reserved_memory_bytes: lease.reserved_memory_bytes,
            reserved_cpu_ns_per_sec: lease.reserved_cpu_ns_per_sec,
            reserved_io_ops_per_sec: lease.reserved_io_ops_per_sec,
            cancellation_budget: lease.cancellation_budget,
            state: lease.state,
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            terminal_at: lease.terminal_at,
            transition,
            transition_reason,
            reason,
        }
    }

    fn workload_lease_schedule_key(
        lease: &SwarmWorkloadLease,
        feedback: Option<&SwarmWorkloadPressureFeedback>,
        resource_degradation_level: DegradationLevel,
        now: Instant,
        aging_step: Duration,
    ) -> (u8, u8, i64, Instant, u8, u8, Instant, u64) {
        (
            Self::resource_pressure_schedule_penalty(lease.priority, resource_degradation_level),
            Self::effective_priority_schedule_rank(lease, now, aging_step),
            Self::feedback_max_pressure_scaled(feedback),
            lease.expires_at,
            Self::proof_lane_schedule_rank(lease.proof_lane),
            Self::lease_state_schedule_rank(lease.state),
            lease.issued_at,
            lease.lease_id.as_u64(),
        )
    }

    fn workload_lease_schedule_entry(
        lease: &SwarmWorkloadLease,
        scheduling_rank: u64,
        feedback: Option<&SwarmWorkloadPressureFeedback>,
        resource_degradation_level: DegradationLevel,
        resource_pressure_scaled: i64,
        workload_pressure_threshold: f64,
        now: Instant,
        aging_step: Duration,
    ) -> SwarmWorkloadLeaseScheduleEntry {
        let replay_pointer = format!(
            "swarm-workload-lease://lease/{}/schedule/{scheduling_rank}",
            lease.lease_id.as_u64()
        );
        let effective_priority_rank =
            Self::effective_priority_schedule_rank(lease, now, aging_step);
        let starvation_aging_discount = Self::starvation_aging_discount(lease, now, aging_step);
        let (
            queue_pressure_scaled,
            disk_io_pressure_scaled,
            rch_queue_pressure_scaled,
            validation_frontier_pressure_scaled,
            cancellation_tail_pressure_scaled,
            max_pressure_scaled,
        ) = Self::schedule_pressure_fields(feedback);
        let dominant_pressure_source = feedback.map_or(
            SwarmWorkloadPressureSource::None,
            SwarmWorkloadPressureFeedback::dominant_pressure_source,
        );
        let workload_pressure_deferral =
            Self::workload_pressure_schedule_deferral(feedback, workload_pressure_threshold);
        let resource_pressure_deferral =
            Self::resource_pressure_schedule_penalty(lease.priority, resource_degradation_level)
                > 0;
        let wait_age_ms = duration_as_u64_ms(now.saturating_duration_since(lease.issued_at));
        let time_to_expiry_ms = duration_as_u64_ms(lease.expires_at.saturating_duration_since(now));
        SwarmWorkloadLeaseScheduleEntry {
            scheduling_rank,
            replay_pointer,
            lease_id: lease.lease_id,
            workload_id: lease.workload_id.clone(),
            owner: lease.owner.clone(),
            proof_lane: lease.proof_lane,
            priority: lease.priority,
            effective_priority_rank,
            starvation_aging_discount,
            region_id: lease.region_id,
            state: lease.state,
            reserved_memory_bytes: lease.reserved_memory_bytes,
            reserved_cpu_ns_per_sec: lease.reserved_cpu_ns_per_sec,
            reserved_io_ops_per_sec: lease.reserved_io_ops_per_sec,
            cancellation_budget_ms: lease.cancellation_budget.map(duration_as_u64_ms),
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            last_renewed_at: lease.last_renewed_at,
            renewal_count: lease.renewal_count,
            wait_age_ms,
            time_to_expiry_ms,
            pressure_feedback_present: feedback.is_some(),
            queue_pressure_scaled,
            disk_io_pressure_scaled,
            rch_queue_pressure_scaled,
            validation_frontier_pressure_scaled,
            cancellation_tail_pressure_scaled,
            max_pressure_scaled,
            workload_pressure_deferral,
            dominant_pressure_source,
            resource_degradation_level,
            resource_pressure_scaled,
            resource_pressure_deferral,
            reason: Self::workload_lease_schedule_reason(
                lease,
                feedback,
                resource_degradation_level,
                resource_pressure_scaled,
                workload_pressure_threshold,
                now,
                aging_step,
            ),
        }
    }

    fn live_workload_feedback_by_id(
        &self,
        now: Instant,
    ) -> HashMap<String, SwarmWorkloadPressureFeedback> {
        let mut reports = self.workload_pressure_feedback.lock().unwrap();
        let _ = prune_stale_workload_pressure_feedback_locked(
            &mut reports,
            self.config.workload_feedback_max_age,
            now,
        );
        reports
            .iter()
            .map(|(workload_id, feedback)| (workload_id.clone(), feedback.clone()))
            .collect()
    }

    fn clear_workload_pressure_feedback_for_receipts(
        &self,
        receipts: &[SwarmWorkloadLeaseReceipt],
    ) {
        if receipts.is_empty() {
            return;
        }

        let mut reports = self.workload_pressure_feedback.lock().unwrap();
        for receipt in receipts {
            if receipt.state.is_terminal() {
                reports.remove(receipt.workload_id.trim());
            }
        }
    }

    fn clear_workload_pressure_feedback_for_workload(&self, workload_id: &str) {
        let workload_id = workload_id.trim();
        if workload_id.is_empty() {
            return;
        }

        let mut reports = self.workload_pressure_feedback.lock().unwrap();
        reports.remove(workload_id);
    }

    fn schedule_pressure_fields(
        feedback: Option<&SwarmWorkloadPressureFeedback>,
    ) -> (i64, i64, i64, i64, i64, i64) {
        if let Some(feedback) = feedback {
            (
                scale_pressure_for_metrics(feedback.queue_pressure),
                scale_pressure_for_metrics(feedback.disk_io_pressure),
                scale_pressure_for_metrics(feedback.rch_queue_pressure),
                scale_pressure_for_metrics(feedback.validation_frontier_pressure),
                scale_pressure_for_metrics(feedback.cancellation_tail_pressure),
                scale_pressure_for_metrics(feedback.max_pressure()),
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        }
    }

    fn feedback_max_pressure_scaled(feedback: Option<&SwarmWorkloadPressureFeedback>) -> i64 {
        feedback.map_or(0, |feedback| {
            scale_pressure_for_metrics(feedback.max_pressure())
        })
    }

    fn workload_pressure_schedule_deferral(
        feedback: Option<&SwarmWorkloadPressureFeedback>,
        threshold: f64,
    ) -> bool {
        let Some(feedback) = feedback else {
            return false;
        };
        let threshold = if threshold.is_finite() && threshold >= 0.0 {
            threshold
        } else {
            DEFAULT_WORKLOAD_FEEDBACK_BACKPRESSURE_THRESHOLD
        };
        feedback.max_pressure() >= threshold
    }

    fn effective_priority_schedule_rank(
        lease: &SwarmWorkloadLease,
        now: Instant,
        aging_step: Duration,
    ) -> u8 {
        Self::priority_schedule_rank(lease.priority)
            .saturating_sub(Self::starvation_aging_discount(lease, now, aging_step))
    }

    fn starvation_aging_discount(
        lease: &SwarmWorkloadLease,
        now: Instant,
        aging_step: Duration,
    ) -> u8 {
        let base_rank = Self::priority_schedule_rank(lease.priority);
        if base_rank <= 1 {
            return 0;
        }

        let max_discount = base_rank - 1;
        let wait_age = now.saturating_duration_since(lease.issued_at);
        let aging_step = if aging_step.is_zero() {
            DEFAULT_WORKLOAD_LEASE_STARVATION_AGING_STEP
        } else {
            aging_step
        };
        let discount = wait_age.as_nanos() / aging_step.as_nanos();
        discount.min(u128::from(max_discount)) as u8
    }

    fn workload_lease_schedule_reason(
        lease: &SwarmWorkloadLease,
        feedback: Option<&SwarmWorkloadPressureFeedback>,
        resource_degradation_level: DegradationLevel,
        resource_pressure_scaled: i64,
        workload_pressure_threshold: f64,
        now: Instant,
        aging_step: Duration,
    ) -> String {
        let mut base = if let Some(feedback) = feedback {
            format!(
                "live workload lease scheduled with pressure feedback dominant_pressure_source={} queue={} disk_io={} rch_queue={} validation_frontier={} cancellation_tail={} max={}",
                feedback.dominant_pressure_source().as_str(),
                scale_pressure_for_metrics(feedback.queue_pressure),
                scale_pressure_for_metrics(feedback.disk_io_pressure),
                scale_pressure_for_metrics(feedback.rch_queue_pressure),
                scale_pressure_for_metrics(feedback.validation_frontier_pressure),
                scale_pressure_for_metrics(feedback.cancellation_tail_pressure),
                scale_pressure_for_metrics(feedback.max_pressure())
            )
        } else {
            "live workload lease scheduled without pressure feedback".to_string()
        };
        let wait_age_ms = duration_as_u64_ms(now.saturating_duration_since(lease.issued_at));
        let time_to_expiry_ms = duration_as_u64_ms(lease.expires_at.saturating_duration_since(now));
        let cancellation_budget_ms =
            optional_u64_reason_field(lease.cancellation_budget.map(duration_as_u64_ms));
        base.push_str(&format!(
            " wait_age_ms={wait_age_ms} time_to_expiry_ms={time_to_expiry_ms} cancellation_budget_ms={cancellation_budget_ms} workload_pressure_deferral={} resource_degradation_level={} resource_pressure_scaled={resource_pressure_scaled} resource_pressure_deferral={}",
            Self::workload_pressure_schedule_deferral(feedback, workload_pressure_threshold),
            degradation_level_as_str(resource_degradation_level),
            Self::resource_pressure_schedule_penalty(lease.priority, resource_degradation_level) > 0
        ));
        let starvation_aging_discount = Self::starvation_aging_discount(lease, now, aging_step);
        if starvation_aging_discount > 0 {
            let effective_priority_rank =
                Self::effective_priority_schedule_rank(lease, now, aging_step);
            base.push_str(&format!(
                " starvation_aging_discount={starvation_aging_discount} effective_priority_rank={effective_priority_rank}"
            ));
        }
        lease.context_reason(&base)
    }

    const fn resource_pressure_schedule_penalty(
        priority: RegionPriority,
        resource_degradation_level: DegradationLevel,
    ) -> u8 {
        match (resource_degradation_level, priority) {
            (DegradationLevel::Light, RegionPriority::BestEffort) => 1,
            (
                DegradationLevel::Moderate | DegradationLevel::Heavy | DegradationLevel::Emergency,
                RegionPriority::Low | RegionPriority::BestEffort,
            ) => 1,
            _ => 0,
        }
    }

    fn workload_lease_starvation_aging_step(&self) -> Duration {
        if self.config.workload_lease_starvation_aging_step.is_zero() {
            DEFAULT_WORKLOAD_LEASE_STARVATION_AGING_STEP
        } else {
            self.config.workload_lease_starvation_aging_step
        }
    }

    const fn priority_schedule_rank(priority: RegionPriority) -> u8 {
        match priority {
            RegionPriority::Critical => 0,
            RegionPriority::High => 1,
            RegionPriority::Normal => 2,
            RegionPriority::Low => 3,
            RegionPriority::BestEffort => 4,
        }
    }

    const fn proof_lane_schedule_rank(proof_lane: SwarmProofLaneKind) -> u8 {
        match proof_lane {
            SwarmProofLaneKind::ReleaseProof => 0,
            SwarmProofLaneKind::CargoCheckAllTargets => 1,
            SwarmProofLaneKind::ClippyAllTargets => 2,
            SwarmProofLaneKind::CargoCheckLib => 3,
            SwarmProofLaneKind::Test => 4,
            SwarmProofLaneKind::Rustdoc => 5,
            SwarmProofLaneKind::RustfmtCheck => 6,
            SwarmProofLaneKind::Other => 7,
            SwarmProofLaneKind::SourceOnly => 8,
        }
    }

    const fn lease_state_schedule_rank(state: SwarmWorkloadLeaseState) -> u8 {
        match state {
            SwarmWorkloadLeaseState::Active => 0,
            SwarmWorkloadLeaseState::Committed => 1,
            SwarmWorkloadLeaseState::Released
            | SwarmWorkloadLeaseState::Aborted
            | SwarmWorkloadLeaseState::Expired => 2,
        }
    }

    fn evaluate_swarm_admission(
        &self,
        priority: RegionPriority,
        pressure_decision: &AdmissionDecision,
        degradation_level: DegradationLevel,
        _requested_memory: Option<u64>,
        peer_pressure: SwarmPeerPressureSummary,
        workload_pressure: SwarmWorkloadPressureSummary,
    ) -> Result<SwarmAdmissionDecisionInternal, SwarmPressureError> {
        // Check region count limits
        let active_count = {
            let envelopes = self.active_regions.lock().unwrap();
            envelopes.len()
        };

        if active_count >= self.config.max_regions_per_instance {
            return Ok(SwarmAdmissionDecisionInternal {
                decision: AdmissionDecision::Reject,
                reason: format!(
                    "Region limit exceeded: {} >= {}",
                    active_count, self.config.max_regions_per_instance
                ),
            });
        }

        let effective_degradation = degradation_level.max(peer_pressure.max_degradation_level);
        let peer_pressure_backpressure_threshold = self.peer_pressure_backpressure_threshold();
        let workload_feedback_backpressure_threshold =
            self.workload_feedback_backpressure_threshold();
        let peer_pressure_high =
            peer_pressure.max_overall_pressure >= peer_pressure_backpressure_threshold;
        let workload_pressure_high =
            workload_pressure.max_overall_pressure >= workload_feedback_backpressure_threshold;

        // Combine pressure governor decision with system degradation
        let decision = match (pressure_decision, effective_degradation, priority) {
            // Always admit critical regions regardless of pressure
            (_, _, RegionPriority::Critical) => AdmissionDecision::Admit,

            // A runtime-local hard rejection must not be downgraded by softer
            // swarm/system backpressure rules for non-critical work.
            (AdmissionDecision::Reject, _, _) => AdmissionDecision::Reject,

            // Peer pressure is a swarm-wide signal: keep background work out of
            // the system and slow normal work before all runtimes stampede.
            (_, _, RegionPriority::Low | RegionPriority::BestEffort) if peer_pressure_high => {
                AdmissionDecision::Reject
            }
            (_, _, RegionPriority::Normal) if peer_pressure_high => {
                AdmissionDecision::AdmitWithBackpressure
            }

            // Explicit workload feedback is scoped to the requesting workload:
            // keep background proof lanes out and slow normal work when its
            // own queues, RCH lane, frontier, or cancellation tail are hot.
            (_, _, RegionPriority::Low | RegionPriority::BestEffort) if workload_pressure_high => {
                AdmissionDecision::Reject
            }
            (_, _, RegionPriority::Normal) if workload_pressure_high => {
                AdmissionDecision::AdmitWithBackpressure
            }

            // Emergency system pressure has no normal-work headroom left.
            (_, DegradationLevel::Emergency, RegionPriority::Normal) => AdmissionDecision::Reject,

            // Apply backpressure for moderate and heavy system stress.
            (_, DegradationLevel::Moderate | DegradationLevel::Heavy, RegionPriority::Normal) => {
                AdmissionDecision::AdmitWithBackpressure
            }

            // Reject low-priority regions under any system or peer-reported stress.
            (
                _,
                DegradationLevel::Light
                | DegradationLevel::Moderate
                | DegradationLevel::Heavy
                | DegradationLevel::Emergency,
                RegionPriority::Low | RegionPriority::BestEffort,
            ) => AdmissionDecision::Reject,

            // Otherwise follow pressure governor decision
            (decision, _, _) => *decision,
        };

        let reason = match decision {
            AdmissionDecision::Admit => Self::format_swarm_admission_reason(
                "Admission approved",
                degradation_level,
                priority,
                peer_pressure,
                workload_pressure,
                peer_pressure_backpressure_threshold,
                workload_feedback_backpressure_threshold,
            ),
            AdmissionDecision::Reject => Self::format_swarm_admission_reason(
                "Rejected due to pressure",
                effective_degradation,
                priority,
                peer_pressure,
                workload_pressure,
                peer_pressure_backpressure_threshold,
                workload_feedback_backpressure_threshold,
            ),
            AdmissionDecision::AdmitWithBackpressure => Self::format_swarm_admission_reason(
                "Admitted with backpressure",
                effective_degradation,
                priority,
                peer_pressure,
                workload_pressure,
                peer_pressure_backpressure_threshold,
                workload_feedback_backpressure_threshold,
            ),
        };

        Ok(SwarmAdmissionDecisionInternal { decision, reason })
    }

    fn record_decision_latency(&self, decision_start: Instant) -> u64 {
        let latency_ns = duration_as_u64_ns(decision_start.elapsed());
        let _ = self.max_decision_latency_ns.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| (latency_ns > current).then_some(latency_ns),
        );
        latency_ns
    }

    fn contextual_admission_reason(
        workload_request: Option<&SwarmWorkloadAdmissionRequest>,
        reason: String,
    ) -> String {
        if let Some(request) = workload_request {
            request.context_reason(&reason)
        } else {
            reason
        }
    }

    fn build_admission_decision_receipt(
        &self,
        decision: AdmissionDecision,
        degradation_level: DegradationLevel,
        pressure_snapshot: &PressureSnapshot,
        reason: &str,
        peer_pressure: SwarmPeerPressureSummary,
        workload_pressure: SwarmWorkloadPressureSummary,
        workload_request: Option<&SwarmWorkloadAdmissionRequest>,
    ) -> SwarmAdmissionDecisionReceipt {
        let decision_id = self
            .next_admission_decision_id
            .fetch_add(1, Ordering::Relaxed);
        let (
            workload_id,
            owner_agent,
            bead_id,
            reservation_scope,
            proof_lane,
            requested_memory_bytes,
            requested_cpu_ns_per_sec,
            requested_io_ops_per_sec,
            deadline_set,
            cancellation_budget_ms,
        ) = if let Some(request) = workload_request {
            let owner = normalized_owner_metadata(&request.owner);
            (
                normalized_optional_string(Some(request.workload_id.as_str())),
                normalized_optional_string(Some(owner.agent_name.as_str())),
                owner.bead_id,
                owner.reservation_scope,
                Some(request.proof_lane),
                request.requested_memory_bytes,
                request.requested_cpu_ns_per_sec,
                request.requested_io_ops_per_sec,
                request.deadline.is_some(),
                request.cancellation_budget.map(duration_as_u64_ms),
            )
        } else {
            (None, None, None, None, None, None, None, None, false, None)
        };

        let peer_pressure_backpressure_threshold = self.peer_pressure_backpressure_threshold();
        let workload_feedback_backpressure_threshold =
            self.workload_feedback_backpressure_threshold();

        SwarmAdmissionDecisionReceipt {
            decision_id,
            replay_pointer: format!("swarm-admission://decision/{decision_id}"),
            decision,
            degradation_level,
            reason: reason.to_string(),
            workload_id,
            owner_agent,
            bead_id,
            reservation_scope,
            proof_lane,
            requested_memory_bytes,
            requested_cpu_ns_per_sec,
            requested_io_ops_per_sec,
            deadline_set,
            cancellation_budget_ms,
            overall_pressure_scaled: scale_pressure_for_metrics(pressure_snapshot.overall_pressure),
            runnable_queue_pressure_scaled: scale_pressure_for_metrics(
                pressure_snapshot.runnable_queue_pressure,
            ),
            blocking_pool_pressure_scaled: scale_pressure_for_metrics(
                pressure_snapshot.blocking_pool_pressure,
            ),
            channel_backlog_pressure_scaled: scale_pressure_for_metrics(
                pressure_snapshot.channel_backlog_pressure,
            ),
            cleanup_debt_pressure_scaled: scale_pressure_for_metrics(
                pressure_snapshot.cleanup_debt_pressure,
            ),
            memory_budget_pressure_scaled: scale_pressure_for_metrics(
                pressure_snapshot.memory_budget_pressure,
            ),
            peer_pressure_report_count: peer_pressure.live_report_count,
            peer_pressure_max_pressure_scaled: scale_pressure_for_metrics(
                peer_pressure.max_overall_pressure,
            ),
            peer_pressure_backpressure_threshold_scaled: scale_pressure_for_metrics(
                peer_pressure_backpressure_threshold,
            ),
            peer_pressure_backpressure_triggered: peer_pressure.max_overall_pressure
                >= peer_pressure_backpressure_threshold,
            peer_pressure_max_degradation_level: peer_pressure.max_degradation_level as u8,
            workload_feedback_report_count: workload_pressure.live_report_count,
            workload_feedback_max_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_overall_pressure,
            ),
            workload_feedback_backpressure_threshold_scaled: scale_pressure_for_metrics(
                workload_feedback_backpressure_threshold,
            ),
            workload_feedback_backpressure_triggered: workload_pressure.max_overall_pressure
                >= workload_feedback_backpressure_threshold,
            workload_feedback_dominant_pressure_source: workload_pressure.dominant_pressure_source,
            workload_queue_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_queue_pressure,
            ),
            workload_disk_io_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_disk_io_pressure,
            ),
            workload_rch_queue_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_rch_queue_pressure,
            ),
            workload_validation_frontier_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_validation_frontier_pressure,
            ),
            workload_cancellation_tail_pressure_scaled: scale_pressure_for_metrics(
                workload_pressure.max_cancellation_tail_pressure,
            ),
        }
    }

    fn peer_pressure_summary(&self, now: Instant) -> SwarmPeerPressureSummary {
        let reports = self.peer_pressure_reports.lock().unwrap();
        let mut summary = SwarmPeerPressureSummary::EMPTY;

        for report in reports.values() {
            if now.saturating_duration_since(report.reported_at) > self.config.peer_pressure_max_age
            {
                continue;
            }

            summary.live_report_count += 1;
            summary.max_overall_pressure =
                summary.max_overall_pressure.max(report.overall_pressure);
            summary.max_degradation_level =
                summary.max_degradation_level.max(report.degradation_level);
        }

        summary
    }

    fn workload_pressure_summary(
        &self,
        now: Instant,
        workload_id: Option<&str>,
    ) -> SwarmWorkloadPressureSummary {
        let reports = self.workload_pressure_feedback.lock().unwrap();
        let mut summary = SwarmWorkloadPressureSummary::EMPTY;
        let workload_id = workload_id.map(str::trim).filter(|id| !id.is_empty());

        for report in reports.values() {
            if now.saturating_duration_since(report.reported_at)
                > self.config.workload_feedback_max_age
            {
                continue;
            }
            if let Some(workload_id) = workload_id
                && report.workload_id != workload_id
            {
                continue;
            }

            summary.live_report_count += 1;
            summary.max_queue_pressure = summary.max_queue_pressure.max(report.queue_pressure);
            summary.max_disk_io_pressure =
                summary.max_disk_io_pressure.max(report.disk_io_pressure);
            summary.max_rch_queue_pressure = summary
                .max_rch_queue_pressure
                .max(report.rch_queue_pressure);
            summary.max_validation_frontier_pressure = summary
                .max_validation_frontier_pressure
                .max(report.validation_frontier_pressure);
            summary.max_cancellation_tail_pressure = summary
                .max_cancellation_tail_pressure
                .max(report.cancellation_tail_pressure);
            summary.max_overall_pressure = summary.max_overall_pressure.max(report.max_pressure());
        }

        summary.dominant_pressure_source = dominant_workload_pressure_source_from_values(
            summary.max_queue_pressure,
            summary.max_disk_io_pressure,
            summary.max_rch_queue_pressure,
            summary.max_validation_frontier_pressure,
            summary.max_cancellation_tail_pressure,
        );

        summary
    }

    fn peer_pressure_backpressure_threshold(&self) -> f64 {
        let threshold = self.config.peer_pressure_backpressure_threshold;
        if threshold.is_finite() && threshold >= 0.0 {
            threshold
        } else {
            DEFAULT_PEER_PRESSURE_BACKPRESSURE_THRESHOLD
        }
    }

    fn workload_feedback_backpressure_threshold(&self) -> f64 {
        let threshold = self.config.workload_feedback_backpressure_threshold;
        if threshold.is_finite() && threshold >= 0.0 {
            threshold
        } else {
            DEFAULT_WORKLOAD_FEEDBACK_BACKPRESSURE_THRESHOLD
        }
    }

    fn format_swarm_admission_reason(
        base: &str,
        degradation_level: DegradationLevel,
        priority: RegionPriority,
        peer_pressure: SwarmPeerPressureSummary,
        workload_pressure: SwarmWorkloadPressureSummary,
        peer_pressure_backpressure_threshold: f64,
        workload_feedback_backpressure_threshold: f64,
    ) -> String {
        if peer_pressure.has_live_pressure() || workload_pressure.has_live_pressure() {
            format!(
                "{base}: {degradation_level:?} degradation, {priority:?} priority, {} live peer pressure reports, max peer pressure {:.3}, peer pressure threshold {:.3}, peer pressure backpressure triggered {}, max peer degradation {:?}, {} live workload feedback reports, max workload pressure {:.3}, workload feedback threshold {:.3}, workload feedback backpressure triggered {}, dominant workload pressure source {} (queue {:.3}, disk_io {:.3}, rch_queue {:.3}, validation_frontier {:.3}, cancellation_tail {:.3})",
                peer_pressure.live_report_count,
                peer_pressure.max_overall_pressure,
                peer_pressure_backpressure_threshold,
                peer_pressure.max_overall_pressure >= peer_pressure_backpressure_threshold,
                peer_pressure.max_degradation_level,
                workload_pressure.live_report_count,
                workload_pressure.max_overall_pressure,
                workload_feedback_backpressure_threshold,
                workload_pressure.max_overall_pressure >= workload_feedback_backpressure_threshold,
                workload_pressure.dominant_pressure_source.as_str(),
                workload_pressure.max_queue_pressure,
                workload_pressure.max_disk_io_pressure,
                workload_pressure.max_rch_queue_pressure,
                workload_pressure.max_validation_frontier_pressure,
                workload_pressure.max_cancellation_tail_pressure
            )
        } else if base == "Admission approved" {
            base.to_string()
        } else {
            format!("{base}: {degradation_level:?} degradation, {priority:?} priority")
        }
    }

    fn first_envelope_budget_excess(
        &self,
        requested_cpu_ns_per_sec: Option<u64>,
        requested_io_ops_per_sec: Option<u64>,
    ) -> Option<(&'static str, u64, u64)> {
        if self.config.envelope_enforcement_enabled {
            if let Some(requested_cpu) = requested_cpu_ns_per_sec
                && requested_cpu > self.config.default_cpu_budget_ns_per_sec
            {
                return Some((
                    "cpu",
                    requested_cpu,
                    self.config.default_cpu_budget_ns_per_sec,
                ));
            }
            if let Some(requested_io) = requested_io_ops_per_sec
                && requested_io > self.config.default_io_budget_ops_per_sec
            {
                return Some((
                    "io",
                    requested_io,
                    self.config.default_io_budget_ops_per_sec,
                ));
            }
        }
        None
    }

    fn rejected_workload_decision(
        &self,
        decision_start: Instant,
        request: &SwarmWorkloadAdmissionRequest,
        reason: String,
    ) -> SwarmAdmissionDecision {
        self.total_admission_checks.fetch_add(1, Ordering::Relaxed);
        self.regions_rejected.fetch_add(1, Ordering::Relaxed);
        let degradation_level = self
            .resource_monitor
            .pressure()
            .composite_degradation_level();
        let pressure_snapshot = self.get_default_pressure_snapshot();
        let peer_pressure = self.peer_pressure_summary(decision_start);
        let reason = request.context_reason(&reason);
        let decision_receipt = self.build_admission_decision_receipt(
            AdmissionDecision::Reject,
            degradation_level,
            &pressure_snapshot,
            &reason,
            peer_pressure,
            SwarmWorkloadPressureSummary::EMPTY,
            Some(request),
        );
        SwarmAdmissionDecision {
            decision: AdmissionDecision::Reject,
            envelope: None,
            pressure_snapshot,
            degradation_level,
            decision_latency_ns: self.record_decision_latency(decision_start),
            reason,
            decision_receipt,
            workload_receipt: Some(SwarmAdmissionWorkloadReceipt::from_request(request)),
        }
    }

    fn create_envelope_for_region(
        &self,
        region_id: RegionId,
        requested_memory: Option<u64>,
        requested_cpu_ns_per_sec: Option<u64>,
        requested_io_ops_per_sec: Option<u64>,
    ) -> Result<ResourceEnvelope, SwarmPressureError> {
        let memory_budget = if self.config.envelope_enforcement_enabled {
            self.config.default_memory_budget_bytes
        } else {
            requested_memory.unwrap_or(self.config.default_memory_budget_bytes)
        };

        let envelope = ResourceEnvelope::new(
            region_id,
            memory_budget,
            self.config.default_cpu_budget_ns_per_sec,
            self.config.default_io_budget_ops_per_sec,
        );
        if let Some(requested_memory) = requested_memory {
            envelope.reserve_memory(requested_memory)?;
        }
        if let Some(requested_cpu) = requested_cpu_ns_per_sec {
            envelope.reserve_cpu(requested_cpu)?;
        }
        if let Some(requested_io) = requested_io_ops_per_sec {
            envelope.reserve_io(requested_io)?;
        }
        Ok(envelope)
    }

    fn create_disabled_governance_envelope(
        &self,
        region_id: RegionId,
        requested_memory: Option<u64>,
        requested_cpu_ns_per_sec: Option<u64>,
        requested_io_ops_per_sec: Option<u64>,
    ) -> Result<ResourceEnvelope, SwarmPressureError> {
        let memory_budget = requested_memory
            .map_or(self.config.default_memory_budget_bytes, |requested| {
                requested.max(self.config.default_memory_budget_bytes)
            });
        let cpu_budget = requested_cpu_ns_per_sec
            .map_or(self.config.default_cpu_budget_ns_per_sec, |requested| {
                requested.max(self.config.default_cpu_budget_ns_per_sec)
            });
        let io_budget = requested_io_ops_per_sec
            .map_or(self.config.default_io_budget_ops_per_sec, |requested| {
                requested.max(self.config.default_io_budget_ops_per_sec)
            });

        let envelope = ResourceEnvelope::new(region_id, memory_budget, cpu_budget, io_budget);
        if let Some(requested_memory) = requested_memory {
            envelope.reserve_memory(requested_memory)?;
        }
        if let Some(requested_cpu) = requested_cpu_ns_per_sec {
            envelope.reserve_cpu(requested_cpu)?;
        }
        if let Some(requested_io) = requested_io_ops_per_sec {
            envelope.reserve_io(requested_io)?;
        }
        Ok(envelope)
    }

    fn get_default_pressure_snapshot(&self) -> PressureSnapshot {
        // Create a default snapshot when pressure governance is disabled
        let signal_availability =
            crate::observability::pressure_governor::PressureSignalAvailability::NONE;
        let fallback_verdict =
            crate::observability::pressure_governor::PressureFallbackVerdict::from_availability(
                signal_availability,
            );
        PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.0,
            blocking_pool_pressure: 0.0,
            channel_backlog_pressure: 0.0,
            cleanup_debt_pressure: 0.0,
            memory_budget_pressure: 0.0,
            overall_pressure: 0.0,
            signal_availability,
            fallback_verdict,
        }
    }

    fn get_default_admission_decision(
        &self,
        degradation_level: DegradationLevel,
    ) -> AdmissionDecision {
        // Make admission decisions based on system resource degradation when
        // no runtime-local pressure governor is available.
        match degradation_level {
            DegradationLevel::Emergency => AdmissionDecision::Reject,
            _ => AdmissionDecision::Admit,
        }
    }
}

#[derive(Debug)]
struct SwarmAdmissionDecisionInternal {
    decision: AdmissionDecision,
    reason: String,
}

/// Metrics for swarm pressure governance.
#[derive(Debug, Clone)]
pub struct SwarmPressureMetrics {
    /// Total admission checks performed.
    pub total_admission_checks: u64,
    /// Total regions admitted.
    pub regions_admitted: u64,
    /// Total regions rejected.
    pub regions_rejected: u64,
    /// Total envelope budget violations.
    pub envelope_budget_violations: u64,
    /// Maximum observed swarm admission decision latency in nanoseconds.
    pub max_decision_latency_ns: u64,
    /// Number of active regions with envelopes.
    pub active_region_count: u64,
    /// Maximum active memory-envelope utilization scaled by 10_000.
    pub max_memory_utilization_scaled: i64,
    /// Maximum active CPU-envelope utilization scaled by 10_000.
    pub max_cpu_utilization_scaled: i64,
    /// Maximum active IO-envelope utilization scaled by 10_000.
    pub max_io_utilization_scaled: i64,
    /// Total workload leases acquired.
    pub workload_leases_acquired: u64,
    /// Total workload leases committed to a caller-owned region.
    pub workload_leases_committed: u64,
    /// Total successful workload lease renewals.
    pub workload_leases_renewed: u64,
    /// Total workload leases released normally.
    pub workload_leases_released: u64,
    /// Total workload leases aborted after cancellation or startup failure.
    pub workload_leases_aborted: u64,
    /// Total workload leases expired by deadline.
    pub workload_leases_expired: u64,
    /// Total workload lease conflict rejections.
    pub workload_lease_conflicts: u64,
    /// Number of live workload leases.
    pub active_workload_lease_count: u64,
    /// Number of terminal workload leases retained for audit.
    pub terminal_workload_lease_count: u64,
    /// Total workload pressure feedback reports recorded.
    pub workload_feedback_reports_recorded: u64,
    /// Number of live workload pressure feedback reports considered by admission.
    pub live_workload_feedback_reports: u64,
    /// Maximum live workload feedback pressure ratio scaled by 10_000.
    pub max_workload_feedback_pressure_scaled: i64,
    /// Dominant live workload feedback pressure axis.
    pub workload_feedback_dominant_pressure_source: SwarmWorkloadPressureSource,
    /// Maximum live workload queue feedback pressure ratio scaled by 10_000.
    pub max_workload_feedback_queue_pressure_scaled: i64,
    /// Maximum live workload disk or artifact-cache IO feedback pressure ratio scaled by 10_000.
    pub max_workload_feedback_disk_io_pressure_scaled: i64,
    /// Maximum live workload RCH or remote-worker queue feedback pressure ratio scaled by 10_000.
    pub max_workload_feedback_rch_queue_pressure_scaled: i64,
    /// Maximum live workload validation-frontier feedback pressure ratio scaled by 10_000.
    pub max_workload_feedback_validation_frontier_pressure_scaled: i64,
    /// Maximum live workload cancellation/drain tail feedback pressure ratio scaled by 10_000.
    pub max_workload_feedback_cancellation_tail_pressure_scaled: i64,
    /// Number of live peer pressure reports considered by admission.
    pub live_peer_pressure_reports: u64,
    /// Maximum live peer pressure ratio scaled by 10_000.
    pub max_peer_pressure_scaled: i64,
    /// Maximum live peer degradation level.
    pub max_peer_degradation_level: u8,
}

fn scale_pressure_for_metrics(pressure: f64) -> i64 {
    const PRESSURE_SCALE: f64 = 10000.0;
    if !pressure.is_finite() || pressure <= 0.0 {
        0
    } else if pressure >= i64::MAX as f64 / PRESSURE_SCALE {
        i64::MAX
    } else {
        (pressure * PRESSURE_SCALE) as i64
    }
}

fn resource_pressure_scaled_from_degradation(degradation_level: DegradationLevel) -> i64 {
    scale_pressure_for_metrics(1.0 - f64::from(degradation_level.to_headroom()))
}

const fn degradation_level_as_str(degradation_level: DegradationLevel) -> &'static str {
    match degradation_level {
        DegradationLevel::None => "none",
        DegradationLevel::Light => "light",
        DegradationLevel::Moderate => "moderate",
        DegradationLevel::Heavy => "heavy",
        DegradationLevel::Emergency => "emergency",
    }
}

fn dominant_workload_pressure_source_from_values(
    queue_pressure: f64,
    disk_io_pressure: f64,
    rch_queue_pressure: f64,
    validation_frontier_pressure: f64,
    cancellation_tail_pressure: f64,
) -> SwarmWorkloadPressureSource {
    let mut dominant = (SwarmWorkloadPressureSource::None, 0.0);
    for (source, pressure) in [
        (SwarmWorkloadPressureSource::Queue, queue_pressure),
        (SwarmWorkloadPressureSource::DiskIo, disk_io_pressure),
        (SwarmWorkloadPressureSource::RchQueue, rch_queue_pressure),
        (
            SwarmWorkloadPressureSource::ValidationFrontier,
            validation_frontier_pressure,
        ),
        (
            SwarmWorkloadPressureSource::CancellationTail,
            cancellation_tail_pressure,
        ),
    ] {
        if pressure.is_finite() && pressure > dominant.1 {
            dominant = (source, pressure);
        }
    }
    dominant.0
}

fn workload_lease_error(reason: impl Into<String>) -> SwarmPressureError {
    SwarmPressureError::WorkloadLease {
        reason: reason.into(),
    }
}

fn duration_as_u64_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

fn duration_as_u64_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn duplicate_count_from_group_counts<'a>(counts: impl Iterator<Item = &'a u64>) -> u64 {
    counts
        .filter(|count| **count > 1)
        .map(|count| count.saturating_sub(1))
        .sum()
}

fn optional_reason_field(value: Option<&str>) -> &str {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unset")
}

fn optional_u64_reason_field(value: Option<u64>) -> String {
    value.map_or_else(|| "unset".to_string(), |value| value.to_string())
}

fn normalized_owner_metadata(owner: &SwarmAdmissionOwner) -> SwarmAdmissionOwner {
    SwarmAdmissionOwner {
        agent_name: owner.agent_name.trim().to_string(),
        bead_id: normalized_optional_string(owner.bead_id.as_deref()),
        reservation_scope: normalized_reservation_scope(owner.reservation_scope.as_deref()),
    }
}

fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalized_reservation_scope(value: Option<&str>) -> Option<String> {
    let trimmed = normalized_optional_string(value)?;
    let mut collapsed = String::with_capacity(trimmed.len());
    let mut previous_slash = false;
    for ch in trimmed.chars() {
        if ch == '/' {
            if !previous_slash {
                collapsed.push(ch);
            }
            previous_slash = true;
        } else {
            collapsed.push(ch);
            previous_slash = false;
        }
    }
    while collapsed.starts_with("./") {
        collapsed.drain(..2);
    }
    normalized_optional_string(Some(&collapsed))
}

fn prune_stale_peer_pressure_reports_locked(
    reports: &mut HashMap<String, SwarmPeerPressureReport>,
    max_age: Duration,
    now: Instant,
) -> usize {
    let before = reports.len();
    reports.retain(|_, report| now.saturating_duration_since(report.reported_at) <= max_age);
    before.saturating_sub(reports.len())
}

fn prune_stale_workload_pressure_feedback_locked(
    reports: &mut HashMap<String, SwarmWorkloadPressureFeedback>,
    max_age: Duration,
    now: Instant,
) -> usize {
    let before = reports.len();
    reports.retain(|_, report| now.saturating_duration_since(report.reported_at) <= max_age);
    before.saturating_sub(reports.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::metrics::Metrics;
    use crate::runtime::RuntimeBuilder;
    use crate::runtime::resource_monitor::ResourceType;
    use crate::types::Budget;

    fn create_test_swarm_governor() -> SwarmPressureGovernor {
        create_test_swarm_governor_with_config(SwarmPressureGovernorConfig::default())
    }

    fn create_test_swarm_governor_with_config(
        config: SwarmPressureGovernorConfig,
    ) -> SwarmPressureGovernor {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );

        let resource_monitor = runtime.resource_monitor();
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");

        SwarmPressureGovernor::new(config, resource_monitor, pressure_governor)
    }

    fn admission_rank(decision: AdmissionDecision) -> u8 {
        match decision {
            AdmissionDecision::Admit => 0,
            AdmissionDecision::AdmitWithBackpressure => 1,
            AdmissionDecision::Reject => 2,
        }
    }

    fn fourth_wave_sample_evidence_rows() -> Vec<FourthWaveEvidenceRow> {
        vec![
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::BeadMailContext,
                "mail-ready-clean",
                FourthWaveEvidenceClaimStatus::CoordinationEvidence,
                8_400,
            )
            .with_age_seconds(120),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::CapacitySnapshot,
                "large-host-64c-256g",
                FourthWaveEvidenceClaimStatus::SchemaContract,
                8_400,
            )
            .with_age_seconds(150),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::LabReplay,
                "large-host-low-pressure-replay",
                FourthWaveEvidenceClaimStatus::ReplayBacked,
                8_600,
            )
            .with_age_seconds(200),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::ObligationPressure,
                "obligation-drain-low",
                FourthWaveEvidenceClaimStatus::ReplayBacked,
                8_400,
            )
            .with_age_seconds(170),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::RchProofLane,
                "remote-required-admit",
                FourthWaveEvidenceClaimStatus::RemoteProof,
                8_400,
            )
            .with_age_seconds(180),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::RegionPressure,
                "regions-low",
                FourthWaveEvidenceClaimStatus::ReplayBacked,
                8_400,
            )
            .with_age_seconds(185),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::WorkerEnvelope,
                "worker-envelope-low",
                FourthWaveEvidenceClaimStatus::SchemaContract,
                8_400,
            )
            .with_age_seconds(160),
        ]
    }

    fn fourth_wave_sample_input(scenario_id: &str) -> FourthWaveGovernorInput {
        FourthWaveGovernorInput {
            bead_id: "asupersync-86fe9v.2".to_string(),
            scenario_id: scenario_id.to_string(),
            objective: FourthWaveGovernorObjective::required("release-proof-safety", 8_000),
            pressure_snapshot: FourthWavePressureSnapshot {
                schema_version: FOURTH_WAVE_PRESSURE_SNAPSHOT_SCHEMA_VERSION.to_string(),
                snapshot_id: format!("fw-snapshot-{}", fourth_wave_scenario_slug(scenario_id)),
                input_status: FourthWaveInputStatus::Complete,
                policy_version: FOURTH_WAVE_GOVERNOR_POLICY_VERSION.to_string(),
                input_artifact_hashes: vec![
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ],
                normalized_host_capacity: FourthWaveHostCapacity {
                    host_profile_id: "large-host-64c-256g".to_string(),
                    physical_core_count: 64,
                    available_parallelism: 64,
                    numa_node_count: 2,
                    memory_total_mib: 262_144,
                    cgroup_cpu_quota_millis: 64_000,
                },
                worker_envelope: FourthWaveWorkerEnvelope {
                    local_agent_slots: 24,
                    max_agent_count: 48,
                    active_agent_count: 16,
                    remote_worker_slots: 6,
                    cache_warm_remote_workers: 3,
                },
                core_envelope: FourthWaveCoreEnvelope {
                    local_core_pressure_bps: 3_200,
                    remote_core_pressure_bps: 2_800,
                    reserved_critical_cores: 8,
                    admit_core_budget_bps: 7_600,
                },
                memory_envelope: FourthWaveMemoryEnvelope {
                    total_mib: 262_144,
                    available_mib: 180_224,
                    reserved_validation_mib: 32_768,
                    artifact_cache_mib: 8_192,
                    memory_pressure_bps: 3_100,
                },
                active_region_pressure: FourthWaveActiveRegionPressure {
                    active_region_count: 28,
                    region_limit: 128,
                    queue_depth: 18,
                    region_pressure_bps: 2_600,
                },
                obligation_pressure: FourthWaveObligationPressure {
                    live_obligation_count: 96,
                    drain_backlog: 4,
                    leak_suspect_count: 0,
                    obligation_pressure_bps: 1_800,
                },
                rch_admission_state: FourthWaveRchAdmissionState {
                    remote_required: true,
                    workers_admissible: true,
                    selected_worker: Some("rch-worker://redacted/cache-warm-01".to_string()),
                    local_fallback_marker_detected: false,
                    first_blocker: None,
                },
                bead_mail_workload_context: FourthWaveBeadMailWorkloadContext {
                    ready_beads: 2,
                    in_progress_beads: 1,
                    reserved_path_count: 4,
                    ack_required_backlog: 0,
                    tracker_writable: true,
                },
                lab_replay_metadata: FourthWaveLabReplayMetadata {
                    scenario_family: "large_host_low_pressure".to_string(),
                    seed: 860_001,
                    replay_artifact: Some(
                        "artifacts/large_host_topology_corpus_v1.json".to_string(),
                    ),
                    replay_backed: true,
                },
                evidence_rows: fourth_wave_sample_evidence_rows(),
            },
        }
    }

    #[test]
    fn fourth_wave_governor_admits_required_work_with_stable_receipt() {
        let input = fourth_wave_sample_input("FW-GOVERNOR-ADMIT-REQUIRED-WORK");

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::AdmitRequiredWork
        );
        assert_eq!(receipt.rule_id, "admit-required-work");
        assert!(!receipt.fail_closed);
        assert_eq!(
            receipt.decision_id,
            "fw-governor-decision/admit-required-work/policy-v1"
        );
        assert_eq!(receipt.confidence_bps, 8_400);
        assert_eq!(receipt.evidence_rows.len(), 7);
        assert!(receipt.rejected_rows.is_empty());
        assert_eq!(receipt.log_fields.selected_action, "admit_required_work");
        assert_eq!(receipt.log_fields.rejected_row_count, 0);
        assert_eq!(
            receipt.objective_row.objective_id,
            input.objective.objective_id
        );
        assert_eq!(receipt.evidence_quality.required_input_classes_present, 7);
        assert!(
            receipt
                .rejected_alternatives
                .iter()
                .any(|alternative| alternative.rule_id == "brownout-optional-work")
        );
    }

    #[test]
    fn fourth_wave_governor_zero_evidence_fails_missing_required_evidence() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-MISSING-REQUIRED-EVIDENCE");
        input.pressure_snapshot.evidence_rows.clear();

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedMissingEvidence
        );
        assert_eq!(receipt.rule_id, "missing-required-evidence");
        assert!(receipt.fail_closed);
        assert_eq!(receipt.confidence_bps, 0);
        assert_eq!(
            receipt.rejected_rows,
            vec![
                "bead_mail_context",
                "capacity_snapshot",
                "lab_replay",
                "obligation_pressure",
                "rch_proof_lane",
                "region_pressure",
                "worker_envelope"
            ]
        );
        assert_eq!(receipt.evidence_quality.row_count, 0);
        assert_eq!(receipt.log_fields.rejected_row_count, 7);
    }

    #[test]
    fn fourth_wave_governor_stale_evidence_fails_closed() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-STALE-EVIDENCE");
        input.pressure_snapshot.evidence_rows[2].evidence_age_seconds =
            FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS + 1;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedStaleEvidence
        );
        assert_eq!(receipt.rule_id, "stale-evidence");
        assert_eq!(
            receipt.rejected_rows,
            vec!["large-host-low-pressure-replay"]
        );
        assert!(
            receipt
                .non_action_reason
                .contains("evidence older than 900 seconds")
        );
        assert!(receipt.fail_closed);
    }

    #[test]
    fn fourth_wave_governor_local_fallback_marker_preempts_stale_and_pressure() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-LOCAL-RCH-FALLBACK");
        input.pressure_snapshot.memory_envelope.memory_pressure_bps = 9_300;
        input.pressure_snapshot.evidence_rows[0].evidence_age_seconds =
            FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS + 1;
        input
            .pressure_snapshot
            .rch_admission_state
            .local_fallback_marker_detected = true;
        let local_fallback_row = input.pressure_snapshot.evidence_rows[4]
            .clone()
            .with_local_fallback_marker("local_fallback_detected");
        input.pressure_snapshot.evidence_rows[4] = local_fallback_row;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedLocalRchFallback
        );
        assert_eq!(receipt.rule_id, "local-rch-fallback");
        assert_eq!(receipt.rejected_rows, vec!["remote-required-admit"]);
        assert_eq!(
            receipt.log_fields.first_rejected_row_reason,
            "local_fallback_detected"
        );
        assert!(
            receipt
                .rejected_alternatives
                .iter()
                .any(|alternative| alternative.rule_id == "stale-evidence"
                    && alternative.reason.contains("skipped"))
        );
    }

    #[test]
    fn fourth_wave_governor_advisory_only_without_replay_fails_closed() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-ADVISORY-ONLY");
        input.pressure_snapshot.lab_replay_metadata.replay_backed = false;
        input.pressure_snapshot.lab_replay_metadata.replay_artifact = None;
        for row in &mut input.pressure_snapshot.evidence_rows {
            row.claim_status = FourthWaveEvidenceClaimStatus::AdvisoryOnly;
            row.confidence_bps = 4_200;
            row.rejected_reason = "advisory_without_replay".to_string();
        }

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedAdvisoryOnly
        );
        assert_eq!(receipt.rule_id, "advisory-only-evidence");
        assert_eq!(receipt.rejected_rows.len(), 7);
        assert_eq!(receipt.confidence_bps, 0);
        assert_eq!(receipt.evidence_quality.advisory_only_row_count, 7);
        assert_eq!(
            receipt.log_fields.first_rejected_row_reason,
            "advisory_without_replay"
        );
    }

    #[test]
    fn fourth_wave_governor_defer_no_remote_worker_no_win_refuses_local_fallback() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-DEFER-NO-REMOTE-WORKER");
        input
            .pressure_snapshot
            .rch_admission_state
            .workers_admissible = false;
        input.pressure_snapshot.rch_admission_state.selected_worker = None;
        input.pressure_snapshot.rch_admission_state.first_blocker =
            Some("active_project_exclusion".to_string());
        input.pressure_snapshot.evidence_rows[4].claim_status =
            FourthWaveEvidenceClaimStatus::RemoteRefusal;
        input.pressure_snapshot.evidence_rows[4].rejected_reason =
            "active_project_exclusion".to_string();
        input.pressure_snapshot.evidence_rows[4].confidence_bps = 7_800;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::DeferNoRemoteWorker
        );
        assert_eq!(receipt.rule_id, "remote-required-no-worker");
        assert!(!receipt.fail_closed);
        assert_eq!(receipt.rejected_rows, vec!["remote-required-admit"]);
        assert_eq!(
            receipt.log_fields.first_rejected_row_reason,
            "active_project_exclusion"
        );
        assert!(receipt.non_action_reason.contains("local fallback refused"));
        assert_eq!(receipt.confidence_bps, 7_800);
    }

    #[test]
    fn fourth_wave_governor_pressure_boundaries_brownout_optional_work() {
        let mut exact_memory = fourth_wave_sample_input("FW-GOVERNOR-BROWNOUT-OPTIONAL-WORK");
        exact_memory
            .pressure_snapshot
            .memory_envelope
            .memory_pressure_bps = FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS;
        let receipt = evaluate_fourth_wave_governor(&exact_memory);
        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::BrownoutOptionalWork
        );
        assert_eq!(
            receipt.non_action_reason,
            "optional work exceeds memory pressure budget"
        );
        assert!(!receipt.fail_closed);

        let mut exact_core_budget = fourth_wave_sample_input("FW-GOVERNOR-ADMIT-EXACT-CORE");
        exact_core_budget
            .pressure_snapshot
            .core_envelope
            .local_core_pressure_bps = 7_600;
        assert_eq!(
            evaluate_fourth_wave_governor(&exact_core_budget).selected_action,
            FourthWaveGovernorAction::AdmitRequiredWork
        );

        let mut cpu_heavy = fourth_wave_sample_input("FW-GOVERNOR-CPU-BROWNOUT");
        cpu_heavy
            .pressure_snapshot
            .core_envelope
            .local_core_pressure_bps = 7_601;
        assert_eq!(
            evaluate_fourth_wave_governor(&cpu_heavy).non_action_reason,
            "optional work exceeds core pressure budget"
        );

        let mut region_heavy = fourth_wave_sample_input("FW-GOVERNOR-REGION-BROWNOUT");
        region_heavy
            .pressure_snapshot
            .active_region_pressure
            .region_pressure_bps = FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS;
        assert_eq!(
            evaluate_fourth_wave_governor(&region_heavy).non_action_reason,
            "optional work exceeds region pressure budget"
        );

        let mut obligation_heavy = fourth_wave_sample_input("FW-GOVERNOR-OBLIGATION-BROWNOUT");
        obligation_heavy
            .pressure_snapshot
            .obligation_pressure
            .leak_suspect_count = 1;
        assert_eq!(
            evaluate_fourth_wave_governor(&obligation_heavy).non_action_reason,
            "optional work exceeds obligation pressure budget"
        );
    }

    #[test]
    fn fourth_wave_governor_malformed_input_preempts_evidence_rules() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-MALFORMED-INPUT");
        input.pressure_snapshot.input_status = FourthWaveInputStatus::Malformed;
        input.pressure_snapshot.evidence_rows.clear();
        input
            .pressure_snapshot
            .rch_admission_state
            .local_fallback_marker_detected = true;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedMalformedInput
        );
        assert_eq!(receipt.rule_id, "malformed-input");
        assert_eq!(
            receipt.non_action_reason,
            "snapshot input_status is malformed"
        );
        assert_eq!(
            receipt.rejected_rows,
            vec!["fw-snapshot-fail-malformed-input"]
        );
        assert!(
            receipt
                .rejected_alternatives
                .iter()
                .any(|alternative| alternative.rule_id == "local-rch-fallback"
                    && alternative.reason.contains("skipped"))
        );
    }

    #[test]
    fn test_resource_envelope_budget_enforcement() {
        let envelope = ResourceEnvelope::new(RegionId::new_for_test(1, 1), 1000, 1000000, 100);

        // Should allow allocation within budget
        assert!(envelope.reserve_memory(500).is_ok());
        assert_eq!(envelope.memory_utilization(), 0.5);

        // Should reject allocation exceeding budget
        assert!(envelope.reserve_memory(600).is_err());

        // Should allow allocation after release
        envelope.release_memory(200);
        assert!(envelope.reserve_memory(400).is_ok());
        assert_eq!(envelope.memory_utilization(), 0.7);
    }

    #[test]
    fn test_resource_envelope_cpu_and_io_budget_enforcement() {
        let envelope = ResourceEnvelope::new(RegionId::new_for_test(1, 2), 1000, 100, 10);

        assert!(envelope.reserve_cpu(60).is_ok());
        assert_eq!(envelope.cpu_utilization(), 0.6);
        assert!(matches!(
            envelope.reserve_cpu(50),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "cpu"
        ));
        envelope.release_cpu(25);
        assert!(envelope.reserve_cpu(40).is_ok());
        assert_eq!(envelope.cpu_utilization(), 0.75);

        assert!(envelope.reserve_io(7).is_ok());
        assert_eq!(envelope.io_utilization(), 0.7);
        assert!(matches!(
            envelope.reserve_io(4),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "io"
        ));
        envelope.release_io(3);
        assert!(envelope.reserve_io(2).is_ok());
        assert_eq!(envelope.io_utilization(), 0.6);
    }

    #[test]
    fn test_resource_envelope_concurrent_reservations_do_not_overshoot_budget() {
        let envelope = std::sync::Arc::new(ResourceEnvelope::new(
            RegionId::new_for_test(1, 3),
            64,
            100,
            100,
        ));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let envelope = std::sync::Arc::clone(&envelope);
            handles.push(std::thread::spawn(move || {
                let mut successful_reservations = 0_u64;
                for _ in 0..32 {
                    if envelope.reserve_memory(1).is_ok() {
                        successful_reservations += 1;
                    }
                }
                successful_reservations
            }));
        }

        let successful_reservations: u64 = handles
            .into_iter()
            .map(|handle| handle.join().expect("reservation thread should finish"))
            .sum();

        assert_eq!(successful_reservations, 64);
        assert_eq!(envelope.memory_used.load(Ordering::Relaxed), 64);
        assert!(matches!(
            envelope.reserve_memory(1),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "memory"
        ));
    }

    #[test]
    fn test_register_region_envelope_binds_envelope_to_region_key() {
        let governor = create_test_swarm_governor();
        let actual_region_id = RegionId::new_for_test(9, 1);
        let stale_admission_region_id = RegionId::new_for_test(1, 99);
        let envelope = ResourceEnvelope::new(stale_admission_region_id, 2048, 100, 10);

        governor.register_region_envelope(actual_region_id, envelope);

        let registered = governor
            .get_region_envelope(actual_region_id)
            .expect("registered region envelope should be retrievable by actual region id");
        assert_eq!(registered.region_id, actual_region_id);
        assert!(
            governor
                .get_region_envelope(stale_admission_region_id)
                .is_none(),
            "stale admission id must not become a separately registered region"
        );
    }

    #[test]
    fn test_unregister_region_envelope_updates_active_region_metrics() {
        let governor = create_test_swarm_governor();
        let region_id = RegionId::new_for_test(10, 1);
        let envelope = ResourceEnvelope::new(region_id, 4096, 100, 10);
        envelope
            .reserve_memory(512)
            .expect("test reservation should fit inside the envelope budget");

        governor.register_region_envelope(region_id, envelope);
        assert_eq!(governor.metrics().active_region_count, 1);

        let removed = governor
            .unregister_region_envelope(region_id)
            .expect("registered envelope should be returned exactly once");
        assert_eq!(removed.region_id, region_id);
        assert_eq!(removed.memory_used.load(Ordering::Relaxed), 512);
        assert!(governor.get_region_envelope(region_id).is_none());
        assert_eq!(governor.metrics().active_region_count, 0);
        assert!(governor.unregister_region_envelope(region_id).is_none());
    }

    #[test]
    fn test_metrics_report_active_envelope_utilization() {
        let governor = create_test_swarm_governor();
        let low_region_id = RegionId::new_for_test(11, 1);
        let high_region_id = RegionId::new_for_test(12, 1);
        let low_envelope = ResourceEnvelope::new(low_region_id, 1024, 100, 10);
        low_envelope
            .reserve_memory(512)
            .expect("memory reservation should fit");
        low_envelope
            .reserve_cpu(25)
            .expect("cpu reservation should fit");
        low_envelope
            .reserve_io(3)
            .expect("io reservation should fit");

        let high_envelope = ResourceEnvelope::new(high_region_id, 1000, 100, 20);
        high_envelope
            .reserve_memory(900)
            .expect("memory reservation should fit");
        high_envelope
            .reserve_cpu(80)
            .expect("cpu reservation should fit");
        high_envelope
            .reserve_io(4)
            .expect("io reservation should fit");

        governor.register_region_envelope(low_region_id, low_envelope);
        governor.register_region_envelope(high_region_id, high_envelope);

        let metrics = governor.metrics();
        assert_eq!(metrics.active_region_count, 2);
        assert_eq!(metrics.max_memory_utilization_scaled, 9000);
        assert_eq!(metrics.max_cpu_utilization_scaled, 8000);
        assert_eq!(metrics.max_io_utilization_scaled, 3000);
    }

    #[test]
    fn test_swarm_governor_region_limits() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_regions_per_instance = 2;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );

        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");

        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);

        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        // First two admissions should succeed
        let decision1 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("First admission should succeed");
        assert!(matches!(decision1.decision, AdmissionDecision::Admit));

        let decision2 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Second admission should succeed");
        assert!(matches!(decision2.decision, AdmissionDecision::Admit));

        // Add envelopes to simulate active regions
        governor
            .register_region_envelope(RegionId::new_for_test(1, 1), decision1.envelope.unwrap());
        governor
            .register_region_envelope(RegionId::new_for_test(2, 1), decision2.envelope.unwrap());

        // Third admission should be rejected
        let decision3 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Third admission check should succeed");
        assert!(matches!(decision3.decision, AdmissionDecision::Reject));
        assert!(decision3.reason.contains("Region limit exceeded"));
    }

    #[test]
    fn test_disabled_governance_admissions_update_metrics() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.enabled = false;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let requested_memory = governor.config.default_memory_budget_bytes + 4096;

        let decision = governor
            .check_region_admission(&cx, RegionPriority::BestEffort, Some(requested_memory))
            .expect("disabled governance should always produce an admission decision");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        let envelope = decision
            .envelope
            .expect("disabled governance should still return an envelope");
        assert_eq!(envelope.memory_budget, requested_memory);
        assert_eq!(
            envelope.memory_used.load(Ordering::Relaxed),
            requested_memory
        );
        assert_eq!(decision.reason, "Swarm governance disabled");

        let metrics = governor.metrics();
        assert_eq!(metrics.total_admission_checks, 1);
        assert_eq!(metrics.regions_admitted, 1);
        assert_eq!(metrics.regions_rejected, 0);
    }

    #[test]
    fn test_no_pressure_governor_default_snapshot_reports_no_win_fallback() {
        let config = SwarmPressureGovernorConfig::default();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let governor = SwarmPressureGovernor::new_without_pressure_governor(
            config,
            runtime.resource_monitor(),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("no-pressure-governor admission should still produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        assert_eq!(
            decision.pressure_snapshot.signal_availability,
            crate::observability::pressure_governor::PressureSignalAvailability::NONE
        );
        assert_eq!(
            decision.pressure_snapshot.fallback_verdict,
            crate::observability::pressure_governor::PressureFallbackVerdict::NoWinNoLiveSignals,
            "a snapshot with no live runtime-local signals must not claim complete pressure evidence"
        );
    }

    #[test]
    fn test_metrics_report_max_decision_latency() {
        let governor = create_test_swarm_governor();
        assert_eq!(governor.metrics().max_decision_latency_ns, 0);

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("admission should produce a latency-bearing decision");

        let metrics = governor.metrics();
        assert_eq!(metrics.total_admission_checks, 1);
        assert_eq!(
            metrics.max_decision_latency_ns, decision.decision_latency_ns,
            "single admission should publish its latency as the max latency metric"
        );
    }

    #[test]
    fn test_backpressure_admission_still_gets_resource_envelope() {
        let governor = create_test_swarm_governor();
        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Moderate,
            );

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, Some(1024))
            .expect("Backpressure admission should produce a decision");

        assert!(matches!(
            decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        let envelope = decision
            .envelope
            .expect("backpressure admission still admits work and must return an envelope");
        assert_eq!(
            envelope.memory_budget,
            governor.config.default_memory_budget_bytes
        );
        assert_eq!(
            envelope.memory_used.load(Ordering::Relaxed),
            1024,
            "admitted requested memory must be charged to the returned envelope"
        );

        governor.register_region_envelope(envelope.region_id, envelope);
        assert_eq!(governor.metrics().active_region_count, 1);
    }

    #[test]
    fn test_requested_memory_over_envelope_budget_rejects_admission() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.default_memory_budget_bytes = 1024;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, Some(1025))
            .expect("Oversized request should be represented as an admission rejection");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("exceeds region envelope budget"));
        let metrics = governor.metrics();
        assert_eq!(metrics.regions_rejected, 1);
        assert_eq!(metrics.envelope_budget_violations, 1);
    }

    #[test]
    fn test_workload_admission_request_charges_declared_resources_and_owner_metadata() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "asw2-proof-lane",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("src/observability/swarm_pressure_governor.rs"),
        )
        .with_priority(RegionPriority::High)
        .with_declared_resources(Some(4096), Some(25_000), Some(7))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(Instant::now() + Duration::from_secs(60))
        .with_cancellation_budget(Duration::from_millis(250));

        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        let envelope = decision
            .envelope
            .expect("admitted workload must receive a resource envelope");
        assert_eq!(envelope.memory_used.load(Ordering::Relaxed), 4096);
        assert_eq!(envelope.cpu_used_ns.load(Ordering::Relaxed), 25_000);
        assert_eq!(envelope.io_ops_used.load(Ordering::Relaxed), 7);
        for expected in [
            "workload_id=asw2-proof-lane",
            "owner_agent=DustyGorge",
            "bead_id=asupersync-oxqrae.2",
            "reservation_scope=src/observability/swarm_pressure_governor.rs",
            "priority=High",
            "proof_lane=cargo_check_lib",
            "requested_memory_bytes=4096",
            "requested_cpu_ns_per_sec=25000",
            "requested_io_ops_per_sec=7",
            "deadline_set=true",
            "cancellation_budget_ms=250",
            "Admission approved",
        ] {
            assert!(
                decision.reason.contains(expected),
                "decision reason missing {expected}: {}",
                decision.reason
            );
        }
    }

    #[test]
    fn test_workload_admission_rejects_declared_memory_cpu_and_io_over_envelope_budget() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.default_memory_budget_bytes = 1024;
        config.default_cpu_budget_ns_per_sec = 100;
        config.default_io_budget_ops_per_sec = 10;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let memory_request = SwarmWorkloadAdmissionRequest::new(
            "oversized-memory",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_declared_resources(Some(1025), Some(10), Some(1))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let memory_decision = governor
            .check_workload_admission(&cx, &memory_request)
            .expect("oversized memory request should classify");
        assert!(matches!(
            memory_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(memory_decision.envelope.is_none());
        assert!(
            memory_decision
                .reason
                .contains("Requested memory 1025 exceeds")
        );
        assert!(
            memory_decision
                .reason
                .contains("workload_id=oversized-memory")
        );
        assert!(
            memory_decision
                .reason
                .contains("proof_lane=cargo_check_lib")
        );

        let cpu_request = SwarmWorkloadAdmissionRequest::new(
            "oversized-cpu",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_declared_resources(None, Some(101), Some(1))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckAllTargets);
        let cpu_decision = governor
            .check_workload_admission(&cx, &cpu_request)
            .expect("oversized cpu request should classify");
        assert!(matches!(cpu_decision.decision, AdmissionDecision::Reject));
        assert!(cpu_decision.envelope.is_none());
        assert!(cpu_decision.reason.contains("Requested cpu 101 exceeds"));
        assert!(cpu_decision.reason.contains("workload_id=oversized-cpu"));
        assert!(
            cpu_decision
                .reason
                .contains("proof_lane=cargo_check_all_targets")
        );

        let io_request = SwarmWorkloadAdmissionRequest::new(
            "oversized-io",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_declared_resources(None, Some(10), Some(11))
        .with_proof_lane(SwarmProofLaneKind::Test);
        let io_decision = governor
            .check_workload_admission(&cx, &io_request)
            .expect("oversized io request should classify");
        assert!(matches!(io_decision.decision, AdmissionDecision::Reject));
        assert!(io_decision.envelope.is_none());
        assert!(io_decision.reason.contains("Requested io 11 exceeds"));
        assert!(io_decision.reason.contains("workload_id=oversized-io"));
        assert!(io_decision.reason.contains("proof_lane=test"));

        let metrics = governor.metrics();
        assert_eq!(metrics.regions_rejected, 3);
        assert_eq!(metrics.envelope_budget_violations, 3);
    }

    #[test]
    fn test_workload_admission_rejects_invalid_owner_deadline_and_cancel_budget() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let missing_owner =
            SwarmWorkloadAdmissionRequest::new("missing-owner", SwarmAdmissionOwner::new(" "));
        let missing_owner_decision = governor
            .check_workload_admission(&cx, &missing_owner)
            .expect("missing owner should classify as a rejection");
        assert!(matches!(
            missing_owner_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(missing_owner_decision.envelope.is_none());
        assert!(
            missing_owner_decision
                .reason
                .contains("owner agent_name must be non-empty")
        );

        let expired_deadline = SwarmWorkloadAdmissionRequest::new(
            "expired-deadline",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_deadline(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test instant should support one-second subtraction"),
        );
        let expired_deadline_decision = governor
            .check_workload_admission(&cx, &expired_deadline)
            .expect("expired deadline should classify as a rejection");
        assert!(matches!(
            expired_deadline_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(
            expired_deadline_decision
                .reason
                .contains("deadline has already expired")
        );

        let zero_cancel_budget = SwarmWorkloadAdmissionRequest::new(
            "zero-cancel-budget",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_cancellation_budget(Duration::ZERO);
        let zero_cancel_budget_decision = governor
            .check_workload_admission(&cx, &zero_cancel_budget)
            .expect("zero cancel budget should classify as a rejection");
        assert!(matches!(
            zero_cancel_budget_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(
            zero_cancel_budget_decision
                .reason
                .contains("cancellation_budget must be non-zero")
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.total_admission_checks, 3);
        assert_eq!(metrics.regions_rejected, 3);
        assert_eq!(metrics.regions_admitted, 0);
    }

    #[test]
    fn test_workload_lease_commit_renew_release_lifecycle() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let cancellation_budget = Duration::from_millis(750);
        let request = SwarmWorkloadAdmissionRequest::new(
            "lease-lifecycle",
            SwarmAdmissionOwner::new("DustyGorge").with_bead_id("asupersync-oxqrae.2"),
        )
        .with_declared_resources(Some(1024), Some(50), Some(5))
        .with_deadline(Instant::now() + Duration::from_secs(60))
        .with_cancellation_budget(cancellation_budget);
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let region_id = RegionId::new_for_test(50, 1);

        let acquired = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire a lease");
        assert_eq!(acquired.lease_id.as_u64(), 1);
        assert_eq!(acquired.state, SwarmWorkloadLeaseState::Active);
        assert_eq!(acquired.transition, SwarmWorkloadLeaseTransition::Acquired);
        assert_eq!(acquired.transition_reason, "workload lease acquired");
        assert_eq!(
            acquired.replay_pointer,
            "swarm-workload-lease://lease/1/transition/acquired"
        );
        assert_eq!(acquired.cancellation_budget, Some(cancellation_budget));
        assert!(acquired.reason.contains("workload lease acquired"));
        assert!(acquired.reason.contains("cancellation_budget_ms=750"));

        let committed = governor
            .commit_workload_lease(acquired.lease_id)
            .expect("live lease should commit");
        assert_eq!(committed.state, SwarmWorkloadLeaseState::Committed);
        assert_eq!(
            committed.transition,
            SwarmWorkloadLeaseTransition::Committed
        );
        assert_eq!(committed.transition_reason, "workload lease committed");
        assert_eq!(
            committed.replay_pointer,
            "swarm-workload-lease://lease/1/transition/committed"
        );
        assert_eq!(committed.cancellation_budget, Some(cancellation_budget));
        assert!(committed.reason.contains("cancellation_budget_ms=750"));
        let old_expiry = committed.expires_at;

        let renewed = governor
            .renew_workload_lease(acquired.lease_id, Duration::from_secs(30))
            .expect("committed lease should renew");
        assert_eq!(renewed.state, SwarmWorkloadLeaseState::Committed);
        assert_eq!(renewed.transition, SwarmWorkloadLeaseTransition::Renewed);
        assert_eq!(renewed.transition_reason, "workload lease renewed");
        assert_eq!(
            renewed.replay_pointer,
            "swarm-workload-lease://lease/1/transition/renewed"
        );
        assert_eq!(renewed.cancellation_budget, Some(cancellation_budget));
        assert!(renewed.expires_at > old_expiry);
        assert!(renewed.reason.contains("renewals=1"));
        assert!(renewed.reason.contains("cancellation_budget_ms=750"));

        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "lease-lifecycle",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.10, 0.20, 0.30, 0.40, 0.50),
            )
            .expect("live workload pressure feedback should record");
        assert_eq!(governor.metrics().live_workload_feedback_reports, 1);
        let schedule = governor.workload_lease_schedule();
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0].cancellation_budget_ms, Some(750));
        assert!(
            schedule[0].reason.contains("cancellation_budget_ms=750"),
            "schedule rows should expose the lease cancellation budget"
        );

        let released = governor
            .release_workload_lease(acquired.lease_id)
            .expect("renewed lease should release");
        assert_eq!(released.state, SwarmWorkloadLeaseState::Released);
        assert_eq!(released.transition, SwarmWorkloadLeaseTransition::Released);
        assert_eq!(released.transition_reason, "workload lease released");
        assert_eq!(
            released.replay_pointer,
            "swarm-workload-lease://lease/1/transition/released"
        );
        assert_eq!(released.cancellation_budget, Some(cancellation_budget));
        assert!(released.reason.contains("cancellation_budget_ms=750"));
        assert!(released.terminal_at.is_some());
        assert_eq!(
            governor.metrics().live_workload_feedback_reports,
            0,
            "terminal release should clear matching workload pressure feedback"
        );
        assert!(
            governor
                .clear_workload_pressure_feedback("lease-lifecycle")
                .is_none(),
            "release should remove the feedback row rather than leaving it for TTL pruning"
        );
        assert!(
            governor
                .renew_workload_lease(acquired.lease_id, Duration::from_secs(1))
                .is_err(),
            "terminal leases must not renew"
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_leases_acquired, 1);
        assert_eq!(metrics.workload_leases_committed, 1);
        assert_eq!(metrics.workload_leases_renewed, 1);
        assert_eq!(metrics.workload_leases_released, 1);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 1);
    }

    #[test]
    fn test_workload_admission_receipt_binds_lease_to_exact_request() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let deadline = Instant::now() + Duration::from_secs(60);
        let request = SwarmWorkloadAdmissionRequest::new(
            " receipt-owner-a ",
            SwarmAdmissionOwner::new(" DustyGorge ")
                .with_bead_id(" asupersync-oxqrae.2 ")
                .with_reservation_scope(" ./src//observability/swarm_pressure_governor.rs "),
        )
        .with_declared_resources(Some(1024), Some(50), Some(5))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(deadline)
        .with_cancellation_budget(Duration::from_secs(5));

        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let receipt = decision
            .workload_receipt
            .as_ref()
            .expect("workload admission should bind a typed workload receipt");
        assert_eq!(receipt.workload_id, "receipt-owner-a");
        assert_eq!(receipt.owner.agent_name, "DustyGorge");
        assert_eq!(
            receipt.owner.bead_id.as_deref(),
            Some("asupersync-oxqrae.2")
        );
        assert_eq!(
            receipt.owner.reservation_scope.as_deref(),
            Some("src/observability/swarm_pressure_governor.rs")
        );
        assert!(receipt.matches_request(&request));
        assert_eq!(decision.decision_receipt.decision, AdmissionDecision::Admit);
        assert!(decision.decision_receipt.decision_id > 0);
        assert!(
            decision
                .decision_receipt
                .replay_pointer
                .starts_with("swarm-admission://decision/")
        );
        assert_eq!(decision.decision_receipt.reason, decision.reason);
        assert_eq!(
            decision.decision_receipt.workload_id.as_deref(),
            Some("receipt-owner-a")
        );
        assert_eq!(
            decision.decision_receipt.owner_agent.as_deref(),
            Some("DustyGorge")
        );
        assert_eq!(
            decision.decision_receipt.bead_id.as_deref(),
            Some("asupersync-oxqrae.2")
        );
        assert_eq!(
            decision.decision_receipt.reservation_scope.as_deref(),
            Some("src/observability/swarm_pressure_governor.rs")
        );
        assert_eq!(
            decision.decision_receipt.proof_lane,
            Some(SwarmProofLaneKind::CargoCheckLib)
        );
        assert_eq!(decision.decision_receipt.requested_memory_bytes, Some(1024));
        assert_eq!(decision.decision_receipt.requested_cpu_ns_per_sec, Some(50));
        assert_eq!(decision.decision_receipt.requested_io_ops_per_sec, Some(5));
        assert!(decision.decision_receipt.deadline_set);
        assert_eq!(decision.decision_receipt.cancellation_budget_ms, Some(5000));
        assert_eq!(decision.decision_receipt.overall_pressure_scaled, 0);
        assert_eq!(decision.decision_receipt.workload_feedback_report_count, 0);
        assert_eq!(
            decision
                .decision_receipt
                .workload_feedback_max_pressure_scaled,
            0
        );
        assert_eq!(decision.decision_receipt.workload_queue_pressure_scaled, 0);
        assert_eq!(
            decision.decision_receipt.workload_disk_io_pressure_scaled,
            0
        );
        assert_eq!(
            decision.decision_receipt.workload_rch_queue_pressure_scaled,
            0
        );
        assert_eq!(
            decision
                .decision_receipt
                .workload_validation_frontier_pressure_scaled,
            0
        );
        assert_eq!(
            decision
                .decision_receipt
                .workload_cancellation_tail_pressure_scaled,
            0
        );

        let mismatched_request = SwarmWorkloadAdmissionRequest::new(
            "receipt-owner-b",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("src/observability/swarm_pressure_governor.rs"),
        )
        .with_declared_resources(Some(1024), Some(50), Some(5))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(deadline)
        .with_cancellation_budget(Duration::from_secs(5));
        let mismatch = governor
            .acquire_workload_lease(
                RegionId::new_for_test(50, 2),
                &mismatched_request,
                &decision,
            )
            .expect_err("lease acquisition must reject a mismatched admission receipt");
        assert!(matches!(
            mismatch,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("admission workload receipt does not match request")
                    && reason.contains("decision_workload_id=receipt-owner-a")
                    && reason.contains("request_workload_id=receipt-owner-b")
        ));
        assert_eq!(governor.metrics().workload_leases_acquired, 0);

        let acquired = governor
            .acquire_workload_lease(RegionId::new_for_test(50, 1), &request, &decision)
            .expect("matching workload receipt should acquire");
        assert_eq!(acquired.workload_id, "receipt-owner-a");
        assert_eq!(acquired.transition, SwarmWorkloadLeaseTransition::Acquired);
        assert_eq!(acquired.transition_reason, "workload lease acquired");
        assert_eq!(acquired.owner.agent_name, "DustyGorge");
        assert_eq!(
            acquired.owner.bead_id.as_deref(),
            Some("asupersync-oxqrae.2")
        );
        assert_eq!(
            acquired.owner.reservation_scope.as_deref(),
            Some("src/observability/swarm_pressure_governor.rs")
        );
        assert_eq!(acquired.proof_lane, SwarmProofLaneKind::CargoCheckLib);
        assert_eq!(acquired.reserved_memory_bytes, Some(1024));
        assert_eq!(acquired.reserved_cpu_ns_per_sec, Some(50));
        assert_eq!(acquired.reserved_io_ops_per_sec, Some(5));
        assert!(acquired.issued_at <= acquired.expires_at);
        assert_eq!(governor.metrics().workload_leases_acquired, 1);
    }

    #[test]
    fn test_workload_lease_conflicts_abort_and_expiry_are_terminal() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "lease-conflict",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");

        let first = governor
            .acquire_workload_lease(RegionId::new_for_test(51, 1), &request, &decision)
            .expect("first workload lease should acquire");
        assert!(
            governor
                .acquire_workload_lease(RegionId::new_for_test(52, 1), &request, &decision)
                .is_err(),
            "same workload id must not hold two live leases"
        );
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "lease-conflict",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.25, 0.0, 0.0, 0.0, 0.0),
            )
            .expect("abort feedback should record before terminal transition");

        let aborted = governor
            .abort_workload_lease(first.lease_id, "cancelled before proof lane started")
            .expect("live lease should abort");
        assert_eq!(aborted.state, SwarmWorkloadLeaseState::Aborted);
        assert_eq!(aborted.transition, SwarmWorkloadLeaseTransition::Aborted);
        assert_eq!(
            aborted.transition_reason,
            "cancelled before proof lane started"
        );
        assert_eq!(
            aborted.replay_pointer,
            "swarm-workload-lease://lease/1/transition/aborted"
        );
        assert!(
            aborted
                .reason
                .contains("cancelled before proof lane started")
        );
        assert_eq!(
            governor.metrics().live_workload_feedback_reports,
            0,
            "terminal abort should clear matching workload pressure feedback"
        );

        let second_request = SwarmWorkloadAdmissionRequest::new(
            "lease-expiry",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second workload admission should classify");
        let expiring = governor
            .acquire_workload_lease(
                RegionId::new_for_test(53, 1),
                &second_request,
                &second_decision,
            )
            .expect("second workload lease should acquire");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "lease-expiry",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.0, 0.0, 0.90, 0.0, 0.0),
            )
            .expect("expiry feedback should record before terminal transition");
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&expiring.lease_id)
                .expect("lease should exist for forced expiry")
                .expires_at = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test instant should support one-second subtraction");
        }

        let expired = governor.expire_stale_workload_leases();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lease_id, expiring.lease_id);
        assert_eq!(expired[0].state, SwarmWorkloadLeaseState::Expired);
        assert_eq!(expired[0].transition, SwarmWorkloadLeaseTransition::Expired);
        assert_eq!(expired[0].transition_reason, "workload lease expired");
        assert_eq!(
            expired[0].replay_pointer,
            "swarm-workload-lease://lease/2/transition/expired"
        );
        assert_eq!(
            governor.metrics().live_workload_feedback_reports,
            0,
            "terminal expiry should clear matching workload pressure feedback"
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_lease_conflicts, 1);
        assert_eq!(metrics.workload_leases_aborted, 1);
        assert_eq!(metrics.workload_leases_expired, 1);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 2);
    }

    #[test]
    fn test_workload_lease_conflicts_on_live_reservation_scope() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let reservation_scope = "src/observability/swarm_pressure_governor.rs";
        let first_request = SwarmWorkloadAdmissionRequest::new(
            "scope-owner-a",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_reservation_scope(format!(" ./{reservation_scope} ")),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first workload admission should classify");
        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(55, 1),
                &first_request,
                &first_decision,
            )
            .expect("first scoped workload lease should acquire");

        let second_request = SwarmWorkloadAdmissionRequest::new(
            "scope-owner-b",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_reservation_scope("src/observability//swarm_pressure_governor.rs"),
        )
        .with_proof_lane(SwarmProofLaneKind::ClippyAllTargets);
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second workload admission should classify before lease conflict check");

        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 1),
                &second_request,
                &second_decision,
            )
            .expect_err("live reservation scope must reject a second workload lease");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("reservation_scope src/observability/swarm_pressure_governor.rs")
                    && reason.contains("live proof_lane=cargo_check_lib")
                    && reason.contains("requested proof_lane=clippy_all_targets")
        ));
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .abort_workload_lease(first.lease_id, "scope owner cancelled")
            .expect("terminal first lease should release reservation-scope conflict");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 1),
                &second_request,
                &second_decision,
            )
            .expect("terminal prior lease must not block the same reservation scope forever");
        assert_eq!(second.workload_id, "scope-owner-b");
    }

    #[test]
    fn test_workload_lease_proof_lane_capacity_rejects_over_cap_and_releases() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_live_workload_leases_per_proof_lane = 1;
        let governor = create_test_swarm_governor_with_config(config);
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let first_request = SwarmWorkloadAdmissionRequest::new(
            "proof-lane-a",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("proof/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "proof-lane-b",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("proof/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let source_request = SwarmWorkloadAdmissionRequest::new(
            "proof-lane-source",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("proof/source"),
        )
        .with_proof_lane(SwarmProofLaneKind::SourceOnly);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first proof-lane workload admission should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second proof-lane workload admission should classify");
        let source_decision = governor
            .check_workload_admission(&cx, &source_request)
            .expect("different proof-lane workload admission should classify");

        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 10),
                &first_request,
                &first_decision,
            )
            .expect("first workload in capped proof lane should acquire");
        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 11),
                &second_request,
                &second_decision,
            )
            .expect_err("same proof lane should reject over the live lease cap");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("proof_lane cargo_check_lib already has 1 live workload leases")
                    && reason.contains("max_live_workload_leases_per_proof_lane=1")
        ));

        let source = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 12),
                &source_request,
                &source_decision,
            )
            .expect("different proof lane should not consume cargo_check_lib capacity");
        assert_eq!(source.workload_id, "proof-lane-source");
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .release_workload_lease(first.lease_id)
            .expect("releasing first lease should free proof-lane capacity");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 13),
                &second_request,
                &second_decision,
            )
            .expect("released proof-lane capacity should allow the next lease");
        assert_eq!(second.workload_id, "proof-lane-b");
    }

    #[test]
    fn test_workload_lease_owner_capacity_rejects_over_cap_and_releases() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_live_workload_leases_per_owner = 1;
        let governor = create_test_swarm_governor_with_config(config);
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let first_request = SwarmWorkloadAdmissionRequest::new(
            "owner-cap-a",
            SwarmAdmissionOwner::new(" DustyGorge ").with_reservation_scope("owner/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "owner-cap-b",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("owner/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);
        let other_owner_request = SwarmWorkloadAdmissionRequest::new(
            "owner-cap-other",
            SwarmAdmissionOwner::new("TealBass").with_reservation_scope("owner/other"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first owner workload admission should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second owner workload admission should classify");
        let other_owner_decision = governor
            .check_workload_admission(&cx, &other_owner_request)
            .expect("different owner workload admission should classify");

        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 1),
                &first_request,
                &first_decision,
            )
            .expect("first workload for capped owner should acquire");
        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 2),
                &second_request,
                &second_decision,
            )
            .expect_err("same owner should reject over the live lease cap");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("owner_agent DustyGorge already has 1 live workload leases")
                    && reason.contains("max_live_workload_leases_per_owner=1")
        ));

        let other_owner = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 3),
                &other_owner_request,
                &other_owner_decision,
            )
            .expect("different owner should not consume DustyGorge capacity");
        assert_eq!(other_owner.workload_id, "owner-cap-other");
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .release_workload_lease(first.lease_id)
            .expect("releasing first owner lease should free owner capacity");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 4),
                &second_request,
                &second_decision,
            )
            .expect("released owner capacity should allow the next lease");
        assert_eq!(second.workload_id, "owner-cap-b");
    }

    #[test]
    fn test_workload_lease_bead_capacity_rejects_over_cap_and_releases() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_live_workload_leases_per_bead = 1;
        let governor = create_test_swarm_governor_with_config(config);
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let first_request = SwarmWorkloadAdmissionRequest::new(
            "bead-cap-a",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id(" asupersync-oxqrae.2 ")
                .with_reservation_scope("bead/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "bead-cap-b",
            SwarmAdmissionOwner::new("TanAspen")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("bead/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);
        let other_bead_request = SwarmWorkloadAdmissionRequest::new(
            "bead-cap-other",
            SwarmAdmissionOwner::new("TanAspen")
                .with_bead_id("asupersync-oxqrae.3")
                .with_reservation_scope("bead/other"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first bead workload admission should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second bead workload admission should classify");
        let other_bead_decision = governor
            .check_workload_admission(&cx, &other_bead_request)
            .expect("different bead workload admission should classify");

        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 1),
                &first_request,
                &first_decision,
            )
            .expect("first workload for capped bead should acquire");
        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 2),
                &second_request,
                &second_decision,
            )
            .expect_err("same bead should reject over the live lease cap");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("bead_id asupersync-oxqrae.2 already has 1 live workload leases")
                    && reason.contains("max_live_workload_leases_per_bead=1")
        ));

        let other_bead = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 3),
                &other_bead_request,
                &other_bead_decision,
            )
            .expect("different bead should not consume asupersync-oxqrae.2 capacity");
        assert_eq!(other_bead.workload_id, "bead-cap-other");
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .release_workload_lease(first.lease_id)
            .expect("releasing first bead lease should free bead capacity");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 4),
                &second_request,
                &second_decision,
            )
            .expect("released bead capacity should allow the next lease");
        assert_eq!(second.workload_id, "bead-cap-b");
    }

    #[test]
    fn test_unregister_region_envelope_releases_bound_workload_lease() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "region-close-release",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let region_id = RegionId::new_for_test(54, 1);
        governor.register_region_envelope(
            region_id,
            decision
                .envelope
                .clone()
                .expect("admitted workload should include an envelope"),
        );
        let lease = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire a lease");
        governor
            .commit_workload_lease(lease.lease_id)
            .expect("lease should commit before region close");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "region-close-release",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.0, 0.70, 0.0, 0.0, 0.0),
            )
            .expect("region-close feedback should record before terminal transition");

        let removed = governor.unregister_region_envelope(region_id);
        assert!(removed.is_some());
        let stored = governor
            .get_workload_lease(lease.lease_id)
            .expect("released lease should remain available for audit");
        assert_eq!(stored.state, SwarmWorkloadLeaseState::Released);
        assert!(stored.terminal_at.is_some());

        let metrics = governor.metrics();
        assert_eq!(metrics.active_region_count, 0);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 1);
        assert_eq!(metrics.workload_leases_released, 1);
        assert_eq!(
            metrics.live_workload_feedback_reports, 0,
            "region close release should clear matching workload pressure feedback"
        );
    }

    #[test]
    fn test_release_region_workload_leases_marks_region_close_transition() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let region_id = RegionId::new_for_test(54, 2);
        let request = SwarmWorkloadAdmissionRequest::new(
            "region-close-transition",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let lease = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire a lease");

        let receipts = governor.release_region_workload_leases(region_id);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].lease_id, lease.lease_id);
        assert_eq!(receipts[0].state, SwarmWorkloadLeaseState::Released);
        assert_eq!(
            receipts[0].transition,
            SwarmWorkloadLeaseTransition::ReleasedByRegionClose
        );
        assert_eq!(
            receipts[0].transition_reason,
            "workload lease released by region close"
        );
        assert_eq!(
            receipts[0].replay_pointer,
            "swarm-workload-lease://lease/1/transition/released_by_region_close"
        );
        assert!(
            receipts[0]
                .reason
                .contains("workload lease released by region close")
        );
    }

    #[test]
    fn test_abort_region_workload_leases_clears_cancelled_admission_obligations() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let region_id = RegionId::new_for_test(54, 5);
        let first_request = SwarmWorkloadAdmissionRequest::new(
            "cancelled-admission-a",
            SwarmAdmissionOwner::new("OrangeElm").with_reservation_scope("asw/cancel/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "cancelled-admission-b",
            SwarmAdmissionOwner::new("OrangeElm").with_reservation_scope("asw/cancel/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::Test);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first cancelled admission workload should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second cancelled admission workload should classify");
        let first = governor
            .acquire_workload_lease(region_id, &first_request, &first_decision)
            .expect("first cancelled admission lease should acquire");
        let second = governor
            .acquire_workload_lease(region_id, &second_request, &second_decision)
            .expect("second cancelled admission lease should acquire");
        governor
            .commit_workload_lease(first.lease_id)
            .expect("committed lease should still abort on region cancellation");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "cancelled-admission-a",
                    SwarmAdmissionOwner::new("OrangeElm"),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.10, 0.20, 0.30, 0.40, 0.50),
            )
            .expect("first feedback should record before cancellation");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "cancelled-admission-b",
                    SwarmAdmissionOwner::new("OrangeElm"),
                    SwarmProofLaneKind::Test,
                )
                .with_pressures(0.50, 0.40, 0.30, 0.20, 0.10),
            )
            .expect("second feedback should record before cancellation");
        assert_eq!(governor.metrics().live_workload_feedback_reports, 2);

        let receipts =
            governor.abort_region_workload_leases(region_id, "admission cancelled by operator");
        let aborted_ids: Vec<_> = receipts.iter().map(|receipt| receipt.lease_id).collect();
        assert_eq!(receipts.len(), 2);
        assert!(aborted_ids.contains(&first.lease_id));
        assert!(aborted_ids.contains(&second.lease_id));
        for receipt in &receipts {
            assert_eq!(receipt.state, SwarmWorkloadLeaseState::Aborted);
            assert_eq!(receipt.transition, SwarmWorkloadLeaseTransition::Aborted);
            assert_eq!(receipt.transition_reason, "admission cancelled by operator");
            assert!(
                receipt
                    .replay_pointer
                    .starts_with("swarm-workload-lease://lease/")
            );
            assert!(receipt.replay_pointer.ends_with("/transition/aborted"));
            assert!(receipt.reason.contains("admission cancelled by operator"));
        }
        assert!(
            governor
                .abort_region_workload_leases(region_id, "")
                .is_empty(),
            "terminal cancelled leases must not emit duplicate abort receipts"
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_leases_aborted, 2);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 2);
        assert_eq!(
            metrics.live_workload_feedback_reports, 0,
            "region cancellation should clear cancelled workload feedback"
        );
        let audit = governor.workload_lease_audit_snapshot();
        assert_eq!(audit.live_lease_count, 0);
        assert_eq!(audit.aborted_lease_count, 2);
        assert!(!audit.leak_detected, "{}", audit.reason);
    }

    #[test]
    fn test_workload_lease_audit_snapshot_reports_linear_obligation_invariants() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let region_id = RegionId::new_for_test(54, 3);
        let duplicate_region_id = RegionId::new_for_test(54, 4);
        let request = SwarmWorkloadAdmissionRequest::new(
            "lease-audit",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("src/observability/swarm_pressure_governor.rs"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let envelope = decision
            .envelope
            .clone()
            .expect("admitted workload should include an envelope");
        let lease = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire");

        let unbound_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(unbound_audit.live_lease_count, 1);
        assert_eq!(unbound_audit.active_lease_count, 1);
        assert_eq!(unbound_audit.live_unregistered_region_count, 1);
        assert!(unbound_audit.leak_detected, "{}", unbound_audit.reason);
        assert!(
            unbound_audit
                .reason
                .contains("live_unregistered_region_count=1")
        );

        governor.register_region_envelope(region_id, envelope.clone());
        let bound_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(bound_audit.live_unregistered_region_count, 0);
        assert!(!bound_audit.leak_detected, "{}", bound_audit.reason);

        governor
            .commit_workload_lease(lease.lease_id)
            .expect("bound lease should commit");
        governor.register_region_envelope(duplicate_region_id, envelope);
        let duplicate_id = SwarmWorkloadLeaseId::new_for_test(99_001);
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            let mut duplicate = leases
                .get(&lease.lease_id)
                .expect("original lease should exist")
                .clone();
            duplicate.lease_id = duplicate_id;
            duplicate.region_id = duplicate_region_id;
            duplicate.state = SwarmWorkloadLeaseState::Active;
            duplicate.terminal_at = None;
            leases.insert(duplicate_id, duplicate);
        }

        let duplicate_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(duplicate_audit.live_lease_count, 2);
        assert_eq!(duplicate_audit.duplicate_live_workload_id_count, 1);
        assert_eq!(duplicate_audit.duplicate_live_owner_agent_count, 1);
        assert_eq!(duplicate_audit.duplicate_live_bead_id_count, 1);
        assert_eq!(duplicate_audit.duplicate_live_reservation_scope_count, 1);
        assert!(
            duplicate_audit
                .reason
                .contains("duplicate_live_owner_agent_count=1")
        );
        assert!(
            duplicate_audit
                .reason
                .contains("duplicate_live_bead_id_count=1")
        );
        assert!(duplicate_audit.leak_detected, "{}", duplicate_audit.reason);

        {
            let mut leases = governor.workload_leases.lock().unwrap();
            let duplicate = leases
                .get_mut(&duplicate_id)
                .expect("duplicate lease should exist");
            duplicate.state = SwarmWorkloadLeaseState::Aborted;
            duplicate.terminal_at = Some(Instant::now());
        }
        governor
            .release_workload_lease(lease.lease_id)
            .expect("original lease should release");
        let terminal_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(terminal_audit.live_lease_count, 0);
        assert_eq!(terminal_audit.terminal_lease_count, 2);
        assert!(!terminal_audit.leak_detected, "{}", terminal_audit.reason);

        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&lease.lease_id)
                .expect("released lease should exist")
                .terminal_at = None;
        }
        let missing_terminal_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(missing_terminal_audit.terminal_missing_terminal_at_count, 1);
        assert!(
            missing_terminal_audit.leak_detected,
            "{}",
            missing_terminal_audit.reason
        );
    }

    #[test]
    fn test_workload_lease_schedule_orders_live_leases_deterministically_and_expires_stale() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let deadline_base = Instant::now() + Duration::from_secs(60);
        let shared_high_deadline = deadline_base + Duration::from_secs(90);

        let critical_request = SwarmWorkloadAdmissionRequest::new(
            "critical-source",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::Critical)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline_base + Duration::from_secs(300));
        let high_release_request = SwarmWorkloadAdmissionRequest::new(
            "high-release",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::High)
        .with_proof_lane(SwarmProofLaneKind::ReleaseProof)
        .with_deadline(shared_high_deadline);
        let high_source_request = SwarmWorkloadAdmissionRequest::new(
            "high-source",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::High)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(shared_high_deadline);
        let normal_request = SwarmWorkloadAdmissionRequest::new(
            "normal-check",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::Normal)
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(deadline_base + Duration::from_secs(10));
        let stale_request = SwarmWorkloadAdmissionRequest::new(
            "stale-best-effort",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::BestEffort)
        .with_proof_lane(SwarmProofLaneKind::Test)
        .with_deadline(deadline_base + Duration::from_secs(5));

        let critical_decision = governor
            .check_workload_admission(&cx, &critical_request)
            .expect("critical workload admission should classify");
        let high_release_decision = governor
            .check_workload_admission(&cx, &high_release_request)
            .expect("release proof workload admission should classify");
        let high_source_decision = governor
            .check_workload_admission(&cx, &high_source_request)
            .expect("source workload admission should classify");
        let normal_decision = governor
            .check_workload_admission(&cx, &normal_request)
            .expect("normal workload admission should classify");
        let stale_decision = governor
            .check_workload_admission(&cx, &stale_request)
            .expect("stale workload admission should classify");

        let critical = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 1),
                &critical_request,
                &critical_decision,
            )
            .expect("critical workload should acquire a lease");
        let high_release = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 2),
                &high_release_request,
                &high_release_decision,
            )
            .expect("high release workload should acquire a lease");
        let high_source = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 3),
                &high_source_request,
                &high_source_decision,
            )
            .expect("high source workload should acquire a lease");
        let normal = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 4),
                &normal_request,
                &normal_decision,
            )
            .expect("normal workload should acquire a lease");
        let stale = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 5),
                &stale_request,
                &stale_decision,
            )
            .expect("stale workload should initially acquire a lease");

        governor
            .commit_workload_lease(high_release.lease_id)
            .expect("committed lease should remain scheduleable");
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&high_release.lease_id)
                .expect("release lease should exist")
                .expires_at = shared_high_deadline;
            leases
                .get_mut(&high_source.lease_id)
                .expect("source lease should exist")
                .expires_at = shared_high_deadline;
            leases
                .get_mut(&stale.lease_id)
                .expect("stale lease should exist")
                .expires_at = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test instant should support one-second subtraction");
        }

        let schedule = governor.workload_lease_schedule();
        let ordered_ids: Vec<_> = schedule.iter().map(|entry| entry.lease_id).collect();
        assert_eq!(
            ordered_ids,
            vec![
                critical.lease_id,
                high_release.lease_id,
                high_source.lease_id,
                normal.lease_id
            ]
        );
        assert_eq!(schedule[0].scheduling_rank, 0);
        assert_eq!(schedule[0].priority, RegionPriority::Critical);
        assert!(!schedule[0].pressure_feedback_present);
        assert_eq!(schedule[0].max_pressure_scaled, 0);
        assert!(
            schedule[0].time_to_expiry_ms > 0,
            "live schedule rows should expose structured time-to-expiry"
        );
        assert_eq!(schedule[1].proof_lane, SwarmProofLaneKind::ReleaseProof);
        assert_eq!(schedule[2].proof_lane, SwarmProofLaneKind::SourceOnly);
        assert!(
            schedule[1]
                .replay_pointer
                .starts_with("swarm-workload-lease://lease/")
        );
        assert!(
            schedule[1]
                .reason
                .contains("live workload lease scheduled without pressure feedback")
        );
        assert!(schedule[1].reason.contains("time_to_expiry_ms="));

        let expired = governor
            .get_workload_lease(stale.lease_id)
            .expect("expired lease should remain available for audit");
        assert_eq!(expired.state, SwarmWorkloadLeaseState::Expired);
        let metrics = governor.metrics();
        assert_eq!(metrics.workload_leases_expired, 1);
        assert_eq!(metrics.active_workload_lease_count, 4);
        assert_eq!(metrics.terminal_workload_lease_count, 1);
    }

    #[test]
    fn test_workload_lease_schedule_applies_starvation_aging_without_overtaking_critical() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let mut config = SwarmPressureGovernorConfig::default();
        config.workload_lease_starvation_aging_step = Duration::from_secs(10);
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let deadline = Instant::now() + Duration::from_secs(300);

        let critical_request = SwarmWorkloadAdmissionRequest::new(
            "critical-admission",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("critical-lane"),
        )
        .with_priority(RegionPriority::Critical)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline);
        let fresh_normal_request = SwarmWorkloadAdmissionRequest::new(
            "fresh-normal",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("normal-lane"),
        )
        .with_priority(RegionPriority::Normal)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline);
        let aged_low_request = SwarmWorkloadAdmissionRequest::new(
            "aged-low",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("low-lane"),
        )
        .with_priority(RegionPriority::Low)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline);

        let critical_decision = governor
            .check_workload_admission(&cx, &critical_request)
            .expect("critical workload admission should classify");
        let fresh_normal_decision = governor
            .check_workload_admission(&cx, &fresh_normal_request)
            .expect("fresh normal workload admission should classify");
        let aged_low_decision = governor
            .check_workload_admission(&cx, &aged_low_request)
            .expect("aged low workload admission should classify");

        let critical = governor
            .acquire_workload_lease(
                RegionId::new_for_test(59, 1),
                &critical_request,
                &critical_decision,
            )
            .expect("critical workload should acquire lease");
        let fresh_normal = governor
            .acquire_workload_lease(
                RegionId::new_for_test(59, 2),
                &fresh_normal_request,
                &fresh_normal_decision,
            )
            .expect("fresh normal workload should acquire lease");
        let aged_low = governor
            .acquire_workload_lease(
                RegionId::new_for_test(59, 3),
                &aged_low_request,
                &aged_low_decision,
            )
            .expect("aged low workload should acquire lease");

        let now = Instant::now();
        let old_issued_at = now
            .checked_sub(Duration::from_secs(25))
            .expect("test time should support subtracting wait age");
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&critical.lease_id)
                .expect("critical lease should exist")
                .expires_at = deadline;
            leases
                .get_mut(&fresh_normal.lease_id)
                .expect("fresh normal lease should exist")
                .expires_at = deadline;
            let aged = leases
                .get_mut(&aged_low.lease_id)
                .expect("aged low lease should exist");
            aged.issued_at = old_issued_at;
            aged.expires_at = deadline;
        }

        let schedule = governor.workload_lease_schedule();
        let ordered_ids: Vec<_> = schedule.iter().map(|entry| entry.lease_id).collect();
        assert_eq!(
            ordered_ids,
            vec![critical.lease_id, aged_low.lease_id, fresh_normal.lease_id],
            "aged low-priority work should catch up to fresh normal work but not critical work"
        );
        assert_eq!(schedule[0].effective_priority_rank, 0);
        assert_eq!(schedule[0].starvation_aging_discount, 0);
        assert_eq!(schedule[1].workload_id, "aged-low");
        assert_eq!(schedule[1].effective_priority_rank, 1);
        assert_eq!(schedule[1].starvation_aging_discount, 2);
        assert!(
            schedule[1].wait_age_ms >= 20_000,
            "aged low-priority lease should expose structured wait age"
        );
        assert!(
            schedule[1].time_to_expiry_ms > 0,
            "aged low-priority lease should expose structured time-to-expiry"
        );
        assert!(schedule[1].reason.contains("wait_age_ms="));
        assert!(schedule[1].reason.contains("time_to_expiry_ms="));
        assert!(
            schedule[1].reason.contains("starvation_aging_discount=2"),
            "{}",
            schedule[1].reason
        );
        assert!(
            schedule[1].reason.contains("effective_priority_rank=1"),
            "{}",
            schedule[1].reason
        );
        assert_eq!(schedule[2].workload_id, "fresh-normal");
        assert_eq!(schedule[2].effective_priority_rank, 2);
        assert_eq!(schedule[2].starvation_aging_discount, 0);

        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);

        let pressure_schedule = governor.workload_lease_schedule();
        let pressure_ordered_ids: Vec<_> = pressure_schedule
            .iter()
            .map(|entry| entry.lease_id)
            .collect();
        assert_eq!(
            pressure_ordered_ids,
            vec![critical.lease_id, fresh_normal.lease_id, aged_low.lease_id],
            "host resource pressure should defer aged background work behind fresh foreground work"
        );
        let normal_row = pressure_schedule
            .iter()
            .find(|entry| entry.workload_id == "fresh-normal")
            .expect("fresh normal row should be scheduled");
        assert_eq!(
            normal_row.resource_degradation_level,
            DegradationLevel::Heavy
        );
        assert_eq!(normal_row.resource_pressure_scaled, 7500);
        assert!(!normal_row.resource_pressure_deferral);
        let aged_row = pressure_schedule
            .iter()
            .find(|entry| entry.workload_id == "aged-low")
            .expect("aged low row should be scheduled");
        assert_eq!(aged_row.resource_degradation_level, DegradationLevel::Heavy);
        assert_eq!(aged_row.resource_pressure_scaled, 7500);
        assert!(aged_row.resource_pressure_deferral, "{}", aged_row.reason);
        assert!(
            aged_row.reason.contains("resource_degradation_level=heavy"),
            "{}",
            aged_row.reason
        );
        assert!(
            aged_row.reason.contains("resource_pressure_deferral=true"),
            "{}",
            aged_row.reason
        );
    }

    #[test]
    fn test_workload_lease_schedule_uses_live_pressure_feedback() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let shared_deadline = Instant::now() + Duration::from_secs(120);
        let hot_owner = SwarmAdmissionOwner::new("DustyGorge")
            .with_bead_id("asupersync-oxqrae.2")
            .with_reservation_scope("asw-hot-rch-lane");
        let cool_owner = SwarmAdmissionOwner::new("DustyGorge")
            .with_bead_id("asupersync-oxqrae.2")
            .with_reservation_scope("asw-cool-rch-lane");
        let hot_request = SwarmWorkloadAdmissionRequest::new("hot-rch-lane", hot_owner)
            .with_priority(RegionPriority::Normal)
            .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
            .with_deadline(shared_deadline);
        let cool_request = SwarmWorkloadAdmissionRequest::new("cool-rch-lane", cool_owner)
            .with_priority(RegionPriority::Normal)
            .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
            .with_deadline(shared_deadline);

        let hot_decision = governor
            .check_workload_admission(&cx, &hot_request)
            .expect("hot workload admission should classify");
        let cool_decision = governor
            .check_workload_admission(&cx, &cool_request)
            .expect("cool workload admission should classify");
        let hot = governor
            .acquire_workload_lease(RegionId::new_for_test(58, 1), &hot_request, &hot_decision)
            .expect("hot workload should acquire first lease");
        let cool = governor
            .acquire_workload_lease(RegionId::new_for_test(58, 2), &cool_request, &cool_decision)
            .expect("cool workload should acquire second lease");

        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "hot-rch-lane",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.20, 0.40, 0.95, 0.90, 0.30),
            )
            .expect("hot pressure feedback should be accepted");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "cool-rch-lane",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.05, 0.10, 0.20, 0.15, 0.05),
            )
            .expect("cool pressure feedback should be accepted");

        let schedule = governor.workload_lease_schedule();
        let ordered_ids: Vec<_> = schedule.iter().map(|entry| entry.lease_id).collect();
        assert_eq!(
            ordered_ids,
            vec![cool.lease_id, hot.lease_id],
            "lower-pressure workload should schedule before an otherwise identical hot lane"
        );
        assert_eq!(schedule[0].workload_id, "cool-rch-lane");
        assert!(schedule[0].pressure_feedback_present);
        assert!(
            !schedule[0].workload_pressure_deferral,
            "{}",
            schedule[0].reason
        );
        assert_eq!(
            schedule[0].dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert_eq!(schedule[0].max_pressure_scaled, 2000);
        assert_eq!(schedule[0].rch_queue_pressure_scaled, 2000);
        assert_eq!(schedule[1].workload_id, "hot-rch-lane");
        assert!(schedule[1].pressure_feedback_present);
        assert!(
            schedule[1].workload_pressure_deferral,
            "{}",
            schedule[1].reason
        );
        assert_eq!(
            schedule[1].dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert_eq!(schedule[1].queue_pressure_scaled, 2000);
        assert_eq!(schedule[1].disk_io_pressure_scaled, 4000);
        assert_eq!(schedule[1].rch_queue_pressure_scaled, 9500);
        assert_eq!(schedule[1].validation_frontier_pressure_scaled, 9000);
        assert_eq!(schedule[1].cancellation_tail_pressure_scaled, 3000);
        assert_eq!(schedule[1].max_pressure_scaled, 9500);
        assert!(
            schedule[1]
                .reason
                .contains("scheduled with pressure feedback")
        );
        assert!(
            schedule[1]
                .reason
                .contains("dominant_pressure_source=rch_queue")
        );
        assert!(
            schedule[1]
                .reason
                .contains("workload_pressure_deferral=true")
        );
    }

    #[test]
    fn test_peer_pressure_backpressures_normal_admission() {
        let governor = create_test_swarm_governor();
        governor
            .record_peer_pressure("peer-a", 0.85, DegradationLevel::Moderate)
            .expect("peer pressure report should be accepted");

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Peer pressure admission should produce a decision");

        assert!(matches!(
            decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        assert!(decision.envelope.is_some());
        assert!(decision.reason.contains("live peer pressure reports"));
        assert_eq!(decision.decision_receipt.peer_pressure_report_count, 1);
        assert!(
            (decision.decision_receipt.peer_pressure_max_pressure_scaled - 8500).abs() <= 1,
            "receipt peer pressure should round near 8500, got {}",
            decision.decision_receipt.peer_pressure_max_pressure_scaled
        );
        assert_eq!(
            decision
                .decision_receipt
                .peer_pressure_backpressure_threshold_scaled,
            8000
        );
        assert!(
            decision
                .decision_receipt
                .peer_pressure_backpressure_triggered
        );
        assert_eq!(
            decision
                .decision_receipt
                .peer_pressure_max_degradation_level,
            DegradationLevel::Moderate as u8
        );
        assert!(decision.reason.contains("peer pressure threshold 0.800"));
        assert!(
            decision
                .reason
                .contains("peer pressure backpressure triggered true")
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.live_peer_pressure_reports, 1);
        assert!(
            (metrics.max_peer_pressure_scaled - 8500).abs() <= 1,
            "scaled peer pressure should round near 8500, got {}",
            metrics.max_peer_pressure_scaled
        );
        assert_eq!(
            metrics.max_peer_degradation_level,
            DegradationLevel::Moderate as u8
        );
    }

    #[test]
    fn test_configurable_peer_pressure_threshold_controls_backpressure() {
        let mut tuned_config = SwarmPressureGovernorConfig::default();
        tuned_config.peer_pressure_backpressure_threshold = 0.70;
        let tuned_runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let tuned_pressure_governor = PressureGovernor::new(
            tuned_config.pressure_config.clone(),
            std::sync::Arc::clone(&tuned_runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let tuned_governor = SwarmPressureGovernor::new(
            tuned_config,
            tuned_runtime.resource_monitor(),
            tuned_pressure_governor,
        );
        tuned_governor
            .record_peer_pressure("peer-tuned", 0.75, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");
        let tuned_cx = tuned_runtime.request_cx_with_budget(Budget::INFINITE);

        let tuned_decision = tuned_governor
            .check_region_admission(&tuned_cx, RegionPriority::Normal, None)
            .expect("tuned peer pressure admission should produce a decision");

        assert!(matches!(
            tuned_decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        assert!(tuned_decision.reason.contains("max peer pressure 0.750"));

        let default_governor = create_test_swarm_governor();
        default_governor
            .record_peer_pressure("peer-default", 0.75, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");
        let default_runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let default_cx = default_runtime.request_cx_with_budget(Budget::INFINITE);

        let default_decision = default_governor
            .check_region_admission(&default_cx, RegionPriority::Normal, None)
            .expect("default peer pressure admission should produce a decision");

        assert!(matches!(
            default_decision.decision,
            AdmissionDecision::Admit
        ));
    }

    #[test]
    fn test_invalid_peer_pressure_threshold_falls_back_to_default() {
        for invalid_threshold in [f64::NAN, -0.01] {
            let mut config = SwarmPressureGovernorConfig::default();
            config.peer_pressure_backpressure_threshold = invalid_threshold;
            let runtime = std::sync::Arc::new(
                RuntimeBuilder::new()
                    .worker_threads(1)
                    .build()
                    .expect("Failed to create test runtime"),
            );
            let pressure_governor = PressureGovernor::new(
                config.pressure_config.clone(),
                std::sync::Arc::clone(&runtime),
                Metrics::new(),
            )
            .expect("Failed to create pressure governor");
            let governor =
                SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);

            governor
                .record_peer_pressure("peer-below-default", 0.75, DegradationLevel::Light)
                .expect("peer pressure report should be accepted");
            let below_default = governor
                .check_region_admission(&cx, RegionPriority::Normal, None)
                .expect("admission should use fallback peer threshold");
            assert!(matches!(below_default.decision, AdmissionDecision::Admit));

            assert!(governor.clear_peer_pressure("peer-below-default").is_some());
            governor
                .record_peer_pressure("peer-above-default", 0.85, DegradationLevel::Light)
                .expect("peer pressure report should be accepted");
            let above_default = governor
                .check_region_admission(&cx, RegionPriority::Normal, None)
                .expect("admission should use fallback peer threshold");
            assert!(matches!(
                above_default.decision,
                AdmissionDecision::AdmitWithBackpressure
            ));
        }
    }

    #[test]
    fn test_peer_pressure_rejects_low_priority_admission() {
        let governor = create_test_swarm_governor();
        governor
            .record_peer_pressure("peer-b", 0.81, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Low, None)
            .expect("Peer pressure admission should produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("peer pressure"));
        assert_eq!(governor.metrics().regions_rejected, 1);
    }

    #[test]
    fn test_workload_pressure_feedback_backpressures_matching_workload_only() {
        let governor = create_test_swarm_governor();
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "hot-proof",
                    SwarmAdmissionOwner::new(" DustyGorge ")
                        .with_bead_id(" asupersync-oxqrae.2 ")
                        .with_reservation_scope(" src/observability/swarm_pressure_governor.rs "),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.20, 0.30, 0.85, 0.40, 0.10),
            )
            .expect("workload feedback should be accepted");
        {
            let reports = governor.workload_pressure_feedback.lock().unwrap();
            let feedback = reports
                .get("hot-proof")
                .expect("feedback should be stored by normalized workload id");
            assert_eq!(feedback.owner.agent_name, "DustyGorge");
            assert_eq!(
                feedback.owner.bead_id.as_deref(),
                Some("asupersync-oxqrae.2")
            );
            assert_eq!(
                feedback.owner.reservation_scope.as_deref(),
                Some("src/observability/swarm_pressure_governor.rs")
            );
        }

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let hot_request =
            SwarmWorkloadAdmissionRequest::new("hot-proof", SwarmAdmissionOwner::new("DustyGorge"));
        let hot_decision = governor
            .check_workload_admission(&cx, &hot_request)
            .expect("hot workload admission should classify");
        assert!(matches!(
            hot_decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        assert!(
            hot_decision
                .reason
                .contains("live workload feedback reports")
        );
        assert!(hot_decision.reason.contains("max workload pressure 0.850"));
        assert!(
            hot_decision
                .reason
                .contains("dominant workload pressure source rch_queue")
        );
        assert_eq!(
            hot_decision.decision_receipt.workload_feedback_report_count,
            1
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_feedback_max_pressure_scaled,
            8500
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_feedback_backpressure_threshold_scaled,
            8000
        );
        assert!(
            hot_decision
                .decision_receipt
                .workload_feedback_backpressure_triggered
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert!(
            hot_decision
                .reason
                .contains("workload feedback threshold 0.800")
        );
        assert!(
            hot_decision
                .reason
                .contains("workload feedback backpressure triggered true")
        );
        assert_eq!(
            hot_decision.decision_receipt.workload_queue_pressure_scaled,
            2000
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_disk_io_pressure_scaled,
            3000
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_rch_queue_pressure_scaled,
            8500
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_validation_frontier_pressure_scaled,
            4000
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_cancellation_tail_pressure_scaled,
            1000
        );

        let cold_request = SwarmWorkloadAdmissionRequest::new(
            "cold-proof",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let cold_decision = governor
            .check_workload_admission(&cx, &cold_request)
            .expect("cold workload admission should classify");
        assert!(matches!(cold_decision.decision, AdmissionDecision::Admit));
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_report_count,
            0
        );
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_max_pressure_scaled,
            0
        );
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_backpressure_threshold_scaled,
            8000
        );
        assert!(
            !cold_decision
                .decision_receipt
                .workload_feedback_backpressure_triggered
        );
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::None
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_feedback_reports_recorded, 1);
        assert_eq!(metrics.live_workload_feedback_reports, 1);
        assert!(
            (metrics.max_workload_feedback_pressure_scaled - 8500).abs() <= 1,
            "scaled workload feedback should round near 8500, got {}",
            metrics.max_workload_feedback_pressure_scaled
        );
        assert_eq!(
            metrics.workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert_eq!(metrics.max_workload_feedback_queue_pressure_scaled, 2000);
        assert_eq!(metrics.max_workload_feedback_disk_io_pressure_scaled, 3000);
        assert_eq!(
            metrics.max_workload_feedback_rch_queue_pressure_scaled,
            8500
        );
        assert_eq!(
            metrics.max_workload_feedback_validation_frontier_pressure_scaled,
            4000
        );
        assert_eq!(
            metrics.max_workload_feedback_cancellation_tail_pressure_scaled,
            1000
        );
    }

    #[test]
    fn test_workload_pressure_feedback_rejects_background_and_prunes_stale_reports() {
        let governor = create_test_swarm_governor();
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "background-proof",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::Test,
                )
                .with_pressures(0.10, 0.20, 0.30, 0.90, 0.40),
            )
            .expect("workload feedback should be accepted");
        assert!(matches!(
            governor.record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "bad-feedback",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::Test,
                )
                .with_pressures(f64::NAN, 0.0, 0.0, 0.0, 0.0),
            ),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "background-proof",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::BestEffort);
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("background workload admission should classify");
        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("live workload feedback reports"));

        {
            let mut reports = governor.workload_pressure_feedback.lock().unwrap();
            reports
                .get_mut("background-proof")
                .expect("feedback should exist before forced stale pruning")
                .reported_at = Instant::now()
                .checked_sub(
                    governor
                        .config
                        .workload_feedback_max_age
                        .checked_mul(2)
                        .expect("test feedback max age should double"),
                )
                .expect("test instant should support feedback-age subtraction");
        }
        assert_eq!(governor.prune_stale_workload_pressure_feedback(), 1);
        let metrics = governor.metrics();
        assert_eq!(metrics.live_workload_feedback_reports, 0);
        assert_eq!(
            metrics.workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::None
        );
        assert_eq!(metrics.max_workload_feedback_pressure_scaled, 0);
        assert_eq!(
            metrics.max_workload_feedback_validation_frontier_pressure_scaled,
            0
        );
    }

    #[test]
    fn test_hard_pressure_reject_is_not_downgraded_by_moderate_degradation() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let mut config = SwarmPressureGovernorConfig::default();
        config.pressure_config.enabled = true;
        config.pressure_config.admission_control = true;
        config.pressure_config.sample_interval = Duration::ZERO;

        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        pressure_governor.record_channel_backlog_sample(5, 4);

        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Moderate,
            );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("hard pressure rejection should produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("Rejected due to pressure"));
        assert_eq!(governor.metrics().regions_rejected, 1);
    }

    #[test]
    fn test_emergency_system_degradation_rejects_normal_admission() {
        let governor = create_test_swarm_governor();
        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Emergency,
            );
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Emergency degradation should still return a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("Emergency"));
        assert_eq!(governor.metrics().regions_rejected, 1);
    }

    #[test]
    fn metamorphic_degradation_never_makes_noncritical_admission_safer() {
        let governor = create_test_swarm_governor();
        let levels = [
            DegradationLevel::None,
            DegradationLevel::Light,
            DegradationLevel::Moderate,
            DegradationLevel::Heavy,
            DegradationLevel::Emergency,
        ];

        for priority in [
            RegionPriority::Normal,
            RegionPriority::Low,
            RegionPriority::BestEffort,
        ] {
            let mut previous_rank = 0;
            for level in levels {
                let decision = governor
                    .evaluate_swarm_admission(
                        priority,
                        &AdmissionDecision::Admit,
                        level,
                        None,
                        SwarmPeerPressureSummary::EMPTY,
                        SwarmWorkloadPressureSummary::EMPTY,
                    )
                    .expect("metamorphic degradation admission should classify");
                let rank = admission_rank(decision.decision);
                assert!(
                    rank >= previous_rank,
                    "worse degradation made {priority:?} admission safer: {level:?} -> {:?}",
                    decision.decision
                );
                previous_rank = rank;
            }
        }

        let critical = governor
            .evaluate_swarm_admission(
                RegionPriority::Critical,
                &AdmissionDecision::Admit,
                DegradationLevel::Emergency,
                None,
                SwarmPeerPressureSummary::EMPTY,
                SwarmWorkloadPressureSummary::EMPTY,
            )
            .expect("critical admission should classify");
        assert!(matches!(critical.decision, AdmissionDecision::Admit));
    }

    #[test]
    fn metamorphic_requested_memory_never_makes_normal_admission_safer() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.default_memory_budget_bytes = 1024;
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let requests = [0, 512, 1024, 1025, 2048, u64::MAX];

        let mut previous_rank = 0;
        for requested_memory in requests {
            let decision = governor
                .check_region_admission(&cx, RegionPriority::Normal, Some(requested_memory))
                .expect("memory-pressure admission should classify");
            let rank = admission_rank(decision.decision);
            assert!(
                rank >= previous_rank,
                "larger requested memory made normal admission safer: {requested_memory} -> {:?}",
                decision.decision
            );
            if requested_memory <= 1024 {
                assert!(
                    decision.envelope.is_some(),
                    "in-budget request should preserve admitted envelope"
                );
            } else {
                assert!(
                    decision.envelope.is_none(),
                    "over-budget request must not allocate an envelope"
                );
            }
            previous_rank = rank;
        }
    }

    #[test]
    fn metamorphic_peer_pressure_transition_storm_never_improves_background_admission() {
        let governor = create_test_swarm_governor();
        let peer_pressures = [0.0, 0.20, 0.79, 0.80, 0.95, 1.25];

        for priority in [
            RegionPriority::Normal,
            RegionPriority::Low,
            RegionPriority::BestEffort,
        ] {
            let mut previous_rank = 0;
            for peer_pressure in peer_pressures {
                governor
                    .record_peer_pressure("peer-storm", peer_pressure, DegradationLevel::Light)
                    .expect("peer pressure report should be accepted");
                let decision = governor
                    .evaluate_swarm_admission(
                        priority,
                        &AdmissionDecision::Admit,
                        DegradationLevel::None,
                        None,
                        governor.peer_pressure_summary(Instant::now()),
                        SwarmWorkloadPressureSummary::EMPTY,
                    )
                    .expect("peer-pressure admission should classify");
                let rank = admission_rank(decision.decision);
                assert!(
                    rank >= previous_rank,
                    "higher peer pressure made {priority:?} admission safer: {peer_pressure} -> {:?}",
                    decision.decision
                );
                previous_rank = rank;
            }
            assert!(governor.clear_peer_pressure("peer-storm").is_some());
        }
    }

    #[test]
    fn test_peer_pressure_rejects_invalid_reports() {
        let governor = create_test_swarm_governor();

        assert!(matches!(
            governor.record_peer_pressure("", 0.5, DegradationLevel::Light),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));
        assert!(matches!(
            governor.record_peer_pressure("peer-a", f64::NAN, DegradationLevel::Light),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));
        assert!(matches!(
            governor.record_peer_pressure("peer-a", -0.01, DegradationLevel::Light),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));
        assert_eq!(governor.metrics().live_peer_pressure_reports, 0);
    }

    #[test]
    fn test_peer_pressure_normalizes_instance_ids() {
        let governor = create_test_swarm_governor();

        governor
            .record_peer_pressure(" peer-a ", 0.40, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");
        governor
            .record_peer_pressure("peer-a", 0.85, DegradationLevel::Moderate)
            .expect("same peer report should update by normalized id");

        let metrics = governor.metrics();
        assert_eq!(
            metrics.live_peer_pressure_reports, 1,
            "whitespace variants must not inflate live peer counts"
        );
        assert!(
            (metrics.max_peer_pressure_scaled - 8500).abs() <= 1,
            "normalized update should replace the old peer pressure, got {}",
            metrics.max_peer_pressure_scaled
        );

        let cleared = governor
            .clear_peer_pressure(" peer-a ")
            .expect("normalized peer report should be clearable by whitespace variant");
        assert_eq!(cleared.instance_id, "peer-a");
        assert_eq!(governor.metrics().live_peer_pressure_reports, 0);
    }

    #[test]
    fn test_prune_stale_peer_pressure_reports_removes_dead_peer_state() {
        let governor = create_test_swarm_governor();
        governor
            .record_peer_pressure("stale-peer", 0.91, DegradationLevel::Heavy)
            .expect("stale peer report should be accepted");
        governor
            .record_peer_pressure("fresh-peer", 0.40, DegradationLevel::Light)
            .expect("fresh peer report should be accepted");
        let stale_reported_at = Instant::now()
            .checked_sub(
                governor
                    .config
                    .peer_pressure_max_age
                    .checked_mul(2)
                    .expect("test peer pressure max age should double without overflow"),
            )
            .expect("test stale timestamp should be representable");

        {
            let mut reports = governor.peer_pressure_reports.lock().unwrap();
            reports
                .get_mut("stale-peer")
                .expect("stale peer report should exist before pruning")
                .reported_at = stale_reported_at;
        }

        assert_eq!(governor.prune_stale_peer_pressure_reports(), 1);
        assert!(governor.clear_peer_pressure("stale-peer").is_none());

        let metrics = governor.metrics();
        assert_eq!(metrics.live_peer_pressure_reports, 1);
        assert_eq!(
            metrics.max_peer_degradation_level,
            DegradationLevel::Light as u8
        );
        assert!(governor.clear_peer_pressure("fresh-peer").is_some());
    }

    #[test]
    fn test_critical_priority_always_admitted() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Critical, None)
            .expect("Critical admission should succeed");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        assert_eq!(decision.reason, "Admission approved");
    }
}
