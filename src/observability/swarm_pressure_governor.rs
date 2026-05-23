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
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

const DEFAULT_PEER_PRESSURE_BACKPRESSURE_THRESHOLD: f64 = 0.80;
const DEFAULT_WORKLOAD_FEEDBACK_BACKPRESSURE_THRESHOLD: f64 = 0.80;

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
    max_overall_pressure: f64,
}

impl SwarmWorkloadPressureSummary {
    const EMPTY: Self = Self {
        live_report_count: 0,
        max_overall_pressure: 0.0,
    };

    #[must_use]
    fn has_live_pressure(self) -> bool {
        self.live_report_count > 0
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
        format!(
            "workload_id={} owner_agent={} bead_id={} reservation_scope={} priority={:?} proof_lane={} requested_memory_bytes={} requested_cpu_ns_per_sec={} requested_io_ops_per_sec={} deadline_set={} cancellation_budget_ms={}: {base}",
            self.workload_id.trim(),
            self.owner.agent_name.trim(),
            optional_reason_field(self.owner.bead_id.as_deref()),
            optional_reason_field(self.owner.reservation_scope.as_deref()),
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
            "lease_id={} workload_id={} region_id={:?} owner_agent={} bead_id={} reservation_scope={} proof_lane={} priority={:?} state={} reserved_memory_bytes={} reserved_cpu_ns_per_sec={} reserved_io_ops_per_sec={} renewals={}: {base}",
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
            self.renewal_count
        )
    }
}

/// Receipt returned by workload lease lifecycle operations.
#[derive(Debug, Clone)]
pub struct SwarmWorkloadLeaseReceipt {
    /// Lease id affected by the operation.
    pub lease_id: SwarmWorkloadLeaseId,
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
    /// Time at which the lease was granted.
    pub issued_at: Instant,
    /// Time at which the lease expires if not renewed or completed.
    pub expires_at: Instant,
    /// Most recent renewal timestamp, when any.
    pub last_renewed_at: Option<Instant>,
    /// Number of successful renewals.
    pub renewal_count: u64,
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
    /// Structured explanation for logs and replay receipts.
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
        let expired_receipts = {
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

            leases.insert(lease_id, lease);
            expired_receipts
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
        live_leases.sort_by_key(|lease| {
            Self::workload_lease_schedule_key(
                lease,
                feedback_by_workload.get(lease.workload_id.as_str()),
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
                )
            })
            .collect()
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
            .map(str::trim)
            .filter(|scope| !scope.is_empty());
        let requested_scope = request
            .owner
            .reservation_scope
            .as_deref()
            .map(str::trim)
            .filter(|scope| !scope.is_empty());
        if let (Some(existing_scope), Some(requested_scope)) = (existing_scope, requested_scope)
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
        SwarmWorkloadLeaseReceipt {
            lease_id: lease.lease_id,
            workload_id: lease.workload_id.clone(),
            owner: lease.owner.clone(),
            proof_lane: lease.proof_lane,
            region_id: lease.region_id,
            priority: lease.priority,
            reserved_memory_bytes: lease.reserved_memory_bytes,
            reserved_cpu_ns_per_sec: lease.reserved_cpu_ns_per_sec,
            reserved_io_ops_per_sec: lease.reserved_io_ops_per_sec,
            state: lease.state,
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            terminal_at: lease.terminal_at,
            transition,
            reason: lease.context_reason(&transition_reason),
            transition_reason,
        }
    }

    fn workload_lease_schedule_key(
        lease: &SwarmWorkloadLease,
        feedback: Option<&SwarmWorkloadPressureFeedback>,
    ) -> (u8, i64, Instant, u8, u8, Instant, u64) {
        (
            Self::priority_schedule_rank(lease.priority),
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
    ) -> SwarmWorkloadLeaseScheduleEntry {
        let replay_pointer = format!(
            "swarm-workload-lease://lease/{}/schedule/{scheduling_rank}",
            lease.lease_id.as_u64()
        );
        let (
            queue_pressure_scaled,
            disk_io_pressure_scaled,
            rch_queue_pressure_scaled,
            validation_frontier_pressure_scaled,
            cancellation_tail_pressure_scaled,
            max_pressure_scaled,
        ) = Self::schedule_pressure_fields(feedback);
        SwarmWorkloadLeaseScheduleEntry {
            scheduling_rank,
            replay_pointer,
            lease_id: lease.lease_id,
            workload_id: lease.workload_id.clone(),
            owner: lease.owner.clone(),
            proof_lane: lease.proof_lane,
            priority: lease.priority,
            region_id: lease.region_id,
            state: lease.state,
            reserved_memory_bytes: lease.reserved_memory_bytes,
            reserved_cpu_ns_per_sec: lease.reserved_cpu_ns_per_sec,
            reserved_io_ops_per_sec: lease.reserved_io_ops_per_sec,
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            last_renewed_at: lease.last_renewed_at,
            renewal_count: lease.renewal_count,
            pressure_feedback_present: feedback.is_some(),
            queue_pressure_scaled,
            disk_io_pressure_scaled,
            rch_queue_pressure_scaled,
            validation_frontier_pressure_scaled,
            cancellation_tail_pressure_scaled,
            max_pressure_scaled,
            reason: Self::workload_lease_schedule_reason(lease, feedback),
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
        feedback
            .map(SwarmWorkloadPressureFeedback::max_pressure)
            .map(scale_pressure_for_metrics)
            .unwrap_or(0)
    }

    fn workload_lease_schedule_reason(
        lease: &SwarmWorkloadLease,
        feedback: Option<&SwarmWorkloadPressureFeedback>,
    ) -> String {
        let base = if let Some(feedback) = feedback {
            format!(
                "live workload lease scheduled with pressure feedback queue={} disk_io={} rch_queue={} validation_frontier={} cancellation_tail={} max={}",
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
        lease.context_reason(&base)
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
        let peer_pressure_high =
            peer_pressure.max_overall_pressure >= self.peer_pressure_backpressure_threshold();
        let workload_pressure_high = workload_pressure.max_overall_pressure
            >= self.workload_feedback_backpressure_threshold();

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
            ),
            AdmissionDecision::Reject => Self::format_swarm_admission_reason(
                "Rejected due to pressure",
                effective_degradation,
                priority,
                peer_pressure,
                workload_pressure,
            ),
            AdmissionDecision::AdmitWithBackpressure => Self::format_swarm_admission_reason(
                "Admitted with backpressure",
                effective_degradation,
                priority,
                peer_pressure,
                workload_pressure,
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
            summary.max_overall_pressure = summary.max_overall_pressure.max(report.max_pressure());
        }

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
    ) -> String {
        if peer_pressure.has_live_pressure() || workload_pressure.has_live_pressure() {
            format!(
                "{base}: {degradation_level:?} degradation, {priority:?} priority, {} live peer pressure reports, max peer pressure {:.3}, max peer degradation {:?}, {} live workload feedback reports, max workload pressure {:.3}",
                peer_pressure.live_report_count,
                peer_pressure.max_overall_pressure,
                peer_pressure.max_degradation_level,
                workload_pressure.live_report_count,
                workload_pressure.max_overall_pressure
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
        let reason = request.context_reason(&reason);
        let decision_receipt = self.build_admission_decision_receipt(
            AdmissionDecision::Reject,
            degradation_level,
            &pressure_snapshot,
            &reason,
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
        PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.0,
            blocking_pool_pressure: 0.0,
            channel_backlog_pressure: 0.0,
            cleanup_debt_pressure: 0.0,
            memory_budget_pressure: 0.0,
            overall_pressure: 0.0,
            signal_availability:
                crate::observability::pressure_governor::PressureSignalAvailability::NONE,
            fallback_verdict:
                crate::observability::pressure_governor::PressureFallbackVerdict::Complete,
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
        reservation_scope: normalized_optional_string(owner.reservation_scope.as_deref()),
    }
}

fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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
    use crate::types::Budget;

    fn create_test_swarm_governor() -> SwarmPressureGovernor {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );

        let config = SwarmPressureGovernorConfig::default();
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
    fn test_workload_admission_rejects_declared_cpu_and_io_over_envelope_budget() {
        let mut config = SwarmPressureGovernorConfig::default();
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
        assert_eq!(metrics.regions_rejected, 2);
        assert_eq!(metrics.envelope_budget_violations, 2);
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
        .with_deadline(Instant::now() - Duration::from_secs(1));
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
        let request = SwarmWorkloadAdmissionRequest::new(
            "lease-lifecycle",
            SwarmAdmissionOwner::new("DustyGorge").with_bead_id("asupersync-oxqrae.2"),
        )
        .with_declared_resources(Some(1024), Some(50), Some(5))
        .with_deadline(Instant::now() + Duration::from_secs(60));
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
        assert!(acquired.reason.contains("workload lease acquired"));

        let committed = governor
            .commit_workload_lease(acquired.lease_id)
            .expect("live lease should commit");
        assert_eq!(committed.state, SwarmWorkloadLeaseState::Committed);
        assert_eq!(
            committed.transition,
            SwarmWorkloadLeaseTransition::Committed
        );
        assert_eq!(committed.transition_reason, "workload lease committed");
        let old_expiry = committed.expires_at;

        let renewed = governor
            .renew_workload_lease(acquired.lease_id, Duration::from_secs(30))
            .expect("committed lease should renew");
        assert_eq!(renewed.state, SwarmWorkloadLeaseState::Committed);
        assert_eq!(renewed.transition, SwarmWorkloadLeaseTransition::Renewed);
        assert_eq!(renewed.transition_reason, "workload lease renewed");
        assert!(renewed.expires_at > old_expiry);
        assert!(renewed.reason.contains("renewals=1"));

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

        let released = governor
            .release_workload_lease(acquired.lease_id)
            .expect("renewed lease should release");
        assert_eq!(released.state, SwarmWorkloadLeaseState::Released);
        assert_eq!(released.transition, SwarmWorkloadLeaseTransition::Released);
        assert_eq!(released.transition_reason, "workload lease released");
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
                .with_reservation_scope(" src/observability/swarm_pressure_governor.rs "),
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
                .expires_at = Instant::now() - Duration::from_secs(1);
        }

        let expired = governor.expire_stale_workload_leases();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lease_id, expiring.lease_id);
        assert_eq!(expired[0].state, SwarmWorkloadLeaseState::Expired);
        assert_eq!(expired[0].transition, SwarmWorkloadLeaseTransition::Expired);
        assert_eq!(expired[0].transition_reason, "workload lease expired");
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
                .with_reservation_scope(format!(" {reservation_scope} ")),
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
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope(reservation_scope),
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
                .expires_at = Instant::now() - Duration::from_secs(1);
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
        assert_eq!(schedule[0].max_pressure_scaled, 2000);
        assert_eq!(schedule[0].rch_queue_pressure_scaled, 2000);
        assert_eq!(schedule[1].workload_id, "hot-rch-lane");
        assert!(schedule[1].pressure_feedback_present);
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

        let cold_request = SwarmWorkloadAdmissionRequest::new(
            "cold-proof",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let cold_decision = governor
            .check_workload_admission(&cx, &cold_request)
            .expect("cold workload admission should classify");
        assert!(matches!(cold_decision.decision, AdmissionDecision::Admit));

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_feedback_reports_recorded, 1);
        assert_eq!(metrics.live_workload_feedback_reports, 1);
        assert!(
            (metrics.max_workload_feedback_pressure_scaled - 8500).abs() <= 1,
            "scaled workload feedback should round near 8500, got {}",
            metrics.max_workload_feedback_pressure_scaled
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
                - governor
                    .config
                    .workload_feedback_max_age
                    .checked_mul(2)
                    .expect("test feedback max age should double");
        }
        assert_eq!(governor.prune_stale_workload_pressure_feedback(), 1);
        assert_eq!(governor.metrics().live_workload_feedback_reports, 0);
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
