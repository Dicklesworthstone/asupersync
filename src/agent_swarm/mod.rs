//! Agent Swarm Control Plane for high-core AI workloads.
//!
//! This module provides coordination and handoff mechanisms for multi-agent
//! software development workflows, including safe session resumption after
//! compaction and agent coordination protocols.

pub mod control_plane;
pub mod handoff_verifier;
pub mod release_proof_aggregator;

pub use handoff_verifier::{
    BeadClaim, BeadStatus, BlockerInfo, BlockerType, CommitInfo, ConflictInfo, ConflictSeverity,
    CoordinationRequirement, CoordinationType, DirtyPathSummary, DocReceipt, FileReservation,
    GitState, HandoffCapsule, HandoffDecision, HandoffVerifier, InboxState, MessagePriority,
    MessageRef, ProofCommand, ProofCommandType, RefreshTarget, RiskAssessment, RiskCategory,
    RiskLevel, SafetyViolation, SessionMetadata, SessionType, StalenessThresholds,
    ViolationCategory,
};

pub use release_proof_aggregator::{
    AggregatorConfig, AggregatorError, AggregatorMetrics, BlockerRecord, CommitRecord,
    FileReservation as ProofFileReservation, GitRef, HandoffStatus, LeaseReceipt, ProofStatus,
    ProofSummary, RchCommandRecord, ReleaseProofAggregator, ReleaseProofRecord,
};

pub use control_plane::{
    AgentAdmissionRequest, AgentAdmissionResult, AdmissionRejectionReason, AgentId,
    AgentSession, AgentStatus, AgentSwarmControlPlane, ControlPlaneConfig, ControlPlaneMetrics,
    ResourceRequirements, ResourceUsage, SessionId, SystemPressure, ValidationLane,
    ValidationType, AdmissionController, ValidationCoordinator, PressureMonitor,
    AdmissionPriority, LaneId, LaneStatus,
};
