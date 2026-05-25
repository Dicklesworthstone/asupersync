//! Agent Swarm Control Plane for high-core AI workloads.
//!
//! This module provides coordination and handoff mechanisms for multi-agent
//! software development workflows, including safe session resumption after
//! compaction and agent coordination protocols.

pub mod handoff_verifier;

pub use handoff_verifier::{
    BlockerInfo, BlockerType, BeadClaim, BeadStatus, CommitInfo, ConflictInfo, ConflictSeverity,
    CoordinationRequirement, CoordinationType, DirtyPathSummary, DocReceipt, FileReservation,
    GitState, HandoffCapsule, HandoffDecision, HandoffVerifier, InboxState, MessagePriority,
    MessageRef, ProofCommand, ProofCommandType, RefreshTarget, RiskAssessment, RiskCategory,
    RiskLevel, SafetyViolation, SessionMetadata, SessionType, StalenessThresholds,
    ViolationCategory,
};