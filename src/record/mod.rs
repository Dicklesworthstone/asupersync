//! Internal records for runtime entities.
//!
//! This module contains the internal record types used by the runtime
//! to track tasks, regions, and obligations.
//!
//! These are internal implementation details and not part of the public API.

pub mod distributed_region;
pub mod finalizer;
pub mod obligation;
pub mod region;
pub mod symbol_obligation_tracker;
pub mod symbolic_obligation;
pub mod task;

pub use distributed_region::{
    ConsistencyLevel, DistributedRegionConfig, DistributedRegionRecord, DistributedRegionState,
    ReplicaInfo, ReplicaStatus, StateTransition, TransitionReason,
};
pub use finalizer::{Finalizer, FinalizerEscalation, FinalizerStack};
pub use obligation::SourceLocation;
pub use obligation::{ObligationAbortReason, ObligationKind, ObligationRecord, ObligationState};
pub use region::{AdmissionError, AdmissionKind, RegionLimits, RegionRecord};
pub use symbol_obligation_tracker::{
    EpochId, EpochWindow, ObligationGuard, SymbolObligation, SymbolObligationKind,
    SymbolObligationTracker,
};
pub use symbolic_obligation::{
    FulfillmentProgress, FulfillmentSnapshot, ObligationSummary, SymbolicObligation,
    SymbolicObligationKind, SymbolicObligationRegistry, SymbolicObligationState,
};
pub use task::TaskRecord;
