//! Distributed tracing infrastructure.
//!
//! This module provides:
//!
//! - **Trace identifiers and context** (`id`, `context`, `span`, `collector`):
//!   W3C-compatible trace IDs, symbol-level span recording, and in-process collection.
//! - **Vector clocks** (`vclock`): Causal ordering for distributed events.
//!   Events are partially ordered: concurrent events remain unordered.
//! - **Convergent state lattice** (`lattice`): Join-semilattice for obligation
//!   and lease state that converges across replicas via CRDT-style merge.

pub mod collector;
pub mod context;
pub mod id;
pub mod lattice;
pub mod sheaf;
pub mod span;
pub mod vclock;

pub use collector::{SymbolTraceCollector, TraceRecord, TraceSummary};
pub use context::{RegionTag, SymbolTraceContext, TraceFlags};
pub use id::{SymbolSpanId, TraceId};
pub use lattice::{LatticeState, LeaseLatticeState, ObligationEntry, ObligationLattice};
pub use sheaf::{
    ConsistencyReport, ConstraintViolation, NodeSnapshot, PhantomState, SagaConsistencyChecker,
    SagaConstraint,
};
pub use span::{SymbolSpan, SymbolSpanKind, SymbolSpanStatus};
pub use vclock::{
    CausalEvent, CausalOrder, CausalTracker, HybridClock, HybridTime, LamportClock, LamportTime,
    LogicalClock, LogicalClockHandle, LogicalClockKind, LogicalClockMode, LogicalTime, VectorClock,
    VectorClockHandle,
};
