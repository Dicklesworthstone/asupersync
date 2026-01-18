//! Core types for the Asupersync runtime.
//!
//! This module contains the fundamental types used throughout the runtime:
//!
//! - [`id`]: Identifier types (`RegionId`, `TaskId`, `ObligationId`, `Time`)
//! - [`outcome`]: Four-valued outcome type with severity lattice
//! - [`cancel`]: Cancellation reason and kind types
//! - [`budget`]: Budget type with product semiring semantics
//! - [`policy`]: Policy trait for outcome aggregation
//! - [`symbol`]: Symbol types for RaptorQ-based distributed layer
//! - [`resource`]: Resource limits and symbol buffer pools

pub mod budget;
pub mod cancel;
pub mod id;
pub mod outcome;
pub mod policy;
pub mod resource;
pub mod symbol;
pub mod symbol_set;
pub mod task_context;

pub use budget::Budget;
pub use cancel::{CancelKind, CancelReason};
pub use id::{ObligationId, RegionId, TaskId, Time};
pub use outcome::{join_outcomes, Outcome, OutcomeError, PanicPayload, Severity};
pub use policy::Policy;
pub use symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind, DEFAULT_SYMBOL_SIZE};
pub use symbol_set::{
    BlockProgress, ConcurrentSymbolSet, InsertResult, SymbolSet, ThresholdConfig,
};
pub use task_context::CxInner;
