//! Core types for the Asupersync runtime.
//!
//! This module contains the fundamental types used throughout the runtime:
//!
//! - [`id`]: Identifier types (`RegionId`, `TaskId`, `ObligationId`, `Time`)
//! - [`outcome`]: Four-valued outcome type with severity lattice
//! - [`cancel`]: Cancellation reason and kind types
//! - [`budget`]: Budget type with product semiring semantics + min-plus curves
//! - [`policy`]: Policy trait for outcome aggregation
//! - [`symbol`]: Symbol types for RaptorQ-based distributed layer
//! - [`resource`]: Resource limits and symbol buffer pools
//! - [`rref`]: Region-owned reference for Send tasks

pub mod budget;
pub mod builder;
pub mod cancel;
pub mod id;
pub mod outcome;
pub mod policy;
pub mod resource;
pub mod rref;
pub mod symbol;
pub mod symbol_set;
pub mod task_context;
pub mod typed_symbol;

pub use budget::{backlog_bound, delay_bound, Budget, CurveBudget, CurveError, MinPlusCurve};
pub use builder::{BuildError, BuildResult};
pub use cancel::{
    CancelAttributionConfig, CancelKind, CancelPhase, CancelReason, CancelWitness,
    CancelWitnessError,
};
pub use id::{ObligationId, RegionId, TaskId, Time};
pub use outcome::{join_outcomes, Outcome, OutcomeError, PanicPayload, Severity};
pub use policy::Policy;
pub use rref::{RRef, RRefAccess, RRefError};
pub use symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind, DEFAULT_SYMBOL_SIZE};
pub use symbol_set::{
    BlockProgress, ConcurrentSymbolSet, InsertResult, SymbolSet, ThresholdConfig,
};
pub use task_context::{CheckpointState, CxInner};
pub use typed_symbol::{
    DeserializationError, Deserializer, SerdeCodec, SerializationError, SerializationFormat,
    Serializer, TypeDescriptor, TypeMismatchError, TypeRegistry, TypedDecoder, TypedEncoder,
    TypedSymbol, TYPED_SYMBOL_HEADER_LEN, TYPED_SYMBOL_MAGIC,
};
