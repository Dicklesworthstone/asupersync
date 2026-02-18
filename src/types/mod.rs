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
pub mod pressure;
pub mod resource;
pub mod rref;
pub mod symbol;
pub mod symbol_set;
pub mod task_context;
pub mod typed_symbol;

pub use budget::{Budget, CurveBudget, CurveError, MinPlusCurve, backlog_bound, delay_bound};
pub use builder::{BuildError, BuildResult};
pub use cancel::{
    CancelAttributionConfig, CancelKind, CancelPhase, CancelReason, CancelWitness,
    CancelWitnessError,
};
pub use id::{ObligationId, RegionId, TaskId, Time};
pub use outcome::{Outcome, OutcomeError, PanicPayload, Severity, join_outcomes};
pub use policy::Policy;
pub use pressure::SystemPressure;
pub use rref::{RRef, RRefAccess, RRefAccessWitness, RRefError};
pub use symbol::{DEFAULT_SYMBOL_SIZE, ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
pub use symbol_set::{
    BlockProgress, ConcurrentSymbolSet, InsertResult, SymbolSet, ThresholdConfig,
};
pub use task_context::{CheckpointState, CxInner, MAX_MASK_DEPTH};
pub use typed_symbol::{
    DeserializationError, Deserializer, SerdeCodec, SerializationError, SerializationFormat,
    Serializer, TYPED_SYMBOL_HEADER_LEN, TYPED_SYMBOL_MAGIC, TypeDescriptor, TypeMismatchError,
    TypeRegistry, TypedDecoder, TypedEncoder, TypedSymbol,
};
