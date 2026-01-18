//! Asupersync: Spec-first, cancel-correct, capability-secure async runtime for Rust.
//!
//! # Overview
//!
//! Asupersync is an async runtime built on the principle that correctness should be
//! structural, not conventional. Every task is owned by a region that closes to
//! quiescence. Cancellation is a first-class protocol, not a silent drop. Effects
//! require explicit capabilities.
//!
//! # Core Guarantees
//!
//! - **No orphan tasks**: Every spawned task is owned by a region; region close waits for all children
//! - **Cancel-correctness**: Cancellation is request → drain → finalize, never silent data loss
//! - **Bounded cleanup**: Cleanup budgets are sufficient conditions, not hopes
//! - **No silent drops**: Two-phase effects (reserve/commit) prevent data loss
//! - **Deterministic testing**: Lab runtime with virtual time and deterministic scheduling
//! - **Capability security**: All effects flow through explicit `Cx`; no ambient authority
//!
//! # Module Structure
//!
//! - [`types`]: Core types (identifiers, outcomes, budgets, policies)
//! - [`record`]: Internal records for tasks, regions, obligations
//! - [`trace`]: Tracing infrastructure for deterministic replay
//! - [`runtime`]: Scheduler and runtime state
//! - [`cx`]: Capability context and scope API
//! - [`combinator`]: Join, race, timeout combinators
//! - [`lab`]: Deterministic lab runtime for testing
//! - [`util`]: Internal utilities (deterministic RNG, arenas)
//! - [`error`]: Error types
//! - [`channel`]: Two-phase channel primitives (MPSC, etc.)
//! - [`encoding`]: RaptorQ encoding pipeline
//! - [`observability`]: Structured logging, metrics, and diagnostic context
//! - [`security`]: Symbol authentication and security primitives
//! - [`time`]: Sleep and timeout primitives for time-based operations
//! - [`io`]: Async I/O traits and adapters
//! - [`net`]: Async networking primitives (Phase 0: synchronous wrappers)
//! - [`bytes`]: Zero-copy buffer types (Bytes, BytesMut, Buf, BufMut)

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
// Phase 0: Allow dead code and documentation lints for stubs
#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::module_inception)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::cast_possible_truncation)]

pub mod bytes;
pub mod channel;
pub mod codec;
pub mod combinator;
pub mod config;
pub mod cx;
pub mod decoding;
pub mod encoding;
pub mod epoch;
pub mod error;
pub mod fs;
pub mod io;
pub mod lab;
pub mod net;
pub mod observability;
pub mod record;
pub mod runtime;
pub mod security;
pub mod service;
pub mod stream;
pub mod sync;
pub mod time;
pub mod trace;
pub mod transport;
pub mod types;
pub mod util;

// Re-exports for convenient access to core types
pub use config::{
    AdaptiveConfig, BackoffConfig, ConfigError, ConfigLoader, EncodingConfig,
    PathSelectionStrategy, RaptorQConfig, ResourceConfig, RuntimeProfile, SecurityConfig,
    TimeoutConfig, TransportConfig,
};
pub use cx::{Cx, Scope};
pub use decoding::{
    DecodingConfig, DecodingError, DecodingPipeline, DecodingProgress, RejectReason,
    SymbolAcceptResult,
};
pub use encoding::{EncodedSymbol, EncodingError, EncodingPipeline, EncodingStats};
pub use epoch::{
    bulkhead_call_in_epoch, bulkhead_call_weighted_in_epoch, circuit_breaker_call_in_epoch,
    epoch_join2, epoch_race2, epoch_select, BarrierResult, BarrierTrigger, Epoch, EpochBarrier,
    EpochBulkheadError, EpochCircuitBreakerError, EpochClock, EpochConfig, EpochContext,
    EpochError, EpochId, EpochJoin2, EpochPolicy, EpochRace2, EpochScoped, EpochSelect,
    EpochSource, EpochState, EpochTransitionBehavior, SymbolValidityWindow,
};
pub use error::{
    AcquireError, BackoffHint, Error, ErrorCategory, ErrorKind, Recoverability, RecoveryAction,
    RecvError, Result, ResultExt, SendError,
};
pub use lab::{LabConfig, LabRuntime};
pub use types::{
    join_outcomes, Budget, CancelKind, CancelReason, ObligationId, Outcome, OutcomeError,
    PanicPayload, Policy, RegionId, Severity, TaskId, Time,
};
