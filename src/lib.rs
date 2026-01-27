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
//! - [`tracing_compat`]: Optional tracing integration (requires `tracing-integration` feature)

// Default to deny for unsafe code - specific modules (like epoll reactor) can use #[allow(unsafe_code)]
// when they need to interface with FFI or low-level system APIs
#![deny(unsafe_code)]
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
#![cfg_attr(test, allow(clippy::large_stack_arrays))]
#![cfg_attr(test, allow(clippy::large_stack_arrays))]

pub mod bytes;
pub mod channel;
pub mod cli;
pub mod codec;
pub mod combinator;
pub mod config;
pub mod conformance;
pub mod cx;
pub mod decoding;
pub mod encoding;
pub mod epoch;
pub mod error;
pub mod fs;
pub mod grpc;
pub mod http;
pub mod io;
pub mod lab;
pub mod net;
pub mod observability;
#[cfg(unix)]
pub mod process;
pub mod record;
pub mod runtime;
pub mod security;
pub mod service;
pub mod signal;
pub mod stream;
pub mod sync;
pub mod test_logging;
#[cfg(any(test, feature = "test-internals"))]
pub mod test_utils;
pub mod time;
pub mod trace;
pub mod tracing_compat;
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

// Re-export proc macros when the proc-macros feature is enabled
// Note: join! and race! are not re-exported because they conflict with the
// existing macro_rules! definitions in combinator/. The proc macro versions
// will replace those in future tasks (asupersync-mwff, asupersync-hcpl).
#[cfg(feature = "proc-macros")]
pub use asupersync_macros::{join_all, scope, spawn};

// Proc macro versions available with explicit path when needed
#[cfg(feature = "proc-macros")]
pub mod proc_macros {
    //! Proc macro versions of structured concurrency macros.
    //!
    //! These are provided for explicit access when the macro_rules! versions
    //! are also in scope.
    pub use asupersync_macros::{join, join_all, race, scope, spawn};
}
