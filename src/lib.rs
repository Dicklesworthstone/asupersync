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
//! - [`trace`](mod@trace): Tracing infrastructure for deterministic replay
//! - [`runtime`]: Scheduler and runtime state
//! - [`cx`]: Capability context and scope API
//! - [`combinator`]: Join, race, timeout combinators
//! - [`lab`]: Deterministic lab runtime for testing
//! - [`util`]: Internal utilities (deterministic RNG, arenas)
//! - [`error`](mod@error): Error types
//! - [`channel`]: Two-phase channel primitives (MPSC, etc.)
//! - [`encoding`]: RaptorQ encoding pipeline
//! - [`observability`]: Structured logging, metrics, and diagnostic context
//! - [`security`]: Symbol authentication and security primitives
//! - [`time`]: Sleep and timeout primitives for time-based operations
//! - [`io`]: Async I/O traits and adapters
//! - [`net`]: Async networking primitives (Phase 0: synchronous wrappers)
//! - [`bytes`]: Zero-copy buffer types (Bytes, BytesMut, Buf, BufMut)
//! - [`tracing_compat`]: Optional tracing integration (requires `tracing-integration` feature)
//! - [`plan`]: Plan DAG IR for join/race/timeout rewrites
//!
//! # API Stability
//!
//! Asupersync is currently in the 0.x series. Unless explicitly noted in
//! `docs/api_audit.md`, public items should be treated as **unstable** and
//! subject to change. Core types like [`Cx`], [`Outcome`], and [`Budget`] are
//! intended to stabilize first.

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
// Test harness builds a large test table in one frame.
#![cfg_attr(test, allow(clippy::large_stack_frames))]

pub mod actor;
pub mod app;
pub mod audit;
pub mod bytes;
pub mod cancel;
pub mod channel;
pub mod cli;
pub mod codec;
pub mod combinator;
pub mod config;
pub mod conformance;
pub mod console;
pub mod cx;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub mod database;
pub mod decoding;
pub mod distributed;
pub mod encoding;
pub mod epoch;
pub mod error;
pub mod evidence;
pub mod evidence_sink;
pub mod fs;
pub mod gen_server;
pub mod grpc;
pub mod http;
pub mod io;
pub mod lab;
pub mod link;
pub mod messaging;
pub mod migration;
pub mod monitor;
pub mod net;
pub mod obligation;
pub mod observability;
pub mod plan;
#[cfg(unix)]
pub mod process;
pub mod raptorq;
pub mod record;
pub mod remote;
pub mod runtime;
pub mod security;
pub mod server;
pub mod service;
pub mod session;
pub mod signal;
pub mod spork;
pub mod stream;
pub mod supervision;
pub mod sync;
#[cfg(any(test, feature = "test-internals"))]
pub mod test_logging;
#[cfg(any(test, feature = "test-internals"))]
pub mod test_ndjson;
#[cfg(any(test, feature = "test-internals"))]
pub mod test_utils;
pub mod time;
#[cfg(feature = "tls")]
pub mod tls;
pub mod trace;
pub mod tracing_compat;
pub mod transport;
pub mod types;
pub mod util;
pub mod web;

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
pub use remote::{
    spawn_remote, CancelRequest, CompensationResult, ComputationName, DedupDecision,
    IdempotencyKey, IdempotencyRecord, IdempotencyStore, Lease, LeaseError, LeaseRenewal,
    LeaseState, NodeId, RemoteCap, RemoteError, RemoteHandle, RemoteMessage, RemoteOutcome,
    RemoteTaskId, ResultDelivery, Saga, SagaState, SagaStepError, SpawnAck, SpawnAckStatus,
    SpawnRejectReason, SpawnRequest,
};
pub use types::{
    join_outcomes, Budget, CancelKind, CancelReason, ObligationId, Outcome, OutcomeError,
    PanicPayload, Policy, RegionId, Severity, SystemPressure, TaskId, Time,
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
    pub use asupersync_macros::{join, join_all, race, scope, session_protocol, spawn};
}
