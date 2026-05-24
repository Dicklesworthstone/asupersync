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
//! - [`atp`]: ATP data movement layer primitives
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
// missing_docs, clippy::pedantic, clippy::nursery, and the large set of
// targeted `allow` overrides live in `[lints.rust]` / `[lints.clippy]` in
// Cargo.toml so they propagate to integration tests and benches (crate-level
// inner attributes don't reach `tests/*.rs`).
// Phase 0 complete: dead code denied to prevent regressions.
// Downgraded to warn on Windows: several signal/process/io_uring items are
// platform-gated and appear dead on non-Unix targets.
#![cfg_attr(not(target_family = "windows"), deny(dead_code))]
#![cfg_attr(target_family = "windows", warn(dead_code))]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::module_inception)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::duration_suboptimal_units)]
// Pedantic/nursery/WIP lints that should be silenced are configured via
// [lints.clippy] in Cargo.toml, which propagates to integration tests and
// benches too. Crate-level attributes don't reach `tests/*.rs` since each
// integration test is its own crate root.
#![cfg_attr(test, allow(clippy::large_stack_arrays))]
// Test harness builds a large test table in one frame.
#![cfg_attr(test, allow(clippy::large_stack_frames))]
#![cfg_attr(feature = "simd-intrinsics", feature(portable_simd))]

#[cfg_attr(test, allow(unused_extern_crates))]
#[cfg(test)]
extern crate self as asupersync;

#[cfg(all(
    target_arch = "wasm32",
    not(any(
        feature = "wasm-browser-dev",
        feature = "wasm-browser-prod",
        feature = "wasm-browser-deterministic",
        feature = "wasm-browser-minimal",
    ))
))]
compile_error!(
    "wasm32 builds require exactly one canonical profile feature: `wasm-browser-dev`, \
     `wasm-browser-prod`, `wasm-browser-deterministic`, or `wasm-browser-minimal`."
);

#[cfg(all(
    target_arch = "wasm32",
    any(
        all(feature = "wasm-browser-dev", feature = "wasm-browser-prod"),
        all(feature = "wasm-browser-dev", feature = "wasm-browser-deterministic"),
        all(feature = "wasm-browser-dev", feature = "wasm-browser-minimal"),
        all(feature = "wasm-browser-prod", feature = "wasm-browser-deterministic"),
        all(feature = "wasm-browser-prod", feature = "wasm-browser-minimal"),
        all(
            feature = "wasm-browser-deterministic",
            feature = "wasm-browser-minimal"
        ),
    )
))]
compile_error!("wasm32 builds must select exactly one canonical browser profile feature.");

#[cfg(all(target_arch = "wasm32", feature = "native-runtime"))]
compile_error!("feature `native-runtime` is forbidden on wasm32 browser builds.");

#[cfg(all(
    target_arch = "wasm32",
    feature = "wasm-browser-minimal",
    feature = "browser-io"
))]
compile_error!("feature `browser-io` is forbidden with `wasm-browser-minimal`.");

#[cfg(all(
    target_arch = "wasm32",
    feature = "wasm-browser-minimal",
    feature = "browser-trace"
))]
compile_error!("feature `browser-trace` is forbidden with `wasm-browser-minimal`.");

#[cfg(all(target_arch = "wasm32", feature = "cli"))]
compile_error!(
    "feature `cli` is unsupported on wasm32 (requires native filesystem/process surfaces)."
);

#[cfg(all(target_arch = "wasm32", feature = "io-uring"))]
compile_error!("feature `io-uring` is unsupported on wasm32.");

#[cfg(all(target_arch = "wasm32", feature = "tls"))]
compile_error!("feature `tls` is unsupported on wasm32 browser preview builds.");

#[cfg(all(target_arch = "wasm32", feature = "tls-native-roots"))]
compile_error!("feature `tls-native-roots` is unsupported on wasm32.");

#[cfg(all(target_arch = "wasm32", feature = "tls-webpki-roots"))]
compile_error!("feature `tls-webpki-roots` is unsupported on wasm32.");

#[cfg(all(target_arch = "wasm32", feature = "sqlite"))]
compile_error!("feature `sqlite` is unsupported on wasm32 browser preview builds.");

#[cfg(all(target_arch = "wasm32", feature = "postgres"))]
compile_error!("feature `postgres` is unsupported on wasm32 browser preview builds.");

#[cfg(all(target_arch = "wasm32", feature = "mysql"))]
compile_error!("feature `mysql` is unsupported on wasm32 browser preview builds.");

#[cfg(all(target_arch = "wasm32", feature = "kafka"))]
compile_error!("feature `kafka` is unsupported on wasm32 browser preview builds.");

// ── Portable modules (no platform assumptions) ──────────────────────────
pub mod actor;
pub mod adapter_certification;
pub mod app;
#[cfg(not(target_arch = "wasm32"))]
pub mod atp;
pub mod audit;
pub mod bytes;
pub mod cancel;
pub mod channel;
pub mod codec;
pub mod combinator;
pub mod config;
pub mod conformance;
pub use conformance::traceability;
pub mod console;
pub mod cx;
pub mod decoding;
pub mod distributed;
pub mod encoding;
pub mod epoch;
pub mod error;
pub mod evidence;
pub mod evidence_sink;
pub mod gen_server;
pub mod http;
pub mod io;
pub mod lab;
pub mod link;
pub mod migration;
pub mod monitor;
pub mod net;
pub mod obligation;
pub mod observability;
pub mod plan;
pub mod raptorq;
pub mod record;
pub mod remote;
pub mod runtime;
pub mod security;
pub mod service;
pub mod session;
pub mod spork;
pub mod stream;
pub mod supervision;
pub mod sync;
pub mod time;
pub mod trace;
pub mod tracing_compat;
pub mod transport;
pub mod types;
pub mod util;
pub mod web;

#[cfg(test)]
#[path = "../tests/conformance/task_inspector_wire.rs"]
mod task_inspector_wire_conformance;

// ── Feature-gated modules ───────────────────────────────────────────────
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub mod database;
pub mod tls;

// ── Platform-specific modules (excluded from wasm32 browser builds) ─────
// These modules depend on native OS surfaces (libc, nix, epoll, signal-hook,
// socket2) that are unavailable on wasm32-unknown-unknown. Browser adapters
// for the portable modules above are provided via platform trait seams
// (see docs/wasm_platform_trait_seams.md).
#[cfg(not(target_arch = "wasm32"))]
pub mod fs;
#[cfg(not(target_arch = "wasm32"))]
pub mod grpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod messaging;
#[cfg(not(target_arch = "wasm32"))]
pub mod process;
#[cfg(not(target_arch = "wasm32"))]
pub mod server;
#[cfg(not(target_arch = "wasm32"))]
pub mod signal;

// ── Test-only modules ───────────────────────────────────────────────────
#[cfg(any(test, feature = "test-internals"))]
pub mod actor_genserver_monitor_evidence_link_process_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod bytes_io_time_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod cancel_cx_runtime_channel_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod channel_ordering_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod cli_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod combinator_family_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod cx_obligation_trace_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod cx_scheduler_remote_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod database_grpc_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod database_pool_transaction_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod database_primitives_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod deterministic_state_golden_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod distributed_obligation_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod distributed_primitives_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod distributed_security_codec_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod distributed_service_messaging_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod error_message_golden_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod fs_config_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod fs_protocol_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod golden_artifacts_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod grpc_protocol_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod http_grpc_protocol_metamorphic_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod integration_mutation_testing;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod integration_scenario_mutations;
#[cfg(any(test, feature = "test-internals"))]
pub mod io_bytes_time_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod lab_determinism_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod lab_trace_observability_security_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod messaging_primitives_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod messaging_scheduler_deep_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod net_cli_audit_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod net_http_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod obligation_choreography_record_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod obligation_combinator_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod obligation_leak_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod plan_trace_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod protocol_serialization_golden_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod public_api_golden_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod raptorq_deep_dive_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod raptorq_rfc6330_conformance_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_bytes_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_cancel_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_channel_broadcast_obligation_saga_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_channel_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_channel_mpsc_sync_semaphore_backpressure_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_channel_supervision_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_codec_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_codec_length_delimited_framed_read_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_combinator_supervision_failure_propagation_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_cx_macaroon_obligation_recovery_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_cx_registry_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_cx_registry_trace_distributed_commit_permit_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_database_postgres_tls_connector_renegotiation_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_database_sqlite_obligation_saga_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_distributed_bridge_trace_distributed_sheaf_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_distributed_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_distributed_obligation_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_distributed_snapshot_raptorq_encoder_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_e2e_hardening_consolidation;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_epoch_obligation_no_leak_proof_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_fs_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_fs_uring_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_fs_uring_raptorq_encoder_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_fs_vfs_obligation_recovery_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_grpc_bidirectional_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_grpc_server_database_postgres_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_grpc_streaming_service_hedge_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_http_grpc_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_http_h2_concurrent_load_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_http_h2_server_messaging_kafka_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_http_h3_server_websocket_upgrade_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_integration_scenarios_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_kafka_consumer_group_rebalance_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_lab_chaos_runtime_state_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_lab_oracle_quiescence_runtime_state_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_lab_oracle_raptorq_proof_encode_decode_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_net_dns_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_net_dns_resolver_happy_eyeballs_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_net_websocket_http_h1_upgrade_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_obligation_e2e_tests;
#[cfg(any(
    all(test, feature = "real-service-e2e"),
    feature = "obligation-cleanup-e2e"
))]
pub mod real_obligation_leak_check_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_plan_scheduler_certificate_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_quic_native_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_raptorq_decoder_stream_backpressure_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_raptorq_decoder_trace_integrity_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_raptorq_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_raptorq_scheduler_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_raptorq_systematic_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_runtime_obligation_trace_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_scheduler_priority_promotion_starvation_cancel_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_scheduler_three_lane_obligation_leak_check_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_server_session_evidence_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_service_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_signal_graceful_shutdown_supervision_tree_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_sqlite_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_supervision_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_tcp_unix_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_timer_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_timer_extended_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_timer_wheel_region_drain_integration_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_tls_acceptor_http_h1_server_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_transport_security_authenticated_routing_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_web_multipart_codec_raptorq_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_web_sse_broadcast_fanout_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_websocket_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_websocket_server_channel_broadcast_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_runtime_blocking_pool_cancel_symbol_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_http_h2_server_grpc_protobuf_streaming_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_signal_graceful_server_shutdown_e2e_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod real_time_intrusive_wheel_combinator_timeout_e2e_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod runtime_state_machine_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod scheduler_priority_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod server_session_evidence_epoch_spork_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod service_layer_conformance_tests;
#[cfg(all(test, feature = "real-service-e2e"))]
pub mod subsystem_mutation_testing;
#[cfg(any(test, feature = "test-internals"))]
pub mod supervision_genserver_actor_io_fs_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod sync_primitives_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod sync_scheduler_metamorphic_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod test_logging;
#[cfg(any(test, feature = "test-internals"))]
pub mod test_ndjson;
#[cfg(any(test, feature = "test-internals"))]
pub mod test_utils;
#[cfg(any(test, feature = "test-internals"))]
pub mod timer_wheel_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod trace_causality_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod web_protocol_conformance_tests;
#[cfg(any(test, feature = "test-internals"))]
pub mod web_tls_codec_raptorq_metamorphic_tests;

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
    BarrierResult, BarrierTrigger, Epoch, EpochBarrier, EpochBulkheadError,
    EpochCircuitBreakerError, EpochClock, EpochConfig, EpochContext, EpochError, EpochId,
    EpochJoin2, EpochPolicy, EpochRace2, EpochScoped, EpochSelect, EpochSource, EpochState,
    EpochTransitionBehavior, SymbolValidityWindow, bulkhead_call_in_epoch,
    bulkhead_call_weighted_in_epoch, circuit_breaker_call_in_epoch, epoch_join2, epoch_race2,
    epoch_select,
};
pub use error::{
    AcquireError, BackoffHint, Error, ErrorCategory, ErrorKind, Recoverability, RecoveryAction,
    RecvError, Result, ResultExt, SendError,
};
pub use lab::{LabConfig, LabRuntime};
pub use remote::{
    CancelRequest, CompensationResult, ComputationName, DedupDecision, IdempotencyKey,
    IdempotencyRecord, IdempotencyRequestFingerprint, IdempotencyStore, Lease, LeaseError,
    LeaseRenewal, LeaseState, NodeId, Phase0RemoteFailure, Phase0RetryPolicy,
    Phase0SimulationConfig, RemoteCap, RemoteError, RemoteHandle, RemoteMessage, RemoteOutcome,
    RemoteTaskId, ResultDelivery, Saga, SagaState, SagaStepError, SpawnAck, SpawnAckStatus,
    SpawnRejectReason, SpawnRequest, spawn_remote,
};
pub use types::{
    Budget, CancelKind, CancelReason, CapabilityBudget, CapabilityBudgetDimension,
    CapabilityBudgetRefusal, CapabilityBudgetRequirements, NextjsBootstrapPhase,
    NextjsIntegrationSnapshot, NextjsNavigationType, NextjsRenderEnvironment, ObligationId,
    Outcome, OutcomeError, PanicPayload, Policy, ProgressiveLoadSlot, ProgressiveLoadSnapshot,
    ReactProviderConfig, ReactProviderPhase, ReactProviderState, RegionId, Severity,
    SuspenseBoundaryState, SuspenseDiagnosticEvent, SuspenseTaskConfig, SuspenseTaskSnapshot,
    SystemPressure, TaskId, Time, TransitionTaskState, WASM_ABI_MAJOR_VERSION,
    WASM_ABI_MINOR_VERSION, WASM_ABI_SIGNATURE_FINGERPRINT_V1, WASM_ABI_SIGNATURES_V1,
    WasmAbiBoundaryEvent, WasmAbiCancellation, WasmAbiChangeClass, WasmAbiCompatibilityDecision,
    WasmAbiErrorCode, WasmAbiFailure, WasmAbiOutcomeEnvelope, WasmAbiPayloadShape,
    WasmAbiRecoverability, WasmAbiSignature, WasmAbiSymbol, WasmAbiValue, WasmAbiVersion,
    WasmAbiVersionBump, WasmAbortInteropSnapshot, WasmAbortInteropUpdate, WasmAbortPropagationMode,
    WasmBoundaryState, WasmBoundaryTransitionError, WasmExportDispatcher, WasmHandleKind,
    WasmHandleRef, WasmOutcomeExt, WasmTaskCancelRequest, WasmTaskSpawnBuilder,
    apply_abort_signal_event, apply_runtime_cancel_phase_event, classify_wasm_abi_compatibility,
    is_valid_bootstrap_transition, is_valid_wasm_boundary_transition, join_outcomes,
    outcome_to_error_boundary_action, outcome_to_suspense_state, outcome_to_transition_state,
    required_wasm_abi_bump, validate_wasm_boundary_transition, wasm_abi_signature_fingerprint,
    wasm_boundary_state_for_cancel_phase,
};

// Re-export the supported structured-concurrency proc-macro DSL from the
// crate root when the `proc-macros` feature is enabled. Default builds include
// this feature.
//
// Minimal builds that disable `proc-macros` do not get a functional macro DSL
// fallback: `join!` and `race!` intentionally resolve to compile-error arms,
// while `scope!`, `spawn!`, and `join_all!` are unavailable until `proc-macros`
// is re-enabled.
#[cfg(feature = "proc-macros")]
pub use asupersync_macros::{join, join_all, race, scope, spawn};

// Proc macro versions available with explicit path when needed
#[cfg(feature = "proc-macros")]
pub mod proc_macros {
    //! Proc-macro structured-concurrency DSL available when `proc-macros` is enabled.
    //!
    //! This module mirrors the supported root re-exports (`scope!`, `spawn!`,
    //! `join!`, `join_all!`, `race!`) and also exposes advanced macros that
    //! intentionally remain explicit-path-only, such as `session_protocol!`.
    pub use asupersync_macros::{join, join_all, race, scope, session_protocol, spawn};
}
