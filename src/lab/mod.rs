//! Deterministic lab runtime for testing.
//!
//! The lab runtime provides:
//!
//! - Virtual time (no wall-clock dependencies)
//! - Deterministic scheduling (same seed → same execution)
//! - Trace capture and replay
//! - Schedule exploration (DPOR-style)
//! - Test oracles for invariant verification
//! - Await point tracking for cancellation injection

pub mod config;
pub mod instrumented_future;
pub mod oracle;
pub mod replay;
pub mod runtime;

pub use config::LabConfig;
pub use instrumented_future::{
    AwaitPoint, CancellationInjector, InjectionMode, InjectionOutcome, InjectionReport,
    InjectionResult, InjectionRunner, InjectionStrategy, InstrumentedFuture, InstrumentedPollResult,
};
pub use oracle::{
    assert_deterministic, assert_deterministic_multi, DeterminismOracle, DeterminismViolation,
    FinalizerId, FinalizerOracle, FinalizerViolation, LoserDrainOracle, LoserDrainViolation,
    ObligationLeakOracle, ObligationLeakViolation, OracleSuite, OracleViolation, QuiescenceOracle,
    QuiescenceViolation, TaskLeakOracle, TaskLeakViolation, TraceEventSummary,
};
pub use runtime::LabRuntime;
