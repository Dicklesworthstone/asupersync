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
//! - Integrated cancellation injection with oracle verification
//! - Chaos testing with configurable failure injection
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::lab::{LabConfig, LabRuntime};
//! use asupersync::types::Budget;
//!
//! let mut runtime = LabRuntime::new(LabConfig::new(42));
//! let region = runtime.state.create_root_region(Budget::INFINITE);
//!
//! let (task_id, _handle) = runtime
//!     .state
//!     .create_task(region, Budget::INFINITE, async { 42 })
//!     .expect("create task");
//!
//! runtime.scheduler.lock().unwrap().schedule(task_id, 0);
//! runtime.run_until_quiescent();
//! ```
//!
//! # Chaos Testing
//!
//! Enable chaos injection to stress-test error handling:
//!
//! ```ignore
//! // Light chaos for CI (1% cancel, 5% delay)
//! let config = LabConfig::new(42).with_light_chaos();
//! let mut runtime = LabRuntime::new(config);
//!
//! // ... run tests ...
//!
//! // Check injection statistics
//! let stats = runtime.chaos_stats();
//! println!("Injections: {} delays, {} cancellations", stats.delays, stats.cancellations);
//! ```
//!
//! See the [`chaos`] module for detailed documentation on chaos testing.

pub mod chaos;
pub mod config;
pub mod injection;
pub mod instrumented_future;
pub mod meta;
pub mod oracle;
pub mod replay;
pub mod runtime;
pub mod virtual_time_wheel;

pub use crate::util::{
    disable_strict_entropy, enable_strict_entropy, strict_entropy_enabled, StrictEntropyGuard,
};
pub use config::LabConfig;
pub use injection::{
    lab, LabBuilder, LabInjectionConfig, LabInjectionReport, LabInjectionResult, LabInjectionRunner,
};
pub use instrumented_future::{
    AwaitPoint, CancellationInjector, InjectionMode, InjectionOutcome, InjectionReport,
    InjectionResult, InjectionRunner, InjectionStrategy, InstrumentedFuture,
    InstrumentedPollResult,
};
pub use meta::{
    builtin_mutations, invariant_from_violation, BuiltinMutation, MetaCoverageEntry,
    MetaCoverageReport, MetaReport, MetaResult, MetaRunner, ALL_ORACLE_INVARIANTS,
};
pub use oracle::{
    assert_deterministic, assert_deterministic_multi, DeterminismOracle, DeterminismViolation,
    FinalizerId, FinalizerOracle, FinalizerViolation, LoserDrainOracle, LoserDrainViolation,
    ObligationLeakOracle, ObligationLeakViolation, OracleSuite, OracleViolation, QuiescenceOracle,
    QuiescenceViolation, TaskLeakOracle, TaskLeakViolation, TraceEventSummary,
};
pub use runtime::LabRuntime;
pub use virtual_time_wheel::{ExpiredTimer, VirtualTimerHandle, VirtualTimerWheel};
