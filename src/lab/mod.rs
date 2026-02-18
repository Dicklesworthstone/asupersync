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
//! runtime.scheduler.lock().schedule(task_id, 0);
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
pub mod conformal;
pub mod explorer;
pub mod fuzz;
pub mod http;
pub mod injection;
pub mod instrumented_future;
pub mod meta;
pub mod network;
pub mod opportunity;
pub mod oracle;
pub mod replay;
pub mod runtime;
pub mod scenario;
pub mod scenario_runner;
pub mod snapshot_restore;
pub mod spork_harness;
pub mod virtual_time_wheel;

pub use crate::util::{
    StrictEntropyGuard, disable_strict_entropy, enable_strict_entropy, strict_entropy_enabled,
};
pub use config::LabConfig;
pub use conformal::{
    CalibrationReport, ConformalCalibrator, ConformalConfig, ConformityScore, CoverageTracker,
    PredictionSet,
};
pub use explorer::{
    CoverageMetrics, DporCoverageMetrics, DporExplorer, ExplorationReport, ExplorerConfig,
    RunResult, ScheduleExplorer, TopologyExplorer, ViolationReport,
};
pub use fuzz::{FuzzConfig, FuzzFinding, FuzzHarness, FuzzReport, fuzz_quick};
pub use http::{
    RequestBuilder, RequestTrace, TestHarness, TraceEntry, VirtualClient, VirtualServer,
};
pub use injection::{
    LabBuilder, LabInjectionConfig, LabInjectionReport, LabInjectionResult, LabInjectionRunner, lab,
};
pub use instrumented_future::{
    AwaitPoint, CancellationInjector, InjectionMode, InjectionOutcome, InjectionReport,
    InjectionResult, InjectionRunner, InjectionStrategy, InstrumentedFuture,
    InstrumentedPollResult,
};
pub use meta::{
    ALL_ORACLE_INVARIANTS, BuiltinMutation, MetaCoverageEntry, MetaCoverageReport, MetaReport,
    MetaResult, MetaRunner, builtin_mutations, invariant_from_violation,
};
pub use network::{
    Fault as NetworkFault, JitterModel, LatencyModel, NetworkConditions, NetworkConfig,
    NetworkMetrics, NetworkTraceEvent, NetworkTraceKind, Packet, SimulatedNetwork,
};
pub use oracle::{
    ActorLeakOracle, ActorLeakViolation, BayesFactor, DetectionModel, DeterminismOracle,
    DeterminismViolation, DownOrderOracle, DownOrderViolation, EProcess, EProcessConfig,
    EProcessMonitor, EValue, EvidenceEntry, EvidenceLedger, EvidenceLine, EvidenceStrength,
    EvidenceSummary, FinalizerId, FinalizerOracle, FinalizerViolation, LogLikelihoodContributions,
    LoserDrainOracle, LoserDrainViolation, MailboxOracle, MailboxViolation, MailboxViolationKind,
    MonitorResult, ObligationLeakOracle, ObligationLeakViolation, OracleEntryReport, OracleReport,
    OracleStats, OracleSuite, OracleViolation, QuiescenceOracle, QuiescenceViolation,
    RegistryLeaseOracle, RegistryLeaseViolation, ReplyLinearityOracle, ReplyLinearityViolation,
    SupervisionOracle, SupervisionViolation, SupervisionViolationKind, SupervisorQuiescenceOracle,
    SupervisorQuiescenceViolation, TaskLeakOracle, TaskLeakViolation, TraceEventSummary,
    assert_deterministic, assert_deterministic_multi,
};
pub use replay::{
    ExplorationFingerprintClass as ReplayExplorationFingerprintClass,
    ExplorationReport as ReplayExplorationReport,
    ExplorationRunSummary as ReplayExplorationRunSummary, NormalizationResult, ReplayValidation,
    SporkExplorationReport, SporkExplorationRunSummary, TraceDivergence, TraceSummary,
    classify_fingerprint_classes, compare_normalized, explore_scenario_runner_seed_space,
    explore_seed_space, explore_spork_seed_space, normalize_for_replay,
    normalize_for_replay_with_config, summarize_spork_reports, traces_equivalent,
};
pub use runtime::{
    HarnessAttachmentKind, HarnessAttachmentRef, LabConfigSummary, LabRunReport, LabRuntime,
    LabTraceCertificateSummary, SporkHarnessReport, VirtualTimeReport,
};
pub use scenario::{
    CancellationSection, CancellationStrategy, ChaosSection, FaultAction, FaultEvent, IncludeRef,
    LabSection, LatencySpec, LinkConditions, NetworkPreset, NetworkSection, Participant,
    SCENARIO_SCHEMA_VERSION, Scenario, ValidationError as ScenarioValidationError,
};
pub use scenario_runner::{
    ExplorationRunSummary, FilteredOracleReport, ScenarioExplorationResult, ScenarioRunResult,
    ScenarioRunner, ScenarioRunnerError as FrankenLabRunnerError, TraceCertificateSnapshot,
};
pub use snapshot_restore::{
    RestorableSnapshot, RestoreError, SnapshotRestore, SnapshotStats, ValidationResult,
};
pub use spork_harness::{
    HarnessError, ScenarioRunnerError, SporkAppHarness, SporkScenarioConfig, SporkScenarioResult,
    SporkScenarioRunner, SporkScenarioSpec,
};
pub use virtual_time_wheel::{ExpiredTimer, VirtualTimerHandle, VirtualTimerWheel};
