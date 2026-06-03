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

pub mod atp_lab {
    pub use crate::atp::lab::*;
}
pub mod atp_path;
#[cfg(feature = "benchmark-adapters")]
pub mod benchmark_cartel;
pub mod chaos;
pub mod config;
pub mod conformal;
pub mod crashpack;
pub mod deadlock_radar;
pub mod dual_run;
pub mod explorer;
pub mod fixtures;
#[cfg(feature = "benchmark-adapters")]
pub mod forensics;
pub mod fuzz;
pub mod http;
pub mod injection;
pub mod instrumented_future;
pub mod meta;
pub mod network;
pub mod numa;
pub mod opportunity;
pub mod oracle;
pub mod replay;
#[cfg(feature = "benchmark-adapters")]
pub mod replay_minimization;
pub mod runtime;
pub mod scenario;
pub mod scenario_runner;
pub mod snapshot_restore;
pub mod spork_harness;
pub mod swarm_replay;
pub mod util;
pub mod virtual_time_wheel;

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod deterministic_validation_tests;

pub use crate::util::{
    StrictEntropyGuard, disable_strict_entropy, enable_strict_entropy, strict_entropy_enabled,
};
pub use atp_lab::{
    ATP_LAB_MODEL_SCHEMA_VERSION, AtpLabArtifact, AtpLabAttachment, AtpLabEvent, AtpLabFailure,
    AtpLabFault, AtpLabOracleConfig, AtpLabRegime, AtpLabReplayMetadata, AtpLabScenario,
    AtpLabTransferSpec, AtpTransferLabPlan,
};
pub use config::LabConfig;
pub use conformal::{
    CalibrationReport, ConformalCalibrator, ConformalConfig, ConformityScore, CoverageTracker,
    PredictionSet,
};
pub use crashpack::{
    ATP_CRASHPACK_SCHEMA_VERSION, AtpCrashpack, AtpEvidenceLedger, AtpOracleResult,
    AtpTransferOracle, AtpTransferState, CrashpackBuilder, CrashpackError, ReplayError,
    TraceMinimizer, TraceMinimizerConfig, TransferOracle, TransferOracleResult, TransferState,
    TransferViolation, ViolationSeverity,
};
pub use deadlock_radar::{
    DEADLOCK_RADAR_SCHEMA_VERSION, DeadlockRadarCandidate, DeadlockRadarEvidence,
    DeadlockRadarFinding, DeadlockRadarHazardClass, DeadlockRadarInterleavingStep,
    DeadlockRadarLockRank, DeadlockRadarProofStatus, DeadlockRadarReport, DeadlockRadarVerdict,
    run_deadlock_radar,
};
pub use dual_run::{
    CancelTerminalPhase, CancellationRecord, CaptureAnnotation, CaptureManifest, ComparisonVerdict,
    CounterTolerance, DUAL_RUN_SCHEMA_VERSION, DrainStatus, DualRunHarness, DualRunResult,
    DualRunScenarioIdentity, ExecutionInstanceId, FieldObservability, LiveExecutionProfile,
    LiveRunMetadata, LiveRunResult, LiveRunnerConfig, LiveWitnessCollector, LoserDrainRecord,
    NORMALIZED_OBSERVABLE_SCHEMA_VERSION, NormalizedObservable, NormalizedSemantics,
    ObligationBalanceRecord, OutcomeClass, Phase, PromotedExplorationScenario,
    PromotedFuzzScenario, RegionCloseRecord, RegionState as DualRunRegionState, ReplayMetadata,
    ReplayPolicy, ResourceSurfaceRecord, RuntimeKind, ScenarioFamilyId, SeedLineageRecord,
    SeedMode, SeedPlan, SemanticMismatch, TerminalOutcome, assert_dual_run_passes,
    assert_semantics, capture_cancellation, capture_loser_drain, capture_obligation_balance,
    capture_region_close, capture_terminal_from_result, capture_terminal_outcome,
    check_core_invariants, compare_observables, normalize_lab_observable, normalize_lab_report,
    normalize_live_observable, promote_exploration_report, promote_fuzz_finding,
    promote_regression_case, promote_regression_corpus, run_live_adapter,
};
pub use explorer::{
    CoverageMetrics, DporCoverageMetrics, DporExplorer, ExplorationReport, ExplorerConfig,
    RunResult, ScheduleExplorer, TopologyExplorer, ViolationReport,
};
pub use fixtures::{
    E2eReport, ExpectedOutcome, PerformanceImpact, ProofArtifactRef, RegimeSummary,
    RepairDecisionLog, RepairRoiE2eHarness, RepairRoiE2eResult, RepairRoiE2eScenario,
    TransferConfig, TransferResult,
};
pub use fuzz::{
    FuzzConfig, FuzzFinding, FuzzHarness, FuzzRegressionCase, FuzzRegressionCorpus, FuzzReport,
    fuzz_quick,
};
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
    DeterministicNetwork, Fault as NetworkFault, JitterModel, LatencyModel, NetworkConditions,
    NetworkConfig, NetworkMetrics, NetworkTraceEvent, NetworkTraceKind, Packet,
};
pub use numa::{
    NumaCachePressureInput, NumaCachePressureProjection, NumaPressureClass,
    project_numa_cache_pressure,
};
pub use oracle::{
    ActorLeakOracle, ActorLeakViolation, BayesFactor, DetectionModel, DeterminismOracle,
    DeterminismViolation, DownOrderOracle, DownOrderViolation, EProcess, EProcessConfig,
    EProcessMonitor, EValue, EvidenceEntry, EvidenceLedger, EvidenceLine, EvidenceStrength,
    EvidenceSummary, FinalizerId, FinalizerOracle, FinalizerViolation, LogLikelihoodContributions,
    LoserDrainOracle, LoserDrainViolation, MailboxOracle, MailboxViolation, MailboxViolationKind,
    MonitorResult, ObligationLeakOracle, ObligationLeakViolation, Oracle, OracleEntryReport,
    OracleReport, OracleStats, OracleSuite, OracleViolation, QuiescenceOracle, QuiescenceViolation,
    RegistryLeaseOracle, RegistryLeaseViolation, ReplyLinearityOracle, ReplyLinearityViolation,
    SupervisionOracle, SupervisionViolation, SupervisionViolationKind, SupervisorQuiescenceOracle,
    SupervisorQuiescenceViolation, TaskLeakOracle, TaskLeakViolation, TraceEventSummary,
    assert_deterministic, assert_deterministic_multi,
};
#[cfg(feature = "messaging-fabric")]
pub use oracle::{
    FabricPublishOracle, FabricPublishViolation, FabricQuiescenceOracle, FabricQuiescenceViolation,
    FabricRedeliveryOracle, FabricRedeliveryViolation, FabricReplyOracle, FabricReplyViolation,
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
    AutoAdvanceTermination, HarnessAttachmentKind, HarnessAttachmentRef, LabConfigSummary,
    LabRunReport, LabRuntime, LabTraceCertificateSummary, SporkHarnessReport, VirtualTimeReport,
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
pub use swarm_replay::{
    SWARM_AGENT_RUN_SCHEMA_VERSION, SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION,
    SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION, SWARM_HANDOFF_VERIFICATION_SCHEMA_VERSION,
    SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION, SWARM_PRESSURE_SCHEMA_VERSION,
    SWARM_PRESSURE_TRACE_SUMMARY_SCHEMA_VERSION, SWARM_PROOF_LANE_ATLAS_REPORT_SCHEMA_VERSION,
    SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION, SWARM_REPLAY_SCHEMA_VERSION,
    SWARM_WHAT_IF_PLAN_SCHEMA_VERSION, SwarmAgentRunEvent, SwarmAgentRunEventKind,
    SwarmAgentRunForbiddenActions, SwarmAgentRunScenario, SwarmAgentRunSummary,
    SwarmContentionHeatmapInput, SwarmContentionHeatmapLedger, SwarmContentionHeatmapVerdict,
    SwarmContentionHotSpot, SwarmContentionHotspotKind, SwarmContentionLockMetric,
    SwarmContentionSchedulerLaneMetric, SwarmContentionSeverity, SwarmDiskPressureLevel,
    SwarmDiskPressureTransition, SwarmFailureBundle, SwarmFailureInvariantClass,
    SwarmFailureMinimizerInput, SwarmFailureMinimizerReport, SwarmFailureMinimizerStopReason,
    SwarmFailureMinimizerVerdict, SwarmFailureReductionStep, SwarmHandoffCapsule,
    SwarmHandoffCommit, SwarmHandoffDecision, SwarmHandoffDirtyOwner, SwarmHandoffDirtyPath,
    SwarmHandoffInboxAck, SwarmHandoffProofCommand, SwarmHandoffReservation,
    SwarmHandoffVerification, SwarmHandoffVerifierReason, SwarmOperatorCockpitInput,
    SwarmOperatorCockpitMemoryDecision, SwarmOperatorCockpitObligationVerdict,
    SwarmOperatorCockpitOutcome, SwarmOperatorCockpitProofLaneSummary, SwarmOperatorCockpitReport,
    SwarmPressureEvent, SwarmPressureEventKind, SwarmPressureLane, SwarmPressureScenario,
    SwarmPressureSummary, SwarmPressureTraceAdmission, SwarmPressureTraceCancellation,
    SwarmPressureTraceCleanup, SwarmPressureTraceDrainHotSpot, SwarmPressureTraceHotRegion,
    SwarmPressureTraceObligationLeakSuspect, SwarmPressureTraceObligations,
    SwarmPressureTraceQueueHotSpot, SwarmPressureTraceQueuePressure,
    SwarmPressureTraceRegionLifecycle, SwarmPressureTraceSourceKind, SwarmPressureTraceSummary,
    SwarmPressureTraceTaskLifecycle, SwarmPressureTraceVerdict, SwarmProofLaneAdmissionDecision,
    SwarmProofLaneAtlasAdmissionContext, SwarmProofLaneAtlasReport, SwarmProofLaneDecision,
    SwarmProofLaneFallbackPolicy, SwarmProofLaneFinding, SwarmProofLaneFindingSeverity,
    SwarmProofLanePeerReservationOverlapStatus, SwarmProofLanePlan, SwarmProofLaneRchProvenance,
    SwarmProofLaneRequest, SwarmProofLaneTargetDirIsolationStatus,
    SwarmProofLaneTrappedCycleWitnessStatus, SwarmRchWorkerEvent, SwarmRchWorkerEventKind,
    SwarmReplayAdmissionDecision, SwarmReplayAdmissionDrainResult, SwarmReplayAdmissionRecord,
    SwarmReplayBudgetClass, SwarmReplayError, SwarmReplayEvent, SwarmReplayEventKind,
    SwarmReplayScenario, SwarmReplayShrinkHint, SwarmReplaySummary, SwarmReplayTaskOutcome,
    SwarmReplayTaskStatus, SwarmWhatIfInputFreshness, SwarmWhatIfPlan, SwarmWhatIfPriority,
    SwarmWhatIfRecommendation, SwarmWhatIfScenario, SwarmWhatIfStarvationRisk,
    SwarmWhatIfWorkClass, SwarmWhatIfWorkload, build_swarm_contention_heatmap,
    build_swarm_operator_cockpit_report, build_swarm_proof_lane_atlas_report,
    minimize_swarm_failure, plan_swarm_admission_wave, plan_swarm_proof_lane,
    render_swarm_contention_heatmap_text, render_swarm_failure_minimizer_text,
    render_swarm_operator_cockpit_text, render_swarm_pressure_trace_text,
    render_swarm_proof_lane_agent_mail_summary, render_swarm_proof_lane_atlas_report_json,
    render_swarm_proof_lane_atlas_report_markdown, run_swarm_agent_run_scenario,
    run_swarm_pressure_scenario, run_swarm_replay_scenario,
    scheduler_feedback_metrics_from_swarm_replay, summarize_swarm_agent_run_trace,
    summarize_swarm_pressure_trace, summarize_swarm_replay_trace,
    summarize_swarm_trace_artifact_json, verify_swarm_handoff_capsule,
};
pub use util::{
    StackTraceConfig, capture_stack_trace, capture_stack_trace_default, capture_stack_trace_depth,
    capture_stack_trace_minimal,
};
pub use virtual_time_wheel::{ExpiredTimer, VirtualTimerHandle, VirtualTimerWheel};
