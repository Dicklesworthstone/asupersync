//! Asupersync Transfer Protocol data movement primitives.
//!
//! ATP is the project-owned data movement layer that combines native QUIC,
//! verified object graphs, resumable transfer journals, adaptive RaptorQ
//! repair, path establishment, and deterministic replay. The module starts
//! small on purpose: each submodule should expose a reusable, testable model
//! before endpoint, CLI, daemon, or relay code depends on it.

pub mod actor;
pub mod adapter;
pub mod atpd;
pub mod autotune;
#[cfg(feature = "benchmark-adapters")]
pub mod benchmark;
pub mod cache;
#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
pub mod cache_seeding_integration_tests;
pub mod daemon_control;
pub mod diagnostics;
#[cfg(not(target_arch = "wasm32"))]
pub mod doctor;
#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
pub mod early_usability_tests;
pub mod governance;
pub mod grant;
pub mod identity;
pub mod inbox;
pub mod journal;
pub mod lab;
pub mod logging;
pub mod mailbox;
pub mod manifest;
pub mod object;
pub mod path;
pub mod planner;
#[cfg(not(target_arch = "wasm32"))]
pub mod platform;
pub mod policy;
pub mod profiles;
pub mod proof;
pub mod quota;
pub mod repair_coordinator;
pub mod repair_receiver;
pub mod repair_roi;
pub mod repair_scheduler;
pub mod safety;
#[path = "sdk.rs"]
pub mod sdk;
pub mod seeding;
pub mod stream_object;
pub mod supervision;
pub mod swarm;
pub mod sync;
pub mod timing_security;
pub mod transfer;
#[cfg(feature = "tokio-compat")]
pub mod transfer_actor;
pub mod transfer_brain;
pub mod upgrade_integration;
pub mod verifier;
pub mod verify;
pub mod writer;

pub use adapter::{
    AdapterConfig, AdapterManager, AdapterMetadata, AdapterNegotiation, AdapterParity,
    AdapterSession, AdapterSpecificConfig, AdapterType, CaveatReporting, CertValidationMode,
    DowngradePolicy, DowngradeReason, FeatureSupport, PerformanceCaveat, RequiredFeature,
    SessionStats, TransportPath,
};
pub use autotune::{
    ATP_AUTOTUNE_APPLICATION_RECEIPT_SCHEMA_VERSION, ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION,
    ATP_AUTOTUNE_METRIC_NAMES, AtpAutotuneApplicationOutcome, AtpAutotuneApplicationReceipt,
    AtpAutotuneApplicationState, AtpAutotuneDecision, AtpAutotuneDecisionOutcome,
    AtpAutotuneDecisionReceipt, AtpAutotuneKnob, AtpAutotuneKnobChange, AtpAutotuneKnobDirection,
    AtpAutotuneLimits, AtpAutotuneMetric, AtpAutotuneMetricSample, AtpAutotunePolicy,
    AtpAutotuneReceiptConfidence, AtpAutotuneReceiptProofPointer, AtpAutotuneReceiptStatus,
    AtpAutotuneReceiptValidationError, AtpAutotuneSettings, AtpAutotuneTelemetry,
    AtpAutotuneTelemetryError, AtpAutotuneTelemetryReport, AtpBottleneckKind, AtpBottleneckSignal,
    AtpRepairAction, AtpRepairCoordinator, AtpRepairCoordinatorDecision,
    AtpRepairCoordinatorPolicy, AtpRepairDecisionFactor, AtpRepairDecisionFactorEffect,
    AtpRepairDecisionFactorKind, AtpRepairMode, AtpRepairPathMode, AtpRepairRoiInputs,
    AtpTransferPressureSnapshot,
};
pub use cache::{
    AtpCache, CacheConfig, CacheEntry, CacheError, CacheKey, CacheMetrics, EvictionPolicy,
    StorageLocation, VerificationMetadata,
};
pub use daemon_control::{
    DaemonControlCapability, DaemonControlResult, DaemonProcessInfo, DaemonState,
    SecureDaemonController, create_atp_daemon_controller,
};
pub use diagnostics::{
    ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA, ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA,
    AtpCancellationDrainEvidence, AtpFinalizerEvidence, AtpObligationEvidenceCounts,
    AtpReplayEvidencePointer, AtpRuntimeDiagnosticDocument, AtpRuntimeEvidenceBridge,
    AtpRuntimeEvidenceEnvelope, AtpRuntimeEvidenceSignal, AtpRuntimeSignalClass,
    AtpRuntimeSignalSource,
};
#[cfg(not(target_arch = "wasm32"))]
pub use doctor::{
    ATP_PATH_DOCTOR_SCHEMA, ATP_PATH_TRACE_ATTEMPT_SCHEMA, ATP_PLATFORM_DOCTOR_SCHEMA,
    ATP_PLATFORM_PROBE_LOG_SCHEMA, AtpPathDoctorBudget, AtpPathDoctorCandidate,
    AtpPathDoctorDocument, AtpPathDoctorRecommendation, AtpPathDoctorSecurity,
    AtpPathDoctorSelectedPath, AtpPathDoctorSummary, AtpPathTraceAttemptLogEntry,
    AtpPlatformDoctorDocument, AtpPlatformProbeLogEntry, build_path_doctor_document,
    build_platform_doctor_document, detect_platform_doctor_document, render_path_doctor_human,
    render_platform_doctor_human,
};
pub use governance::{
    AtpFairShareAllocation, AtpFairnessCoordinator, AtpFairnessPolicy, AtpGovernanceDecision,
    AtpGovernanceViolation, AtpGovernanceViolationKind, AtpResourceBudget, AtpResourceDemand,
    AtpResourceGovernor, AtpTransferId,
    config::{AtpCustomLimits, AtpGovernanceCliArgs, AtpGovernanceConfig, AtpGovernanceMetadata},
};
pub use grant::{GrantInfo, GrantManager, GrantQuery, GrantStats, PairingCode, PairingManager};
pub use identity::{DurablePeerIdentity, IdentityError};
pub use inbox::{
    AllowAction, DaemonDiagnostics, GrantQuota, GrantScope, InboxDiagnostics, InboxError,
    InboxItem, InboxJsonRow, InboxOffer, InboxState, LocalInbox, MailboxPrivacyPolicy,
    MailboxRetrievalReceipt, MailboxSecurityError, MailboxStorageClass, MailboxStorageRecord,
    MailboxStoreRequest, MailboxTamperEvidence, ObjectDigest, ReceiveGrant,
};
pub use logging::{ATP_LOG_EVENT_SCHEMA_VERSION, AtpEvent, AtpLogger, AtpSubsystem, EventContext};
pub use manifest::{ChunkStrategy, ProofStrength};
pub use planner::{
    ATP_PLAN_EXECUTION_REPORT_SCHEMA, ATP_TRANSFER_PLAN_SCHEMA, AtpTransferPlan,
    AtpTransferPlanner, CacheAnalysis, ChunkingProfile, DiskAllocationPlan, ObjectGraphSummary,
    PathCandidate, PlanDeviation, PlanExecutionReport, PlanExecutionTracker, PlanUncertainty,
    PlannerConfig, PlannerError, PlannerOptions, ResourceGovernanceProfile, ResumeState,
    TransferMode, TransferType,
};
pub use policy::{
    Capability, CapabilityAction, PolicyDecision, PolicyEnforcer, ResourceScope, TemporalScope,
};
pub use profiles::{AtpPowerProfile, AtpResourceProfile};
pub use quota::{
    QuotaAllocation, QuotaBucket, QuotaError, QuotaLedger, QuotaLimit, QuotaRow, QuotaUsage,
    RetentionClock, RetentionPolicy, RetentionRecord, RetentionRule,
};
pub use repair_coordinator::{
    PathCharacteristics, RepairCoordinator, RepairCoordinatorConfig, RepairDecision,
    RepairDecisionFactors, RepairMode, RepairRoi, RepairTelemetry, TransferState,
};
pub use repair_roi::{
    EfficiencyStats, NetworkRegime, PolicyAnalysis, RegimeStats, RepairRoiSimulationResult,
    RepairRoiSimulator,
};
pub use repair_scheduler::{
    DecodeMatrix, MultiSourceRepairScheduler, PeerScoringWeights, RejectionReason,
    RepairSymbolRequest, SymbolProcessResult,
};
pub use seeding::{
    AtpSeedingService, ManifestAuthorization, SeedingConfig, SeedingError, SeedingMetrics,
    SeedingPriority, SeedingSession,
};
#[cfg(feature = "tokio-compat")]
pub use transfer_actor::{
    SessionId, SessionState, TransferActor, TransferActorConfig, TransferActorHandle,
    TransferMessage, TransferSession, TransferSessionStatus,
};
pub use transfer_brain::{
    ChunkId, DecisionFactors, ResourceUsage, ScheduledChunk, SchedulingDecision, SchedulingState,
    SystemPressure, TransferBrain, TransferBrainConfig, TransferMetrics, TransferPriority,
};
pub use upgrade_integration::{UpgradeDaemonController, create_upgrade_daemon_controller};
