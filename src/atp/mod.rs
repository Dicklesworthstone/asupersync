//! Asupersync Transfer Protocol data movement primitives.
//!
//! ATP is the project-owned data movement layer that combines native QUIC,
//! verified object graphs, resumable transfer journals, adaptive RaptorQ
//! repair, path establishment, and deterministic replay. The module starts
//! small on purpose: each submodule should expose a reusable, testable model
//! before endpoint, CLI, daemon, or relay code depends on it.

pub mod actor;
pub mod autotune;
#[cfg(feature = "benchmark-adapters")]
pub mod benchmark;
pub mod diagnostics;
#[cfg(not(target_arch = "wasm32"))]
pub mod doctor;
pub mod governance;
pub mod grant;
pub mod identity;
pub mod inbox;
pub mod journal;
pub mod lab;
pub mod logging;
pub mod manifest;
pub mod object;
pub mod path;
#[cfg(not(target_arch = "wasm32"))]
pub mod platform;
pub mod policy;
pub mod profiles;
pub mod proof;
pub mod quota;
pub mod repair_receiver;
pub mod safety;
#[path = "sdk.rs"]
pub mod sdk;
pub mod stream_object;
pub mod sync;
pub mod transfer;
pub mod verifier;
pub mod verify;
pub mod writer;

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
    AtpRepairDecisionFactorKind, AtpRepairPathMode, AtpRepairRoiInputs,
    AtpTransferPressureSnapshot,
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
    AtpGovernanceDecision, AtpGovernanceViolation, AtpGovernanceViolationKind, AtpResourceBudget,
    AtpResourceDemand, AtpResourceGovernor,
};
pub use grant::{GrantInfo, GrantManager, GrantQuery, GrantStats, PairingCode, PairingManager};
pub use identity::{DurablePeerIdentity, IdentityError};
pub use inbox::{
    AllowAction, DaemonDiagnostics, GrantQuota, GrantScope, InboxDiagnostics, InboxError,
    InboxItem, InboxJsonRow, InboxOffer, InboxState, LocalInbox, MailboxPrivacyPolicy,
    MailboxRetrievalReceipt, MailboxSecurityError, MailboxStorageClass, MailboxStorageRecord,
    MailboxStoreRequest, MailboxTamperEvidence, ObjectDigest, ReceiveGrant,
};
pub use logging::{
    AtpEvent, AtpLogger, AtpLoggerConfig, AtpSubsystem, EventContext, LogFormat, atp_logger,
    init_atp_logger,
};
pub use manifest::{ChunkStrategy, ProofStrength};
pub use policy::{
    Capability, CapabilityAction, PolicyDecision, PolicyEnforcer, ResourceScope, TemporalScope,
};
pub use profiles::{AtpPowerProfile, AtpResourceProfile};
pub use quota::{
    QuotaAllocation, QuotaBucket, QuotaError, QuotaLedger, QuotaLimit, QuotaRow, QuotaUsage,
    RetentionClock, RetentionPolicy, RetentionRecord, RetentionRule,
};
