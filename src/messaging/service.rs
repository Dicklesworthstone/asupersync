//! Contract-carrying service schemas for the FABRIC lane.

use super::class::{AckKind, DeliveryClass, DeliveryClassPolicy, DeliveryClassPolicyError};
use super::control::{
    ControlHandlerId, ControlRegistry, ControlRegistryError, NamespaceControlScope,
    SystemSubjectFamily,
};
use super::morphism::{ExportPlan, ImportPlan, Morphism, MorphismCompileError};
use super::subject::{NamespaceKernel, NamespaceKernelError, Subject};
use crate::lab::conformal::{HealthThresholdCalibrator, HealthThresholdConfig, ThresholdMode};
use crate::obligation::eprocess::{
    AlertState as EProcessAlertState, LeakMonitor, MonitorConfig as LeakMonitorConfig,
};
use crate::obligation::ledger::{ObligationLedger, ObligationToken};
use crate::record::{ObligationAbortReason, ObligationKind, ObligationState, SourceLocation};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::panic::Location;
use std::time::Duration;
use thiserror::Error;

/// Payload-shape declaration for FABRIC service requests and replies.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadShape {
    /// No payload is carried.
    #[default]
    Empty,
    /// The payload is a JSON document.
    JsonDocument,
    /// The payload is an opaque binary frame.
    BinaryBlob,
    /// The payload is encoded directly into the subject path.
    SubjectEncoded,
    /// The payload follows an externally named schema.
    NamedSchema {
        /// Human-readable schema identifier.
        schema: String,
    },
}

impl PayloadShape {
    fn validate(&self, field: &str) -> Result<(), ServiceContractError> {
        if let Self::NamedSchema { schema } = self
            && schema.trim().is_empty()
        {
            return Err(ServiceContractError::EmptyNamedSchema {
                field: field.to_owned(),
            });
        }
        Ok(())
    }
}

/// Reply-shape declaration for service responses.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplyShape {
    /// The service does not emit a reply payload.
    #[default]
    None,
    /// The service emits exactly one reply payload.
    Unary {
        /// Payload shape for the reply.
        shape: PayloadShape,
    },
    /// The service emits a bounded stream of reply payloads.
    Stream {
        /// Payload shape for each streamed reply item.
        shape: PayloadShape,
    },
}

impl ReplyShape {
    fn validate(&self, field: &str) -> Result<(), ServiceContractError> {
        match self {
            Self::None => Ok(()),
            Self::Unary { shape } | Self::Stream { shape } => shape.validate(field),
        }
    }
}

/// Cleanup urgency promised by the service boundary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CleanupUrgency {
    /// Cleanup can happen in the background after request cancellation.
    Background,
    /// Cleanup should complete promptly before the service fully unwinds.
    #[default]
    Prompt,
    /// Cleanup is urgent and should be prioritized immediately.
    Immediate,
}

impl fmt::Display for CleanupUrgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Background => "background",
            Self::Prompt => "prompt",
            Self::Immediate => "immediate",
        };
        write!(f, "{name}")
    }
}

/// Budget semantics attached to a FABRIC service surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSemantics {
    /// Cleanup urgency when request cancellation occurs.
    pub cleanup_urgency: CleanupUrgency,
    /// Default timeout applied when the caller does not override it.
    pub default_timeout: Option<Duration>,
    /// Whether the caller may request a narrower timeout.
    pub allow_timeout_override: bool,
    /// Whether caller-provided priority hints are honored.
    pub honor_priority_hints: bool,
}

impl Default for BudgetSemantics {
    fn default() -> Self {
        Self {
            cleanup_urgency: CleanupUrgency::Prompt,
            default_timeout: Some(Duration::from_secs(30)),
            allow_timeout_override: true,
            honor_priority_hints: false,
        }
    }
}

impl BudgetSemantics {
    fn validate(&self) -> Result<(), ServiceContractError> {
        if self
            .default_timeout
            .is_some_and(|timeout| timeout.is_zero())
        {
            return Err(ServiceContractError::ZeroDuration {
                field: "budget_semantics.default_timeout".to_owned(),
            });
        }
        Ok(())
    }
}

/// Cancellation protocol expected from the service implementation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CancellationObligations {
    /// Best-effort drain with no reply guarantee.
    BestEffortDrain,
    /// Drain outstanding work before resolving the reply path.
    #[default]
    DrainBeforeReply,
    /// Drain outstanding work and run compensation before completion.
    DrainAndCompensate,
}

impl fmt::Display for CancellationObligations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::BestEffortDrain => "best-effort-drain",
            Self::DrainBeforeReply => "drain-before-reply",
            Self::DrainAndCompensate => "drain-and-compensate",
        };
        write!(f, "{name}")
    }
}

/// Capture policy for service-plane requests and replies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CaptureRules {
    /// Whether request envelopes are captured for replay or diagnostics.
    pub capture_requests: bool,
    /// Whether reply envelopes are captured for replay or diagnostics.
    pub capture_replies: bool,
    /// Whether payload hashes are retained alongside captures.
    pub record_payload_hashes: bool,
    /// Whether branch attachments are retained when present.
    pub record_branch_artifacts: bool,
}

impl Default for CaptureRules {
    fn default() -> Self {
        Self {
            capture_requests: true,
            capture_replies: true,
            record_payload_hashes: true,
            record_branch_artifacts: false,
        }
    }
}

/// Compensation guarantee attached to a service surface.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CompensationSemantics {
    /// No compensation is promised.
    #[default]
    None,
    /// Compensation is attempted but not mandatory for every failure path.
    BestEffort,
    /// Compensation is part of the declared contract.
    Required,
}

impl fmt::Display for CompensationSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::None => "none",
            Self::BestEffort => "best-effort",
            Self::Required => "required",
        };
        write!(f, "{name}")
    }
}

/// Mobility envelope for a service surface.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MobilityConstraint {
    /// The service may execute on any eligible region.
    #[default]
    Unrestricted,
    /// The service may move only inside the named region boundary.
    BoundedRegion {
        /// Human-readable region label.
        region: String,
    },
    /// The service is pinned to its current authority boundary.
    Pinned,
}

impl MobilityConstraint {
    fn validate(&self, field: &str) -> Result<(), ServiceContractError> {
        if let Self::BoundedRegion { region } = self
            && region.trim().is_empty()
        {
            return Err(ServiceContractError::EmptyBoundedRegion {
                field: field.to_owned(),
            });
        }
        Ok(())
    }

    /// Returns whether the provider's mobility boundary satisfies a required contract boundary.
    #[must_use]
    pub fn satisfies(&self, required: &Self) -> bool {
        match required {
            Self::Unrestricted => true,
            Self::BoundedRegion { region } => match self {
                Self::BoundedRegion {
                    region: provider_region,
                } => provider_region == region,
                Self::Pinned => true,
                Self::Unrestricted => false,
            },
            Self::Pinned => matches!(self, Self::Pinned),
        }
    }
}

impl fmt::Display for MobilityConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unrestricted => write!(f, "unrestricted"),
            Self::BoundedRegion { region } => write!(f, "bounded-region({region})"),
            Self::Pinned => write!(f, "pinned"),
        }
    }
}

/// Evidence depth required by the service boundary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// Minimal audit trail.
    Minimal,
    /// Standard operational evidence.
    #[default]
    Standard,
    /// Rich diagnostics and replay metadata.
    Detailed,
    /// Forensic-grade evidence and replay linkage.
    Forensic,
}

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Detailed => "detailed",
            Self::Forensic => "forensic",
        };
        write!(f, "{name}")
    }
}

/// Overload response declared by the service provider.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OverloadPolicy {
    /// Reject new requests once overload is detected.
    #[default]
    RejectNew,
    /// Admit work only while the bounded pending queue has capacity.
    QueueWithinBudget {
        /// Maximum queued requests once overload begins.
        max_pending: u32,
    },
    /// Prefer dropping the weakest delivery-class traffic first.
    DropEphemeral,
    /// Fail fast before request execution starts.
    FailFast,
}

impl OverloadPolicy {
    fn validate(&self) -> Result<(), ServiceContractError> {
        if let Self::QueueWithinBudget { max_pending } = self
            && *max_pending == 0
        {
            return Err(ServiceContractError::InvalidQueueCapacity);
        }
        Ok(())
    }
}

/// Full FABRIC service contract schema for one service boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceContractSchema {
    /// Request payload shape.
    pub request_shape: PayloadShape,
    /// Reply payload shape.
    pub reply_shape: ReplyShape,
    /// Cancellation duties for the service implementation.
    pub cancellation_obligations: CancellationObligations,
    /// Timeout and priority behavior.
    pub budget_semantics: BudgetSemantics,
    /// Minimum delivery/durability class promised by the contract.
    pub durability_class: DeliveryClass,
    /// Capture and replay policy.
    pub capture_rules: CaptureRules,
    /// Compensation semantics required by the contract.
    pub compensation_semantics: CompensationSemantics,
    /// Mobility envelope required by the contract.
    pub mobility_constraints: MobilityConstraint,
    /// Evidence depth required by the contract.
    pub evidence_requirements: EvidenceLevel,
    /// Overload behavior exposed to callers.
    pub overload_policy: OverloadPolicy,
}

impl Default for ServiceContractSchema {
    fn default() -> Self {
        Self {
            request_shape: PayloadShape::JsonDocument,
            reply_shape: ReplyShape::Unary {
                shape: PayloadShape::JsonDocument,
            },
            cancellation_obligations: CancellationObligations::default(),
            budget_semantics: BudgetSemantics::default(),
            durability_class: DeliveryClass::ObligationBacked,
            capture_rules: CaptureRules::default(),
            compensation_semantics: CompensationSemantics::None,
            mobility_constraints: MobilityConstraint::Unrestricted,
            evidence_requirements: EvidenceLevel::Standard,
            overload_policy: OverloadPolicy::default(),
        }
    }
}

impl ServiceContractSchema {
    /// Validate the contract for internal consistency.
    pub fn validate(&self) -> Result<(), ServiceContractError> {
        self.request_shape.validate("request_shape")?;
        self.reply_shape.validate("reply_shape")?;
        self.budget_semantics.validate()?;
        self.mobility_constraints.validate("mobility_constraints")?;
        self.overload_policy.validate()?;
        Ok(())
    }
}

/// Provider-declared guarantees that bound caller-selected options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTerms {
    /// Provider-admitted delivery classes and default choice.
    pub admissible_classes: DeliveryClassPolicy,
    /// Strongest durability class the provider guarantees on this surface.
    pub guaranteed_durability: DeliveryClass,
    /// Compensation policy the provider will honor.
    pub compensation_policy: CompensationSemantics,
    /// Provider mobility boundary.
    pub mobility_constraint: MobilityConstraint,
    /// Provider evidence guarantee.
    pub evidence_level: EvidenceLevel,
}

impl ProviderTerms {
    /// Validate provider terms against the contract envelope.
    pub fn validate_against(
        &self,
        contract: &ServiceContractSchema,
    ) -> Result<(), ServiceContractError> {
        self.mobility_constraint
            .validate("provider_terms.mobility_constraint")?;

        if self.guaranteed_durability < contract.durability_class {
            return Err(ServiceContractError::ProviderGuaranteeBelowContractFloor {
                guaranteed_durability: self.guaranteed_durability,
                required_durability: contract.durability_class,
            });
        }
        if self.compensation_policy < contract.compensation_semantics {
            return Err(ServiceContractError::ProviderCompensationBelowContract {
                provider: self.compensation_policy,
                required: contract.compensation_semantics,
            });
        }
        if self.evidence_level < contract.evidence_requirements {
            return Err(ServiceContractError::ProviderEvidenceBelowContract {
                provider: self.evidence_level,
                required: contract.evidence_requirements,
            });
        }
        if !self
            .mobility_constraint
            .satisfies(&contract.mobility_constraints)
        {
            return Err(ServiceContractError::ProviderMobilityIncompatible {
                provider: self.mobility_constraint.clone(),
                required: contract.mobility_constraints.clone(),
            });
        }
        for class in self.admissible_classes.admissible_classes() {
            if *class < contract.durability_class {
                return Err(ServiceContractError::ProviderClassBelowContractFloor {
                    class: *class,
                    required_durability: contract.durability_class,
                });
            }
            if *class > self.guaranteed_durability {
                return Err(
                    ServiceContractError::ProviderClassAboveGuaranteedDurability {
                        class: *class,
                        guaranteed_durability: self.guaranteed_durability,
                    },
                );
            }
        }
        Ok(())
    }
}

/// Caller-selected options that stay bounded by provider terms.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CallerOptions {
    /// Explicit delivery class request, or `None` for the provider default.
    pub requested_class: Option<DeliveryClass>,
    /// Narrower timeout requested by the caller.
    pub timeout_override: Option<Duration>,
    /// Optional scheduling hint in the range `0..=255`.
    pub priority_hint: Option<u8>,
}

/// Effective caller request after provider-bound validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedServiceRequest {
    /// Delivery class selected for the request.
    pub delivery_class: DeliveryClass,
    /// Effective timeout after applying defaults and caller overrides.
    pub timeout: Option<Duration>,
    /// Caller-provided priority hint, if honored.
    pub priority_hint: Option<u8>,
    /// Provider durability guarantee for the selected request.
    pub guaranteed_durability: DeliveryClass,
    /// Provider evidence guarantee.
    pub evidence_level: EvidenceLevel,
    /// Provider mobility boundary.
    pub mobility_constraint: MobilityConstraint,
    /// Compensation policy enforced for the request.
    pub compensation_policy: CompensationSemantics,
    /// Overload policy presented at the service boundary.
    pub overload_policy: OverloadPolicy,
}

/// Typed failure recorded when a request/reply obligation aborts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceFailure {
    /// The caller or runtime cancelled the request.
    Cancelled,
    /// The request timed out and was explicitly aborted.
    TimedOut,
    /// Admission or policy rejected the request before completion.
    Rejected,
    /// The service failed because it was overloaded.
    Overloaded,
    /// The reply path encountered transport failure.
    TransportError,
    /// Application logic failed while serving the request.
    ApplicationError,
}

impl ServiceFailure {
    fn abort_reason(self) -> ObligationAbortReason {
        match self {
            Self::Cancelled => ObligationAbortReason::Cancel,
            Self::TimedOut | Self::Rejected => ObligationAbortReason::Explicit,
            Self::Overloaded | Self::TransportError | Self::ApplicationError => {
                ObligationAbortReason::Error
            }
        }
    }
}

impl fmt::Display for ServiceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Rejected => "rejected",
            Self::Overloaded => "overloaded",
            Self::TransportError => "transport_error",
            Self::ApplicationError => "application_error",
        };
        write!(f, "{name}")
    }
}

/// Transfer hop recorded when a request is forwarded through a morphism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceTransferHop {
    /// Human-readable morphism or import/export adapter name.
    pub morphism: String,
    /// New callee selected by the transfer.
    pub callee: String,
    /// New subject or route used after the transfer.
    pub subject: String,
    /// Timestamp when the transfer occurred.
    pub transferred_at: Time,
}

// ─── Certificate-carrying request/reply protocol ────────────────────────────

/// Deterministic certificate that a request was admitted, validated, and
/// authorised before entering the service pipeline.
///
/// Callers attach a `RequestCertificate` to every request so the callee can
/// verify the caller's identity, capability proof, and negotiated service class
/// without re-validating the contract schema at the hot path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestCertificate {
    /// Stable identifier for the request (same as `ServiceObligation.request_id`).
    pub request_id: String,
    /// Caller identity verified during admission.
    pub caller: String,
    /// Subject the request was issued on.
    pub subject: String,
    /// Delivery class negotiated between caller options and provider terms.
    pub delivery_class: DeliveryClass,
    /// Reply-space rule governing where the reply may land.
    pub reply_space_rule: super::ir::ReplySpaceRule,
    /// Service class from the validated contract.
    pub service_class: String,
    /// Fingerprint of the capability proof used during admission.
    ///
    /// This is a deterministic hash of the caller's capability set at admission
    /// time — not the raw capability material itself.
    pub capability_fingerprint: u64,
    /// Timestamp when the certificate was issued.
    pub issued_at: Time,
    /// Optional timeout after which the request is considered stale.
    pub timeout: Option<Duration>,
}

impl RequestCertificate {
    /// Build a certificate from request metadata and a validated request.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_validated(
        request_id: String,
        caller: String,
        subject: String,
        validated: &ValidatedServiceRequest,
        reply_space_rule: super::ir::ReplySpaceRule,
        service_class: String,
        capability_fingerprint: u64,
        issued_at: Time,
    ) -> Self {
        Self {
            request_id,
            caller,
            subject,
            delivery_class: validated.delivery_class,
            reply_space_rule,
            service_class,
            capability_fingerprint,
            issued_at,
            timeout: validated.timeout,
        }
    }

    /// Validate that the certificate fields are internally consistent.
    pub fn validate(&self) -> Result<(), ServiceObligationError> {
        validate_service_text("request_id", &self.request_id)?;
        validate_service_text("caller", &self.caller)?;
        validate_service_text("subject", &self.subject)?;
        validate_service_text("service_class", &self.service_class)?;
        match &self.reply_space_rule {
            super::ir::ReplySpaceRule::CallerInbox => {}
            super::ir::ReplySpaceRule::SharedPrefix { prefix }
            | super::ir::ReplySpaceRule::DedicatedPrefix { prefix } => {
                validate_service_text("reply_space_rule.prefix", prefix)?;
            }
        }
        if self.timeout.is_some_and(|d| d.is_zero()) {
            return Err(ServiceObligationError::ZeroTimeout);
        }
        Ok(())
    }

    /// Deterministic digest of the certificate for audit trails.
    #[must_use]
    pub fn digest(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = crate::util::DetHasher::default();
        self.request_id.hash(&mut hasher);
        self.caller.hash(&mut hasher);
        self.subject.hash(&mut hasher);
        (self.delivery_class as u8).hash(&mut hasher);
        match &self.reply_space_rule {
            super::ir::ReplySpaceRule::CallerInbox => 0u8.hash(&mut hasher),
            super::ir::ReplySpaceRule::SharedPrefix { prefix } => {
                1u8.hash(&mut hasher);
                prefix.hash(&mut hasher);
            }
            super::ir::ReplySpaceRule::DedicatedPrefix { prefix } => {
                2u8.hash(&mut hasher);
                prefix.hash(&mut hasher);
            }
        }
        self.service_class.hash(&mut hasher);
        self.capability_fingerprint.hash(&mut hasher);
        self.issued_at.hash(&mut hasher);
        self.timeout.hash(&mut hasher);
        hasher.finish()
    }
}

/// Deterministic certificate that a reply was produced, committed, and
/// (optionally) obligation-tracked before delivery to the caller.
///
/// Callees produce a `ReplyCertificate` as evidence that the reply
/// obligation was honestly resolved — either successfully or via an
/// explicit abort with a typed failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyCertificate {
    /// Request ID this reply corresponds to.
    pub request_id: String,
    /// Callee identity that produced the reply.
    pub callee: String,
    /// Delivery class of the original request.
    pub delivery_class: DeliveryClass,
    /// Obligation ID if the reply was tracked by the ledger.
    pub service_obligation_id: Option<ObligationId>,
    /// Digest of the reply payload for integrity verification.
    pub payload_digest: u64,
    /// Whether the reply is chunked (streamed) rather than unary.
    pub is_chunked: bool,
    /// Total chunks if this is a chunked reply.
    pub total_chunks: Option<u32>,
    /// Timestamp when the reply certificate was issued.
    pub issued_at: Time,
    /// Service latency: time between request admission and reply production.
    pub service_latency: Duration,
}

impl ReplyCertificate {
    /// Build a reply certificate from a committed service reply.
    #[must_use]
    pub fn from_commit(
        commit: &ServiceReplyCommit,
        callee: String,
        issued_at: Time,
        service_latency: Duration,
    ) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = crate::util::DetHasher::default();
        commit.payload.hash(&mut hasher);
        let payload_digest = hasher.finish();

        Self {
            request_id: commit.request_id.clone(),
            callee,
            delivery_class: commit.delivery_class,
            service_obligation_id: commit.service_obligation_id,
            payload_digest,
            is_chunked: false,
            total_chunks: None,
            issued_at,
            service_latency,
        }
    }

    /// Validate that the certificate fields are internally consistent.
    pub fn validate(&self) -> Result<(), ServiceObligationError> {
        validate_service_text("request_id", &self.request_id)?;
        validate_service_text("callee", &self.callee)?;
        if self.is_chunked {
            if self.total_chunks.is_none() {
                return Err(ServiceObligationError::ChunkedReplyMissingCount);
            }
        } else if self.total_chunks.is_some() {
            return Err(ServiceObligationError::UnaryReplyChunkCountPresent);
        }
        if self.delivery_class >= DeliveryClass::ObligationBacked
            && self.service_obligation_id.is_none()
        {
            return Err(
                ServiceObligationError::TrackedReplyMissingParentObligationId {
                    delivery_class: self.delivery_class,
                },
            );
        }
        Ok(())
    }

    /// Deterministic digest of the certificate for audit trails.
    #[must_use]
    pub fn digest(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = crate::util::DetHasher::default();
        self.request_id.hash(&mut hasher);
        self.callee.hash(&mut hasher);
        (self.delivery_class as u8).hash(&mut hasher);
        self.service_obligation_id.hash(&mut hasher);
        self.payload_digest.hash(&mut hasher);
        self.is_chunked.hash(&mut hasher);
        self.total_chunks.hash(&mut hasher);
        self.issued_at.hash(&mut hasher);
        self.service_latency.hash(&mut hasher);
        hasher.finish()
    }
}

/// Obligation family for chunked/streamed replies with bounded cleanup.
///
/// When a reply is streamed in chunks, each chunk is tracked as a member
/// of an obligation family. The family enforces bounded cleanup: if the
/// stream is cancelled or times out, pending chunks are drained within
/// the cleanup budget.
#[derive(Debug)]
pub struct ChunkedReplyObligation {
    /// Family identifier for the chunk obligation set.
    pub family_id: String,
    /// Parent service obligation ID.
    pub service_obligation_id: Option<ObligationId>,
    /// Request ID this chunked reply belongs to.
    pub request_id: String,
    /// Total expected chunks (may be unknown for unbounded streams).
    pub expected_chunks: Option<u32>,
    /// Number of chunks committed so far.
    received_chunks: u32,
    /// Whether the stream has been finalized (all chunks received or aborted).
    finalized: bool,
    /// Delivery class governing chunk obligations.
    pub delivery_class: DeliveryClass,
    /// Delivery boundary for per-chunk acknowledgement.
    pub chunk_ack_boundary: AckKind,
}

impl ChunkedReplyObligation {
    /// Create a new chunked reply obligation family.
    pub fn new(
        family_id: String,
        request_id: String,
        service_obligation_id: Option<ObligationId>,
        expected_chunks: Option<u32>,
        delivery_class: DeliveryClass,
        chunk_ack_boundary: AckKind,
    ) -> Result<Self, ServiceObligationError> {
        validate_service_text("family_id", &family_id)?;
        validate_service_text("request_id", &request_id)?;
        if expected_chunks == Some(0) {
            return Err(ServiceObligationError::ChunkedReplyZeroExpected);
        }
        if delivery_class >= DeliveryClass::ObligationBacked && service_obligation_id.is_none() {
            return Err(
                ServiceObligationError::TrackedReplyMissingParentObligationId { delivery_class },
            );
        }
        validate_reply_boundary(delivery_class, chunk_ack_boundary, false)?;
        Ok(Self {
            family_id,
            service_obligation_id,
            request_id,
            expected_chunks,
            received_chunks: 0,
            finalized: false,
            delivery_class,
            chunk_ack_boundary,
        })
    }

    /// Record receipt of a chunk. Returns the chunk index (0-based).
    pub fn receive_chunk(&mut self) -> Result<u32, ServiceObligationError> {
        if self.finalized {
            return Err(ServiceObligationError::AlreadyResolved {
                operation: "receive chunk on finalized stream",
            });
        }
        if let Some(expected) = self.expected_chunks {
            if self.received_chunks >= expected {
                return Err(ServiceObligationError::ChunkedReplyOverflow {
                    expected,
                    received: self.received_chunks + 1,
                });
            }
        }
        let index = self.received_chunks;
        self.received_chunks = self.received_chunks.saturating_add(1);
        Ok(index)
    }

    /// Finalize the stream. Returns the number of chunks received.
    pub fn finalize(&mut self) -> Result<u32, ServiceObligationError> {
        if self.finalized {
            return Err(ServiceObligationError::AlreadyResolved {
                operation: "finalize chunked reply",
            });
        }
        if let Some(expected) = self.expected_chunks
            && self.received_chunks != expected
        {
            return Err(ServiceObligationError::ChunkedReplyIncomplete {
                expected,
                received: self.received_chunks,
            });
        }
        self.finalized = true;
        Ok(self.received_chunks)
    }

    /// Whether all expected chunks have been received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.expected_chunks
            .is_some_and(|expected| self.received_chunks >= expected)
    }

    /// Number of chunks received so far.
    #[must_use]
    pub fn received_chunks(&self) -> u32 {
        self.received_chunks
    }

    /// Whether the stream has been finalized.
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Build a reply certificate for the completed chunked stream.
    pub fn certificate(
        &self,
        callee: String,
        payload_digest: u64,
        issued_at: Time,
        service_latency: Duration,
    ) -> Result<ReplyCertificate, ServiceObligationError> {
        if !self.finalized {
            return Err(ServiceObligationError::ChunkedReplyNotFinalized);
        }
        if let Some(expected) = self.expected_chunks
            && self.received_chunks != expected
        {
            return Err(ServiceObligationError::ChunkedReplyIncomplete {
                expected,
                received: self.received_chunks,
            });
        }
        Ok(ReplyCertificate {
            request_id: self.request_id.clone(),
            callee,
            delivery_class: self.delivery_class,
            service_obligation_id: self.service_obligation_id,
            payload_digest,
            is_chunked: true,
            total_chunks: Some(self.received_chunks),
            issued_at,
            service_latency,
        })
    }
}

/// Runtime request/reply obligation tracked against the global obligation
/// ledger when the delivery class requires it.
#[derive(Debug)]
pub struct ServiceObligation {
    /// Stable request identifier.
    pub request_id: String,
    /// Human-readable caller identity.
    pub caller: String,
    /// Human-readable callee identity.
    pub callee: String,
    /// Subject used for the request.
    pub subject: String,
    /// Delivery class selected for the request.
    pub delivery_class: DeliveryClass,
    /// Time when the request was created.
    pub created_at: Time,
    /// Optional request timeout carried into the service surface.
    pub timeout: Option<Duration>,
    /// Morphism transfer lineage captured across forwards.
    pub lineage: Vec<ServiceTransferHop>,
    resolved: bool,
    token: Option<ObligationToken>,
}

impl ServiceObligation {
    /// Allocate a service obligation for one request.
    ///
    /// The common-case `EphemeralInteractive` path stays cheap and does not
    /// allocate a ledger entry. `ObligationBacked` and stronger service classes
    /// allocate a ledger-backed lease obligation that must later be committed,
    /// aborted, or intentionally surfaced as a leak by the runtime.
    #[track_caller]
    #[allow(clippy::too_many_arguments)]
    pub fn allocate(
        ledger: &mut ObligationLedger,
        request_id: impl Into<String>,
        caller: impl Into<String>,
        target: impl Into<String>,
        subject: impl Into<String>,
        delivery_class: DeliveryClass,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
        timeout: Option<Duration>,
    ) -> Result<Self, ServiceObligationError> {
        let request_id = request_id.into();
        let caller = caller.into();
        let service_target = target.into();
        let subject = subject.into();
        validate_service_text("request_id", &request_id)?;
        validate_service_text("caller", &caller)?;
        validate_service_text("callee", &service_target)?;
        validate_service_text("subject", &subject)?;
        if timeout.is_some_and(|value| value.is_zero()) {
            return Err(ServiceObligationError::ZeroTimeout);
        }

        let token = if delivery_class >= DeliveryClass::ObligationBacked {
            let description = format!("service request {request_id}: {caller} -> {service_target}");
            Some(ledger.acquire_with_context(
                ObligationKind::Lease,
                holder,
                region,
                created_at,
                SourceLocation::from_panic_location(Location::caller()),
                None,
                Some(description),
            ))
        } else {
            None
        };

        Ok(Self {
            request_id,
            caller,
            callee: service_target,
            subject,
            delivery_class,
            created_at,
            timeout,
            lineage: Vec::new(),
            resolved: false,
            token,
        })
    }

    fn ensure_active(&self, operation: &'static str) -> Result<(), ServiceObligationError> {
        if self.resolved {
            return Err(ServiceObligationError::AlreadyResolved { operation });
        }
        Ok(())
    }

    /// Return the underlying ledger obligation id when the request is tracked.
    #[must_use]
    pub fn obligation_id(&self) -> Option<ObligationId> {
        self.token.as_ref().map(ObligationToken::id)
    }

    /// Return whether this request is currently backed by the obligation ledger.
    #[must_use]
    pub fn is_tracked(&self) -> bool {
        self.token.is_some()
    }

    /// Transfer the request through an import/export morphism while preserving
    /// the existing service obligation.
    pub fn transfer(
        &mut self,
        callee: impl Into<String>,
        subject: impl Into<String>,
        morphism: impl Into<String>,
        transferred_at: Time,
    ) -> Result<(), ServiceObligationError> {
        self.ensure_active("transfer")?;
        let callee = callee.into();
        let subject = subject.into();
        let morphism = morphism.into();
        validate_service_text("transfer.callee", &callee)?;
        validate_service_text("transfer.subject", &subject)?;
        validate_service_text("transfer.morphism", &morphism)?;
        self.callee.clone_from(&callee);
        self.subject.clone_from(&subject);
        self.lineage.push(ServiceTransferHop {
            morphism,
            callee,
            subject,
            transferred_at,
        });
        Ok(())
    }

    /// Commit the service obligation with a reply payload and optionally create
    /// a follow-on reply-delivery obligation.
    #[track_caller]
    pub fn commit_with_reply(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
        payload: impl Into<Vec<u8>>,
        delivery_boundary: AckKind,
        receipt_required: bool,
    ) -> Result<ServiceReplyCommit, ServiceObligationError> {
        self.ensure_active("commit_with_reply")?;
        validate_reply_boundary(self.delivery_class, delivery_boundary, receipt_required)?;

        let service_obligation_id = self.obligation_id();
        let payload = payload.into();

        let reply_obligation = if let Some(token) = self.token.take() {
            let holder = token.holder();
            let region = token.region();
            let service_obligation_id = token.id();
            ledger.commit(token, now);

            if requires_follow_up_reply(delivery_boundary, receipt_required) {
                Some(ReplyObligation::allocate(
                    ledger,
                    service_obligation_id,
                    holder,
                    region,
                    now,
                    payload.clone(),
                    delivery_boundary,
                    receipt_required,
                ))
            } else {
                None
            }
        } else if requires_follow_up_reply(delivery_boundary, receipt_required) {
            return Err(ServiceObligationError::ReplyTrackingUnavailable {
                delivery_class: self.delivery_class,
                requested_boundary: delivery_boundary,
                receipt_required,
            });
        } else {
            None
        };

        self.resolved = true;

        Ok(ServiceReplyCommit {
            request_id: self.request_id.clone(),
            service_obligation_id,
            payload,
            delivery_class: self.delivery_class,
            reply_obligation,
        })
    }

    /// Abort the service obligation with a typed failure.
    pub fn abort(
        mut self,
        ledger: &mut ObligationLedger,
        now: Time,
        failure: ServiceFailure,
    ) -> Result<ServiceAbortReceipt, ServiceObligationError> {
        self.ensure_active("abort")?;
        let obligation_id = self.obligation_id();
        if let Some(token) = self.token.take() {
            ledger.abort(token, now, failure.abort_reason());
        }
        Ok(ServiceAbortReceipt {
            request_id: self.request_id,
            obligation_id,
            failure,
            delivery_class: self.delivery_class,
        })
    }

    /// Explicitly timeout the service obligation instead of letting it vanish.
    pub fn timeout(
        self,
        ledger: &mut ObligationLedger,
        now: Time,
    ) -> Result<ServiceAbortReceipt, ServiceObligationError> {
        self.ensure_active("timeout")?;
        self.abort(ledger, now, ServiceFailure::TimedOut)
    }
}

/// Result of committing a service obligation with a reply.
#[derive(Debug)]
pub struct ServiceReplyCommit {
    /// Stable request identifier.
    pub request_id: String,
    /// Service obligation resolved by the commit, when tracking was enabled.
    pub service_obligation_id: Option<ObligationId>,
    /// Reply payload returned by the callee.
    pub payload: Vec<u8>,
    /// Delivery class used for the request.
    pub delivery_class: DeliveryClass,
    /// Optional follow-on reply-delivery obligation.
    pub reply_obligation: Option<ReplyObligation>,
}

/// Receipt emitted when a service obligation aborts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAbortReceipt {
    /// Stable request identifier.
    pub request_id: String,
    /// Service obligation id when the request was tracked.
    pub obligation_id: Option<ObligationId>,
    /// Typed failure recorded for the abort.
    pub failure: ServiceFailure,
    /// Delivery class used for the request.
    pub delivery_class: DeliveryClass,
}

/// Follow-on obligation for reply delivery or receipt after the callee has
/// already served the request.
#[derive(Debug)]
pub struct ReplyObligation {
    /// Service obligation that produced this reply.
    pub service_obligation_id: ObligationId,
    /// Delivery or receipt boundary the reply still needs to cross.
    pub delivery_boundary: AckKind,
    /// Whether the caller required explicit receipt.
    pub receipt_required: bool,
    /// Reply payload bound to this follow-on obligation.
    pub payload: Vec<u8>,
    obligation_id: ObligationId,
    token: Option<ObligationToken>,
}

impl ReplyObligation {
    #[track_caller]
    #[allow(clippy::too_many_arguments)]
    fn allocate(
        ledger: &mut ObligationLedger,
        service_obligation_id: ObligationId,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
        payload: Vec<u8>,
        delivery_boundary: AckKind,
        receipt_required: bool,
    ) -> Self {
        let description = format!("reply obligation for service {service_obligation_id:?}");
        let token = ledger.acquire_with_context(
            ObligationKind::Ack,
            holder,
            region,
            created_at,
            SourceLocation::from_panic_location(Location::caller()),
            None,
            Some(description),
        );
        let obligation_id = token.id();
        Self {
            service_obligation_id,
            delivery_boundary,
            receipt_required,
            payload,
            obligation_id,
            token: Some(token),
        }
    }

    /// Return the reply-obligation id.
    #[must_use]
    pub const fn obligation_id(&self) -> ObligationId {
        self.obligation_id
    }

    /// Commit the reply-delivery obligation.
    pub fn commit_delivery(
        mut self,
        ledger: &mut ObligationLedger,
        now: Time,
    ) -> ReplyDeliveryReceipt {
        let token = self
            .token
            .take()
            .expect("reply obligation token must be present until resolved");
        ledger.commit(token, now);
        ReplyDeliveryReceipt {
            obligation_id: self.obligation_id,
            service_obligation_id: self.service_obligation_id,
            delivery_boundary: self.delivery_boundary,
            receipt_required: self.receipt_required,
        }
    }

    /// Abort the reply-delivery obligation with a typed failure.
    pub fn abort_delivery(
        mut self,
        ledger: &mut ObligationLedger,
        now: Time,
        failure: ServiceFailure,
    ) -> ReplyAbortReceipt {
        let token = self
            .token
            .take()
            .expect("reply obligation token must be present until resolved");
        ledger.abort(token, now, failure.abort_reason());
        ReplyAbortReceipt {
            obligation_id: self.obligation_id,
            service_obligation_id: self.service_obligation_id,
            delivery_boundary: self.delivery_boundary,
            failure,
        }
    }

    /// Explicitly timeout the reply-delivery obligation.
    pub fn timeout(self, ledger: &mut ObligationLedger, now: Time) -> ReplyAbortReceipt {
        self.abort_delivery(ledger, now, ServiceFailure::TimedOut)
    }
}

/// Receipt emitted when a reply obligation commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyDeliveryReceipt {
    /// Reply obligation id.
    pub obligation_id: ObligationId,
    /// Parent service obligation id.
    pub service_obligation_id: ObligationId,
    /// Boundary satisfied by the delivery.
    pub delivery_boundary: AckKind,
    /// Whether the original request required receipt.
    pub receipt_required: bool,
}

/// Receipt emitted when a reply obligation aborts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyAbortReceipt {
    /// Reply obligation id.
    pub obligation_id: ObligationId,
    /// Parent service obligation id.
    pub service_obligation_id: ObligationId,
    /// Boundary that failed to complete.
    pub delivery_boundary: AckKind,
    /// Typed failure recorded for the abort.
    pub failure: ServiceFailure,
}

// ─── Quantitative obligation contracts (SLO-style) ──────────────────────────

/// Retry strategy for SLO-bound obligations.
///
/// Controls how retries are synthesized when a quantitative contract detects
/// that the target latency or probability is at risk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetryLaw {
    /// No automatic retries — binary obligation semantics only.
    None,
    /// Fixed-interval retries with a bounded attempt count.
    Fixed {
        /// Interval between retries.
        interval: Duration,
        /// Maximum number of attempts (including the original).
        max_attempts: u32,
    },
    /// Exponential backoff with jitter and bounded attempts.
    ExponentialBackoff {
        /// Initial delay before the first retry.
        initial_delay: Duration,
        /// Multiplicative factor per retry (typically 2.0).
        multiplier: f64,
        /// Maximum delay cap.
        max_delay: Duration,
        /// Maximum number of attempts (including the original).
        max_attempts: u32,
    },
    /// Budget-aware: retry only while remaining cleanup budget permits.
    BudgetBounded {
        /// Base interval between retries.
        interval: Duration,
    },
}

/// Monitoring policy for quantitative contract drift detection.
///
/// Controls how the runtime observes whether the quantitative contract's
/// SLO targets are being met, and what evidence is produced when they drift.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MonitoringPolicy {
    /// No active monitoring — rely on external systems.
    Passive,
    /// Sample-based monitoring with configurable observation window.
    Sampled {
        /// Fraction of requests to observe (0.0–1.0).
        sampling_ratio: f64,
        /// Rolling window size for computing running statistics.
        window_size: u32,
    },
    /// Continuous e-process monitoring with anytime-valid evidence.
    EProcess {
        /// Confidence level for the e-process (e.g. 0.99).
        confidence: f64,
        /// Maximum evidence accumulation before auto-reset.
        max_evidence: f64,
    },
    /// Conformal prediction monitoring with coverage guarantees.
    Conformal {
        /// Target coverage probability.
        target_coverage: f64,
        /// Calibration set size before predictions begin.
        calibration_size: u32,
    },
}

/// Quantitative obligation contract — SLO-style performance bounds that
/// sit above the binary obligation floor.
///
/// A binary obligation says "this request will be resolved (committed or
/// aborted)." A quantitative contract says "this request will be resolved
/// within `target_latency` with probability ≥ `target_probability` under
/// delivery class `delivery_class`."
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuantitativeContract {
    /// Human-readable name for the contract (e.g. "order-processing-p99").
    pub name: String,
    /// Delivery class this contract applies to.
    pub delivery_class: DeliveryClass,
    /// Target latency bound (e.g. 50ms for interactive, 5s for durable).
    pub target_latency: Duration,
    /// Target probability of meeting the latency bound (e.g. 0.999).
    pub target_probability: f64,
    /// Retry strategy when the SLO is at risk.
    pub retry_law: RetryLaw,
    /// Monitoring policy for drift detection.
    pub monitoring_policy: MonitoringPolicy,
    /// Whether evidence should be recorded when the contract is violated.
    pub record_violations: bool,
}

/// Validation failure for quantitative contracts.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum QuantitativeContractError {
    /// Contract name must be non-empty.
    #[error("quantitative contract name must not be empty")]
    EmptyName,
    /// Target latency must be positive.
    #[error("target latency must be greater than zero")]
    ZeroLatency,
    /// Target probability must be in (0.0, 1.0].
    #[error("target probability {0} must be in (0.0, 1.0]")]
    InvalidProbability(f64),
    /// Retry multiplier must be > 1.0.
    #[error("exponential backoff multiplier {0} must be > 1.0")]
    InvalidMultiplier(f64),
    /// Retry max_attempts must be >= 1.
    #[error("max_attempts must be >= 1")]
    ZeroMaxAttempts,
    /// Sampling ratio must be in (0.0, 1.0].
    #[error("sampling ratio {0} must be in (0.0, 1.0]")]
    InvalidSamplingRatio(f64),
    /// E-process confidence must be in (0.0, 1.0).
    #[error("e-process confidence {0} must be in (0.0, 1.0)")]
    InvalidConfidence(f64),
    /// Conformal coverage must be in (0.0, 1.0).
    #[error("conformal target coverage {0} must be in (0.0, 1.0)")]
    InvalidCoverage(f64),
    /// Conformal calibration size must be > 0.
    #[error("conformal calibration_size must be > 0")]
    ZeroCalibrationSize,
    /// Fixed retry interval must be positive.
    #[error("retry interval must be > 0")]
    ZeroRetryInterval,
    /// Max delay must be positive.
    #[error("max delay must be > 0")]
    ZeroMaxDelay,
    /// Max delay must not be smaller than the initial delay.
    #[error(
        "max delay {max_delay:?} must be greater than or equal to initial delay {initial_delay:?}"
    )]
    MaxDelayBelowInitialDelay {
        /// Initial backoff delay configured for the contract.
        initial_delay: Duration,
        /// Maximum backoff delay cap configured for the contract.
        max_delay: Duration,
    },
    /// Initial delay must be positive.
    #[error("initial delay must be > 0")]
    ZeroInitialDelay,
    /// Monitoring window must be > 0.
    #[error("monitoring window_size must be > 0")]
    ZeroWindowSize,
    /// E-process max_evidence must be > 0.
    #[error("e-process max_evidence must be > 0")]
    ZeroMaxEvidence,
    /// E-process max_evidence must not cap evidence below the alert threshold.
    #[error(
        "e-process max_evidence {max_evidence} must be greater than or equal to alert threshold {threshold}"
    )]
    MaxEvidenceBelowAlertThreshold {
        /// Configured evidence cap.
        max_evidence: f64,
        /// Minimum alert threshold implied by confidence.
        threshold: f64,
    },
}

impl QuantitativeContract {
    /// Validate the contract fields.
    pub fn validate(&self) -> Result<(), QuantitativeContractError> {
        if self.name.trim().is_empty() {
            return Err(QuantitativeContractError::EmptyName);
        }
        if self.target_latency.is_zero() {
            return Err(QuantitativeContractError::ZeroLatency);
        }
        if !is_finite_probability(self.target_probability) {
            return Err(QuantitativeContractError::InvalidProbability(
                self.target_probability,
            ));
        }
        self.validate_retry_law()?;
        self.validate_monitoring_policy()?;
        Ok(())
    }

    fn validate_retry_law(&self) -> Result<(), QuantitativeContractError> {
        match &self.retry_law {
            RetryLaw::None => {}
            RetryLaw::Fixed {
                interval,
                max_attempts,
            } => {
                if interval.is_zero() {
                    return Err(QuantitativeContractError::ZeroRetryInterval);
                }
                if *max_attempts == 0 {
                    return Err(QuantitativeContractError::ZeroMaxAttempts);
                }
            }
            RetryLaw::ExponentialBackoff {
                initial_delay,
                multiplier,
                max_delay,
                max_attempts,
            } => {
                if initial_delay.is_zero() {
                    return Err(QuantitativeContractError::ZeroInitialDelay);
                }
                if !is_finite_gt_one(*multiplier) {
                    return Err(QuantitativeContractError::InvalidMultiplier(*multiplier));
                }
                if max_delay.is_zero() {
                    return Err(QuantitativeContractError::ZeroMaxDelay);
                }
                if max_delay < initial_delay {
                    return Err(QuantitativeContractError::MaxDelayBelowInitialDelay {
                        initial_delay: *initial_delay,
                        max_delay: *max_delay,
                    });
                }
                if *max_attempts == 0 {
                    return Err(QuantitativeContractError::ZeroMaxAttempts);
                }
            }
            RetryLaw::BudgetBounded { interval } => {
                if interval.is_zero() {
                    return Err(QuantitativeContractError::ZeroRetryInterval);
                }
            }
        }
        Ok(())
    }

    fn validate_monitoring_policy(&self) -> Result<(), QuantitativeContractError> {
        match &self.monitoring_policy {
            MonitoringPolicy::Passive => {}
            MonitoringPolicy::Sampled {
                sampling_ratio,
                window_size,
            } => {
                if !is_finite_probability(*sampling_ratio) {
                    return Err(QuantitativeContractError::InvalidSamplingRatio(
                        *sampling_ratio,
                    ));
                }
                if *window_size == 0 {
                    return Err(QuantitativeContractError::ZeroWindowSize);
                }
            }
            MonitoringPolicy::EProcess {
                confidence,
                max_evidence,
            } => {
                if !is_finite_open_probability(*confidence) {
                    return Err(QuantitativeContractError::InvalidConfidence(*confidence));
                }
                if !is_finite_positive(*max_evidence) {
                    return Err(QuantitativeContractError::ZeroMaxEvidence);
                }
                let threshold = quantitative_eprocess_threshold(*confidence);
                if *max_evidence < threshold {
                    return Err(QuantitativeContractError::MaxEvidenceBelowAlertThreshold {
                        max_evidence: *max_evidence,
                        threshold,
                    });
                }
            }
            MonitoringPolicy::Conformal {
                target_coverage,
                calibration_size,
            } => {
                if !is_finite_open_probability(*target_coverage) {
                    return Err(QuantitativeContractError::InvalidCoverage(*target_coverage));
                }
                if *calibration_size == 0 {
                    return Err(QuantitativeContractError::ZeroCalibrationSize);
                }
            }
        }
        Ok(())
    }

    /// Check whether a measured latency satisfies this contract's target.
    #[must_use]
    pub fn latency_satisfies(&self, measured: Duration) -> bool {
        measured <= self.target_latency
    }
}

/// Current health of a quantitative obligation contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuantitativeContractState {
    /// The observed service remains within the declared envelope.
    #[default]
    Healthy,
    /// Early warning indicates the service is drifting toward violation.
    AtRisk,
    /// The observed service has violated the declared contract.
    Violated,
}

impl fmt::Display for QuantitativeContractState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Healthy => "healthy",
            Self::AtRisk => "at_risk",
            Self::Violated => "violated",
        };
        write!(f, "{name}")
    }
}

/// Recommended action after evaluating a quantitative contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuantitativePolicyRecommendation {
    /// The current policy remains inside the declared envelope.
    #[default]
    KeepCurrent,
    /// Apply the contract's retry law before escalating further.
    ApplyRetryLaw,
    /// Escalate to an operator-visible policy change or degradation path.
    Escalate,
}

impl fmt::Display for QuantitativePolicyRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::KeepCurrent => "keep_current",
            Self::ApplyRetryLaw => "apply_retry_law",
            Self::Escalate => "escalate",
        };
        write!(f, "{name}")
    }
}

/// Alert state surfaced from the quantitative contract's e-process monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantitativeMonitorAlertState {
    /// No active alert.
    Clear,
    /// Evidence is accumulating but has not crossed the alert threshold.
    Watching,
    /// The anytime-valid monitor crossed its threshold.
    Alert,
}

impl From<EProcessAlertState> for QuantitativeMonitorAlertState {
    fn from(value: EProcessAlertState) -> Self {
        match value {
            EProcessAlertState::Clear => Self::Clear,
            EProcessAlertState::Watching => Self::Watching,
            EProcessAlertState::Alert => Self::Alert,
        }
    }
}

/// Monitor-specific evidence attached to a quantitative contract evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuantitativeMonitorEvidence {
    /// Passive monitoring uses only observed success probability.
    Passive,
    /// Sampled monitoring tracks a rolling sampled window.
    Sampled {
        /// Deterministic sampling ratio applied to observations.
        sampling_ratio: f64,
        /// Total sampled observations since monitor creation.
        sampled_observations: u64,
        /// Rolling window size used for drift checks.
        window_size: u32,
        /// Fraction of sampled observations that met the target latency.
        window_hit_rate: f64,
    },
    /// E-process monitoring with anytime-valid evidence.
    EProcess {
        /// Confidence level configured for the monitor.
        confidence: f64,
        /// Current e-value after processing the latest sample.
        e_value: f64,
        /// Rejection threshold (Ville bound) for the e-process.
        threshold: f64,
        /// Maximum evidence level before the monitor auto-resets.
        max_evidence: f64,
        /// Whether the reported evidence hit the configured cap.
        capped: bool,
        /// Current alert state of the e-process.
        alert_state: QuantitativeMonitorAlertState,
    },
    /// Conformal calibration evidence for latency drift detection.
    Conformal {
        /// Target conformal coverage probability.
        target_coverage: f64,
        /// Calibration-set size required before anomaly checks begin.
        calibration_size: u32,
        /// Current number of calibration samples recorded for this contract.
        calibration_samples: usize,
        /// Current conformal latency threshold, once calibrated.
        threshold_latency: Option<Duration>,
        /// Observed coverage rate since tracking began, if available.
        coverage: Option<f64>,
        /// Whether the latest observation was conforming, if a check ran.
        latest_conforming: Option<bool>,
    },
}

/// Structured evaluation of one quantitative contract observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuantitativeContractEvaluation {
    /// Contract name being evaluated.
    pub contract_name: String,
    /// Delivery class bound to the contract.
    pub delivery_class: DeliveryClass,
    /// Latest observed latency.
    pub latest_latency: Duration,
    /// Latency target encoded in the contract.
    pub target_latency: Duration,
    /// Total observations processed by the monitor.
    pub observations: u64,
    /// Number of observations that met `target_latency`.
    pub hit_count: u64,
    /// Observed success probability so far.
    pub observed_probability: f64,
    /// Required success probability from the contract.
    pub target_probability: f64,
    /// Current contract state after the latest observation.
    pub state: QuantitativeContractState,
    /// Recommended next action for the control surface.
    pub recommendation: QuantitativePolicyRecommendation,
    /// Monitor-specific supporting evidence.
    pub evidence: QuantitativeMonitorEvidence,
}

/// Stateful runtime monitor for quantitative contract drift detection.
#[derive(Debug)]
pub struct QuantitativeContractMonitor {
    contract: QuantitativeContract,
    observations: u64,
    hit_count: u64,
    sampled_window: VecDeque<bool>,
    sampled_observations: u64,
    eprocess: Option<LeakMonitor>,
    conformal: Option<HealthThresholdCalibrator>,
    last_evaluation: Option<QuantitativeContractEvaluation>,
}

impl QuantitativeContractMonitor {
    /// Create a new monitor for the given contract.
    pub fn new(contract: QuantitativeContract) -> Result<Self, QuantitativeContractError> {
        contract.validate()?;
        let eprocess = match contract.monitoring_policy {
            MonitoringPolicy::EProcess {
                confidence,
                max_evidence: _,
            } => Some(new_quantitative_eprocess(
                contract.target_latency,
                confidence,
            )),
            _ => None,
        };
        let conformal = match contract.monitoring_policy {
            MonitoringPolicy::Conformal {
                target_coverage,
                calibration_size,
            } => Some(HealthThresholdCalibrator::new(
                HealthThresholdConfig::new(1.0 - target_coverage, ThresholdMode::Upper)
                    .min_samples(usize::try_from(calibration_size).expect("u32 fits usize")),
            )),
            _ => None,
        };

        Ok(Self {
            contract,
            observations: 0,
            hit_count: 0,
            sampled_window: VecDeque::new(),
            sampled_observations: 0,
            eprocess,
            conformal,
            last_evaluation: None,
        })
    }

    /// Return the underlying contract.
    #[must_use]
    pub fn contract(&self) -> &QuantitativeContract {
        &self.contract
    }

    /// Return the aggregate probability of meeting the target latency.
    #[must_use]
    pub fn observed_probability(&self) -> f64 {
        ratio(self.hit_count, self.observations)
    }

    /// Return the most recent quantitative evaluation, if one exists.
    #[must_use]
    pub fn last_evaluation(&self) -> Option<&QuantitativeContractEvaluation> {
        self.last_evaluation.as_ref()
    }

    /// Return the latest policy-change evidence when recording is enabled.
    #[must_use]
    pub fn policy_change_evidence(&self) -> Option<QuantitativeContractEvaluation> {
        let evaluation = self.last_evaluation.as_ref()?;
        if self.contract.record_violations && evaluation.state != QuantitativeContractState::Healthy
        {
            Some(evaluation.clone())
        } else {
            None
        }
    }

    /// Observe one completed service latency and evaluate the contract.
    #[allow(clippy::too_many_lines)]
    pub fn observe_latency(&mut self, latency: Duration) -> QuantitativeContractEvaluation {
        self.observations = self.observations.saturating_add(1);
        let hit = self.contract.latency_satisfies(latency);
        if hit {
            self.hit_count = self.hit_count.saturating_add(1);
        }

        let observed_probability = self.observed_probability();
        let mut state = self.baseline_state(hit, observed_probability);
        let evidence = match &self.contract.monitoring_policy {
            MonitoringPolicy::Passive => QuantitativeMonitorEvidence::Passive,
            MonitoringPolicy::Sampled {
                sampling_ratio,
                window_size,
            } => {
                let window_size_usize = usize::try_from(*window_size).expect("u32 fits usize");
                if should_sample_observation(self.observations, *sampling_ratio) {
                    self.sampled_observations = self.sampled_observations.saturating_add(1);
                    self.sampled_window.push_back(hit);
                    while self.sampled_window.len() > window_size_usize {
                        self.sampled_window.pop_front();
                    }
                }

                let window_hit_rate = bool_ratio(&self.sampled_window);
                if self.sampled_window.len() >= window_size_usize
                    && window_hit_rate < self.contract.target_probability
                {
                    state = state.max(QuantitativeContractState::Violated);
                }

                QuantitativeMonitorEvidence::Sampled {
                    sampling_ratio: *sampling_ratio,
                    sampled_observations: self.sampled_observations,
                    window_size: *window_size,
                    window_hit_rate,
                }
            }
            MonitoringPolicy::EProcess {
                confidence,
                max_evidence,
            } => {
                let (reported_e_value, threshold, capped, alert_state) = {
                    let Some(monitor) = self.eprocess.as_mut() else {
                        unreachable!("e-process monitor must exist for e-process policies");
                    };
                    monitor.observe(duration_to_monitor_nanos(latency));

                    let raw_e_value = monitor.e_value();
                    let capped = raw_e_value >= *max_evidence;
                    (
                        raw_e_value.min(*max_evidence),
                        monitor.threshold(),
                        capped,
                        QuantitativeMonitorAlertState::from(monitor.alert_state()),
                    )
                };
                state = match alert_state {
                    QuantitativeMonitorAlertState::Clear => state,
                    QuantitativeMonitorAlertState::Watching => {
                        state.max(QuantitativeContractState::AtRisk)
                    }
                    QuantitativeMonitorAlertState::Alert => QuantitativeContractState::Violated,
                };

                if capped && matches!(alert_state, QuantitativeMonitorAlertState::Alert) {
                    self.eprocess = Some(new_quantitative_eprocess(
                        self.contract.target_latency,
                        *confidence,
                    ));
                }

                QuantitativeMonitorEvidence::EProcess {
                    confidence: *confidence,
                    e_value: reported_e_value,
                    threshold,
                    max_evidence: *max_evidence,
                    capped,
                    alert_state,
                }
            }
            MonitoringPolicy::Conformal {
                target_coverage,
                calibration_size,
            } => {
                let Some(calibrator) = self.conformal.as_mut() else {
                    unreachable!("conformal monitor must exist for conformal policies");
                };
                let metric = self.contract.name.as_str();
                let latency_ms = duration_to_millis(latency);

                let (threshold_latency, coverage, latest_conforming) = if calibrator
                    .is_metric_calibrated(metric)
                {
                    let Some(check) = calibrator.check_and_track(metric, latency_ms) else {
                        unreachable!("calibrated conformal monitor must return a check");
                    };
                    let coverage = calibrator.coverage_rates().get(metric).copied();
                    if !check.conforming || coverage.is_some_and(|value| value < *target_coverage) {
                        state = state.max(QuantitativeContractState::AtRisk);
                    }

                    (
                        Some(duration_from_millis(check.threshold)),
                        coverage,
                        Some(check.conforming),
                    )
                } else {
                    calibrator.calibrate(metric, latency_ms);
                    (
                        calibrator.threshold(metric).map(duration_from_millis),
                        None,
                        None,
                    )
                };

                let calibration_samples =
                    calibrator.metric_counts().get(metric).copied().unwrap_or(0);

                QuantitativeMonitorEvidence::Conformal {
                    target_coverage: *target_coverage,
                    calibration_size: *calibration_size,
                    calibration_samples,
                    threshold_latency,
                    coverage,
                    latest_conforming,
                }
            }
        };

        let recommendation = match state {
            QuantitativeContractState::Healthy => QuantitativePolicyRecommendation::KeepCurrent,
            QuantitativeContractState::AtRisk => {
                if matches!(self.contract.retry_law, RetryLaw::None) {
                    QuantitativePolicyRecommendation::Escalate
                } else {
                    QuantitativePolicyRecommendation::ApplyRetryLaw
                }
            }
            QuantitativeContractState::Violated => QuantitativePolicyRecommendation::Escalate,
        };

        let evaluation = QuantitativeContractEvaluation {
            contract_name: self.contract.name.clone(),
            delivery_class: self.contract.delivery_class,
            latest_latency: latency,
            target_latency: self.contract.target_latency,
            observations: self.observations,
            hit_count: self.hit_count,
            observed_probability,
            target_probability: self.contract.target_probability,
            state,
            recommendation,
            evidence,
        };
        self.last_evaluation = Some(evaluation.clone());
        evaluation
    }

    fn baseline_state(&self, hit: bool, observed_probability: f64) -> QuantitativeContractState {
        if self.observations >= 3 && observed_probability < self.contract.target_probability {
            QuantitativeContractState::Violated
        } else if !hit || observed_probability < self.contract.target_probability {
            QuantitativeContractState::AtRisk
        } else {
            QuantitativeContractState::Healthy
        }
    }
}

fn new_quantitative_eprocess(target_latency: Duration, confidence: f64) -> LeakMonitor {
    let alpha = quantitative_eprocess_alpha(confidence);
    LeakMonitor::new(LeakMonitorConfig {
        alpha,
        expected_lifetime_ns: duration_to_monitor_nanos(target_latency),
        min_observations: 3,
    })
}

fn quantitative_eprocess_alpha(confidence: f64) -> f64 {
    (1.0 - confidence).clamp(f64::EPSILON, 1.0 - f64::EPSILON)
}

fn quantitative_eprocess_threshold(confidence: f64) -> f64 {
    1.0 / quantitative_eprocess_alpha(confidence)
}

#[allow(clippy::cast_possible_truncation)]
fn duration_to_monitor_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn duration_to_millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn duration_from_millis(millis: f64) -> Duration {
    if !millis.is_finite() || millis <= 0.0 {
        Duration::ZERO
    } else {
        Duration::from_secs_f64(millis / 1000.0)
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn bool_ratio(values: &VecDeque<bool>) -> f64 {
    let hits =
        u64::try_from(values.iter().filter(|value| **value).count()).expect("usize fits u64");
    let len = u64::try_from(values.len()).expect("usize fits u64");
    ratio(hits, len)
}

#[allow(clippy::cast_precision_loss)]
fn should_sample_observation(index: u64, sampling_ratio: f64) -> bool {
    if sampling_ratio >= 1.0 {
        return true;
    }
    if index == 0 {
        return false;
    }
    let previous_bucket = ((index - 1) as f64 * sampling_ratio).floor();
    let current_bucket = (index as f64 * sampling_ratio).floor();
    current_bucket > previous_bucket
}

fn is_finite_positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

fn is_finite_gt_one(value: f64) -> bool {
    value.is_finite() && value > 1.0
}

fn is_finite_probability(value: f64) -> bool {
    value.is_finite() && value > 0.0 && value <= 1.0
}

fn is_finite_open_probability(value: f64) -> bool {
    value.is_finite() && value > 0.0 && value < 1.0
}

/// Validation failure for runtime service obligations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceObligationError {
    /// Required string fields must be non-empty.
    #[error("service obligation field `{field}` must not be empty")]
    EmptyField {
        /// Field that failed validation.
        field: &'static str,
    },
    /// Timeout values must be strictly positive when present.
    #[error("service obligation timeout must be greater than zero")]
    ZeroTimeout,
    /// Resolved obligations cannot be mutated again.
    #[error("service obligation already resolved; cannot {operation}")]
    AlreadyResolved {
        /// Operation attempted on an already-resolved obligation.
        operation: &'static str,
    },
    /// Requested reply boundary is weaker than the selected delivery class can
    /// honestly claim.
    #[error(
        "reply boundary `{requested_boundary}` is weaker than minimum `{minimum_boundary}` for delivery class `{delivery_class}`"
    )]
    ReplyBoundaryBelowMinimum {
        /// Delivery class bound to the request.
        delivery_class: DeliveryClass,
        /// Minimum honest boundary for the class.
        minimum_boundary: AckKind,
        /// Boundary the caller attempted to use.
        requested_boundary: AckKind,
    },
    /// Receipt-tracked replies must finish at the `received` boundary.
    #[error(
        "receipt-required replies must use the `received` boundary, not `{requested_boundary}`"
    )]
    ReceiptRequiresReceivedBoundary {
        /// Boundary requested by the caller.
        requested_boundary: AckKind,
    },
    /// Lower-cost classes stay cheap and cannot pretend to support tracked
    /// reply delivery semantics they did not pay for.
    #[error(
        "delivery class `{delivery_class}` cannot support tracked reply boundary `{requested_boundary}` (receipt_required={receipt_required})"
    )]
    ReplyTrackingUnavailable {
        /// Delivery class bound to the request.
        delivery_class: DeliveryClass,
        /// Boundary the caller attempted to use.
        requested_boundary: AckKind,
        /// Whether explicit receipt was requested.
        receipt_required: bool,
    },
    /// Tracked reply state must keep the parent service obligation id.
    #[error(
        "delivery class `{delivery_class}` requires a parent service obligation id for tracked reply state"
    )]
    TrackedReplyMissingParentObligationId {
        /// Delivery class bound to the reply.
        delivery_class: DeliveryClass,
    },
    /// Chunked reply declared as chunked but missing expected count.
    #[error("chunked reply certificate must declare total_chunks")]
    ChunkedReplyMissingCount,
    /// Unary replies must not claim streamed chunk counts.
    #[error("unary reply certificate must not declare total_chunks")]
    UnaryReplyChunkCountPresent,
    /// Chunked reply declared zero expected chunks.
    #[error("chunked reply expected_chunks must be > 0")]
    ChunkedReplyZeroExpected,
    /// Chunked reply stream was certified before finalization.
    #[error("chunked reply certificate requires a finalized stream")]
    ChunkedReplyNotFinalized,
    /// Bounded chunked reply stream was finalized or certified before all chunks arrived.
    #[error("chunked reply incomplete: expected {expected}, received {received}")]
    ChunkedReplyIncomplete {
        /// Declared expected chunk count.
        expected: u32,
        /// Actual chunk count recorded so far.
        received: u32,
    },
    /// More chunks received than the declared expected count.
    #[error("chunked reply overflow: expected {expected}, received {received}")]
    ChunkedReplyOverflow {
        /// Declared expected chunk count.
        expected: u32,
        /// Actual chunk count that exceeded the limit.
        received: u32,
    },
}

fn validate_service_text(field: &'static str, value: &str) -> Result<(), ServiceObligationError> {
    if value.trim().is_empty() {
        return Err(ServiceObligationError::EmptyField { field });
    }
    Ok(())
}

fn requires_follow_up_reply(delivery_boundary: AckKind, receipt_required: bool) -> bool {
    receipt_required || delivery_boundary > AckKind::Served
}

fn validate_reply_boundary(
    delivery_class: DeliveryClass,
    delivery_boundary: AckKind,
    receipt_required: bool,
) -> Result<(), ServiceObligationError> {
    let minimum_boundary = delivery_class.minimum_ack();
    if delivery_boundary < minimum_boundary {
        return Err(ServiceObligationError::ReplyBoundaryBelowMinimum {
            delivery_class,
            minimum_boundary,
            requested_boundary: delivery_boundary,
        });
    }
    if receipt_required && delivery_boundary != AckKind::Received {
        return Err(ServiceObligationError::ReceiptRequiresReceivedBoundary {
            requested_boundary: delivery_boundary,
        });
    }
    if delivery_class < DeliveryClass::ObligationBacked
        && requires_follow_up_reply(delivery_boundary, receipt_required)
    {
        return Err(ServiceObligationError::ReplyTrackingUnavailable {
            delivery_class,
            requested_boundary: delivery_boundary,
            receipt_required,
        });
    }
    Ok(())
}

/// Registered FABRIC service surface with provider/caller authority split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRegistration {
    /// Human-readable service name.
    pub service_name: String,
    /// Structural contract for the service boundary.
    pub contract: ServiceContractSchema,
    /// Provider-declared bounds and guarantees.
    pub provider_terms: ProviderTerms,
}

impl ServiceRegistration {
    /// Register a service surface with validated provider terms.
    pub fn new(
        service_name: impl Into<String>,
        contract: ServiceContractSchema,
        provider_terms: ProviderTerms,
    ) -> Result<Self, ServiceContractError> {
        let service_name = service_name.into();
        if service_name.trim().is_empty() {
            return Err(ServiceContractError::EmptyServiceName);
        }
        contract.validate()?;
        provider_terms.validate_against(&contract)?;
        Ok(Self {
            service_name,
            contract,
            provider_terms,
        })
    }

    /// Validate caller-selected options against provider-declared bounds.
    pub fn validate_caller(
        &self,
        caller: &CallerOptions,
    ) -> Result<ValidatedServiceRequest, ServiceContractError> {
        if caller
            .timeout_override
            .is_some_and(|timeout| timeout.is_zero())
        {
            return Err(ServiceContractError::ZeroDuration {
                field: "caller_options.timeout_override".to_owned(),
            });
        }
        if caller.timeout_override.is_some()
            && !self.contract.budget_semantics.allow_timeout_override
        {
            return Err(ServiceContractError::TimeoutOverrideNotAllowed);
        }
        if caller.priority_hint.is_some() && !self.contract.budget_semantics.honor_priority_hints {
            return Err(ServiceContractError::PriorityHintsNotAllowed);
        }

        let delivery_class = self
            .provider_terms
            .admissible_classes
            .select_for_caller(caller.requested_class)?;

        Ok(ValidatedServiceRequest {
            delivery_class,
            timeout: caller
                .timeout_override
                .or(self.contract.budget_semantics.default_timeout),
            priority_hint: caller.priority_hint,
            guaranteed_durability: self.provider_terms.guaranteed_durability,
            evidence_level: self.provider_terms.evidence_level,
            mobility_constraint: self.provider_terms.mobility_constraint.clone(),
            compensation_policy: self.provider_terms.compensation_policy,
            overload_policy: self.contract.overload_policy.clone(),
        })
    }
}

/// Error returned by the composed FABRIC service-boundary surface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceBoundaryError {
    /// The declared request subject does not belong to the namespace.
    #[error("service subject `{subject}` is outside namespace `{namespace}`")]
    SubjectOutsideNamespace {
        /// Subject that failed validation.
        subject: String,
        /// Canonical namespace pattern the subject should have matched.
        namespace: String,
    },
    /// The morphism does not cover this boundary's request subject.
    #[error(
        "service boundary subject `{subject}` is not covered by morphism source language `{source_language}`"
    )]
    MorphismDoesNotCoverBoundary {
        /// Boundary request subject that failed to match the morphism source.
        subject: String,
        /// Source language declared by the morphism.
        source_language: String,
    },
    /// The target subject does not satisfy the morphism destination language.
    #[error(
        "target subject `{subject}` is not covered by morphism destination language `{dest_language}`"
    )]
    TargetOutsideMorphismDestination {
        /// Concrete target subject passed to the transfer.
        subject: String,
        /// Destination language declared by the morphism.
        dest_language: String,
    },
    /// Subject-only transfer helpers require unrestricted mobility.
    #[error(
        "subject-only service transfer to `{target_subject}` requires unrestricted mobility, got `{constraint}`"
    )]
    TransferRequiresUnrestrictedMobility {
        /// Mobility contract attached to the admitted request.
        constraint: MobilityConstraint,
        /// Concrete target subject that required a mobility check.
        target_subject: String,
    },
    /// The provided admission does not describe the obligation being transferred.
    #[error(
        "service admission request `{admission_request_id}` does not match obligation request `{obligation_request_id}`"
    )]
    AdmissionRequestMismatch {
        /// Request id from the admission certificate.
        admission_request_id: String,
        /// Request id carried by the obligation being transferred.
        obligation_request_id: String,
    },
    /// The obligation is no longer positioned at this boundary's request subject.
    #[error(
        "service obligation subject `{subject}` is not currently owned by boundary subject `{boundary_subject}`"
    )]
    ObligationOutsideBoundary {
        /// Current obligation subject.
        subject: String,
        /// Request subject owned by this boundary.
        boundary_subject: String,
    },
    /// Namespace-scoped subject generation failed.
    #[error(transparent)]
    Namespace(#[from] NamespaceKernelError),
    /// Service contract validation failed.
    #[error(transparent)]
    Contract(#[from] ServiceContractError),
    /// Control-plane handler registration failed.
    #[error(transparent)]
    ControlRegistry(#[from] ControlRegistryError),
    /// Morphism boundary-plan compilation failed.
    #[error(transparent)]
    MorphismCompile(#[from] MorphismCompileError),
    /// Request certificate or service-obligation operations failed.
    #[error(transparent)]
    Obligation(#[from] ServiceObligationError),
}

/// Concrete control and discovery subjects attached to one service boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceControlSubjects {
    /// Data-plane discovery subject for the service namespace.
    pub discovery: Subject,
    /// Control-plane health status subject for the service namespace.
    pub health: Subject,
    /// Control-plane advisory subject for service-routing events.
    pub advisories: Subject,
}

/// Registered control handlers for one service boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceControlHandlers {
    /// Handler serving health subjects for the service namespace.
    pub health: ControlHandlerId,
    /// Handler serving service advisory subjects for the service namespace.
    pub advisories: ControlHandlerId,
}

/// Result of admitting one request through the FABRIC service boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAdmission {
    /// Effective request envelope after provider-bound validation.
    pub validated: ValidatedServiceRequest,
    /// Deterministic request certificate emitted at admission.
    pub certificate: RequestCertificate,
}

/// Unified FABRIC-native service boundary.
///
/// This composes one namespace-bound request subject, one validated service
/// registration, control-plane health/advisory surfaces, and morphism helpers
/// for cross-domain routing without introducing a separate service-mesh plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricServiceBoundary {
    namespace: NamespaceKernel,
    request_subject: Subject,
    registration: ServiceRegistration,
}

impl FabricServiceBoundary {
    /// Create a new FABRIC service boundary for one namespace and request subject.
    pub fn new(
        namespace: NamespaceKernel,
        request_subject: Subject,
        registration: ServiceRegistration,
    ) -> Result<Self, ServiceBoundaryError> {
        if !namespace.owns_subject(&request_subject) {
            return Err(ServiceBoundaryError::SubjectOutsideNamespace {
                subject: request_subject.as_str().to_owned(),
                namespace: namespace.service_pattern().as_str().to_owned(),
            });
        }

        Ok(Self {
            namespace,
            request_subject,
            registration,
        })
    }

    /// Return the namespace kernel that owns this boundary.
    #[must_use]
    pub fn namespace(&self) -> &NamespaceKernel {
        &self.namespace
    }

    /// Return the request subject served by this boundary.
    #[must_use]
    pub fn request_subject(&self) -> &Subject {
        &self.request_subject
    }

    /// Return the validated service registration for this boundary.
    #[must_use]
    pub fn registration(&self) -> &ServiceRegistration {
        &self.registration
    }

    /// Return the discovery, health, and advisory subjects for this boundary.
    pub fn control_subjects(&self) -> Result<ServiceControlSubjects, ServiceBoundaryError> {
        Ok(ServiceControlSubjects {
            discovery: self.namespace.service_discovery_subject(),
            health: self.health_scope().subject("status")?,
            advisories: self.advisory_scope().subject("advisory")?,
        })
    }

    /// Register namespace-scoped control handlers for health and advisory traffic.
    pub fn register_control_handlers(
        &self,
        registry: &mut ControlRegistry,
    ) -> Result<ServiceControlHandlers, ServiceBoundaryError> {
        Ok(ServiceControlHandlers {
            health: registry.register_namespace_default(&self.health_scope())?,
            advisories: registry.register_namespace_default(&self.advisory_scope())?,
        })
    }

    /// Validate caller options and emit an admission certificate for the request.
    pub fn admit_request(
        &self,
        request_id: impl Into<String>,
        caller: impl Into<String>,
        caller_options: &CallerOptions,
        reply_space_rule: super::ir::ReplySpaceRule,
        capability_fingerprint: u64,
        issued_at: Time,
    ) -> Result<ServiceAdmission, ServiceBoundaryError> {
        let validated = self.registration.validate_caller(caller_options)?;
        let certificate = RequestCertificate::from_validated(
            request_id.into(),
            caller.into(),
            self.request_subject.as_str().to_owned(),
            &validated,
            reply_space_rule,
            self.registration.service_name.clone(),
            capability_fingerprint,
            issued_at,
        );
        certificate.validate()?;

        Ok(ServiceAdmission {
            validated,
            certificate,
        })
    }

    /// Compile an import-side morphism plan for this boundary.
    pub fn compile_import_plan(
        &self,
        morphism: &Morphism,
        requested_reply_space: Option<super::ir::ReplySpaceRule>,
    ) -> Result<ImportPlan, ServiceBoundaryError> {
        self.ensure_morphism_covers_boundary(morphism)?;
        Ok(morphism.compile_import_plan(requested_reply_space)?)
    }

    /// Compile an export-side morphism plan for this boundary.
    pub fn compile_export_plan(
        &self,
        morphism: &Morphism,
        requested_reply_space: Option<super::ir::ReplySpaceRule>,
    ) -> Result<ExportPlan, ServiceBoundaryError> {
        self.ensure_morphism_covers_boundary(morphism)?;
        Ok(morphism.compile_export_plan(requested_reply_space)?)
    }

    /// Transfer an admitted in-flight request through an import-side morphism boundary.
    ///
    /// This helper operates on subject-level evidence only, so it fails closed
    /// unless the admitted request has unrestricted mobility and the obligation
    /// is still positioned at this boundary's request subject.
    pub fn transfer_request_via_import(
        &self,
        admission: &ServiceAdmission,
        obligation: &mut ServiceObligation,
        callee: impl Into<String>,
        target_subject: Subject,
        morphism_name: impl Into<String>,
        morphism: &Morphism,
        requested_reply_space: Option<super::ir::ReplySpaceRule>,
        transferred_at: Time,
    ) -> Result<ImportPlan, ServiceBoundaryError> {
        self.ensure_transfer_request_matches(admission, obligation)?;
        self.ensure_transfer_mobility(&admission.validated, &target_subject)?;
        self.ensure_morphism_target(morphism, &target_subject)?;
        let plan = self.compile_import_plan(morphism, requested_reply_space)?;
        obligation.transfer(
            callee.into(),
            target_subject.as_str(),
            morphism_name.into(),
            transferred_at,
        )?;
        Ok(plan)
    }

    /// Abort an in-flight request with the canonical cancelled failure.
    pub fn cancel_request(
        &self,
        obligation: ServiceObligation,
        ledger: &mut ObligationLedger,
        aborted_at: Time,
    ) -> Result<ServiceAbortReceipt, ServiceBoundaryError> {
        Ok(obligation.abort(ledger, aborted_at, ServiceFailure::Cancelled)?)
    }

    fn health_scope(&self) -> NamespaceControlScope {
        NamespaceControlScope::from_namespace(SystemSubjectFamily::Health, &self.namespace)
    }

    fn advisory_scope(&self) -> NamespaceControlScope {
        NamespaceControlScope::from_namespace(SystemSubjectFamily::Route, &self.namespace)
    }

    fn ensure_morphism_covers_boundary(
        &self,
        morphism: &Morphism,
    ) -> Result<(), ServiceBoundaryError> {
        if morphism.source_language.matches(&self.request_subject) {
            Ok(())
        } else {
            Err(ServiceBoundaryError::MorphismDoesNotCoverBoundary {
                subject: self.request_subject.as_str().to_owned(),
                source_language: morphism.source_language.as_str().to_owned(),
            })
        }
    }

    fn ensure_morphism_target(
        &self,
        morphism: &Morphism,
        target_subject: &Subject,
    ) -> Result<(), ServiceBoundaryError> {
        if morphism.dest_language.matches(target_subject) {
            Ok(())
        } else {
            Err(ServiceBoundaryError::TargetOutsideMorphismDestination {
                subject: target_subject.as_str().to_owned(),
                dest_language: morphism.dest_language.as_str().to_owned(),
            })
        }
    }

    fn ensure_transfer_mobility(
        &self,
        validated: &ValidatedServiceRequest,
        target_subject: &Subject,
    ) -> Result<(), ServiceBoundaryError> {
        if validated.mobility_constraint == MobilityConstraint::Unrestricted {
            Ok(())
        } else {
            Err(ServiceBoundaryError::TransferRequiresUnrestrictedMobility {
                constraint: validated.mobility_constraint.clone(),
                target_subject: target_subject.as_str().to_owned(),
            })
        }
    }

    fn ensure_transfer_request_matches(
        &self,
        admission: &ServiceAdmission,
        obligation: &ServiceObligation,
    ) -> Result<(), ServiceBoundaryError> {
        if admission.certificate.request_id != obligation.request_id {
            return Err(ServiceBoundaryError::AdmissionRequestMismatch {
                admission_request_id: admission.certificate.request_id.clone(),
                obligation_request_id: obligation.request_id.clone(),
            });
        }

        if obligation.subject == self.request_subject.as_str() {
            Ok(())
        } else {
            Err(ServiceBoundaryError::ObligationOutsideBoundary {
                subject: obligation.subject.clone(),
                boundary_subject: self.request_subject.as_str().to_owned(),
            })
        }
    }
}

fn validate_workflow_text(field: &'static str, value: &str) -> Result<(), WorkflowStateError> {
    if value.trim().is_empty() {
        return Err(WorkflowStateError::EmptyField { field });
    }
    Ok(())
}

/// Validation and lifecycle failures for FABRIC workflow and saga state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WorkflowStateError {
    /// Required workflow text fields must be non-empty.
    #[error("workflow field `{field}` must not be empty")]
    EmptyField {
        /// Field that failed validation.
        field: &'static str,
    },
    /// Duration-valued workflow fields must be strictly positive when present.
    #[error("workflow duration field `{field}` must be greater than zero")]
    ZeroDuration {
        /// Field that failed validation.
        field: &'static str,
    },
    /// Step transitions must respect the workflow lifecycle.
    #[error("workflow step `{step_id}` cannot {operation} while in status `{status}`")]
    InvalidStepTransition {
        /// Step that rejected the transition.
        step_id: String,
        /// Operation attempted.
        operation: &'static str,
        /// Current step status.
        status: &'static str,
    },
    /// A saga must contain at least one step.
    #[error("workflow saga `{saga_id}` must contain at least one step")]
    EmptySaga {
        /// Saga identifier.
        saga_id: String,
    },
    /// The saga has no step that can be started or resumed.
    #[error("workflow saga `{saga_id}` has no runnable step")]
    NoRunnableStep {
        /// Saga identifier.
        saga_id: String,
    },
    /// `current_step` pointed outside the declared step list.
    #[error(
        "workflow saga `{saga_id}` current_step {current_step} is out of bounds for {len} steps"
    )]
    InvalidCurrentStep {
        /// Saga identifier.
        saga_id: String,
        /// Invalid current-step index.
        current_step: usize,
        /// Total step count.
        len: usize,
    },
    /// The workflow references an obligation id that is not present in the ledger.
    #[error("workflow obligation `{obligation_id:?}` is not present in the ledger")]
    UnknownObligation {
        /// Missing obligation id.
        obligation_id: ObligationId,
    },
    /// Crash recovery can still abort by id, but a commit requires the original live token.
    #[error(
        "workflow obligation `{obligation_id:?}` is still pending but no live token is available to commit it"
    )]
    MissingLiveToken {
        /// Obligation that lost its live token.
        obligation_id: ObligationId,
    },
    /// Terminal obligations cannot be resolved a second time.
    #[error("workflow obligation `{obligation_id:?}` is already resolved as `{state:?}`")]
    ObligationAlreadyResolved {
        /// Obligation id.
        obligation_id: ObligationId,
        /// Terminal state already recorded in the ledger.
        state: ObligationState,
    },
}

/// Direct obligation role carried by a durable workflow step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkflowObligationRole {
    /// Reply delivery or receipt still owed for the step.
    Reply {
        /// Delivery boundary still owed.
        delivery_boundary: AckKind,
        /// Whether explicit caller receipt is still owed.
        receipt_required: bool,
    },
    /// A lease or reservation on an external resource remains active.
    Lease {
        /// Human-readable resource name.
        resource: String,
    },
    /// The step is carrying an explicit timeout duty.
    Timeout,
    /// Compensation along a subject transition path is still owed.
    Compensation {
        /// Subject transition that performs the compensation action.
        subject: Subject,
    },
    /// The step owes a deadline checkpoint by a specific instant.
    Deadline {
        /// Absolute deadline for the step.
        deadline: Time,
    },
}

impl WorkflowObligationRole {
    fn validate(&self) -> Result<(), WorkflowStateError> {
        if let Self::Lease { resource } = self {
            validate_workflow_text("workflow_obligation.lease.resource", resource)?;
        }
        Ok(())
    }

    const fn obligation_kind(&self) -> ObligationKind {
        match self {
            Self::Reply { .. } => ObligationKind::Ack,
            Self::Lease { .. } => ObligationKind::Lease,
            Self::Timeout | Self::Deadline { .. } => ObligationKind::IoOp,
            Self::Compensation { .. } => ObligationKind::SendPermit,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Reply {
                delivery_boundary,
                receipt_required,
            } => {
                format!("reply boundary {delivery_boundary} (receipt_required={receipt_required})")
            }
            Self::Lease { resource } => format!("lease {resource}"),
            Self::Timeout => "timeout".to_owned(),
            Self::Compensation { subject } => format!("compensation {}", subject.as_str()),
            Self::Deadline { deadline } => format!("deadline at {deadline:?}"),
        }
    }

    const fn is_compensation(&self) -> bool {
        matches!(self, Self::Compensation { .. })
    }
}

/// One concrete workflow obligation tracked against the global obligation ledger.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowObligationHandle {
    /// Semantic role of the live obligation.
    pub role: WorkflowObligationRole,
    /// Obligation id recorded in the global ledger.
    pub obligation_id: ObligationId,
    /// Human-readable description carried into diagnostics.
    pub description: String,
    /// Allocation timestamp for replay and evidence.
    pub allocated_at: Time,
    #[serde(skip, default)]
    token: Option<ObligationToken>,
}

impl WorkflowObligationHandle {
    #[track_caller]
    fn allocate(
        ledger: &mut ObligationLedger,
        role: WorkflowObligationRole,
        description: String,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> Result<Self, WorkflowStateError> {
        role.validate()?;
        validate_workflow_text("workflow_obligation.description", &description)?;

        let token = ledger.acquire_with_context(
            role.obligation_kind(),
            holder,
            region,
            now,
            SourceLocation::from_panic_location(Location::caller()),
            None,
            Some(description.clone()),
        );

        Ok(Self {
            role,
            obligation_id: token.id(),
            description,
            allocated_at: now,
            token: Some(token),
        })
    }

    /// Return the current ledger state for this workflow obligation.
    pub fn state(&self, ledger: &ObligationLedger) -> Result<ObligationState, WorkflowStateError> {
        ledger
            .get(self.obligation_id)
            .map(|record| record.state)
            .ok_or(WorkflowStateError::UnknownObligation {
                obligation_id: self.obligation_id,
            })
    }

    /// Return whether the obligation is still owed.
    pub fn is_owed(&self, ledger: &ObligationLedger) -> Result<bool, WorkflowStateError> {
        Ok(self.state(ledger)? == ObligationState::Reserved)
    }

    fn commit(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
    ) -> Result<(), WorkflowStateError> {
        if let Some(token) = self.token.take() {
            ledger.commit(token, now);
            return Ok(());
        }

        let state = ledger
            .get(self.obligation_id)
            .map(|record| record.state)
            .ok_or(WorkflowStateError::UnknownObligation {
                obligation_id: self.obligation_id,
            })?;
        if state == ObligationState::Reserved {
            return Err(WorkflowStateError::MissingLiveToken {
                obligation_id: self.obligation_id,
            });
        }
        Err(WorkflowStateError::ObligationAlreadyResolved {
            obligation_id: self.obligation_id,
            state,
        })
    }

    fn abort(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
        reason: ObligationAbortReason,
    ) -> Result<(), WorkflowStateError> {
        if let Some(token) = self.token.take() {
            ledger.abort(token, now, reason);
            return Ok(());
        }

        let state = ledger
            .get(self.obligation_id)
            .map(|record| record.state)
            .ok_or(WorkflowStateError::UnknownObligation {
                obligation_id: self.obligation_id,
            })?;
        if state == ObligationState::Reserved {
            ledger.abort_by_id(self.obligation_id, now, reason);
            return Ok(());
        }
        Err(WorkflowStateError::ObligationAlreadyResolved {
            obligation_id: self.obligation_id,
            state,
        })
    }
}

/// One still-owed unit of work in a workflow or saga.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowOwedObligation {
    /// Step that still owes this work.
    pub step_id: String,
    /// Subject transition associated with the step.
    pub subject: Subject,
    /// Semantic role of the still-owed work.
    pub role: WorkflowObligationRole,
    /// Ledger obligation id holding the work open.
    pub obligation_id: ObligationId,
    /// Human-readable diagnostic description.
    pub description: String,
    /// Current ledger state, which will be `reserved` for still-owed work.
    pub state: ObligationState,
}

/// Lifecycle state of a workflow step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkflowStepStatus {
    /// Step has been declared but not started.
    Pending,
    /// Step is currently executing.
    Active,
    /// Step finished without outstanding work.
    Completed,
    /// Step failed without entering compensation.
    Failed {
        /// Failure recorded for the step.
        failure: ServiceFailure,
    },
    /// Step failed and compensation is now owed.
    Compensating {
        /// Failure that activated compensation.
        failure: ServiceFailure,
    },
    /// Compensation finished for the failed step.
    Compensated {
        /// Failure that was compensated.
        failure: ServiceFailure,
    },
}

impl WorkflowStepStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Failed { .. } => "failed",
            Self::Compensating { .. } => "compensating",
            Self::Compensated { .. } => "compensated",
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed { .. } | Self::Compensated { .. }
        )
    }
}

/// Durable workflow step bound to a subject transition and explicit obligations.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Stable step identifier inside the saga.
    pub step_id: String,
    /// Subject transition executed by the step.
    pub subject: Subject,
    /// Live and historical obligations allocated for the step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<WorkflowObligationHandle>,
    /// Ordered compensation path to activate on failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compensation_path: Vec<Subject>,
    /// Optional timeout budget attached to the step.
    pub timeout: Option<Duration>,
    /// Current workflow status.
    pub status: WorkflowStepStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    declared_obligations: Vec<WorkflowObligationRole>,
}

impl WorkflowStep {
    /// Construct a durable workflow step declaration.
    pub fn new(
        step_id: impl Into<String>,
        subject: Subject,
        obligations: Vec<WorkflowObligationRole>,
        compensation_path: Vec<Subject>,
        timeout: Option<Duration>,
    ) -> Result<Self, WorkflowStateError> {
        let step_id = step_id.into();
        validate_workflow_text("workflow_step.step_id", &step_id)?;
        if timeout.is_some_and(|value| value.is_zero()) {
            return Err(WorkflowStateError::ZeroDuration {
                field: "workflow_step.timeout",
            });
        }
        for obligation in &obligations {
            obligation.validate()?;
        }

        Ok(Self {
            step_id,
            subject,
            obligations: Vec::new(),
            compensation_path,
            timeout,
            status: WorkflowStepStatus::Pending,
            declared_obligations: obligations,
        })
    }

    fn outstanding_ids(
        &self,
        ledger: &ObligationLedger,
    ) -> Result<Vec<ObligationId>, WorkflowStateError> {
        let mut ids = Vec::new();
        for obligation in &self.obligations {
            if obligation.is_owed(ledger)? {
                ids.push(obligation.obligation_id);
            }
        }
        Ok(ids)
    }

    fn ensure_status(
        &self,
        expected: WorkflowStepStatus,
        operation: &'static str,
    ) -> Result<(), WorkflowStateError> {
        if self.status != expected {
            return Err(WorkflowStateError::InvalidStepTransition {
                step_id: self.step_id.clone(),
                operation,
                status: self.status.as_str(),
            });
        }
        Ok(())
    }

    /// Start the step and allocate its declared obligations into the ledger.
    #[track_caller]
    pub fn start(
        &mut self,
        ledger: &mut ObligationLedger,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> Result<(), WorkflowStateError> {
        self.ensure_status(WorkflowStepStatus::Pending, "start")?;
        for role in self.declared_obligations.iter().cloned() {
            let description = format!(
                "workflow step {} on {} owes {}",
                self.step_id,
                self.subject.as_str(),
                role.label()
            );
            self.obligations.push(WorkflowObligationHandle::allocate(
                ledger,
                role,
                description,
                holder,
                region,
                now,
            )?);
        }
        self.status = WorkflowStepStatus::Active;
        Ok(())
    }

    /// Commit every still-owed non-compensation obligation for a successful step.
    pub fn complete(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
    ) -> Result<(), WorkflowStateError> {
        self.ensure_status(WorkflowStepStatus::Active, "complete")?;
        for obligation in &mut self.obligations {
            if obligation.role.is_compensation() || !obligation.is_owed(ledger)? {
                continue;
            }
            obligation.commit(ledger, now)?;
        }
        self.status = WorkflowStepStatus::Completed;
        Ok(())
    }

    /// Fail the step, abort current obligations, and activate compensation if configured.
    #[track_caller]
    pub fn fail(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
        failure: ServiceFailure,
        holder: TaskId,
        region: RegionId,
    ) -> Result<(), WorkflowStateError> {
        self.ensure_status(WorkflowStepStatus::Active, "fail")?;
        for obligation in &mut self.obligations {
            if obligation.role.is_compensation() || !obligation.is_owed(ledger)? {
                continue;
            }
            obligation.abort(ledger, now, failure.abort_reason())?;
        }

        if self.compensation_path.is_empty() {
            self.status = WorkflowStepStatus::Failed { failure };
            return Ok(());
        }

        for subject in self.compensation_path.iter().cloned() {
            let role = WorkflowObligationRole::Compensation { subject };
            let description = format!(
                "workflow step {} compensation for {} via {}",
                self.step_id,
                self.subject.as_str(),
                role.label()
            );
            self.obligations.push(WorkflowObligationHandle::allocate(
                ledger,
                role,
                description,
                holder,
                region,
                now,
            )?);
        }
        self.status = WorkflowStepStatus::Compensating { failure };
        Ok(())
    }

    /// Commit every still-owed compensation obligation for the step.
    pub fn complete_compensation(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
    ) -> Result<(), WorkflowStateError> {
        let WorkflowStepStatus::Compensating { failure } = self.status else {
            return Err(WorkflowStateError::InvalidStepTransition {
                step_id: self.step_id.clone(),
                operation: "complete compensation for",
                status: self.status.as_str(),
            });
        };

        for obligation in &mut self.obligations {
            if !obligation.role.is_compensation() || !obligation.is_owed(ledger)? {
                continue;
            }
            obligation.commit(ledger, now)?;
        }
        self.status = WorkflowStepStatus::Compensated { failure };
        Ok(())
    }

    /// Query the step for every obligation that is still directly owed.
    pub fn what_is_still_owed(
        &self,
        ledger: &ObligationLedger,
    ) -> Result<Vec<WorkflowOwedObligation>, WorkflowStateError> {
        let mut owed = Vec::new();
        for obligation in &self.obligations {
            let state = obligation.state(ledger)?;
            if state == ObligationState::Reserved {
                owed.push(WorkflowOwedObligation {
                    step_id: self.step_id.clone(),
                    subject: self.subject.clone(),
                    role: obligation.role.clone(),
                    obligation_id: obligation.obligation_id,
                    description: obligation.description.clone(),
                    state,
                });
            }
        }
        Ok(owed)
    }
}

/// Evidence event emitted while a saga advances or recovers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SagaEvidenceEvent {
    /// A step was started and its obligations entered the ledger.
    Started,
    /// A step completed successfully.
    StepCompleted,
    /// A step failed with a typed service failure.
    StepFailed {
        /// Failure recorded for the step.
        failure: ServiceFailure,
    },
    /// Compensation obligations were activated.
    CompensationActivated,
    /// Compensation completed successfully.
    CompensationCompleted,
    /// A serialized saga snapshot was recovered and reconciled with the ledger.
    Recovered,
}

/// Evidence record carried in the durable saga trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaEvidenceRecord {
    /// Timestamp when the evidence record was written.
    pub recorded_at: Time,
    /// Step that emitted the record, when applicable.
    pub step_id: Option<String>,
    /// Subject associated with the record, when applicable.
    pub subject: Option<Subject>,
    /// Event that occurred.
    pub event: SagaEvidenceEvent,
    /// Outstanding obligation ids visible at this point in the execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outstanding_obligations: Vec<ObligationId>,
}

/// Durable multi-step saga state built from subject-native workflow steps.
#[derive(Debug, Serialize, Deserialize)]
pub struct SagaState {
    /// Stable saga identifier.
    pub saga_id: String,
    /// Ordered workflow steps.
    pub steps: Vec<WorkflowStep>,
    /// Current step index, if any.
    pub current_step: Option<usize>,
    /// Steps that finished compensation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compensated_steps: Vec<String>,
    /// Replayable evidence trail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_trail: Vec<SagaEvidenceRecord>,
}

impl SagaState {
    /// Construct a new saga from ordered workflow steps.
    pub fn new(
        saga_id: impl Into<String>,
        steps: Vec<WorkflowStep>,
    ) -> Result<Self, WorkflowStateError> {
        let saga_id = saga_id.into();
        validate_workflow_text("saga_state.saga_id", &saga_id)?;
        if steps.is_empty() {
            return Err(WorkflowStateError::EmptySaga { saga_id });
        }
        Ok(Self {
            saga_id,
            steps,
            current_step: None,
            compensated_steps: Vec::new(),
            evidence_trail: Vec::new(),
        })
    }

    fn first_non_terminal_step(&self) -> Option<usize> {
        self.steps
            .iter()
            .position(|step| !step.status.is_terminal())
    }

    fn current_index(&self) -> Result<usize, WorkflowStateError> {
        let index = self
            .current_step
            .ok_or_else(|| WorkflowStateError::NoRunnableStep {
                saga_id: self.saga_id.clone(),
            })?;
        if index >= self.steps.len() {
            return Err(WorkflowStateError::InvalidCurrentStep {
                saga_id: self.saga_id.clone(),
                current_step: index,
                len: self.steps.len(),
            });
        }
        Ok(index)
    }

    fn push_evidence(
        &mut self,
        step_index: Option<usize>,
        recorded_at: Time,
        event: SagaEvidenceEvent,
        outstanding_obligations: Vec<ObligationId>,
    ) {
        let (step_id, subject) = step_index
            .and_then(|index| self.steps.get(index))
            .map_or((None, None), |step| {
                (Some(step.step_id.clone()), Some(step.subject.clone()))
            });

        self.evidence_trail.push(SagaEvidenceRecord {
            recorded_at,
            step_id,
            subject,
            event,
            outstanding_obligations,
        });
    }

    /// Start the next pending step and allocate its obligations into the ledger.
    #[track_caller]
    pub fn start_next_step(
        &mut self,
        ledger: &mut ObligationLedger,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> Result<(), WorkflowStateError> {
        let index = match self.current_step {
            Some(index) if index < self.steps.len() => match self.steps[index].status {
                WorkflowStepStatus::Pending => index,
                WorkflowStepStatus::Active | WorkflowStepStatus::Compensating { .. } => {
                    return Ok(());
                }
                WorkflowStepStatus::Completed
                | WorkflowStepStatus::Failed { .. }
                | WorkflowStepStatus::Compensated { .. } => self
                    .steps
                    .iter()
                    .position(|step| matches!(step.status, WorkflowStepStatus::Pending))
                    .ok_or_else(|| WorkflowStateError::NoRunnableStep {
                        saga_id: self.saga_id.clone(),
                    })?,
            },
            Some(index) => {
                return Err(WorkflowStateError::InvalidCurrentStep {
                    saga_id: self.saga_id.clone(),
                    current_step: index,
                    len: self.steps.len(),
                });
            }
            None => self
                .steps
                .iter()
                .position(|step| matches!(step.status, WorkflowStepStatus::Pending))
                .ok_or_else(|| WorkflowStateError::NoRunnableStep {
                    saga_id: self.saga_id.clone(),
                })?,
        };

        self.steps[index].start(ledger, holder, region, now)?;
        self.current_step = Some(index);
        let outstanding = self.steps[index].outstanding_ids(ledger)?;
        self.push_evidence(Some(index), now, SagaEvidenceEvent::Started, outstanding);
        Ok(())
    }

    /// Complete the current active step and advance the cursor to the next one.
    pub fn complete_current_step(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
    ) -> Result<(), WorkflowStateError> {
        let index = self.current_index()?;
        self.steps[index].complete(ledger, now)?;
        let outstanding = self.steps[index].outstanding_ids(ledger)?;
        self.push_evidence(
            Some(index),
            now,
            SagaEvidenceEvent::StepCompleted,
            outstanding,
        );
        self.current_step = self
            .steps
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, step)| !step.status.is_terminal())
            .map(|(next, _)| next);
        Ok(())
    }

    /// Fail the current step, preserving no-orphan semantics by activating explicit compensation work.
    #[track_caller]
    pub fn fail_current_step(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
        failure: ServiceFailure,
        holder: TaskId,
        region: RegionId,
    ) -> Result<(), WorkflowStateError> {
        let index = self.current_index()?;
        self.steps[index].fail(ledger, now, failure, holder, region)?;
        let outstanding = self.steps[index].outstanding_ids(ledger)?;
        self.push_evidence(
            Some(index),
            now,
            SagaEvidenceEvent::StepFailed { failure },
            outstanding.clone(),
        );
        if matches!(
            self.steps[index].status,
            WorkflowStepStatus::Compensating { .. }
        ) {
            self.push_evidence(
                Some(index),
                now,
                SagaEvidenceEvent::CompensationActivated,
                outstanding,
            );
        }
        Ok(())
    }

    /// Complete compensation for the current step.
    pub fn complete_current_compensation(
        &mut self,
        ledger: &mut ObligationLedger,
        now: Time,
    ) -> Result<(), WorkflowStateError> {
        let index = self.current_index()?;
        self.steps[index].complete_compensation(ledger, now)?;
        if !self
            .compensated_steps
            .iter()
            .any(|step_id| step_id == &self.steps[index].step_id)
        {
            self.compensated_steps
                .push(self.steps[index].step_id.clone());
        }
        let outstanding = self.steps[index].outstanding_ids(ledger)?;
        self.push_evidence(
            Some(index),
            now,
            SagaEvidenceEvent::CompensationCompleted,
            outstanding,
        );
        self.current_step = self.first_non_terminal_step();
        Ok(())
    }

    /// Query every still-owed obligation directly from the global ledger.
    pub fn what_is_still_owed(
        &self,
        ledger: &ObligationLedger,
    ) -> Result<Vec<WorkflowOwedObligation>, WorkflowStateError> {
        let mut owed = Vec::new();
        for step in &self.steps {
            owed.extend(step.what_is_still_owed(ledger)?);
        }
        Ok(owed)
    }

    /// Reconcile a deserialized saga snapshot with the current obligation ledger.
    pub fn recover_from_replay(
        mut self,
        ledger: &ObligationLedger,
        recovered_at: Time,
    ) -> Result<Self, WorkflowStateError> {
        for step in &self.steps {
            for obligation in &step.obligations {
                obligation.state(ledger)?;
            }
        }

        self.current_step = match self.current_step {
            Some(index) if index < self.steps.len() && !self.steps[index].status.is_terminal() => {
                Some(index)
            }
            Some(index) if index >= self.steps.len() => {
                return Err(WorkflowStateError::InvalidCurrentStep {
                    saga_id: self.saga_id.clone(),
                    current_step: index,
                    len: self.steps.len(),
                });
            }
            _ => self.first_non_terminal_step(),
        };

        let outstanding = self
            .what_is_still_owed(ledger)?
            .into_iter()
            .map(|owed| owed.obligation_id)
            .collect::<Vec<_>>();
        self.push_evidence(
            self.current_step,
            recovered_at,
            SagaEvidenceEvent::Recovered,
            outstanding,
        );
        Ok(self)
    }
}

/// Validation failure for FABRIC service contracts and caller requests.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceContractError {
    /// Service name must not be empty.
    #[error("service name must not be empty")]
    EmptyServiceName,
    /// Named schema references must be non-empty.
    #[error("named schema at `{field}` must not be empty")]
    EmptyNamedSchema {
        /// Field that declared an empty schema name.
        field: String,
    },
    /// Bounded-region mobility constraints require a non-empty region label.
    #[error("bounded-region mobility constraint at `{field}` must declare a region label")]
    EmptyBoundedRegion {
        /// Field that declared an empty region label.
        field: String,
    },
    /// Duration-valued fields must be non-zero when present.
    #[error("duration at `{field}` must be greater than zero")]
    ZeroDuration {
        /// Field that contained a zero duration.
        field: String,
    },
    /// Queue-based overload policies require positive capacity.
    #[error("queue-within-budget overload policy must declare max_pending > 0")]
    InvalidQueueCapacity,
    /// Provider durability guarantee is weaker than the contract floor.
    #[error(
        "provider guaranteed durability {guaranteed_durability} is weaker than contract floor {required_durability}"
    )]
    ProviderGuaranteeBelowContractFloor {
        /// Provider-declared durability guarantee.
        guaranteed_durability: DeliveryClass,
        /// Minimum durability required by the contract.
        required_durability: DeliveryClass,
    },
    /// Provider compensation guarantee is weaker than the contract requirement.
    #[error("provider compensation `{provider}` is weaker than contract requirement `{required}`")]
    ProviderCompensationBelowContract {
        /// Provider-declared compensation policy.
        provider: CompensationSemantics,
        /// Contract-required compensation policy.
        required: CompensationSemantics,
    },
    /// Provider evidence guarantee is weaker than the contract requirement.
    #[error(
        "provider evidence level `{provider}` is weaker than contract requirement `{required}`"
    )]
    ProviderEvidenceBelowContract {
        /// Provider-declared evidence level.
        provider: EvidenceLevel,
        /// Contract-required evidence level.
        required: EvidenceLevel,
    },
    /// Provider mobility guarantee is incompatible with the contract.
    #[error("provider mobility `{provider}` does not satisfy contract requirement `{required}`")]
    ProviderMobilityIncompatible {
        /// Provider-declared mobility boundary.
        provider: MobilityConstraint,
        /// Contract-required mobility boundary.
        required: MobilityConstraint,
    },
    /// Provider admitted a class weaker than the contract floor.
    #[error("provider admitted delivery class {class} below contract floor {required_durability}")]
    ProviderClassBelowContractFloor {
        /// Admitted delivery class.
        class: DeliveryClass,
        /// Contract floor for the service.
        required_durability: DeliveryClass,
    },
    /// Provider admitted a class it cannot guarantee durably.
    #[error(
        "provider admitted delivery class {class} above guaranteed durability {guaranteed_durability}"
    )]
    ProviderClassAboveGuaranteedDurability {
        /// Admitted delivery class.
        class: DeliveryClass,
        /// Strongest provider-guaranteed class.
        guaranteed_durability: DeliveryClass,
    },
    /// Caller tried to override timeout when the contract forbids it.
    #[error("caller timeout overrides are not allowed by the contract budget semantics")]
    TimeoutOverrideNotAllowed,
    /// Caller tried to pass a priority hint when the contract ignores hints.
    #[error("caller priority hints are not allowed by the contract budget semantics")]
    PriorityHintsNotAllowed,
    /// Delivery-class selection failed against the provider policy.
    #[error(transparent)]
    DeliveryClassPolicy(#[from] DeliveryClassPolicyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::ir::ReplySpaceRule;
    use crate::messaging::morphism::{
        FabricCapability, MorphismClass, MorphismPlanDirection, ResponsePolicy,
        ReversibilityRequirement, SharingPolicy, SubjectTransform,
    };
    use crate::messaging::subject::SubjectPattern;
    use crate::record::{ObligationAbortReason, ObligationState};
    use crate::util::ArenaIndex;

    fn provider_terms() -> ProviderTerms {
        ProviderTerms {
            admissible_classes: DeliveryClassPolicy::new(
                DeliveryClass::ObligationBacked,
                [DeliveryClass::ObligationBacked, DeliveryClass::MobilitySafe],
            )
            .expect("provider policy"),
            guaranteed_durability: DeliveryClass::MobilitySafe,
            compensation_policy: CompensationSemantics::BestEffort,
            mobility_constraint: MobilityConstraint::Pinned,
            evidence_level: EvidenceLevel::Detailed,
        }
    }

    fn provider_terms_with_mobility(mobility_constraint: MobilityConstraint) -> ProviderTerms {
        ProviderTerms {
            mobility_constraint,
            ..provider_terms()
        }
    }

    fn contract() -> ServiceContractSchema {
        ServiceContractSchema {
            budget_semantics: BudgetSemantics {
                honor_priority_hints: true,
                ..BudgetSemantics::default()
            },
            compensation_semantics: CompensationSemantics::BestEffort,
            mobility_constraints: MobilityConstraint::Unrestricted,
            evidence_requirements: EvidenceLevel::Standard,
            ..ServiceContractSchema::default()
        }
    }

    fn namespace() -> NamespaceKernel {
        NamespaceKernel::new("acme", "orders").expect("namespace kernel")
    }

    fn service_subject() -> Subject {
        Subject::new("tenant.acme.service.orders.lookup")
    }

    fn service_boundary() -> FabricServiceBoundary {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");
        FabricServiceBoundary::new(namespace(), service_subject(), registration)
            .expect("valid service boundary")
    }

    fn transferable_service_boundary() -> FabricServiceBoundary {
        let registration = ServiceRegistration::new(
            "fabric.echo",
            contract(),
            provider_terms_with_mobility(MobilityConstraint::Unrestricted),
        )
        .expect("valid");
        FabricServiceBoundary::new(namespace(), service_subject(), registration)
            .expect("valid service boundary")
    }

    fn authoritative_import_morphism() -> Morphism {
        Morphism {
            source_language: SubjectPattern::new("tenant.acme.service.orders.lookup"),
            dest_language: SubjectPattern::new("tenant.acme.service.edge-orders.lookup"),
            class: MorphismClass::Authoritative,
            transform: SubjectTransform::RenamePrefix {
                from: SubjectPattern::new("tenant.acme.service.orders.lookup"),
                to: SubjectPattern::new("tenant.acme.service.edge-orders.lookup"),
            },
            reversibility: ReversibilityRequirement::Bijective,
            capability_requirements: vec![
                FabricCapability::CarryAuthority,
                FabricCapability::ReplyAuthority,
            ],
            sharing_policy: SharingPolicy::TenantScoped,
            response_policy: ResponsePolicy::ReplyAuthoritative,
            ..Morphism::default()
        }
    }

    fn make_task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(11, 0))
    }

    fn make_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(7, 0))
    }

    fn workflow_step(
        step_id: &str,
        subject: &str,
        obligations: Vec<WorkflowObligationRole>,
        compensation_path: &[&str],
    ) -> WorkflowStep {
        WorkflowStep::new(
            step_id,
            Subject::new(subject),
            obligations,
            compensation_path
                .iter()
                .map(|subject| Subject::new(*subject))
                .collect(),
            Some(Duration::from_secs(5)),
        )
        .expect("valid workflow step")
    }

    #[test]
    fn service_registration_accepts_valid_contract() {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");

        assert_eq!(registration.service_name, "fabric.echo");
        assert_eq!(
            registration.provider_terms.guaranteed_durability,
            DeliveryClass::MobilitySafe
        );
    }

    #[test]
    fn service_boundary_binds_request_and_control_subjects() {
        let boundary = service_boundary();
        let subjects = boundary.control_subjects().expect("subjects");

        assert_eq!(
            boundary.request_subject().as_str(),
            "tenant.acme.service.orders.lookup"
        );
        assert_eq!(
            subjects.discovery.as_str(),
            "tenant.acme.service.orders.discover"
        );
        assert_eq!(
            subjects.health.as_str(),
            "$SYS.FABRIC.HEALTH.TENANT.acme.SERVICE.orders.status"
        );
        assert_eq!(
            subjects.advisories.as_str(),
            "$SYS.FABRIC.ROUTE.TENANT.acme.SERVICE.orders.advisory"
        );
    }

    #[test]
    fn service_boundary_registers_namespace_control_handlers() {
        let boundary = service_boundary();
        let subjects = boundary.control_subjects().expect("subjects");
        let mut registry = ControlRegistry::new();

        let handlers = boundary
            .register_control_handlers(&mut registry)
            .expect("register handlers");

        let health_matches = registry.matching_handlers(&subjects.health);
        assert_eq!(health_matches.len(), 1);
        assert_eq!(health_matches[0].id, handlers.health);

        let advisory_matches = registry.matching_handlers(&subjects.advisories);
        assert_eq!(advisory_matches.len(), 1);
        assert_eq!(advisory_matches[0].id, handlers.advisories);
    }

    #[test]
    fn service_boundary_admission_issues_request_certificate() {
        let boundary = service_boundary();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            timeout_override: Some(Duration::from_secs(5)),
            priority_hint: Some(200),
        };

        let admission = boundary
            .admit_request(
                "req-service-boundary",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                0xfeed_u64,
                Time::from_nanos(10),
            )
            .expect("admit request");

        assert_eq!(
            admission.validated.delivery_class,
            DeliveryClass::MobilitySafe
        );
        assert_eq!(
            admission.certificate.subject,
            "tenant.acme.service.orders.lookup"
        );
        assert_eq!(admission.certificate.service_class, "fabric.echo");
        assert_eq!(
            admission.certificate.reply_space_rule,
            ReplySpaceRule::CallerInbox
        );
    }

    #[test]
    fn service_boundary_transfer_compiles_import_plan_and_updates_obligation() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                99,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let plan = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                "orders-edge",
                Subject::new("tenant.acme.service.edge-orders.lookup"),
                "import/orders->edge",
                &authoritative_import_morphism(),
                Some(ReplySpaceRule::DedicatedPrefix {
                    prefix: "tenant.acme.service.edge-orders.lookup".to_owned(),
                }),
                Time::from_nanos(3),
            )
            .expect("transfer through import plan");

        assert_eq!(obligation.subject, "tenant.acme.service.edge-orders.lookup");
        assert_eq!(obligation.callee, "orders-edge");
        assert_eq!(obligation.lineage.len(), 1);
        assert_eq!(obligation.lineage[0].morphism, "import/orders->edge");
        assert_eq!(plan.direction, MorphismPlanDirection::Import);
        assert_eq!(
            plan.selected_reply_space,
            Some(ReplySpaceRule::DedicatedPrefix {
                prefix: "tenant.acme.service.edge-orders.lookup".to_owned(),
            })
        );
    }

    #[test]
    fn service_boundary_rejects_import_morphism_outside_request_subject() {
        let boundary = service_boundary();
        let morphism = Morphism {
            source_language: SubjectPattern::new("tenant.acme.service.inventory.lookup"),
            ..authoritative_import_morphism()
        };

        let error = boundary
            .compile_import_plan(&morphism, None)
            .expect_err("morphism should not cover this boundary");

        assert_eq!(
            error,
            ServiceBoundaryError::MorphismDoesNotCoverBoundary {
                subject: "tenant.acme.service.orders.lookup".to_owned(),
                source_language: "tenant.acme.service.inventory.lookup".to_owned(),
            }
        );
    }

    #[test]
    fn service_boundary_transfer_rejects_non_unrestricted_mobility() {
        let boundary = service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-pinned",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                11,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-pinned",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                "orders-edge",
                Subject::new("tenant.acme.service.edge-orders.lookup"),
                "import/orders->edge",
                &authoritative_import_morphism(),
                None,
                Time::from_nanos(3),
            )
            .expect_err("pinned mobility should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::TransferRequiresUnrestrictedMobility {
                constraint: MobilityConstraint::Pinned,
                target_subject: "tenant.acme.service.edge-orders.lookup".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_target_outside_destination_language() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-miss",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                12,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-miss",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                "orders-edge",
                Subject::new("tenant.acme.service.wrong.lookup"),
                "import/orders->edge",
                &authoritative_import_morphism(),
                None,
                Time::from_nanos(3),
            )
            .expect_err("target outside morphism destination should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::TargetOutsideMorphismDestination {
                subject: "tenant.acme.service.wrong.lookup".to_owned(),
                dest_language: "tenant.acme.service.edge-orders.lookup".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_admission_request_mismatch() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-a",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                13,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-b",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                "orders-edge",
                Subject::new("tenant.acme.service.edge-orders.lookup"),
                "import/orders->edge",
                &authoritative_import_morphism(),
                None,
                Time::from_nanos(3),
            )
            .expect_err("mismatched admission should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::AdmissionRequestMismatch {
                admission_request_id: "req-transfer-a".to_owned(),
                obligation_request_id: "req-transfer-b".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
        assert_eq!(obligation.subject, boundary.request_subject().as_str());
    }

    #[test]
    fn service_boundary_transfer_rejects_obligation_outside_boundary_subject() {
        let boundary = transferable_service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-transfer-shifted",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                14,
                Time::from_nanos(1),
            )
            .expect("admission");
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-shifted",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");
        obligation.subject = "tenant.acme.service.edge-orders.lookup".to_owned();

        let error = boundary
            .transfer_request_via_import(
                &admission,
                &mut obligation,
                "orders-edge",
                Subject::new("tenant.acme.service.edge-orders.lookup"),
                "import/orders->edge",
                &authoritative_import_morphism(),
                None,
                Time::from_nanos(3),
            )
            .expect_err("obligation outside boundary should fail closed");

        assert_eq!(
            error,
            ServiceBoundaryError::ObligationOutsideBoundary {
                subject: "tenant.acme.service.edge-orders.lookup".to_owned(),
                boundary_subject: "tenant.acme.service.orders.lookup".to_owned(),
            }
        );
        assert!(obligation.lineage.is_empty());
    }

    #[test]
    fn service_boundary_cancellation_propagates_to_service_obligation_abort() {
        let boundary = service_boundary();
        let mut ledger = ObligationLedger::new();
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::ObligationBacked),
            ..CallerOptions::default()
        };
        let admission = boundary
            .admit_request(
                "req-cancel",
                "caller-a",
                &caller,
                ReplySpaceRule::CallerInbox,
                42,
                Time::from_nanos(1),
            )
            .expect("admission");
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-cancel",
            "caller-a",
            "orders-origin",
            boundary.request_subject().as_str(),
            admission.validated.delivery_class,
            make_task(),
            make_region(),
            Time::from_nanos(2),
            admission.validated.timeout,
        )
        .expect("allocate obligation");
        let obligation_id = obligation.obligation_id().expect("tracked obligation");

        let aborted = boundary
            .cancel_request(obligation, &mut ledger, Time::from_nanos(3))
            .expect("cancel request");

        assert_eq!(aborted.failure, ServiceFailure::Cancelled);
        assert_eq!(aborted.obligation_id, Some(obligation_id));
        assert_eq!(ledger.pending_count(), 0);
        let record = ledger.get(obligation_id).expect("ledger record");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Cancel));
    }

    #[test]
    fn service_registration_rejects_provider_terms_below_contract() {
        let provider_terms = ProviderTerms {
            guaranteed_durability: DeliveryClass::DurableOrdered,
            ..provider_terms()
        };

        let err = ServiceRegistration::new("fabric.echo", contract(), provider_terms)
            .expect_err("durability floor should be enforced");

        assert_eq!(
            err,
            ServiceContractError::ProviderGuaranteeBelowContractFloor {
                guaranteed_durability: DeliveryClass::DurableOrdered,
                required_durability: DeliveryClass::ObligationBacked,
            }
        );
    }

    #[test]
    fn validate_caller_accepts_in_bounds_request() {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::MobilitySafe),
            timeout_override: Some(Duration::from_secs(5)),
            priority_hint: Some(200),
        };

        let validated = registration
            .validate_caller(&caller)
            .expect("caller request should be valid");

        assert_eq!(validated.delivery_class, DeliveryClass::MobilitySafe);
        assert_eq!(validated.timeout, Some(Duration::from_secs(5)));
        assert_eq!(validated.priority_hint, Some(200));
        assert_eq!(validated.mobility_constraint, MobilityConstraint::Pinned);
    }

    #[test]
    fn validate_caller_rejects_out_of_bounds_delivery_class() {
        let registration =
            ServiceRegistration::new("fabric.echo", contract(), provider_terms()).expect("valid");
        let caller = CallerOptions {
            requested_class: Some(DeliveryClass::ForensicReplayable),
            ..CallerOptions::default()
        };

        let err = registration
            .validate_caller(&caller)
            .expect_err("caller class should be rejected");

        assert_eq!(
            err,
            ServiceContractError::DeliveryClassPolicy(
                DeliveryClassPolicyError::RequestedClassNotAdmissible {
                    requested: DeliveryClass::ForensicReplayable,
                    default_class: DeliveryClass::ObligationBacked,
                }
            )
        );
    }

    #[test]
    fn validate_caller_rejects_timeout_override_when_disabled() {
        let mut contract = contract();
        contract.budget_semantics.allow_timeout_override = false;
        let registration =
            ServiceRegistration::new("fabric.echo", contract, provider_terms()).expect("valid");
        let caller = CallerOptions {
            timeout_override: Some(Duration::from_secs(1)),
            ..CallerOptions::default()
        };

        let err = registration
            .validate_caller(&caller)
            .expect_err("timeout override should be rejected");

        assert_eq!(err, ServiceContractError::TimeoutOverrideNotAllowed);
    }

    #[test]
    fn ephemeral_request_reply_stays_untracked() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-ephemeral",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::EphemeralInteractive,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("ephemeral path should be valid");

        assert!(!obligation.is_tracked());
        assert_eq!(ledger.pending_count(), 0);

        let reply = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"ok".to_vec(),
                AckKind::Accepted,
                false,
            )
            .expect("cheap path commit should succeed");

        assert_eq!(reply.service_obligation_id, None);
        assert!(reply.reply_obligation.is_none());
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn obligation_backed_request_commits_and_creates_reply_obligation() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-1",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(10),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let service_id = obligation.obligation_id().expect("tracked obligation id");
        assert_eq!(ledger.pending_count(), 1);

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(20),
                b"payload".to_vec(),
                AckKind::Received,
                true,
            )
            .expect("tracked commit should succeed");

        assert_eq!(committed.service_obligation_id, Some(service_id));
        assert_eq!(committed.payload, b"payload".to_vec());
        let reply = committed
            .reply_obligation
            .expect("reply obligation expected");
        let reply_id = reply.obligation_id();
        assert_eq!(reply.service_obligation_id, service_id);
        assert_eq!(ledger.pending_count(), 1);

        let delivery = reply.commit_delivery(&mut ledger, Time::from_nanos(30));
        assert_eq!(delivery.obligation_id, reply_id);
        assert_eq!(delivery.service_obligation_id, service_id);
        assert_eq!(delivery.delivery_boundary, AckKind::Received);
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn service_obligation_abort_records_typed_failure() {
        let mut ledger = ObligationLedger::new();
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-2",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(5),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let aborted = obligation
            .abort(
                &mut ledger,
                Time::from_nanos(15),
                ServiceFailure::ApplicationError,
            )
            .expect("abort should succeed");

        assert_eq!(aborted.obligation_id, Some(obligation_id));
        assert_eq!(aborted.failure, ServiceFailure::ApplicationError);
        assert_eq!(ledger.pending_count(), 0);
        let record = ledger.get(obligation_id).expect("ledger record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Error));
    }

    #[test]
    fn service_obligation_transfer_preserves_identity_and_lineage() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-3",
            "caller",
            "callee-a",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        obligation
            .transfer(
                "callee-b",
                "svc.echo.imported",
                "import/orders->edge",
                Time::from_nanos(2),
            )
            .expect("transfer should succeed");

        assert_eq!(obligation.obligation_id(), Some(obligation_id));
        assert_eq!(obligation.callee, "callee-b");
        assert_eq!(obligation.subject, "svc.echo.imported");
        assert_eq!(obligation.lineage.len(), 1);
        assert_eq!(obligation.lineage[0].morphism, "import/orders->edge");
    }

    #[test]
    fn invalid_transfer_preserves_tracked_obligation() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-transfer-invalid",
            "caller",
            "callee-a",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let err = obligation
            .transfer(
                "",
                "svc.echo.imported",
                "import/orders->edge",
                Time::from_nanos(2),
            )
            .expect_err("invalid transfer should be rejected");

        assert_eq!(
            err,
            ServiceObligationError::EmptyField {
                field: "transfer.callee",
            }
        );
        assert_eq!(obligation.obligation_id(), Some(obligation_id));
        assert_eq!(ledger.pending_count(), 1);
        obligation
            .abort(
                &mut ledger,
                Time::from_nanos(3),
                ServiceFailure::ApplicationError,
            )
            .expect("abort should succeed");
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn service_obligation_timeout_is_explicit_abort() {
        let mut ledger = ObligationLedger::new();
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-4",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(3),
            Some(Duration::from_secs(1)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let timed_out = obligation
            .timeout(&mut ledger, Time::from_nanos(100))
            .expect("timeout should abort successfully");

        assert_eq!(timed_out.failure, ServiceFailure::TimedOut);
        let record = ledger.get(obligation_id).expect("ledger record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Explicit));
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn resolved_service_obligation_rejects_second_resolution() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-resolved-twice",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect("first resolution should succeed");

        assert!(committed.reply_obligation.is_none());
        assert_eq!(ledger.pending_count(), 0);
        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(3),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect_err("resolved obligation should reject a second commit");

        assert_eq!(
            err,
            ServiceObligationError::AlreadyResolved {
                operation: "commit_with_reply",
            }
        );
    }

    #[test]
    fn resolved_service_obligation_rejects_abort_after_commit() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-resolved-abort",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect("first resolution should succeed");

        let err = obligation
            .abort(
                &mut ledger,
                Time::from_nanos(3),
                ServiceFailure::ApplicationError,
            )
            .expect_err("resolved obligation should reject abort");

        assert_eq!(
            err,
            ServiceObligationError::AlreadyResolved { operation: "abort" }
        );
    }

    #[test]
    fn resolved_service_obligation_rejects_timeout_after_commit() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-resolved-timeout",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                false,
            )
            .expect("first resolution should succeed");

        let err = obligation
            .timeout(&mut ledger, Time::from_nanos(3))
            .expect_err("resolved obligation should reject timeout");

        assert_eq!(
            err,
            ServiceObligationError::AlreadyResolved {
                operation: "timeout",
            }
        );
    }

    #[test]
    fn tracked_reply_boundary_below_minimum_preserves_obligation() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-boundary-floor",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Committed,
                false,
            )
            .expect_err("boundary below durable floor should be rejected");

        assert_eq!(
            err,
            ServiceObligationError::ReplyBoundaryBelowMinimum {
                delivery_class: DeliveryClass::MobilitySafe,
                minimum_boundary: AckKind::Received,
                requested_boundary: AckKind::Committed,
            }
        );
        assert_eq!(obligation.obligation_id(), Some(obligation_id));
        assert_eq!(ledger.pending_count(), 1);
        let aborted = obligation
            .abort(
                &mut ledger,
                Time::from_nanos(3),
                ServiceFailure::ApplicationError,
            )
            .expect("abort should succeed");
        assert_eq!(aborted.obligation_id, Some(obligation_id));
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn receipt_required_reply_must_use_received_boundary() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-receipt-boundary",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::EphemeralInteractive,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("ephemeral request should allocate");

        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Served,
                true,
            )
            .expect_err("receipt-required replies must use the received boundary");

        assert_eq!(
            err,
            ServiceObligationError::ReceiptRequiresReceivedBoundary {
                requested_boundary: AckKind::Served,
            }
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn untracked_delivery_class_rejects_follow_up_reply_tracking() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-untracked-follow-up",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::EphemeralInteractive,
            make_task(),
            make_region(),
            Time::from_nanos(1),
            Some(Duration::from_secs(5)),
        )
        .expect("ephemeral request should allocate");

        let err = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                b"payload".to_vec(),
                AckKind::Received,
                false,
            )
            .expect_err("cheap path should not pretend to support tracked reply delivery");

        assert_eq!(
            err,
            ServiceObligationError::ReplyTrackingUnavailable {
                delivery_class: DeliveryClass::EphemeralInteractive,
                requested_boundary: AckKind::Received,
                receipt_required: false,
            }
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn reply_obligation_abort_records_failure_and_clears_pending() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-reply-abort",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(10),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(20),
                b"payload".to_vec(),
                AckKind::Received,
                true,
            )
            .expect("tracked commit should succeed");

        let reply = committed
            .reply_obligation
            .expect("reply obligation expected");
        let reply_id = reply.obligation_id();
        let aborted = reply.abort_delivery(
            &mut ledger,
            Time::from_nanos(30),
            ServiceFailure::TransportError,
        );

        assert_eq!(aborted.obligation_id, reply_id);
        assert_eq!(aborted.failure, ServiceFailure::TransportError);
        assert_eq!(aborted.delivery_boundary, AckKind::Received);
        let record = ledger.get(reply_id).expect("reply record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Error));
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn reply_obligation_timeout_is_explicit_abort() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-reply-timeout",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::MobilitySafe,
            make_task(),
            make_region(),
            Time::from_nanos(10),
            Some(Duration::from_secs(5)),
        )
        .expect("tracked request should allocate");

        let committed = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(20),
                b"payload".to_vec(),
                AckKind::Received,
                true,
            )
            .expect("tracked commit should succeed");

        let reply = committed
            .reply_obligation
            .expect("reply obligation expected");
        let reply_id = reply.obligation_id();
        let timed_out = reply.timeout(&mut ledger, Time::from_nanos(40));

        assert_eq!(timed_out.obligation_id, reply_id);
        assert_eq!(timed_out.failure, ServiceFailure::TimedOut);
        assert_eq!(timed_out.delivery_boundary, AckKind::Received);
        let record = ledger.get(reply_id).expect("reply record exists");
        assert_eq!(record.state, ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Explicit));
        assert_eq!(ledger.pending_count(), 0);
    }

    // ========================================================================
    // Comprehensive service contract tests (bead 8w83i.10.2)
    // ========================================================================

    // -- PayloadShape validation ---------------------------------------------

    #[test]
    fn payload_shape_named_schema_rejects_empty() {
        let shape = PayloadShape::NamedSchema {
            schema: "  ".to_owned(),
        };
        assert!(shape.validate("test").is_err());
    }

    #[test]
    fn payload_shape_named_schema_accepts_non_empty() {
        let shape = PayloadShape::NamedSchema {
            schema: "orders.v1".to_owned(),
        };
        assert!(shape.validate("test").is_ok());
    }

    #[test]
    fn payload_shape_non_named_variants_validate() {
        for shape in [
            PayloadShape::Empty,
            PayloadShape::JsonDocument,
            PayloadShape::BinaryBlob,
            PayloadShape::SubjectEncoded,
        ] {
            assert!(shape.validate("test").is_ok());
        }
    }

    // -- ReplyShape validation -----------------------------------------------

    #[test]
    fn reply_shape_none_validates() {
        assert!(ReplyShape::None.validate("test").is_ok());
    }

    #[test]
    fn reply_shape_unary_with_empty_named_schema_rejects() {
        let shape = ReplyShape::Unary {
            shape: PayloadShape::NamedSchema {
                schema: "".to_owned(),
            },
        };
        assert!(shape.validate("test").is_err());
    }

    #[test]
    fn reply_shape_stream_validates_inner_shape() {
        let shape = ReplyShape::Stream {
            shape: PayloadShape::JsonDocument,
        };
        assert!(shape.validate("test").is_ok());
    }

    // -- BudgetSemantics validation ------------------------------------------

    #[test]
    fn budget_semantics_rejects_zero_timeout() {
        let budget = BudgetSemantics {
            default_timeout: Some(Duration::ZERO),
            ..BudgetSemantics::default()
        };
        match budget.validate() {
            Err(ServiceContractError::ZeroDuration { field }) => {
                assert!(field.contains("default_timeout"));
            }
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    #[test]
    fn budget_semantics_none_timeout_validates() {
        let budget = BudgetSemantics {
            default_timeout: None,
            ..BudgetSemantics::default()
        };
        assert!(budget.validate().is_ok());
    }

    // -- MobilityConstraint satisfies ----------------------------------------

    #[test]
    fn mobility_unrestricted_satisfies_any_requirement() {
        assert!(MobilityConstraint::Unrestricted.satisfies(&MobilityConstraint::Unrestricted));
    }

    #[test]
    fn mobility_pinned_satisfies_pinned() {
        assert!(MobilityConstraint::Pinned.satisfies(&MobilityConstraint::Pinned));
    }

    #[test]
    fn mobility_pinned_satisfies_bounded_region() {
        assert!(
            MobilityConstraint::Pinned.satisfies(&MobilityConstraint::BoundedRegion {
                region: "us-east".to_owned(),
            })
        );
    }

    #[test]
    fn mobility_bounded_satisfies_same_region() {
        let constraint = MobilityConstraint::BoundedRegion {
            region: "eu-west".to_owned(),
        };
        let required = MobilityConstraint::BoundedRegion {
            region: "eu-west".to_owned(),
        };
        assert!(constraint.satisfies(&required));
    }

    #[test]
    fn mobility_bounded_does_not_satisfy_different_region() {
        let constraint = MobilityConstraint::BoundedRegion {
            region: "us-east".to_owned(),
        };
        let required = MobilityConstraint::BoundedRegion {
            region: "eu-west".to_owned(),
        };
        assert!(!constraint.satisfies(&required));
    }

    #[test]
    fn mobility_unrestricted_does_not_satisfy_bounded() {
        assert!(
            !MobilityConstraint::Unrestricted.satisfies(&MobilityConstraint::BoundedRegion {
                region: "any".to_owned(),
            })
        );
    }

    #[test]
    fn mobility_unrestricted_does_not_satisfy_pinned() {
        assert!(!MobilityConstraint::Unrestricted.satisfies(&MobilityConstraint::Pinned));
    }

    #[test]
    fn mobility_bounded_rejects_empty_region() {
        let mc = MobilityConstraint::BoundedRegion {
            region: "  ".to_owned(),
        };
        assert!(mc.validate("test").is_err());
    }

    // -- OverloadPolicy validation -------------------------------------------

    #[test]
    fn overload_queue_rejects_zero_capacity() {
        let policy = OverloadPolicy::QueueWithinBudget { max_pending: 0 };
        assert_eq!(
            policy.validate().unwrap_err(),
            ServiceContractError::InvalidQueueCapacity
        );
    }

    #[test]
    fn overload_queue_accepts_nonzero_capacity() {
        let policy = OverloadPolicy::QueueWithinBudget { max_pending: 100 };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn overload_non_queue_variants_validate() {
        for policy in [
            OverloadPolicy::RejectNew,
            OverloadPolicy::DropEphemeral,
            OverloadPolicy::FailFast,
        ] {
            assert!(policy.validate().is_ok());
        }
    }

    // -- ServiceContractSchema validation ------------------------------------

    #[test]
    fn default_contract_schema_validates() {
        assert!(ServiceContractSchema::default().validate().is_ok());
    }

    #[test]
    fn contract_schema_rejects_invalid_overload_policy() {
        let mut schema = ServiceContractSchema::default();
        schema.overload_policy = OverloadPolicy::QueueWithinBudget { max_pending: 0 };
        assert!(schema.validate().is_err());
    }

    // -- ProviderTerms validation against contract ---------------------------

    #[test]
    fn provider_terms_reject_compensation_below_contract() {
        let provider = ProviderTerms {
            compensation_policy: CompensationSemantics::None,
            ..provider_terms()
        };
        let err = provider.validate_against(&contract()).unwrap_err();
        assert!(matches!(
            err,
            ServiceContractError::ProviderCompensationBelowContract { .. }
        ));
    }

    #[test]
    fn provider_terms_reject_evidence_below_contract() {
        let c = ServiceContractSchema {
            evidence_requirements: EvidenceLevel::Forensic,
            ..contract()
        };
        let provider = ProviderTerms {
            evidence_level: EvidenceLevel::Standard,
            ..provider_terms()
        };
        let err = provider.validate_against(&c).unwrap_err();
        assert!(matches!(
            err,
            ServiceContractError::ProviderEvidenceBelowContract { .. }
        ));
    }

    #[test]
    fn provider_terms_reject_incompatible_mobility() {
        let c = ServiceContractSchema {
            mobility_constraints: MobilityConstraint::Pinned,
            ..contract()
        };
        let provider = ProviderTerms {
            mobility_constraint: MobilityConstraint::Unrestricted,
            ..provider_terms()
        };
        let err = provider.validate_against(&c).unwrap_err();
        assert!(matches!(
            err,
            ServiceContractError::ProviderMobilityIncompatible { .. }
        ));
    }

    // -- ServiceFailure abort_reason mapping ---------------------------------

    #[test]
    fn service_failure_maps_to_correct_abort_reasons() {
        assert_eq!(
            ServiceFailure::Cancelled.abort_reason(),
            ObligationAbortReason::Cancel
        );
        assert_eq!(
            ServiceFailure::TimedOut.abort_reason(),
            ObligationAbortReason::Explicit
        );
        assert_eq!(
            ServiceFailure::Rejected.abort_reason(),
            ObligationAbortReason::Explicit
        );
        assert_eq!(
            ServiceFailure::Overloaded.abort_reason(),
            ObligationAbortReason::Error
        );
        assert_eq!(
            ServiceFailure::TransportError.abort_reason(),
            ObligationAbortReason::Error
        );
        assert_eq!(
            ServiceFailure::ApplicationError.abort_reason(),
            ObligationAbortReason::Error
        );
    }

    // -- Display implementations ---------------------------------------------

    #[test]
    fn cleanup_urgency_display() {
        assert_eq!(format!("{}", CleanupUrgency::Background), "background");
        assert_eq!(format!("{}", CleanupUrgency::Prompt), "prompt");
        assert_eq!(format!("{}", CleanupUrgency::Immediate), "immediate");
    }

    #[test]
    fn cancellation_obligations_display() {
        assert_eq!(
            format!("{}", CancellationObligations::BestEffortDrain),
            "best-effort-drain"
        );
        assert_eq!(
            format!("{}", CancellationObligations::DrainBeforeReply),
            "drain-before-reply"
        );
        assert_eq!(
            format!("{}", CancellationObligations::DrainAndCompensate),
            "drain-and-compensate"
        );
    }

    #[test]
    fn service_failure_display() {
        assert_eq!(format!("{}", ServiceFailure::Cancelled), "cancelled");
        assert_eq!(format!("{}", ServiceFailure::TimedOut), "timed_out");
        assert_eq!(format!("{}", ServiceFailure::Overloaded), "overloaded");
    }

    // -- Serialization round-trips -------------------------------------------

    #[test]
    fn service_contract_schema_json_round_trip() {
        let schema = ServiceContractSchema::default();
        let json = serde_json::to_string(&schema).expect("serialize");
        let rt: ServiceContractSchema = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schema, rt);
    }

    #[test]
    fn payload_shape_all_variants_json_round_trip() {
        for shape in [
            PayloadShape::Empty,
            PayloadShape::JsonDocument,
            PayloadShape::BinaryBlob,
            PayloadShape::SubjectEncoded,
            PayloadShape::NamedSchema {
                schema: "test.v1".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&shape).expect("serialize");
            let rt: PayloadShape = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(shape, rt);
        }
    }

    #[test]
    fn mobility_constraint_all_variants_json_round_trip() {
        for mc in [
            MobilityConstraint::Unrestricted,
            MobilityConstraint::BoundedRegion {
                region: "us-west".to_owned(),
            },
            MobilityConstraint::Pinned,
        ] {
            let json = serde_json::to_string(&mc).expect("serialize");
            let rt: MobilityConstraint = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(mc, rt);
        }
    }

    #[test]
    fn overload_policy_all_variants_json_round_trip() {
        for policy in [
            OverloadPolicy::RejectNew,
            OverloadPolicy::QueueWithinBudget { max_pending: 50 },
            OverloadPolicy::DropEphemeral,
            OverloadPolicy::FailFast,
        ] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let rt: OverloadPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, rt);
        }
    }

    // -- Default enum values -------------------------------------------------

    #[test]
    fn default_enum_values_match_expected() {
        assert_eq!(PayloadShape::default(), PayloadShape::Empty);
        assert_eq!(ReplyShape::default(), ReplyShape::None);
        assert_eq!(CleanupUrgency::default(), CleanupUrgency::Prompt);
        assert_eq!(
            CancellationObligations::default(),
            CancellationObligations::DrainBeforeReply
        );
        assert_eq!(
            CompensationSemantics::default(),
            CompensationSemantics::None
        );
        assert_eq!(
            MobilityConstraint::default(),
            MobilityConstraint::Unrestricted
        );
        assert_eq!(EvidenceLevel::default(), EvidenceLevel::Standard);
        assert_eq!(OverloadPolicy::default(), OverloadPolicy::RejectNew);
    }

    // -- Previously existing tests below ------------------------------------

    #[test]
    fn unresolved_service_obligation_is_visible_to_leak_checks() {
        let mut ledger = ObligationLedger::new();
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            "req-5",
            "caller",
            "callee",
            "svc.echo",
            DeliveryClass::ObligationBacked,
            make_task(),
            make_region(),
            Time::from_nanos(3),
            Some(Duration::from_secs(1)),
        )
        .expect("tracked request should allocate");
        let obligation_id = obligation.obligation_id().expect("tracked id");

        let leaks = ledger.check_leaks();

        assert!(!leaks.is_clean());
        assert_eq!(ledger.pending_count(), 1);
        assert!(leaks.leaked.iter().any(|entry| entry.id == obligation_id));
        drop(obligation);
    }

    // ── RequestCertificate tests ────────────────────────────────────────

    #[test]
    fn request_certificate_from_validated_roundtrip() {
        let request = ValidatedServiceRequest {
            delivery_class: DeliveryClass::ObligationBacked,
            timeout: Some(Duration::from_secs(5)),
            priority_hint: None,
            guaranteed_durability: DeliveryClass::MobilitySafe,
            evidence_level: EvidenceLevel::Standard,
            mobility_constraint: MobilityConstraint::Unrestricted,
            compensation_policy: CompensationSemantics::None,
            overload_policy: OverloadPolicy::RejectNew,
        };

        let cert = RequestCertificate::from_validated(
            "req-1".into(),
            "caller-a".into(),
            "orders.region1.created".into(),
            &request,
            super::super::ir::ReplySpaceRule::CallerInbox,
            "OrderService".into(),
            0xDEAD_BEEF,
            Time::from_nanos(1000),
        );

        assert_eq!(cert.request_id, "req-1");
        assert_eq!(cert.caller, "caller-a");
        assert_eq!(cert.delivery_class, DeliveryClass::ObligationBacked);
        assert_eq!(cert.capability_fingerprint, 0xDEAD_BEEF);
        assert!(cert.validate().is_ok());
    }

    #[test]
    fn request_certificate_rejects_empty_fields() {
        let cert = RequestCertificate {
            request_id: String::new(),
            caller: "caller".into(),
            subject: "sub".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_space_rule: super::super::ir::ReplySpaceRule::CallerInbox,
            service_class: "svc".into(),
            capability_fingerprint: 0,
            issued_at: Time::from_nanos(1),
            timeout: None,
        };
        assert!(cert.validate().is_err());
    }

    #[test]
    fn request_certificate_rejects_zero_timeout() {
        let cert = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller".into(),
            subject: "sub".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_space_rule: super::super::ir::ReplySpaceRule::CallerInbox,
            service_class: "svc".into(),
            capability_fingerprint: 0,
            issued_at: Time::from_nanos(1),
            timeout: Some(Duration::ZERO),
        };
        assert!(matches!(
            cert.validate(),
            Err(ServiceObligationError::ZeroTimeout)
        ));
    }

    #[test]
    fn request_certificate_rejects_empty_reply_space_prefix() {
        let cert = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller".into(),
            subject: "sub".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_space_rule: super::super::ir::ReplySpaceRule::SharedPrefix {
                prefix: "   ".into(),
            },
            service_class: "svc".into(),
            capability_fingerprint: 0,
            issued_at: Time::from_nanos(1),
            timeout: None,
        };
        assert_eq!(
            cert.validate(),
            Err(ServiceObligationError::EmptyField {
                field: "reply_space_rule.prefix",
            })
        );
    }

    #[test]
    fn request_certificate_digest_is_deterministic() {
        let cert = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller-a".into(),
            subject: "orders.created".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            reply_space_rule: super::super::ir::ReplySpaceRule::CallerInbox,
            service_class: "OrderSvc".into(),
            capability_fingerprint: 42,
            issued_at: Time::from_nanos(1000),
            timeout: None,
        };
        assert_eq!(cert.digest(), cert.digest());
    }

    #[test]
    fn request_certificate_digest_distinguishes_reply_contract_metadata() {
        let shared = RequestCertificate {
            request_id: "req-1".into(),
            caller: "caller-a".into(),
            subject: "orders.created".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            reply_space_rule: super::super::ir::ReplySpaceRule::SharedPrefix {
                prefix: "_INBOX.shared".into(),
            },
            service_class: "OrderSvc".into(),
            capability_fingerprint: 42,
            issued_at: Time::from_nanos(1000),
            timeout: Some(Duration::from_secs(5)),
        };
        let dedicated = RequestCertificate {
            reply_space_rule: super::super::ir::ReplySpaceRule::DedicatedPrefix {
                prefix: "_INBOX.dedicated".into(),
            },
            ..shared.clone()
        };

        assert_ne!(shared.digest(), dedicated.digest());
    }

    // ── ReplyCertificate tests ──────────────────────────────────────────

    #[test]
    fn reply_certificate_from_commit() {
        let commit = ServiceReplyCommit {
            request_id: "req-1".into(),
            service_obligation_id: None,
            payload: b"hello".to_vec(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            reply_obligation: None,
        };

        let cert = ReplyCertificate::from_commit(
            &commit,
            "callee-a".into(),
            Time::from_nanos(2000),
            Duration::from_millis(50),
        );

        assert_eq!(cert.request_id, "req-1");
        assert_eq!(cert.callee, "callee-a");
        assert!(!cert.is_chunked);
        assert!(cert.total_chunks.is_none());
        assert!(cert.validate().is_ok());
    }

    #[test]
    fn reply_certificate_rejects_chunked_without_count() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            service_obligation_id: None,
            payload_digest: 0,
            is_chunked: true,
            total_chunks: None,
            issued_at: Time::from_nanos(1),
            service_latency: Duration::from_millis(1),
        };
        assert!(matches!(
            cert.validate(),
            Err(ServiceObligationError::ChunkedReplyMissingCount)
        ));
    }

    #[test]
    fn reply_certificate_rejects_unary_chunk_count() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            service_obligation_id: None,
            payload_digest: 0,
            is_chunked: false,
            total_chunks: Some(1),
            issued_at: Time::from_nanos(1),
            service_latency: Duration::from_millis(1),
        };
        assert!(matches!(
            cert.validate(),
            Err(ServiceObligationError::UnaryReplyChunkCountPresent)
        ));
    }

    #[test]
    fn reply_certificate_rejects_tracked_class_without_service_obligation_id() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            service_obligation_id: None,
            payload_digest: 0,
            is_chunked: false,
            total_chunks: None,
            issued_at: Time::from_nanos(1),
            service_latency: Duration::from_millis(1),
        };
        assert!(matches!(
            cert.validate(),
            Err(
                ServiceObligationError::TrackedReplyMissingParentObligationId {
                    delivery_class: DeliveryClass::ObligationBacked,
                }
            )
        ));
    }

    #[test]
    fn reply_certificate_digest_is_deterministic() {
        let cert = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            service_obligation_id: None,
            payload_digest: 0xCAFE,
            is_chunked: false,
            total_chunks: None,
            issued_at: Time::from_nanos(1000),
            service_latency: Duration::from_millis(10),
        };
        assert_eq!(cert.digest(), cert.digest());
    }

    #[test]
    fn reply_certificate_digest_distinguishes_chunk_metadata() {
        let unary = ReplyCertificate {
            request_id: "req-1".into(),
            callee: "callee-a".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            service_obligation_id: Some(ObligationId::new_for_test(7, 0)),
            payload_digest: 0xCAFE,
            is_chunked: false,
            total_chunks: None,
            issued_at: Time::from_nanos(1000),
            service_latency: Duration::from_millis(10),
        };
        let chunked = ReplyCertificate {
            is_chunked: true,
            total_chunks: Some(3),
            ..unary.clone()
        };

        assert_ne!(unary.digest(), chunked.digest());
    }

    // ── ChunkedReplyObligation tests ────────────────────────────────────

    #[test]
    fn chunked_reply_lifecycle_bounded() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-1".into(),
            "req-1".into(),
            None,
            Some(3),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        assert!(!chunked.is_complete());
        assert_eq!(chunked.receive_chunk().unwrap(), 0);
        assert_eq!(chunked.receive_chunk().unwrap(), 1);
        assert!(!chunked.is_complete());
        assert_eq!(chunked.receive_chunk().unwrap(), 2);
        assert!(chunked.is_complete());

        // Fourth chunk should overflow
        assert!(matches!(
            chunked.receive_chunk(),
            Err(ServiceObligationError::ChunkedReplyOverflow {
                expected: 3,
                received: 4,
            })
        ));

        let count = chunked.finalize().unwrap();
        assert_eq!(count, 3);
        assert!(chunked.is_finalized());
    }

    #[test]
    fn chunked_reply_unbounded_stream() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-2".into(),
            "req-2".into(),
            Some(ObligationId::new_for_test(21, 0)),
            None, // unbounded
            DeliveryClass::ObligationBacked,
            AckKind::Served,
        )
        .unwrap();

        for _ in 0..100 {
            chunked.receive_chunk().unwrap();
        }
        assert!(!chunked.is_complete()); // unbounded never reports complete
        assert_eq!(chunked.received_chunks(), 100);

        let count = chunked.finalize().unwrap();
        assert_eq!(count, 100);
    }

    #[test]
    fn chunked_reply_rejects_zero_expected() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-3".into(),
                "req-3".into(),
                None,
                Some(0),
                DeliveryClass::DurableOrdered,
                AckKind::Recoverable,
            ),
            Err(ServiceObligationError::ChunkedReplyZeroExpected)
        ));
    }

    #[test]
    fn chunked_reply_finalize_is_idempotent_guard() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-4".into(),
            "req-4".into(),
            None,
            Some(1),
            DeliveryClass::EphemeralInteractive,
            AckKind::Accepted,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        chunked.finalize().unwrap();

        // Second finalize should fail
        assert!(matches!(
            chunked.finalize(),
            Err(ServiceObligationError::AlreadyResolved { .. })
        ));
    }

    #[test]
    fn chunked_reply_certificate_carries_chunk_count() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-5".into(),
            "req-5".into(),
            None,
            Some(2),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        chunked.receive_chunk().unwrap();
        chunked.finalize().unwrap();

        let cert = chunked
            .certificate(
                "callee-a".into(),
                0xBEEF,
                Time::from_nanos(3000),
                Duration::from_millis(100),
            )
            .expect("finalized bounded stream should produce a certificate");

        assert!(cert.is_chunked);
        assert_eq!(cert.total_chunks, Some(2));
        assert_eq!(cert.payload_digest, 0xBEEF);
        assert!(cert.validate().is_ok());
    }

    #[test]
    fn chunked_reply_finalize_rejects_incomplete_bounded_stream() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-early-finalize".into(),
            "req-early-finalize".into(),
            None,
            Some(2),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();

        assert!(matches!(
            chunked.finalize(),
            Err(ServiceObligationError::ChunkedReplyIncomplete {
                expected: 2,
                received: 1,
            })
        ));
        assert!(!chunked.is_finalized());
    }

    #[test]
    fn chunked_reply_certificate_requires_finalize() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-unfinalized-cert".into(),
            "req-unfinalized-cert".into(),
            None,
            Some(1),
            DeliveryClass::DurableOrdered,
            AckKind::Recoverable,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();

        assert!(matches!(
            chunked.certificate(
                "callee-a".into(),
                0xCAFE,
                Time::from_nanos(1),
                Duration::from_millis(10),
            ),
            Err(ServiceObligationError::ChunkedReplyNotFinalized)
        ));
    }

    #[test]
    fn chunked_reply_receive_after_finalize_fails() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-6".into(),
            "req-6".into(),
            Some(ObligationId::new_for_test(22, 0)),
            Some(1), // bounded stream — finalize is allowed once the single chunk arrives
            DeliveryClass::ObligationBacked,
            AckKind::Served,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        chunked.finalize().unwrap();

        assert!(matches!(
            chunked.receive_chunk(),
            Err(ServiceObligationError::AlreadyResolved { .. })
        ));
    }

    #[test]
    fn chunked_reply_finalize_rejects_incomplete() {
        let mut chunked = ChunkedReplyObligation::new(
            "family-7".into(),
            "req-7".into(),
            Some(ObligationId::new_for_test(23, 0)),
            Some(5),
            DeliveryClass::ObligationBacked,
            AckKind::Served,
        )
        .unwrap();

        chunked.receive_chunk().unwrap();
        // Finalize with only 1 of 5 chunks should fail
        assert!(matches!(
            chunked.finalize(),
            Err(ServiceObligationError::ChunkedReplyIncomplete {
                expected: 5,
                received: 1,
            })
        ));
    }

    #[test]
    fn chunked_reply_rejects_boundary_below_minimum() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-below-min".into(),
                "req-below-min".into(),
                None,
                Some(1),
                DeliveryClass::DurableOrdered,
                AckKind::Committed,
            ),
            Err(ServiceObligationError::ReplyBoundaryBelowMinimum {
                delivery_class: DeliveryClass::DurableOrdered,
                minimum_boundary: AckKind::Recoverable,
                requested_boundary: AckKind::Committed,
            })
        ));
    }

    #[test]
    fn chunked_reply_rejects_untracked_follow_up_boundary() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-untracked".into(),
                "req-untracked".into(),
                None,
                Some(1),
                DeliveryClass::EphemeralInteractive,
                AckKind::Received,
            ),
            Err(ServiceObligationError::ReplyTrackingUnavailable {
                delivery_class: DeliveryClass::EphemeralInteractive,
                requested_boundary: AckKind::Received,
                receipt_required: false,
            })
        ));
    }

    #[test]
    fn chunked_reply_rejects_tracked_class_without_parent_obligation_id() {
        assert!(matches!(
            ChunkedReplyObligation::new(
                "family-tracked-missing-parent".into(),
                "req-tracked-missing-parent".into(),
                None,
                Some(1),
                DeliveryClass::ObligationBacked,
                AckKind::Served,
            ),
            Err(
                ServiceObligationError::TrackedReplyMissingParentObligationId {
                    delivery_class: DeliveryClass::ObligationBacked,
                }
            )
        ));
    }

    // ── QuantitativeContract tests ──────────────────────────────────────

    #[test]
    fn quantitative_contract_valid_interactive_slo() {
        let contract = QuantitativeContract {
            name: "order-processing-p99".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.999,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: true,
        };
        assert!(contract.validate().is_ok());
        assert!(contract.latency_satisfies(Duration::from_millis(30)));
        assert!(!contract.latency_satisfies(Duration::from_millis(100)));
    }

    #[test]
    fn quantitative_contract_valid_with_fixed_retry() {
        let contract = QuantitativeContract {
            name: "durable-ack".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(5),
            target_probability: 0.99,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(500),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: 0.1,
                window_size: 100,
            },
            record_violations: false,
        };
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn quantitative_contract_valid_with_exponential_backoff() {
        let contract = QuantitativeContract {
            name: "obligation-backed-slo".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            target_latency: Duration::from_secs(1),
            target_probability: 0.995,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(100),
                multiplier: 2.0,
                max_delay: Duration::from_secs(10),
                max_attempts: 5,
            },
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.99,
                max_evidence: 100.0,
            },
            record_violations: true,
        };
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn quantitative_contract_valid_with_conformal_monitoring() {
        let contract = QuantitativeContract {
            name: "forensic-slo".into(),
            delivery_class: DeliveryClass::ForensicReplayable,
            target_latency: Duration::from_secs(30),
            target_probability: 0.9,
            retry_law: RetryLaw::BudgetBounded {
                interval: Duration::from_secs(1),
            },
            monitoring_policy: MonitoringPolicy::Conformal {
                target_coverage: 0.95,
                calibration_size: 50,
            },
            record_violations: true,
        };
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn quantitative_contract_rejects_empty_name() {
        let contract = QuantitativeContract {
            name: String::new(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.999,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::EmptyName)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_zero_latency() {
        let contract = QuantitativeContract {
            name: "zero-lat".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::ZERO,
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroLatency)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_invalid_probability() {
        for p in [0.0, -0.1, 1.1, f64::NAN] {
            let contract = QuantitativeContract {
                name: "bad-prob".into(),
                delivery_class: DeliveryClass::EphemeralInteractive,
                target_latency: Duration::from_millis(50),
                target_probability: p,
                retry_law: RetryLaw::None,
                monitoring_policy: MonitoringPolicy::Passive,
                record_violations: false,
            };
            assert!(contract.validate().is_err(), "probability {p} should fail");
        }
    }

    #[test]
    fn quantitative_contract_rejects_bad_retry_law() {
        // Zero interval
        let contract = QuantitativeContract {
            name: "bad-retry".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::Fixed {
                interval: Duration::ZERO,
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroRetryInterval)
        ));

        // Zero max_attempts
        let contract = QuantitativeContract {
            name: "bad-retry".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(100),
                max_attempts: 0,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroMaxAttempts)
        ));

        // Bad multiplier
        let contract = QuantitativeContract {
            name: "bad-mult".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(100),
                multiplier: 1.0,
                max_delay: Duration::from_secs(10),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::InvalidMultiplier(_))
        ));

        // Max delay below initial delay
        let contract = QuantitativeContract {
            name: "bad-delay-order".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_secs(2),
                multiplier: 2.0,
                max_delay: Duration::from_secs(1),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::MaxDelayBelowInitialDelay {
                initial_delay,
                max_delay,
            }) if initial_delay == Duration::from_secs(2) && max_delay == Duration::from_secs(1)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_bad_monitoring() {
        // Zero window
        let contract = QuantitativeContract {
            name: "bad-mon".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: 0.5,
                window_size: 0,
            },
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroWindowSize)
        ));

        // Bad e-process confidence
        let contract = QuantitativeContract {
            name: "bad-eproc".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 1.0,
                max_evidence: 100.0,
            },
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::InvalidConfidence(_))
        ));

        // Bad conformal calibration
        let contract = QuantitativeContract {
            name: "bad-conformal".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Conformal {
                target_coverage: 0.95,
                calibration_size: 0,
            },
            record_violations: false,
        };
        assert!(matches!(
            contract.validate(),
            Err(QuantitativeContractError::ZeroCalibrationSize)
        ));
    }

    #[test]
    fn quantitative_contract_rejects_non_finite_float_parameters() {
        let bad_multiplier = QuantitativeContract {
            name: "bad-multiplier".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_secs(1),
            target_probability: 0.99,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(100),
                multiplier: f64::NAN,
                max_delay: Duration::from_secs(10),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        assert!(matches!(
            bad_multiplier.validate(),
            Err(QuantitativeContractError::InvalidMultiplier(value)) if value.is_nan()
        ));

        let bad_sampling_ratio = QuantitativeContract {
            name: "bad-sampling".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: f64::NAN,
                window_size: 10,
            },
            record_violations: false,
        };
        assert!(matches!(
            bad_sampling_ratio.validate(),
            Err(QuantitativeContractError::InvalidSamplingRatio(value)) if value.is_nan()
        ));

        let bad_max_evidence = QuantitativeContract {
            name: "bad-evidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.95,
                max_evidence: f64::INFINITY,
            },
            record_violations: false,
        };
        assert!(matches!(
            bad_max_evidence.validate(),
            Err(QuantitativeContractError::ZeroMaxEvidence)
        ));

        let cap_below_threshold = QuantitativeContract {
            name: "bad-evidence-threshold".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.80,
                max_evidence: 4.0,
            },
            record_violations: false,
        };
        assert!(matches!(
            cap_below_threshold.validate(),
            Err(QuantitativeContractError::MaxEvidenceBelowAlertThreshold {
                max_evidence,
                threshold,
            }) if (max_evidence - 4.0).abs() < f64::EPSILON
                && (threshold - 5.0).abs() < 1e-9
        ));
    }

    #[test]
    fn quantitative_contract_uses_clamped_eprocess_threshold_near_confidence_one() {
        let confidence = f64::from_bits(1.0_f64.to_bits() - 1);
        let threshold = quantitative_eprocess_threshold(confidence);
        assert_eq!(quantitative_eprocess_alpha(confidence), f64::EPSILON);
        assert_eq!(threshold, 1.0 / f64::EPSILON);

        let contract = QuantitativeContract {
            name: "near-one-confidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence,
                max_evidence: threshold,
            },
            record_violations: false,
        };
        assert!(contract.validate().is_ok());

        let rejected = QuantitativeContract {
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence,
                max_evidence: threshold / 2.0,
            },
            ..contract
        };
        assert!(matches!(
            rejected.validate(),
            Err(QuantitativeContractError::MaxEvidenceBelowAlertThreshold {
                max_evidence,
                threshold: rejected_threshold,
            }) if max_evidence == threshold / 2.0 && rejected_threshold == threshold
        ));
    }

    #[test]
    fn quantitative_contract_serde_roundtrip() {
        let contract = QuantitativeContract {
            name: "serde-test".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            target_latency: Duration::from_millis(200),
            target_probability: 0.999,
            retry_law: RetryLaw::ExponentialBackoff {
                initial_delay: Duration::from_millis(50),
                multiplier: 2.0,
                max_delay: Duration::from_secs(5),
                max_attempts: 4,
            },
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.99,
                max_evidence: 50.0,
            },
            record_violations: true,
        };

        let json = serde_json::to_string(&contract).expect("serialize");
        let deserialized: QuantitativeContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, deserialized);
    }

    #[test]
    fn quantitative_monitor_passive_records_policy_change_evidence() {
        let contract = QuantitativeContract {
            name: "passive-evidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(50),
            target_probability: 0.90,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(10),
                max_attempts: 2,
            },
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(20));
        monitor.observe_latency(Duration::from_millis(70));
        let evaluation = monitor.observe_latency(Duration::from_millis(80));

        assert_eq!(evaluation.state, QuantitativeContractState::Violated);
        assert_eq!(
            evaluation.recommendation,
            QuantitativePolicyRecommendation::Escalate
        );
        let evidence = monitor
            .policy_change_evidence()
            .expect("violations should produce evidence");
        assert_eq!(evidence.contract_name, "passive-evidence");
        assert_eq!(evidence.hit_count, 1);
        assert_eq!(evidence.observations, 3);
    }

    #[test]
    fn quantitative_monitor_sampled_window_detects_violation() {
        let contract = QuantitativeContract {
            name: "sampled-window".into(),
            delivery_class: DeliveryClass::DurableOrdered,
            target_latency: Duration::from_millis(40),
            target_probability: 0.75,
            retry_law: RetryLaw::BudgetBounded {
                interval: Duration::from_millis(15),
            },
            monitoring_policy: MonitoringPolicy::Sampled {
                sampling_ratio: 1.0,
                window_size: 4,
            },
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(10));
        monitor.observe_latency(Duration::from_millis(20));
        monitor.observe_latency(Duration::from_millis(60));
        let evaluation = monitor.observe_latency(Duration::from_millis(70));

        assert_eq!(evaluation.state, QuantitativeContractState::Violated);
        assert_eq!(
            evaluation.recommendation,
            QuantitativePolicyRecommendation::Escalate
        );
        let QuantitativeMonitorEvidence::Sampled {
            sampled_observations,
            window_hit_rate,
            ..
        } = evaluation.evidence
        else {
            panic!("expected sampled monitoring evidence");
        };
        assert_eq!(sampled_observations, 4);
        assert!((window_hit_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn quantitative_monitor_eprocess_alerts_and_auto_resets() {
        let contract = QuantitativeContract {
            name: "eprocess-slo".into(),
            delivery_class: DeliveryClass::ObligationBacked,
            target_latency: Duration::from_millis(10),
            target_probability: 0.95,
            retry_law: RetryLaw::Fixed {
                interval: Duration::from_millis(5),
                max_attempts: 3,
            },
            monitoring_policy: MonitoringPolicy::EProcess {
                confidence: 0.80,
                max_evidence: 10.0,
            },
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(100));
        monitor.observe_latency(Duration::from_millis(120));
        let evaluation = monitor.observe_latency(Duration::from_millis(150));

        assert_eq!(evaluation.state, QuantitativeContractState::Violated);
        let QuantitativeMonitorEvidence::EProcess {
            e_value,
            threshold,
            max_evidence,
            capped,
            alert_state,
            ..
        } = evaluation.evidence
        else {
            panic!("expected e-process evidence");
        };
        assert!(
            max_evidence >= threshold,
            "test config must not cap evidence below the alert threshold"
        );
        assert!(
            e_value >= threshold,
            "reported evidence should clear the alert threshold once alert_state=Alert"
        );
        assert!(capped, "e-value should cap and reset");
        assert_eq!(alert_state, QuantitativeMonitorAlertState::Alert);

        let after_reset = monitor.observe_latency(Duration::from_millis(5));
        let QuantitativeMonitorEvidence::EProcess { e_value, .. } = after_reset.evidence else {
            panic!("expected e-process evidence after reset");
        };
        assert!(
            e_value <= 1.0,
            "fresh monitor should restart from a low evidence level"
        );
    }

    #[test]
    fn quantitative_monitor_conformal_reports_drift() {
        let contract = QuantitativeContract {
            name: "conformal-slo".into(),
            delivery_class: DeliveryClass::ForensicReplayable,
            target_latency: Duration::from_millis(50),
            target_probability: 0.80,
            retry_law: RetryLaw::BudgetBounded {
                interval: Duration::from_millis(10),
            },
            monitoring_policy: MonitoringPolicy::Conformal {
                target_coverage: 0.80,
                calibration_size: 4,
            },
            record_violations: true,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        for sample in [20_u64, 22, 24, 26] {
            let evaluation = monitor.observe_latency(Duration::from_millis(sample));
            assert_eq!(
                evaluation.state,
                QuantitativeContractState::Healthy,
                "calibration samples should not trigger drift by themselves"
            );
        }
        let evaluation = monitor.observe_latency(Duration::from_millis(200));

        assert_eq!(evaluation.state, QuantitativeContractState::AtRisk);
        assert_eq!(
            evaluation.recommendation,
            QuantitativePolicyRecommendation::ApplyRetryLaw
        );
        let QuantitativeMonitorEvidence::Conformal {
            calibration_samples,
            latest_conforming,
            threshold_latency,
            ..
        } = evaluation.evidence
        else {
            panic!("expected conformal evidence");
        };
        assert_eq!(calibration_samples, 4);
        assert_eq!(latest_conforming, Some(false));
        assert!(
            threshold_latency.is_some(),
            "conformal evaluation should expose the calibrated threshold"
        );
        assert!(
            monitor.policy_change_evidence().is_some(),
            "non-healthy conformal result should emit evidence when recording is enabled"
        );
    }

    #[test]
    fn quantitative_monitor_suppresses_policy_change_evidence_when_disabled() {
        let contract = QuantitativeContract {
            name: "no-evidence".into(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            target_latency: Duration::from_millis(30),
            target_probability: 0.99,
            retry_law: RetryLaw::None,
            monitoring_policy: MonitoringPolicy::Passive,
            record_violations: false,
        };
        let mut monitor = QuantitativeContractMonitor::new(contract).expect("valid monitor");
        monitor.observe_latency(Duration::from_millis(100));
        monitor.observe_latency(Duration::from_millis(110));
        monitor.observe_latency(Duration::from_millis(120));
        assert!(monitor.policy_change_evidence().is_none());
    }

    #[test]
    fn workflow_linear_execution_tracks_subject_steps() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let reserve = workflow_step(
            "reserve",
            "fabric.order.reserve",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Lease {
                    resource: "inventory.sku-42".to_owned(),
                },
            ],
            &[],
        );
        let settle = workflow_step(
            "settle",
            "fabric.payment.settle",
            vec![WorkflowObligationRole::Reply {
                delivery_boundary: AckKind::Received,
                receipt_required: true,
            }],
            &[],
        );
        let mut saga = SagaState::new("checkout", vec![reserve, settle]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(10))
            .expect("start first step");
        assert_eq!(saga.current_step, Some(0));
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("owed obligations for first step");
        assert_eq!(owed.len(), 2);
        assert!(owed.iter().all(|entry| entry.step_id == "reserve"));

        saga.complete_current_step(&mut ledger, Time::from_nanos(20))
            .expect("complete first step");
        assert_eq!(saga.steps[0].status, WorkflowStepStatus::Completed);
        assert_eq!(saga.current_step, Some(1));
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("no second-step obligations before start")
                .is_empty()
        );

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(30))
            .expect("start second step");
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("owed obligations for second step");
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].step_id, "settle");

        saga.complete_current_step(&mut ledger, Time::from_nanos(40))
            .expect("complete second step");
        assert_eq!(saga.steps[1].status, WorkflowStepStatus::Completed);
        assert_eq!(saga.current_step, None);
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("all work should be resolved")
                .is_empty()
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn workflow_failure_activates_and_commits_compensation() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let charge = workflow_step(
            "charge",
            "fabric.payment.charge",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Lease {
                    resource: "payment.intent.pi_123".to_owned(),
                },
            ],
            &["fabric.payment.refund", "fabric.inventory.restock"],
        );
        let mut saga = SagaState::new("payment-saga", vec![charge]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(5))
            .expect("start workflow");
        saga.fail_current_step(
            &mut ledger,
            Time::from_nanos(8),
            ServiceFailure::ApplicationError,
            task,
            region,
        )
        .expect("fail current step");

        assert_eq!(
            saga.steps[0].status,
            WorkflowStepStatus::Compensating {
                failure: ServiceFailure::ApplicationError,
            }
        );
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("compensation should now be owed");
        assert_eq!(owed.len(), 2);
        assert!(
            owed.iter()
                .all(|entry| matches!(entry.role, WorkflowObligationRole::Compensation { .. }))
        );

        saga.complete_current_compensation(&mut ledger, Time::from_nanos(13))
            .expect("commit compensation");
        assert_eq!(
            saga.steps[0].status,
            WorkflowStepStatus::Compensated {
                failure: ServiceFailure::ApplicationError,
            }
        );
        assert_eq!(saga.compensated_steps, vec!["charge".to_owned()]);
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("compensation should be resolved")
                .is_empty()
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn workflow_partial_progress_tracks_only_active_step_obligations() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let prepare = workflow_step(
            "prepare",
            "fabric.order.prepare",
            vec![WorkflowObligationRole::Reply {
                delivery_boundary: AckKind::Received,
                receipt_required: true,
            }],
            &[],
        );
        let ship = workflow_step(
            "ship",
            "fabric.order.ship",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Deadline {
                    deadline: Time::from_nanos(500),
                },
            ],
            &[],
        );
        let mut saga = SagaState::new("ship-flow", vec![prepare, ship]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(10))
            .expect("start prepare");
        saga.complete_current_step(&mut ledger, Time::from_nanos(20))
            .expect("complete prepare");
        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(30))
            .expect("start ship");

        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("active step obligations");
        assert_eq!(owed.len(), 2);
        assert!(owed.iter().all(|entry| entry.step_id == "ship"));
        assert!(
            owed.iter()
                .any(|entry| matches!(entry.role, WorkflowObligationRole::Reply { .. }))
        );
        assert!(
            owed.iter()
                .any(|entry| matches!(entry.role, WorkflowObligationRole::Deadline { .. }))
        );
    }

    #[test]
    fn workflow_recovery_after_crash_preserves_explicit_owed_work() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let replicate = workflow_step(
            "replicate",
            "fabric.repair.replicate",
            vec![
                WorkflowObligationRole::Reply {
                    delivery_boundary: AckKind::Received,
                    receipt_required: true,
                },
                WorkflowObligationRole::Timeout,
            ],
            &[],
        );
        let mut saga = SagaState::new("repair", vec![replicate]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(11))
            .expect("start step");
        let encoded = serde_json::to_string(&saga).expect("serialize saga snapshot");
        let snapshot: SagaState = serde_json::from_str(&encoded).expect("deserialize snapshot");

        let mut recovered = snapshot
            .recover_from_replay(&ledger, Time::from_nanos(19))
            .expect("recover from snapshot");
        assert_eq!(recovered.current_step, Some(0));
        assert!(matches!(
            recovered
                .evidence_trail
                .last()
                .expect("recovery evidence")
                .event,
            SagaEvidenceEvent::Recovered
        ));
        assert_eq!(
            recovered
                .what_is_still_owed(&ledger)
                .expect("recovered owed work")
                .len(),
            2
        );

        recovered
            .fail_current_step(
                &mut ledger,
                Time::from_nanos(25),
                ServiceFailure::TimedOut,
                task,
                region,
            )
            .expect("abort by id during recovery");
        assert_eq!(
            recovered.steps[0].status,
            WorkflowStepStatus::Failed {
                failure: ServiceFailure::TimedOut,
            }
        );
        assert!(
            recovered
                .what_is_still_owed(&ledger)
                .expect("all recovered work should be resolved")
                .is_empty()
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn workflow_what_is_still_owed_excludes_future_pending_steps() {
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();
        let ingest = workflow_step(
            "ingest",
            "fabric.ingest.start",
            vec![WorkflowObligationRole::Lease {
                resource: "shard-01".to_owned(),
            }],
            &[],
        );
        let compact = workflow_step(
            "compact",
            "fabric.ingest.compact",
            vec![WorkflowObligationRole::Reply {
                delivery_boundary: AckKind::Received,
                receipt_required: true,
            }],
            &[],
        );
        let mut saga = SagaState::new("ingest-flow", vec![ingest, compact]).expect("valid saga");

        saga.start_next_step(&mut ledger, task, region, Time::from_nanos(7))
            .expect("start ingest");
        let owed = saga
            .what_is_still_owed(&ledger)
            .expect("ingest obligation should be owed");
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].step_id, "ingest");
        assert_eq!(owed[0].state, ObligationState::Reserved);
        let record = ledger
            .get(owed[0].obligation_id)
            .expect("obligation record must exist");
        assert_eq!(record.state, ObligationState::Reserved);

        saga.complete_current_step(&mut ledger, Time::from_nanos(9))
            .expect("complete ingest");
        assert!(
            saga.what_is_still_owed(&ledger)
                .expect("future pending step should stay absent")
                .is_empty()
        );
    }

    #[test]
    fn quantitative_ratio_is_fail_closed_on_empty_window() {
        assert_eq!(ratio(0, 0), 0.0);
        assert_eq!(bool_ratio(&VecDeque::new()), 0.0);
    }
}
