//! Contract-carrying service schemas for the FABRIC lane.

use super::class::{AckKind, DeliveryClass, DeliveryClassPolicy, DeliveryClassPolicyError};
use crate::obligation::ledger::{ObligationLedger, ObligationToken};
use crate::record::{ObligationAbortReason, ObligationKind, SourceLocation};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};
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
        self.callee = callee.clone();
        self.subject = subject.clone();
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
    ) -> ServiceAbortReceipt {
        assert!(
            !self.resolved,
            "service obligation already resolved; cannot abort"
        );
        let obligation_id = self.obligation_id();
        if let Some(token) = self.token.take() {
            ledger.abort(token, now, failure.abort_reason());
        }
        ServiceAbortReceipt {
            request_id: self.request_id,
            obligation_id,
            failure,
            delivery_class: self.delivery_class,
        }
    }

    /// Explicitly timeout the service obligation instead of letting it vanish.
    pub fn timeout(self, ledger: &mut ObligationLedger, now: Time) -> ServiceAbortReceipt {
        assert!(
            !self.resolved,
            "service obligation already resolved; cannot timeout"
        );
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

    fn make_task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(11, 0))
    }

    fn make_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(7, 0))
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
        let obligation = ServiceObligation::allocate(
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
        let obligation = ServiceObligation::allocate(
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
        let mut obligation = ServiceObligation::allocate(
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

        let aborted = obligation.abort(
            &mut ledger,
            Time::from_nanos(15),
            ServiceFailure::ApplicationError,
        );

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
        obligation.abort(
            &mut ledger,
            Time::from_nanos(3),
            ServiceFailure::ApplicationError,
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn service_obligation_timeout_is_explicit_abort() {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
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

        let timed_out = obligation.timeout(&mut ledger, Time::from_nanos(100));

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
        let aborted = obligation.abort(
            &mut ledger,
            Time::from_nanos(3),
            ServiceFailure::ApplicationError,
        );
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
}
