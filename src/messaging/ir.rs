//! Core FABRIC intermediate-representation types.
//!
//! These data structures give the messaging fabric a deterministic schema that
//! higher-layer declarations can compile into and inspect before runtime
//! behavior exists. The types here deliberately model declarations, policies,
//! and contracts rather than live protocol machinery.

#![allow(clippy::struct_field_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::semicolon_if_nothing_returned)]

use super::class::{AckKind, DeliveryClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;
use thiserror::Error;

#[cfg(all(test, not(feature = "messaging-fabric")))]
#[path = "subject.rs"]
mod subject_defs;

#[cfg(feature = "messaging-fabric")]
pub use super::subject::SubjectPattern;
#[cfg(all(test, not(feature = "messaging-fabric")))]
pub use subject_defs::SubjectPattern;

/// Schema version for the current FABRIC IR layout.
pub const FABRIC_IR_SCHEMA_VERSION: u16 = 1;

/// Root FABRIC IR document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FabricIr {
    /// Schema version for forward-compatible upgrades.
    pub schema_version: u16,
    /// Subject declarations that define semantic routing intent.
    pub subjects: Vec<SubjectSchema>,
    /// Namespace or semantics transforms applied during lowering.
    pub morphisms: Vec<MorphismPlan>,
    /// Service interface declarations.
    pub services: Vec<ServiceContract>,
    /// Session-typed protocol declarations.
    pub protocols: Vec<ProtocolContract>,
    /// Reusable consumer-policy declarations.
    pub consumers: Vec<ConsumerPolicy>,
    /// Reusable privacy-policy declarations.
    pub privacy_policies: Vec<PrivacyPolicy>,
    /// Reusable cut-policy declarations.
    pub cut_policies: Vec<CutPolicy>,
    /// Reusable branch-policy declarations.
    pub branch_policies: Vec<BranchPolicy>,
    /// Reusable quantitative obligation contracts.
    pub obligation_contracts: Vec<QuantitativeObligationContract>,
    /// Capability token schemas that constrain privileged actions.
    pub capability_tokens: Vec<CapabilityTokenSchema>,
}

impl Default for FabricIr {
    fn default() -> Self {
        Self {
            schema_version: FABRIC_IR_SCHEMA_VERSION,
            subjects: Vec::new(),
            morphisms: Vec::new(),
            services: Vec::new(),
            protocols: Vec::new(),
            consumers: Vec::new(),
            privacy_policies: Vec::new(),
            cut_policies: Vec::new(),
            branch_policies: Vec::new(),
            obligation_contracts: Vec::new(),
            capability_tokens: Vec::new(),
        }
    }
}

impl FabricIr {
    /// Validate the IR document for structural correctness.
    #[must_use]
    pub fn validate(&self) -> Vec<FabricIrValidationError> {
        let mut errors = Vec::new();

        if self.schema_version != FABRIC_IR_SCHEMA_VERSION {
            errors.push(FabricIrValidationError::new(
                "schema_version",
                format!(
                    "unsupported FABRIC IR version {}, expected {FABRIC_IR_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }

        self.validate_unique_names(&mut errors);
        self.validate_entries(&mut errors);
        self.validate_cross_references(&mut errors);

        errors
    }

    fn validate_unique_names(&self, errors: &mut Vec<FabricIrValidationError>) {
        validate_unique_keys(
            self.subjects
                .iter()
                .map(|subject| subject.pattern.as_str().to_owned()),
            "subjects",
            "subject pattern must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.morphisms.iter().map(|morphism| morphism.name.clone()),
            "morphisms",
            "morphism name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.services.iter().map(|service| service.name.clone()),
            "services",
            "service name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.protocols.iter().map(|protocol| protocol.name.clone()),
            "protocols",
            "protocol name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.consumers.iter().map(|consumer| consumer.name.clone()),
            "consumers",
            "consumer policy name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.privacy_policies
                .iter()
                .map(|policy| policy.name.clone()),
            "privacy_policies",
            "privacy policy name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.cut_policies.iter().map(|policy| policy.name.clone()),
            "cut_policies",
            "cut policy name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.branch_policies
                .iter()
                .map(|policy| policy.name.clone()),
            "branch_policies",
            "branch policy name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.obligation_contracts
                .iter()
                .map(|contract| contract.name.clone()),
            "obligation_contracts",
            "quantitative obligation contract name must be unique within a FabricIr document",
            errors,
        );
        validate_unique_keys(
            self.capability_tokens
                .iter()
                .map(|capability| capability.name.clone()),
            "capability_tokens",
            "capability token schema name must be unique within a FabricIr document",
            errors,
        );
    }

    fn validate_entries(&self, errors: &mut Vec<FabricIrValidationError>) {
        for (index, subject) in self.subjects.iter().enumerate() {
            subject.validate_at(&format!("subjects[{index}]"), errors);
        }
        for (index, morphism) in self.morphisms.iter().enumerate() {
            morphism.validate_at(&format!("morphisms[{index}]"), errors);
        }
        for (index, service) in self.services.iter().enumerate() {
            service.validate_at(&format!("services[{index}]"), errors);
        }
        for (index, protocol) in self.protocols.iter().enumerate() {
            protocol.validate_at(&format!("protocols[{index}]"), errors);
        }
        for (index, consumer) in self.consumers.iter().enumerate() {
            consumer.validate_at(&format!("consumers[{index}]"), errors);
        }
        for (index, policy) in self.privacy_policies.iter().enumerate() {
            policy.validate_at(&format!("privacy_policies[{index}]"), errors);
        }
        for (index, policy) in self.cut_policies.iter().enumerate() {
            policy.validate_at(&format!("cut_policies[{index}]"), errors);
        }
        for (index, policy) in self.branch_policies.iter().enumerate() {
            policy.validate_at(&format!("branch_policies[{index}]"), errors);
        }
        for (index, contract) in self.obligation_contracts.iter().enumerate() {
            contract.validate_at(&format!("obligation_contracts[{index}]"), errors);
        }
        for (index, capability) in self.capability_tokens.iter().enumerate() {
            capability.validate_at(&format!("capability_tokens[{index}]"), errors);
        }
    }

    fn validate_cross_references(&self, errors: &mut Vec<FabricIrValidationError>) {
        let capability_names = self
            .capability_tokens
            .iter()
            .map(|capability| capability.name.as_str())
            .collect::<BTreeSet<_>>();

        for (index, service) in self.services.iter().enumerate() {
            if let Some(required_capability) = service.required_capability.as_deref() {
                let required_capability = required_capability.trim();
                if !required_capability.is_empty()
                    && !capability_names.contains(required_capability)
                {
                    errors.push(FabricIrValidationError::new(
                        format!("services[{index}].required_capability"),
                        format!(
                            "required capability token `{required_capability}` is not declared in capability_tokens"
                        ),
                    ));
                }
            }
        }
    }
}

/// Validation error for a FABRIC IR declaration.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{field}: {message}")]
pub struct FabricIrValidationError {
    /// Logical field path that failed validation.
    pub field: String,
    /// Human-readable problem description.
    pub message: String,
}

impl FabricIrValidationError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Canonical subject pattern schema used by the FABRIC IR.
impl SubjectPattern {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        let pattern = self.as_str().trim();
        if pattern.is_empty() {
            errors.push(FabricIrValidationError::new(
                field,
                "subject pattern must not be empty",
            ));
            return;
        }
        if pattern.chars().any(char::is_whitespace) {
            errors.push(FabricIrValidationError::new(
                field,
                "subject pattern must not contain whitespace",
            ));
        }

        let segments = pattern.split('.').collect::<Vec<_>>();
        if segments.iter().any(|segment| segment.is_empty()) {
            errors.push(FabricIrValidationError::new(
                field,
                "subject pattern must not contain empty segments",
            ));
        }

        let tail_count = segments.iter().filter(|segment| **segment == ">").count();
        if tail_count > 1 {
            errors.push(FabricIrValidationError::new(
                field,
                "subject pattern may contain at most one tail wildcard",
            ));
        }

        if let Some(position) = segments.iter().position(|segment| *segment == ">")
            && position + 1 != segments.len()
        {
            errors.push(FabricIrValidationError::new(
                field,
                "tail wildcard must be the terminal segment",
            ));
        }

        for segment in segments {
            if segment != "*" && segment != ">" && (segment.contains('*') || segment.contains('>'))
            {
                errors.push(FabricIrValidationError::new(
                    field,
                    format!("subject segment `{segment}` embeds a wildcard token"),
                ));
            }
        }
    }
}

/// Semantic family attached to a subject declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectFamily {
    /// Imperative action request.
    Command,
    /// Notification that something happened.
    #[default]
    Event,
    /// Response to a command or service request.
    Reply,
    /// Control-plane or runtime-management traffic.
    Control,
    /// Step inside a session-typed protocol.
    ProtocolStep,
    /// Stream or consumer capture selector.
    CaptureSelector,
    /// Read-only projected or derived view.
    DerivedView,
}

impl SubjectFamily {
    /// Exhaustive list of subject families.
    pub const ALL: [Self; 7] = [
        Self::Command,
        Self::Event,
        Self::Reply,
        Self::Control,
        Self::ProtocolStep,
        Self::CaptureSelector,
        Self::DerivedView,
    ];

    /// Canonical snake-case name used in logs and explain plans.
    #[must_use]
    #[allow(dead_code)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Event => "event",
            Self::Reply => "reply",
            Self::Control => "control",
            Self::ProtocolStep => "protocol_step",
            Self::CaptureSelector => "capture_selector",
            Self::DerivedView => "derived_view",
        }
    }
}

/// Reply-space contract for request/reply or service subjects.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplySpaceRule {
    /// Use the caller-provided inbox.
    #[default]
    CallerInbox,
    /// Route replies into a shared reply subject prefix.
    SharedPrefix {
        /// Reply-subject prefix shared across callers.
        prefix: String,
    },
    /// Allocate a dedicated reply prefix per requestor or tenant.
    DedicatedPrefix {
        /// Reply-subject prefix allocated to one requestor or tenant.
        prefix: String,
    },
}

impl ReplySpaceRule {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        let prefix = match self {
            Self::CallerInbox => return,
            Self::SharedPrefix { prefix } | Self::DedicatedPrefix { prefix } => prefix,
        };

        if prefix.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                field,
                "reply-space prefix must not be empty",
            ));
        }
    }
}

/// Whether a subject may move across stewardship or topology boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobilityPermission {
    /// Subject is pinned to the local authority boundary.
    #[default]
    LocalOnly,
    /// Subject may traverse federated boundaries.
    Federated,
    /// Subject may change stewardship with explicit control-plane support.
    StewardshipTransfer,
}

impl MobilityPermission {
    /// Exhaustive list of mobility permissions.
    pub const ALL: [Self; 3] = [Self::LocalOnly, Self::Federated, Self::StewardshipTransfer];
}

/// Subject declaration in the FABRIC IR.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SubjectSchema {
    /// Subject or subject-pattern declaration.
    pub pattern: SubjectPattern,
    /// Semantic family classification.
    pub family: SubjectFamily,
    /// Default service class for this subject family.
    pub delivery_class: DeliveryClass,
    /// Evidence capture policy.
    pub evidence_policy: EvidencePolicy,
    /// Privacy and metadata disclosure policy.
    pub privacy_policy: PrivacyPolicy,
    /// Optional reply-space contract.
    pub reply_space: Option<ReplySpaceRule>,
    /// Stewardship and federation mobility constraint.
    pub mobility: MobilityPermission,
    /// Optional quantitative obligation for the subject.
    pub quantitative_obligation: Option<QuantitativeObligationContract>,
}

impl SubjectSchema {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        self.pattern
            .validate_at(&format!("{field}.pattern"), errors);
        self.evidence_policy
            .validate_at(&format!("{field}.evidence_policy"), errors);
        self.privacy_policy
            .validate_at(&format!("{field}.privacy_policy"), errors);
        if let Some(rule) = &self.reply_space {
            rule.validate_at(&format!("{field}.reply_space"), errors);
        }
        if let Some(contract) = &self.quantitative_obligation {
            contract.validate_at(&format!("{field}.quantitative_obligation"), errors);
            if contract.class != self.delivery_class {
                errors.push(FabricIrValidationError::new(
                    format!("{field}.quantitative_obligation.class"),
                    "quantitative obligation class must match the subject delivery class",
                ));
            }
        }

        match self.family {
            SubjectFamily::Command => {
                if self.reply_space.is_none() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.reply_space"),
                        "command subjects must declare a reply-space rule",
                    ));
                }
            }
            SubjectFamily::Event | SubjectFamily::Reply | SubjectFamily::DerivedView => {
                if self.reply_space.is_some() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.reply_space"),
                        "event, reply, and derived-view subjects must not declare reply-space rules",
                    ));
                }
            }
            SubjectFamily::Control => {
                if !self.pattern.as_str().starts_with("$SYS.")
                    && !self.pattern.as_str().starts_with("sys.")
                {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.pattern"),
                        "control subjects must live under `$SYS.` or `sys.`",
                    ));
                }
            }
            SubjectFamily::CaptureSelector => {
                if !self.pattern.as_str().contains('*') && !self.pattern.as_str().contains('>') {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.pattern"),
                        "capture-selector subjects must include `*` or `>`",
                    ));
                }
            }
            SubjectFamily::ProtocolStep => {}
        }
    }
}

/// Latency estimate with median and tail percentiles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawLatencyEstimate")]
pub struct LatencyEstimate {
    /// Median steady-state latency.
    pub median: Duration,
    /// p99 latency.
    pub p99: Duration,
    /// p999 latency.
    pub p999: Duration,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct RawLatencyEstimate {
    median: Duration,
    p99: Duration,
    p999: Duration,
}

impl From<RawLatencyEstimate> for LatencyEstimate {
    fn from(value: RawLatencyEstimate) -> Self {
        Self::new(value.median, value.p99, value.p999)
    }
}

const fn duration_less(lhs: Duration, rhs: Duration) -> bool {
    lhs.as_secs() < rhs.as_secs()
        || (lhs.as_secs() == rhs.as_secs() && lhs.subsec_nanos() < rhs.subsec_nanos())
}

const fn duration_max(lhs: Duration, rhs: Duration) -> Duration {
    if duration_less(lhs, rhs) { rhs } else { lhs }
}

impl LatencyEstimate {
    /// Zero-latency estimate.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            median: Duration::ZERO,
            p99: Duration::ZERO,
            p999: Duration::ZERO,
        }
    }

    /// Construct a monotone latency estimate.
    #[must_use]
    pub const fn new(median: Duration, p99: Duration, p999: Duration) -> Self {
        let p99 = duration_max(p99, median);
        let p999 = duration_max(p999, p99);
        Self { median, p99, p999 }
    }

    #[allow(dead_code)]
    fn max(self, other: Self) -> Self {
        Self {
            median: self.median.max(other.median),
            p99: self.p99.max(other.p99),
            p999: self.p999.max(other.p999),
        }
    }

    fn cheaper_or_equal(self, other: Self) -> bool {
        self.median <= other.median && self.p99 <= other.p99 && self.p999 <= other.p999
    }
}

/// CPU-cost estimate per message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawCpuEstimate")]
pub struct CpuEstimate {
    /// Typical per-message CPU budget in microseconds.
    pub typical_micros: u64,
    /// p99 per-message CPU budget in microseconds.
    pub p99_micros: u64,
}

impl CpuEstimate {
    /// Construct a monotone CPU estimate.
    #[must_use]
    pub const fn new(typical_micros: u64, p99_micros: u64) -> Self {
        let p99_micros = if p99_micros < typical_micros {
            typical_micros
        } else {
            p99_micros
        };
        Self {
            typical_micros,
            p99_micros,
        }
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            typical_micros: self.typical_micros.saturating_add(other.typical_micros),
            p99_micros: self.p99_micros.saturating_add(other.p99_micros),
        }
    }

    #[allow(dead_code)]
    fn max(self, other: Self) -> Self {
        Self {
            typical_micros: self.typical_micros.max(other.typical_micros),
            p99_micros: self.p99_micros.max(other.p99_micros),
        }
    }

    fn cheaper_or_equal(self, other: Self) -> bool {
        self.typical_micros <= other.typical_micros && self.p99_micros <= other.p99_micros
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct RawCpuEstimate {
    typical_micros: u64,
    p99_micros: u64,
}

impl From<RawCpuEstimate> for CpuEstimate {
    fn from(value: RawCpuEstimate) -> Self {
        Self::new(value.typical_micros, value.p99_micros)
    }
}

/// Byte-cost estimate with bounded range.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawByteEstimate")]
pub struct ByteEstimate {
    /// Minimum expected bytes.
    pub min_bytes: u64,
    /// Typical expected bytes.
    pub typical_bytes: u64,
    /// Maximum expected bytes.
    pub max_bytes: u64,
}

impl ByteEstimate {
    /// Construct a monotone byte estimate.
    #[must_use]
    pub const fn new(min_bytes: u64, typical_bytes: u64, max_bytes: u64) -> Self {
        let typical_bytes = if typical_bytes < min_bytes {
            min_bytes
        } else {
            typical_bytes
        };
        let max_bytes = if max_bytes < typical_bytes {
            typical_bytes
        } else {
            max_bytes
        };
        Self {
            min_bytes,
            typical_bytes,
            max_bytes,
        }
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            min_bytes: self.min_bytes.saturating_add(other.min_bytes),
            typical_bytes: self.typical_bytes.saturating_add(other.typical_bytes),
            max_bytes: self.max_bytes.saturating_add(other.max_bytes),
        }
    }

    #[allow(dead_code)]
    fn max(self, other: Self) -> Self {
        Self {
            min_bytes: self.min_bytes.max(other.min_bytes),
            typical_bytes: self.typical_bytes.max(other.typical_bytes),
            max_bytes: self.max_bytes.max(other.max_bytes),
        }
    }

    fn cheaper_or_equal(self, other: Self) -> bool {
        self.min_bytes <= other.min_bytes
            && self.typical_bytes <= other.typical_bytes
            && self.max_bytes <= other.max_bytes
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct RawByteEstimate {
    min_bytes: u64,
    typical_bytes: u64,
    max_bytes: u64,
}

impl From<RawByteEstimate> for ByteEstimate {
    fn from(value: RawByteEstimate) -> Self {
        Self::new(value.min_bytes, value.typical_bytes, value.max_bytes)
    }
}

/// Duration estimate for restore or handoff operations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawDurationEstimate")]
pub struct DurationEstimate {
    /// Minimum expected duration.
    pub min: Duration,
    /// Typical expected duration.
    pub typical: Duration,
    /// Maximum expected duration.
    pub max: Duration,
}

impl DurationEstimate {
    /// Construct a monotone duration estimate.
    #[must_use]
    pub const fn new(min: Duration, typical: Duration, max: Duration) -> Self {
        let typical = duration_max(typical, min);
        let max = duration_max(max, typical);
        Self { min, typical, max }
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            min: self.min.saturating_add(other.min),
            typical: self.typical.saturating_add(other.typical),
            max: self.max.saturating_add(other.max),
        }
    }

    #[allow(dead_code)]
    fn max(self, other: Self) -> Self {
        Self {
            min: self.min.max(other.min),
            typical: self.typical.max(other.typical),
            max: self.max.max(other.max),
        }
    }

    fn cheaper_or_equal(self, other: Self) -> bool {
        self.min <= other.min && self.typical <= other.typical && self.max <= other.max
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct RawDurationEstimate {
    min: Duration,
    typical: Duration,
    max: Duration,
}

impl From<RawDurationEstimate> for DurationEstimate {
    fn from(value: RawDurationEstimate) -> Self {
        Self::new(value.min, value.typical, value.max)
    }
}

/// Multidimensional FABRIC feature cost envelope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct CostVector {
    /// Steady-state latency envelope.
    pub steady_state_latency: LatencyEstimate,
    /// Tail-latency envelope under stress.
    pub tail_latency: LatencyEstimate,
    /// Ratio of durable bytes versus raw payload bytes.
    pub storage_amplification: f64,
    /// Ratio of control-plane chatter versus data-plane messages.
    pub control_plane_amplification: f64,
    /// CPU and cryptographic overhead.
    pub cpu_crypto_cost: CpuEstimate,
    /// Evidence bytes emitted per decision or message.
    pub evidence_bytes: ByteEstimate,
    /// Restore or handoff latency envelope.
    pub restore_handoff_time: DurationEstimate,
}

impl CostVector {
    /// Zero-cost baseline.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            steady_state_latency: LatencyEstimate::zero(),
            tail_latency: LatencyEstimate::zero(),
            storage_amplification: 0.0,
            control_plane_amplification: 0.0,
            cpu_crypto_cost: CpuEstimate::new(0, 0),
            evidence_bytes: ByteEstimate::new(0, 0, 0),
            restore_handoff_time: DurationEstimate::new(
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
            ),
        }
    }

    /// Construct a baseline cost envelope for a delivery class.
    #[must_use]
    pub fn baseline_for_delivery_class(class: DeliveryClass) -> Self {
        match class {
            DeliveryClass::EphemeralInteractive => Self {
                steady_state_latency: LatencyEstimate::new(
                    Duration::from_micros(50),
                    Duration::from_micros(200),
                    Duration::from_micros(500),
                ),
                tail_latency: LatencyEstimate::new(
                    Duration::from_micros(100),
                    Duration::from_millis(1),
                    Duration::from_millis(2),
                ),
                storage_amplification: 1.0,
                control_plane_amplification: 0.0,
                cpu_crypto_cost: CpuEstimate::new(4, 12),
                evidence_bytes: ByteEstimate::new(0, 0, 0),
                restore_handoff_time: DurationEstimate::default(),
            },
            DeliveryClass::DurableOrdered => Self {
                steady_state_latency: LatencyEstimate::new(
                    Duration::from_micros(150),
                    Duration::from_millis(2),
                    Duration::from_millis(4),
                ),
                tail_latency: LatencyEstimate::new(
                    Duration::from_millis(1),
                    Duration::from_millis(6),
                    Duration::from_millis(12),
                ),
                storage_amplification: 1.25,
                control_plane_amplification: 0.15,
                cpu_crypto_cost: CpuEstimate::new(12, 30),
                evidence_bytes: ByteEstimate::new(32, 96, 256),
                restore_handoff_time: DurationEstimate::new(
                    Duration::from_millis(10),
                    Duration::from_millis(50),
                    Duration::from_millis(250),
                ),
            },
            DeliveryClass::ObligationBacked => Self {
                steady_state_latency: LatencyEstimate::new(
                    Duration::from_micros(250),
                    Duration::from_millis(3),
                    Duration::from_millis(6),
                ),
                tail_latency: LatencyEstimate::new(
                    Duration::from_millis(2),
                    Duration::from_millis(10),
                    Duration::from_millis(20),
                ),
                storage_amplification: 1.4,
                control_plane_amplification: 0.35,
                cpu_crypto_cost: CpuEstimate::new(20, 48),
                evidence_bytes: ByteEstimate::new(96, 256, 768),
                restore_handoff_time: DurationEstimate::new(
                    Duration::from_millis(25),
                    Duration::from_millis(125),
                    Duration::from_millis(500),
                ),
            },
            DeliveryClass::MobilitySafe => Self {
                steady_state_latency: LatencyEstimate::new(
                    Duration::from_micros(350),
                    Duration::from_millis(5),
                    Duration::from_millis(10),
                ),
                tail_latency: LatencyEstimate::new(
                    Duration::from_millis(3),
                    Duration::from_millis(15),
                    Duration::from_millis(30),
                ),
                storage_amplification: 1.6,
                control_plane_amplification: 0.6,
                cpu_crypto_cost: CpuEstimate::new(28, 70),
                evidence_bytes: ByteEstimate::new(192, 640, 1536),
                restore_handoff_time: DurationEstimate::new(
                    Duration::from_millis(100),
                    Duration::from_millis(750),
                    Duration::from_secs(3),
                ),
            },
            DeliveryClass::ForensicReplayable => Self {
                steady_state_latency: LatencyEstimate::new(
                    Duration::from_micros(500),
                    Duration::from_millis(8),
                    Duration::from_millis(16),
                ),
                tail_latency: LatencyEstimate::new(
                    Duration::from_millis(5),
                    Duration::from_millis(25),
                    Duration::from_millis(50),
                ),
                storage_amplification: 2.4,
                control_plane_amplification: 0.9,
                cpu_crypto_cost: CpuEstimate::new(40, 96),
                evidence_bytes: ByteEstimate::new(512, 2048, 8192),
                restore_handoff_time: DurationEstimate::new(
                    Duration::from_millis(250),
                    Duration::from_secs(2),
                    Duration::from_secs(8),
                ),
            },
        }
    }

    /// Estimate the subject-level cost envelope from its declared features.
    #[must_use]
    pub fn estimate_subject(subject: &SubjectSchema) -> Self {
        let mut cost = Self::baseline_for_delivery_class(subject.delivery_class);

        let evidence_sampling = subject.evidence_policy.sampling_ratio.clamp(0.0, 1.0);
        let evidence_base = if subject.evidence_policy.record_payload_hashes {
            96
        } else {
            24
        };
        let sampled_bytes = (f64::from(evidence_base) * evidence_sampling).round() as u64;
        cost.evidence_bytes = cost.evidence_bytes.saturating_add(ByteEstimate::new(
            sampled_bytes / 2,
            sampled_bytes,
            sampled_bytes * 2,
        ));

        if subject.evidence_policy.record_control_transitions {
            cost.control_plane_amplification += 0.08;
            cost.evidence_bytes = cost
                .evidence_bytes
                .saturating_add(ByteEstimate::new(32, 96, 192));
        }
        if subject.evidence_policy.record_counterfactual_branches {
            cost.storage_amplification += 0.2;
            cost.control_plane_amplification += 0.12;
            cost.evidence_bytes = cost
                .evidence_bytes
                .saturating_add(ByteEstimate::new(128, 256, 512));
            cost.restore_handoff_time =
                cost.restore_handoff_time
                    .saturating_add(DurationEstimate::new(
                        Duration::from_millis(10),
                        Duration::from_millis(50),
                        Duration::from_millis(200),
                    ));
        }

        match subject.evidence_policy.retention {
            RetentionPolicy::DropImmediately => {}
            RetentionPolicy::RetainFor { duration } => {
                cost.storage_amplification = (duration.as_secs_f64().min(3600.0) / 3600.0)
                    .mul_add(0.3, cost.storage_amplification);
                cost.restore_handoff_time =
                    cost.restore_handoff_time
                        .saturating_add(DurationEstimate::new(
                            Duration::from_millis(5),
                            Duration::from_millis(25),
                            Duration::from_millis(100),
                        ));
            }
            RetentionPolicy::RetainForEvents { events } => {
                let event_factor = events.min(10_000) as f64 / 10_000.0;
                cost.storage_amplification =
                    0.4f64.mul_add(event_factor, cost.storage_amplification);
            }
            RetentionPolicy::Forever => {
                cost.storage_amplification += 0.75;
                cost.evidence_bytes = cost
                    .evidence_bytes
                    .saturating_add(ByteEstimate::new(64, 256, 1024));
            }
        }

        if subject.reply_space.is_some() {
            cost.control_plane_amplification += 0.1;
            cost.cpu_crypto_cost = cost.cpu_crypto_cost.saturating_add(CpuEstimate::new(2, 8));
        }

        match subject.mobility {
            MobilityPermission::LocalOnly => {}
            MobilityPermission::Federated => {
                cost.control_plane_amplification += 0.05;
                cost.restore_handoff_time =
                    cost.restore_handoff_time
                        .saturating_add(DurationEstimate::new(
                            Duration::from_millis(20),
                            Duration::from_millis(80),
                            Duration::from_millis(300),
                        ));
            }
            MobilityPermission::StewardshipTransfer => {
                cost.control_plane_amplification += 0.15;
                cost.restore_handoff_time =
                    cost.restore_handoff_time
                        .saturating_add(DurationEstimate::new(
                            Duration::from_millis(50),
                            Duration::from_millis(250),
                            Duration::from_secs(1),
                        ));
            }
        }

        if let Some(contract) = &subject.quantitative_obligation {
            cost.tail_latency = cost.tail_latency.max(LatencyEstimate::new(
                contract.target_latency,
                contract.target_latency.saturating_mul(2),
                contract.target_latency.saturating_mul(4),
            ));
            cost.control_plane_amplification += 0.05;
        }

        cost
    }

    /// Return true when every cost dimension is cheaper than or equal to the
    /// corresponding dimension in `other`.
    #[must_use]
    pub fn cheaper_or_equal(&self, other: &Self) -> bool {
        self.steady_state_latency
            .cheaper_or_equal(other.steady_state_latency)
            && self.tail_latency.cheaper_or_equal(other.tail_latency)
            && self.storage_amplification <= other.storage_amplification
            && self.control_plane_amplification <= other.control_plane_amplification
            && self.cpu_crypto_cost.cheaper_or_equal(other.cpu_crypto_cost)
            && self.evidence_bytes.cheaper_or_equal(other.evidence_bytes)
            && self
                .restore_handoff_time
                .cheaper_or_equal(other.restore_handoff_time)
    }

    /// Return true when at least one dimension is more expensive than the
    /// corresponding dimension in `other`.
    #[must_use]
    pub fn more_expensive_on_any_dimension(&self, other: &Self) -> bool {
        !self.cheaper_or_equal(other)
    }

    fn max(self, other: Self) -> Self {
        Self {
            steady_state_latency: self.steady_state_latency.max(other.steady_state_latency),
            tail_latency: self.tail_latency.max(other.tail_latency),
            storage_amplification: self.storage_amplification.max(other.storage_amplification),
            control_plane_amplification: self
                .control_plane_amplification
                .max(other.control_plane_amplification),
            cpu_crypto_cost: self.cpu_crypto_cost.max(other.cpu_crypto_cost),
            evidence_bytes: self.evidence_bytes.max(other.evidence_bytes),
            restore_handoff_time: self.restore_handoff_time.max(other.restore_handoff_time),
        }
    }

    /// Compute a conservative worst-case envelope across a set of cost vectors.
    #[must_use]
    #[allow(dead_code)]
    pub fn max_dimensions<I>(costs: I) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        costs.into_iter().fold(Self::zero(), Self::max)
    }
}

/// Namespace transform or semantics rewrite plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MorphismPlan {
    /// Human-readable plan name.
    pub name: String,
    /// Source subject pattern to match.
    pub source_pattern: SubjectPattern,
    /// Canonical target prefix after rewriting.
    pub target_prefix: String,
    /// Families this transform is allowed to rewrite.
    pub allowed_families: Vec<SubjectFamily>,
    /// Concrete transform steps.
    pub transforms: Vec<MorphismTransform>,
}

impl Default for MorphismPlan {
    fn default() -> Self {
        Self {
            name: "identity".to_owned(),
            source_pattern: SubjectPattern::default(),
            target_prefix: "fabric".to_owned(),
            allowed_families: vec![SubjectFamily::Event],
            transforms: vec![MorphismTransform::PreserveReplySpace],
        }
    }
}

impl MorphismPlan {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "morphism plan name must not be empty",
            ));
        }
        self.source_pattern
            .validate_at(&format!("{field}.source_pattern"), errors);
        if self.target_prefix.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.target_prefix"),
                "morphism target prefix must not be empty",
            ));
        }
        if self.allowed_families.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.allowed_families"),
                "morphism plan must admit at least one subject family",
            ));
        }
        if self.transforms.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.transforms"),
                "morphism plan must declare at least one transform step",
            ));
        }
        for (index, transform) in self.transforms.iter().enumerate() {
            transform.validate_at(&format!("{field}.transforms[{index}]"), errors);
        }
    }
}

/// Individual transform step in a morphism plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MorphismTransform {
    /// Rename one namespace prefix to another.
    RenamePrefix {
        /// Source namespace prefix.
        from: String,
        /// Target namespace prefix.
        to: String,
    },
    /// Restrict the plan to a single family.
    FilterFamily {
        /// Admitted subject family.
        family: SubjectFamily,
    },
    /// Escalate the delivery class during lowering.
    EscalateDeliveryClass {
        /// Delivery class applied after the transform.
        class: DeliveryClass,
    },
    /// Preserve reply-space declarations.
    PreserveReplySpace,
    /// Attach a stricter evidence policy to rewritten subjects.
    AttachEvidencePolicy {
        /// Evidence policy attached by the transform.
        policy: EvidencePolicy,
    },
}

impl MorphismTransform {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        match self {
            Self::RenamePrefix { from, to } => {
                if from.trim().is_empty() || to.trim().is_empty() {
                    errors.push(FabricIrValidationError::new(
                        field,
                        "rename-prefix transform requires non-empty `from` and `to`",
                    ));
                } else if from == to {
                    errors.push(FabricIrValidationError::new(
                        field,
                        "rename-prefix transform must change the prefix",
                    ));
                }
            }
            Self::FilterFamily { .. }
            | Self::EscalateDeliveryClass { .. }
            | Self::PreserveReplySpace => {}
            Self::AttachEvidencePolicy { policy } => {
                policy.validate_at(&format!("{field}.policy"), errors);
            }
        }
    }
}

/// Service interface contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceContract {
    /// Human-readable service name.
    pub name: String,
    /// Concrete service operations.
    pub operations: Vec<ServiceOperation>,
    /// Default consumer-policy expectations.
    pub default_consumer_policy: ConsumerPolicy,
    /// Optional capability token schema name required by the service.
    pub required_capability: Option<String>,
    /// Optional quantitative obligation for the service boundary.
    pub quantitative_obligation: Option<QuantitativeObligationContract>,
}

impl Default for ServiceContract {
    fn default() -> Self {
        Self {
            name: "service".to_owned(),
            operations: vec![ServiceOperation::default()],
            default_consumer_policy: ConsumerPolicy::default(),
            required_capability: None,
            quantitative_obligation: None,
        }
    }
}

impl ServiceContract {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "service contract name must not be empty",
            ));
        }
        if self.operations.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.operations"),
                "service contract must declare at least one operation",
            ));
        }
        self.default_consumer_policy
            .validate_at(&format!("{field}.default_consumer_policy"), errors);
        if let Some(required_capability) = &self.required_capability
            && required_capability.trim().is_empty()
        {
            errors.push(FabricIrValidationError::new(
                format!("{field}.required_capability"),
                "required capability token name must not be empty",
            ));
        }
        if let Some(contract) = &self.quantitative_obligation {
            contract.validate_at(&format!("{field}.quantitative_obligation"), errors);
        }
        for (index, operation) in self.operations.iter().enumerate() {
            operation.validate_at(&format!("{field}.operations[{index}]"), errors);
        }
    }
}

/// Individual service operation declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceOperation {
    /// Operation name.
    pub name: String,
    /// Request subject pattern.
    pub request: SubjectPattern,
    /// Reply-space rule for request/reply operations.
    pub reply_space: Option<ReplySpaceRule>,
    /// Delivery class promised by the service boundary.
    pub delivery_class: DeliveryClass,
    /// Whether retries are safe without semantic duplication.
    pub idempotent: bool,
}

impl Default for ServiceOperation {
    fn default() -> Self {
        Self {
            name: "handle".to_owned(),
            request: SubjectPattern::default(),
            reply_space: Some(ReplySpaceRule::CallerInbox),
            delivery_class: DeliveryClass::default(),
            idempotent: true,
        }
    }
}

impl ServiceOperation {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "service operation name must not be empty",
            ));
        }
        self.request
            .validate_at(&format!("{field}.request"), errors);
        if let Some(rule) = &self.reply_space {
            rule.validate_at(&format!("{field}.reply_space"), errors);
        } else if self.delivery_class >= DeliveryClass::ObligationBacked {
            errors.push(FabricIrValidationError::new(
                format!("{field}.reply_space"),
                "obligation-backed and stronger service operations must declare a reply-space rule",
            ));
        }
    }
}

/// Protocol contract for session-typed interactions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolContract {
    /// Protocol name.
    pub name: String,
    /// Distinct protocol roles.
    pub roles: Vec<String>,
    /// Entry subject for protocol initiation.
    pub entry_subject: SubjectPattern,
    /// Session grammar for the protocol.
    pub session: SessionSchema,
    /// Counterfactual branch policy for replay or audit.
    pub branch_policy: BranchPolicy,
}

impl Default for ProtocolContract {
    fn default() -> Self {
        Self {
            name: "protocol".to_owned(),
            roles: vec!["caller".to_owned(), "callee".to_owned()],
            entry_subject: SubjectPattern::default(),
            session: SessionSchema::default(),
            branch_policy: BranchPolicy::default(),
        }
    }
}

impl ProtocolContract {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "protocol contract name must not be empty",
            ));
        }
        self.entry_subject
            .validate_at(&format!("{field}.entry_subject"), errors);
        self.branch_policy
            .validate_at(&format!("{field}.branch_policy"), errors);
        self.session
            .validate_at(&format!("{field}.session"), errors);

        if self.roles.len() < 2 {
            errors.push(FabricIrValidationError::new(
                format!("{field}.roles"),
                "protocol contract must declare at least two distinct roles",
            ));
        }
        validate_unique_keys(
            self.roles.iter().cloned(),
            &format!("{field}.roles"),
            "protocol role names must be unique and non-empty",
            errors,
        );

        let declared_roles = self
            .roles
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .collect::<BTreeSet<_>>();
        self.session.validate_role_references_at(
            &format!("{field}.session"),
            &declared_roles,
            errors,
        );
    }
}

/// Session-typed protocol schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSchema {
    /// Session schema name.
    pub name: String,
    /// Ordered session steps.
    pub steps: Vec<SessionStep>,
}

impl Default for SessionSchema {
    fn default() -> Self {
        Self {
            name: "session".to_owned(),
            steps: vec![SessionStep::End],
        }
    }
}

impl SessionSchema {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "session schema name must not be empty",
            ));
        }
        if self.steps.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.steps"),
                "session schema must contain at least one step",
            ));
            return;
        }

        for (index, step) in self.steps.iter().enumerate() {
            step.validate_at(&format!("{field}.steps[{index}]"), errors);
        }

        if !matches!(self.steps.last(), Some(SessionStep::End)) {
            errors.push(FabricIrValidationError::new(
                format!("{field}.steps"),
                "session schema must terminate with an `end` step",
            ));
        }
    }

    fn validate_role_references_at(
        &self,
        field: &str,
        declared_roles: &BTreeSet<&str>,
        errors: &mut Vec<FabricIrValidationError>,
    ) {
        for (index, step) in self.steps.iter().enumerate() {
            step.validate_role_references_at(
                &format!("{field}.steps[{index}]"),
                declared_roles,
                errors,
            );
        }
    }
}

/// Individual session-typed protocol step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionStep {
    /// Sender emits a message on a subject.
    Send {
        /// Role performing the send.
        role: String,
        /// Subject emitted by the role.
        subject: SubjectPattern,
    },
    /// Receiver consumes a message on a subject.
    Receive {
        /// Role performing the receive.
        role: String,
        /// Subject consumed by the role.
        subject: SubjectPattern,
    },
    /// Branching choice driven by one role.
    Choice {
        /// Role deciding which branch to take.
        decider_role: String,
        /// Branches available to the decider.
        branches: Vec<SessionBranch>,
    },
    /// Terminal step.
    End,
}

impl SessionStep {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        match self {
            Self::Send { role, subject } | Self::Receive { role, subject } => {
                if role.trim().is_empty() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.role"),
                        "session step role must not be empty",
                    ));
                }
                subject.validate_at(&format!("{field}.subject"), errors);
            }
            Self::Choice {
                decider_role,
                branches,
            } => {
                if decider_role.trim().is_empty() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.decider_role"),
                        "session choice decider role must not be empty",
                    ));
                }
                if branches.is_empty() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.branches"),
                        "session choice must include at least one branch",
                    ));
                }
                validate_unique_keys(
                    branches.iter().map(|branch| branch.label.clone()),
                    &format!("{field}.branches"),
                    "session branch labels must be unique and non-empty",
                    errors,
                );
                for (index, branch) in branches.iter().enumerate() {
                    branch.validate_at(&format!("{field}.branches[{index}]"), errors);
                }
            }
            Self::End => {}
        }
    }

    fn validate_role_references_at(
        &self,
        field: &str,
        declared_roles: &BTreeSet<&str>,
        errors: &mut Vec<FabricIrValidationError>,
    ) {
        match self {
            Self::Send { role, .. } | Self::Receive { role, .. } => {
                validate_declared_role(role, &format!("{field}.role"), declared_roles, errors)
            }
            Self::Choice {
                decider_role,
                branches,
            } => {
                validate_declared_role(
                    decider_role,
                    &format!("{field}.decider_role"),
                    declared_roles,
                    errors,
                );
                for (index, branch) in branches.iter().enumerate() {
                    branch.validate_role_references_at(
                        &format!("{field}.branches[{index}]"),
                        declared_roles,
                        errors,
                    );
                }
            }
            Self::End => {}
        }
    }
}

/// Named branch in a session choice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionBranch {
    /// Branch label.
    pub label: String,
    /// Steps executed if the branch is chosen.
    pub steps: Vec<SessionStep>,
}

impl Default for SessionBranch {
    fn default() -> Self {
        Self {
            label: "ok".to_owned(),
            steps: vec![SessionStep::End],
        }
    }
}

impl SessionBranch {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.label.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.label"),
                "session branch label must not be empty",
            ));
        }
        if self.steps.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.steps"),
                "session branch must contain at least one step",
            ));
            return;
        }
        for (index, step) in self.steps.iter().enumerate() {
            step.validate_at(&format!("{field}.steps[{index}]"), errors);
        }
        if !matches!(self.steps.last(), Some(SessionStep::End)) {
            errors.push(FabricIrValidationError::new(
                format!("{field}.steps"),
                "session branch must terminate with an `end` step",
            ));
        }
    }

    fn validate_role_references_at(
        &self,
        field: &str,
        declared_roles: &BTreeSet<&str>,
        errors: &mut Vec<FabricIrValidationError>,
    ) {
        for (index, step) in self.steps.iter().enumerate() {
            step.validate_role_references_at(
                &format!("{field}.steps[{index}]"),
                declared_roles,
                errors,
            );
        }
    }
}

/// Delivery policy configuration for consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerPolicy {
    /// Consumer policy name.
    pub name: String,
    /// Consumer durability / replay mode.
    pub mode: ConsumerMode,
    /// Delivery class expected by the consumer.
    pub delivery_class: DeliveryClass,
    /// Acknowledgement boundary emitted by the consumer.
    pub ack_kind: AckKind,
    /// Maximum buffered messages before applying backpressure.
    pub max_pending: u32,
    /// Maximum delivery attempts before policy escalation.
    pub max_deliver: u16,
    /// Optional replay window.
    pub replay_window: Option<Duration>,
}

impl Default for ConsumerPolicy {
    fn default() -> Self {
        Self {
            name: "consumer".to_owned(),
            mode: ConsumerMode::default(),
            delivery_class: DeliveryClass::default(),
            ack_kind: DeliveryClass::default().minimum_ack(),
            max_pending: 256,
            max_deliver: 1,
            replay_window: None,
        }
    }
}

impl ConsumerPolicy {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "consumer policy name must not be empty",
            ));
        }
        if self.max_pending == 0 {
            errors.push(FabricIrValidationError::new(
                format!("{field}.max_pending"),
                "consumer policy max_pending must be greater than zero",
            ));
        }
        if self.max_deliver == 0 {
            errors.push(FabricIrValidationError::new(
                format!("{field}.max_deliver"),
                "consumer policy max_deliver must be greater than zero",
            ));
        }
        if self.ack_kind < self.delivery_class.minimum_ack() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.ack_kind"),
                format!(
                    "consumer policy ack boundary `{}` is weaker than the minimum `{}` for delivery class `{}`",
                    self.ack_kind,
                    self.delivery_class.minimum_ack(),
                    self.delivery_class
                ),
            ));
        }
        match self.replay_window {
            Some(window) if window.is_zero() => errors.push(FabricIrValidationError::new(
                format!("{field}.replay_window"),
                "consumer replay window must be greater than zero when present",
            )),
            Some(_) if self.mode != ConsumerMode::Replayable => {
                errors.push(FabricIrValidationError::new(
                    format!("{field}.replay_window"),
                    "consumer replay window is only valid for replayable consumers",
                ));
            }
            None if self.mode == ConsumerMode::Replayable => {
                errors.push(FabricIrValidationError::new(
                    format!("{field}.replay_window"),
                    "replayable consumers must declare a replay window",
                ));
            }
            _ => {}
        }
    }
}

/// Consumer durability mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerMode {
    /// Stateless or best-effort consumption.
    #[default]
    Ephemeral,
    /// Durable cursor without replay inspection.
    Durable,
    /// Durable cursor with replay inspection and auditing.
    Replayable,
}

impl ConsumerMode {
    /// Exhaustive list of consumer modes.
    pub const ALL: [Self; 3] = [Self::Ephemeral, Self::Durable, Self::Replayable];
}

/// Capability token schema that binds privileges to fabric declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTokenSchema {
    /// Capability schema name.
    pub name: String,
    /// Subject families this token may authorize.
    pub families: Vec<SubjectFamily>,
    /// Delivery classes this token may request.
    pub delivery_classes: Vec<DeliveryClass>,
    /// Permissions granted by the token.
    pub permissions: Vec<CapabilityPermission>,
}

impl Default for CapabilityTokenSchema {
    fn default() -> Self {
        Self {
            name: "fabric.token".to_owned(),
            families: vec![SubjectFamily::Event],
            delivery_classes: vec![DeliveryClass::default()],
            permissions: vec![CapabilityPermission::Publish],
        }
    }
}

impl CapabilityTokenSchema {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "capability token schema name must not be empty",
            ));
        }
        if self.families.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.families"),
                "capability token schema must authorize at least one subject family",
            ));
        }
        if self.delivery_classes.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.delivery_classes"),
                "capability token schema must authorize at least one delivery class",
            ));
        }
        if self.permissions.is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.permissions"),
                "capability token schema must authorize at least one permission",
            ));
        }
    }
}

/// Capability permission granted by a token schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPermission {
    /// Publish on authorized subjects.
    #[default]
    Publish,
    /// Subscribe on authorized subjects.
    Subscribe,
    /// Initiate request/reply interactions.
    Request,
    /// Reply on authorized subjects.
    Reply,
    /// Attach or inspect counterfactual branches.
    BranchAttach,
}

impl CapabilityPermission {
    /// Exhaustive list of capability permissions.
    pub const ALL: [Self; 5] = [
        Self::Publish,
        Self::Subscribe,
        Self::Request,
        Self::Reply,
        Self::BranchAttach,
    ];
}

/// Evidence capture and retention policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePolicy {
    /// Sampling ratio in the closed interval `[0.0, 1.0]`.
    pub sampling_ratio: f64,
    /// Evidence retention policy.
    pub retention: RetentionPolicy,
    /// Whether payload hashes are recorded.
    pub record_payload_hashes: bool,
    /// Whether control transitions are always recorded.
    pub record_control_transitions: bool,
    /// Whether branch attachments are recorded.
    pub record_counterfactual_branches: bool,
}

impl Default for EvidencePolicy {
    fn default() -> Self {
        Self {
            sampling_ratio: 1.0,
            retention: RetentionPolicy::default(),
            record_payload_hashes: true,
            record_control_transitions: true,
            record_counterfactual_branches: false,
        }
    }
}

impl EvidencePolicy {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if !self.sampling_ratio.is_finite() || !(0.0..=1.0).contains(&self.sampling_ratio) {
            errors.push(FabricIrValidationError::new(
                format!("{field}.sampling_ratio"),
                format!(
                    "evidence sampling ratio must be a finite value in [0.0, 1.0], got {}",
                    self.sampling_ratio
                ),
            ));
        }
        self.retention
            .validate_at(&format!("{field}.retention"), errors);
    }
}

/// Metadata disclosure policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyPolicy {
    /// Policy name.
    pub name: String,
    /// Boundary-crossing metadata disclosure mode.
    pub metadata_disclosure: MetadataDisclosure,
    /// Whether literal subject segments should be redacted.
    pub redact_subject_literals: bool,
    /// Optional finite privacy-noise budget.
    pub noise_budget: Option<f64>,
    /// Whether cross-tenant metadata movement is allowed.
    pub allow_cross_tenant_flow: bool,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self {
            name: "privacy".to_owned(),
            metadata_disclosure: MetadataDisclosure::default(),
            redact_subject_literals: false,
            noise_budget: None,
            allow_cross_tenant_flow: false,
        }
    }
}

impl PrivacyPolicy {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "privacy policy name must not be empty",
            ));
        }
        if let Some(noise_budget) = self.noise_budget
            && (!noise_budget.is_finite() || noise_budget <= 0.0)
        {
            errors.push(FabricIrValidationError::new(
                format!("{field}.noise_budget"),
                "privacy noise budget must be a finite value greater than zero",
            ));
        }
    }
}

/// Metadata disclosure modes across boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataDisclosure {
    /// Full metadata is visible.
    Full,
    /// Metadata stays visible only as hashed or opaque identifiers.
    #[default]
    Hashed,
    /// Metadata is redacted at the boundary.
    Redacted,
}

impl MetadataDisclosure {
    /// Exhaustive list of disclosure modes.
    pub const ALL: [Self; 3] = [Self::Full, Self::Hashed, Self::Redacted];
}

/// Cut, checkpoint, and materialization policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutPolicy {
    /// Policy name.
    pub name: String,
    /// When a cut should be materialized.
    pub trigger: CutTrigger,
    /// How long the cut metadata or snapshot is retained.
    pub retention: RetentionPolicy,
    /// What degree of state gets materialized.
    pub materialization: MaterializationPolicy,
}

impl Default for CutPolicy {
    fn default() -> Self {
        Self {
            name: "cut".to_owned(),
            trigger: CutTrigger::default(),
            retention: RetentionPolicy::default(),
            materialization: MaterializationPolicy::default(),
        }
    }
}

impl CutPolicy {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "cut policy name must not be empty",
            ));
        }
        self.trigger
            .validate_at(&format!("{field}.trigger"), errors);
        self.retention
            .validate_at(&format!("{field}.retention"), errors);
    }
}

/// Trigger that decides when to create a cut.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CutTrigger {
    /// Operator- or policy-driven manual cut.
    #[default]
    Manual,
    /// Create a cut when stewardship changes.
    OnStewardshipChange,
    /// Cut when evidence reaches a threshold.
    AtEvidenceBudgetBytes {
        /// Evidence-budget threshold in bytes.
        bytes: u64,
    },
    /// Cut on a deterministic interval.
    Every {
        /// Interval between cuts.
        interval: Duration,
    },
}

impl CutTrigger {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        match self {
            Self::AtEvidenceBudgetBytes { bytes } if *bytes == 0 => {
                errors.push(FabricIrValidationError::new(
                    format!("{field}.bytes"),
                    "cut evidence budget must be greater than zero",
                ));
            }
            Self::Every { interval } if interval.is_zero() => {
                errors.push(FabricIrValidationError::new(
                    format!("{field}.interval"),
                    "cut interval must be greater than zero",
                ));
            }
            _ => {}
        }
    }
}

/// What a cut materializes when emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationPolicy {
    /// Materialize only metadata references.
    #[default]
    MetadataOnly,
    /// Materialize control-plane artifacts and cursors.
    ControlPlaneOnly,
    /// Materialize a full replayable snapshot.
    FullReplayable,
}

impl MaterializationPolicy {
    /// Exhaustive list of materialization policies.
    pub const ALL: [Self; 3] = [
        Self::MetadataOnly,
        Self::ControlPlaneOnly,
        Self::FullReplayable,
    ];
}

/// Counterfactual branch-attachment policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchPolicy {
    /// Policy name.
    pub name: String,
    /// Who may attach branches.
    pub attachment: BranchAttachment,
    /// Whether the branch may mutate or stays read-only.
    pub mutation_mode: BranchMutationMode,
    /// How long branch artifacts are retained.
    pub retention: RetentionPolicy,
}

impl Default for BranchPolicy {
    fn default() -> Self {
        Self {
            name: "branch".to_owned(),
            attachment: BranchAttachment::default(),
            mutation_mode: BranchMutationMode::default(),
            retention: RetentionPolicy::default(),
        }
    }
}

impl BranchPolicy {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "branch policy name must not be empty",
            ));
        }
        self.retention
            .validate_at(&format!("{field}.retention"), errors);
    }
}

/// Authorized branch-attachment identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchAttachment {
    /// Only the service owner may attach branches.
    #[default]
    ServiceOwnerOnly,
    /// Any matching capability holder may attach branches.
    CapabilityHolder,
    /// Only explicitly audited analysts may attach branches.
    AuditedAnalyst,
}

impl BranchAttachment {
    /// Exhaustive list of branch-attachment policies.
    pub const ALL: [Self; 3] = [
        Self::ServiceOwnerOnly,
        Self::CapabilityHolder,
        Self::AuditedAnalyst,
    ];
}

/// Whether a branch is read-only or may mutate inside a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchMutationMode {
    /// Branch cannot mutate authority-bearing state.
    #[default]
    ReadOnly,
    /// Branch may mutate inside a sandboxed control envelope.
    SandboxedMutation,
}

impl BranchMutationMode {
    /// Exhaustive list of mutation modes.
    pub const ALL: [Self; 2] = [Self::ReadOnly, Self::SandboxedMutation];
}

/// Retention policy used by evidence, cuts, and branches.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetentionPolicy {
    /// Retain nothing after the immediate action.
    #[default]
    DropImmediately,
    /// Retain for a fixed amount of time.
    RetainFor {
        /// Retention duration.
        duration: Duration,
    },
    /// Retain for a fixed number of events.
    RetainForEvents {
        /// Retention event budget.
        events: u64,
    },
    /// Retain indefinitely.
    Forever,
}

impl RetentionPolicy {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        match self {
            Self::RetainFor { duration } if duration.is_zero() => {
                errors.push(FabricIrValidationError::new(
                    format!("{field}.duration"),
                    "retention duration must be greater than zero",
                ));
            }
            Self::RetainForEvents { events } if *events == 0 => {
                errors.push(FabricIrValidationError::new(
                    format!("{field}.events"),
                    "retention event count must be greater than zero",
                ));
            }
            _ => {}
        }
    }
}

/// SLO-style quantitative contract for an obligation-bearing flow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuantitativeObligationContract {
    /// Contract name.
    pub name: String,
    /// Delivery class the quantitative contract applies to.
    pub class: DeliveryClass,
    /// Target end-to-end latency.
    pub target_latency: Duration,
    /// Probability threshold for meeting the target latency.
    pub target_probability: f64,
    /// Retry law that may be used before degrading.
    pub retry_law: RetryLaw,
    /// Degradation behavior after the retry law is exhausted.
    pub degradation_policy: DegradationPolicy,
}

impl Default for QuantitativeObligationContract {
    fn default() -> Self {
        Self {
            name: "obligation".to_owned(),
            class: DeliveryClass::default(),
            target_latency: Duration::from_millis(50),
            target_probability: 0.99,
            retry_law: RetryLaw::default(),
            degradation_policy: DegradationPolicy::default(),
        }
    }
}

impl QuantitativeObligationContract {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        if self.name.trim().is_empty() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.name"),
                "quantitative obligation contract name must not be empty",
            ));
        }
        if self.target_latency.is_zero() {
            errors.push(FabricIrValidationError::new(
                format!("{field}.target_latency"),
                "quantitative target latency must be greater than zero",
            ));
        }
        if !(self.target_probability.is_finite()
            && 0.0 < self.target_probability
            && self.target_probability <= 1.0)
        {
            errors.push(FabricIrValidationError::new(
                format!("{field}.target_probability"),
                format!(
                    "quantitative target probability must be a finite value in (0.0, 1.0], got {}",
                    self.target_probability
                ),
            ));
        }
        self.retry_law
            .validate_at(&format!("{field}.retry_law"), errors);
        self.degradation_policy.validate_at(
            &format!("{field}.degradation_policy"),
            self.class,
            errors,
        );
    }
}

/// Retry policy before degradation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetryLaw {
    /// Do not retry.
    #[default]
    Never,
    /// Retry with a fixed delay.
    Fixed {
        /// Maximum retry attempts after the first failure.
        max_retries: u16,
        /// Delay between retries.
        delay: Duration,
    },
    /// Retry with exponential backoff.
    Exponential {
        /// Maximum retry attempts after the first failure.
        max_retries: u16,
        /// Starting backoff delay.
        base_delay: Duration,
        /// Maximum backoff delay.
        max_delay: Duration,
    },
}

impl RetryLaw {
    fn validate_at(&self, field: &str, errors: &mut Vec<FabricIrValidationError>) {
        match self {
            Self::Never => {}
            Self::Fixed { max_retries, delay } => {
                if *max_retries == 0 {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.max_retries"),
                        "fixed retry law must allow at least one retry",
                    ));
                }
                if delay.is_zero() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.delay"),
                        "fixed retry delay must be greater than zero",
                    ));
                }
            }
            Self::Exponential {
                max_retries,
                base_delay,
                max_delay,
            } => {
                if *max_retries == 0 {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.max_retries"),
                        "exponential retry law must allow at least one retry",
                    ));
                }
                if base_delay.is_zero() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.base_delay"),
                        "exponential retry base delay must be greater than zero",
                    ));
                }
                if max_delay.is_zero() {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.max_delay"),
                        "exponential retry max delay must be greater than zero",
                    ));
                }
                if max_delay < base_delay {
                    errors.push(FabricIrValidationError::new(
                        format!("{field}.max_delay"),
                        "exponential retry max delay must be greater than or equal to the base delay",
                    ));
                }
            }
        }
    }
}

/// Degradation behavior after retries or budgets are exhausted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DegradationPolicy {
    /// Stop and fail the operation.
    #[default]
    FailClosed,
    /// Shed load and reject new work.
    ShedLoad,
    /// Downgrade to a weaker delivery class.
    DowngradeTo {
        /// Weaker delivery class selected after degradation.
        class: DeliveryClass,
    },
    /// Escalate evidence capture while preserving behavior.
    EscalateEvidence,
}

impl DegradationPolicy {
    fn validate_at(
        &self,
        field: &str,
        baseline_class: DeliveryClass,
        errors: &mut Vec<FabricIrValidationError>,
    ) {
        if let Self::DowngradeTo { class } = self
            && *class >= baseline_class
        {
            errors.push(FabricIrValidationError::new(
                format!("{field}.class"),
                "degradation downgrade target must be strictly weaker than the baseline delivery class",
            ));
        }
    }
}

fn validate_unique_keys<I>(
    values: I,
    field: &str,
    message: &str,
    errors: &mut Vec<FabricIrValidationError>,
) where
    I: IntoIterator<Item = String>,
{
    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim().to_owned();
        if trimmed.is_empty() || !seen.insert(trimmed) {
            errors.push(FabricIrValidationError::new(field, message));
            break;
        }
    }
}

fn validate_declared_role(
    role: &str,
    field: &str,
    declared_roles: &BTreeSet<&str>,
    errors: &mut Vec<FabricIrValidationError>,
) {
    let role = role.trim();
    if !role.is_empty() && !declared_roles.contains(role) {
        errors.push(FabricIrValidationError::new(
            field,
            format!("session role `{role}` is not declared by the protocol contract"),
        ));
    }
}

#[cfg(test)]
#[path = "ir_inline_tests.rs"]
mod tests;
