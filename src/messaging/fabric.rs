//! Foundational brokerless subject-fabric types and placement rules.
//!
//! The goal of this module is deliberately narrow: define the smallest
//! trustworthy `SubjectCell` model plus the canonical subject-partition,
//! bounded control-capsule artifacts, and deterministic placement rules that
//! later brokerless beads can build on. It does not attempt to implement the
//! full distributed data plane, federation, or consumer semantics yet.

use super::class::{AckKind, DeliveryClass};
pub use super::subject::{Subject, SubjectPattern, SubjectPatternError, SubjectToken};
use crate::cx::Cx;
use crate::distributed::HashRing;
use crate::error::{Error as AsupersyncError, ErrorKind};
use crate::remote::NodeId;
use crate::util::DetHasher;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;
use thiserror::Error;

fn fabric_input_error(message: impl Into<String>) -> AsupersyncError {
    AsupersyncError::new(ErrorKind::User).with_message(message)
}

#[allow(clippy::result_large_err)]
fn parse_subject(raw: impl AsRef<str>) -> Result<Subject, AsupersyncError> {
    Subject::parse(raw.as_ref()).map_err(|error| fabric_input_error(error.to_string()))
}

#[allow(clippy::result_large_err)]
fn parse_subject_pattern(raw: impl AsRef<str>) -> Result<SubjectPattern, AsupersyncError> {
    SubjectPattern::parse(raw.as_ref()).map_err(|error| fabric_input_error(error.to_string()))
}

fn shared_fabric_state(endpoint: &str) -> Arc<Mutex<FabricState>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, Weak<Mutex<FabricState>>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry.lock();
    registry.retain(|_, state| state.upgrade().is_some());

    if let Some(existing) = registry.get(endpoint).and_then(Weak::upgrade) {
        return existing;
    }

    let state = Arc::new(Mutex::new(FabricState::default()));
    registry.insert(endpoint.to_owned(), Arc::downgrade(&state));
    state
}

/// Minimal public Browser/Native FABRIC handle.
///
/// This surface intentionally models the NATS-small API promised by the FABRIC
/// plan without pretending the full distributed data plane is implemented yet.
/// The current behavior is an in-process semantic seam that:
///
/// - validates subjects and subject patterns,
/// - preserves explicit `&Cx` propagation on every async entry point, and
/// - keeps Layer 0 publish/subscribe on the default
///   [`DeliveryClass::EphemeralInteractive`] path.
#[derive(Debug, Clone)]
pub struct Fabric {
    endpoint: String,
    state: Arc<Mutex<FabricState>>,
}

#[derive(Debug, Default)]
struct FabricState {
    published: Vec<FabricMessage>,
}

/// Published or received packet-plane message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricMessage {
    /// Concrete subject of the message.
    pub subject: Subject,
    /// Message payload bytes.
    pub payload: Vec<u8>,
    /// Semantic class applied to the message.
    pub delivery_class: DeliveryClass,
}

/// Packet-plane publish acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReceipt {
    /// Subject accepted by the packet plane.
    pub subject: Subject,
    /// Number of payload bytes accepted.
    pub payload_len: usize,
    /// Acknowledgement boundary reached by the operation.
    pub ack_kind: AckKind,
    /// Delivery class used for the publish.
    pub delivery_class: DeliveryClass,
}

/// Request/reply response envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricReply {
    /// Reply subject echoed by the current semantic seam.
    pub subject: Subject,
    /// Reply payload bytes.
    pub payload: Vec<u8>,
    /// Acknowledgement boundary observed for the request.
    pub ack_kind: AckKind,
    /// Delivery class used for the request.
    pub delivery_class: DeliveryClass,
}

/// Capture policy for stream declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapturePolicy {
    /// Stream capture is disabled.
    #[default]
    Disabled,
    /// Capture only when the caller explicitly opts into the stream.
    ExplicitOptIn,
}

/// Public stream configuration for `Fabric::stream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricStreamConfig {
    /// Subjects captured by the stream declaration.
    pub subjects: Vec<SubjectPattern>,
    /// Requested delivery class for the stream surface.
    pub delivery_class: DeliveryClass,
    /// Capture behavior for matching packet-plane traffic.
    pub capture_policy: CapturePolicy,
    /// Optional request timeout carried into stream operations.
    pub request_timeout: Option<Duration>,
}

impl Default for FabricStreamConfig {
    fn default() -> Self {
        Self {
            subjects: Vec::new(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            capture_policy: CapturePolicy::ExplicitOptIn,
            request_timeout: None,
        }
    }
}

impl FabricStreamConfig {
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), AsupersyncError> {
        if self.subjects.is_empty() {
            return Err(AsupersyncError::new(ErrorKind::ConfigError)
                .with_message("stream config must declare at least one subject pattern"));
        }

        SubjectPattern::validate_non_overlapping(&self.subjects)
            .map_err(|error| fabric_input_error(error.to_string()))?;
        Ok(())
    }
}

/// Ergonomic alias matching the planned user-facing `stream(...)` example.
pub type StreamConfig = FabricStreamConfig;

/// Handle returned by `Fabric::stream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricStreamHandle {
    endpoint: String,
    config: FabricStreamConfig,
}

impl FabricStreamHandle {
    /// Return the configured stream declaration.
    #[must_use]
    pub fn config(&self) -> &FabricStreamConfig {
        &self.config
    }

    /// Return the endpoint that created the stream declaration.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Subscription handle returned by `Fabric::subscribe`.
#[derive(Debug, Clone)]
pub struct FabricSubscription {
    pattern: SubjectPattern,
    next_index: usize,
    state: Arc<Mutex<FabricState>>,
}

impl FabricSubscription {
    /// Return the subscribed pattern.
    #[must_use]
    pub fn pattern(&self) -> &SubjectPattern {
        &self.pattern
    }

    /// Return the next matching message, if one is currently available.
    ///
    /// Cancellation propagates by returning `None` once the supplied `Cx`
    /// observes a cancellation request.
    #[allow(clippy::unused_async)]
    pub async fn next(&mut self, cx: &Cx) -> Option<FabricMessage> {
        if cx.checkpoint().is_err() {
            return None;
        }

        let state = self.state.lock();
        let published = &state.published;

        while self.next_index < published.len() {
            let message = published[self.next_index].clone();
            self.next_index += 1;
            if self.pattern.matches(&message.subject) {
                drop(state);
                return Some(message);
            }
        }
        drop(state);

        None
    }
}

impl Fabric {
    /// Connect to a known fabric endpoint.
    #[allow(clippy::unused_async)]
    pub async fn connect(cx: &Cx, endpoint: impl AsRef<str>) -> Result<Self, AsupersyncError> {
        cx.checkpoint()?;

        let endpoint = endpoint.as_ref().trim();
        if endpoint.is_empty() {
            return Err(AsupersyncError::new(ErrorKind::ConfigError)
                .with_message("fabric endpoint must not be empty"));
        }

        Ok(Self {
            endpoint: endpoint.to_owned(),
            state: shared_fabric_state(endpoint),
        })
    }

    /// Return the endpoint used for the current handle.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Publish a packet-plane message with the default delivery class.
    #[allow(clippy::unused_async)]
    pub async fn publish(
        &self,
        cx: &Cx,
        subject: impl AsRef<str>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<PublishReceipt, AsupersyncError> {
        cx.checkpoint()?;

        let subject = parse_subject(subject)?;
        let payload = payload.into();
        let message = FabricMessage {
            subject: subject.clone(),
            payload: payload.clone(),
            delivery_class: DeliveryClass::EphemeralInteractive,
        };
        self.state.lock().published.push(message);

        Ok(PublishReceipt {
            subject,
            payload_len: payload.len(),
            ack_kind: AckKind::Accepted,
            delivery_class: DeliveryClass::EphemeralInteractive,
        })
    }

    /// Subscribe to a packet-plane subject pattern.
    #[allow(clippy::unused_async)]
    pub async fn subscribe(
        &self,
        cx: &Cx,
        subject_pattern: impl AsRef<str>,
    ) -> Result<FabricSubscription, AsupersyncError> {
        cx.checkpoint()?;
        let next_index = self.state.lock().published.len();

        Ok(FabricSubscription {
            pattern: parse_subject_pattern(subject_pattern)?,
            // Layer-0 FABRIC models packet-plane pub/sub rather than durable
            // replay, so subscriptions observe publishes from the subscription
            // point forward even when endpoint state is shared across handles.
            next_index,
            state: Arc::clone(&self.state),
        })
    }

    /// Issue a bounded request/reply interaction.
    ///
    /// The current API-design seam performs an immediate loopback reply so the
    /// public surface is testable before the full authority/data plane lands.
    pub async fn request(
        &self,
        cx: &Cx,
        subject: impl AsRef<str>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<FabricReply, AsupersyncError> {
        let payload = payload.into();
        let receipt = self.publish(cx, subject, payload.clone()).await?;

        Ok(FabricReply {
            subject: receipt.subject,
            payload,
            ack_kind: receipt.ack_kind,
            delivery_class: receipt.delivery_class,
        })
    }

    /// Opt into a stream declaration with explicit configuration.
    #[allow(clippy::unused_async)]
    pub async fn stream(
        &self,
        cx: &Cx,
        config: FabricStreamConfig,
    ) -> Result<FabricStreamHandle, AsupersyncError> {
        cx.checkpoint()?;
        config.validate()?;

        Ok(FabricStreamHandle {
            endpoint: self.endpoint.clone(),
            config,
        })
    }
}

/// Compact identifier for a subject cell.
///
/// `CellId` is deterministic for a given canonical subject partition and
/// membership epoch so replay and placement evidence stay stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(u128);

impl CellId {
    /// Derive a stable cell id for the given subject partition and epoch.
    #[must_use]
    pub fn for_partition(epoch: CellEpoch, subject_partition: &SubjectPattern) -> Self {
        let canonical = subject_partition.canonical_key();
        let lower = stable_hash((
            "subject-cell",
            epoch.membership_epoch,
            epoch.generation,
            &canonical,
        ));
        let upper = stable_hash((
            "subject-cell:v2",
            epoch.membership_epoch,
            epoch.generation,
            &canonical,
        ));
        Self((u128::from(upper) << 64) | u128::from(lower))
    }

    /// Return the raw 128-bit identifier.
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }
}

impl fmt::Display for CellId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cell-{:032x}", self.0)
    }
}

/// Membership epoch and local generation for a subject cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellEpoch {
    /// Cluster or roster epoch used for placement.
    pub membership_epoch: u64,
    /// Per-cell generation inside the membership epoch.
    pub generation: u64,
}

impl CellEpoch {
    /// Create a new cell epoch descriptor.
    #[must_use]
    pub const fn new(membership_epoch: u64, generation: u64) -> Self {
        Self {
            membership_epoch,
            generation,
        }
    }

    /// Advance the per-cell generation while keeping the membership epoch.
    #[must_use]
    pub const fn next_generation(self) -> Self {
        Self {
            membership_epoch: self.membership_epoch,
            generation: self.generation + 1,
        }
    }
}

impl SubjectPattern {
    /// Aggregate ephemeral reply subjects before placement.
    ///
    /// This intentionally collapses reply-space suffix churn so fabric cells do
    /// not explode on per-request inbox identifiers.
    #[must_use]
    pub fn aggregate_reply_space(&self, policy: ReplySpaceCompactionPolicy) -> Self {
        if !policy.enabled
            || !self.is_reply_subject()
            || self.segments().len() <= policy.preserve_segments
        {
            return self.clone();
        }

        let keep = policy.preserve_segments.max(1).min(self.segments().len());
        let mut segments = self.segments()[..keep].to_vec();
        if !matches!(segments.last(), Some(SubjectToken::Tail)) {
            segments.push(SubjectToken::Tail);
        }
        Self::from_tokens(segments).expect("reply-space compaction must produce a valid pattern")
    }

    /// Validate that the provided set of patterns is pairwise non-overlapping.
    #[allow(clippy::result_large_err)]
    pub fn validate_non_overlapping(patterns: &[Self]) -> Result<(), FabricError> {
        for (index, left) in patterns.iter().enumerate() {
            for right in patterns.iter().skip(index + 1) {
                if left.overlaps(right) {
                    return Err(FabricError::OverlappingSubjectPartitions {
                        left: left.clone(),
                        right: right.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn is_reply_subject(&self) -> bool {
        matches!(
            self.segments().first(),
            Some(SubjectToken::Literal(prefix))
                if prefix == "_INBOX" || prefix == "_RPLY" || prefix == "reply"
        )
    }

    fn literal_segments(&self) -> Result<Vec<String>, SubjectPatternError> {
        self.segments()
            .iter()
            .map(|segment| match segment {
                SubjectToken::Literal(value) => Ok(value.clone()),
                SubjectToken::One | SubjectToken::Tail => Err(
                    SubjectPatternError::LiteralOnlyPatternRequired(self.canonical_key()),
                ),
            })
            .collect()
    }
}

/// Reply-space compaction settings applied before placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplySpaceCompactionPolicy {
    /// Whether reply-space aggregation is enabled.
    pub enabled: bool,
    /// Number of leading segments to keep before collapsing the suffix.
    pub preserve_segments: usize,
}

impl Default for ReplySpaceCompactionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            preserve_segments: 3,
        }
    }
}

/// Deterministic literal-prefix rewrite applied before placement.
///
/// This models the "import/export morphism" stage from the fabric plan without
/// allowing wildcard-bearing rewrites that would re-introduce ambiguity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPrefixMorphism {
    from: Vec<String>,
    to: Vec<String>,
}

impl SubjectPrefixMorphism {
    /// Create a new literal-prefix rewrite.
    pub fn new(from: &str, to: &str) -> Result<Self, SubjectPatternError> {
        let from = SubjectPattern::parse(from)?;
        let to = SubjectPattern::parse(to)?;

        Ok(Self {
            from: from.literal_segments()?,
            to: to.literal_segments()?,
        })
    }

    fn apply(&self, pattern: &SubjectPattern) -> Option<SubjectPattern> {
        if pattern.segments().len() < self.from.len() {
            return None;
        }

        let mut remainder = Vec::new();
        for (index, segment) in pattern.segments().iter().enumerate() {
            let Some(expected) = self.from.get(index) else {
                remainder.push(segment.clone());
                continue;
            };

            match segment {
                SubjectToken::Literal(value) if value == expected => {}
                _ => return None,
            }
        }

        let mut rewritten = self
            .to
            .iter()
            .cloned()
            .map(SubjectToken::Literal)
            .collect::<Vec<_>>();
        rewritten.extend(remainder);
        Some(
            SubjectPattern::from_tokens(rewritten)
                .expect("rewritten literal-prefix morphism must stay syntactically valid"),
        )
    }
}

/// Canonicalization pipeline that runs before subject-cell placement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NormalizationPolicy {
    /// Ordered literal-prefix rewrites that canonicalize alias subject spaces.
    pub morphisms: Vec<SubjectPrefixMorphism>,
    /// Reply-space aggregation policy applied after morphisms.
    pub reply_space_policy: ReplySpaceCompactionPolicy,
}

impl NormalizationPolicy {
    /// Produce the authoritative canonical subject partition used for placement.
    #[allow(clippy::result_large_err)]
    pub fn normalize(&self, pattern: &SubjectPattern) -> Result<SubjectPattern, FabricError> {
        let mut canonical = pattern.clone();
        let mut seen = BTreeSet::from([canonical.canonical_key()]);
        let mut index = 0;

        while index < self.morphisms.len() {
            let Some(candidate) = self.morphisms[index].apply(&canonical) else {
                index += 1;
                continue;
            };

            for other in self.morphisms.iter().skip(index + 1) {
                let Some(other_candidate) = other.apply(&canonical) else {
                    continue;
                };
                if candidate != other_candidate {
                    return Err(FabricError::ConflictingSubjectMorphisms {
                        subject: pattern.clone(),
                        left: candidate,
                        right: other_candidate,
                    });
                }
            }

            if candidate == canonical {
                index += 1;
                continue;
            }

            if !seen.insert(candidate.canonical_key()) {
                return Err(FabricError::CyclicSubjectMorphisms {
                    subject: pattern.clone(),
                    cycle_point: candidate,
                });
            }

            canonical = candidate;
            index = 0;
        }

        Ok(canonical.aggregate_reply_space(self.reply_space_policy))
    }
}

/// Coarse cell traffic temperature used to scale stewardship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellTemperature {
    /// Minimal steward footprint for cold partitions.
    Cold,
    /// Intermediate steward footprint.
    Warm,
    /// Wider steward set for hot partitions.
    Hot,
}

/// Observed load signal used to steer temperature transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedCellLoad {
    /// Approximate publish arrival rate for the cell.
    pub publishes_per_second: u64,
}

impl ObservedCellLoad {
    /// Create a simple load sample from a publish rate estimate.
    #[must_use]
    pub const fn new(publishes_per_second: u64) -> Self {
        Self {
            publishes_per_second,
        }
    }
}

/// Hysteresis thresholds that damp steward-set temperature changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThermalHysteresis {
    /// Promote cold cells to warm once this rate is reached.
    pub cold_to_warm_publishes_per_second: u64,
    /// Demote warm cells back to cold only once load falls below this rate.
    pub warm_to_cold_publishes_per_second: u64,
    /// Promote warm cells to hot once this rate is reached.
    pub warm_to_hot_publishes_per_second: u64,
    /// Demote hot cells back to warm only once load falls below this rate.
    pub hot_to_warm_publishes_per_second: u64,
}

impl Default for ThermalHysteresis {
    fn default() -> Self {
        Self {
            cold_to_warm_publishes_per_second: 128,
            warm_to_cold_publishes_per_second: 48,
            warm_to_hot_publishes_per_second: 1_024,
            hot_to_warm_publishes_per_second: 512,
        }
    }
}

/// Explicit budget limiting how aggressively a steward set may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebalanceBudget {
    /// Maximum node additions/removals allowed in a single rebalance step.
    pub max_steward_changes: usize,
}

impl Default for RebalanceBudget {
    fn default() -> Self {
        Self {
            max_steward_changes: 2,
        }
    }
}

/// Incremental steward-set transition plan under hysteresis and budget limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalancePlan {
    /// Temperature recommended after applying hysteresis to the observed load.
    pub next_temperature: CellTemperature,
    /// Steward set after applying the rebalance budget to the desired target.
    pub next_stewards: Vec<NodeId>,
    /// Newly added stewards in this incremental rebalance step.
    pub added_stewards: Vec<NodeId>,
    /// Stewards removed in this incremental rebalance step.
    pub removed_stewards: Vec<NodeId>,
}

/// Repair-material binding captured for one steward or repair witness while a
/// rebalance cut is being certified.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepairSymbolBinding {
    /// Repair-capable node that collected the material.
    pub node_id: NodeId,
    /// Cell epoch the material belongs to.
    pub cell_epoch: CellEpoch,
    /// Retention generation the symbols were derived from.
    pub retention_generation: u64,
}

impl RepairSymbolBinding {
    /// Construct a repair-symbol binding for one repair-capable node.
    #[must_use]
    pub const fn new(node_id: NodeId, cell_epoch: CellEpoch, retention_generation: u64) -> Self {
        Self {
            node_id,
            cell_epoch,
            retention_generation,
        }
    }
}

/// Explicit transfer summary that proves a rebalance cut does not strand live
/// publish, consumer, or reply obligations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalanceObligationSummary {
    /// Number of unresolved publish obligations below the cut frontier.
    pub publish_obligations_below_cut: usize,
    /// Number of active consumer leases that must move or be reissued.
    pub active_consumer_leases: usize,
    /// Number of consumer leases explicitly transferred or reissued.
    pub transferred_consumer_leases: usize,
    /// Number of consumers still reporting ambiguous lease ownership.
    pub ambiguous_consumer_lease_owners: usize,
    /// Number of active reply rights at the cut frontier.
    pub active_reply_rights: usize,
    /// Number of reply rights explicitly reissued onto the next epoch.
    pub reissued_reply_rights: usize,
    /// Number of dangling reply rights that would become ownerless.
    pub dangling_reply_rights: usize,
}

/// Semantic-cut evidence attached to a steward-set rebalance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalanceCutEvidence {
    /// Steward that will hold append and cursor authority after the cut.
    pub next_sequencer: NodeId,
    /// Retention generation against which repair material was captured.
    pub retention_generation: u64,
    /// Explicit obligation-transfer proof attached to the cut.
    pub obligation_summary: RebalanceObligationSummary,
    /// Repair symbol bindings collected by next stewards and witnesses.
    pub repair_symbols: Vec<RepairSymbolBinding>,
}

/// Certified outcome of a steward-set self-rebalance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedRebalance {
    /// Authoritative append proving the cut was decided under the prior epoch.
    pub control_append: AppendCertificate,
    /// In-band joint configuration entry fencing the old steward lease.
    pub joint_config: JointConfigEntry,
    /// Incremental rebalance plan that was certified.
    pub plan: RebalancePlan,
    /// Canonical semantic-cut evidence attached to the certification.
    pub cut_evidence: RebalanceCutEvidence,
    /// Removed stewards whose old authority must now drain.
    pub drained_stewards: Vec<NodeId>,
    /// Resulting subject cell after the certified cut and epoch advance.
    pub resulting_cell: SubjectCell,
}

/// Storage class used during steward negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageClass {
    /// Ephemeral memory-only participation.
    Ephemeral,
    /// General durable node.
    Standard,
    /// Durable or archival-capable node.
    Durable,
}

/// Health tier used during steward negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StewardHealth {
    /// Fully eligible and healthy.
    Healthy,
    /// Eligible but less preferred.
    Degraded,
    /// Draining; still visible but last resort.
    Draining,
    /// Not eligible for stewardship.
    Unavailable,
}

/// Logical role a node may play inside the subject fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeRole {
    /// Publisher or request originator for a subject flow.
    Origin,
    /// Passive subscriber consuming pushed messages.
    Subscriber,
    /// Stateful consumer with explicit cursor or delivery ownership.
    Consumer,
    /// Node eligible to steward the control and data capsules of a cell.
    Steward,
    /// Node eligible to store repair symbols outside the active steward quorum.
    RepairWitness,
    /// Node allowed to relay traffic across topology boundaries.
    Bridge,
}

/// Candidate node used during steward placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StewardCandidate {
    /// Stable identity of the candidate node.
    pub node_id: NodeId,
    /// Logical roles currently available on the node.
    pub roles: BTreeSet<NodeRole>,
    /// Current health state used during placement scoring.
    pub health: StewardHealth,
    /// Durability tier offered by the node.
    pub storage_class: StorageClass,
    /// Failure-domain label used to diversify steward placement.
    pub failure_domain: String,
    /// Measured or budgeted one-way latency envelope in milliseconds.
    pub latency_millis: u32,
}

impl StewardCandidate {
    /// Create a new candidate with conservative defaults.
    #[must_use]
    pub fn new(node_id: NodeId, failure_domain: impl Into<String>) -> Self {
        Self {
            node_id,
            roles: BTreeSet::new(),
            health: StewardHealth::Healthy,
            storage_class: StorageClass::Standard,
            failure_domain: failure_domain.into(),
            latency_millis: 10,
        }
    }

    /// Mark the candidate with an additional role.
    #[must_use]
    pub fn with_role(mut self, role: NodeRole) -> Self {
        self.roles.insert(role);
        self
    }

    /// Override the candidate health.
    #[must_use]
    pub fn with_health(mut self, health: StewardHealth) -> Self {
        self.health = health;
        self
    }

    /// Override the storage class.
    #[must_use]
    pub fn with_storage_class(mut self, storage_class: StorageClass) -> Self {
        self.storage_class = storage_class;
        self
    }

    /// Override the measured latency envelope.
    #[must_use]
    pub fn with_latency_millis(mut self, latency_millis: u32) -> Self {
        self.latency_millis = latency_millis;
        self
    }

    /// Return true when the node is currently eligible to act as a steward.
    #[must_use]
    pub fn is_steward_eligible(&self) -> bool {
        self.roles.contains(&NodeRole::Steward) && self.health != StewardHealth::Unavailable
    }

    /// Return true when the node can also act as a repair witness.
    #[must_use]
    pub fn can_repair(&self) -> bool {
        self.roles.contains(&NodeRole::RepairWitness) || self.is_steward_eligible()
    }
}

/// Foundational placement policy for a `SubjectCell`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementPolicy {
    /// Virtual node count used by the deterministic hash ring.
    pub vnodes_per_node: usize,
    /// Number of candidate nodes to consider before final negotiation.
    pub candidate_pool_size: usize,
    /// Target steward count for cold cells.
    pub cold_stewards: usize,
    /// Target steward count for warm cells.
    pub warm_stewards: usize,
    /// Target steward count for hot cells.
    pub hot_stewards: usize,
    /// Soft latency cap for preferred candidates.
    pub max_latency_millis: u32,
    /// Load thresholds used to damp temperature transitions.
    pub thermal_hysteresis: ThermalHysteresis,
    /// Budget limiting how many steward moves one rebalance may perform.
    pub rebalance_budget: RebalanceBudget,
    /// Canonicalization rules applied before consistent hashing.
    pub normalization: NormalizationPolicy,
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        Self {
            vnodes_per_node: 64,
            candidate_pool_size: 6,
            cold_stewards: 1,
            warm_stewards: 3,
            hot_stewards: 5,
            max_latency_millis: 150,
            thermal_hysteresis: ThermalHysteresis::default(),
            rebalance_budget: RebalanceBudget::default(),
            normalization: NormalizationPolicy::default(),
        }
    }
}

impl PlacementPolicy {
    /// Recommend the next cell temperature from the current load sample.
    #[must_use]
    pub fn recommend_temperature(
        &self,
        current: CellTemperature,
        observed_load: ObservedCellLoad,
    ) -> CellTemperature {
        let rate = observed_load.publishes_per_second;

        match current {
            CellTemperature::Cold => {
                if rate >= self.thermal_hysteresis.warm_to_hot_publishes_per_second {
                    CellTemperature::Hot
                } else if rate >= self.thermal_hysteresis.cold_to_warm_publishes_per_second {
                    CellTemperature::Warm
                } else {
                    CellTemperature::Cold
                }
            }
            CellTemperature::Warm => {
                if rate >= self.thermal_hysteresis.warm_to_hot_publishes_per_second {
                    CellTemperature::Hot
                } else if rate <= self.thermal_hysteresis.warm_to_cold_publishes_per_second {
                    CellTemperature::Cold
                } else {
                    CellTemperature::Warm
                }
            }
            CellTemperature::Hot => {
                if rate <= self.thermal_hysteresis.hot_to_warm_publishes_per_second {
                    CellTemperature::Warm
                } else {
                    CellTemperature::Hot
                }
            }
        }
    }

    fn target_steward_count(&self, temperature: CellTemperature) -> usize {
        match temperature {
            CellTemperature::Cold => self.cold_stewards,
            CellTemperature::Warm => self.warm_stewards,
            CellTemperature::Hot => self.hot_stewards,
        }
    }

    /// Plan an incremental steward-set transition subject to the rebalance budget.
    #[allow(clippy::result_large_err)]
    pub fn plan_rebalance(
        &self,
        subject_partition: &SubjectPattern,
        candidates: &[StewardCandidate],
        current_stewards: &[NodeId],
        current_temperature: CellTemperature,
        observed_load: ObservedCellLoad,
    ) -> Result<RebalancePlan, FabricError> {
        let next_temperature = self.recommend_temperature(current_temperature, observed_load);
        let canonical_partition = self.normalization.normalize(subject_partition)?;
        let desired_stewards =
            self.select_stewards(&canonical_partition, candidates, next_temperature)?;
        let next_stewards = self.advance_toward_desired(
            current_stewards,
            &desired_stewards,
            self.target_steward_count(next_temperature),
        );

        let added_stewards = next_stewards
            .iter()
            .filter(|node| !contains_node(current_stewards, node))
            .cloned()
            .collect();
        let removed_stewards = current_stewards
            .iter()
            .filter(|node| !contains_node(&next_stewards, node))
            .cloned()
            .collect();

        Ok(RebalancePlan {
            next_temperature,
            next_stewards,
            added_stewards,
            removed_stewards,
        })
    }

    #[allow(clippy::result_large_err)]
    fn candidate_pool<'a>(
        &self,
        subject_partition: &SubjectPattern,
        candidates: &'a [StewardCandidate],
        temperature: CellTemperature,
    ) -> Result<Vec<&'a StewardCandidate>, FabricError> {
        let eligible: Vec<&StewardCandidate> = candidates
            .iter()
            .filter(|candidate| candidate.is_steward_eligible())
            .collect();
        if eligible.is_empty() {
            return Err(FabricError::NoStewardCandidates {
                partition: subject_partition.clone(),
            });
        }

        let required = self
            .candidate_pool_size
            .max(self.target_steward_count(temperature))
            .min(eligible.len());

        let mut ring = HashRing::new(self.vnodes_per_node.max(1));
        let mut by_node = BTreeMap::new();
        for candidate in &eligible {
            let key = candidate.node_id.as_str().to_string();
            ring.add_node(key.clone());
            by_node.insert(key, *candidate);
        }

        let subject_key = subject_partition.canonical_key();
        let mut pool = Vec::new();
        let mut seen = BTreeSet::new();
        for salt in 0_u64.. {
            if pool.len() >= required || seen.len() >= eligible.len() {
                break;
            }
            let lookup = (&subject_key, salt);
            let Some(node_id) = ring.node_for_key(&lookup) else {
                break;
            };
            if !seen.insert(node_id.to_string()) {
                continue;
            }
            if let Some(candidate) = by_node.get(node_id) {
                pool.push(*candidate);
            }
        }

        Ok(pool)
    }

    #[allow(clippy::result_large_err)]
    fn select_stewards(
        &self,
        subject_partition: &SubjectPattern,
        candidates: &[StewardCandidate],
        temperature: CellTemperature,
    ) -> Result<Vec<NodeId>, FabricError> {
        let pool = self.candidate_pool(subject_partition, candidates, temperature)?;
        let target = self.target_steward_count(temperature).min(pool.len());
        if target == 0 {
            return Err(FabricError::NoStewardCandidates {
                partition: subject_partition.clone(),
            });
        }

        let mut preferred: Vec<&StewardCandidate> = pool
            .iter()
            .copied()
            .filter(|candidate| candidate.latency_millis <= self.max_latency_millis)
            .collect();
        let mut fallback: Vec<&StewardCandidate> = pool
            .iter()
            .copied()
            .filter(|candidate| candidate.latency_millis > self.max_latency_millis)
            .collect();

        preferred.sort_by(|left, right| compare_candidates(left, right, temperature));
        fallback.sort_by(|left, right| compare_candidates(left, right, temperature));
        preferred.extend(fallback);

        let mut selected = Vec::with_capacity(target);
        let mut selected_ids = BTreeSet::new();
        let mut used_domains = BTreeSet::new();

        for candidate in &preferred {
            if selected.len() >= target {
                break;
            }
            if !used_domains.insert(candidate.failure_domain.clone()) {
                continue;
            }
            selected_ids.insert(candidate.node_id.as_str().to_string());
            selected.push(candidate.node_id.clone());
        }

        for candidate in preferred {
            if selected.len() >= target {
                break;
            }
            if !selected_ids.insert(candidate.node_id.as_str().to_string()) {
                continue;
            }
            selected.push(candidate.node_id.clone());
        }

        Ok(selected)
    }

    fn advance_toward_desired(
        &self,
        current_stewards: &[NodeId],
        desired_stewards: &[NodeId],
        target_len: usize,
    ) -> Vec<NodeId> {
        let desired_ids = desired_stewards
            .iter()
            .map(NodeId::as_str)
            .collect::<BTreeSet<_>>();
        let mut remaining_budget = self.rebalance_budget.max_steward_changes;
        let mut next = current_stewards.to_vec();

        while next.len() > target_len && remaining_budget > 0 {
            let remove_index = next
                .iter()
                .rposition(|node| !desired_ids.contains(node.as_str()))
                .unwrap_or_else(|| next.len().saturating_sub(1));
            next.remove(remove_index);
            remaining_budget = remaining_budget.saturating_sub(1);
        }

        for desired in desired_stewards {
            if contains_node(&next, desired) {
                continue;
            }

            if next.len() < target_len {
                if remaining_budget == 0 {
                    break;
                }
                next.push(desired.clone());
                remaining_budget = remaining_budget.saturating_sub(1);
                continue;
            }

            let Some(remove_index) = next
                .iter()
                .rposition(|node| !desired_ids.contains(node.as_str()))
            else {
                continue;
            };
            if remaining_budget < 2 {
                break;
            }
            next.remove(remove_index);
            remaining_budget = remaining_budget.saturating_sub(1);
            next.push(desired.clone());
            remaining_budget = remaining_budget.saturating_sub(1);
        }

        next
    }
}

/// Control-plane epoch fenced into brokerless control artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlEpoch {
    /// Placement epoch used for the current subject cell.
    pub cell_epoch: CellEpoch,
    /// Monotonic control-plane revision inside the cell epoch.
    pub policy_revision: u64,
}

impl ControlEpoch {
    /// Construct the current control epoch for a subject cell.
    #[must_use]
    pub const fn new(cell_epoch: CellEpoch, policy_revision: u64) -> Self {
        Self {
            cell_epoch,
            policy_revision,
        }
    }

    #[must_use]
    const fn bump_policy(self) -> Self {
        Self {
            cell_epoch: self.cell_epoch,
            policy_revision: self.policy_revision + 1,
        }
    }
}

/// Lease proving that one steward currently owns authoritative append rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerLease {
    /// Steward currently allowed to append control-log decisions.
    pub holder: NodeId,
    /// Control epoch for which the lease is valid.
    pub control_epoch: ControlEpoch,
    /// Fence generation invalidating older authority artifacts.
    pub fence_generation: u64,
}

/// Unique identity of one authoritative append in the control log.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlAppendIdentity {
    /// Subject cell that owns the append.
    pub cell_id: CellId,
    /// Cell epoch the append belongs to.
    pub epoch: CellEpoch,
    /// Monotonic sequence number inside the epoch.
    pub sequence: u64,
}

/// Commit proof emitted for one authoritative control-log append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendCertificate {
    /// Unique identity of the committed append.
    pub identity: ControlAppendIdentity,
    /// Steward that held append authority for the decision.
    pub sequencer: NodeId,
    /// Control epoch for the append.
    pub control_epoch: ControlEpoch,
    /// Fence generation under which the append was committed.
    pub fence_generation: u64,
}

/// Joint-consensus reconfiguration entry kept in-band with the control log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JointConfigEntry {
    /// Control epoch after the reconfiguration decision.
    pub control_epoch: ControlEpoch,
    /// Prior steward set that still overlaps the new decision set.
    pub old_stewards: Vec<NodeId>,
    /// New steward set activated by the decision.
    pub new_stewards: Vec<NodeId>,
    /// Sequencer installed for the next decision window.
    pub next_sequencer: NodeId,
    /// Fence generation that invalidates older authority artifacts.
    pub fence_generation: u64,
}

/// Fence artifact proving that a prior sequencer lease is stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceToken {
    /// Control epoch for the fencing decision.
    pub control_epoch: ControlEpoch,
    /// Sequencer that just lost authority.
    pub previous_holder: NodeId,
    /// Sequencer that now owns authority.
    pub next_holder: NodeId,
    /// Fence generation that invalidates the previous lease.
    pub fence_generation: u64,
}

/// Fenced lease for consumer-control authority within a subject cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorAuthorityLease {
    /// Holder currently allowed to issue cursor-control decisions.
    pub holder: NodeId,
    /// Control epoch for which the lease is valid.
    pub control_epoch: ControlEpoch,
    /// Fence generation invalidating older cursor-authority leases.
    pub fence_generation: u64,
}

/// Shared control shard assignment for cold or low-rate cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedControlShard {
    /// Shared shard identity carrying the packed control stream.
    pub shard_id: String,
    /// Slot occupied by this cell within the shard.
    pub slot_index: usize,
    /// Maximum number of cells admitted to the shard.
    pub cardinality_limit: usize,
}

/// Deterministic outcome when a replica or late delivery response presents an
/// append certificate to the control capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicatedAppendOutcome {
    /// The append was newly committed.
    Committed(AppendCertificate),
    /// The append was already committed with the same identity and certificate.
    IdempotentNoop(AppendCertificate),
    /// The append belongs to a fenced control generation and must be rejected.
    StaleReject {
        /// Identity of the rejected append.
        identity: ControlAppendIdentity,
        /// Fence generation carried by the rejected append.
        attempted_fence_generation: u64,
        /// Current fence generation of the capsule.
        current_fence_generation: u64,
    },
}

/// Validation failure while mutating the bounded control capsule.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlCapsuleError {
    /// Authoritative appends require an active sequencer lease.
    #[error("control capsule has no active sequencer lease")]
    NoActiveSequencer,
    /// Cursor-control decisions require an active cursor-authority lease.
    #[error("control capsule has no active cursor-authority lease")]
    NoCursorAuthority,
    /// The requested steward is not part of the active steward pool.
    #[error("node `{node}` is not part of the active steward pool")]
    UnknownSteward {
        /// Node that failed membership validation.
        node: NodeId,
    },
    /// A stale sequencer lease attempted to emit a control-log append.
    #[error(
        "sequencer lease for `{holder}` at fence generation {fence_generation} is stale (current holder `{current_holder}`, current fence generation {current_fence_generation})"
    )]
    StaleSequencerLease {
        /// Holder that attempted the stale append.
        holder: NodeId,
        /// Fence generation carried by the stale lease.
        fence_generation: u64,
        /// Holder of the current live lease.
        current_holder: NodeId,
        /// Capsule fence generation after the latest authoritative change.
        current_fence_generation: u64,
    },
    /// A stale cursor-authority lease attempted a control decision.
    #[error(
        "cursor authority lease for `{holder}` at fence generation {fence_generation} is stale (current holder `{current_holder}`, current fence generation {current_fence_generation})"
    )]
    StaleCursorAuthorityLease {
        /// Holder that attempted the stale decision.
        holder: NodeId,
        /// Fence generation carried by the stale cursor lease.
        fence_generation: u64,
        /// Holder of the current live cursor-authority lease.
        current_holder: NodeId,
        /// Capsule fence generation after the latest authoritative change.
        current_fence_generation: u64,
    },
    /// Two different append certificates tried to claim the same append
    /// identity.
    #[error("append identity `{identity:?}` is already committed with different contents")]
    ConflictingAppendIdentity {
        /// Identity that collided with an existing committed append.
        identity: ControlAppendIdentity,
    },
    /// Replicated append certificates must belong to the current cell.
    #[error(
        "append identity `{identity:?}` belongs to cell `{actual}`, but this capsule owns `{expected}`"
    )]
    WrongCell {
        /// Identity that failed validation.
        identity: ControlAppendIdentity,
        /// Cell owned by this capsule.
        expected: CellId,
        /// Cell carried by the replicated certificate.
        actual: CellId,
    },
    /// Replicated append certificates must belong to the current cell epoch.
    #[error(
        "append identity `{identity:?}` belongs to epoch `{actual:?}`, but this capsule is on `{expected:?}`"
    )]
    WrongEpoch {
        /// Identity that failed validation.
        identity: ControlAppendIdentity,
        /// Cell epoch owned by this capsule.
        expected: CellEpoch,
        /// Cell epoch carried by the replicated certificate.
        actual: CellEpoch,
    },
    /// Joint consensus requires an overlap set between old and new stewards.
    #[error("joint configuration must retain at least one steward across the transition")]
    JointConfigRequiresOverlap,
    /// Joint consensus steward sets must contain distinct members.
    #[error("joint configuration contains duplicate steward `{node}`")]
    DuplicateSteward {
        /// Duplicate steward discovered in the proposed steward set.
        node: NodeId,
    },
    /// Shared control shards must admit at least one slot.
    #[error("shared control shard cardinality limit must be at least 1")]
    InvalidSharedShardLimit,
    /// Slot indexes outside the shard cardinality bound are invalid.
    #[error(
        "shared control shard `{shard_id}` slot {slot_index} exceeds cardinality limit {cardinality_limit}"
    )]
    SharedShardOverCapacity {
        /// Shared shard identity.
        shard_id: String,
        /// Slot requested for the cell.
        slot_index: usize,
        /// Cardinality bound of the shard.
        cardinality_limit: usize,
    },
}

/// Bounded control-plane state owned by a subject cell.
///
/// This is intentionally narrower than a full brokerless control plane: it
/// captures enough explicit artifacts to model fenced sequencing, joint
/// reconfiguration, cursor-authority transfer, and deterministic stale
/// rejection without pretending the entire distributed protocol already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCapsuleV1 {
    cell_id: CellId,
    cell_epoch: CellEpoch,
    /// Full steward pool negotiated for the current control epoch.
    pub steward_pool: Vec<NodeId>,
    /// Steward currently holding the append lease, if any.
    pub active_sequencer: Option<NodeId>,
    /// Fence generation invalidating older authority artifacts.
    pub sequencer_lease_generation: u64,
    /// Monotonic revision of the policy snapshot stored in the capsule.
    pub policy_revision: u64,
    /// Holder currently allowed to issue cursor-control decisions.
    pub cursor_authority: Option<CursorAuthorityLease>,
    /// Optional shared control shard assignment for low-rate cells.
    pub shared_control_shard: Option<SharedControlShard>,
    /// History of in-band joint-consensus configuration transitions.
    pub joint_config_history: Vec<JointConfigEntry>,
    committed_appends: BTreeMap<ControlAppendIdentity, AppendCertificate>,
    next_sequence: u64,
}

impl ControlCapsuleV1 {
    fn new(cell_id: CellId, steward_pool: Vec<NodeId>, epoch: CellEpoch) -> Self {
        let policy_revision = 1;
        let active_sequencer = steward_pool.first().cloned();
        let cursor_authority = steward_pool
            .first()
            .cloned()
            .map(|holder| CursorAuthorityLease {
                holder,
                control_epoch: ControlEpoch::new(epoch, policy_revision),
                fence_generation: epoch.generation,
            });

        Self {
            cell_id,
            cell_epoch: epoch,
            steward_pool,
            active_sequencer,
            sequencer_lease_generation: epoch.generation,
            policy_revision,
            cursor_authority,
            shared_control_shard: None,
            joint_config_history: Vec::new(),
            committed_appends: BTreeMap::new(),
            next_sequence: 1,
        }
    }

    /// Return the current sequencer holder, if one exists.
    #[must_use]
    pub fn active_sequencer_holder(&self) -> Option<&NodeId> {
        self.active_sequencer.as_ref()
    }

    /// Return the current bounded control epoch for the cell.
    #[must_use]
    pub const fn control_epoch(&self) -> ControlEpoch {
        ControlEpoch::new(self.cell_epoch, self.policy_revision)
    }

    /// Return the current sequencer lease, if one exists.
    #[must_use]
    pub fn active_sequencer_lease(&self) -> Option<SequencerLease> {
        self.active_sequencer.clone().map(|holder| SequencerLease {
            holder,
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        })
    }

    /// Return the current cursor-authority lease, if one exists.
    #[must_use]
    pub fn cursor_authority_lease(&self) -> Option<&CursorAuthorityLease> {
        self.cursor_authority.as_ref()
    }

    fn advance_control_fence(&mut self) {
        self.sequencer_lease_generation += 1;
        let control_epoch = self.control_epoch();
        if let Some(lease) = &mut self.cursor_authority {
            lease.fence_generation = self.sequencer_lease_generation;
            lease.control_epoch = control_epoch;
        }
    }

    fn install_sequencer(&mut self, holder: NodeId) -> SequencerLease {
        let lease = SequencerLease {
            holder: holder.clone(),
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.active_sequencer = Some(holder);
        lease
    }

    fn install_cursor_authority(&mut self, holder: NodeId) -> CursorAuthorityLease {
        let lease = CursorAuthorityLease {
            holder,
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.cursor_authority = Some(lease.clone());
        lease
    }

    fn rebind_epoch(&mut self, cell_id: CellId, epoch: CellEpoch) {
        self.cell_id = cell_id;
        self.cell_epoch = epoch;
        self.policy_revision = 1;
        self.sequencer_lease_generation = self.sequencer_lease_generation.max(epoch.generation);
        let control_epoch = self.control_epoch();
        if let Some(cursor_authority) = &mut self.cursor_authority {
            cursor_authority.control_epoch = control_epoch;
            cursor_authority.fence_generation = self.sequencer_lease_generation;
        }
        self.committed_appends.clear();
        self.next_sequence = 1;
    }

    fn validate_sequencer_lease(
        &self,
        lease: &SequencerLease,
    ) -> Result<SequencerLease, ControlCapsuleError> {
        let Some(active) = self.active_sequencer_lease() else {
            return Err(ControlCapsuleError::NoActiveSequencer);
        };
        if lease != &active {
            return Err(ControlCapsuleError::StaleSequencerLease {
                holder: lease.holder.clone(),
                fence_generation: lease.fence_generation,
                current_holder: active.holder.clone(),
                current_fence_generation: active.fence_generation,
            });
        }
        Ok(active)
    }

    /// Emit and commit one authoritative append under the active sequencer
    /// lease. The committed certificate is retained so duplicate late delivery
    /// collapses to an idempotent no-op rather than duplicating authority.
    pub fn authoritative_append(
        &mut self,
        lease: &SequencerLease,
    ) -> Result<AppendCertificate, ControlCapsuleError> {
        let active = self.validate_sequencer_lease(lease)?;
        let identity = ControlAppendIdentity {
            cell_id: self.cell_id,
            epoch: self.cell_epoch,
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;

        let certificate = AppendCertificate {
            identity: identity.clone(),
            sequencer: active.holder,
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.committed_appends.insert(identity, certificate.clone());
        Ok(certificate)
    }

    /// Accept a replicated or late append certificate from elsewhere in the
    /// control plane and reduce it to a deterministic committed/no-op/stale
    /// outcome.
    pub fn accept_replicated_append(
        &mut self,
        certificate: AppendCertificate,
    ) -> Result<ReplicatedAppendOutcome, ControlCapsuleError> {
        if certificate.identity.cell_id != self.cell_id {
            return Err(ControlCapsuleError::WrongCell {
                identity: certificate.identity.clone(),
                expected: self.cell_id,
                actual: certificate.identity.cell_id,
            });
        }
        if certificate.identity.epoch != self.cell_epoch {
            return Err(ControlCapsuleError::WrongEpoch {
                identity: certificate.identity.clone(),
                expected: self.cell_epoch,
                actual: certificate.identity.epoch,
            });
        }
        if certificate.fence_generation != self.sequencer_lease_generation {
            return Ok(ReplicatedAppendOutcome::StaleReject {
                identity: certificate.identity,
                attempted_fence_generation: certificate.fence_generation,
                current_fence_generation: self.sequencer_lease_generation,
            });
        }

        if let Some(existing) = self.committed_appends.get(&certificate.identity) {
            if existing == &certificate {
                return Ok(ReplicatedAppendOutcome::IdempotentNoop(existing.clone()));
            }
            return Err(ControlCapsuleError::ConflictingAppendIdentity {
                identity: certificate.identity,
            });
        }

        self.next_sequence = self
            .next_sequence
            .max(certificate.identity.sequence.saturating_add(1));
        self.committed_appends
            .insert(certificate.identity.clone(), certificate.clone());
        Ok(ReplicatedAppendOutcome::Committed(certificate))
    }

    /// Fence the active sequencer and install a new steward lease.
    pub fn fence_sequencer(
        &mut self,
        next_holder: NodeId,
    ) -> Result<FenceToken, ControlCapsuleError> {
        if !contains_node(&self.steward_pool, &next_holder) {
            return Err(ControlCapsuleError::UnknownSteward { node: next_holder });
        }

        let Some(previous_holder) = self.active_sequencer_holder().cloned() else {
            return Err(ControlCapsuleError::NoActiveSequencer);
        };

        self.advance_control_fence();
        let token = FenceToken {
            control_epoch: self.control_epoch(),
            previous_holder,
            next_holder: next_holder.clone(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.install_sequencer(next_holder);
        Ok(token)
    }

    /// Install an in-band joint-consensus transition with overlap between the
    /// old and new stewardship sets and a freshly fenced sequencer lease.
    pub fn reconfigure(
        &mut self,
        new_stewards: Vec<NodeId>,
        next_sequencer: NodeId,
    ) -> Result<JointConfigEntry, ControlCapsuleError> {
        if let Some(node) = duplicate_node(&new_stewards) {
            return Err(ControlCapsuleError::DuplicateSteward { node });
        }
        if !new_stewards
            .iter()
            .any(|candidate| contains_node(&self.steward_pool, candidate))
        {
            return Err(ControlCapsuleError::JointConfigRequiresOverlap);
        }
        if !contains_node(&new_stewards, &next_sequencer) {
            return Err(ControlCapsuleError::UnknownSteward {
                node: next_sequencer,
            });
        }

        let old_stewards = self.steward_pool.clone();
        self.steward_pool.clone_from(&new_stewards);
        self.policy_revision += 1;
        self.advance_control_fence();
        self.install_sequencer(next_sequencer.clone());
        self.install_cursor_authority(next_sequencer.clone());

        let joint = JointConfigEntry {
            control_epoch: self.control_epoch(),
            old_stewards,
            new_stewards,
            next_sequencer,
            fence_generation: self.sequencer_lease_generation,
        };
        self.joint_config_history.push(joint.clone());
        Ok(joint)
    }

    /// Fence and transfer cursor-control authority to a new holder.
    pub fn transfer_cursor_authority(
        &mut self,
        next_holder: NodeId,
    ) -> Result<CursorAuthorityLease, ControlCapsuleError> {
        if !contains_node(&self.steward_pool, &next_holder) {
            return Err(ControlCapsuleError::UnknownSteward { node: next_holder });
        }
        self.advance_control_fence();
        Ok(self.install_cursor_authority(next_holder))
    }

    /// Validate that a caller still holds the current fenced cursor-authority
    /// lease.
    pub fn validate_cursor_authority(
        &self,
        lease: &CursorAuthorityLease,
    ) -> Result<(), ControlCapsuleError> {
        let Some(active) = self.cursor_authority.as_ref() else {
            return Err(ControlCapsuleError::NoCursorAuthority);
        };
        if lease != active {
            return Err(ControlCapsuleError::StaleCursorAuthorityLease {
                holder: lease.holder.clone(),
                fence_generation: lease.fence_generation,
                current_holder: active.holder.clone(),
                current_fence_generation: self.sequencer_lease_generation,
            });
        }
        Ok(())
    }

    /// Pack the cell onto a shared control shard under an explicit cardinality
    /// limit.
    pub fn attach_shared_control_shard(
        &mut self,
        shard_id: impl Into<String>,
        slot_index: usize,
        cardinality_limit: usize,
    ) -> Result<SharedControlShard, ControlCapsuleError> {
        let shard_id = shard_id.into();
        if cardinality_limit == 0 {
            return Err(ControlCapsuleError::InvalidSharedShardLimit);
        }
        if slot_index >= cardinality_limit {
            return Err(ControlCapsuleError::SharedShardOverCapacity {
                shard_id,
                slot_index,
                cardinality_limit,
            });
        }

        let shard = SharedControlShard {
            shard_id,
            slot_index,
            cardinality_limit,
        };
        self.shared_control_shard = Some(shard.clone());
        Ok(shard)
    }
}

/// Minimal data-plane configuration owned by a subject cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataCapsule {
    /// Current traffic temperature of the cell.
    pub temperature: CellTemperature,
    /// Number of recent message blocks retained inline by the cell.
    pub retained_message_blocks: usize,
}

impl Default for DataCapsule {
    fn default() -> Self {
        Self {
            temperature: CellTemperature::Cold,
            retained_message_blocks: 1,
        }
    }
}

/// Repair and recoverability policy for a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPolicy {
    /// Minimum recoverability class the cell should preserve during churn.
    pub recoverability_target: u8,
    /// Number of repair witnesses to keep for cold cells.
    pub cold_witnesses: usize,
    /// Number of repair witnesses to keep for hot cells.
    pub hot_witnesses: usize,
}

impl Default for RepairPolicy {
    fn default() -> Self {
        Self {
            recoverability_target: 2,
            cold_witnesses: 1,
            hot_witnesses: 3,
        }
    }
}

impl RepairPolicy {
    fn witness_target(&self, temperature: CellTemperature) -> usize {
        match temperature {
            CellTemperature::Cold | CellTemperature::Warm => self.cold_witnesses,
            CellTemperature::Hot => self.hot_witnesses,
        }
    }

    fn minimum_repair_holders(&self, temperature: CellTemperature, steward_count: usize) -> usize {
        steward_count
            .saturating_add(self.witness_target(temperature))
            .max(self.recoverability_target as usize)
    }
}

/// Smallest sovereign unit of the brokerless subject fabric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectCell {
    /// Deterministic identifier for this canonical subject partition and epoch.
    pub cell_id: CellId,
    /// Canonical non-overlapping subject slice owned by this cell.
    pub subject_partition: SubjectPattern,
    /// Active steward set selected for the current temperature and epoch.
    pub steward_set: Vec<NodeId>,
    /// Current bounded control-plane capsule for the cell.
    pub control_capsule: ControlCapsuleV1,
    /// Current data-plane capsule placeholder for the cell.
    pub data_capsule: DataCapsule,
    /// Repair and recoverability policy attached to the cell.
    pub repair_policy: RepairPolicy,
    /// Membership epoch and generation fenced into the cell identity.
    pub epoch: CellEpoch,
}

impl SubjectCell {
    /// Create a new subject cell with deterministic placement.
    #[allow(clippy::result_large_err)]
    pub fn new(
        subject_partition: &SubjectPattern,
        epoch: CellEpoch,
        candidates: &[StewardCandidate],
        placement_policy: &PlacementPolicy,
        repair_policy: RepairPolicy,
        data_capsule: DataCapsule,
    ) -> Result<Self, FabricError> {
        let canonical_partition = placement_policy
            .normalization
            .normalize(subject_partition)?;
        let steward_set = placement_policy.select_stewards(
            &canonical_partition,
            candidates,
            data_capsule.temperature,
        )?;
        let cell_id = CellId::for_partition(epoch, &canonical_partition);
        let control_capsule = ControlCapsuleV1::new(cell_id, steward_set.clone(), epoch);

        Ok(Self {
            cell_id,
            subject_partition: canonical_partition,
            steward_set,
            control_capsule,
            data_capsule,
            repair_policy,
            epoch,
        })
    }

    /// Certify an explicit steward-set self-rebalance under the current epoch,
    /// then advance the cell generation once the cut is fenced.
    #[allow(clippy::result_large_err)]
    pub fn certify_self_rebalance(
        &self,
        placement_policy: &PlacementPolicy,
        candidates: &[StewardCandidate],
        observed_load: ObservedCellLoad,
        cut_evidence: RebalanceCutEvidence,
    ) -> Result<CertifiedRebalance, RebalanceError> {
        let plan = placement_policy.plan_rebalance(
            &self.subject_partition,
            candidates,
            &self.steward_set,
            self.data_capsule.temperature,
            observed_load,
        )?;
        if plan.next_temperature == self.data_capsule.temperature
            && plan.next_stewards == self.steward_set
        {
            return Err(RebalanceError::NoRebalanceNeeded {
                cell_id: self.cell_id,
            });
        }
        if !contains_node(&plan.next_stewards, &cut_evidence.next_sequencer) {
            return Err(RebalanceError::NextSequencerNotInPlan {
                node: cut_evidence.next_sequencer,
            });
        }

        cut_evidence.obligation_summary.validate()?;
        let canonical_repair_symbols = validate_repair_bindings(
            &cut_evidence,
            candidates,
            &plan,
            self.epoch,
            &self.repair_policy,
        )?;

        let mut next_control = self.control_capsule.clone();
        let active_lease = next_control
            .active_sequencer_lease()
            .ok_or(ControlCapsuleError::NoActiveSequencer)?;
        let control_append = next_control.authoritative_append(&active_lease)?;
        let joint_config = next_control.reconfigure(
            plan.next_stewards.clone(),
            cut_evidence.next_sequencer.clone(),
        )?;

        let next_epoch = self.epoch.next_generation();
        let next_cell_id = CellId::for_partition(next_epoch, &self.subject_partition);
        next_control.rebind_epoch(next_cell_id, next_epoch);

        let resulting_cell = Self {
            cell_id: next_cell_id,
            subject_partition: self.subject_partition.clone(),
            steward_set: plan.next_stewards.clone(),
            control_capsule: next_control,
            data_capsule: DataCapsule {
                temperature: plan.next_temperature,
                retained_message_blocks: self.data_capsule.retained_message_blocks,
            },
            repair_policy: self.repair_policy.clone(),
            epoch: next_epoch,
        };

        Ok(CertifiedRebalance {
            control_append,
            joint_config,
            plan: plan.clone(),
            cut_evidence: RebalanceCutEvidence {
                next_sequencer: cut_evidence.next_sequencer,
                retention_generation: cut_evidence.retention_generation,
                obligation_summary: cut_evidence.obligation_summary,
                repair_symbols: canonical_repair_symbols,
            },
            drained_stewards: plan.removed_stewards,
            resulting_cell,
        })
    }
}

/// Deterministic failures while certifying a self-rebalance.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RebalanceError {
    /// The sampled load stayed inside the current hysteresis band.
    #[error("rebalance for `{cell_id}` produced no epoch-changing steward transition")]
    NoRebalanceNeeded {
        /// Cell that remained within its current rebalance envelope.
        cell_id: CellId,
    },
    /// The chosen next sequencer is not present in the certified target set.
    #[error("next sequencer `{node}` is not part of the certified steward set")]
    NextSequencerNotInPlan {
        /// Node proposed as the next sequencer.
        node: NodeId,
    },
    /// There are still unresolved publish obligations below the semantic cut.
    #[error("rebalance cut still has {unresolved} publish obligations below the cut frontier")]
    PublishFrontierNotDrained {
        /// Count of unresolved publish obligations.
        unresolved: usize,
    },
    /// Consumer lease ownership was not unique at the cut frontier.
    #[error("rebalance cut still has {ambiguous} ambiguous consumer lease owners")]
    AmbiguousConsumerLeaseOwners {
        /// Count of ambiguous lease owners.
        ambiguous: usize,
    },
    /// Consumer lease transfers or reissues did not cover all live leases.
    #[error("rebalance cut transferred {transferred} consumer leases but requires {active_leases}")]
    ConsumerLeaseTransferIncomplete {
        /// Number of active consumer leases at the cut.
        active_leases: usize,
        /// Number of consumer leases explicitly transferred or reissued.
        transferred: usize,
    },
    /// Reply rights were left dangling at the cut frontier.
    #[error("rebalance cut leaves {dangling} dangling reply rights")]
    DanglingReplyRights {
        /// Count of dangling reply rights.
        dangling: usize,
    },
    /// Reply-right reissue proof did not cover all live reply rights.
    #[error("rebalance cut reissued {reissued} reply rights but requires {active_rights}")]
    ReplyRightsNotReissued {
        /// Number of active reply rights at the cut.
        active_rights: usize,
        /// Number of reply rights reissued onto the next epoch.
        reissued: usize,
    },
    /// Rebalance evidence carried multiple repair bindings for the same node.
    #[error("rebalance evidence contains duplicate repair bindings for `{node}`")]
    DuplicateRepairBinding {
        /// Node with conflicting duplicate bindings.
        node: NodeId,
    },
    /// Repair material was bound to the wrong epoch.
    #[error("repair symbol binding for `{node}` uses epoch {actual:?}, expected {expected:?}")]
    RepairBindingWrongEpoch {
        /// Repair-capable holder attached to the binding.
        node: NodeId,
        /// Cell epoch that should have been used.
        expected: CellEpoch,
        /// Epoch carried by the binding.
        actual: CellEpoch,
    },
    /// Repair material was bound to the wrong retention generation.
    #[error(
        "repair symbol binding for `{node}` uses retention generation {actual}, expected {expected}"
    )]
    RepairBindingWrongRetentionGeneration {
        /// Repair-capable holder attached to the binding.
        node: NodeId,
        /// Retention generation that should have been used.
        expected: u64,
        /// Retention generation carried by the binding.
        actual: u64,
    },
    /// Only repair-capable nodes may be credited with repair material.
    #[error("repair symbol holder `{node}` is not eligible to store repair material")]
    IneligibleRepairHolder {
        /// Holder that is not repair-capable in the supplied candidate set.
        node: NodeId,
    },
    /// Every next steward must prove it collected the current repair material.
    #[error("next steward `{node}` is missing a repair-symbol binding for the rebalance cut")]
    MissingStewardRepairBinding {
        /// Steward missing a binding.
        node: NodeId,
    },
    /// The certified cut did not gather enough repair-capable holders.
    #[error("rebalance collected {actual} repair-capable holders but requires at least {required}")]
    InsufficientRepairSymbolHolders {
        /// Required number of repair-capable holders.
        required: usize,
        /// Number of unique holders actually proven.
        actual: usize,
    },
    /// Placement planning failed.
    #[error(transparent)]
    Placement(#[from] FabricError),
    /// Control-capsule fencing or reconfiguration failed.
    #[error(transparent)]
    Control(#[from] ControlCapsuleError),
}

/// Errors produced by foundational fabric modeling and placement.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FabricError {
    /// Two canonical subject partitions still overlap after normalization.
    #[error("subject partitions `{left}` and `{right}` overlap")]
    OverlappingSubjectPartitions {
        /// Left partition in the conflicting pair.
        left: SubjectPattern,
        /// Right partition in the conflicting pair.
        right: SubjectPattern,
    },
    /// No steward-eligible nodes were available for the requested partition.
    #[error("no steward-eligible candidates available for partition `{partition}`")]
    NoStewardCandidates {
        /// Canonical partition that could not be placed.
        partition: SubjectPattern,
    },
    /// Multiple distinct morphisms claimed the same subject and disagreed on the result.
    #[error("subject `{subject}` matched multiple canonical morphisms (`{left}` and `{right}`)")]
    ConflictingSubjectMorphisms {
        /// Original subject presented to the normalization pipeline.
        subject: SubjectPattern,
        /// First canonical candidate produced by a matching morphism.
        left: SubjectPattern,
        /// Conflicting canonical candidate produced by another morphism.
        right: SubjectPattern,
    },
    /// Prefix morphisms cycled instead of converging on one canonical partition.
    #[error("subject `{subject}` entered a morphism cycle at `{cycle_point}`")]
    CyclicSubjectMorphisms {
        /// Original subject presented to the normalization pipeline.
        subject: SubjectPattern,
        /// Canonical subject that repeated while chasing morphisms.
        cycle_point: SubjectPattern,
    },
}

impl RebalanceObligationSummary {
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), RebalanceError> {
        if self.publish_obligations_below_cut != 0 {
            return Err(RebalanceError::PublishFrontierNotDrained {
                unresolved: self.publish_obligations_below_cut,
            });
        }
        if self.ambiguous_consumer_lease_owners != 0 {
            return Err(RebalanceError::AmbiguousConsumerLeaseOwners {
                ambiguous: self.ambiguous_consumer_lease_owners,
            });
        }
        if self.transferred_consumer_leases < self.active_consumer_leases {
            return Err(RebalanceError::ConsumerLeaseTransferIncomplete {
                active_leases: self.active_consumer_leases,
                transferred: self.transferred_consumer_leases,
            });
        }
        if self.dangling_reply_rights != 0 {
            return Err(RebalanceError::DanglingReplyRights {
                dangling: self.dangling_reply_rights,
            });
        }
        if self.reissued_reply_rights < self.active_reply_rights {
            return Err(RebalanceError::ReplyRightsNotReissued {
                active_rights: self.active_reply_rights,
                reissued: self.reissued_reply_rights,
            });
        }
        Ok(())
    }
}

fn stable_hash<T: Hash>(value: T) -> u64 {
    let mut hasher = DetHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

fn compare_candidates(
    left: &StewardCandidate,
    right: &StewardCandidate,
    temperature: CellTemperature,
) -> std::cmp::Ordering {
    candidate_score(right, temperature)
        .cmp(&candidate_score(left, temperature))
        .then_with(|| left.latency_millis.cmp(&right.latency_millis))
        .then_with(|| left.failure_domain.cmp(&right.failure_domain))
        .then_with(|| left.node_id.as_str().cmp(right.node_id.as_str()))
}

fn candidate_score(candidate: &StewardCandidate, temperature: CellTemperature) -> u64 {
    let health_score = match candidate.health {
        StewardHealth::Healthy => 400_u64,
        StewardHealth::Degraded => 250,
        StewardHealth::Draining => 100,
        StewardHealth::Unavailable => 0,
    };
    let storage_score = match candidate.storage_class {
        StorageClass::Ephemeral => 40_u64,
        StorageClass::Standard => 80,
        StorageClass::Durable => 120,
    };
    // Only an explicit RepairWitness role differentiates extra repair capacity
    // beyond ordinary stewardship during hot-cell placement.
    let hot_repair_bonus = if matches!(temperature, CellTemperature::Hot)
        && candidate.roles.contains(&NodeRole::RepairWitness)
    {
        40_u64
    } else {
        0
    };
    let latency_credit = 1_000_u64.saturating_sub(u64::from(candidate.latency_millis));

    health_score + storage_score + hot_repair_bonus + latency_credit
}

fn contains_node(nodes: &[NodeId], candidate: &NodeId) -> bool {
    nodes.iter().any(|node| node == candidate)
}

fn duplicate_node(nodes: &[NodeId]) -> Option<NodeId> {
    let mut seen = BTreeSet::new();
    for node in nodes {
        if !seen.insert(node.clone()) {
            return Some(node.clone());
        }
    }
    None
}

#[allow(clippy::result_large_err)]
fn validate_repair_bindings(
    cut_evidence: &RebalanceCutEvidence,
    candidates: &[StewardCandidate],
    plan: &RebalancePlan,
    current_epoch: CellEpoch,
    repair_policy: &RepairPolicy,
) -> Result<Vec<RepairSymbolBinding>, RebalanceError> {
    let mut by_node = BTreeMap::new();
    for binding in &cut_evidence.repair_symbols {
        if binding.cell_epoch != current_epoch {
            return Err(RebalanceError::RepairBindingWrongEpoch {
                node: binding.node_id.clone(),
                expected: current_epoch,
                actual: binding.cell_epoch,
            });
        }
        if binding.retention_generation != cut_evidence.retention_generation {
            return Err(RebalanceError::RepairBindingWrongRetentionGeneration {
                node: binding.node_id.clone(),
                expected: cut_evidence.retention_generation,
                actual: binding.retention_generation,
            });
        }
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.node_id == binding.node_id);
        let retained_steward = contains_node(&plan.next_stewards, &binding.node_id);
        if !candidate.is_some_and(StewardCandidate::can_repair) && !retained_steward {
            return Err(RebalanceError::IneligibleRepairHolder {
                node: binding.node_id.clone(),
            });
        }
        if by_node
            .insert(binding.node_id.clone(), binding.clone())
            .is_some()
        {
            return Err(RebalanceError::DuplicateRepairBinding {
                node: binding.node_id.clone(),
            });
        }
    }

    for steward in &plan.next_stewards {
        if !by_node.contains_key(steward) {
            return Err(RebalanceError::MissingStewardRepairBinding {
                node: steward.clone(),
            });
        }
    }

    let required_holders =
        repair_policy.minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
    let actual_holders = by_node.len();
    if actual_holders < required_holders {
        return Err(RebalanceError::InsufficientRepairSymbolHolders {
            required: required_holders,
            actual: actual_holders,
        });
    }

    Ok(by_node.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::run_test_with_cx;
    use std::time::Duration;

    fn candidate(
        name: &str,
        domain: &str,
        storage_class: StorageClass,
        latency_millis: u32,
    ) -> StewardCandidate {
        StewardCandidate::new(NodeId::new(name), domain)
            .with_role(NodeRole::Steward)
            .with_role(NodeRole::RepairWitness)
            .with_storage_class(storage_class)
            .with_latency_millis(latency_millis)
    }

    #[test]
    fn stream_config_defaults_to_ephemeral_interactive() {
        let config = FabricStreamConfig::default();
        assert_eq!(config.delivery_class, DeliveryClass::EphemeralInteractive);
        assert_eq!(config.capture_policy, CapturePolicy::ExplicitOptIn);
        assert!(config.subjects.is_empty());
    }

    #[test]
    fn stream_config_rejects_empty_subject_lists() {
        let err = FabricStreamConfig::default()
            .validate()
            .expect_err("empty stream declarations must fail closed");
        assert_eq!(err.kind(), ErrorKind::ConfigError);
    }

    #[test]
    fn stream_config_rejects_overlapping_subjects() {
        let config = FabricStreamConfig {
            subjects: vec![
                SubjectPattern::parse("orders.>").expect("orders wildcard"),
                SubjectPattern::parse("orders.created").expect("orders literal"),
            ],
            ..FabricStreamConfig::default()
        };

        let err = config
            .validate()
            .expect_err("overlapping capture declarations must be rejected");
        assert_eq!(err.kind(), ErrorKind::User);
    }

    #[test]
    fn connect_rejects_blank_endpoints() {
        run_test_with_cx(|cx| async move {
            let err = Fabric::connect(&cx, "   ")
                .await
                .expect_err("blank endpoint must fail");
            assert_eq!(err.kind(), ErrorKind::ConfigError);
        });
    }

    #[test]
    fn publish_and_subscribe_round_trip_with_ephemeral_defaults() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/publish")
                .await
                .expect("connect");
            let mut subscription = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            let receipt = fabric
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");
            let message = subscription.next(&cx).await.expect("message");

            assert_eq!(receipt.ack_kind, AckKind::Accepted);
            assert_eq!(receipt.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(message.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());
        });
    }

    #[test]
    fn request_uses_same_surface_and_returns_reply() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/request")
                .await
                .expect("connect");
            let reply = fabric
                .request(&cx, "service.lookup", b"lookup".to_vec())
                .await
                .expect("request");

            assert_eq!(reply.ack_kind, AckKind::Accepted);
            assert_eq!(reply.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(reply.subject.as_str(), "service.lookup");
            assert_eq!(reply.payload, b"lookup".to_vec());
        });
    }

    #[test]
    fn stream_accepts_explicit_subjects_and_preserves_endpoint() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/stream")
                .await
                .expect("connect");
            let handle = fabric
                .stream(
                    &cx,
                    FabricStreamConfig {
                        subjects: vec![SubjectPattern::parse("orders.>").expect("pattern")],
                        delivery_class: DeliveryClass::DurableOrdered,
                        capture_policy: CapturePolicy::ExplicitOptIn,
                        request_timeout: Some(Duration::from_secs(5)),
                    },
                )
                .await
                .expect("stream");

            assert_eq!(handle.endpoint(), "node1:4222/stream");
            assert_eq!(
                handle.config().delivery_class,
                DeliveryClass::DurableOrdered
            );
            assert_eq!(handle.config().subjects.len(), 1);
        });
    }

    #[test]
    fn same_endpoint_connections_share_published_messages() {
        run_test_with_cx(|cx| async move {
            let publisher = Fabric::connect(&cx, "node1:4222/shared")
                .await
                .expect("connect");
            let subscriber = Fabric::connect(&cx, "node1:4222/shared")
                .await
                .expect("connect");
            let mut subscription = subscriber
                .subscribe(&cx, "orders.>")
                .await
                .expect("subscribe");

            publisher
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");
            let message = subscription.next(&cx).await.expect("message");

            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());
        });
    }

    #[test]
    fn different_endpoints_do_not_share_messages() {
        run_test_with_cx(|cx| async move {
            let left = Fabric::connect(&cx, "node1:4222/left")
                .await
                .expect("connect");
            let right = Fabric::connect(&cx, "node1:4222/right")
                .await
                .expect("connect");
            let mut subscription = right.subscribe(&cx, "orders.>").await.expect("subscribe");

            left.publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");

            assert_eq!(subscription.next(&cx).await, None);
        });
    }

    #[test]
    fn late_subscriber_does_not_replay_prior_messages_on_shared_endpoint() {
        run_test_with_cx(|cx| async move {
            let publisher = Fabric::connect(&cx, "node1:4222/live-only")
                .await
                .expect("connect");
            let late_subscriber = Fabric::connect(&cx, "node1:4222/live-only")
                .await
                .expect("connect");

            publisher
                .publish(&cx, "orders.created", b"before-subscribe".to_vec())
                .await
                .expect("publish");

            let mut subscription = late_subscriber
                .subscribe(&cx, "orders.>")
                .await
                .expect("subscribe");

            assert_eq!(
                subscription.next(&cx).await,
                None,
                "late subscribers should not replay pre-subscription packet-plane history"
            );

            publisher
                .publish(&cx, "orders.created", b"after-subscribe".to_vec())
                .await
                .expect("publish");

            let message = subscription.next(&cx).await.expect("live message");
            assert_eq!(message.payload, b"after-subscribe".to_vec());
        });
    }

    #[test]
    fn parse_subject_pattern_trims_outer_whitespace() {
        let pattern = SubjectPattern::parse("  orders.created.>  ").expect("pattern");
        assert_eq!(pattern.canonical_key(), "orders.created.>");
    }

    #[test]
    fn parse_subject_pattern_rejects_non_terminal_tail_wildcard() {
        let err = SubjectPattern::parse("orders.>.created").expect_err("should reject");
        assert_eq!(err, SubjectPatternError::TailWildcardMustBeTerminal);
    }

    #[test]
    fn reply_space_aggregation_compacts_ephemeral_suffixes() {
        let pattern =
            SubjectPattern::parse("_INBOX.orders.region.instance.12345").expect("pattern");
        let compacted = pattern.aggregate_reply_space(ReplySpaceCompactionPolicy {
            enabled: true,
            preserve_segments: 3,
        });
        assert_eq!(compacted.canonical_key(), "_INBOX.orders.region.>");
    }

    #[test]
    fn overlap_detection_handles_literals_and_wildcards() {
        let left = SubjectPattern::parse("orders.*").expect("left");
        let right = SubjectPattern::parse("orders.created").expect("right");
        let third = SubjectPattern::parse("metrics.>").expect("third");
        let fourth = SubjectPattern::parse("orders.created").expect("fourth");

        assert!(left.overlaps(&right));
        assert!(!left.overlaps(&third));
        assert!(third.overlaps(&SubjectPattern::parse("metrics.region.1").expect("tail")));
        assert!(right.overlaps(&fourth));
    }

    #[test]
    fn tail_wildcard_requires_a_non_empty_suffix() {
        let wildcard = SubjectPattern::parse("orders.>").expect("wildcard");
        let bare_prefix = SubjectPattern::parse("orders").expect("bare prefix");

        assert!(!wildcard.overlaps(&bare_prefix));
        assert!(wildcard.overlaps(&SubjectPattern::parse("orders.created").expect("expanded")));
    }

    #[test]
    fn normalization_policy_applies_prefix_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "orders.created");
    }

    #[test]
    fn normalization_policy_chains_prefix_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                SubjectPrefixMorphism::new("orders", "canonical.orders").expect("morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "canonical.orders.created");
    }

    #[test]
    fn normalization_policy_rejects_morphism_cycles() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                SubjectPrefixMorphism::new("orders", "svc.orders").expect("morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let err = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect_err("should reject cycle");

        assert!(matches!(err, FabricError::CyclicSubjectMorphisms { .. }));
    }

    #[test]
    fn normalization_policy_can_compact_reply_space_after_morphism() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc", "_INBOX").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.region.instance.123").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "_INBOX.orders.region.>");
    }

    #[test]
    fn non_overlapping_validation_rejects_conflicts() {
        let patterns = vec![
            SubjectPattern::parse("orders.created").expect("orders.created"),
            SubjectPattern::parse("orders.*").expect("orders.*"),
        ];
        let err = SubjectPattern::validate_non_overlapping(&patterns).expect_err("should overlap");
        assert!(matches!(
            err,
            FabricError::OverlappingSubjectPartitions { .. }
        ));
    }

    #[test]
    fn cell_id_is_stable_for_same_partition_and_epoch() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let epoch = CellEpoch::new(7, 3);
        let first = CellId::for_partition(epoch, &partition);
        let second = CellId::for_partition(epoch, &partition);

        assert_eq!(first, second);
        assert_ne!(
            first,
            CellId::for_partition(CellEpoch::new(8, 3), &partition)
        );
    }

    #[test]
    fn alias_subjects_collapse_to_the_same_subject_cell() {
        let policy = PlacementPolicy {
            normalization: NormalizationPolicy {
                morphisms: vec![
                    SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                ],
                ..NormalizationPolicy::default()
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 9),
        ];
        let epoch = CellEpoch::new(17, 4);

        let canonical = SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("canonical"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("canonical cell");
        let aliased = SubjectCell::new(
            &SubjectPattern::parse("svc.orders.created").expect("aliased"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("aliased cell");

        assert_eq!(canonical.subject_partition, aliased.subject_partition);
        assert_eq!(canonical.cell_id, aliased.cell_id);
        assert_eq!(canonical.steward_set, aliased.steward_set);
    }

    #[test]
    fn thermal_hysteresis_damps_temperature_flips() {
        let policy = PlacementPolicy::default();

        assert_eq!(
            policy.recommend_temperature(CellTemperature::Warm, ObservedCellLoad::new(64)),
            CellTemperature::Warm
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Warm, ObservedCellLoad::new(32)),
            CellTemperature::Cold
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Hot, ObservedCellLoad::new(768)),
            CellTemperature::Hot
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Hot, ObservedCellLoad::new(256)),
            CellTemperature::Warm
        );
    }

    #[test]
    fn rebalance_budget_limits_steward_churn() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 5,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 1,
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];
        let current_stewards = vec![NodeId::new("node-a")];

        let plan = policy
            .plan_rebalance(
                &partition,
                &candidates,
                &current_stewards,
                CellTemperature::Cold,
                ObservedCellLoad::new(2_048),
            )
            .expect("rebalance");

        assert_eq!(plan.next_temperature, CellTemperature::Hot);
        assert_eq!(plan.added_stewards.len(), 1);
        assert!(plan.removed_stewards.is_empty());
        assert_eq!(plan.next_stewards.len(), 2);
        assert!(
            plan.next_stewards
                .iter()
                .any(|node| node.as_str() == "node-a")
        );
    }

    #[test]
    fn rebalance_planning_uses_normalized_subject_partition() {
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 1,
            hot_stewards: 1,
            candidate_pool_size: 4,
            normalization: NormalizationPolicy {
                morphisms: vec![
                    SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                ],
                ..NormalizationPolicy::default()
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
            candidate("node-d", "rack-d", StorageClass::Standard, 8),
            candidate("node-e", "rack-e", StorageClass::Standard, 9),
        ];
        let alias_subjects = [
            "svc.orders.created",
            "svc.orders.updated",
            "svc.orders.cancelled",
            "svc.orders.fulfilled",
            "svc.orders.archived",
            "svc.orders.audit",
            "svc.orders.retry",
            "svc.orders.snapshot",
        ];

        let (aliased, current_stewards) = alias_subjects
            .iter()
            .find_map(|raw| {
                let aliased = SubjectPattern::parse(raw).expect("pattern");
                let canonical = policy.normalization.normalize(&aliased).expect("canonical");
                let raw_stewards = policy
                    .select_stewards(&aliased, &candidates, CellTemperature::Warm)
                    .expect("raw placement");
                let canonical_stewards = policy
                    .select_stewards(&canonical, &candidates, CellTemperature::Warm)
                    .expect("canonical placement");

                (raw_stewards != canonical_stewards).then_some((aliased, canonical_stewards))
            })
            .expect("expected at least one alias subject to hash differently before normalization");

        let plan = policy
            .plan_rebalance(
                &aliased,
                &candidates,
                &current_stewards,
                CellTemperature::Warm,
                ObservedCellLoad::new(256),
            )
            .expect("rebalance");

        assert_eq!(plan.next_stewards, current_stewards);
        assert!(plan.added_stewards.is_empty());
        assert!(plan.removed_stewards.is_empty());
    }

    #[test]
    fn placement_is_deterministic_and_filters_ineligible_nodes() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 2,
            candidate_pool_size: 4,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 8),
            candidate("node-b", "rack-b", StorageClass::Standard, 12),
            StewardCandidate::new(NodeId::new("observer"), "rack-c")
                .with_role(NodeRole::Subscriber)
                .with_health(StewardHealth::Healthy),
        ];

        let first = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("placement");
        let second = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("placement");

        assert_eq!(first, second);
        assert!(first.iter().all(|node| node.as_str() != "observer"));
    }

    #[test]
    fn hot_cells_widen_steward_set() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 5,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];

        let cold = policy
            .select_stewards(&partition, &candidates, CellTemperature::Cold)
            .expect("cold");
        let hot = policy
            .select_stewards(&partition, &candidates, CellTemperature::Hot)
            .expect("hot");

        assert_eq!(cold.len(), 1);
        assert_eq!(hot.len(), 3);
    }

    #[test]
    fn placement_prefers_failure_domain_diversity() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 2,
            candidate_pool_size: 4,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-a", StorageClass::Durable, 5),
            candidate("node-c", "rack-b", StorageClass::Standard, 6),
            candidate("node-d", "rack-c", StorageClass::Standard, 7),
        ];

        let selected = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("selected");
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().any(|node| node.as_str() == "node-a"));
        assert!(
            selected
                .iter()
                .any(|node| node.as_str() == "node-c" || node.as_str() == "node-d")
        );
    }

    #[test]
    fn placement_falls_back_to_high_latency_candidates_to_fill_steward_set() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 3,
            warm_stewards: 3,
            hot_stewards: 3,
            candidate_pool_size: 3,
            max_latency_millis: 20,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 250),
        ];

        let selected = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("selected");

        assert_eq!(selected.len(), 3);
        assert!(selected.iter().any(|node| node.as_str() == "node-c"));
    }

    #[test]
    fn hot_placement_prefers_explicit_repair_witness_capacity() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 1,
            hot_stewards: 1,
            candidate_pool_size: 2,
            max_latency_millis: 20,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            StewardCandidate::new(NodeId::new("node-a"), "rack-a")
                .with_role(NodeRole::Steward)
                .with_storage_class(StorageClass::Standard)
                .with_latency_millis(5),
            StewardCandidate::new(NodeId::new("node-b"), "rack-b")
                .with_role(NodeRole::Steward)
                .with_role(NodeRole::RepairWitness)
                .with_storage_class(StorageClass::Standard)
                .with_latency_millis(5),
        ];

        let warm = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("warm");
        let hot = policy
            .select_stewards(&partition, &candidates, CellTemperature::Hot)
            .expect("hot");

        assert_eq!(warm, vec![NodeId::new("node-a")]);
        assert_eq!(hot, vec![NodeId::new("node-b")]);
    }

    #[test]
    fn subject_cell_construction_builds_capsules_and_compacts_reply_space() {
        let subject_partition =
            SubjectPattern::parse("_INBOX.orders.region.instance.123").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 4,
            normalization: NormalizationPolicy {
                morphisms: Vec::new(),
                reply_space_policy: ReplySpaceCompactionPolicy {
                    enabled: true,
                    preserve_segments: 3,
                },
            },
            ..PlacementPolicy::default()
        };
        let data_capsule = DataCapsule {
            temperature: CellTemperature::Warm,
            retained_message_blocks: 4,
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];

        let cell = SubjectCell::new(
            &subject_partition,
            CellEpoch::new(11, 2),
            &candidates,
            &policy,
            RepairPolicy::default(),
            data_capsule,
        )
        .expect("cell");

        assert_eq!(
            cell.subject_partition.canonical_key(),
            "_INBOX.orders.region.>"
        );
        assert_eq!(
            cell.control_capsule.active_sequencer_holder(),
            cell.steward_set.first()
        );
        assert_eq!(cell.steward_set.len(), 2);
    }

    fn control_capsule() -> ControlCapsuleV1 {
        let epoch = CellEpoch::new(23, 4);
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let cell_id = CellId::for_partition(epoch, &partition);
        ControlCapsuleV1::new(
            cell_id,
            vec![NodeId::new("node-a"), NodeId::new("node-b")],
            epoch,
        )
    }

    fn rebalance_policy() -> PlacementPolicy {
        PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 3,
            hot_stewards: 4,
            candidate_pool_size: 6,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 3,
            },
            ..PlacementPolicy::default()
        }
    }

    fn rebalance_candidates() -> Vec<StewardCandidate> {
        vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
            candidate("node-d", "rack-d", StorageClass::Standard, 8),
            candidate("node-e", "rack-e", StorageClass::Standard, 9),
            candidate("node-f", "rack-f", StorageClass::Standard, 10),
        ]
    }

    fn cold_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule::default(),
        )
        .expect("cold cell")
    }

    fn warm_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule {
                temperature: CellTemperature::Warm,
                retained_message_blocks: 4,
            },
        )
        .expect("warm cell")
    }

    fn repair_bindings_for(
        cell: &SubjectCell,
        plan: &RebalancePlan,
        candidates: &[StewardCandidate],
        retention_generation: u64,
        required_holders: usize,
    ) -> Vec<RepairSymbolBinding> {
        let mut holders = plan.next_stewards.clone();
        for candidate in candidates {
            if holders.len() >= required_holders {
                break;
            }
            if contains_node(&holders, &candidate.node_id) || !candidate.can_repair() {
                continue;
            }
            holders.push(candidate.node_id.clone());
        }
        holders
            .into_iter()
            .map(|node_id| RepairSymbolBinding::new(node_id, cell.epoch, retention_generation))
            .collect()
    }

    fn successful_rebalance_evidence(
        cell: &SubjectCell,
        plan: &RebalancePlan,
        candidates: &[StewardCandidate],
        retention_generation: u64,
    ) -> RebalanceCutEvidence {
        let required_holders = cell
            .repair_policy
            .minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
        RebalanceCutEvidence {
            next_sequencer: plan
                .added_stewards
                .first()
                .cloned()
                .unwrap_or_else(|| plan.next_stewards[0].clone()),
            retention_generation,
            obligation_summary: RebalanceObligationSummary {
                publish_obligations_below_cut: 0,
                active_consumer_leases: 2,
                transferred_consumer_leases: 2,
                ambiguous_consumer_lease_owners: 0,
                active_reply_rights: 1,
                reissued_reply_rights: 1,
                dangling_reply_rights: 0,
            },
            repair_symbols: repair_bindings_for(
                cell,
                plan,
                candidates,
                retention_generation,
                required_holders,
            ),
        }
    }

    #[test]
    fn control_capsule_v1_fences_stale_sequencer_leases() {
        let mut capsule = control_capsule();
        let original = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let fence = capsule
            .fence_sequencer(NodeId::new("node-b"))
            .expect("fence should succeed");

        assert_eq!(fence.previous_holder, NodeId::new("node-a"));
        assert_eq!(fence.next_holder, NodeId::new("node-b"));

        let err = capsule
            .authoritative_append(&original)
            .expect_err("old sequencer lease must be fenced");
        assert!(matches!(
            err,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == NodeId::new("node-b")
                && current_fence_generation == fence.fence_generation
        ));

        let current = capsule
            .active_sequencer_lease()
            .expect("refreshed sequencer lease");
        let certificate = capsule
            .authoritative_append(&current)
            .expect("fresh lease should append");
        assert_eq!(certificate.identity.sequence, 1);
        assert_eq!(certificate.sequencer, NodeId::new("node-b"));
    }

    #[test]
    fn control_capsule_v1_reconfiguration_uses_joint_overlap_and_single_live_sequencer() {
        let mut capsule = control_capsule();
        let original = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let err = capsule
            .reconfigure(
                vec![NodeId::new("node-c"), NodeId::new("node-d")],
                NodeId::new("node-c"),
            )
            .expect_err("overlap-free reconfiguration must fail");
        assert_eq!(err, ControlCapsuleError::JointConfigRequiresOverlap);

        let joint = capsule
            .reconfigure(
                vec![NodeId::new("node-a"), NodeId::new("node-c")],
                NodeId::new("node-c"),
            )
            .expect("joint reconfiguration should succeed");

        assert_eq!(
            joint.old_stewards,
            vec![NodeId::new("node-a"), NodeId::new("node-b")]
        );
        assert_eq!(
            joint.new_stewards,
            vec![NodeId::new("node-a"), NodeId::new("node-c")]
        );
        assert_eq!(joint.next_sequencer, NodeId::new("node-c"));
        assert_eq!(capsule.policy_revision, 2);
        assert_eq!(
            capsule.active_sequencer_holder().map(NodeId::as_str),
            Some("node-c")
        );
        assert_eq!(capsule.joint_config_history, vec![joint.clone()]);

        let stale = capsule
            .authoritative_append(&original)
            .expect_err("old sequencer must not decide after fencing");
        assert!(matches!(
            stale,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                ..
            } if current_holder == NodeId::new("node-c")
        ));

        let current = capsule
            .active_sequencer_lease()
            .expect("new sequencer lease");
        let certificate = capsule
            .authoritative_append(&current)
            .expect("new sequencer should be able to append");
        assert_eq!(certificate.sequencer, NodeId::new("node-c"));
        assert_eq!(certificate.control_epoch, joint.control_epoch);
    }

    #[test]
    fn control_capsule_v1_reconfiguration_rejects_duplicate_stewards_without_mutation() {
        let mut capsule = control_capsule();

        let err = capsule
            .reconfigure(
                vec![NodeId::new("node-a"), NodeId::new("node-a")],
                NodeId::new("node-a"),
            )
            .expect_err("duplicate steward sets must fail closed");
        assert_eq!(
            err,
            ControlCapsuleError::DuplicateSteward {
                node: NodeId::new("node-a")
            }
        );
        assert_eq!(
            capsule.steward_pool,
            vec![NodeId::new("node-a"), NodeId::new("node-b")]
        );
        assert_eq!(capsule.policy_revision, 1);
        assert_eq!(
            capsule.active_sequencer_holder().map(NodeId::as_str),
            Some("node-a")
        );
    }

    #[test]
    fn control_capsule_v1_replicated_append_is_idempotent_or_stale() {
        let mut capsule = control_capsule();
        let lease = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let first = capsule
            .authoritative_append(&lease)
            .expect("first append should commit");
        let second = capsule
            .authoritative_append(&lease)
            .expect("second append should commit");
        assert_ne!(first.identity, second.identity);

        let outcome = capsule
            .accept_replicated_append(first.clone())
            .expect("duplicate delivery should collapse");
        assert_eq!(
            outcome,
            ReplicatedAppendOutcome::IdempotentNoop(first.clone())
        );

        capsule
            .fence_sequencer(NodeId::new("node-b"))
            .expect("fence should succeed");
        let stale = capsule
            .accept_replicated_append(second.clone())
            .expect("late delivery must reduce deterministically");
        assert_eq!(
            stale,
            ReplicatedAppendOutcome::StaleReject {
                identity: second.identity.clone(),
                attempted_fence_generation: second.fence_generation,
                current_fence_generation: capsule.sequencer_lease_generation,
            }
        );
    }

    #[test]
    fn control_capsule_v1_cursor_authority_transfer_fences_old_holder() {
        let mut capsule = control_capsule();
        let original = capsule
            .cursor_authority_lease()
            .cloned()
            .expect("initial cursor-authority lease");

        let transferred = capsule
            .transfer_cursor_authority(NodeId::new("node-b"))
            .expect("steward transfer should succeed");

        capsule
            .validate_cursor_authority(&transferred)
            .expect("fresh cursor-authority lease should validate");
        let err = capsule
            .validate_cursor_authority(&original)
            .expect_err("old cursor-authority lease must be fenced");
        assert!(matches!(
            err,
            ControlCapsuleError::StaleCursorAuthorityLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == NodeId::new("node-b")
                && current_fence_generation == capsule.sequencer_lease_generation
        ));
    }

    #[test]
    fn control_capsule_v1_cursor_authority_transfer_rejects_foreign_holder_without_mutation() {
        let mut capsule = control_capsule();
        let original = capsule
            .cursor_authority_lease()
            .cloned()
            .expect("initial cursor-authority lease");
        let original_generation = capsule.sequencer_lease_generation;

        let err = capsule
            .transfer_cursor_authority(NodeId::new("consumer-a"))
            .expect_err("foreign holders must be rejected");
        assert_eq!(
            err,
            ControlCapsuleError::UnknownSteward {
                node: NodeId::new("consumer-a")
            }
        );
        assert_eq!(capsule.cursor_authority_lease(), Some(&original));
        assert_eq!(capsule.sequencer_lease_generation, original_generation);
    }

    #[test]
    fn subject_cell_certified_rebalance_advances_epoch_and_fences_old_sequencer() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let original = cell
            .control_capsule
            .active_sequencer_lease()
            .expect("original sequencer lease");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 7);
        let next_sequencer = evidence.next_sequencer.clone();

        let mut certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");

        assert_eq!(certified.plan, plan);
        assert_eq!(certified.control_append.identity.cell_id, cell.cell_id);
        assert_eq!(certified.control_append.identity.epoch, cell.epoch);
        assert_eq!(
            certified.resulting_cell.epoch,
            CellEpoch::new(cell.epoch.membership_epoch, cell.epoch.generation + 1)
        );
        assert_eq!(certified.resulting_cell.steward_set, plan.next_stewards);
        assert_eq!(
            certified.resulting_cell.data_capsule.temperature,
            CellTemperature::Warm
        );
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .active_sequencer_holder(),
            Some(&next_sequencer)
        );
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .cursor_authority_lease()
                .map(|lease| &lease.holder),
            Some(&next_sequencer)
        );

        let stale = certified
            .resulting_cell
            .control_capsule
            .authoritative_append(&original)
            .expect_err("pre-cut sequencer lease must be fenced");
        assert!(matches!(
            stale,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == next_sequencer
                && current_fence_generation == certified.resulting_cell.epoch.generation
        ));
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_consumer_lease_transfer() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 9);
        evidence.obligation_summary.transferred_consumer_leases = 1;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("consumer lease transfer gaps must fail closed");
        assert_eq!(
            err,
            RebalanceError::ConsumerLeaseTransferIncomplete {
                active_leases: 2,
                transferred: 1,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_reply_right_reissue() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 10);
        evidence.obligation_summary.active_reply_rights = 2;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("reply rights must be reissued onto the next epoch");
        assert_eq!(
            err,
            RebalanceError::ReplyRightsNotReissued {
                active_rights: 2,
                reissued: 1,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_honors_hysteresis_band() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let err = cell
            .certify_self_rebalance(
                &policy,
                &candidates,
                ObservedCellLoad::new(512),
                RebalanceCutEvidence {
                    next_sequencer: cell.steward_set[0].clone(),
                    retention_generation: 4,
                    obligation_summary: RebalanceObligationSummary {
                        publish_obligations_below_cut: 0,
                        active_consumer_leases: 0,
                        transferred_consumer_leases: 0,
                        ambiguous_consumer_lease_owners: 0,
                        active_reply_rights: 0,
                        reissued_reply_rights: 0,
                        dangling_reply_rights: 0,
                    },
                    repair_symbols: Vec::new(),
                },
            )
            .expect_err("in-band load should not force an epoch change");
        assert_eq!(
            err,
            RebalanceError::NoRebalanceNeeded {
                cell_id: cell.cell_id,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_hot_repair_spread() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 11);
        evidence.repair_symbols =
            repair_bindings_for(&cell, &plan, &candidates, 11, plan.next_stewards.len());

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("hot rebalance must prove wider repair spread");
        assert_eq!(
            err,
            RebalanceError::InsufficientRepairSymbolHolders {
                required: 6,
                actual: 4,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_wrong_symbol_epoch_binding() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 12);
        evidence.repair_symbols[0].cell_epoch = cell.epoch.next_generation();

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("repair symbols must be bound to the certified source epoch");
        assert_eq!(
            err,
            RebalanceError::RepairBindingWrongEpoch {
                node: plan.next_stewards[0].clone(),
                expected: cell.epoch,
                actual: cell.epoch.next_generation(),
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_allows_retained_steward_binding_after_candidate_drop() {
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 3,
            hot_stewards: 3,
            candidate_pool_size: 3,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 1,
            },
            ..PlacementPolicy::default()
        };
        let all_candidates = rebalance_candidates();
        let cell = cold_subject_cell(&all_candidates, &policy);
        let current_steward = cell.steward_set[0].clone();
        let reduced_candidates: Vec<_> = all_candidates
            .into_iter()
            .filter(|candidate| candidate.node_id != current_steward)
            .collect();
        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &reduced_candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        assert!(
            contains_node(&plan.next_stewards, &current_steward),
            "budgeted rebalance should retain the current steward for one step"
        );

        let required_holders = cell
            .repair_policy
            .minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
        let repair_symbols =
            repair_bindings_for(&cell, &plan, &reduced_candidates, 13, required_holders);
        assert!(
            repair_symbols
                .iter()
                .any(|binding| binding.node_id == current_steward),
            "retained steward should remain eligible as a repair holder"
        );

        let evidence = RebalanceCutEvidence {
            next_sequencer: plan
                .added_stewards
                .first()
                .cloned()
                .expect("one added steward"),
            retention_generation: 13,
            obligation_summary: RebalanceObligationSummary {
                publish_obligations_below_cut: 0,
                active_consumer_leases: 0,
                transferred_consumer_leases: 0,
                ambiguous_consumer_lease_owners: 0,
                active_reply_rights: 0,
                reissued_reply_rights: 0,
                dangling_reply_rights: 0,
            },
            repair_symbols,
        };

        let certified = cell
            .certify_self_rebalance(&policy, &reduced_candidates, observed_load, evidence)
            .expect("retained stewards remain lawful repair holders during budgeted churn");
        assert!(contains_node(
            &certified.resulting_cell.steward_set,
            &current_steward
        ));
    }

    #[test]
    fn subject_cell_certified_rebalance_preserves_monotonic_fence_generation_across_epochs() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let mut cell = warm_subject_cell(&candidates, &policy);
        let second_steward = cell.steward_set[1].clone();
        let original_steward = cell.steward_set[0].clone();

        cell.control_capsule
            .fence_sequencer(second_steward)
            .expect("first fence");
        cell.control_capsule
            .fence_sequencer(original_steward)
            .expect("second fence");
        let pre_cut_generation = cell.control_capsule.sequencer_lease_generation;
        assert!(
            pre_cut_generation > cell.epoch.generation,
            "test setup must lift fence generation above the cell epoch generation"
        );

        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 14);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            pre_cut_generation + 1
        );
        assert!(
            certified
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation
                > certified.resulting_cell.epoch.generation
        );
    }

    #[test]
    fn control_capsule_v1_shared_control_shard_respects_cardinality_limits() {
        let mut capsule = control_capsule();

        let shard = capsule
            .attach_shared_control_shard("control-shard-a", 1, 3)
            .expect("slot inside cardinality bound should succeed");
        assert_eq!(capsule.shared_control_shard, Some(shard.clone()));

        let err = capsule
            .attach_shared_control_shard("control-shard-a", 3, 3)
            .expect_err("out-of-range slot must fail");
        assert_eq!(
            err,
            ControlCapsuleError::SharedShardOverCapacity {
                shard_id: "control-shard-a".to_owned(),
                slot_index: 3,
                cardinality_limit: 3,
            }
        );
    }
}
