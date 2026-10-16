//! System subject namespace and control handlers for the FABRIC control plane.
//!
//! Models the `$SYS.FABRIC.*` subject space inspired by NATS `$SYS.*`, with
//! region-owned handlers, reserved budgets, priority scheduling, and a
//! break-glass recovery path that operates even when the ordinary fabric is
//! degraded.
//!
//! # Design invariants
//!
//! - Control subjects live exclusively under `$SYS.FABRIC.` (enforced by
//!   [`SubjectSchema`] validation, which requires `$SYS.` or `sys.` prefix for
//!   `SubjectFamily::Control`).
//! - Control handlers run with a **reserved** budget and scheduling priority so
//!   they never compete with user traffic for resources.
//! - Advisory subjects must **NOT** automatically feed policy loops without
//!   explicit damping, stratification, or operator intent — otherwise the
//!   control plane would amplify its own observations.
//! - A minimal break-glass recovery surface is available even when ordinary
//!   fabric connectivity is degraded.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use franken_decision::{DecisionAuditEntry, DecisionOutcome};
use franken_evidence::EvidenceLedger;
use franken_kernel::{DecisionId, TraceId};

use crate::remote::NodeId;

use super::class::{AckKind, DeliveryClass};
use super::ir::{
    EvidencePolicy, MobilityPermission, PrivacyPolicy, RetentionPolicy, SubjectFamily,
    SubjectPattern, SubjectSchema,
};
use super::subject::{NamespaceComponent, NamespaceKernel, NamespaceKernelError, Subject};

// ---------------------------------------------------------------------------
// System subject families
// ---------------------------------------------------------------------------

/// Well-known system subject families under `$SYS.FABRIC.*`.
///
/// Each family covers a distinct control-plane concern.  The string
/// representation is the canonical subject prefix (e.g.
/// `$SYS.FABRIC.HEALTH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SystemSubjectFamily {
    /// Health check probes and liveness status.
    Health,
    /// Import morphism lifecycle events.
    Import,
    /// Export morphism lifecycle events.
    Export,
    /// Routing table changes and announcements.
    Route,
    /// Graceful drain lifecycle signals.
    Drain,
    /// Authentication and authorization events.
    Auth,
    /// Consumer lifecycle and advisory events.
    Consumer,
    /// Stream lifecycle and advisory events.
    Stream,
    /// RaptorQ repair status and erasure-coding advisories.
    Repair,
    /// Replay and forensic-trace lifecycle signals.
    Replay,
}

impl SystemSubjectFamily {
    /// All known system subject families in canonical order.
    pub const ALL: [Self; 10] = [
        Self::Health,
        Self::Import,
        Self::Export,
        Self::Route,
        Self::Drain,
        Self::Auth,
        Self::Consumer,
        Self::Stream,
        Self::Repair,
        Self::Replay,
    ];

    /// Canonical upper-case name used in subject paths.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Health => "HEALTH",
            Self::Import => "IMPORT",
            Self::Export => "EXPORT",
            Self::Route => "ROUTE",
            Self::Drain => "DRAIN",
            Self::Auth => "AUTH",
            Self::Consumer => "CONSUMER",
            Self::Stream => "STREAM",
            Self::Repair => "REPAIR",
            Self::Replay => "REPLAY",
        }
    }

    /// Returns the canonical subject prefix, e.g. `$SYS.FABRIC.HEALTH`.
    #[must_use]
    pub fn prefix(self) -> String {
        format!("$SYS.FABRIC.{}", self.name())
    }

    /// Returns a wildcard pattern matching all subjects in this family,
    /// e.g. `$SYS.FABRIC.HEALTH.>`.
    #[must_use]
    pub fn wildcard_pattern(self) -> SubjectPattern {
        SubjectPattern::new(format!("$SYS.FABRIC.{}.>", self.name()))
    }

    /// The default delivery class for this control family.
    ///
    /// Health, Route, and Drain are ephemeral (best-effort); Auth and Replay
    /// are forensic-replayable for audit; the rest use obligation-backed
    /// semantics.
    #[must_use]
    pub const fn default_delivery_class(self) -> DeliveryClass {
        match self {
            // Hot ephemeral — control heartbeats must not impose durability tax.
            Self::Health | Self::Route | Self::Drain => DeliveryClass::EphemeralInteractive,
            // Import/export/consumer/stream/repair advisories are
            // obligation-backed so the operator has explicit ack semantics.
            Self::Import | Self::Export | Self::Consumer | Self::Stream | Self::Repair => {
                DeliveryClass::ObligationBacked
            }
            // Auth and Replay events carry audit-trail obligations.
            Self::Auth | Self::Replay => DeliveryClass::ForensicReplayable,
        }
    }

    /// The minimum ack kind for this control family.
    #[must_use]
    pub const fn minimum_ack(self) -> AckKind {
        match self {
            Self::Health | Self::Route | Self::Drain => AckKind::Accepted,
            Self::Import | Self::Export | Self::Consumer | Self::Stream | Self::Repair => {
                AckKind::Committed
            }
            Self::Auth | Self::Replay => AckKind::Recoverable,
        }
    }

    /// Construct a [`SubjectSchema`] for this control family with default
    /// policies.
    #[must_use]
    pub fn default_schema(self) -> SubjectSchema {
        SubjectSchema {
            pattern: self.wildcard_pattern(),
            family: SubjectFamily::Control,
            delivery_class: self.default_delivery_class(),
            evidence_policy: self.default_evidence_policy(),
            privacy_policy: PrivacyPolicy::default(),
            reply_space: None,
            mobility: MobilityPermission::LocalOnly,
            quantitative_obligation: None,
        }
    }

    /// Default evidence policy for this control family.
    ///
    /// Auth and Replay always sample at 100% with full control transition
    /// recording.  Other families sample at 100% but skip counterfactual
    /// branches.
    fn default_evidence_policy(self) -> EvidencePolicy {
        match self {
            Self::Auth | Self::Replay => EvidencePolicy {
                sampling_ratio: 1.0,
                retention: RetentionPolicy::default(),
                record_payload_hashes: true,
                record_control_transitions: true,
                record_counterfactual_branches: true,
            },
            _ => EvidencePolicy::default(),
        }
    }
}

impl fmt::Display for SystemSubjectFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "$SYS.FABRIC.{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// Control handler budget and priority
// ---------------------------------------------------------------------------

/// Reserved resource envelope for a control handler.
///
/// Control handlers must run with bounded resources that do NOT compete with
/// user-data traffic.  This struct captures the scheduling priority, poll
/// quota, and deadline budget that the runtime should reserve for a handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlBudget {
    /// Scheduling priority (0 = lowest, 255 = highest).
    /// Control handlers default to 240 — well above normal user traffic
    /// (typically 128) but below the break-glass emergency ceiling (255).
    pub priority: u8,
    /// Maximum number of polls before the handler must yield.
    pub poll_quota: u32,
    /// Soft deadline for a single handler invocation.
    pub deadline: Duration,
}

impl Default for ControlBudget {
    fn default() -> Self {
        Self {
            priority: 240,
            poll_quota: 256,
            deadline: Duration::from_millis(50),
        }
    }
}

impl ControlBudget {
    /// Break-glass budget: maximum priority, generous quota, short deadline.
    #[must_use]
    pub const fn break_glass() -> Self {
        Self {
            priority: 255,
            poll_quota: 512,
            deadline: Duration::from_millis(100),
        }
    }
}

// ---------------------------------------------------------------------------
// Advisory damping policy
// ---------------------------------------------------------------------------

/// Policy controlling how advisory subjects feed into policy loops.
///
/// **Critical guardrail:** advisories must NOT automatically trigger further
/// control-plane actions without explicit damping.  This prevents the control
/// plane from amplifying its own observations into a feedback storm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryDampingPolicy {
    /// Minimum interval between re-evaluation of the same advisory class.
    pub min_interval: Duration,
    /// Maximum number of advisory events that can contribute to a single
    /// policy evaluation window.
    pub max_events_per_window: u32,
    /// Whether an explicit operator intent (approval) is required before the
    /// advisory can trigger an automated action.
    pub requires_operator_intent: bool,
    /// Optional stratification tier — advisories at tier N cannot trigger
    /// actions that produce advisories at tier <= N.
    pub stratification_tier: Option<u8>,
}

impl Default for AdvisoryDampingPolicy {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(5),
            max_events_per_window: 10,
            requires_operator_intent: true,
            stratification_tier: None,
        }
    }
}

impl AdvisoryDampingPolicy {
    /// A permissive policy for non-recursive advisories that are known to be
    /// safe from feedback loops (e.g. health probes that produce no further
    /// control traffic).
    #[must_use]
    pub const fn non_recursive() -> Self {
        Self {
            min_interval: Duration::from_secs(1),
            max_events_per_window: 100,
            requires_operator_intent: false,
            stratification_tier: Some(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Delta-CRDT metadata for non-authoritative control surfaces
// ---------------------------------------------------------------------------

/// Join-semilattice interface for control-plane delta CRDTs.
///
/// These types are explicitly reserved for non-authoritative metadata such as
/// aggregated interest, coarse checkpoints, membership hints, load sketches,
/// and advisory summaries. Authoritative state still belongs in fenced control
/// capsules and obligation-backed protocols.
pub trait JoinSemilattice: Clone + PartialEq {
    /// Sparse delta type that can be merged into a full state.
    type Delta: Clone + PartialEq + Default;

    /// Join another replica into `self`.
    fn merge(&mut self, other: &Self);

    /// Produce the sparse delta needed to advance `baseline` to `self`.
    fn delta(&self, baseline: &Self) -> Self::Delta;

    /// Return whether `delta` carries no material state change.
    fn delta_is_empty(delta: &Self::Delta) -> bool {
        delta == &Self::Delta::default()
    }

    /// Apply a sparse delta produced by [`Self::delta`].
    fn apply_delta(&mut self, delta: &Self::Delta) -> bool;
}

/// Version vector tracking the highest converged CRDT version per replica.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplicaVersionVector {
    versions: BTreeMap<NodeId, u64>,
}

impl ReplicaVersionVector {
    /// Return the current converged version for `replica`.
    #[must_use]
    pub fn version(&self, replica: &NodeId) -> u64 {
        self.versions.get(replica).copied().unwrap_or(0)
    }

    /// Advance the local version for `replica` and return the new value.
    pub fn advance(&mut self, replica: &NodeId) -> u64 {
        let entry = self.versions.entry(replica.clone()).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    /// Observe a remote version for `replica`.
    pub fn observe(&mut self, replica: &NodeId, version: u64) {
        let entry = self.versions.entry(replica.clone()).or_insert(0);
        *entry = (*entry).max(version);
    }

    /// Join another version vector into `self`.
    pub fn merge(&mut self, other: &Self) {
        for (replica, version) in &other.versions {
            self.observe(replica, *version);
        }
    }

    fn same_except(&self, other: &Self, except: &NodeId) -> bool {
        self.all_replicas(other)
            .into_iter()
            .filter(|replica| replica != except)
            .all(|replica| self.version(&replica) == other.version(&replica))
    }

    fn dominates_except(&self, other: &Self, except: &NodeId) -> bool {
        self.all_replicas(other)
            .into_iter()
            .filter(|replica| replica != except)
            .all(|replica| self.version(&replica) >= other.version(&replica))
    }

    fn dominates(&self, other: &Self) -> bool {
        self.all_replicas(other)
            .into_iter()
            .all(|replica| self.version(&replica) >= other.version(&replica))
    }

    fn all_replicas(&self, other: &Self) -> BTreeSet<NodeId> {
        self.versions
            .keys()
            .chain(other.versions.keys())
            .cloned()
            .collect()
    }
}

/// Digest exchanged during anti-entropy to detect CRDT frontier divergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiEntropyDigest {
    steward: NodeId,
    frontier: ReplicaVersionVector,
}

impl AntiEntropyDigest {
    /// Steward that emitted this digest.
    #[must_use]
    pub fn steward(&self) -> &NodeId {
        &self.steward
    }

    /// Converged replica frontier advertised by the digest.
    #[must_use]
    pub fn frontier(&self) -> &ReplicaVersionVector {
        &self.frontier
    }
}

/// Propagation mode used for CRDT control metadata exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationMode {
    /// Peer is only one local step behind, so a narrow incremental delta is
    /// sufficient.
    Incremental,
    /// Peer is missing history or reconnecting after a partition, so send a
    /// full anti-entropy snapshot encoded as a CRDT delta from the empty state.
    AntiEntropy,
}

/// Delta envelope exchanged between stewards and relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagationEnvelope<D> {
    steward: NodeId,
    frontier: ReplicaVersionVector,
    mode: PropagationMode,
    delta: D,
}

impl<D> PropagationEnvelope<D> {
    /// Steward that emitted this envelope.
    #[must_use]
    pub fn steward(&self) -> &NodeId {
        &self.steward
    }

    /// Replica frontier carried by this envelope.
    #[must_use]
    pub fn frontier(&self) -> &ReplicaVersionVector {
        &self.frontier
    }

    /// Propagation mode for this envelope.
    #[must_use]
    pub const fn mode(&self) -> PropagationMode {
        self.mode
    }

    /// Delta payload carried by this envelope.
    #[must_use]
    pub fn delta(&self) -> &D {
        &self.delta
    }
}

/// Result of applying a propagation envelope to a local replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationApply {
    /// Envelope advanced local convergence state.
    Applied,
    /// Envelope was already covered by local state.
    AlreadySatisfied,
    /// Envelope could not be applied incrementally and anti-entropy repair is
    /// now required.
    NeedsAntiEntropy,
}

/// Deterministic propagation helper for non-authoritative control CRDTs.
///
/// The propagation path stays optimistic when a peer is only one local version
/// behind the current steward. If a relay gap or partition is detected, the
/// replica switches to anti-entropy mode and emits a compressed snapshot delta
/// from the empty state to restore convergence.
#[derive(Debug, Clone, PartialEq)]
pub struct CrdtPropagationReplica<T: JoinSemilattice + Default> {
    steward: NodeId,
    state: T,
    frontier: ReplicaVersionVector,
    last_local_update: Option<(u64, T::Delta)>,
    repair_needed: BTreeMap<NodeId, u64>,
}

impl<T> CrdtPropagationReplica<T>
where
    T: JoinSemilattice + Default,
{
    /// Create a new empty propagation replica for `steward`.
    #[must_use]
    pub fn new(steward: NodeId) -> Self {
        Self {
            steward,
            state: T::default(),
            frontier: ReplicaVersionVector::default(),
            last_local_update: None,
            repair_needed: BTreeMap::new(),
        }
    }

    /// Steward identity for this replica.
    #[must_use]
    pub fn steward(&self) -> &NodeId {
        &self.steward
    }

    /// Current converged CRDT state.
    #[must_use]
    pub fn state(&self) -> &T {
        &self.state
    }

    /// Current replica frontier.
    #[must_use]
    pub fn frontier(&self) -> &ReplicaVersionVector {
        &self.frontier
    }

    /// Return the current anti-entropy digest.
    #[must_use]
    pub fn digest(&self) -> AntiEntropyDigest {
        AntiEntropyDigest {
            steward: self.steward.clone(),
            frontier: self.frontier.clone(),
        }
    }

    /// Whether a remote origin has been marked for anti-entropy repair.
    #[must_use]
    pub fn needs_anti_entropy(&self) -> bool {
        !self.repair_needed.is_empty()
    }

    /// Record a local mutation and produce an incremental propagation envelope.
    pub fn mutate<F>(&mut self, mutate: F) -> Option<PropagationEnvelope<T::Delta>>
    where
        F: FnOnce(&mut T),
    {
        let mut updated = self.state.clone();
        mutate(&mut updated);
        self.record_local_state(updated)
    }

    /// Record a new local CRDT state and produce an incremental envelope.
    pub fn record_local_state(&mut self, updated: T) -> Option<PropagationEnvelope<T::Delta>> {
        let delta = updated.delta(&self.state);
        if T::delta_is_empty(&delta) {
            return None;
        }

        self.state = updated;
        let version = self.frontier.advance(&self.steward);
        self.last_local_update = Some((version, delta.clone()));

        Some(PropagationEnvelope {
            steward: self.steward.clone(),
            frontier: self.frontier.clone(),
            mode: PropagationMode::Incremental,
            delta,
        })
    }

    /// Prepare the best envelope for a peer with `digest`.
    #[must_use]
    pub fn prepare_for(&self, digest: &AntiEntropyDigest) -> Option<PropagationEnvelope<T::Delta>> {
        if self.frontier == digest.frontier {
            return None;
        }

        if self.can_send_incremental(digest) {
            let (_, delta) = self.last_local_update.as_ref()?;
            return Some(PropagationEnvelope {
                steward: self.steward.clone(),
                frontier: self.frontier.clone(),
                mode: PropagationMode::Incremental,
                delta: delta.clone(),
            });
        }

        self.snapshot_envelope()
    }

    /// Encode the full current state as an anti-entropy snapshot envelope.
    #[must_use]
    pub fn snapshot_envelope(&self) -> Option<PropagationEnvelope<T::Delta>> {
        let delta = self.state.delta(&T::default());
        if T::delta_is_empty(&delta) {
            return None;
        }

        Some(PropagationEnvelope {
            steward: self.steward.clone(),
            frontier: self.frontier.clone(),
            mode: PropagationMode::AntiEntropy,
            delta,
        })
    }

    /// Apply a remote propagation envelope.
    pub fn apply(&mut self, envelope: &PropagationEnvelope<T::Delta>) -> PropagationApply {
        match envelope.mode {
            PropagationMode::Incremental => self.apply_incremental(envelope),
            PropagationMode::AntiEntropy => self.apply_snapshot(envelope),
        }
    }

    fn apply_incremental(&mut self, envelope: &PropagationEnvelope<T::Delta>) -> PropagationApply {
        let remote_version = envelope.frontier.version(&envelope.steward);
        let local_version = self.frontier.version(&envelope.steward);

        if remote_version <= local_version && self.frontier.dominates(&envelope.frontier) {
            return PropagationApply::AlreadySatisfied;
        }

        let expected_next = local_version.saturating_add(1);
        if remote_version != expected_next
            || !self
                .frontier
                .dominates_except(&envelope.frontier, &envelope.steward)
        {
            self.repair_needed
                .insert(envelope.steward.clone(), remote_version);
            return PropagationApply::NeedsAntiEntropy;
        }

        if !self.state.apply_delta(&envelope.delta) {
            self.repair_needed
                .insert(envelope.steward.clone(), remote_version);
            return PropagationApply::NeedsAntiEntropy;
        }
        self.frontier.merge(&envelope.frontier);
        self.repair_needed.remove(&envelope.steward);
        PropagationApply::Applied
    }

    fn apply_snapshot(&mut self, envelope: &PropagationEnvelope<T::Delta>) -> PropagationApply {
        if self.frontier.dominates(&envelope.frontier) {
            return PropagationApply::AlreadySatisfied;
        }

        if !self.state.apply_delta(&envelope.delta) {
            self.repair_needed.insert(
                envelope.steward.clone(),
                envelope.frontier.version(&envelope.steward),
            );
            return PropagationApply::NeedsAntiEntropy;
        }
        self.frontier.merge(&envelope.frontier);
        for replica in envelope.frontier.versions.keys() {
            self.repair_needed.remove(replica);
        }
        PropagationApply::Applied
    }

    fn can_send_incremental(&self, digest: &AntiEntropyDigest) -> bool {
        let Some((version, _)) = &self.last_local_update else {
            return false;
        };

        digest.frontier.version(&self.steward).saturating_add(1) == *version
            && self.frontier.same_except(&digest.frontier, &self.steward)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ReplicaCounter {
    positive: BTreeMap<NodeId, u64>,
    negative: BTreeMap<NodeId, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ReplicaCounterDelta {
    positive: BTreeMap<NodeId, u64>,
    negative: BTreeMap<NodeId, u64>,
}

impl ReplicaCounter {
    fn increment(&mut self, replica: &NodeId, amount: u64) {
        if amount == 0 {
            return;
        }
        let entry = self.positive.entry(replica.clone()).or_insert(0);
        *entry = (*entry).saturating_add(amount);
    }

    fn decrement(&mut self, replica: &NodeId, amount: u64) {
        if amount == 0 {
            return;
        }
        let entry = self.negative.entry(replica.clone()).or_insert(0);
        *entry = (*entry).saturating_add(amount);
    }

    fn value(&self) -> u64 {
        let positive = self
            .positive
            .values()
            .fold(0_u64, |total, value| total.saturating_add(*value));
        let negative = self
            .negative
            .values()
            .fold(0_u64, |total, value| total.saturating_add(*value));
        positive.saturating_sub(negative)
    }

    fn merge_map(target: &mut BTreeMap<NodeId, u64>, source: &BTreeMap<NodeId, u64>) {
        for (replica, value) in source {
            let entry = target.entry(replica.clone()).or_insert(0);
            *entry = (*entry).max(*value);
        }
    }

    fn delta_map(
        current: &BTreeMap<NodeId, u64>,
        baseline: &BTreeMap<NodeId, u64>,
    ) -> BTreeMap<NodeId, u64> {
        current
            .iter()
            .filter_map(|(replica, value)| {
                let baseline_value = baseline.get(replica).copied().unwrap_or(0);
                (*value > baseline_value).then_some((replica.clone(), *value))
            })
            .collect()
    }

    fn apply_map(target: &mut BTreeMap<NodeId, u64>, delta: &BTreeMap<NodeId, u64>) {
        Self::merge_map(target, delta);
    }
}

impl JoinSemilattice for ReplicaCounter {
    type Delta = ReplicaCounterDelta;

    fn merge(&mut self, other: &Self) {
        Self::merge_map(&mut self.positive, &other.positive);
        Self::merge_map(&mut self.negative, &other.negative);
    }

    fn delta(&self, baseline: &Self) -> Self::Delta {
        ReplicaCounterDelta {
            positive: Self::delta_map(&self.positive, &baseline.positive),
            negative: Self::delta_map(&self.negative, &baseline.negative),
        }
    }

    fn apply_delta(&mut self, delta: &Self::Delta) -> bool {
        Self::apply_map(&mut self.positive, &delta.positive);
        Self::apply_map(&mut self.negative, &delta.negative);
        true
    }
}

/// Delta-CRDT summary of subscriber interest counts by subject pattern.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InterestSummary {
    counts: BTreeMap<SubjectPattern, ReplicaCounter>,
}

/// Sparse delta for [`InterestSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InterestSummaryDelta {
    counts: BTreeMap<SubjectPattern, ReplicaCounterDelta>,
}

impl InterestSummary {
    /// Register one subscriber interest for `pattern` on `replica`.
    pub fn subscribe(&mut self, replica: &NodeId, pattern: SubjectPattern) {
        self.counts
            .entry(pattern)
            .or_default()
            .increment(replica, 1);
    }

    /// Remove one subscriber interest for `pattern` on `replica`.
    ///
    /// Only decrements when the pattern already has local state (from a prior
    /// subscribe or an inbound delta).  Calling unsubscribe on a pattern that
    /// has never been observed is a no-op, preventing unbounded growth of
    /// zero-value entries from spurious or adversarial unsubscribe calls.
    pub fn unsubscribe(&mut self, replica: &NodeId, pattern: &SubjectPattern) {
        if let Some(counter) = self.counts.get_mut(pattern) {
            counter.decrement(replica, 1);
        }
    }

    /// Current converged subscriber count for `pattern`.
    #[must_use]
    pub fn interest_count(&self, pattern: &SubjectPattern) -> u64 {
        self.counts.get(pattern).map_or(0, ReplicaCounter::value)
    }
}

impl JoinSemilattice for InterestSummary {
    type Delta = InterestSummaryDelta;

    fn merge(&mut self, other: &Self) {
        for (pattern, counter) in &other.counts {
            self.counts
                .entry(pattern.clone())
                .or_default()
                .merge(counter);
        }
    }

    fn delta(&self, baseline: &Self) -> Self::Delta {
        let counts = self
            .counts
            .iter()
            .filter_map(|(pattern, counter)| {
                let baseline_counter = baseline.counts.get(pattern).cloned().unwrap_or_default();
                let delta = counter.delta(&baseline_counter);
                (!delta.positive.is_empty() || !delta.negative.is_empty())
                    .then_some((pattern.clone(), delta))
            })
            .collect();
        InterestSummaryDelta { counts }
    }

    fn apply_delta(&mut self, delta: &Self::Delta) -> bool {
        for (pattern, counter_delta) in &delta.counts {
            self.counts
                .entry(pattern.clone())
                .or_default()
                .apply_delta(counter_delta);
        }
        true
    }
}

/// Monotone coarse cursor position for one consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorMark {
    offset: u64,
    checkpoint_unix_ms: u64,
    steward: NodeId,
}

impl CursorMark {
    /// Create a new coarse cursor mark.
    #[must_use]
    pub fn new(offset: u64, checkpoint_unix_ms: u64, steward: NodeId) -> Self {
        Self {
            offset,
            checkpoint_unix_ms,
            steward,
        }
    }

    /// Highest fully observed offset represented by this mark.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Capture timestamp for the mark.
    #[must_use]
    pub const fn checkpoint_unix_ms(&self) -> u64 {
        self.checkpoint_unix_ms
    }

    /// Steward that emitted this mark.
    #[must_use]
    pub fn steward(&self) -> &NodeId {
        &self.steward
    }

    fn is_newer_than(&self, other: &Self) -> bool {
        (self.offset, self.checkpoint_unix_ms, self.steward.as_str())
            > (
                other.offset,
                other.checkpoint_unix_ms,
                other.steward.as_str(),
            )
    }
}

/// Delta-CRDT summary of coarse consumer cursor positions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CursorCheckpoint {
    checkpoints: BTreeMap<String, CursorMark>,
}

/// Sparse delta for [`CursorCheckpoint`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CursorCheckpointDelta {
    checkpoints: BTreeMap<String, CursorMark>,
}

impl CursorCheckpoint {
    /// Observe a newer checkpoint for `consumer`.
    pub fn observe(&mut self, consumer: impl Into<String>, mark: CursorMark) {
        let consumer = consumer.into();
        match self.checkpoints.get_mut(&consumer) {
            Some(existing) if mark.is_newer_than(existing) => *existing = mark,
            None => {
                self.checkpoints.insert(consumer, mark);
            }
            Some(_) => {}
        }
    }

    /// Return the current converged mark for `consumer`.
    #[must_use]
    pub fn checkpoint(&self, consumer: &str) -> Option<&CursorMark> {
        self.checkpoints.get(consumer)
    }
}

impl JoinSemilattice for CursorCheckpoint {
    type Delta = CursorCheckpointDelta;

    fn merge(&mut self, other: &Self) {
        for (consumer, mark) in &other.checkpoints {
            self.observe(consumer.clone(), mark.clone());
        }
    }

    fn delta(&self, baseline: &Self) -> Self::Delta {
        let checkpoints = self
            .checkpoints
            .iter()
            .filter_map(
                |(consumer, mark)| match baseline.checkpoints.get(consumer) {
                    Some(existing) if !mark.is_newer_than(existing) => None,
                    _ => Some((consumer.clone(), mark.clone())),
                },
            )
            .collect();
        CursorCheckpointDelta { checkpoints }
    }

    fn apply_delta(&mut self, delta: &Self::Delta) -> bool {
        for (consumer, mark) in &delta.checkpoints {
            self.observe(consumer.clone(), mark.clone());
        }
        true
    }
}

/// Coarse membership state used for non-authoritative control hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MembershipState {
    /// No useful information yet.
    Unknown,
    /// Replica is joining the fabric.
    Joining,
    /// Replica is healthy and serving.
    Healthy,
    /// Replica is reachable but degraded.
    Degraded,
    /// Replica is draining or preparing to leave.
    Leaving,
    /// Replica has been removed from the non-authoritative view.
    Removed,
}

/// Versioned non-authoritative membership record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRecord {
    version: u64,
    state: MembershipState,
    last_heartbeat_unix_ms: u64,
    load_per_mille: u16,
}

impl MembershipRecord {
    /// Construct a new membership record snapshot.
    #[must_use]
    pub const fn new(
        version: u64,
        state: MembershipState,
        last_heartbeat_unix_ms: u64,
        load_per_mille: u16,
    ) -> Self {
        Self {
            version,
            state,
            last_heartbeat_unix_ms,
            load_per_mille,
        }
    }

    /// Monotone version stamp for this record.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Current coarse membership state.
    #[must_use]
    pub const fn state(&self) -> MembershipState {
        self.state
    }

    /// Last heartbeat carried by the record.
    #[must_use]
    pub const fn last_heartbeat_unix_ms(&self) -> u64 {
        self.last_heartbeat_unix_ms
    }

    /// Advertised load in per-mille units.
    #[must_use]
    pub const fn load_per_mille(&self) -> u16 {
        self.load_per_mille
    }

    fn is_newer_than(&self, other: &Self) -> bool {
        (
            self.version,
            self.last_heartbeat_unix_ms,
            self.state,
            self.load_per_mille,
        ) > (
            other.version,
            other.last_heartbeat_unix_ms,
            other.state,
            other.load_per_mille,
        )
    }
}

/// Delta-CRDT view of non-authoritative replica membership.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MembershipView {
    records: BTreeMap<NodeId, MembershipRecord>,
}

/// Sparse delta for [`MembershipView`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MembershipViewDelta {
    records: BTreeMap<NodeId, MembershipRecord>,
}

impl MembershipView {
    /// Observe a versioned membership record for `node`.
    pub fn observe(&mut self, node: NodeId, record: MembershipRecord) {
        match self.records.get_mut(&node) {
            Some(existing) if record.is_newer_than(existing) => *existing = record,
            None => {
                self.records.insert(node, record);
            }
            Some(_) => {}
        }
    }

    /// Return the current converged record for `node`.
    #[must_use]
    pub fn record(&self, node: &NodeId) -> Option<&MembershipRecord> {
        self.records.get(node)
    }
}

impl JoinSemilattice for MembershipView {
    type Delta = MembershipViewDelta;

    fn merge(&mut self, other: &Self) {
        for (node, record) in &other.records {
            self.observe(node.clone(), record.clone());
        }
    }

    fn delta(&self, baseline: &Self) -> Self::Delta {
        let records = self
            .records
            .iter()
            .filter_map(|(node, record)| match baseline.records.get(node) {
                Some(existing) if !record.is_newer_than(existing) => None,
                _ => Some((node.clone(), record.clone())),
            })
            .collect();
        MembershipViewDelta { records }
    }

    fn apply_delta(&mut self, delta: &Self::Delta) -> bool {
        for (node, record) in &delta.records {
            self.observe(node.clone(), record.clone());
        }
        true
    }
}

/// Bucketed delta-CRDT sketch for lag and load observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LagSketch {
    bucket_width: u64,
    buckets: BTreeMap<u64, ReplicaCounter>,
}

/// Sparse delta for [`LagSketch`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LagSketchDelta {
    bucket_width: u64,
    buckets: BTreeMap<u64, ReplicaCounterDelta>,
}

impl LagSketch {
    /// Create a new sketch with a deterministic `bucket_width`.
    #[must_use]
    pub fn new(bucket_width: u64) -> Self {
        Self {
            bucket_width: bucket_width.max(1),
            buckets: BTreeMap::new(),
        }
    }

    /// Sketch bucket width in units of observed lag.
    #[must_use]
    pub const fn bucket_width(&self) -> u64 {
        self.bucket_width
    }

    fn bucket_index(&self, lag: u64) -> u64 {
        lag / self.bucket_width
    }

    fn bucket_midpoint(&self, bucket: u64) -> u64 {
        bucket
            .saturating_mul(self.bucket_width)
            .saturating_add(self.bucket_width / 2)
    }

    /// Record one lag observation for `replica`.
    pub fn observe(&mut self, replica: &NodeId, lag: u64) {
        self.buckets
            .entry(self.bucket_index(lag))
            .or_default()
            .increment(replica, 1);
    }

    /// Compatibility alias for recording one lag observation.
    pub fn record(&mut self, replica: &NodeId, lag: u64) {
        self.observe(replica, lag);
    }

    /// Total number of samples represented by the sketch.
    #[must_use]
    pub fn total_samples(&self) -> u64 {
        self.buckets.values().fold(0_u64, |total, counter| {
            total.saturating_add(counter.value())
        })
    }

    /// Number of populated buckets in the sketch.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Midpoint-based mean estimate.
    #[must_use]
    pub fn estimated_mean(&self) -> Option<u64> {
        let total_samples = self.total_samples();
        if total_samples == 0 {
            return None;
        }

        let weighted_sum = self
            .buckets
            .iter()
            .fold(0_u128, |total, (bucket, counter)| {
                total.saturating_add(
                    u128::from(self.bucket_midpoint(*bucket))
                        .saturating_mul(u128::from(counter.value())),
                )
            });
        Some((weighted_sum / u128::from(total_samples)) as u64)
    }

    /// Worst-case absolute error of [`Self::estimated_mean`] under midpoint
    /// reconstruction.
    #[must_use]
    pub const fn max_mean_error_bound(&self) -> u64 {
        self.bucket_width / 2
    }
}

impl Default for LagSketch {
    fn default() -> Self {
        Self::new(16)
    }
}

impl JoinSemilattice for LagSketch {
    type Delta = LagSketchDelta;

    fn merge(&mut self, other: &Self) {
        if self.bucket_width != other.bucket_width {
            // Adopt the peer's width when the local state is empty (fresh
            // replica).  Once data exists the width is locked in and
            // mismatched peers are silently ignored — this is a deployment
            // configuration error, not something merge can resolve.
            if self.buckets.is_empty() {
                self.bucket_width = other.bucket_width;
            } else {
                return;
            }
        }
        for (bucket, counter) in &other.buckets {
            self.buckets.entry(*bucket).or_default().merge(counter);
        }
    }

    fn delta(&self, baseline: &Self) -> Self::Delta {
        let buckets = if self.bucket_width == baseline.bucket_width {
            self.buckets
                .iter()
                .filter_map(|(bucket, counter)| {
                    let baseline_counter =
                        baseline.buckets.get(bucket).cloned().unwrap_or_default();
                    let delta = counter.delta(&baseline_counter);
                    (!delta.positive.is_empty() || !delta.negative.is_empty())
                        .then_some((*bucket, delta))
                })
                .collect()
        } else {
            self.buckets
                .iter()
                .map(|(bucket, counter)| (*bucket, counter.delta(&ReplicaCounter::default())))
                .collect()
        };
        LagSketchDelta {
            bucket_width: self.bucket_width,
            buckets,
        }
    }

    fn delta_is_empty(delta: &Self::Delta) -> bool {
        delta.buckets.is_empty()
    }

    fn apply_delta(&mut self, delta: &Self::Delta) -> bool {
        if self.bucket_width != delta.bucket_width {
            // Adopt the incoming width when the local state is empty (fresh
            // replica joining an established cluster).  When local data
            // already exists, return true to break the anti-entropy retry
            // loop — the mismatch is a configuration error that retrying
            // will never resolve.
            if self.buckets.is_empty() {
                self.bucket_width = delta.bucket_width;
            } else {
                return true;
            }
        }
        for (bucket, counter_delta) in &delta.buckets {
            self.buckets
                .entry(*bucket)
                .or_default()
                .apply_delta(counter_delta);
        }
        true
    }
}

/// Windowed delta-CRDT aggregate of advisory counts and rates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryAggregate {
    window_width_ms: u64,
    windows: BTreeMap<u64, BTreeMap<String, ReplicaCounter>>,
}

/// Sparse delta for [`AdvisoryAggregate`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdvisoryAggregateDelta {
    window_width_ms: u64,
    windows: BTreeMap<u64, BTreeMap<String, ReplicaCounterDelta>>,
}

impl AdvisoryAggregate {
    /// Create a new aggregate with fixed `window_width_ms`.
    #[must_use]
    pub fn new(window_width_ms: u64) -> Self {
        Self {
            window_width_ms: window_width_ms.max(1),
            windows: BTreeMap::new(),
        }
    }

    /// Width of each advisory aggregation window.
    #[must_use]
    pub const fn window_width_ms(&self) -> u64 {
        self.window_width_ms
    }

    fn window_start(&self, ts_unix_ms: u64) -> u64 {
        ts_unix_ms - (ts_unix_ms % self.window_width_ms)
    }

    /// Record one advisory kind observation in the corresponding window.
    pub fn record_kind(&mut self, replica: &NodeId, advisory_kind: &str, ts_unix_ms: u64) {
        self.windows
            .entry(self.window_start(ts_unix_ms))
            .or_default()
            .entry(advisory_kind.to_owned())
            .or_default()
            .increment(replica, 1);
    }

    /// Prune windows strictly older than the window containing `cutoff_unix_ms`.
    ///
    /// This is an explicit retention hook so callers can bound memory only once
    /// a cutoff is known to be causally safe for every steward.
    pub fn prune_before(&mut self, cutoff_unix_ms: u64) {
        let first_retained_window = self.window_start(cutoff_unix_ms);
        self.windows
            .retain(|window_start, _| *window_start >= first_retained_window);
    }

    /// Return the converged count for `advisory_kind` in `window_start`.
    #[must_use]
    pub fn count(&self, window_start: u64, advisory_kind: &str) -> u64 {
        self.windows
            .get(&window_start)
            .and_then(|kinds| kinds.get(advisory_kind))
            .map_or(0, ReplicaCounter::value)
    }

    /// Return the converged per-second rate for `advisory_kind` in
    /// `window_start`.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn rate_per_second(&self, window_start: u64, advisory_kind: &str) -> f64 {
        let count = self.count(window_start, advisory_kind) as f64;
        count * 1000.0 / self.window_width_ms as f64
    }
}

impl Default for AdvisoryAggregate {
    fn default() -> Self {
        Self::new(60_000)
    }
}

impl JoinSemilattice for AdvisoryAggregate {
    type Delta = AdvisoryAggregateDelta;

    fn merge(&mut self, other: &Self) {
        if self.window_width_ms != other.window_width_ms {
            if self.windows.is_empty() {
                self.window_width_ms = other.window_width_ms;
            } else {
                return;
            }
        }
        for (window_start, kinds) in &other.windows {
            let window = self.windows.entry(*window_start).or_default();
            for (kind, counter) in kinds {
                window.entry(kind.clone()).or_default().merge(counter);
            }
        }
    }

    fn delta(&self, baseline: &Self) -> Self::Delta {
        let windows = if self.window_width_ms == baseline.window_width_ms {
            self.windows
                .iter()
                .filter_map(|(window_start, kinds)| {
                    let mut delta_kinds = BTreeMap::new();
                    for (kind, counter) in kinds {
                        let baseline_counter = baseline
                            .windows
                            .get(window_start)
                            .and_then(|baseline_kinds| baseline_kinds.get(kind))
                            .cloned()
                            .unwrap_or_default();
                        let delta = counter.delta(&baseline_counter);
                        if !delta.positive.is_empty() || !delta.negative.is_empty() {
                            delta_kinds.insert(kind.clone(), delta);
                        }
                    }
                    (!delta_kinds.is_empty()).then_some((*window_start, delta_kinds))
                })
                .collect()
        } else {
            self.windows
                .iter()
                .map(|(window_start, kinds)| {
                    let delta_kinds = kinds
                        .iter()
                        .map(|(kind, counter)| {
                            (kind.clone(), counter.delta(&ReplicaCounter::default()))
                        })
                        .collect();
                    (*window_start, delta_kinds)
                })
                .collect()
        };
        AdvisoryAggregateDelta {
            window_width_ms: self.window_width_ms,
            windows,
        }
    }

    fn delta_is_empty(delta: &Self::Delta) -> bool {
        delta.windows.is_empty()
    }

    fn apply_delta(&mut self, delta: &Self::Delta) -> bool {
        if self.window_width_ms != delta.window_width_ms {
            if self.windows.is_empty() {
                self.window_width_ms = delta.window_width_ms;
            } else {
                return true;
            }
        }
        for (window_start, kinds) in &delta.windows {
            let window = self.windows.entry(*window_start).or_default();
            for (kind, counter_delta) in kinds {
                window
                    .entry(kind.clone())
                    .or_default()
                    .apply_delta(counter_delta);
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Advisory types with FrankenSuite evidence
// ---------------------------------------------------------------------------

/// Classification of control-plane advisory events.
///
/// Each variant represents a material control-plane decision or state change
/// that operators need full provenance for — not just "gateway detached" but
/// *why*, *what edges were affected*, and *what evidence justified it*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAdvisoryType {
    /// A capability graph edge was added, removed, or modified.
    CapabilityGraphChange {
        /// Subject patterns whose capability edges were affected.
        affected_subjects: Vec<SubjectPattern>,
        /// Human-readable description of what changed.
        description: String,
    },
    /// An obligation was transferred, aborted, or scheduled for replay.
    ObligationTransfer {
        /// The kind of obligation lifecycle event.
        action: ObligationTransferAction,
        /// Subject carrying the obligation.
        subject: Subject,
    },
    /// A policy decision was made (e.g. failover, load-shed, drain).
    PolicyDecision {
        /// Name of the policy that made the decision.
        policy_name: String,
        /// The action chosen by the policy.
        action_chosen: String,
        /// Why this action was chosen (human-readable).
        justification: String,
    },
    /// A structured evidence record was emitted for operator review.
    EvidenceRecord {
        /// Stable identifier for the emitted evidence record.
        evidence_id: String,
        /// Subsystem/component that produced the evidence.
        component: String,
        /// Action or decision summarized by the evidence.
        action: String,
        /// Human-readable summary of why the evidence matters.
        summary: String,
    },
    /// A break-glass recovery action was taken.
    BreakGlassActivation {
        /// Reason the break-glass path was triggered.
        reason: String,
    },
}

impl ControlAdvisoryType {
    /// Stable advisory kind name used for filtering and serialized payloads.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::CapabilityGraphChange { .. } => "capability_graph_change",
            Self::ObligationTransfer { .. } => "obligation_transfer",
            Self::PolicyDecision { .. } => "policy_decision",
            Self::EvidenceRecord { .. } => "evidence_record",
            Self::BreakGlassActivation { .. } => "break_glass_activation",
        }
    }
}

/// Obligation lifecycle actions that produce advisories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObligationTransferAction {
    /// Obligation custody was transferred to another handler.
    Transferred,
    /// Obligation was aborted (could not be fulfilled).
    Aborted,
    /// Obligation was scheduled for replay/retry.
    ReplayScheduled,
}

impl fmt::Display for ObligationTransferAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transferred => write!(f, "transferred"),
            Self::Aborted => write!(f, "aborted"),
            Self::ReplayScheduled => write!(f, "replay_scheduled"),
        }
    }
}

/// A control-plane advisory with full FrankenSuite evidence provenance.
///
/// This is the primary artifact emitted when a material control-plane
/// decision occurs.  Operators get decision provenance — not just "what
/// happened" but "why, with what evidence, and what was the alternative".
#[derive(Debug, Clone)]
pub struct ControlAdvisory {
    /// Classification of the advisory event.
    pub advisory_type: ControlAdvisoryType,
    /// System subject family this advisory belongs to.
    pub family: SystemSubjectFamily,
    /// Subject the advisory should be published on.
    pub subject: Subject,
    /// Trace context linking this advisory to a distributed trace.
    pub trace_id: TraceId,
    /// Decision identifier linking to the FrankenSuite decision record.
    pub decision_id: DecisionId,
    /// Unix timestamp in milliseconds when the advisory was created.
    pub ts_unix_ms: u64,
    /// The full decision audit entry with posterior, losses, and
    /// calibration data.  `None` for advisories that are pure
    /// notifications without a decision contract evaluation.
    pub decision_audit: Option<DecisionAuditEntry>,
}

/// Typed filter for advisory subscription and operator views.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlAdvisoryFilter {
    /// Limit matches to one control-plane family.
    pub family: Option<SystemSubjectFamily>,
    /// Limit matches to a single advisory kind.
    pub advisory_kind: Option<&'static str>,
    /// If true, only advisories carrying FrankenSuite decision provenance
    /// should match.
    pub require_decision_provenance: bool,
}

impl ControlAdvisory {
    fn derived_evidence_id(family: SystemSubjectFamily, audit: &DecisionAuditEntry) -> String {
        format!(
            "control:{}:{}:{}",
            family.name().to_ascii_lowercase(),
            audit.decision_id,
            audit.ts_unix_ms
        )
    }

    /// Create a new advisory from a decision outcome.
    ///
    /// This is the preferred constructor when a FrankenSuite decision
    /// contract has been evaluated.
    #[must_use]
    pub fn from_decision(
        advisory_type: ControlAdvisoryType,
        family: SystemSubjectFamily,
        subject: Subject,
        outcome: &DecisionOutcome,
    ) -> Self {
        let audit = &outcome.audit_entry;
        Self {
            advisory_type,
            family,
            subject,
            trace_id: audit.trace_id,
            decision_id: audit.decision_id,
            ts_unix_ms: audit.ts_unix_ms,
            decision_audit: Some(audit.clone()),
        }
    }

    /// Create an explicit evidence-record advisory from a decision outcome.
    ///
    /// Use this when operators need an advisory that names the evidence bundle
    /// directly rather than inferring it from a policy-decision payload.
    #[must_use]
    pub fn evidence_record(
        family: SystemSubjectFamily,
        subject: Subject,
        outcome: &DecisionOutcome,
        summary: impl Into<String>,
    ) -> Self {
        let audit = &outcome.audit_entry;
        Self::from_decision(
            ControlAdvisoryType::EvidenceRecord {
                evidence_id: Self::derived_evidence_id(family, audit),
                component: audit.contract_name.clone(),
                action: audit.action_chosen.clone(),
                summary: summary.into(),
            },
            family,
            subject,
            outcome,
        )
    }

    /// Create a notification-only advisory (no decision contract).
    #[must_use]
    pub fn notification(
        advisory_type: ControlAdvisoryType,
        family: SystemSubjectFamily,
        subject: Subject,
        trace_id: TraceId,
        ts_unix_ms: u64,
    ) -> Self {
        Self {
            advisory_type,
            family,
            subject,
            trace_id,
            decision_id: DecisionId::from_raw(0),
            ts_unix_ms,
            decision_audit: None,
        }
    }

    /// Convert the decision audit (if present) to an evidence ledger entry.
    ///
    /// Returns `None` if this advisory has no associated decision audit.
    #[must_use]
    pub fn to_evidence_ledger(&self) -> Option<EvidenceLedger> {
        self.decision_audit
            .as_ref()
            .map(DecisionAuditEntry::to_evidence_ledger)
    }

    /// Stable evidence identifier for this advisory when provenance exists.
    #[must_use]
    pub fn evidence_id(&self) -> Option<String> {
        match &self.advisory_type {
            ControlAdvisoryType::EvidenceRecord { evidence_id, .. } => Some(evidence_id.clone()),
            _ => self
                .decision_audit
                .as_ref()
                .map(|audit| Self::derived_evidence_id(self.family, audit)),
        }
    }

    /// Whether this advisory carries decision provenance.
    #[must_use]
    pub fn has_decision_provenance(&self) -> bool {
        self.decision_audit.is_some()
    }

    /// Returns `true` when this advisory matches the given typed filter.
    #[must_use]
    pub fn matches_filter(&self, filter: &ControlAdvisoryFilter) -> bool {
        if let Some(family) = filter.family
            && self.family != family
        {
            return false;
        }
        if let Some(kind) = filter.advisory_kind
            && self.advisory_type.kind() != kind
        {
            return false;
        }
        !filter.require_decision_provenance || self.has_decision_provenance()
    }

    /// Serialize the advisory payload to JSON bytes for publication.
    #[must_use]
    pub fn to_json_payload(&self) -> Vec<u8> {
        // Keep the payload deterministic, but preserve typed values and
        // variant-specific details instead of flattening everything into
        // string fields.
        let mut payload = BTreeMap::new();
        payload.insert(
            "decision_id",
            serde_json::Value::String(format!("{}", self.decision_id)),
        );
        payload.insert(
            "family",
            serde_json::Value::String(self.family.name().to_owned()),
        );
        payload.insert(
            "has_decision_provenance",
            serde_json::Value::Bool(self.has_decision_provenance()),
        );
        payload.insert(
            "subject",
            serde_json::Value::String(self.subject.as_str().to_owned()),
        );
        payload.insert(
            "trace_id",
            serde_json::Value::String(format!("{}", self.trace_id)),
        );
        payload.insert("ts_unix_ms", serde_json::Value::from(self.ts_unix_ms));
        payload.insert(
            "type",
            serde_json::Value::String(self.advisory_type.kind().to_owned()),
        );
        if let Some(evidence_id) = self.evidence_id() {
            payload.insert("evidence_id", serde_json::Value::String(evidence_id));
        }

        match &self.advisory_type {
            ControlAdvisoryType::CapabilityGraphChange {
                affected_subjects,
                description,
            } => {
                payload.insert(
                    "affected_subjects",
                    serde_json::Value::Array(
                        affected_subjects
                            .iter()
                            .map(|pattern| serde_json::Value::String(pattern.as_str().to_owned()))
                            .collect(),
                    ),
                );
                payload.insert(
                    "description",
                    serde_json::Value::String(description.clone()),
                );
            }
            ControlAdvisoryType::ObligationTransfer { action, subject } => {
                payload.insert("action", serde_json::Value::String(action.to_string()));
                payload.insert(
                    "obligation_subject",
                    serde_json::Value::String(subject.as_str().to_owned()),
                );
            }
            ControlAdvisoryType::PolicyDecision {
                policy_name,
                action_chosen,
                justification,
            } => {
                payload.insert(
                    "policy_name",
                    serde_json::Value::String(policy_name.clone()),
                );
                payload.insert(
                    "action_chosen",
                    serde_json::Value::String(action_chosen.clone()),
                );
                payload.insert(
                    "justification",
                    serde_json::Value::String(justification.clone()),
                );
            }
            ControlAdvisoryType::EvidenceRecord {
                component,
                action,
                summary,
                ..
            } => {
                payload.insert("component", serde_json::Value::String(component.clone()));
                payload.insert("action", serde_json::Value::String(action.clone()));
                payload.insert("summary", serde_json::Value::String(summary.clone()));
            }
            ControlAdvisoryType::BreakGlassActivation { reason } => {
                payload.insert("reason", serde_json::Value::String(reason.clone()));
            }
        }

        serde_json::to_vec(&payload).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Control handler
// ---------------------------------------------------------------------------

/// Outcome of a control handler invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    /// Handler processed the event successfully.
    Ok,
    /// Handler processed the event but produced an advisory that should be
    /// published on the given subject.
    Advisory {
        /// Subject for the advisory message.
        subject: Subject,
        /// Opaque advisory payload (JSON-encoded for interoperability).
        payload: Vec<u8>,
    },
    /// Handler could not process the event within its budget.
    BudgetExhausted,
    /// Handler encountered an error.
    Error {
        /// Human-readable error description.
        message: String,
    },
}

/// Registration record for a single control handler.
///
/// Each control handler is region-owned, which means it participates in
/// structured concurrency: the handler's region must close to quiescence
/// before the parent scope exits.
#[derive(Debug, Clone)]
pub struct ControlHandler {
    /// Unique handler identifier (scoped to the control namespace).
    pub id: ControlHandlerId,
    /// Which system subject family this handler serves.
    pub family: SystemSubjectFamily,
    /// Subject pattern the handler subscribes to within its family.
    pub pattern: SubjectPattern,
    /// Reserved budget for this handler.
    pub budget: ControlBudget,
    /// Advisory damping policy applied to any advisories this handler emits.
    pub damping: AdvisoryDampingPolicy,
    /// Whether this handler is a break-glass recovery handler.
    pub break_glass: bool,
}

/// Opaque identifier for a registered control handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlHandlerId(u64);

impl ControlHandlerId {
    /// Create a new handler identifier.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ControlHandlerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ctrl-{}", self.0)
    }
}

/// Tenant/service-scoped control surface under one `$SYS.FABRIC.<FAMILY>` root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceControlScope {
    family: SystemSubjectFamily,
    tenant: NamespaceComponent,
    service: NamespaceComponent,
}

impl NamespaceControlScope {
    /// Build a control scope directly from an existing namespace kernel.
    #[must_use]
    pub fn from_namespace(family: SystemSubjectFamily, namespace: &NamespaceKernel) -> Self {
        Self {
            family,
            tenant: namespace.tenant().clone(),
            service: namespace.service().clone(),
        }
    }

    /// Build a validated tenant/service control scope for one system family.
    pub fn new(
        family: SystemSubjectFamily,
        tenant: impl AsRef<str>,
        service: impl AsRef<str>,
    ) -> Result<Self, NamespaceKernelError> {
        Ok(Self {
            family,
            tenant: NamespaceComponent::parse(tenant)?,
            service: NamespaceComponent::parse(service)?,
        })
    }

    /// Return the control family covered by this scope.
    #[must_use]
    pub const fn family(&self) -> SystemSubjectFamily {
        self.family
    }

    /// Return the tenant component.
    #[must_use]
    pub fn tenant(&self) -> &NamespaceComponent {
        &self.tenant
    }

    /// Return the service component.
    #[must_use]
    pub fn service(&self) -> &NamespaceComponent {
        &self.service
    }

    /// Return the namespace-scoped wildcard pattern for this control surface.
    #[must_use]
    pub fn wildcard_pattern(&self) -> SubjectPattern {
        SubjectPattern::new(format!(
            "{}.TENANT.{}.SERVICE.{}.>",
            self.family.prefix(),
            self.tenant,
            self.service
        ))
    }

    /// Return one concrete channel subject inside this control scope.
    pub fn subject(&self, channel: impl AsRef<str>) -> Result<Subject, NamespaceKernelError> {
        let channel = NamespaceComponent::parse(channel)?;
        Ok(Subject::new(format!(
            "{}.TENANT.{}.SERVICE.{}.{}",
            self.family.prefix(),
            self.tenant,
            self.service,
            channel
        )))
    }
}

// ---------------------------------------------------------------------------
// Control namespace registry
// ---------------------------------------------------------------------------

/// Error returned when registering or looking up control handlers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlRegistryError {
    /// The subject pattern is not under `$SYS.FABRIC.`.
    #[error("control subject must be under $SYS.FABRIC.*: got `{pattern}`")]
    InvalidPrefix {
        /// The offending subject pattern.
        pattern: String,
    },
    /// The subject pattern is not scoped to the declared family.
    #[error("control subject `{pattern}` does not belong to family `{family}`")]
    FamilyMismatch {
        /// The declared family for the handler.
        family: SystemSubjectFamily,
        /// The offending subject pattern.
        pattern: String,
    },
    /// A handler with the same ID is already registered.
    #[error("duplicate handler id: {id}")]
    DuplicateId {
        /// The duplicate handler identifier.
        id: ControlHandlerId,
    },
    /// The system subject family is not recognized.
    #[error("unknown system subject family in pattern: `{pattern}`")]
    UnknownFamily {
        /// The unrecognized subject pattern.
        pattern: String,
    },
}

/// Registry of active control handlers.
///
/// The registry owns the set of control handler registrations and provides
/// dispatch lookup by subject.  It does NOT own the handler futures
/// themselves — those live in the runtime's region tree.
#[derive(Debug, Clone)]
pub struct ControlRegistry {
    handlers: BTreeMap<ControlHandlerId, ControlHandler>,
    next_id: u64,
    /// Break-glass handlers are always available, even when the ordinary
    /// fabric is degraded.  They are indexed separately for fast lookup.
    break_glass_ids: Vec<ControlHandlerId>,
}

impl Default for ControlRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlRegistry {
    /// Create an empty control registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
            next_id: 0,
            break_glass_ids: Vec::new(),
        }
    }

    /// Register a control handler.
    ///
    /// The pattern must start with `$SYS.FABRIC.` and remain scoped to the
    /// declared family; otherwise [`ControlRegistryError::InvalidPrefix`] or
    /// [`ControlRegistryError::FamilyMismatch`] is returned.
    pub fn register(
        &mut self,
        family: SystemSubjectFamily,
        pattern: SubjectPattern,
        budget: ControlBudget,
        damping: AdvisoryDampingPolicy,
        break_glass: bool,
    ) -> Result<ControlHandlerId, ControlRegistryError> {
        let pat_str = pattern.as_str();
        if !pat_str.starts_with("$SYS.FABRIC.") {
            return Err(ControlRegistryError::InvalidPrefix {
                pattern: pat_str.to_owned(),
            });
        }
        let family_prefix = family.prefix();
        if pat_str != family_prefix
            && !pat_str
                .strip_prefix(&family_prefix)
                .is_some_and(|suffix| suffix.starts_with('.'))
        {
            return Err(ControlRegistryError::FamilyMismatch {
                family,
                pattern: pat_str.to_owned(),
            });
        }
        let id = ControlHandlerId::new(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("control handler id counter exhausted");

        let handler = ControlHandler {
            id,
            family,
            pattern,
            budget,
            damping,
            break_glass,
        };
        self.handlers.insert(id, handler);
        if break_glass {
            self.break_glass_ids.push(id);
        }
        Ok(id)
    }

    /// Register a handler with default budget and damping for the given
    /// family.
    pub fn register_default(
        &mut self,
        family: SystemSubjectFamily,
    ) -> Result<ControlHandlerId, ControlRegistryError> {
        self.register(
            family,
            family.wildcard_pattern(),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        )
    }

    /// Register a tenant/service-scoped control handler.
    pub fn register_namespace(
        &mut self,
        scope: &NamespaceControlScope,
        budget: ControlBudget,
        damping: AdvisoryDampingPolicy,
        break_glass: bool,
    ) -> Result<ControlHandlerId, ControlRegistryError> {
        self.register(
            scope.family(),
            scope.wildcard_pattern(),
            budget,
            damping,
            break_glass,
        )
    }

    /// Register a tenant/service-scoped handler with default policies.
    pub fn register_namespace_default(
        &mut self,
        scope: &NamespaceControlScope,
    ) -> Result<ControlHandlerId, ControlRegistryError> {
        self.register_namespace(
            scope,
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        )
    }

    /// Register a break-glass recovery handler for the given family.
    pub fn register_break_glass(
        &mut self,
        family: SystemSubjectFamily,
    ) -> Result<ControlHandlerId, ControlRegistryError> {
        self.register(
            family,
            family.wildcard_pattern(),
            ControlBudget::break_glass(),
            AdvisoryDampingPolicy::non_recursive(),
            true,
        )
    }

    /// Remove a handler by ID.
    ///
    /// Returns `true` if the handler was present.
    pub fn unregister(&mut self, id: ControlHandlerId) -> bool {
        if self.handlers.remove(&id).is_some() {
            self.break_glass_ids.retain(|&bg_id| bg_id != id);
            true
        } else {
            false
        }
    }

    /// Look up a handler by ID.
    #[must_use]
    pub fn get(&self, id: ControlHandlerId) -> Option<&ControlHandler> {
        self.handlers.get(&id)
    }

    /// Return all handlers whose pattern matches the given control subject.
    #[must_use]
    pub fn matching_handlers(&self, subject: &Subject) -> Vec<&ControlHandler> {
        self.handlers
            .values()
            .filter(|h| h.pattern.matches(subject))
            .collect()
    }

    /// Return all break-glass recovery handlers.
    #[must_use]
    pub fn break_glass_handlers(&self) -> Vec<&ControlHandler> {
        self.break_glass_ids
            .iter()
            .filter_map(|id| self.handlers.get(id))
            .collect()
    }

    /// Return all handlers for a specific system subject family.
    #[must_use]
    pub fn handlers_for_family(&self, family: SystemSubjectFamily) -> Vec<&ControlHandler> {
        self.handlers
            .values()
            .filter(|h| h.family == family)
            .collect()
    }

    /// Total number of registered handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether the registry has no handlers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "control_inline_tests.rs"]
mod tests;
