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
        if filter.require_decision_provenance && !self.has_decision_provenance() {
            return false;
        }
        true
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
        self.next_id += 1;

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
mod tests {
    use super::*;

    fn node(id: &str) -> NodeId {
        NodeId::new(id)
    }

    fn pattern(value: &str) -> SubjectPattern {
        SubjectPattern::new(value)
    }

    fn assert_delta_round_trip<T>(baseline: T, updated: T)
    where
        T: JoinSemilattice + std::fmt::Debug,
        T::Delta: std::fmt::Debug,
    {
        let delta = updated.delta(&baseline);
        let mut applied = baseline.clone();
        assert!(applied.apply_delta(&delta));
        assert_eq!(applied, updated);
    }

    fn assert_converges<T>(left: T, middle: T, right: T)
    where
        T: JoinSemilattice + std::fmt::Debug,
    {
        let mut lhs = left.clone();
        lhs.merge(&middle);
        lhs.merge(&right);

        let mut rhs = right.clone();
        rhs.merge(&middle);
        rhs.merge(&left);

        assert_eq!(lhs, rhs);
    }

    // -- Delta-CRDT control metadata ----------------------------------------

    #[test]
    fn interest_summary_round_trips_delta() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let baseline = InterestSummary::default();
        let mut updated = InterestSummary::default();
        updated.subscribe(&replica_a, orders.clone());
        updated.subscribe(&replica_b, orders.clone());
        updated.unsubscribe(&replica_a, &orders);
        updated.subscribe(&replica_b, invoices.clone());

        assert_eq!(updated.interest_count(&orders), 1);
        assert_eq!(updated.interest_count(&invoices), 1);
        assert_delta_round_trip(baseline, updated);
    }

    #[test]
    fn interest_summary_converges_across_merge_orders() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");

        let mut left = InterestSummary::default();
        left.subscribe(&replica_a, orders.clone());

        let mut middle = InterestSummary::default();
        middle.subscribe(&replica_b, orders.clone());

        let mut right = InterestSummary::default();
        right.unsubscribe(&replica_a, &orders);

        assert_converges(left, middle, right);
    }

    #[test]
    fn cursor_checkpoint_prefers_newest_mark() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let baseline = CursorCheckpoint::default();

        let mut updated = CursorCheckpoint::default();
        updated.observe("consumer-a", CursorMark::new(10, 1_000, replica_a.clone()));
        updated.observe("consumer-a", CursorMark::new(12, 1_100, replica_b.clone()));

        let checkpoint = updated.checkpoint("consumer-a").expect("checkpoint");
        assert_eq!(checkpoint.offset(), 12);
        assert_eq!(checkpoint.checkpoint_unix_ms(), 1_100);
        assert_eq!(checkpoint.steward(), &replica_b);
        assert_delta_round_trip(baseline, updated);
    }

    #[test]
    fn membership_view_prefers_higher_version_and_converges() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");

        let mut left = MembershipView::default();
        left.observe(
            replica_a.clone(),
            MembershipRecord::new(1, MembershipState::Healthy, 1_000, 125),
        );

        let mut middle = MembershipView::default();
        middle.observe(
            replica_a.clone(),
            MembershipRecord::new(2, MembershipState::Degraded, 1_100, 600),
        );

        let mut right = MembershipView::default();
        right.observe(
            replica_b.clone(),
            MembershipRecord::new(1, MembershipState::Joining, 900, 50),
        );

        let mut merged = left.clone();
        merged.merge(&middle);
        let record = merged.record(&replica_a).expect("membership record");
        assert_eq!(record.version(), 2);
        assert_eq!(record.state(), MembershipState::Degraded);
        assert_eq!(record.load_per_mille(), 600);

        assert_delta_round_trip(MembershipView::default(), merged);
        assert_converges(left, middle, right);
    }

    #[test]
    fn lag_sketch_round_trips_delta_and_respects_error_bound() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let mut sketch = LagSketch::new(8);

        let samples = [3_u64, 9, 12, 18];
        sketch.observe(&replica_a, samples[0]);
        sketch.observe(&replica_a, samples[1]);
        sketch.observe(&replica_b, samples[2]);
        sketch.observe(&replica_b, samples[3]);

        assert_eq!(sketch.total_samples(), samples.len() as u64);
        let estimated_mean = sketch.estimated_mean().expect("mean estimate");
        let actual_mean = samples.iter().sum::<u64>() / samples.len() as u64;
        let error = estimated_mean.abs_diff(actual_mean);
        assert!(error <= sketch.max_mean_error_bound());

        assert_delta_round_trip(LagSketch::new(8), sketch);
    }

    #[test]
    fn lag_sketch_empty_delta_with_only_bucket_width_change_is_noop() {
        let baseline = LagSketch::default();
        let updated = LagSketch::new(8);
        let delta = updated.delta(&baseline);

        assert!(<LagSketch as JoinSemilattice>::delta_is_empty(&delta));
    }

    #[test]
    fn advisory_aggregate_round_trips_delta_and_reports_rate() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let mut aggregate = AdvisoryAggregate::new(1_000);

        aggregate.record_kind(&replica_a, "policy_decision", 1_200);
        aggregate.record_kind(&replica_b, "policy_decision", 1_400);
        aggregate.record_kind(&replica_b, "evidence_record", 1_800);

        assert_eq!(aggregate.count(1_000, "policy_decision"), 2);
        assert_eq!(aggregate.count(1_000, "evidence_record"), 1);
        assert_eq!(aggregate.rate_per_second(1_000, "policy_decision"), 2.0);

        assert_delta_round_trip(AdvisoryAggregate::new(1_000), aggregate);
    }

    #[test]
    fn advisory_aggregate_empty_delta_with_only_window_width_change_is_noop() {
        let baseline = AdvisoryAggregate::default();
        let updated = AdvisoryAggregate::new(1_000);
        let delta = updated.delta(&baseline);

        assert!(<AdvisoryAggregate as JoinSemilattice>::delta_is_empty(
            &delta
        ));
    }

    #[test]
    fn lag_sketch_adopts_incoming_width_when_local_state_is_empty() {
        let mut empty = LagSketch::new(16);
        let mut other = LagSketch::new(8);
        let replica = node("r1");
        other.record(&replica, 42);

        empty.merge(&other);

        assert_eq!(empty.bucket_width, 8);
        assert_eq!(empty.bucket_count(), 1);
    }

    #[test]
    fn lag_sketch_apply_delta_adopts_width_when_empty_and_breaks_loop_when_non_empty() {
        let replica = node("r1");

        // Empty local adopts incoming width via apply_delta.
        let mut empty = LagSketch::new(16);
        let mut source = LagSketch::new(8);
        source.record(&replica, 42);
        let delta = source.delta(&LagSketch::new(8));
        assert!(empty.apply_delta(&delta));
        assert_eq!(empty.bucket_width, 8);
        assert_eq!(empty.bucket_count(), 1);

        // Non-empty local with different width returns true (breaks loop)
        // but does NOT adopt the data.
        let mut established = LagSketch::new(16);
        established.record(&replica, 99);
        let before_count = established.bucket_count();
        let mismatched_delta = source.delta(&LagSketch::new(8));
        assert!(established.apply_delta(&mismatched_delta));
        assert_eq!(established.bucket_width, 16); // width unchanged
        assert_eq!(established.bucket_count(), before_count); // data unchanged
    }

    #[test]
    fn advisory_aggregate_adopts_incoming_window_width_when_empty() {
        let mut empty = AdvisoryAggregate::new(500);
        let mut other = AdvisoryAggregate::new(1_000);
        other.record_kind(&node("r1"), "evt", 1_200);

        empty.merge(&other);
        assert_eq!(empty.window_width_ms, 1_000);
        assert_eq!(empty.count(1_000, "evt"), 1);
    }

    #[test]
    fn advisory_aggregate_apply_delta_breaks_loop_when_non_empty() {
        let r = node("r1");
        let mut established = AdvisoryAggregate::new(500);
        established.record_kind(&r, "evt", 200);

        let mut source = AdvisoryAggregate::new(1_000);
        source.record_kind(&r, "evt", 1_200);
        let delta = source.delta(&AdvisoryAggregate::new(1_000));

        // Returns true to break anti-entropy loop, but doesn't adopt data.
        assert!(established.apply_delta(&delta));
        assert_eq!(established.window_width_ms, 500);
    }

    #[test]
    fn unsubscribe_on_absent_pattern_does_not_create_entry() {
        let r = node("r1");
        let mut summary = InterestSummary::default();

        // Unsubscribe from a pattern that was never subscribed to.
        summary.unsubscribe(&r, &pattern("absent.>"));

        // No entry should have been created.
        assert_eq!(summary.interest_count(&pattern("absent.>")), 0);
        assert!(summary.counts.is_empty());
    }

    #[test]
    fn unsubscribe_after_subscribe_decrements_normally() {
        let r = node("r1");
        let p = pattern("orders.>");
        let mut summary = InterestSummary::default();

        summary.subscribe(&r, p.clone());
        assert_eq!(summary.interest_count(&p), 1);

        summary.unsubscribe(&r, &p);
        assert_eq!(summary.interest_count(&p), 0);
        // Entry exists (from subscribe) but value is zero.
        assert_eq!(summary.counts.len(), 1);
    }

    #[test]
    fn propagation_applies_incremental_delta_when_peer_is_one_step_behind() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let envelope = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("incremental envelope");

        assert_eq!(envelope.mode(), PropagationMode::Incremental);
        assert_eq!(peer.apply(&envelope), PropagationApply::Applied);
        assert_eq!(peer.state().interest_count(&orders), 1);
        assert_eq!(peer.frontier().version(&replica_a), 1);
    }

    #[test]
    fn propagation_relay_uses_snapshot_for_downstream_peer() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");
        let orders = pattern("tenant.orders.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut relay = CrdtPropagationReplica::<InterestSummary>::new(replica_b);
        let mut downstream = CrdtPropagationReplica::<InterestSummary>::new(replica_c);

        let first_hop = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first-hop envelope");
        assert_eq!(relay.apply(&first_hop), PropagationApply::Applied);

        let second_hop = relay
            .prepare_for(&downstream.digest())
            .expect("relay snapshot");
        assert_eq!(second_hop.mode(), PropagationMode::AntiEntropy);
        assert_eq!(downstream.apply(&second_hop), PropagationApply::Applied);
        assert_eq!(downstream.state().interest_count(&orders), 1);
    }

    #[test]
    fn propagation_detects_partition_gap_and_repairs_via_snapshot() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let first = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first delta");
        let second = steward
            .mutate(|summary| summary.subscribe(&replica_a, invoices.clone()))
            .expect("second delta");

        assert_eq!(peer.apply(&second), PropagationApply::NeedsAntiEntropy);
        assert!(peer.needs_anti_entropy());

        let repair = steward
            .prepare_for(&peer.digest())
            .expect("repair snapshot");
        assert_eq!(repair.mode(), PropagationMode::AntiEntropy);
        assert_eq!(peer.apply(&repair), PropagationApply::Applied);
        assert!(!peer.needs_anti_entropy());
        assert_eq!(peer.state().interest_count(&orders), 1);
        assert_eq!(peer.state().interest_count(&invoices), 1);
        assert_eq!(peer.frontier().version(&replica_a), 2);
        assert_eq!(peer.apply(&first), PropagationApply::AlreadySatisfied);
    }

    #[test]
    fn propagation_converges_leaderlessly_after_partition_via_relay() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let mut left = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut right = CrdtPropagationReplica::<InterestSummary>::new(replica_b.clone());
        let mut relay = CrdtPropagationReplica::<InterestSummary>::new(replica_c);

        let left_delta = left
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("left delta");
        let _right_delta = right
            .mutate(|summary| summary.subscribe(&replica_b, invoices.clone()))
            .expect("right delta");

        assert_eq!(relay.apply(&left_delta), PropagationApply::Applied);
        let from_right = right
            .prepare_for(&relay.digest())
            .expect("relay repair from right");
        assert_eq!(from_right.mode(), PropagationMode::AntiEntropy);
        assert_eq!(relay.apply(&from_right), PropagationApply::Applied);

        let relay_to_left = relay.prepare_for(&left.digest()).expect("relay to left");
        let relay_to_right = relay.prepare_for(&right.digest()).expect("relay to right");

        assert_eq!(left.apply(&relay_to_left), PropagationApply::Applied);
        assert_eq!(right.apply(&relay_to_right), PropagationApply::Applied);

        let mut expected = InterestSummary::default();
        expected.subscribe(&replica_a, orders.clone());
        expected.subscribe(&replica_b, invoices.clone());

        assert_eq!(left.state(), &expected);
        assert_eq!(right.state(), &expected);
        assert_eq!(relay.state(), &expected);
    }

    #[test]
    fn propagation_prefers_incremental_delta_when_it_is_smaller_than_snapshot() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let first = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first delta");
        assert_eq!(peer.apply(&first), PropagationApply::Applied);

        let incremental = steward
            .mutate(|summary| summary.subscribe(&replica_a, invoices.clone()))
            .expect("incremental delta");
        let snapshot = steward.snapshot_envelope().expect("snapshot delta");

        assert_eq!(incremental.mode(), PropagationMode::Incremental);
        assert_eq!(snapshot.mode(), PropagationMode::AntiEntropy);

        let incremental_counts = match incremental.delta() {
            InterestSummaryDelta { counts } => counts.len(),
        };
        let snapshot_counts = match snapshot.delta() {
            InterestSummaryDelta { counts } => counts.len(),
        };

        assert_eq!(incremental_counts, 1);
        assert_eq!(snapshot_counts, 2);
        assert!(incremental_counts < snapshot_counts);
    }

    #[test]
    fn cursor_checkpoint_converges_and_ignores_stale_observations() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");

        let mut left = CursorCheckpoint::default();
        left.observe("consumer-a", CursorMark::new(12, 1_200, replica_a.clone()));
        left.observe("consumer-a", CursorMark::new(11, 1_300, replica_b.clone()));

        let checkpoint = left.checkpoint("consumer-a").expect("checkpoint");
        assert_eq!(checkpoint.offset(), 12);
        assert_eq!(checkpoint.checkpoint_unix_ms(), 1_200);
        assert_eq!(checkpoint.steward(), &replica_a);

        let mut middle = CursorCheckpoint::default();
        middle.observe("consumer-b", CursorMark::new(4, 900, replica_b));

        let mut right = CursorCheckpoint::default();
        right.observe("consumer-c", CursorMark::new(2, 800, replica_c));

        assert_converges(left, middle, right);
    }

    #[test]
    fn lag_sketch_converges_across_merge_orders() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");

        let mut left = LagSketch::new(8);
        left.observe(&replica_a, 3);
        left.observe(&replica_a, 7);

        let mut middle = LagSketch::new(8);
        middle.observe(&replica_b, 11);

        let mut right = LagSketch::new(8);
        right.observe(&replica_c, 19);

        assert_converges(left, middle, right);
    }

    #[test]
    fn propagation_duplicate_incremental_delta_is_idempotent() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let envelope = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("incremental envelope");

        assert_eq!(peer.apply(&envelope), PropagationApply::Applied);
        assert_eq!(peer.apply(&envelope), PropagationApply::AlreadySatisfied);
        assert_eq!(peer.state().interest_count(&orders), 1);
    }

    #[test]
    fn propagation_resumes_incremental_after_snapshot_repair() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");
        let payments = pattern("tenant.payments.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let first = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first delta");
        let second = steward
            .mutate(|summary| summary.subscribe(&replica_a, invoices.clone()))
            .expect("second delta");

        assert_eq!(peer.apply(&second), PropagationApply::NeedsAntiEntropy);
        let repair = steward
            .prepare_for(&peer.digest())
            .expect("repair snapshot");
        assert_eq!(repair.mode(), PropagationMode::AntiEntropy);
        assert_eq!(peer.apply(&repair), PropagationApply::Applied);
        assert_eq!(peer.apply(&first), PropagationApply::AlreadySatisfied);

        let third = steward
            .mutate(|summary| summary.subscribe(&replica_a, payments.clone()))
            .expect("third delta");
        assert_eq!(third.mode(), PropagationMode::Incremental);
        assert_eq!(peer.apply(&third), PropagationApply::Applied);
        assert_eq!(peer.state().interest_count(&orders), 1);
        assert_eq!(peer.state().interest_count(&invoices), 1);
        assert_eq!(peer.state().interest_count(&payments), 1);
        assert_eq!(peer.frontier().version(&replica_a), 3);
    }

    #[test]
    fn propagation_snapshot_applies_mismatched_lag_sketch_delta_to_break_retry_loop() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");

        let mut peer = CrdtPropagationReplica::<LagSketch>::new(replica_b.clone());
        let _ = peer.mutate(|sketch| sketch.observe(&replica_b, 42));

        let mut frontier = ReplicaVersionVector::default();
        frontier.advance(&replica_a);

        let mut counter_delta = ReplicaCounterDelta::default();
        counter_delta.positive.insert(replica_a.clone(), 1);

        let mut buckets = BTreeMap::new();
        buckets.insert(0, counter_delta);

        let envelope = PropagationEnvelope {
            steward: replica_a.clone(),
            frontier,
            mode: PropagationMode::AntiEntropy,
            delta: LagSketchDelta {
                bucket_width: 8,
                buckets,
            },
        };

        assert_eq!(peer.apply(&envelope), PropagationApply::Applied);
        assert_eq!(peer.frontier().version(&replica_a), 1);
        assert!(!peer.needs_anti_entropy());
    }

    #[test]
    fn advisory_aggregate_collapses_decision_identity_to_kind_counts() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");

        let audit_a = make_test_audit_entry();
        let mut audit_b = make_test_audit_entry();
        audit_b.decision_id = DecisionId::from_raw(77);
        audit_b.trace_id = TraceId::from_raw(200);
        audit_b.action_chosen = "hold".to_owned();
        audit_b.expected_loss = 0.7;
        audit_b.ts_unix_ms = 1_700_000_000_500;

        let outcome_a = DecisionOutcome {
            action_index: 0,
            action_name: audit_a.action_chosen.clone(),
            expected_loss: audit_a.expected_loss,
            expected_losses: audit_a.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit_a,
        };
        let outcome_b = DecisionOutcome {
            action_index: 1,
            action_name: audit_b.action_chosen.clone(),
            expected_loss: audit_b.expected_loss,
            expected_losses: audit_b.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit_b,
        };

        let advisory_a = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome_a,
            "drain evidence a",
        );
        let advisory_b = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome_b,
            "drain evidence b",
        );

        let mut aggregate = AdvisoryAggregate::new(1_000);
        aggregate.record_kind(
            &replica_a,
            advisory_a.advisory_type.kind(),
            advisory_a.ts_unix_ms,
        );
        aggregate.record_kind(
            &replica_b,
            advisory_b.advisory_type.kind(),
            advisory_b.ts_unix_ms,
        );

        let window_start = 1_700_000_000_000;
        let kind_window = aggregate.windows.get(&window_start).expect("window");
        assert_eq!(aggregate.count(window_start, "evidence_record"), 2);
        assert_eq!(kind_window.len(), 1);
        assert!(kind_window.contains_key("evidence_record"));

        let evidence_id_a = advisory_a.evidence_id();
        let evidence_id_b = advisory_b.evidence_id();
        assert!(
            matches!((&evidence_id_a, &evidence_id_b), (Some(left), Some(right)) if left != right)
        );
        if let Some(evidence_id_a) = evidence_id_a {
            assert!(!kind_window.contains_key(&evidence_id_a));
        }
        if let Some(evidence_id_b) = evidence_id_b {
            assert!(!kind_window.contains_key(&evidence_id_b));
        }
    }

    #[test]
    fn advisory_aggregate_prune_before_retains_cutoff_window_and_newer() {
        let replica_a = node("replica-a");
        let mut aggregate = AdvisoryAggregate::new(1_000);

        aggregate.record_kind(&replica_a, "evidence_record", 1_100);
        aggregate.record_kind(&replica_a, "evidence_record", 2_100);
        aggregate.record_kind(&replica_a, "evidence_record", 3_100);

        aggregate.prune_before(2_500);

        assert_eq!(aggregate.count(1_000, "evidence_record"), 0);
        assert_eq!(aggregate.count(2_000, "evidence_record"), 1);
        assert_eq!(aggregate.count(3_000, "evidence_record"), 1);
    }

    // -- SystemSubjectFamily -------------------------------------------------

    #[test]
    fn all_families_have_unique_names() {
        let mut names: Vec<&str> = SystemSubjectFamily::ALL.iter().map(|f| f.name()).collect();
        let original_len = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), original_len, "duplicate family names");
    }

    #[test]
    fn all_families_produce_valid_subject_patterns() {
        for family in &SystemSubjectFamily::ALL {
            let pattern = family.wildcard_pattern();
            assert!(
                pattern.as_str().starts_with("$SYS.FABRIC."),
                "pattern does not start with $SYS.FABRIC.: {}",
                pattern.as_str()
            );
            assert!(
                pattern.as_str().ends_with(".>"),
                "pattern does not end with .>: {}",
                pattern.as_str()
            );
        }
    }

    #[test]
    fn all_families_produce_valid_schemas() {
        for family in &SystemSubjectFamily::ALL {
            let schema = family.default_schema();
            assert_eq!(schema.family, SubjectFamily::Control);
            assert_eq!(schema.mobility, MobilityPermission::LocalOnly);
            assert!(schema.reply_space.is_none());
        }
    }

    #[test]
    fn delivery_class_monotonicity() {
        // Health/Route/Drain are cheapest (ephemeral), Auth/Replay most
        // expensive (forensic).
        assert_eq!(
            SystemSubjectFamily::Health.default_delivery_class(),
            DeliveryClass::EphemeralInteractive
        );
        assert_eq!(
            SystemSubjectFamily::Auth.default_delivery_class(),
            DeliveryClass::ForensicReplayable
        );
        assert_eq!(
            SystemSubjectFamily::Consumer.default_delivery_class(),
            DeliveryClass::ObligationBacked
        );
    }

    #[test]
    fn display_shows_prefix() {
        assert_eq!(
            format!("{}", SystemSubjectFamily::Health),
            "$SYS.FABRIC.HEALTH"
        );
        assert_eq!(
            format!("{}", SystemSubjectFamily::Replay),
            "$SYS.FABRIC.REPLAY"
        );
    }

    // -- ControlBudget -------------------------------------------------------

    #[test]
    fn default_budget_below_break_glass() {
        let normal = ControlBudget::default();
        let bg = ControlBudget::break_glass();
        assert!(normal.priority < bg.priority);
        assert!(normal.poll_quota < bg.poll_quota);
    }

    // -- AdvisoryDampingPolicy -----------------------------------------------

    #[test]
    fn default_damping_requires_operator_intent() {
        let policy = AdvisoryDampingPolicy::default();
        assert!(policy.requires_operator_intent);
    }

    #[test]
    fn non_recursive_damping_does_not_require_intent() {
        let policy = AdvisoryDampingPolicy::non_recursive();
        assert!(!policy.requires_operator_intent);
        assert_eq!(policy.stratification_tier, Some(0));
    }

    // -- ControlOutcome ------------------------------------------------------

    #[test]
    fn outcome_advisory_round_trip() {
        let outcome = ControlOutcome::Advisory {
            subject: Subject::new("$SYS.FABRIC.HEALTH.ok"),
            payload: b"{\"status\":\"ok\"}".to_vec(),
        };
        if let ControlOutcome::Advisory { subject, payload } = &outcome {
            assert_eq!(subject.as_str(), "$SYS.FABRIC.HEALTH.ok");
            assert!(!payload.is_empty());
        } else {
            panic!("expected Advisory variant");
        }
    }

    // -- ControlRegistry -----------------------------------------------------

    #[test]
    fn register_and_lookup() {
        let mut registry = ControlRegistry::new();
        let id = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register");
        assert_eq!(registry.len(), 1);
        let handler = registry.get(id).expect("lookup");
        assert_eq!(handler.family, SystemSubjectFamily::Health);
        assert!(!handler.break_glass);
    }

    #[test]
    fn register_rejects_non_sys_prefix() {
        let mut registry = ControlRegistry::new();
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("user.health.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ControlRegistryError::InvalidPrefix { pattern } => {
                assert_eq!(pattern, "user.health.>");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn register_rejects_family_mismatch() {
        let mut registry = ControlRegistry::new();
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("$SYS.FABRIC.AUTH.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        match result.expect_err("family mismatch must fail") {
            ControlRegistryError::FamilyMismatch { family, pattern } => {
                assert_eq!(family, SystemSubjectFamily::Health);
                assert_eq!(pattern, "$SYS.FABRIC.AUTH.>");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn register_rejects_similar_prefix_outside_family_boundary() {
        let mut registry = ControlRegistry::new();
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("$SYS.FABRIC.HEALTHY.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        match result.expect_err("family boundary mismatch must fail") {
            ControlRegistryError::FamilyMismatch { family, pattern } => {
                assert_eq!(family, SystemSubjectFamily::Health);
                assert_eq!(pattern, "$SYS.FABRIC.HEALTHY.>");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn break_glass_registration() {
        let mut registry = ControlRegistry::new();
        let bg_id = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("bg register");
        let normal_id = registry
            .register_default(SystemSubjectFamily::Route)
            .expect("normal register");
        assert_eq!(registry.len(), 2);

        let bg = registry.break_glass_handlers();
        assert_eq!(bg.len(), 1);
        assert_eq!(bg[0].id, bg_id);
        assert!(bg[0].break_glass);

        // Normal handler should not appear in break-glass list.
        assert!(bg.iter().all(|h| h.id != normal_id));
    }

    #[test]
    fn matching_handlers_filters_by_subject() {
        let mut registry = ControlRegistry::new();
        registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register health");
        registry
            .register_default(SystemSubjectFamily::Auth)
            .expect("register auth");

        let health_subj = Subject::new("$SYS.FABRIC.HEALTH.ok");
        let matches = registry.matching_handlers(&health_subj);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].family, SystemSubjectFamily::Health);

        let auth_subj = Subject::new("$SYS.FABRIC.AUTH.login.failed");
        let matches = registry.matching_handlers(&auth_subj);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].family, SystemSubjectFamily::Auth);

        // Unregistered family yields no matches.
        let drain_subj = Subject::new("$SYS.FABRIC.DRAIN.start");
        let matches = registry.matching_handlers(&drain_subj);
        assert!(matches.is_empty());
    }

    #[test]
    fn namespace_control_scope_builds_tenant_service_system_subjects() {
        let scope = NamespaceControlScope::new(SystemSubjectFamily::Health, "acme", "orders")
            .expect("namespace control scope");

        assert_eq!(scope.family(), SystemSubjectFamily::Health);
        assert_eq!(scope.tenant().as_str(), "acme");
        assert_eq!(scope.service().as_str(), "orders");
        assert_eq!(
            scope.wildcard_pattern().as_str(),
            "$SYS.FABRIC.HEALTH.TENANT.acme.SERVICE.orders.>"
        );
        assert_eq!(
            scope.subject("status").expect("status subject").as_str(),
            "$SYS.FABRIC.HEALTH.TENANT.acme.SERVICE.orders.status"
        );
    }

    #[test]
    fn namespace_control_scope_can_be_derived_from_namespace_kernel() {
        let namespace = NamespaceKernel::new("acme", "orders").expect("namespace kernel");
        let scope = NamespaceControlScope::from_namespace(SystemSubjectFamily::Route, &namespace);

        assert_eq!(scope.family(), SystemSubjectFamily::Route);
        assert_eq!(scope.tenant(), namespace.tenant());
        assert_eq!(scope.service(), namespace.service());
        assert_eq!(
            scope.wildcard_pattern().as_str(),
            "$SYS.FABRIC.ROUTE.TENANT.acme.SERVICE.orders.>"
        );
        assert_eq!(
            scope
                .subject("rebalance")
                .expect("route control subject")
                .as_str(),
            "$SYS.FABRIC.ROUTE.TENANT.acme.SERVICE.orders.rebalance"
        );
    }

    #[test]
    fn control_registry_keeps_namespace_control_handlers_isolated() {
        let mut registry = ControlRegistry::new();
        let acme_orders_ns = NamespaceKernel::new("acme", "orders").expect("acme orders kernel");
        let bravo_orders_ns = NamespaceKernel::new("bravo", "orders").expect("bravo orders kernel");
        let acme_orders =
            NamespaceControlScope::from_namespace(SystemSubjectFamily::Health, &acme_orders_ns);
        let bravo_orders =
            NamespaceControlScope::from_namespace(SystemSubjectFamily::Health, &bravo_orders_ns);

        let acme_id = registry
            .register_namespace_default(&acme_orders)
            .expect("register acme orders");
        let bravo_id = registry
            .register_namespace_default(&bravo_orders)
            .expect("register bravo orders");

        let acme_status = acme_orders.subject("status").expect("acme status");
        let matches = registry.matching_handlers(&acme_status);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, acme_id);
        assert_eq!(
            matches[0].pattern.as_str(),
            acme_orders.wildcard_pattern().as_str()
        );

        let bravo_status = bravo_orders.subject("status").expect("bravo status");
        let matches = registry.matching_handlers(&bravo_status);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, bravo_id);
        assert_eq!(
            matches[0].pattern.as_str(),
            bravo_orders.wildcard_pattern().as_str()
        );
    }

    #[test]
    fn handlers_for_family() {
        let mut registry = ControlRegistry::new();
        registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register 1");
        registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("register 2");
        registry
            .register_default(SystemSubjectFamily::Route)
            .expect("register 3");

        let health = registry.handlers_for_family(SystemSubjectFamily::Health);
        assert_eq!(health.len(), 2);
        let route = registry.handlers_for_family(SystemSubjectFamily::Route);
        assert_eq!(route.len(), 1);
    }

    #[test]
    fn unregister_removes_handler() {
        let mut registry = ControlRegistry::new();
        let id = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register");
        assert_eq!(registry.len(), 1);
        assert!(registry.unregister(id));
        assert_eq!(registry.len(), 0);
        assert!(registry.get(id).is_none());
    }

    #[test]
    fn unregister_clears_break_glass_index() {
        let mut registry = ControlRegistry::new();
        let bg_id = registry
            .register_break_glass(SystemSubjectFamily::Drain)
            .expect("bg");
        assert_eq!(registry.break_glass_handlers().len(), 1);
        registry.unregister(bg_id);
        assert!(registry.break_glass_handlers().is_empty());
    }

    #[test]
    fn unregister_one_break_glass_preserves_remaining_handlers() {
        let mut registry = ControlRegistry::new();
        let health = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("health break-glass");
        let drain = registry
            .register_break_glass(SystemSubjectFamily::Drain)
            .expect("drain break-glass");

        assert!(registry.unregister(health));

        let remaining = registry.break_glass_handlers();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, drain);
        assert_eq!(remaining[0].family, SystemSubjectFamily::Drain);
    }

    #[test]
    fn unregister_returns_false_for_missing() {
        let mut registry = ControlRegistry::new();
        assert!(!registry.unregister(ControlHandlerId::new(999)));
    }

    #[test]
    fn empty_registry() {
        let registry = ControlRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.break_glass_handlers().is_empty());
    }

    // -- ControlHandlerId ----------------------------------------------------

    #[test]
    fn handler_id_display() {
        let id = ControlHandlerId::new(42);
        assert_eq!(format!("{id}"), "ctrl-42");
    }

    #[test]
    fn handler_id_round_trip() {
        let id = ControlHandlerId::new(7);
        assert_eq!(id.raw(), 7);
    }

    // -- Evidence policy per family ------------------------------------------

    #[test]
    fn auth_replay_have_full_evidence() {
        for family in &[SystemSubjectFamily::Auth, SystemSubjectFamily::Replay] {
            let schema = family.default_schema();
            assert!(
                schema.evidence_policy.record_counterfactual_branches,
                "{family} should record counterfactual branches"
            );
            assert_eq!(schema.evidence_policy.sampling_ratio, 1.0);
        }
    }

    #[test]
    fn health_has_default_evidence() {
        let schema = SystemSubjectFamily::Health.default_schema();
        assert!(!schema.evidence_policy.record_counterfactual_branches);
        assert_eq!(schema.evidence_policy.sampling_ratio, 1.0);
    }

    // -- Minimum ack ---------------------------------------------------------

    #[test]
    fn minimum_ack_matches_delivery_class() {
        // EphemeralInteractive → Accepted
        assert_eq!(SystemSubjectFamily::Health.minimum_ack(), AckKind::Accepted);
        // ObligationBacked → Committed
        assert_eq!(
            SystemSubjectFamily::Consumer.minimum_ack(),
            AckKind::Committed
        );
        // ForensicReplayable → Recoverable
        assert_eq!(
            SystemSubjectFamily::Auth.minimum_ack(),
            AckKind::Recoverable
        );
    }

    // -- ControlAdvisoryType -------------------------------------------------

    #[test]
    fn advisory_type_capability_graph_change() {
        let advisory = ControlAdvisoryType::CapabilityGraphChange {
            affected_subjects: vec![SubjectPattern::new("$SYS.FABRIC.AUTH.>")],
            description: "revoked admin capability".to_owned(),
        };
        match &advisory {
            ControlAdvisoryType::CapabilityGraphChange {
                affected_subjects,
                description,
            } => {
                assert_eq!(affected_subjects.len(), 1);
                assert_eq!(description, "revoked admin capability");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn advisory_type_evidence_record_has_explicit_identity() {
        let advisory = ControlAdvisoryType::EvidenceRecord {
            evidence_id: "control:drain:42:1700000000000".to_owned(),
            component: "drain_policy".to_owned(),
            action: "failover".to_owned(),
            summary: "latency SLO breach justified failover".to_owned(),
        };
        match &advisory {
            ControlAdvisoryType::EvidenceRecord {
                evidence_id,
                component,
                action,
                summary,
            } => {
                assert_eq!(evidence_id, "control:drain:42:1700000000000");
                assert_eq!(component, "drain_policy");
                assert_eq!(action, "failover");
                assert!(summary.contains("SLO breach"));
                assert_eq!(advisory.kind(), "evidence_record");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn obligation_transfer_action_display() {
        assert_eq!(
            format!("{}", ObligationTransferAction::Transferred),
            "transferred"
        );
        assert_eq!(format!("{}", ObligationTransferAction::Aborted), "aborted");
        assert_eq!(
            format!("{}", ObligationTransferAction::ReplayScheduled),
            "replay_scheduled"
        );
    }

    // -- ControlAdvisory with FrankenSuite evidence --------------------------

    fn make_test_audit_entry() -> DecisionAuditEntry {
        let mut losses = BTreeMap::new();
        losses.insert("failover".to_owned(), 0.3);
        losses.insert("hold".to_owned(), 0.7);
        DecisionAuditEntry {
            decision_id: DecisionId::from_raw(42),
            trace_id: TraceId::from_raw(100),
            contract_name: "drain_policy".to_owned(),
            action_chosen: "failover".to_owned(),
            expected_loss: 0.3,
            calibration_score: 0.85,
            fallback_active: false,
            posterior_snapshot: vec![0.6, 0.4],
            expected_loss_by_action: losses,
            ts_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn advisory_from_decision_carries_provenance() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "drain_policy".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "downstream latency exceeded SLO".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.failover"),
            &outcome,
        );

        assert!(advisory.has_decision_provenance());
        assert_eq!(advisory.family, SystemSubjectFamily::Drain);
        assert_eq!(advisory.trace_id, TraceId::from_raw(100));
        assert_eq!(advisory.decision_id, DecisionId::from_raw(42));
    }

    #[test]
    fn advisory_to_evidence_ledger() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "drain_policy".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "SLO breach".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.failover"),
            &outcome,
        );

        let evidence = advisory.to_evidence_ledger();
        assert!(evidence.is_some());
        let ledger = evidence.unwrap();
        assert!(ledger.is_valid());
        assert_eq!(ledger.component, "drain_policy");
        assert_eq!(ledger.action, "failover");
        assert!((ledger.calibration_score - 0.85).abs() < f64::EPSILON);
        assert!(!ledger.fallback_active);
    }

    #[test]
    fn evidence_record_advisory_uses_stable_evidence_id() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome,
            "drain failover evidence bundle",
        );

        let evidence_id = advisory.evidence_id().expect("evidence id");
        assert!(evidence_id.starts_with("control:drain:"));
        assert!(advisory.has_decision_provenance());
    }

    #[test]
    fn notification_advisory_has_no_provenance() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::BreakGlassActivation {
                reason: "fabric unreachable".to_owned(),
            },
            SystemSubjectFamily::Health,
            Subject::new("$SYS.FABRIC.HEALTH.break_glass"),
            TraceId::from_raw(200),
            1_700_000_000_000,
        );

        assert!(!advisory.has_decision_provenance());
        assert!(advisory.to_evidence_ledger().is_none());
        assert_eq!(advisory.trace_id, TraceId::from_raw(200));
    }

    #[test]
    fn advisory_json_payload_contains_type_and_provenance() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::ObligationTransfer {
                action: ObligationTransferAction::Aborted,
                subject: Subject::new("$SYS.FABRIC.CONSUMER.lease.expired"),
            },
            SystemSubjectFamily::Consumer,
            Subject::new("$SYS.FABRIC.CONSUMER.advisory"),
            TraceId::from_raw(300),
            1_700_000_000_000,
        );

        let payload = advisory.to_json_payload();
        assert!(!payload.is_empty());
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("obligation_transfer")
        );
        assert_eq!(
            parsed.get("action").and_then(serde_json::Value::as_str),
            Some("aborted")
        );
        assert_eq!(
            parsed.get("family").and_then(serde_json::Value::as_str),
            Some("CONSUMER")
        );
        assert_eq!(
            parsed
                .get("obligation_subject")
                .and_then(serde_json::Value::as_str),
            Some("$SYS.FABRIC.CONSUMER.lease.expired")
        );
        assert_eq!(
            parsed
                .get("has_decision_provenance")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            parsed.get("ts_unix_ms").and_then(serde_json::Value::as_u64),
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn advisory_json_payload_policy_decision() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "load_shed".to_owned(),
                action_chosen: "reject_new".to_owned(),
                justification: "queue depth exceeded threshold".to_owned(),
            },
            SystemSubjectFamily::Route,
            Subject::new("$SYS.FABRIC.ROUTE.shed"),
            &outcome,
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("policy_decision")
        );
        assert_eq!(
            parsed
                .get("policy_name")
                .and_then(serde_json::Value::as_str),
            Some("load_shed")
        );
        assert_eq!(
            parsed
                .get("action_chosen")
                .and_then(serde_json::Value::as_str),
            Some("reject_new")
        );
        assert_eq!(
            parsed
                .get("has_decision_provenance")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn advisory_json_payload_evidence_record() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome,
            "bounded drain failover evidence",
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("evidence_record")
        );
        assert!(
            parsed
                .get("evidence_id")
                .and_then(serde_json::Value::as_str)
                .expect("string evidence_id")
                .starts_with("control:drain:")
        );
        assert_eq!(
            parsed.get("component").and_then(serde_json::Value::as_str),
            Some("drain_policy")
        );
        assert_eq!(
            parsed.get("action").and_then(serde_json::Value::as_str),
            Some("failover")
        );
        assert_eq!(
            parsed.get("summary").and_then(serde_json::Value::as_str),
            Some("bounded drain failover evidence")
        );
    }

    #[test]
    fn break_glass_advisory_payload() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::BreakGlassActivation {
                reason: "network partition detected".to_owned(),
            },
            SystemSubjectFamily::Health,
            Subject::new("$SYS.FABRIC.HEALTH.break_glass"),
            TraceId::from_raw(400),
            1_700_000_000_000,
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("break_glass_activation")
        );
        assert_eq!(
            parsed.get("reason").and_then(serde_json::Value::as_str),
            Some("network partition detected")
        );
    }

    #[test]
    fn capability_graph_change_payload_preserves_affected_subjects() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::CapabilityGraphChange {
                affected_subjects: vec![
                    SubjectPattern::new("tenant.acme.service.orders.>"),
                    SubjectPattern::new("tenant.acme.service.inventory.lookup"),
                ],
                description: "added bounded import edge".to_owned(),
            },
            SystemSubjectFamily::Route,
            Subject::new("$SYS.FABRIC.ROUTE.capability_change"),
            TraceId::from_raw(401),
            1_700_000_000_100,
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        let affected_subjects = parsed
            .get("affected_subjects")
            .and_then(serde_json::Value::as_array)
            .expect("affected_subjects array");

        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("capability_graph_change")
        );
        assert_eq!(
            parsed
                .get("description")
                .and_then(serde_json::Value::as_str),
            Some("added bounded import edge")
        );
        assert_eq!(affected_subjects.len(), 2);
        assert_eq!(
            affected_subjects[0].as_str(),
            Some("tenant.acme.service.orders.>")
        );
        assert_eq!(
            affected_subjects[1].as_str(),
            Some("tenant.acme.service.inventory.lookup")
        );
    }

    #[test]
    fn advisory_filter_matches_family_kind_and_provenance() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let evidence_advisory = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome,
            "drain evidence",
        );
        let notification = ControlAdvisory::notification(
            ControlAdvisoryType::BreakGlassActivation {
                reason: "fabric unreachable".to_owned(),
            },
            SystemSubjectFamily::Health,
            Subject::new("$SYS.FABRIC.HEALTH.break_glass"),
            TraceId::from_raw(9),
            1_700_000_000_123,
        );

        let drain_evidence_only = ControlAdvisoryFilter {
            family: Some(SystemSubjectFamily::Drain),
            advisory_kind: Some("evidence_record"),
            require_decision_provenance: true,
        };
        assert!(evidence_advisory.matches_filter(&drain_evidence_only));
        assert!(!notification.matches_filter(&drain_evidence_only));

        let health_break_glass = ControlAdvisoryFilter {
            family: Some(SystemSubjectFamily::Health),
            advisory_kind: Some("break_glass_activation"),
            require_decision_provenance: false,
        };
        assert!(notification.matches_filter(&health_break_glass));
        assert!(!evidence_advisory.matches_filter(&health_break_glass));
    }

    // ========================================================================
    // Comprehensive control plane tests (bead 8w83i.8.3)
    // ========================================================================

    // -- Capability domain enforcement ---------------------------------------

    #[test]
    fn control_subjects_require_sys_fabric_prefix() {
        // All system subject families produce subjects under $SYS.FABRIC.
        for family in &SystemSubjectFamily::ALL {
            let prefix = family.prefix();
            assert!(
                prefix.starts_with("$SYS.FABRIC."),
                "family {family} prefix `{prefix}` must start with $SYS.FABRIC."
            );
        }
    }

    #[test]
    fn registry_rejects_non_fabric_sys_prefix() {
        let mut registry = ControlRegistry::new();
        // $SYS.OTHER.* is NOT $SYS.FABRIC.* — should be rejected.
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("$SYS.OTHER.health.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn admin_control_capability_scope_maps_correctly() {
        // Verify that control handler families are associated with the
        // AdminControl capability scope (the capability module enforces
        // this at runtime; here we verify the type-level contract).
        use super::super::capability::FabricCapabilityScope;
        assert_eq!(
            format!("{}", FabricCapabilityScope::AdminControl),
            "admin_control"
        );
    }

    // -- Reserved budget under load ------------------------------------------

    #[test]
    fn control_budget_priority_above_user_traffic() {
        let budget = ControlBudget::default();
        // User traffic typically runs at priority 128.  Control handlers
        // must be above that.
        assert!(
            budget.priority > 128,
            "control budget priority {} must exceed user traffic (128)",
            budget.priority
        );
    }

    #[test]
    fn break_glass_budget_is_maximum_priority() {
        let bg = ControlBudget::break_glass();
        assert_eq!(bg.priority, 255, "break-glass must be max priority");
    }

    #[test]
    fn control_budget_deadline_is_bounded() {
        let budget = ControlBudget::default();
        // Control handlers should finish quickly — sub-second.
        assert!(budget.deadline < Duration::from_secs(1));
        let bg = ControlBudget::break_glass();
        assert!(bg.deadline < Duration::from_secs(1));
    }

    // -- Break-glass recovery path -------------------------------------------

    #[test]
    fn break_glass_available_when_main_fabric_degraded() {
        // Simulate: register several normal handlers + one break-glass.
        // Then unregister all normal handlers (simulating degradation).
        // The break-glass handler must still be reachable.
        let mut registry = ControlRegistry::new();
        let normal1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("normal 1");
        let normal2 = registry
            .register_default(SystemSubjectFamily::Route)
            .expect("normal 2");
        let bg = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("break-glass");

        // Simulate degradation: remove all normal handlers.
        registry.unregister(normal1);
        registry.unregister(normal2);

        // Break-glass handler survives.
        assert_eq!(registry.len(), 1);
        let bg_handlers = registry.break_glass_handlers();
        assert_eq!(bg_handlers.len(), 1);
        assert_eq!(bg_handlers[0].id, bg);
        assert!(bg_handlers[0].break_glass);
    }

    #[test]
    fn break_glass_handler_has_non_recursive_damping() {
        let mut registry = ControlRegistry::new();
        let bg_id = registry
            .register_break_glass(SystemSubjectFamily::Drain)
            .expect("bg");
        let handler = registry.get(bg_id).unwrap();
        // Break-glass handlers use non-recursive damping — they must not
        // require operator intent (recovery must be autonomous).
        assert!(!handler.damping.requires_operator_intent);
        assert_eq!(handler.damping.stratification_tier, Some(0));
    }

    // -- Advisory damping enforcement ----------------------------------------

    #[test]
    fn damping_default_prevents_feedback_loops() {
        let policy = AdvisoryDampingPolicy::default();
        // Default damping requires operator intent — advisories cannot
        // autonomously trigger further control-plane actions.
        assert!(policy.requires_operator_intent);
        // Minimum interval prevents rapid-fire re-evaluation.
        assert!(policy.min_interval >= Duration::from_secs(1));
        // Window cap prevents event flood from overwhelming evaluator.
        assert!(policy.max_events_per_window <= 100);
    }

    #[test]
    fn damping_stratification_prevents_recursive_amplification() {
        // A tier-1 advisory should not be able to trigger actions that
        // produce tier-0 or tier-1 advisories.
        let tier1 = AdvisoryDampingPolicy {
            stratification_tier: Some(1),
            ..AdvisoryDampingPolicy::default()
        };
        let tier0 = AdvisoryDampingPolicy::non_recursive();

        // Tier 1 > tier 0 — a higher-tier advisory can only trigger
        // actions at a strictly higher tier.
        assert!(tier1.stratification_tier.unwrap() > tier0.stratification_tier.unwrap());
    }

    // -- Registration edge cases ---------------------------------------------

    #[test]
    fn multiple_handlers_same_family_all_match() {
        let mut registry = ControlRegistry::new();
        let id1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("h1");
        let id2 = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("h2");

        let subj = Subject::new("$SYS.FABRIC.HEALTH.probe");
        let matches = registry.matching_handlers(&subj);
        assert_eq!(matches.len(), 2);

        let ids: Vec<_> = matches.iter().map(|h| h.id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn family_scoped_pattern_routes_only_within_declared_prefix() {
        let mut registry = ControlRegistry::new();
        let narrow = registry
            .register(
                SystemSubjectFamily::Health,
                SubjectPattern::new("$SYS.FABRIC.HEALTH.break_glass.>"),
                ControlBudget::default(),
                AdvisoryDampingPolicy::default(),
                false,
            )
            .expect("narrow register");
        let wildcard = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("wildcard register");

        let narrow_matches =
            registry.matching_handlers(&Subject::new("$SYS.FABRIC.HEALTH.break_glass.activate"));
        let narrow_ids: Vec<_> = narrow_matches.iter().map(|handler| handler.id).collect();
        assert_eq!(narrow_ids, vec![narrow, wildcard]);

        let general_matches = registry.matching_handlers(&Subject::new("$SYS.FABRIC.HEALTH.probe"));
        let general_ids: Vec<_> = general_matches.iter().map(|handler| handler.id).collect();
        assert_eq!(general_ids, vec![wildcard]);
    }

    #[test]
    fn handler_ids_are_monotonically_increasing() {
        let mut registry = ControlRegistry::new();
        let id1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("1");
        let id2 = registry
            .register_default(SystemSubjectFamily::Route)
            .expect("2");
        let id3 = registry
            .register_default(SystemSubjectFamily::Auth)
            .expect("3");
        assert!(id1.raw() < id2.raw());
        assert!(id2.raw() < id3.raw());
    }

    #[test]
    fn unregister_then_reregister_gets_new_id() {
        let mut registry = ControlRegistry::new();
        let id1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("first");
        registry.unregister(id1);
        let id2 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("second");
        // New registration gets a fresh ID, not the old one.
        assert_ne!(id1, id2);
        assert!(id2.raw() > id1.raw());
    }

    // -- All advisory types produce valid JSON ------------------------------

    #[test]
    fn all_advisory_types_produce_valid_json() {
        let types = vec![
            ControlAdvisoryType::CapabilityGraphChange {
                affected_subjects: vec![SubjectPattern::new("$SYS.FABRIC.AUTH.>")],
                description: "test".to_owned(),
            },
            ControlAdvisoryType::ObligationTransfer {
                action: ObligationTransferAction::Transferred,
                subject: Subject::new("$SYS.FABRIC.CONSUMER.tx"),
            },
            ControlAdvisoryType::PolicyDecision {
                policy_name: "test_policy".to_owned(),
                action_chosen: "accept".to_owned(),
                justification: "test reason".to_owned(),
            },
            ControlAdvisoryType::EvidenceRecord {
                evidence_id: "control:health:1:1700000000000".to_owned(),
                component: "health_policy".to_owned(),
                action: "mark_degraded".to_owned(),
                summary: "health evidence bundle".to_owned(),
            },
            ControlAdvisoryType::BreakGlassActivation {
                reason: "test reason".to_owned(),
            },
        ];

        for advisory_type in types {
            let advisory = ControlAdvisory::notification(
                advisory_type,
                SystemSubjectFamily::Health,
                Subject::new("$SYS.FABRIC.HEALTH.test"),
                TraceId::from_raw(1),
                1_700_000_000_000,
            );
            let payload = advisory.to_json_payload();
            let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&payload);
            assert!(parsed.is_ok(), "advisory payload must be valid JSON");
            let map = parsed.unwrap();
            assert!(map.get("type").is_some(), "payload must contain 'type' key");
            assert!(
                map.get("family").is_some(),
                "payload must contain 'family' key"
            );
        }
    }

    // -- Evidence ledger validation ------------------------------------------

    #[test]
    fn evidence_ledger_posterior_sums_to_one() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "test".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "test".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.test"),
            &outcome,
        );

        let ledger = advisory.to_evidence_ledger().unwrap();
        let sum: f64 = ledger.posterior.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "posterior must sum to ~1.0, got {sum}"
        );
    }

    #[test]
    fn evidence_ledger_has_expected_losses_for_all_actions() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "drain".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "test".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.test"),
            &outcome,
        );

        let ledger = advisory.to_evidence_ledger().unwrap();
        // Should have expected losses for both "failover" and "hold".
        assert_eq!(ledger.expected_loss_by_action.len(), 2);
        assert!(ledger.expected_loss_by_action.contains_key("failover"));
        assert!(ledger.expected_loss_by_action.contains_key("hold"));
    }

    #[test]
    fn evidence_ledger_fallback_flag_propagates() {
        let mut audit = make_test_audit_entry();
        audit.fallback_active = true;
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: true,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "test".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "test".to_owned(),
            },
            SystemSubjectFamily::Route,
            Subject::new("$SYS.FABRIC.ROUTE.test"),
            &outcome,
        );

        let ledger = advisory.to_evidence_ledger().unwrap();
        assert!(
            ledger.fallback_active,
            "fallback flag must propagate to evidence"
        );
    }

    // -- Subject matching precision ------------------------------------------

    #[test]
    fn wildcard_pattern_matches_deep_subjects() {
        let pattern = SystemSubjectFamily::Auth.wildcard_pattern();
        // Tail wildcard ">" should match any depth.
        assert!(pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login")));
        assert!(pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login.failed")));
        assert!(pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login.failed.ip.127.0.0.1")));
    }

    #[test]
    fn wildcard_pattern_does_not_cross_families() {
        let health_pattern = SystemSubjectFamily::Health.wildcard_pattern();
        // Should NOT match Auth subjects.
        assert!(!health_pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login")));
        // Should NOT match the bare family prefix without a trailing token.
        // (The ">" wildcard requires at least one token after the prefix.)
    }

    // -- ControlHandlerId edge cases -----------------------------------------

    #[test]
    fn handler_id_zero_is_valid() {
        let id = ControlHandlerId::new(0);
        assert_eq!(id.raw(), 0);
        assert_eq!(format!("{id}"), "ctrl-0");
    }

    #[test]
    fn handler_id_max_is_valid() {
        let id = ControlHandlerId::new(u64::MAX);
        assert_eq!(id.raw(), u64::MAX);
    }
}
