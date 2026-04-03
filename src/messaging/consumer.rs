//! Consumer cursor leases over recoverable FABRIC capsules.
//!
//! This module establishes a deterministic cursor-lease state machine with
//! delegated cursor partitions and lease-bound read tickets:
//!
//! - cursor authority is fenced by cell epoch plus lease generation,
//! - delivery attempts are certified with obligation-backed metadata,
//! - failover and contested transfer are deterministic lease transitions, and
//! - stale acknowledgements collapse to an explicit no-op instead of
//!   reanimating stale authority.

use super::fabric::{CellEpoch, CellId, SubjectCell, SubjectPattern};
use super::jetstream::{AckPolicy, DeliverPolicy};
use crate::obligation::ledger::{LedgerStats, ObligationLedger, ObligationToken};
use crate::record::{ObligationAbortReason, ObligationKind, SourceLocation};
use crate::remote::NodeId;
use crate::types::{ObligationId, RegionId, TaskId, Time};
use crate::util::DetHasher;
use franken_decision::{
    DecisionAuditEntry, DecisionContract, EvalContext, FallbackPolicy, LossMatrix, Posterior,
    evaluate,
};
use franken_kernel::{DecisionId, TraceId};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::panic::Location;
use std::time::Duration;
use thiserror::Error;

/// Inclusive sequence window requested or served by a consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceWindow {
    start: u64,
    end: u64,
}

impl SequenceWindow {
    /// Create a new inclusive window.
    pub fn new(start: u64, end: u64) -> Result<Self, ConsumerCursorError> {
        if start > end {
            return Err(ConsumerCursorError::InvalidSequenceWindow { start, end });
        }
        Ok(Self { start, end })
    }

    /// Return the first covered sequence number.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Return the last covered sequence number.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Return true when the window fully contains `other`.
    #[must_use]
    pub const fn contains_window(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }

    /// Return true when the window contains `sequence`.
    #[must_use]
    pub const fn contains_sequence(self, sequence: u64) -> bool {
        self.start <= sequence && sequence <= self.end
    }
}

impl fmt::Display for SequenceWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", self.start, self.end)
    }
}

/// Pull consumers can request explicit windows or named demand classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsumerDemandClass {
    /// Resume from the current tail.
    Tail,
    /// Catch up a lagging consumer from durable state.
    CatchUp,
    /// Replay a historical slice.
    Replay,
}

impl ConsumerDemandClass {
    #[must_use]
    const fn priority_rank(self) -> u8 {
        match self {
            Self::Tail => 0,
            Self::CatchUp => 1,
            Self::Replay => 2,
        }
    }
}

/// Request selector captured in an attempt certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CursorRequest {
    /// Single-sequence delivery.
    Sequence(u64),
    /// Explicit inclusive window.
    Window(SequenceWindow),
    /// Demand-class request with no concrete window yet attached.
    DemandClass(ConsumerDemandClass),
}

impl CursorRequest {
    #[must_use]
    fn requested_window(self) -> Option<SequenceWindow> {
        match self {
            Self::Sequence(sequence) => Some(SequenceWindow {
                start: sequence,
                end: sequence,
            }),
            Self::Window(window) => Some(window),
            Self::DemandClass(_) => None,
        }
    }
}

/// Push and pull flows bind cursor authority differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CursorDeliveryMode {
    /// Consumer explicitly requests a sequence/window/demand class.
    Pull(CursorRequest),
    /// Delivery stays pinned to the currently leased peer for the window.
    Push {
        /// Inclusive window pinned to the current lease holder.
        window: SequenceWindow,
    },
}

impl CursorDeliveryMode {
    #[must_use]
    fn requested_window(self) -> Option<SequenceWindow> {
        match self {
            Self::Pull(request) => request.requested_window(),
            Self::Push { window } => Some(window),
        }
    }
}

/// Authority location for the current cursor lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CursorLeaseScope {
    /// Cursor authority still lives in the cell control capsule.
    ControlCapsule,
    /// Authority has been delegated into a narrower cursor partition.
    DelegatedCursorPartition {
        /// Deterministic delegated partition identifier.
        partition: u16,
    },
}

/// Peer currently allowed to serve under the active cursor lease.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CursorLeaseHolder {
    /// One of the cell stewards.
    Steward(NodeId),
    /// A delegated relay peer serving through a read ticket.
    Relay(NodeId),
}

impl CursorLeaseHolder {
    /// Return the underlying peer regardless of holder type.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        match self {
            Self::Steward(node) | Self::Relay(node) => node,
        }
    }
}

/// Active cursor authority lease derived from the control capsule or a
/// delegated partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorAuthorityLease {
    /// Cell whose authority this lease fences.
    pub cell_id: CellId,
    /// Epoch paired with the cell id.
    pub epoch: CellEpoch,
    /// Where the authoritative cursor state currently lives.
    pub scope: CursorLeaseScope,
    /// Peer currently serving under the lease.
    pub holder: CursorLeaseHolder,
    /// Monotonic generation fencing stale attempts and acks.
    pub lease_generation: u64,
    /// Control-capsule policy revision captured when the lease was minted.
    pub policy_revision: u64,
}

impl CursorAuthorityLease {
    /// Derive the initial cursor authority from a subject cell.
    pub fn from_subject_cell(cell: &SubjectCell) -> Result<Self, ConsumerCursorError> {
        let Some(active) = cell.control_capsule.active_sequencer.clone() else {
            return Err(ConsumerCursorError::NoActiveSequencer {
                cell_id: cell.cell_id,
            });
        };

        Ok(Self {
            cell_id: cell.cell_id,
            epoch: cell.epoch,
            scope: CursorLeaseScope::ControlCapsule,
            holder: CursorLeaseHolder::Steward(active),
            lease_generation: cell.control_capsule.sequencer_lease_generation,
            policy_revision: cell.control_capsule.policy_revision,
        })
    }
}

/// Stable reference to the lease a read-delegation ticket was minted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorLeaseRef {
    /// Scope of the delegated cursor authority.
    pub scope: CursorLeaseScope,
    /// Holder that owned the lease when the ticket was issued.
    pub holder: CursorLeaseHolder,
    /// Generation fencing stale delegated reads.
    pub lease_generation: u64,
}

impl CursorLeaseRef {
    /// Capture the current lease as a ticket-stable reference.
    #[must_use]
    pub fn from_authority_lease(lease: &CursorAuthorityLease) -> Self {
        Self {
            scope: lease.scope,
            holder: lease.holder.clone(),
            lease_generation: lease.lease_generation,
        }
    }
}

/// Partition-scoped lease extracted from a delegated cursor authority lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPartitionLease {
    /// Deterministic delegated partition identifier.
    pub partition: u16,
    /// Peer currently leading the partition.
    pub leader: CursorLeaseHolder,
    /// Generation fencing stale partition state.
    pub lease_generation: u64,
}

impl CursorPartitionLease {
    /// Capture a partition lease only when the authority lease is delegated.
    #[must_use]
    pub fn from_authority_lease(lease: &CursorAuthorityLease) -> Option<Self> {
        match lease.scope {
            CursorLeaseScope::ControlCapsule => None,
            CursorLeaseScope::DelegatedCursorPartition { partition } => Some(Self {
                partition,
                leader: lease.holder.clone(),
                lease_generation: lease.lease_generation,
            }),
        }
    }
}

/// Deterministic strategy used to assign consumers into delegated partitions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CursorPartitionSelector {
    /// Partition is responsible for one named consumer group.
    ConsumerGroup(String),
    /// Partition owns a contiguous subject-key sub-range.
    SubjectSubRange {
        /// Inclusive lower bound for the sub-range.
        start: String,
        /// Inclusive upper bound for the sub-range.
        end: String,
    },
    /// Partition owns one hash bucket from a bounded bucket set.
    HashBucket {
        /// Zero-based bucket index.
        bucket: u16,
        /// Total bucket count.
        buckets: u16,
    },
}

impl CursorPartitionSelector {
    fn validate(&self) -> Result<(), ConsumerCursorError> {
        match self {
            Self::ConsumerGroup(group) if group.trim().is_empty() => {
                Err(ConsumerCursorError::EmptyCursorPartitionSelector {
                    field: "consumer_group",
                })
            }
            Self::SubjectSubRange { start, end } if start.trim().is_empty() => {
                Err(ConsumerCursorError::EmptyCursorPartitionSelector { field: "start" })
            }
            Self::SubjectSubRange { start: _, end } if end.trim().is_empty() => {
                Err(ConsumerCursorError::EmptyCursorPartitionSelector { field: "end" })
            }
            Self::SubjectSubRange { start, end } if start > end => {
                Err(ConsumerCursorError::InvalidCursorPartitionSubRange {
                    start: start.clone(),
                    end: end.clone(),
                })
            }
            Self::HashBucket { buckets, .. } if *buckets == 0 => {
                Err(ConsumerCursorError::InvalidCursorPartitionBucket {
                    bucket: 0,
                    buckets: *buckets,
                })
            }
            Self::HashBucket { bucket, buckets } if *bucket >= *buckets => {
                Err(ConsumerCursorError::InvalidCursorPartitionBucket {
                    bucket: *bucket,
                    buckets: *buckets,
                })
            }
            Self::ConsumerGroup(_) | Self::SubjectSubRange { .. } | Self::HashBucket { .. } => {
                Ok(())
            }
        }
    }
}

/// Deterministic delegated cursor-partition assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPartitionAssignment {
    /// Deterministic delegated partition identifier.
    pub partition: u16,
    /// Partition leader currently responsible for this slice of cursor state.
    pub leader: CursorLeaseHolder,
    /// Partitioning strategy used to assign consumers.
    pub selector: CursorPartitionSelector,
    /// Stable identifiers for consumers served by this partition.
    pub consumers: BTreeSet<String>,
}

impl CursorPartitionAssignment {
    fn validate(&self) -> Result<(), ConsumerCursorError> {
        self.selector.validate()?;
        if self.consumers.is_empty() {
            return Err(ConsumerCursorError::EmptyCursorPartitionConsumers {
                partition: self.partition,
            });
        }
        Ok(())
    }
}

/// Coarse checkpoint report emitted by one delegated partition leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPartitionCheckpoint {
    /// Partition issuing the report.
    pub partition: u16,
    /// Lease generation this report was computed against.
    pub lease_generation: u64,
    /// Highest sequence durably acknowledged by the partition.
    pub ack_floor: u64,
    /// Highest sequence delivered by the partition.
    pub delivered_through: u64,
    /// Number of outstanding pending deliveries in the partition.
    pub pending_count: u64,
    /// Deterministic count of consumers assigned to the partition.
    pub consumer_count: u32,
}

/// Coarse checkpoint summary retained by the control capsule for one partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPartitionSummary {
    /// Partition the summary belongs to.
    pub partition: u16,
    /// Partitioning strategy used to assign consumers.
    pub selector: CursorPartitionSelector,
    /// Partition leader that reported the summary.
    pub leader: CursorLeaseHolder,
    /// Lease generation the summary is bound to.
    pub lease_generation: u64,
    /// Highest sequence durably acknowledged by the partition.
    pub ack_floor: u64,
    /// Highest sequence delivered by the partition.
    pub delivered_through: u64,
    /// Number of outstanding pending deliveries in the partition.
    pub pending_count: u64,
    /// Deterministic count of consumers assigned to the partition.
    pub consumer_count: u32,
}

/// Cacheability metadata carried by a delegated read ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CacheabilityRule {
    /// The delegated payload must not be cached.
    NoCache,
    /// The delegated payload may be cached privately for a bounded interval.
    Private {
        /// Maximum private-cache age in logical ticks.
        max_age_ticks: u64,
    },
    /// The delegated payload may be cached by shared intermediaries.
    Shared {
        /// Maximum shared-cache age in logical ticks.
        max_age_ticks: u64,
    },
}

/// Opaque handle used to revoke a ticket after issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadDelegationRevocationHandle(u64);

impl ReadDelegationRevocationHandle {
    /// Return the stable handle value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Logical expiry for a delegated read ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadDelegationExpiry {
    /// Logical tick when the ticket was issued.
    pub issued_at_tick: u64,
    /// Last logical tick where the ticket remains valid.
    pub not_after_tick: u64,
}

impl ReadDelegationExpiry {
    /// Create a bounded expiry window in logical cursor ticks.
    pub fn new(issued_at_tick: u64, ttl_ticks: u64) -> Result<Self, ConsumerCursorError> {
        if ttl_ticks == 0 {
            return Err(ConsumerCursorError::InvalidReadDelegationTtl { ttl_ticks });
        }
        Ok(Self {
            issued_at_tick,
            not_after_tick: issued_at_tick.saturating_add(ttl_ticks),
        })
    }

    #[must_use]
    fn is_expired(self, current_tick: u64) -> bool {
        current_tick > self.not_after_tick
    }
}

/// Obligation-backed proof that a relay may serve a specific window for the
/// current cursor lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDelegationTicket {
    /// Cell whose data may be served.
    pub cell_id: CellId,
    /// Epoch bound into the delegation.
    pub epoch: CellEpoch,
    /// Lease reference that this ticket delegates from.
    pub cursor_lease_ref: CursorLeaseRef,
    /// Relay peer allowed to serve.
    pub relay: NodeId,
    /// Inclusive segment window the relay may serve.
    pub segment_window: SequenceWindow,
    /// Logical expiry bound for the ticket.
    pub expiry: ReadDelegationExpiry,
    /// Cacheability metadata the relay must preserve.
    pub cacheability_rules: CacheabilityRule,
    /// Revocation handle recorded by the issuing cursor authority.
    pub revocation_handle: ReadDelegationRevocationHandle,
}

impl ReadDelegationTicket {
    /// Bind a relay to the current lease for one concrete window.
    pub fn new(
        lease: &CursorAuthorityLease,
        relay: NodeId,
        segment_window: SequenceWindow,
        issued_at_tick: u64,
        ttl_ticks: u64,
        cacheability_rules: CacheabilityRule,
        revocation_handle: ReadDelegationRevocationHandle,
    ) -> Result<Self, ConsumerCursorError> {
        Ok(Self {
            cell_id: lease.cell_id,
            epoch: lease.epoch,
            cursor_lease_ref: CursorLeaseRef::from_authority_lease(lease),
            relay,
            segment_window,
            expiry: ReadDelegationExpiry::new(issued_at_tick, ttl_ticks)?,
            cacheability_rules,
            revocation_handle,
        })
    }

    fn validate(
        &self,
        lease: &CursorAuthorityLease,
        relay: &NodeId,
        window: SequenceWindow,
        current_tick: u64,
        revoked_tickets: &BTreeMap<ReadDelegationRevocationHandle, u64>,
    ) -> Result<(), ConsumerCursorError> {
        if self.cell_id != lease.cell_id || self.epoch != lease.epoch {
            return Err(ConsumerCursorError::StaleReadDelegationEpoch {
                relay: relay.clone(),
                ticket_cell: self.cell_id,
                ticket_epoch: self.epoch,
                current_cell: lease.cell_id,
                current_epoch: lease.epoch,
            });
        }
        if revoked_tickets.contains_key(&self.revocation_handle) {
            return Err(ConsumerCursorError::RevokedReadDelegationTicket {
                relay: relay.clone(),
                revocation_handle: self.revocation_handle,
            });
        }
        if self.expiry.is_expired(current_tick) {
            return Err(ConsumerCursorError::ExpiredReadDelegationTicket {
                relay: relay.clone(),
                expired_at_tick: self.expiry.not_after_tick,
                current_tick,
            });
        }
        if self.cursor_lease_ref != CursorLeaseRef::from_authority_lease(lease)
            || &self.relay != relay
            || !self.segment_window.contains_window(window)
        {
            return Err(ConsumerCursorError::InvalidReadDelegationTicket {
                relay: relay.clone(),
                requested_window: window,
            });
        }
        Ok(())
    }
}

/// Attempt certificate emitted for each delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptCertificate {
    /// Cell being served.
    pub cell_id: CellId,
    /// Epoch used when the attempt was minted.
    pub epoch: CellEpoch,
    /// Captured cursor authority lease.
    pub cursor_authority_lease: CursorAuthorityLease,
    /// Requested sequence/window or push pin.
    pub delivery_mode: CursorDeliveryMode,
    /// Monotonic retry counter for this logical delivery.
    pub delivery_attempt: u32,
    /// Obligation backing the attempt.
    pub obligation_id: ObligationId,
    /// Previous obligation superseded by a redelivery, when applicable.
    pub supersedes_obligation_id: Option<ObligationId>,
}

impl AttemptCertificate {
    /// Expose the partition-scoped lease when the attempt was minted from a
    /// delegated partition leader.
    #[must_use]
    pub fn cursor_partition_lease(&self) -> Option<CursorPartitionLease> {
        CursorPartitionLease::from_authority_lease(&self.cursor_authority_lease)
    }
}

/// Coverage map for symbols retained in recoverable capsules.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoverableCapsule {
    coverage: BTreeMap<NodeId, Vec<SequenceWindow>>,
}

impl RecoverableCapsule {
    /// Record that `node` retains symbols for `window`.
    #[must_use]
    pub fn with_window(mut self, node: NodeId, window: SequenceWindow) -> Self {
        self.insert_window(node, window);
        self
    }

    /// Record another retained window for `node`.
    pub fn insert_window(&mut self, node: NodeId, window: SequenceWindow) {
        self.coverage.entry(node).or_default().push(window);
    }

    #[must_use]
    fn node_covers(&self, node: &NodeId, window: SequenceWindow) -> bool {
        self.coverage.get(node).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|candidate| candidate.contains_window(window))
        })
    }

    #[must_use]
    fn reconstruction_contributors(&self, window: SequenceWindow) -> Option<Vec<NodeId>> {
        let mut current = window.start();
        let mut contributors = Vec::new();

        while current <= window.end() {
            let mut best: Option<(u64, NodeId)> = None;

            for (node, ranges) in &self.coverage {
                for range in ranges {
                    if !range.contains_sequence(current) {
                        continue;
                    }

                    let candidate = (range.end(), node.clone());
                    if best.as_ref().is_none_or(|(best_end, best_node)| {
                        candidate.0 > *best_end
                            || (candidate.0 == *best_end
                                && candidate.1.as_str() < best_node.as_str())
                    }) {
                        best = Some(candidate);
                    }
                }
            }

            let (best_end, best_node) = best?;
            if contributors.last() != Some(&best_node) {
                contributors.push(best_node);
            }
            if best_end >= window.end() {
                break;
            }
            current = best_end.saturating_add(1);
        }

        Some(contributors)
    }
}

/// Concrete delivery path chosen for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryPlan {
    /// Current steward serves directly under the active lease.
    CurrentSteward(NodeId),
    /// Delegated relay serves under a read ticket bound to the lease.
    LeasedRelay {
        /// Relay peer serving the request.
        relay: NodeId,
        /// Ticket proving the relay is bound to the current lease/window.
        ticket: ReadDelegationTicket,
    },
    /// No single peer has the whole window; reconstruct from distributed
    /// symbols deterministically.
    Reconstructed {
        /// Deterministic contributor order used for reconstruction.
        contributors: Vec<NodeId>,
    },
}

/// Result of applying an acknowledgement attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckResolution {
    /// The acknowledgement commits against the current lease holder.
    Committed {
        /// Obligation closed by the acknowledgement.
        obligation_id: ObligationId,
        /// Holder the acknowledgement commits against.
        against: CursorLeaseHolder,
    },
    /// The attempt refers to a stale lease generation and collapses to a no-op.
    StaleNoOp {
        /// Obligation associated with the stale acknowledgement.
        obligation_id: ObligationId,
        /// Current generation that fenced out the stale attempt.
        current_generation: u64,
        /// Holder that currently owns the lease.
        current_holder: CursorLeaseHolder,
    },
}

/// Transfer claim presented during a contested cursor move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorTransferProposal {
    /// Peer that wants authority next.
    pub proposed_holder: CursorLeaseHolder,
    /// Scope the proposer wants authority over.
    pub proposed_scope: CursorLeaseScope,
    /// Generation the proposer believes is current.
    pub expected_generation: u64,
    /// Obligation backing the transfer attempt.
    pub transfer_obligation: ObligationId,
}

impl CursorTransferProposal {
    /// Build a transfer proposal that returns authority to the control capsule.
    #[must_use]
    pub fn control_capsule(
        proposed_holder: CursorLeaseHolder,
        expected_generation: u64,
        transfer_obligation: ObligationId,
    ) -> Self {
        Self {
            proposed_holder,
            proposed_scope: CursorLeaseScope::ControlCapsule,
            expected_generation,
            transfer_obligation,
        }
    }

    /// Build a transfer proposal that delegates authority to one partition.
    #[must_use]
    pub fn delegated_partition(
        proposed_holder: CursorLeaseHolder,
        partition: u16,
        expected_generation: u64,
        transfer_obligation: ObligationId,
    ) -> Self {
        Self {
            proposed_holder,
            proposed_scope: CursorLeaseScope::DelegatedCursorPartition { partition },
            expected_generation,
            transfer_obligation,
        }
    }

    fn validate(&self) -> Result<(), ConsumerCursorError> {
        match (&self.proposed_holder, self.proposed_scope) {
            (CursorLeaseHolder::Relay(relay), CursorLeaseScope::ControlCapsule) => {
                Err(ConsumerCursorError::RelayTransferRequiresPartition {
                    relay: relay.clone(),
                })
            }
            _ => Ok(()),
        }
    }
}

/// Deterministic outcome of contested transfer resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContestedTransferResolution {
    /// One proposal won and minted a new lease generation.
    Accepted {
        /// Lease minted for the winning proposal.
        new_lease: CursorAuthorityLease,
        /// Obligation that won the contested transfer.
        winning_obligation: ObligationId,
    },
    /// All proposals were stale relative to the current lease.
    StaleNoOp {
        /// Lease that remains authoritative after rejecting stale proposals.
        current_lease: CursorAuthorityLease,
    },
}

/// Consumer cursor authority state backed by the control capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricConsumerCursor {
    steward_pool: Vec<NodeId>,
    current_lease: CursorAuthorityLease,
    partition_assignments: BTreeMap<u16, CursorPartitionAssignment>,
    partition_summaries: BTreeMap<u16, CursorPartitionSummary>,
    ticket_clock: u64,
    next_revocation_handle: u64,
    /// Revoked ticket handles mapped to their `not_after_tick` for pruning.
    revoked_tickets: BTreeMap<ReadDelegationRevocationHandle, u64>,
}

impl FabricConsumerCursor {
    /// Build cursor authority from the current subject cell.
    pub fn new(cell: &SubjectCell) -> Result<Self, ConsumerCursorError> {
        Ok(Self {
            steward_pool: cell.control_capsule.steward_pool.clone(),
            current_lease: CursorAuthorityLease::from_subject_cell(cell)?,
            partition_assignments: BTreeMap::new(),
            partition_summaries: BTreeMap::new(),
            ticket_clock: 0,
            next_revocation_handle: 1,
            revoked_tickets: BTreeMap::new(),
        })
    }

    /// Return the current lease.
    #[must_use]
    pub fn current_lease(&self) -> &CursorAuthorityLease {
        &self.current_lease
    }

    /// Return one delegated partition assignment when present.
    #[must_use]
    pub fn partition_assignment(&self, partition: u16) -> Option<&CursorPartitionAssignment> {
        self.partition_assignments.get(&partition)
    }

    /// Return the last coarse checkpoint summary for one partition.
    #[must_use]
    pub fn partition_summary(&self, partition: u16) -> Option<&CursorPartitionSummary> {
        self.partition_summaries.get(&partition)
    }

    /// Return the current logical ticket clock.
    #[must_use]
    pub const fn ticket_clock(&self) -> u64 {
        self.ticket_clock
    }

    /// Advance logical ticket time for deterministic expiry tests.
    pub fn advance_ticket_clock(&mut self, ticks: u64) -> u64 {
        self.ticket_clock = self.ticket_clock.saturating_add(ticks);
        self.ticket_clock
    }

    /// Register or replace the deterministic assignment for one delegated
    /// cursor partition.
    pub fn assign_partition(
        &mut self,
        assignment: CursorPartitionAssignment,
    ) -> Result<&CursorPartitionAssignment, ConsumerCursorError> {
        assignment.validate()?;
        let partition = assignment.partition;
        self.partition_assignments.insert(partition, assignment);
        // Any assignment change invalidates the retained coarse summary until
        // the active leader reports against the new partition state.
        self.partition_summaries.remove(&partition);
        Ok(self
            .partition_assignments
            .get(&partition)
            .expect("assignment inserted"))
    }

    /// Mint an obligation-backed attempt certificate.
    pub fn issue_attempt(
        &self,
        delivery_mode: CursorDeliveryMode,
        delivery_attempt: u32,
        obligation_id: ObligationId,
    ) -> Result<AttemptCertificate, ConsumerCursorError> {
        if delivery_attempt == 0 {
            return Err(ConsumerCursorError::InvalidDeliveryAttempt);
        }

        Ok(AttemptCertificate {
            cell_id: self.current_lease.cell_id,
            epoch: self.current_lease.epoch,
            cursor_authority_lease: self.current_lease.clone(),
            delivery_mode,
            delivery_attempt,
            obligation_id,
            supersedes_obligation_id: None,
        })
    }

    /// Bind a relay ticket to the current lease for one window.
    pub fn grant_read_ticket(
        &mut self,
        relay: NodeId,
        segment_window: SequenceWindow,
        ttl_ticks: u64,
        cacheability_rules: CacheabilityRule,
    ) -> Result<ReadDelegationTicket, ConsumerCursorError> {
        if self.steward_pool.iter().any(|node| node == &relay) {
            return Err(ConsumerCursorError::RelayMustNotBeSteward { relay });
        }
        let revocation_handle = ReadDelegationRevocationHandle(self.next_revocation_handle);
        self.next_revocation_handle = self.next_revocation_handle.saturating_add(1);
        ReadDelegationTicket::new(
            &self.current_lease,
            relay,
            segment_window,
            self.ticket_clock,
            ttl_ticks,
            cacheability_rules,
            revocation_handle,
        )
    }

    /// Revoke a previously issued ticket by handle.
    ///
    /// The `not_after_tick` from the ticket's expiry is stored alongside the
    /// handle so that stale revocations can be pruned once the ticket clock
    /// advances past them (see [`prune_expired_revocations`]).
    pub fn revoke_read_ticket(
        &mut self,
        handle: ReadDelegationRevocationHandle,
        not_after_tick: u64,
    ) {
        self.revoked_tickets.insert(handle, not_after_tick);
    }

    /// Remove revocation entries whose tickets have already expired.
    ///
    /// After the ticket clock advances past a ticket's `not_after_tick`, the
    /// ticket is already rejected by the expiry check in [`validate_ticket`],
    /// so the revocation entry is redundant and can be safely pruned.
    pub fn prune_expired_revocations(&mut self) {
        let clock = self.ticket_clock;
        self.revoked_tickets
            .retain(|_, &mut expiry| clock <= expiry);
    }

    /// Choose the concrete serving path for the current lease.
    pub fn plan_delivery(
        &self,
        delivery_mode: CursorDeliveryMode,
        capsule: &RecoverableCapsule,
        ticket: Option<&ReadDelegationTicket>,
    ) -> Result<DeliveryPlan, ConsumerCursorError> {
        let Some(window) = delivery_mode.requested_window() else {
            return Ok(DeliveryPlan::CurrentSteward(
                self.current_lease.holder.node().clone(),
            ));
        };

        match &self.current_lease.holder {
            CursorLeaseHolder::Steward(node) if capsule.node_covers(node, window) => {
                Ok(DeliveryPlan::CurrentSteward(node.clone()))
            }
            CursorLeaseHolder::Relay(node) => {
                let Some(ticket) = ticket else {
                    return Err(ConsumerCursorError::MissingReadDelegationTicket {
                        relay: node.clone(),
                    });
                };
                ticket.validate(
                    &self.current_lease,
                    node,
                    window,
                    self.ticket_clock,
                    &self.revoked_tickets,
                )?;
                if capsule.node_covers(node, window) {
                    Ok(DeliveryPlan::LeasedRelay {
                        relay: node.clone(),
                        ticket: ticket.clone(),
                    })
                } else {
                    capsule
                        .reconstruction_contributors(window)
                        .map(|contributors| DeliveryPlan::Reconstructed { contributors })
                        .ok_or(ConsumerCursorError::UnrecoverableWindow { window })
                }
            }
            CursorLeaseHolder::Steward(_) => capsule
                .reconstruction_contributors(window)
                .map(|contributors| DeliveryPlan::Reconstructed { contributors })
                .ok_or(ConsumerCursorError::UnrecoverableWindow { window }),
        }
    }

    /// Fail over authority to another steward that already holds symbols and
    /// the control capsule state.
    pub fn failover(
        &mut self,
        next_steward: NodeId,
    ) -> Result<&CursorAuthorityLease, ConsumerCursorError> {
        if !self.steward_pool.iter().any(|node| node == &next_steward) {
            return Err(ConsumerCursorError::UnknownSteward {
                cell_id: self.current_lease.cell_id,
                steward: next_steward,
            });
        }

        self.current_lease.holder = CursorLeaseHolder::Steward(next_steward);
        self.current_lease.lease_generation = self.current_lease.lease_generation.saturating_add(1);
        self.current_lease.scope = CursorLeaseScope::ControlCapsule;
        Ok(&self.current_lease)
    }

    /// Resolve a contested cursor transfer deterministically using control
    /// capsule order first, then stable relay ordering, then obligation id.
    pub fn resolve_contested_transfer(
        &mut self,
        proposals: &[CursorTransferProposal],
    ) -> Result<ContestedTransferResolution, ConsumerCursorError> {
        let valid = proposals
            .iter()
            .map(|proposal| proposal.validate().map(|()| proposal))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|proposal| proposal.expected_generation == self.current_lease.lease_generation)
            .filter_map(|proposal| {
                self.transfer_rank(&proposal.proposed_holder)
                    .map(|rank| (rank, scope_rank(proposal.proposed_scope), proposal))
            })
            .min_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then_with(|| left.1.cmp(&right.1))
                    .then_with(|| left.2.transfer_obligation.cmp(&right.2.transfer_obligation))
            });

        let Some((_, _, winner)) = valid else {
            return Ok(ContestedTransferResolution::StaleNoOp {
                current_lease: self.current_lease.clone(),
            });
        };

        if let CursorLeaseScope::DelegatedCursorPartition { partition } = self.current_lease.scope {
            self.partition_summaries.remove(&partition);
        }
        if let CursorLeaseScope::DelegatedCursorPartition { partition } = winner.proposed_scope {
            let Some(assignment) = self.partition_assignments.get_mut(&partition) else {
                return Err(ConsumerCursorError::UnknownCursorPartition { partition });
            };
            assignment.leader = winner.proposed_holder.clone();
            self.partition_summaries.remove(&partition);
        }

        self.current_lease.holder = winner.proposed_holder.clone();
        self.current_lease.lease_generation = self.current_lease.lease_generation.saturating_add(1);
        self.current_lease.scope = winner.proposed_scope;

        Ok(ContestedTransferResolution::Accepted {
            new_lease: self.current_lease.clone(),
            winning_obligation: winner.transfer_obligation,
        })
    }

    /// Report a coarse checkpoint from the currently delegated partition leader.
    pub fn report_partition_checkpoint(
        &mut self,
        checkpoint: CursorPartitionCheckpoint,
    ) -> Result<&CursorPartitionSummary, ConsumerCursorError> {
        let CursorLeaseScope::DelegatedCursorPartition { partition } = self.current_lease.scope
        else {
            return Err(
                ConsumerCursorError::PartitionCheckpointRequiresDelegatedLease {
                    partition: checkpoint.partition,
                    current_scope: self.current_lease.scope,
                },
            );
        };

        if checkpoint.partition != partition {
            return Err(
                ConsumerCursorError::PartitionCheckpointRequiresDelegatedLease {
                    partition: checkpoint.partition,
                    current_scope: self.current_lease.scope,
                },
            );
        }

        if checkpoint.lease_generation != self.current_lease.lease_generation {
            return Err(ConsumerCursorError::StaleCursorPartitionCheckpoint {
                partition: checkpoint.partition,
                report_generation: checkpoint.lease_generation,
                current_generation: self.current_lease.lease_generation,
            });
        }

        let Some(assignment) = self.partition_assignments.get(&partition) else {
            return Err(ConsumerCursorError::UnknownCursorPartition { partition });
        };
        if usize::try_from(checkpoint.consumer_count).ok() != Some(assignment.consumers.len()) {
            return Err(
                ConsumerCursorError::PartitionCheckpointConsumerCountMismatch {
                    partition,
                    reported_consumer_count: checkpoint.consumer_count,
                    assigned_consumer_count: assignment.consumers.len(),
                },
            );
        }

        let summary = CursorPartitionSummary {
            partition,
            selector: assignment.selector.clone(),
            leader: self.current_lease.holder.clone(),
            lease_generation: checkpoint.lease_generation,
            ack_floor: checkpoint.ack_floor,
            delivered_through: checkpoint.delivered_through,
            pending_count: checkpoint.pending_count,
            consumer_count: checkpoint.consumer_count,
        };
        self.partition_summaries.insert(partition, summary);
        Ok(self
            .partition_summaries
            .get(&partition)
            .expect("partition summary inserted"))
    }

    /// Rebalance one delegated cursor partition to a new leader with lease
    /// fencing.
    pub fn rebalance_partition(
        &mut self,
        partition: u16,
        next_leader: CursorLeaseHolder,
        expected_generation: u64,
        transfer_obligation: ObligationId,
    ) -> Result<ContestedTransferResolution, ConsumerCursorError> {
        if !self.partition_assignments.contains_key(&partition) {
            return Err(ConsumerCursorError::UnknownCursorPartition { partition });
        }

        self.resolve_contested_transfer(&[CursorTransferProposal::delegated_partition(
            next_leader,
            partition,
            expected_generation,
            transfer_obligation,
        )])
    }

    /// Apply an acknowledgement attempt against the current lease.
    pub fn acknowledge(
        &self,
        attempt: &AttemptCertificate,
    ) -> Result<AckResolution, ConsumerCursorError> {
        if attempt.cell_id != self.current_lease.cell_id
            || attempt.epoch != self.current_lease.epoch
        {
            return Err(ConsumerCursorError::AttemptScopeMismatch {
                certificate_cell: attempt.cell_id,
                certificate_epoch: attempt.epoch,
                current_cell: self.current_lease.cell_id,
                current_epoch: self.current_lease.epoch,
            });
        }

        if attempt.cursor_authority_lease.lease_generation == self.current_lease.lease_generation {
            Ok(AckResolution::Committed {
                obligation_id: attempt.obligation_id,
                against: self.current_lease.holder.clone(),
            })
        } else {
            Ok(AckResolution::StaleNoOp {
                obligation_id: attempt.obligation_id,
                current_generation: self.current_lease.lease_generation,
                current_holder: self.current_lease.holder.clone(),
            })
        }
    }

    fn transfer_rank(&self, holder: &CursorLeaseHolder) -> Option<(u8, usize, String)> {
        match holder {
            CursorLeaseHolder::Steward(node) => self
                .steward_pool
                .iter()
                .position(|candidate| candidate == node)
                .map(|index| (0, index, node.as_str().to_owned())),
            CursorLeaseHolder::Relay(node) => Some((1, usize::MAX, node.as_str().to_owned())),
        }
    }
}

fn scope_rank(scope: CursorLeaseScope) -> (u8, u16) {
    match scope {
        CursorLeaseScope::ControlCapsule => (0, 0),
        CursorLeaseScope::DelegatedCursorPartition { partition } => (1, partition),
    }
}

/// Replay pacing applied to pull-based consumer delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConsumerReplayPolicy {
    /// Replay as quickly as policy gates allow.
    #[default]
    Instant,
    /// Preserve source pacing semantics when replaying historical windows.
    Original,
}

/// High-level dispatch mode for a FABRIC consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConsumerDispatchMode {
    /// Windows are pushed according to the active delivery policy.
    #[default]
    Push,
    /// Windows are served only in response to queued pull requests.
    Pull,
}

/// Static consumer configuration for the FABRIC delivery engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricConsumerConfig {
    /// Stable durable consumer name, when the consumer survives process restarts.
    pub durable_name: Option<String>,
    /// Optional subject filter narrowing which stream slice the consumer may see.
    pub filter_subject: Option<SubjectPattern>,
    /// Acknowledgement semantics for delivered messages.
    pub ack_policy: AckPolicy,
    /// Maximum number of delivery attempts before policy escalation.
    pub max_deliver: u16,
    /// Maximum number of messages that may remain pending acknowledgement.
    pub max_ack_pending: usize,
    /// Maximum queued pull requests waiting for service.
    pub max_waiting: usize,
    /// Ack deadline carried into obligation-backed pending state.
    pub ack_wait: Duration,
    /// Replay pacing for historical or recovery delivery.
    pub replay_policy: ConsumerReplayPolicy,
    /// Starting delivery anchor for replay-oriented pull requests.
    pub deliver_policy: DeliverPolicy,
    /// Whether explicit flow-control pause/resume is enabled.
    pub flow_control: bool,
    /// Stable kernel mode or audit-backed adaptive consumer scheduling.
    pub adaptive_kernel: AdaptiveConsumerKernel,
    /// Bounded overflow rule applied when the pull queue is full.
    pub overflow_policy: ConsumerOverflowPolicy,
    /// Heartbeat cadence while actively delivering.
    pub heartbeat: Option<Duration>,
    /// Heartbeat cadence while idle.
    pub idle_heartbeat: Option<Duration>,
}

impl Default for FabricConsumerConfig {
    fn default() -> Self {
        Self {
            durable_name: None,
            filter_subject: None,
            ack_policy: AckPolicy::Explicit,
            max_deliver: 1,
            max_ack_pending: 256,
            max_waiting: 64,
            ack_wait: Duration::from_secs(30),
            replay_policy: ConsumerReplayPolicy::Instant,
            deliver_policy: DeliverPolicy::All,
            flow_control: false,
            adaptive_kernel: AdaptiveConsumerKernel::Stable,
            overflow_policy: ConsumerOverflowPolicy::RejectNew,
            heartbeat: None,
            idle_heartbeat: None,
        }
    }
}

impl FabricConsumerConfig {
    /// Validate the consumer configuration before construction.
    pub fn validate(&self) -> Result<(), FabricConsumerError> {
        if self.max_deliver == 0 {
            return Err(FabricConsumerError::InvalidMaxDeliver);
        }
        if self.max_ack_pending == 0 {
            return Err(FabricConsumerError::InvalidMaxAckPending);
        }
        if self.max_waiting == 0 {
            return Err(FabricConsumerError::InvalidMaxWaiting);
        }
        if self.ack_wait.is_zero() {
            return Err(FabricConsumerError::InvalidAckWait);
        }
        if self.heartbeat.is_some_and(|duration| duration.is_zero()) {
            return Err(FabricConsumerError::InvalidHeartbeat { field: "heartbeat" });
        }
        if self
            .idle_heartbeat
            .is_some_and(|duration| duration.is_zero())
        {
            return Err(FabricConsumerError::InvalidHeartbeat {
                field: "idle_heartbeat",
            });
        }
        Ok(())
    }
}

/// Runtime mode for consumer scheduling decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AdaptiveConsumerKernel {
    /// Keep deterministic stable defaults without decision-audit artifacts.
    #[default]
    Stable,
    /// Evaluate auditable FrankenSuite decision contracts for material choices.
    AuditBacked,
}

/// Overflow handling when the consumer's pull queue reaches `max_waiting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConsumerOverflowPolicy {
    /// Reject new requests once the queue is full.
    #[default]
    RejectNew,
    /// Permit higher-priority requests to evict lower-priority queued work.
    ReplaceLowestPriority,
}

/// Dynamic consumer-delivery policy toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FabricConsumerDeliveryPolicy {
    /// Whether the consumer currently runs in push or pull mode.
    pub mode: ConsumerDispatchMode,
    /// Whether the engine is paused by explicit flow control.
    pub paused: bool,
}

impl Default for FabricConsumerDeliveryPolicy {
    fn default() -> Self {
        Self {
            mode: ConsumerDispatchMode::Push,
            paused: false,
        }
    }
}

/// Runtime ownership bound to the consumer's obligation ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FabricConsumerOwner {
    /// Task currently holding the consumer's delivery obligations.
    pub holder: TaskId,
    /// Region that must quiesce before all consumer obligations resolve.
    pub region: RegionId,
}

impl Default for FabricConsumerOwner {
    fn default() -> Self {
        Self {
            holder: TaskId::new_ephemeral(),
            region: RegionId::new_ephemeral(),
        }
    }
}

/// Pull request admitted into the consumer wait queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    /// Maximum number of messages requested.
    pub batch_size: u32,
    /// Named demand class used to interpret the request.
    pub demand_class: ConsumerDemandClass,
    /// Optional byte bound used to tighten the batch size conservatively.
    pub max_bytes: Option<u32>,
    /// Optional expiry in logical cursor ticks relative to enqueue time.
    pub expires: Option<u64>,
    /// Whether the request should fail fast when no data is currently available.
    pub no_wait: bool,
    /// Preferred relay/client that should serve through a temporary capability lease.
    pub pinned_client: Option<NodeId>,
}

impl PullRequest {
    /// Create a new pull request with the required batch size and demand class.
    pub fn new(
        batch_size: u32,
        demand_class: ConsumerDemandClass,
    ) -> Result<Self, FabricConsumerError> {
        if batch_size == 0 {
            return Err(FabricConsumerError::InvalidPullBatchSize);
        }
        Ok(Self {
            batch_size,
            demand_class,
            max_bytes: None,
            expires: None,
            no_wait: false,
            pinned_client: None,
        })
    }

    /// Cap the request by a byte budget.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u32) -> Self {
        self.max_bytes = Some(max_bytes);
        self
    }

    /// Expire the request after `ticks` logical cursor ticks.
    #[must_use]
    pub fn with_expires(mut self, ticks: u64) -> Self {
        self.expires = Some(ticks);
        self
    }

    /// Mark the request as no-wait.
    #[must_use]
    pub fn with_no_wait(mut self) -> Self {
        self.no_wait = true;
        self
    }

    /// Pin the request to a preferred leased relay/client when possible.
    #[must_use]
    pub fn with_pinned_client(mut self, client: NodeId) -> Self {
        self.pinned_client = Some(client);
        self
    }

    fn effective_batch_size(&self) -> Result<u64, FabricConsumerError> {
        if self.max_bytes == Some(0) {
            return Err(FabricConsumerError::InvalidPullMaxBytes);
        }
        if self.expires == Some(0) {
            return Err(FabricConsumerError::InvalidPullExpiry);
        }
        let batch_size = u64::from(self.batch_size);
        let byte_bound = self.max_bytes.map_or(batch_size, u64::from);
        Ok(batch_size.min(byte_bound).max(1))
    }

    fn is_expired(&self, enqueued_at_tick: u64, current_tick: u64) -> bool {
        self.expires
            .is_some_and(|ttl| current_tick > enqueued_at_tick.saturating_add(ttl))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedPullRequest {
    request: PullRequest,
    enqueued_at_tick: u64,
    enqueue_order: u64,
}

/// Pending acknowledgement tracked against an obligation id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAckState {
    /// Original request shape that produced this pending delivery.
    pub request: ScheduledConsumerRequest,
    /// Inclusive sequence window still awaiting acknowledgement.
    pub window: SequenceWindow,
    /// Cursor delivery mode used when the attempt was issued.
    pub delivery_mode: CursorDeliveryMode,
    /// Monotonic attempt number for the logical delivery.
    pub delivery_attempt: u32,
    /// Prior obligation superseded by this attempt, when the delivery is a retry.
    pub supersedes_obligation_id: Option<ObligationId>,
}

/// Dynamic consumer state surfaced to policy and tests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FabricConsumerState {
    /// Total messages dispatched by this consumer engine.
    pub delivered_count: u64,
    /// Messages currently pending acknowledgement.
    pub pending_count: u64,
    /// Highest sequence durably acknowledged by the engine.
    pub ack_floor: u64,
    /// Highest sequence dispatched by the engine.
    pub highest_dispatched: u64,
    /// Pending acknowledgements keyed by their obligation id.
    pub pending_acks: BTreeMap<ObligationId, PendingAckState>,
    next_delivery_attempt: u32,
}

impl FabricConsumerState {
    fn next_attempt(&mut self) -> u32 {
        self.next_delivery_attempt = self.next_delivery_attempt.saturating_add(1).max(1);
        self.next_delivery_attempt
    }

    /// Recompute `ack_floor` after an ack by advancing to `candidate` only if
    /// no pending windows start at or below `candidate`.  This prevents
    /// out-of-order acks from advancing the floor past unacked gaps.
    fn advance_ack_floor(&mut self, candidate: u64) {
        if self.pending_acks.is_empty() {
            // Nothing pending — the candidate is the new floor.
            self.ack_floor = self.ack_floor.max(candidate);
            return;
        }
        let min_pending_start = self
            .pending_acks
            .values()
            .map(|p| p.window.start())
            .filter(|&s| s > 0) // Ignore zero-start windows — they cannot meaningfully bound the floor
            .min()
            .unwrap_or(u64::MAX);
        // Only advance as far as the lowest pending window allows,
        // and do not advance past the sequence we are actually acknowledging.
        // Everything below `min_pending_start` has been acked.
        let safe_floor = candidate.min(min_pending_start.saturating_sub(1));
        self.ack_floor = self.ack_floor.max(safe_floor);
    }
}

/// Public request shape returned with a scheduled delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledConsumerRequest {
    /// A push delivery pinned to a concrete window.
    Push(SequenceWindow),
    /// A pull request resolved into a concrete delivery.
    Pull(PullRequest),
}

/// Concrete delivery scheduled by the consumer engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledConsumerDelivery {
    /// High-level request shape that led to this delivery.
    pub request: ScheduledConsumerRequest,
    /// Window selected for the concrete delivery attempt.
    pub window: SequenceWindow,
    /// Cursor attempt certificate minted for the delivery.
    pub attempt: AttemptCertificate,
    /// Delivery plan chosen from the current cursor lease plus capsule coverage.
    pub plan: DeliveryPlan,
}

/// Result of polling the next queued pull request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullDispatchOutcome {
    /// A concrete delivery was scheduled immediately.
    Scheduled(Box<ScheduledConsumerDelivery>),
    /// No data was available yet; the request remains queued.
    Waiting(PullRequest),
}

/// Typed reason for aborting a delivery attempt instead of committing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerNackReason {
    /// Operator or caller explicitly rejected the delivery.
    Explicit,
    /// Delivery failed due to a processing error.
    Error,
    /// Delivery was cancelled before the consumer could complete it.
    Cancel,
}

impl ConsumerNackReason {
    const fn abort_reason(self) -> ObligationAbortReason {
        match self {
            Self::Explicit => ObligationAbortReason::Explicit,
            Self::Error => ObligationAbortReason::Error,
            Self::Cancel => ObligationAbortReason::Cancel,
        }
    }
}

/// Result of negatively acknowledging a delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NackResolution {
    /// The pending obligation was aborted and removed from consumer state.
    Aborted {
        /// Obligation closed by the nack path.
        obligation_id: ObligationId,
        /// Window released by the abort.
        window: SequenceWindow,
        /// Typed reason recorded against the ledger entry.
        reason: ConsumerNackReason,
    },
    /// The attempt was already stale or previously resolved, so the nack is a no-op.
    StaleNoOp {
        /// Obligation associated with the stale negative acknowledgement.
        obligation_id: ObligationId,
        /// Current generation that fences out the stale attempt.
        current_generation: u64,
        /// Holder that currently owns the lease.
        current_holder: CursorLeaseHolder,
    },
}

/// Structured dead-letter transfer emitted when a delivery attempt is abandoned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterTransfer {
    /// Obligation that was removed from the pending set.
    pub obligation_id: ObligationId,
    /// Window that moved to the dead-letter path.
    pub window: SequenceWindow,
    /// Delivery attempt associated with the transfer.
    pub delivery_attempt: u32,
    /// Human-readable reason recorded for the DLQ transfer.
    pub reason: String,
}

/// Typed consumer decision surfaces that can emit FrankenSuite audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsumerDecisionKind {
    /// Ordering or lease choice for queued pull work.
    PullScheduling,
    /// Full-queue handling and bounded overflow policy.
    Overflow,
    /// Retry/delay/dead-letter choice for a failed delivery.
    Redelivery,
}

/// Material action chosen by the redelivery policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsumerRedeliveryAction {
    /// Retry immediately under a fresh obligation.
    RetryNow,
    /// Keep the current delivery pending and defer the retry.
    Delay,
    /// Stop retrying and route the delivery to dead letter handling.
    DeadLetter,
}

impl ConsumerRedeliveryAction {
    #[must_use]
    const fn label(self) -> &'static str {
        match self {
            Self::RetryNow => "retry_now",
            Self::Delay => "delay",
            Self::DeadLetter => "dead_letter",
        }
    }
}

/// Auditable record of one consumer scheduling / retry decision.
#[derive(Debug, Clone)]
pub struct ConsumerDecisionRecord {
    /// Decision surface that produced this record.
    pub kind: ConsumerDecisionKind,
    /// Chosen action label from the underlying decision contract.
    pub action_name: String,
    /// Primary demand class or retry lane this decision was about.
    pub demand_class: Option<ConsumerDemandClass>,
    /// Pending obligation implicated by the decision, when any.
    pub obligation_id: Option<ObligationId>,
    /// Preferred pinned client considered by the decision, when any.
    pub pinned_client: Option<NodeId>,
    /// Decision audit entry convertible into the evidence ledger.
    pub audit: DecisionAuditEntry,
}

/// High-level policy-driven consumer engine layered on top of cursor leases.
#[derive(Debug)]
pub struct FabricConsumer {
    cursor: FabricConsumerCursor,
    config: FabricConsumerConfig,
    owner: FabricConsumerOwner,
    ledger: ObligationLedger,
    policy: FabricConsumerDeliveryPolicy,
    state: FabricConsumerState,
    pending_ack_tokens: BTreeMap<ObligationId, ObligationToken>,
    decision_log: Vec<ConsumerDecisionRecord>,
    /// Maximum number of decision log entries retained.  Oldest entries are
    /// evicted when the cap is reached.
    decision_log_capacity: usize,
    next_event_nanos: u64,
    next_pull_enqueue_order: u64,
    waiting_pull_requests: Vec<QueuedPullRequest>,
}

impl FabricConsumer {
    /// Construct a new consumer engine from the current subject cell.
    pub fn new(
        cell: &SubjectCell,
        config: FabricConsumerConfig,
    ) -> Result<Self, FabricConsumerError> {
        Self::new_owned(cell, config, FabricConsumerOwner::default())
    }

    /// Construct a new consumer engine with explicit runtime ownership metadata.
    pub fn new_owned(
        cell: &SubjectCell,
        config: FabricConsumerConfig,
        owner: FabricConsumerOwner,
    ) -> Result<Self, FabricConsumerError> {
        config.validate()?;
        Ok(Self {
            cursor: FabricConsumerCursor::new(cell)?,
            config,
            owner,
            ledger: ObligationLedger::new(),
            policy: FabricConsumerDeliveryPolicy::default(),
            state: FabricConsumerState::default(),
            pending_ack_tokens: BTreeMap::new(),
            decision_log: Vec::new(),
            decision_log_capacity: 4096,
            next_event_nanos: 0,
            next_pull_enqueue_order: 0,
            waiting_pull_requests: Vec::new(),
        })
    }

    /// Return the static consumer configuration.
    #[must_use]
    pub fn config(&self) -> &FabricConsumerConfig {
        &self.config
    }

    /// Return the current dynamic delivery policy.
    #[must_use]
    pub fn policy(&self) -> &FabricConsumerDeliveryPolicy {
        &self.policy
    }

    /// Return the dynamic consumer state.
    #[must_use]
    pub fn state(&self) -> &FabricConsumerState {
        &self.state
    }

    /// Return the runtime ownership metadata backing this consumer's obligations.
    #[must_use]
    pub const fn owner(&self) -> FabricConsumerOwner {
        self.owner
    }

    /// Return ledger statistics for the consumer's delivery obligations.
    #[must_use]
    pub fn obligation_stats(&self) -> LedgerStats {
        self.ledger.stats()
    }

    /// Return the in-memory decision log for audit-backed consumer kernels.
    #[must_use]
    pub fn decision_log(&self) -> &[ConsumerDecisionRecord] {
        &self.decision_log
    }

    /// Append a decision record, evicting the oldest entry when the log is
    /// at capacity.
    fn push_decision(&mut self, record: ConsumerDecisionRecord) {
        if self.decision_log.len() >= self.decision_log_capacity {
            self.decision_log.remove(0);
        }
        self.decision_log.push(record);
    }

    /// Return the number of queued pull requests still waiting for service.
    #[must_use]
    pub fn waiting_pull_request_count(&self) -> usize {
        self.waiting_pull_requests.len()
    }

    /// Return the current cursor lease.
    #[must_use]
    pub fn current_lease(&self) -> &CursorAuthorityLease {
        self.cursor.current_lease()
    }

    /// Advance logical time for ticket and pull-request expiry testing.
    pub fn advance_clock(&mut self, ticks: u64) -> u64 {
        self.cursor.advance_ticket_clock(ticks)
    }

    /// Switch between push and pull delivery.
    pub fn switch_mode(&mut self, mode: ConsumerDispatchMode) {
        self.policy.mode = mode;
        if mode == ConsumerDispatchMode::Push {
            self.waiting_pull_requests.clear();
        }
    }

    /// Pause the consumer with explicit flow control.
    pub fn pause(&mut self) -> Result<(), FabricConsumerError> {
        if !self.config.flow_control {
            return Err(FabricConsumerError::FlowControlDisabled);
        }
        self.policy.paused = true;
        Ok(())
    }

    /// Resume the consumer after an explicit pause.
    pub fn resume(&mut self) {
        self.policy.paused = false;
    }

    /// Queue a pull request for later dispatch.
    pub fn queue_pull_request(&mut self, request: PullRequest) -> Result<(), FabricConsumerError> {
        if self.policy.mode != ConsumerDispatchMode::Pull {
            return Err(FabricConsumerError::PullModeRequired);
        }
        let _ = request.effective_batch_size()?;
        if self.waiting_pull_requests.len() >= self.config.max_waiting {
            if !self.resolve_pull_overflow(&request) {
                return Err(FabricConsumerError::MaxWaitingExceeded {
                    limit: self.config.max_waiting,
                });
            }
        }
        let enqueued_at_tick = self.cursor.ticket_clock();
        let enqueue_order = self.allocate_pull_enqueue_order();
        self.insert_pull_request(QueuedPullRequest {
            request,
            enqueued_at_tick,
            enqueue_order,
        });
        Ok(())
    }

    /// Dispatch a concrete push window under the active lease.
    #[track_caller]
    pub fn dispatch_push(
        &mut self,
        window: SequenceWindow,
        capsule: &RecoverableCapsule,
        ticket: Option<&ReadDelegationTicket>,
    ) -> Result<ScheduledConsumerDelivery, FabricConsumerError> {
        if self.policy.mode != ConsumerDispatchMode::Push {
            return Err(FabricConsumerError::PushModeRequired);
        }
        let delivery_mode = CursorDeliveryMode::Push { window };
        self.schedule_delivery(
            ScheduledConsumerRequest::Push(window),
            delivery_mode,
            window,
            capsule,
            ticket,
            None,
        )
    }

    /// Try to dispatch the next queued pull request.
    #[track_caller]
    pub fn dispatch_next_pull(
        &mut self,
        available_tail: u64,
        capsule: &RecoverableCapsule,
        ticket: Option<&ReadDelegationTicket>,
    ) -> Result<PullDispatchOutcome, FabricConsumerError> {
        if self.policy.mode != ConsumerDispatchMode::Pull {
            return Err(FabricConsumerError::PullModeRequired);
        }

        let Some(queued) = self.pop_next_live_pull_request() else {
            return Err(FabricConsumerError::NoQueuedPullRequests);
        };
        let request = queued.request.clone();
        let Some(window) = self.resolve_pull_window(&request, available_tail)? else {
            if request.no_wait {
                return Err(FabricConsumerError::NoDataAvailable {
                    demand_class: request.demand_class,
                    available_tail,
                });
            }
            // Preserve the original enqueued_at_tick so the request's
            // expiry deadline is measured from the first enqueue, not each
            // re-enqueue attempt.
            self.insert_pull_request(queued);
            return Ok(PullDispatchOutcome::Waiting(request));
        };
        if let Some(pinned_client) = &request.pinned_client
            && let Some(ticket) = ticket
            && &ticket.relay != pinned_client
        {
            self.insert_pull_request(queued);
            return Err(FabricConsumerError::PinnedClientTicketMismatch {
                pinned_client: pinned_client.clone(),
                ticket_relay: ticket.relay.clone(),
            });
        }
        let scheduled_request = ScheduledConsumerRequest::Pull(request);
        match self.schedule_delivery(
            scheduled_request,
            CursorDeliveryMode::Pull(CursorRequest::Window(window)),
            window,
            capsule,
            ticket,
            None,
        ) {
            Ok(delivery) => Ok(PullDispatchOutcome::Scheduled(Box::new(delivery))),
            Err(err) => {
                self.insert_pull_request(queued);
                Err(err)
            }
        }
    }

    /// Apply an acknowledgement attempt and update pending state on success.
    pub fn acknowledge_delivery(
        &mut self,
        attempt: &AttemptCertificate,
    ) -> Result<AckResolution, FabricConsumerError> {
        if !self.state.pending_acks.contains_key(&attempt.obligation_id) {
            return Ok(self.stale_attempt_noop(attempt.obligation_id));
        }
        let resolution = self.cursor.acknowledge(attempt)?;
        match resolution {
            AckResolution::Committed { .. } => {
                if let Some(pending) = self.state.pending_acks.remove(&attempt.obligation_id) {
                    let token = self
                        .pending_ack_tokens
                        .remove(&attempt.obligation_id)
                        .ok_or(FabricConsumerError::MissingPendingAckToken {
                            obligation_id: attempt.obligation_id,
                        })?;
                    let resolved_at = self.next_event_time();
                    self.ledger.commit(token, resolved_at);
                    self.state.pending_count = self
                        .state
                        .pending_count
                        .saturating_sub(window_len(pending.window));
                    // Advance ack_floor only as far as the contiguous acked
                    // region extends.  Using max(floor, window.end()) would skip
                    // unacked windows below on out-of-order acks, causing CatchUp
                    // to permanently miss those ranges.
                    self.state.advance_ack_floor(pending.window.end());
                }
            }
            AckResolution::StaleNoOp { .. } => {
                if let Some(pending) = self.state.pending_acks.remove(&attempt.obligation_id) {
                    let token = self
                        .pending_ack_tokens
                        .remove(&attempt.obligation_id)
                        .ok_or(FabricConsumerError::MissingPendingAckToken {
                            obligation_id: attempt.obligation_id,
                        })?;
                    let aborted_at = self.next_event_time();
                    self.ledger
                        .abort(token, aborted_at, ObligationAbortReason::Cancel);
                    self.state.pending_count = self
                        .state
                        .pending_count
                        .saturating_sub(window_len(pending.window));
                }
            }
        }
        Ok(resolution)
    }

    /// Abort a pending delivery attempt without committing it.
    pub fn nack_delivery(
        &mut self,
        attempt: &AttemptCertificate,
        reason: ConsumerNackReason,
    ) -> Result<NackResolution, FabricConsumerError> {
        let Some(pending) = self.state.pending_acks.remove(&attempt.obligation_id) else {
            return Ok(self.stale_nack_noop(attempt.obligation_id));
        };
        let token = self
            .pending_ack_tokens
            .remove(&attempt.obligation_id)
            .ok_or(FabricConsumerError::MissingPendingAckToken {
                obligation_id: attempt.obligation_id,
            })?;
        let aborted_at = self.next_event_time();
        self.ledger.abort(token, aborted_at, reason.abort_reason());
        self.state.pending_count = self
            .state
            .pending_count
            .saturating_sub(window_len(pending.window));
        Ok(NackResolution::Aborted {
            obligation_id: attempt.obligation_id,
            window: pending.window,
            reason,
        })
    }

    /// Reissue a pending delivery attempt under a fresh obligation id.
    #[track_caller]
    pub fn redeliver_delivery(
        &mut self,
        attempt: &AttemptCertificate,
        capsule: &RecoverableCapsule,
        ticket: Option<&ReadDelegationTicket>,
    ) -> Result<ScheduledConsumerDelivery, FabricConsumerError> {
        let Some(pending) = self.state.pending_acks.get(&attempt.obligation_id).cloned() else {
            return Err(FabricConsumerError::PendingAckNotFound {
                obligation_id: attempt.obligation_id,
            });
        };
        let _ = self
            .cursor
            .plan_delivery(pending.delivery_mode, capsule, ticket)?;
        if self.policy.paused {
            return Err(FabricConsumerError::ConsumerPaused);
        }
        let (redelivery_action, decision_record) =
            self.decide_redelivery_action(&pending, attempt.obligation_id);
        if let Some(record) = decision_record {
            self.push_decision(record);
        }
        match redelivery_action {
            ConsumerRedeliveryAction::RetryNow => {}
            ConsumerRedeliveryAction::Delay => {
                return Err(FabricConsumerError::RedeliveryDeferred {
                    obligation_id: attempt.obligation_id,
                    delivery_attempt: pending.delivery_attempt.saturating_add(1),
                });
            }
            ConsumerRedeliveryAction::DeadLetter => {
                return Err(FabricConsumerError::RedeliveryRequiresDeadLetter {
                    obligation_id: attempt.obligation_id,
                    delivery_attempt: pending.delivery_attempt.saturating_add(1),
                });
            }
        }

        let removed = self
            .state
            .pending_acks
            .remove(&attempt.obligation_id)
            .expect("pending state must still exist after preflight");
        let token = self
            .pending_ack_tokens
            .remove(&attempt.obligation_id)
            .ok_or(FabricConsumerError::MissingPendingAckToken {
                obligation_id: attempt.obligation_id,
            })?;
        let aborted_at = self.next_event_time();
        self.ledger
            .abort(token, aborted_at, ObligationAbortReason::Explicit);
        self.state.pending_count = self
            .state
            .pending_count
            .saturating_sub(window_len(removed.window));

        self.schedule_delivery(
            removed.request,
            removed.delivery_mode,
            removed.window,
            capsule,
            ticket,
            Some(attempt.obligation_id),
        )
    }

    /// Transfer a pending attempt into a dead-letter record with an explicit reason.
    pub fn dead_letter_delivery(
        &mut self,
        attempt: &AttemptCertificate,
        reason: impl Into<String>,
    ) -> Result<DeadLetterTransfer, FabricConsumerError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(FabricConsumerError::EmptyDeadLetterReason);
        }

        let pending = self
            .state
            .pending_acks
            .remove(&attempt.obligation_id)
            .ok_or(FabricConsumerError::PendingAckNotFound {
                obligation_id: attempt.obligation_id,
            })?;
        let token = self
            .pending_ack_tokens
            .remove(&attempt.obligation_id)
            .ok_or(FabricConsumerError::MissingPendingAckToken {
                obligation_id: attempt.obligation_id,
            })?;
        let dead_lettered_at = self.next_event_time();
        self.ledger
            .abort(token, dead_lettered_at, ObligationAbortReason::Error);
        self.state.pending_count = self
            .state
            .pending_count
            .saturating_sub(window_len(pending.window));

        Ok(DeadLetterTransfer {
            obligation_id: attempt.obligation_id,
            window: pending.window,
            delivery_attempt: pending.delivery_attempt,
            reason,
        })
    }

    fn pop_next_live_pull_request(&mut self) -> Option<QueuedPullRequest> {
        let current_tick = self.cursor.ticket_clock();
        while !self.waiting_pull_requests.is_empty() {
            let queued = self.waiting_pull_requests.remove(0);
            if !queued
                .request
                .is_expired(queued.enqueued_at_tick, current_tick)
            {
                return Some(queued);
            }
        }
        None
    }

    fn allocate_pull_enqueue_order(&mut self) -> u64 {
        let order = self.next_pull_enqueue_order;
        self.next_pull_enqueue_order = self.next_pull_enqueue_order.saturating_add(1);
        order
    }

    fn insert_pull_request(&mut self, queued: QueuedPullRequest) {
        let insert_at = self
            .waiting_pull_requests
            .iter()
            .position(|existing| {
                queued.request.demand_class.priority_rank()
                    < existing.request.demand_class.priority_rank()
                    || (queued.request.demand_class.priority_rank()
                        == existing.request.demand_class.priority_rank()
                        && queued.enqueue_order < existing.enqueue_order)
            })
            .unwrap_or(self.waiting_pull_requests.len());
        self.waiting_pull_requests.insert(insert_at, queued);
    }

    fn resolve_pull_overflow(&mut self, request: &PullRequest) -> bool {
        let Some(worst_index) = self
            .waiting_pull_requests
            .iter()
            .enumerate()
            .max_by_key(|(_, queued)| {
                (
                    queued.request.demand_class.priority_rank(),
                    queued.enqueue_order,
                )
            })
            .map(|(index, _)| index)
        else {
            return true;
        };

        let incoming_rank = request.demand_class.priority_rank();
        let evicted = self.waiting_pull_requests[worst_index].clone();
        let mut replaced = self.config.overflow_policy
            == ConsumerOverflowPolicy::ReplaceLowestPriority
            && incoming_rank < evicted.request.demand_class.priority_rank();

        if self.config.adaptive_kernel == AdaptiveConsumerKernel::AuditBacked {
            let snapshot = ConsumerOverflowDecisionSnapshot {
                incoming_demand: request.demand_class,
                evicted_demand: evicted.request.demand_class,
                replaced,
            };
            let action = if replaced {
                ConsumerOverflowDecisionAction::ReplaceLowestPriority
            } else {
                ConsumerOverflowDecisionAction::RejectNew
            };
            let contract = ConsumerOverflowDecisionContract::new(action);
            let posterior = snapshot.posterior();
            let ctx = self.decision_context(
                &snapshot,
                snapshot.calibration_score(),
                snapshot.e_process(),
                snapshot.ci_width(),
            );
            let outcome = evaluate(&contract, &posterior, &ctx);

            replaced = outcome.action_name
                == ConsumerOverflowDecisionAction::ReplaceLowestPriority.label();

            self.push_decision(ConsumerDecisionRecord {
                kind: ConsumerDecisionKind::Overflow,
                action_name: outcome.action_name,
                demand_class: Some(request.demand_class),
                obligation_id: None,
                pinned_client: request.pinned_client.clone(),
                audit: outcome.audit_entry,
            });
        }

        if replaced {
            self.waiting_pull_requests.remove(worst_index);
        }

        replaced
    }

    fn resolve_pull_window(
        &self,
        request: &PullRequest,
        available_tail: u64,
    ) -> Result<Option<SequenceWindow>, FabricConsumerError> {
        let batch = request.effective_batch_size()?;
        if available_tail == 0 {
            return Ok(None);
        }

        let next_unacked = self.state.ack_floor.saturating_add(1).max(1);
        let resolve = match request.demand_class {
            ConsumerDemandClass::Tail => {
                if next_unacked > available_tail {
                    None
                } else {
                    let start = available_tail
                        .saturating_sub(batch.saturating_sub(1))
                        .max(next_unacked);
                    Some((start, available_tail))
                }
            }
            ConsumerDemandClass::CatchUp => {
                if next_unacked > available_tail {
                    None
                } else {
                    Some((
                        next_unacked,
                        available_tail.min(next_unacked.saturating_add(batch).saturating_sub(1)),
                    ))
                }
            }
            ConsumerDemandClass::Replay => {
                let start = self.replay_start_sequence(available_tail);
                if start > available_tail {
                    None
                } else {
                    Some((
                        start,
                        available_tail.min(start.saturating_add(batch).saturating_sub(1)),
                    ))
                }
            }
        };

        match resolve {
            Some((start, end)) => Ok(Some(SequenceWindow::new(start, end)?)),
            None => Ok(None),
        }
    }

    fn replay_start_sequence(&self, available_tail: u64) -> u64 {
        match self.config.deliver_policy {
            DeliverPolicy::All => 1,
            DeliverPolicy::New => available_tail.saturating_add(1),
            DeliverPolicy::ByStartSequence(sequence) => sequence.max(1),
            DeliverPolicy::Last | DeliverPolicy::LastPerSubject => available_tail.max(1),
        }
    }

    fn next_event_time(&mut self) -> Time {
        let now = Time::from_nanos(self.next_event_nanos);
        self.next_event_nanos = self.next_event_nanos.saturating_add(1);
        now
    }

    fn decision_context<T: Hash>(
        &mut self,
        seed: &T,
        calibration_score: f64,
        e_process: f64,
        ci_width: f64,
    ) -> EvalContext {
        let when = self.next_event_time();
        let mut hasher = DetHasher::default();
        self.owner.holder.hash(&mut hasher);
        self.owner.region.hash(&mut hasher);
        self.cursor
            .current_lease()
            .lease_generation
            .hash(&mut hasher);
        self.state.pending_count.hash(&mut hasher);
        seed.hash(&mut hasher);
        let fingerprint = u128::from(hasher.finish());
        let ts_unix_ms = when.as_nanos();
        EvalContext {
            calibration_score,
            e_process,
            ci_width,
            decision_id: DecisionId::from_parts(ts_unix_ms, fingerprint),
            trace_id: TraceId::from_parts(ts_unix_ms, fingerprint ^ 0xC0DE_C011_5EED_5100),
            ts_unix_ms,
        }
    }

    fn stale_attempt_noop(&self, obligation_id: ObligationId) -> AckResolution {
        AckResolution::StaleNoOp {
            obligation_id,
            current_generation: self.cursor.current_lease().lease_generation,
            current_holder: self.cursor.current_lease().holder.clone(),
        }
    }

    fn stale_nack_noop(&self, obligation_id: ObligationId) -> NackResolution {
        NackResolution::StaleNoOp {
            obligation_id,
            current_generation: self.cursor.current_lease().lease_generation,
            current_holder: self.cursor.current_lease().holder.clone(),
        }
    }

    #[track_caller]
    fn acquire_ack_token(
        &mut self,
        window: SequenceWindow,
        delivery_attempt: u32,
        supersedes_obligation_id: Option<ObligationId>,
    ) -> ObligationToken {
        let description = supersedes_obligation_id.map_or_else(
            || {
                format!(
                    "consumer ack attempt {} for window {}-{}",
                    delivery_attempt,
                    window.start(),
                    window.end()
                )
            },
            |previous| {
                format!(
                    "consumer ack attempt {} for window {}-{} superseding {:?}",
                    delivery_attempt,
                    window.start(),
                    window.end(),
                    previous
                )
            },
        );
        let acquired_at = self.next_event_time();
        self.ledger.acquire_with_context(
            ObligationKind::Ack,
            self.owner.holder,
            self.owner.region,
            acquired_at,
            SourceLocation::from_panic_location(Location::caller()),
            None,
            Some(description),
        )
    }

    #[track_caller]
    fn schedule_delivery(
        &mut self,
        request: ScheduledConsumerRequest,
        delivery_mode: CursorDeliveryMode,
        window: SequenceWindow,
        capsule: &RecoverableCapsule,
        ticket: Option<&ReadDelegationTicket>,
        supersedes_obligation_id: Option<ObligationId>,
    ) -> Result<ScheduledConsumerDelivery, FabricConsumerError> {
        if self.policy.paused {
            return Err(FabricConsumerError::ConsumerPaused);
        }

        let window_messages = window_len(window);
        if self.state.pending_count.saturating_add(window_messages)
            > self.config.max_ack_pending as u64
        {
            return Err(FabricConsumerError::MaxAckPendingExceeded {
                limit: self.config.max_ack_pending,
                pending: self.state.pending_count,
            });
        }

        let plan = self.cursor.plan_delivery(delivery_mode, capsule, ticket)?;
        let delivery_attempt = self.state.next_attempt();
        let token = self.acquire_ack_token(window, delivery_attempt, supersedes_obligation_id);
        let obligation_id = token.id();
        let mut attempt =
            self.cursor
                .issue_attempt(delivery_mode, delivery_attempt, obligation_id)?;
        attempt.supersedes_obligation_id = supersedes_obligation_id;

        self.state.delivered_count = self.state.delivered_count.saturating_add(window_messages);
        self.state.pending_count = self.state.pending_count.saturating_add(window_messages);
        self.state.highest_dispatched = self.state.highest_dispatched.max(window.end());
        self.state.pending_acks.insert(
            obligation_id,
            PendingAckState {
                request: request.clone(),
                window,
                delivery_mode,
                delivery_attempt,
                supersedes_obligation_id,
            },
        );
        self.pending_ack_tokens.insert(obligation_id, token);
        if let ScheduledConsumerRequest::Pull(pull_request) = &request
            && let Some(record) = self.make_pull_decision_record(pull_request, &plan, obligation_id)
        {
            self.push_decision(record);
        }

        Ok(ScheduledConsumerDelivery {
            request,
            window,
            attempt,
            plan,
        })
    }

    fn make_pull_decision_record(
        &mut self,
        request: &PullRequest,
        plan: &DeliveryPlan,
        obligation_id: ObligationId,
    ) -> Option<ConsumerDecisionRecord> {
        if self.config.adaptive_kernel != AdaptiveConsumerKernel::AuditBacked {
            return None;
        }

        let snapshot = ConsumerPullDecisionSnapshot {
            demand_class: request.demand_class,
            pinned_requested: request.pinned_client.is_some(),
            pending_ratio_permille: pending_ratio_permille(
                self.state.pending_count,
                self.config.max_ack_pending,
            ),
        };
        let chosen_action = ConsumerPullDecisionAction::from_plan(plan, request);
        let contract = ConsumerPullDecisionContract::new(chosen_action);
        let posterior = snapshot.posterior();
        let ctx = self.decision_context(
            &snapshot,
            snapshot.calibration_score(),
            snapshot.e_process(),
            snapshot.ci_width(),
        );
        let outcome = evaluate(&contract, &posterior, &ctx);
        Some(ConsumerDecisionRecord {
            kind: ConsumerDecisionKind::PullScheduling,
            action_name: outcome.action_name,
            demand_class: Some(request.demand_class),
            obligation_id: Some(obligation_id),
            pinned_client: request.pinned_client.clone(),
            audit: outcome.audit_entry,
        })
    }

    fn decide_redelivery_action(
        &mut self,
        pending: &PendingAckState,
        obligation_id: ObligationId,
    ) -> (ConsumerRedeliveryAction, Option<ConsumerDecisionRecord>) {
        let next_attempt = pending.delivery_attempt.saturating_add(1);
        let pending_ratio =
            pending_ratio_permille(self.state.pending_count, self.config.max_ack_pending);
        let action = if next_attempt > u32::from(self.config.max_deliver) {
            ConsumerRedeliveryAction::DeadLetter
        } else if pending_ratio >= 850 && next_attempt > 1 {
            ConsumerRedeliveryAction::Delay
        } else {
            ConsumerRedeliveryAction::RetryNow
        };

        if self.config.adaptive_kernel != AdaptiveConsumerKernel::AuditBacked {
            return (action, None);
        }
        let snapshot = ConsumerRedeliveryDecisionSnapshot {
            next_attempt,
            max_deliver: self.config.max_deliver,
            pending_ratio_permille: pending_ratio,
        };
        let contract = ConsumerRedeliveryDecisionContract::new(action);
        let posterior = snapshot.posterior();
        let ctx = self.decision_context(
            &snapshot,
            snapshot.calibration_score(),
            snapshot.e_process(),
            snapshot.ci_width(),
        );
        let outcome = evaluate(&contract, &posterior, &ctx);
        (
            action,
            Some(ConsumerDecisionRecord {
                kind: ConsumerDecisionKind::Redelivery,
                action_name: outcome.action_name,
                demand_class: None,
                obligation_id: Some(obligation_id),
                pinned_client: None,
                audit: outcome.audit_entry,
            }),
        )
    }
}

fn window_len(window: SequenceWindow) -> u64 {
    window
        .end()
        .saturating_sub(window.start())
        .saturating_add(1)
}

fn pending_ratio_permille(pending_count: u64, max_ack_pending: usize) -> u16 {
    let limit = max_ack_pending.max(1) as u64;
    let ratio = pending_count
        .saturating_mul(1000)
        .checked_div(limit)
        .unwrap_or(0)
        .min(1000);
    ratio as u16
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConsumerPullDecisionAction {
    CurrentSteward,
    LeasedRelay,
    Reconstructed,
}

impl ConsumerPullDecisionAction {
    fn from_plan(plan: &DeliveryPlan, request: &PullRequest) -> Self {
        match plan {
            DeliveryPlan::CurrentSteward(_) => {
                let _ = request;
                Self::CurrentSteward
            }
            DeliveryPlan::LeasedRelay { .. } => Self::LeasedRelay,
            DeliveryPlan::Reconstructed { .. } => Self::Reconstructed,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CurrentSteward => "current_steward",
            Self::LeasedRelay => "leased_relay",
            Self::Reconstructed => "reconstructed",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::CurrentSteward => 0,
            Self::LeasedRelay => 1,
            Self::Reconstructed => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConsumerPullDecisionSnapshot {
    demand_class: ConsumerDemandClass,
    pinned_requested: bool,
    pending_ratio_permille: u16,
}

impl ConsumerPullDecisionSnapshot {
    fn posterior(self) -> Posterior {
        let backpressure = f64::from(self.pending_ratio_permille) / 1000.0;
        let mut weights = [0.05; 4];
        let state_index = match self.demand_class {
            ConsumerDemandClass::Tail => 0,
            ConsumerDemandClass::CatchUp => 1,
            ConsumerDemandClass::Replay => 2,
        };
        weights[state_index] = 0.72 - (backpressure * 0.2);
        weights[3] = 0.08 + (backpressure * 0.55);
        if self.pinned_requested {
            weights[1] += 0.08;
        }
        normalize_posterior(weights)
    }

    fn calibration_score(self) -> f64 {
        if self.pending_ratio_permille >= 850 {
            0.74
        } else {
            0.93
        }
    }

    fn e_process(self) -> f64 {
        1.0 + f64::from(self.pending_ratio_permille) / 650.0
    }

    fn ci_width(self) -> f64 {
        0.08 + f64::from(self.pending_ratio_permille) / 3000.0
    }
}

#[derive(Debug, Clone)]
struct ConsumerPullDecisionContract {
    states: Vec<String>,
    actions: Vec<String>,
    losses: LossMatrix,
    chosen_action: ConsumerPullDecisionAction,
    fallback: FallbackPolicy,
}

impl ConsumerPullDecisionContract {
    fn new(chosen_action: ConsumerPullDecisionAction) -> Self {
        let states = vec![
            "tail_priority".into(),
            "catchup_priority".into(),
            "replay_priority".into(),
            "backpressured".into(),
        ];
        let actions = vec![
            ConsumerPullDecisionAction::CurrentSteward.label().into(),
            ConsumerPullDecisionAction::LeasedRelay.label().into(),
            ConsumerPullDecisionAction::Reconstructed.label().into(),
        ];
        let losses = LossMatrix::new(
            states.clone(),
            actions.clone(),
            vec![
                1.0, 2.0, 7.0, // tail
                4.0, 2.0, 5.0, // catch-up
                6.0, 4.0, 1.0, // replay
                8.0, 5.0, 3.0, // backpressured
            ],
        )
        .expect("consumer pull decision losses should be valid");
        Self {
            states,
            actions,
            losses,
            chosen_action,
            fallback: FallbackPolicy::default(),
        }
    }
}

impl DecisionContract for ConsumerPullDecisionContract {
    fn name(&self) -> &'static str {
        "fabric_consumer_pull_scheduler"
    }

    fn state_space(&self) -> &[String] {
        &self.states
    }

    fn action_set(&self) -> &[String] {
        &self.actions
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.losses
    }

    fn update_posterior(&self, posterior: &mut Posterior, observation: usize) {
        let mut likelihoods = [0.1; 4];
        if let Some(slot) = likelihoods.get_mut(observation) {
            *slot = 0.9;
        }
        posterior.bayesian_update(&likelihoods);
    }

    fn choose_action(&self, _posterior: &Posterior) -> usize {
        self.chosen_action.index()
    }

    fn fallback_action(&self) -> usize {
        self.chosen_action.index()
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConsumerOverflowDecisionAction {
    RejectNew,
    ReplaceLowestPriority,
}

impl ConsumerOverflowDecisionAction {
    const fn label(self) -> &'static str {
        match self {
            Self::RejectNew => "reject_new",
            Self::ReplaceLowestPriority => "replace_low_priority",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::RejectNew => 0,
            Self::ReplaceLowestPriority => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConsumerOverflowDecisionSnapshot {
    incoming_demand: ConsumerDemandClass,
    evicted_demand: ConsumerDemandClass,
    replaced: bool,
}

impl ConsumerOverflowDecisionSnapshot {
    fn posterior(self) -> Posterior {
        let mut weights = [0.05; 4];
        weights[self.incoming_demand.priority_rank() as usize] = 0.68;
        weights[3] = if self.replaced { 0.12 } else { 0.34 };
        normalize_posterior(weights)
    }

    fn calibration_score(self) -> f64 {
        if self.replaced { 0.91 } else { 0.79 }
    }

    fn e_process(self) -> f64 {
        1.6 + f64::from(self.evicted_demand.priority_rank())
    }

    fn ci_width(self) -> f64 {
        if self.replaced { 0.15 } else { 0.31 }
    }
}

#[derive(Debug, Clone)]
struct ConsumerOverflowDecisionContract {
    states: Vec<String>,
    actions: Vec<String>,
    losses: LossMatrix,
    chosen_action: ConsumerOverflowDecisionAction,
    fallback: FallbackPolicy,
}

impl ConsumerOverflowDecisionContract {
    fn new(chosen_action: ConsumerOverflowDecisionAction) -> Self {
        let states = vec![
            "tail_pressure".into(),
            "catchup_pressure".into(),
            "replay_pressure".into(),
            "queue_saturated".into(),
        ];
        let actions = vec![
            ConsumerOverflowDecisionAction::RejectNew.label().into(),
            ConsumerOverflowDecisionAction::ReplaceLowestPriority
                .label()
                .into(),
        ];
        let losses = LossMatrix::new(
            states.clone(),
            actions.clone(),
            vec![
                9.0, 1.0, // tail
                5.0, 3.0, // catch-up
                1.0, 8.0, // replay
                4.0, 2.0, // saturated
            ],
        )
        .expect("consumer overflow decision losses should be valid");
        Self {
            states,
            actions,
            losses,
            chosen_action,
            fallback: FallbackPolicy::default(),
        }
    }
}

impl DecisionContract for ConsumerOverflowDecisionContract {
    fn name(&self) -> &'static str {
        "fabric_consumer_overflow_policy"
    }

    fn state_space(&self) -> &[String] {
        &self.states
    }

    fn action_set(&self) -> &[String] {
        &self.actions
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.losses
    }

    fn update_posterior(&self, posterior: &mut Posterior, observation: usize) {
        let mut likelihoods = [0.1; 4];
        if let Some(slot) = likelihoods.get_mut(observation) {
            *slot = 0.9;
        }
        posterior.bayesian_update(&likelihoods);
    }

    fn choose_action(&self, _posterior: &Posterior) -> usize {
        self.chosen_action.index()
    }

    fn fallback_action(&self) -> usize {
        self.chosen_action.index()
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConsumerRedeliveryDecisionSnapshot {
    next_attempt: u32,
    max_deliver: u16,
    pending_ratio_permille: u16,
}

impl ConsumerRedeliveryDecisionSnapshot {
    fn posterior(self) -> Posterior {
        let exhausted = self.next_attempt > u32::from(self.max_deliver);
        let pressured = self.pending_ratio_permille >= 850;
        let weights = if exhausted {
            [0.05, 0.1, 0.85]
        } else if pressured {
            [0.18, 0.67, 0.15]
        } else {
            [0.82, 0.12, 0.06]
        };
        normalize_posterior(weights)
    }

    fn calibration_score(self) -> f64 {
        if self.next_attempt > u32::from(self.max_deliver) {
            0.88
        } else if self.pending_ratio_permille >= 850 {
            0.77
        } else {
            0.94
        }
    }

    fn e_process(self) -> f64 {
        1.0 + f64::from(self.next_attempt) / 3.0 + f64::from(self.pending_ratio_permille) / 900.0
    }

    fn ci_width(self) -> f64 {
        0.09 + f64::from(self.pending_ratio_permille) / 4000.0
    }
}

#[derive(Debug, Clone)]
struct ConsumerRedeliveryDecisionContract {
    states: Vec<String>,
    actions: Vec<String>,
    losses: LossMatrix,
    chosen_action: ConsumerRedeliveryAction,
    fallback: FallbackPolicy,
}

impl ConsumerRedeliveryDecisionContract {
    fn new(chosen_action: ConsumerRedeliveryAction) -> Self {
        let states = vec![
            "transient_failure".into(),
            "pressure".into(),
            "exhausted".into(),
        ];
        let actions = vec![
            ConsumerRedeliveryAction::RetryNow.label().into(),
            ConsumerRedeliveryAction::Delay.label().into(),
            ConsumerRedeliveryAction::DeadLetter.label().into(),
        ];
        let losses = LossMatrix::new(
            states.clone(),
            actions.clone(),
            vec![
                1.0, 4.0, 12.0, // transient
                7.0, 2.0, 5.0, // pressure
                18.0, 6.0, 1.0, // exhausted
            ],
        )
        .expect("consumer redelivery decision losses should be valid");
        Self {
            states,
            actions,
            losses,
            chosen_action,
            fallback: FallbackPolicy::default(),
        }
    }
}

impl DecisionContract for ConsumerRedeliveryDecisionContract {
    fn name(&self) -> &'static str {
        "fabric_consumer_redelivery_policy"
    }

    fn state_space(&self) -> &[String] {
        &self.states
    }

    fn action_set(&self) -> &[String] {
        &self.actions
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.losses
    }

    fn update_posterior(&self, posterior: &mut Posterior, observation: usize) {
        let mut likelihoods = [0.1; 3];
        if let Some(slot) = likelihoods.get_mut(observation) {
            *slot = 0.9;
        }
        posterior.bayesian_update(&likelihoods);
    }

    fn choose_action(&self, _posterior: &Posterior) -> usize {
        match self.chosen_action {
            ConsumerRedeliveryAction::RetryNow => 0,
            ConsumerRedeliveryAction::Delay => 1,
            ConsumerRedeliveryAction::DeadLetter => 2,
        }
    }

    fn fallback_action(&self) -> usize {
        match self.chosen_action {
            ConsumerRedeliveryAction::RetryNow => 0,
            ConsumerRedeliveryAction::Delay => 1,
            ConsumerRedeliveryAction::DeadLetter => 2,
        }
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

fn normalize_posterior<const N: usize>(mut weights: [f64; N]) -> Posterior {
    for weight in &mut weights {
        if *weight <= 0.0 {
            *weight = 0.01;
        }
    }
    let total = weights.iter().sum::<f64>().max(f64::EPSILON);
    Posterior::new(weights.into_iter().map(|weight| weight / total).collect())
        .expect("consumer decision posterior should normalize")
}

/// High-level consumer-engine failures layered on top of cursor errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FabricConsumerError {
    /// Consumer delivery attempts require a positive retry budget.
    #[error("consumer max_deliver must be greater than zero")]
    InvalidMaxDeliver,
    /// Pending-ack flow control must reserve at least one message slot.
    #[error("consumer max_ack_pending must be greater than zero")]
    InvalidMaxAckPending,
    /// Pull-mode wait queues must reserve at least one slot.
    #[error("consumer max_waiting must be greater than zero")]
    InvalidMaxWaiting,
    /// Ack deadlines must be explicit and positive.
    #[error("consumer ack_wait must be greater than zero")]
    InvalidAckWait,
    /// Heartbeat fields must never be zero-duration sentinels.
    #[error("consumer {field} must be greater than zero when configured")]
    InvalidHeartbeat {
        /// Name of the invalid heartbeat field.
        field: &'static str,
    },
    /// Pull requests must ask for at least one message.
    #[error("pull request batch_size must be greater than zero")]
    InvalidPullBatchSize,
    /// Pull requests may not pretend that zero bytes are useful demand.
    #[error("pull request max_bytes must be greater than zero when configured")]
    InvalidPullMaxBytes,
    /// Pull-request expiries use logical ticks and must be positive.
    #[error("pull request expires must be greater than zero when configured")]
    InvalidPullExpiry,
    /// Push-only operations were attempted while the consumer is in pull mode.
    #[error("consumer is not in push mode")]
    PushModeRequired,
    /// Pull-only operations were attempted while the consumer is not in pull mode.
    #[error("consumer is not in pull mode")]
    PullModeRequired,
    /// Flow-control pause/resume is disabled in the static config.
    #[error("consumer flow control is disabled")]
    FlowControlDisabled,
    /// Dispatch is paused until the operator resumes the consumer.
    #[error("consumer dispatch is paused")]
    ConsumerPaused,
    /// Flow-control backpressure blocked another dispatch.
    #[error("consumer pending messages `{pending}` exceed or meet max_ack_pending `{limit}`")]
    MaxAckPendingExceeded {
        /// Configured pending-message limit.
        limit: usize,
        /// Current pending message count.
        pending: u64,
    },
    /// Pull queue admission exceeded the configured waiting bound.
    #[error("consumer already has max_waiting `{limit}` queued pull requests")]
    MaxWaitingExceeded {
        /// Configured max waiting pull requests.
        limit: usize,
    },
    /// No queued pull request was available when dispatch was attempted.
    #[error("consumer has no queued pull requests")]
    NoQueuedPullRequests,
    /// A no-wait pull request found no data.
    #[error(
        "no data available for pull request class `{demand_class:?}` at tail `{available_tail}`"
    )]
    NoDataAvailable {
        /// Demand class of the request that could not be served.
        demand_class: ConsumerDemandClass,
        /// Tail sequence visible to the consumer at dispatch time.
        available_tail: u64,
    },
    /// A pinned-client request supplied a ticket for a different relay.
    #[error(
        "pinned client `{pinned_client}` does not match supplied ticket relay `{ticket_relay}`"
    )]
    PinnedClientTicketMismatch {
        /// Relay requested by the pull request.
        pinned_client: NodeId,
        /// Relay named inside the supplied read-delegation ticket.
        ticket_relay: NodeId,
    },
    /// The attempt referred to an obligation that is no longer pending.
    #[error("consumer obligation `{obligation_id}` is not pending")]
    PendingAckNotFound {
        /// Obligation the caller attempted to resolve or redeliver.
        obligation_id: ObligationId,
    },
    /// Consumer state lost the linear token for a pending obligation.
    #[error("consumer obligation `{obligation_id}` is pending but its ledger token is missing")]
    MissingPendingAckToken {
        /// Obligation whose token could not be recovered from the consumer state.
        obligation_id: ObligationId,
    },
    /// Dead-letter transfers must capture a non-empty reason.
    #[error("dead-letter reason must not be empty")]
    EmptyDeadLetterReason,
    /// The adaptive redelivery policy deferred the retry instead of executing it now.
    #[error(
        "consumer deferred redelivery for obligation `{obligation_id}` at attempt `{delivery_attempt}`"
    )]
    RedeliveryDeferred {
        /// Pending obligation that remains live.
        obligation_id: ObligationId,
        /// Attempt count the contract evaluated for the deferred retry.
        delivery_attempt: u32,
    },
    /// The adaptive redelivery policy requires the caller to dead-letter this delivery.
    #[error(
        "consumer requires dead-letter handling for obligation `{obligation_id}` at attempt `{delivery_attempt}`"
    )]
    RedeliveryRequiresDeadLetter {
        /// Pending obligation that has exhausted or exceeded its retry budget.
        obligation_id: ObligationId,
        /// Attempt count that triggered the dead-letter recommendation.
        delivery_attempt: u32,
    },
    /// Low-level cursor machinery rejected the operation.
    #[error(transparent)]
    Cursor(#[from] ConsumerCursorError),
}

/// Deterministic cursor-lease failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConsumerCursorError {
    /// Sequence windows must be ordered.
    #[error("invalid sequence window `{start}..={end}`")]
    InvalidSequenceWindow {
        /// Proposed start of the invalid window.
        start: u64,
        /// Proposed end of the invalid window.
        end: u64,
    },
    /// Subject cell must expose an active sequencer to seed cursor authority.
    #[error("subject cell `{cell_id}` has no active sequencer")]
    NoActiveSequencer {
        /// Cell whose control capsule lacked an active sequencer.
        cell_id: CellId,
    },
    /// Delivery attempts are 1-based.
    #[error("delivery attempt must be greater than zero")]
    InvalidDeliveryAttempt,
    /// Delegated read tickets must remain bounded in logical time.
    #[error("read-delegation ticket ttl must be greater than zero, got `{ttl_ticks}`")]
    InvalidReadDelegationTtl {
        /// Requested logical time-to-live for the ticket.
        ttl_ticks: u64,
    },
    /// Failover target is not in the steward pool.
    #[error("steward `{steward}` is not in the steward pool for cell `{cell_id}`")]
    UnknownSteward {
        /// Cell whose steward pool was consulted.
        cell_id: CellId,
        /// Proposed failover target not present in the steward pool.
        steward: NodeId,
    },
    /// Relay delegation is only meaningful for non-stewards.
    #[error("relay `{relay}` is already a steward and does not need a read ticket")]
    RelayMustNotBeSteward {
        /// Relay peer that was already part of the steward set.
        relay: NodeId,
    },
    /// Relay authority transfers must identify the delegated partition they own.
    #[error("relay `{relay}` transfer must target a delegated cursor partition")]
    RelayTransferRequiresPartition {
        /// Relay peer that attempted a control-capsule transfer.
        relay: NodeId,
    },
    /// Partition assignment strategy requires non-empty selector fields.
    #[error("cursor partition selector field `{field}` must not be empty")]
    EmptyCursorPartitionSelector {
        /// Selector field that failed validation.
        field: &'static str,
    },
    /// Subject sub-ranges must be ordered.
    #[error("cursor partition subject sub-range `{start}`..=`{end}` is invalid")]
    InvalidCursorPartitionSubRange {
        /// Proposed start key.
        start: String,
        /// Proposed end key.
        end: String,
    },
    /// Hash-bucket partition selectors must stay inside their bucket set.
    #[error("cursor partition bucket `{bucket}` is invalid for bucket set size `{buckets}`")]
    InvalidCursorPartitionBucket {
        /// Proposed bucket index.
        bucket: u16,
        /// Total bucket count.
        buckets: u16,
    },
    /// Delegated partitions must own at least one consumer.
    #[error("cursor partition `{partition}` must own at least one consumer")]
    EmptyCursorPartitionConsumers {
        /// Partition that was missing consumer assignments.
        partition: u16,
    },
    /// Partition-scoped operations must refer to a registered partition.
    #[error("cursor partition `{partition}` is unknown to the current cursor state")]
    UnknownCursorPartition {
        /// Partition referenced by the caller.
        partition: u16,
    },
    /// Coarse checkpoint reports only make sense while the matching partition is leased.
    #[error(
        "cursor partition `{partition}` checkpoint does not match the current delegated lease scope `{current_scope:?}`"
    )]
    PartitionCheckpointRequiresDelegatedLease {
        /// Partition the report was trying to update.
        partition: u16,
        /// Current lease scope that fenced out the report.
        current_scope: CursorLeaseScope,
    },
    /// Coarse checkpoint reports must be bound to the active lease generation.
    #[error(
        "cursor partition `{partition}` checkpoint generation `{report_generation}` is stale; current generation is `{current_generation}`"
    )]
    StaleCursorPartitionCheckpoint {
        /// Partition the stale report targeted.
        partition: u16,
        /// Generation carried by the report.
        report_generation: u64,
        /// Generation currently owned by the cursor state machine.
        current_generation: u64,
    },
    /// Partition summaries must preserve the control capsule's assigned
    /// consumer cardinality.
    #[error(
        "cursor partition `{partition}` reported consumer_count `{reported_consumer_count}` but assignment owns `{assigned_consumer_count}` consumers"
    )]
    PartitionCheckpointConsumerCountMismatch {
        /// Partition whose summary mismatched the assigned consumer set.
        partition: u16,
        /// Count reported by the delegated partition leader.
        reported_consumer_count: u32,
        /// Deterministic count from the control-capsule assignment.
        assigned_consumer_count: usize,
    },
    /// Relay serving requires a lease-bound read ticket.
    #[error("relay `{relay}` is missing a read-delegation ticket")]
    MissingReadDelegationTicket {
        /// Relay peer that tried to serve without a bound ticket.
        relay: NodeId,
    },
    /// The provided ticket was minted for an earlier or different epoch.
    #[error(
        "read-delegation ticket for relay `{relay}` is stale for `{ticket_cell}`@{ticket_epoch:?}; current lease is `{current_cell}`@{current_epoch:?}"
    )]
    StaleReadDelegationEpoch {
        /// Relay peer carrying the stale ticket.
        relay: NodeId,
        /// Cell bound into the stale ticket.
        ticket_cell: CellId,
        /// Epoch bound into the stale ticket.
        ticket_epoch: CellEpoch,
        /// Cell currently owned by this cursor state machine.
        current_cell: CellId,
        /// Current epoch of the active lease.
        current_epoch: CellEpoch,
    },
    /// The provided ticket has expired in logical cursor time.
    #[error(
        "read-delegation ticket for relay `{relay}` expired at tick `{expired_at_tick}` (current `{current_tick}`)"
    )]
    ExpiredReadDelegationTicket {
        /// Relay peer carrying the expired ticket.
        relay: NodeId,
        /// Last valid logical tick for the ticket.
        expired_at_tick: u64,
        /// Current logical cursor tick.
        current_tick: u64,
    },
    /// The provided ticket was explicitly revoked after issuance.
    #[error(
        "read-delegation ticket for relay `{relay}` was revoked via handle `{revocation_handle:?}`"
    )]
    RevokedReadDelegationTicket {
        /// Relay peer carrying the revoked ticket.
        relay: NodeId,
        /// Revocation handle that fenced the ticket.
        revocation_handle: ReadDelegationRevocationHandle,
    },
    /// The provided ticket does not match the current lease or requested window.
    #[error(
        "read-delegation ticket for relay `{relay}` does not match the current lease/window `{requested_window}`"
    )]
    InvalidReadDelegationTicket {
        /// Relay peer named in the invalid ticket.
        relay: NodeId,
        /// Window the caller asked the relay to serve.
        requested_window: SequenceWindow,
    },
    /// No recoverable path exists for the requested window.
    #[error("requested delivery window `{window}` is not recoverable from the capsule")]
    UnrecoverableWindow {
        /// Window whose bytes were not reconstructable.
        window: SequenceWindow,
    },
    /// Attempt certificate must stay scoped to the current cell/epoch.
    #[error("attempt certificate scope does not match the current cursor lease")]
    AttemptScopeMismatch {
        /// Cell encoded in the stale or foreign attempt certificate.
        certificate_cell: CellId,
        /// Epoch encoded in the stale or foreign attempt certificate.
        certificate_epoch: CellEpoch,
        /// Cell currently owned by this cursor state machine.
        current_cell: CellId,
        /// Epoch currently owned by this cursor state machine.
        current_epoch: CellEpoch,
    },
}

// ── ConsumerActor: GenServer-hosted consumer delivery engine ──────────

/// Call types for the [`ConsumerActor`] GenServer.
#[derive(Debug)]
pub enum ConsumerCall {
    /// Request the next available delivery (pull mode).
    Pull {
        /// Tail sequence available for delivery.
        available_tail: u64,
        /// Recoverable capsule coverage for the pull.
        capsule: RecoverableCapsule,
        /// Optional read-delegation ticket for relay delivery.
        ticket: Option<ReadDelegationTicket>,
    },
    /// Acknowledge a successful delivery.
    Ack {
        /// Certificate minted for the delivery.
        attempt: AttemptCertificate,
    },
    /// Negatively acknowledge a delivery.
    Nack {
        /// Certificate minted for the delivery.
        attempt: AttemptCertificate,
        /// Reason for the nack.
        reason: ConsumerNackReason,
    },
    /// Query the current consumer state snapshot.
    State,
}

/// Reply types returned by [`ConsumerActor`] calls.
#[derive(Debug)]
pub enum ConsumerReply {
    /// Pull result.
    Pull(Result<PullDispatchOutcome, FabricConsumerError>),
    /// Ack result — returns the full resolution so callers can distinguish
    /// committed acks from stale no-ops.
    Ack(Result<AckResolution, FabricConsumerError>),
    /// Nack result.
    Nack(Result<NackResolution, FabricConsumerError>),
    /// Current state snapshot.
    State(FabricConsumerState),
}

/// Cast (fire-and-forget) messages for the [`ConsumerActor`].
#[derive(Debug)]
pub enum ConsumerCast {
    /// Pause delivery dispatch.
    Pause,
    /// Resume delivery dispatch after a pause.
    Resume,
}

/// Info (system/out-of-band) messages for the [`ConsumerActor`].
#[derive(Debug)]
pub enum ConsumerInfo {
    /// Periodic heartbeat tick.
    Heartbeat,
}

/// Actor lifecycle state for the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerActorLifecycle {
    /// Actively dispatching deliveries.
    Running,
    /// Dispatch paused; acks/nacks still accepted.
    Paused,
    /// Draining before shutdown.
    Stopping,
}

/// GenServer-hosted consumer delivery engine.
///
/// Wraps a [`FabricConsumer`] in a GenServer mailbox so that:
/// - pull requests are serialized through `handle_call`,
/// - ack/nack resolve obligations synchronously,
/// - pause/resume are fire-and-forget casts, and
/// - heartbeat ticks arrive as info messages.
///
/// The actor is region-owned: spawning it ties its lifetime to the
/// parent region's close-to-quiescence protocol.
#[derive(Debug)]
pub struct ConsumerActor {
    consumer: FabricConsumer,
    lifecycle: ConsumerActorLifecycle,
}

impl ConsumerActor {
    /// Wrap an existing [`FabricConsumer`] in an actor shell.
    #[must_use]
    pub fn new(consumer: FabricConsumer) -> Self {
        Self {
            consumer,
            lifecycle: ConsumerActorLifecycle::Running,
        }
    }

    /// Returns the current actor lifecycle state.
    #[must_use]
    pub fn lifecycle(&self) -> ConsumerActorLifecycle {
        self.lifecycle
    }

    /// Returns a reference to the inner consumer.
    #[must_use]
    pub fn consumer(&self) -> &FabricConsumer {
        &self.consumer
    }

    /// Returns a mutable reference to the inner consumer.
    pub fn consumer_mut(&mut self) -> &mut FabricConsumer {
        &mut self.consumer
    }
}

impl crate::gen_server::GenServer for ConsumerActor {
    type Call = ConsumerCall;
    type Reply = ConsumerReply;
    type Cast = ConsumerCast;
    type Info = ConsumerInfo;

    fn handle_call(
        &mut self,
        _cx: &crate::cx::Cx,
        request: Self::Call,
        reply: crate::gen_server::Reply<Self::Reply>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            match request {
                ConsumerCall::Pull {
                    available_tail,
                    capsule,
                    ticket,
                } => {
                    if self.lifecycle == ConsumerActorLifecycle::Paused {
                        reply.send(ConsumerReply::Pull(Err(
                            FabricConsumerError::ConsumerPaused,
                        )));
                    } else {
                        let result = self.consumer.dispatch_next_pull(
                            available_tail,
                            &capsule,
                            ticket.as_ref(),
                        );
                        reply.send(ConsumerReply::Pull(result));
                    }
                }
                ConsumerCall::Ack { attempt } => {
                    let result = self.consumer.acknowledge_delivery(&attempt);
                    reply.send(ConsumerReply::Ack(result));
                }
                ConsumerCall::Nack { attempt, reason } => {
                    let result = self.consumer.nack_delivery(&attempt, reason);
                    reply.send(ConsumerReply::Nack(result));
                }
                ConsumerCall::State => {
                    reply.send(ConsumerReply::State(self.consumer.state().clone()));
                }
            }
        })
    }

    fn handle_cast(
        &mut self,
        cx: &crate::cx::Cx,
        msg: Self::Cast,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let name = self
                .consumer
                .config()
                .durable_name
                .clone()
                .unwrap_or_else(|| "anonymous".to_owned());
            match msg {
                ConsumerCast::Pause => {
                    if self.lifecycle == ConsumerActorLifecycle::Running {
                        // Delegate to the consumer's own flow-control pause.
                        // If flow_control is disabled on the config, the inner
                        // pause will fail — we still set the actor lifecycle so
                        // the actor-level guard rejects pull calls.
                        let _ = self.consumer.pause();
                        self.lifecycle = ConsumerActorLifecycle::Paused;
                        cx.trace_with_fields(
                            "fabric.consumer_actor.pause",
                            &[("event", "consumer_pause"), ("consumer", name.as_str())],
                        );
                    }
                }
                ConsumerCast::Resume => {
                    if self.lifecycle == ConsumerActorLifecycle::Paused {
                        self.consumer.resume();
                        self.lifecycle = ConsumerActorLifecycle::Running;
                        cx.trace_with_fields(
                            "fabric.consumer_actor.resume",
                            &[("event", "consumer_resume"), ("consumer", name.as_str())],
                        );
                    }
                }
            }
        })
    }

    fn handle_info(
        &mut self,
        cx: &crate::cx::Cx,
        msg: Self::Info,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let name = self
                .consumer
                .config()
                .durable_name
                .clone()
                .unwrap_or_else(|| "anonymous".to_owned());
            match msg {
                ConsumerInfo::Heartbeat => {
                    cx.trace_with_fields(
                        "fabric.consumer_actor.heartbeat",
                        &[("event", "consumer_heartbeat"), ("consumer", name.as_str())],
                    );
                }
            }
        })
    }

    fn on_start(
        &mut self,
        cx: &crate::cx::Cx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let name = self
                .consumer
                .config()
                .durable_name
                .clone()
                .unwrap_or_else(|| "anonymous".to_owned());
            cx.trace_with_fields(
                "fabric.consumer_actor.start",
                &[
                    ("event", "consumer_actor_start"),
                    ("consumer", name.as_str()),
                ],
            );
        })
    }

    fn on_stop(
        &mut self,
        cx: &crate::cx::Cx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            self.lifecycle = ConsumerActorLifecycle::Stopping;
            let name = self
                .consumer
                .config()
                .durable_name
                .clone()
                .unwrap_or_else(|| "anonymous".to_owned());
            cx.trace_with_fields(
                "fabric.consumer_actor.stop",
                &[
                    ("event", "consumer_actor_stop"),
                    ("consumer", name.as_str()),
                ],
            );
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::fabric::{
        CellTemperature, DataCapsule, NodeRole, PlacementPolicy, RepairPolicy, StewardCandidate,
        StorageClass, SubjectPattern,
    };

    fn candidate(name: &str, domain: &str) -> StewardCandidate {
        StewardCandidate::new(NodeId::new(name), domain)
            .with_role(NodeRole::Steward)
            .with_role(NodeRole::RepairWitness)
            .with_storage_class(StorageClass::Durable)
    }

    fn test_cell() -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(7, 11),
            &[
                candidate("node-a", "rack-a"),
                candidate("node-b", "rack-b"),
                candidate("node-c", "rack-c"),
            ],
            &PlacementPolicy {
                cold_stewards: 3,
                warm_stewards: 3,
                hot_stewards: 3,
                ..PlacementPolicy::default()
            },
            RepairPolicy::default(),
            DataCapsule {
                temperature: CellTemperature::Warm,
                retained_message_blocks: 4,
            },
        )
        .expect("cell")
    }

    fn obligation(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn partition_consumers(partition: u16) -> BTreeSet<String> {
        [
            format!("consumer-{partition}-a"),
            format!("consumer-{partition}-b"),
        ]
        .into_iter()
        .collect()
    }

    fn partition_assignment(
        partition: u16,
        selector: CursorPartitionSelector,
    ) -> CursorPartitionAssignment {
        CursorPartitionAssignment {
            partition,
            leader: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            selector,
            consumers: partition_consumers(partition),
        }
    }

    fn delegate_partition_to_holder(
        cursor: &mut FabricConsumerCursor,
        partition: u16,
        holder: CursorLeaseHolder,
        transfer_obligation: ObligationId,
    ) -> ContestedTransferResolution {
        if cursor.partition_assignment(partition).is_none() {
            cursor
                .assign_partition(partition_assignment(
                    partition,
                    CursorPartitionSelector::ConsumerGroup(format!("group-{partition}")),
                ))
                .expect("assign partition");
        }

        cursor
            .resolve_contested_transfer(&[CursorTransferProposal::delegated_partition(
                holder,
                partition,
                cursor.current_lease().lease_generation,
                transfer_obligation,
            )])
            .expect("delegate partition")
    }

    #[test]
    fn cursor_lease_starts_from_the_control_capsule() {
        let cell = test_cell();
        let cursor = FabricConsumerCursor::new(&cell).expect("cursor");

        assert_eq!(cursor.current_lease().cell_id, cell.cell_id);
        assert_eq!(cursor.current_lease().epoch, cell.epoch);
        assert_eq!(
            cursor.current_lease().holder,
            CursorLeaseHolder::Steward(NodeId::new("node-a"))
        );
        assert_eq!(
            cursor.current_lease().lease_generation,
            cell.control_capsule.sequencer_lease_generation
        );
    }

    #[test]
    fn delivery_attempts_commit_against_the_current_lease_holder() {
        let cell = test_cell();
        let cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(10, 12).expect("window");
        let attempt = cursor
            .issue_attempt(CursorDeliveryMode::Push { window }, 1, obligation(10))
            .expect("attempt");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        assert_eq!(
            cursor.plan_delivery(attempt.delivery_mode, &capsule, None),
            Ok(DeliveryPlan::CurrentSteward(NodeId::new("node-a")))
        );
        assert_eq!(
            cursor.acknowledge(&attempt),
            Ok(AckResolution::Committed {
                obligation_id: obligation(10),
                against: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
    }

    #[test]
    fn pull_demand_class_attempts_preserve_the_named_request() {
        let cell = test_cell();
        let cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Pull(CursorRequest::DemandClass(ConsumerDemandClass::Tail)),
                2,
                obligation(11),
            )
            .expect("attempt");

        assert_eq!(
            attempt.delivery_mode,
            CursorDeliveryMode::Pull(CursorRequest::DemandClass(ConsumerDemandClass::Tail))
        );
        assert_eq!(
            cursor.plan_delivery(attempt.delivery_mode, &RecoverableCapsule::default(), None),
            Ok(DeliveryPlan::CurrentSteward(NodeId::new("node-a")))
        );
    }

    #[test]
    fn failover_bumps_generation_and_turns_old_acks_into_stale_noops() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(20, 20).expect("window");
        let first_attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Pull(CursorRequest::Window(window)),
                1,
                obligation(12),
            )
            .expect("attempt");

        cursor.failover(NodeId::new("node-b")).expect("failover");
        assert_eq!(
            cursor.acknowledge(&first_attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: obligation(12),
                current_generation: cell.control_capsule.sequencer_lease_generation + 1,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-b")),
            })
        );

        let second_attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Pull(CursorRequest::Sequence(20)),
                2,
                obligation(13),
            )
            .expect("attempt");
        assert_eq!(
            cursor.acknowledge(&second_attempt),
            Ok(AckResolution::Committed {
                obligation_id: obligation(13),
                against: CursorLeaseHolder::Steward(NodeId::new("node-b")),
            })
        );
    }

    #[test]
    fn relay_delivery_requires_a_matching_read_ticket() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(30, 35).expect("window");

        let resolution = delegate_partition_to_holder(
            &mut cursor,
            7,
            CursorLeaseHolder::Relay(NodeId::new("relay-1")),
            obligation(14),
        );
        assert!(matches!(
            resolution,
            ContestedTransferResolution::Accepted { .. }
        ));

        let ticket = cursor
            .grant_read_ticket(
                NodeId::new("relay-1"),
                window,
                4,
                CacheabilityRule::Private { max_age_ticks: 2 },
            )
            .expect("ticket");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("relay-1"), window);

        assert_eq!(
            ticket.cursor_lease_ref.lease_generation,
            cursor.current_lease().lease_generation
        );
        assert_eq!(ticket.segment_window, window);
        assert_eq!(
            ticket.cacheability_rules,
            CacheabilityRule::Private { max_age_ticks: 2 }
        );
        assert_eq!(ticket.expiry.issued_at_tick, 0);
        assert_eq!(ticket.expiry.not_after_tick, 4);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Ok(DeliveryPlan::LeasedRelay {
                relay: NodeId::new("relay-1"),
                ticket,
            })
        );
    }

    #[test]
    fn relay_delivery_rejects_missing_ticket_when_authority_is_delegated() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(36, 38).expect("window");
        let relay = NodeId::new("relay-2");

        delegate_partition_to_holder(
            &mut cursor,
            8,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(15),
        );

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, None),
            Err(ConsumerCursorError::MissingReadDelegationTicket { relay })
        );
    }

    #[test]
    fn read_delegation_ticket_expiry_is_enforced() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(46, 49).expect("window");
        let relay = NodeId::new("relay-expiring");

        delegate_partition_to_holder(
            &mut cursor,
            9,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(16),
        );

        let ticket = cursor
            .grant_read_ticket(relay.clone(), window, 1, CacheabilityRule::NoCache)
            .expect("ticket");
        cursor.advance_ticket_clock(2);

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Err(ConsumerCursorError::ExpiredReadDelegationTicket {
                relay,
                expired_at_tick: 1,
                current_tick: 2,
            })
        );
    }

    #[test]
    fn read_delegation_ticket_revocation_is_enforced() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(50, 52).expect("window");
        let relay = NodeId::new("relay-revoked");

        delegate_partition_to_holder(
            &mut cursor,
            10,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(17),
        );

        let ticket = cursor
            .grant_read_ticket(
                relay.clone(),
                window,
                5,
                CacheabilityRule::Shared { max_age_ticks: 1 },
            )
            .expect("ticket");
        cursor.revoke_read_ticket(ticket.revocation_handle, ticket.expiry.not_after_tick);

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Err(ConsumerCursorError::RevokedReadDelegationTicket {
                relay,
                revocation_handle: ticket.revocation_handle,
            })
        );
    }

    #[test]
    fn prune_expired_revocations_removes_stale_entries() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(50, 55).expect("window");
        let relay = NodeId::new("relay-prune");

        delegate_partition_to_holder(
            &mut cursor,
            10,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(30),
        );

        let ticket = cursor
            .grant_read_ticket(
                relay,
                window,
                5, // TTL = 5 ticks
                CacheabilityRule::Private { max_age_ticks: 1 },
            )
            .expect("ticket");

        // Revoke the ticket (not_after_tick = issued_at + 5 = 0 + 5 = 5).
        cursor.revoke_read_ticket(ticket.revocation_handle, ticket.expiry.not_after_tick);
        assert_eq!(cursor.revoked_tickets.len(), 1);

        // Advance clock past the ticket's expiry.
        cursor.ticket_clock = 6;
        cursor.prune_expired_revocations();

        // The revocation entry should be pruned since the ticket has expired.
        assert_eq!(
            cursor.revoked_tickets.len(),
            0,
            "expired revocation entries must be pruned"
        );
    }

    #[test]
    fn stale_epoch_read_delegation_ticket_is_rejected() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(60, 63).expect("window");
        let relay = NodeId::new("relay-stale");

        delegate_partition_to_holder(
            &mut cursor,
            11,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(18),
        );

        let mut ticket = cursor
            .grant_read_ticket(relay.clone(), window, 5, CacheabilityRule::NoCache)
            .expect("ticket");
        ticket.epoch = CellEpoch::new(6, 99);

        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        assert_eq!(
            cursor.plan_delivery(CursorDeliveryMode::Push { window }, &capsule, Some(&ticket)),
            Err(ConsumerCursorError::StaleReadDelegationEpoch {
                relay,
                ticket_cell: cell.cell_id,
                ticket_epoch: CellEpoch::new(6, 99),
                current_cell: cell.cell_id,
                current_epoch: cell.epoch,
            })
        );
    }

    #[test]
    fn partition_assignments_preserve_selector_strategies_and_consumers() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let by_group = partition_assignment(
            20,
            CursorPartitionSelector::ConsumerGroup("orders-tail".to_owned()),
        );
        let by_range = partition_assignment(
            21,
            CursorPartitionSelector::SubjectSubRange {
                start: "orders.a".to_owned(),
                end: "orders.m".to_owned(),
            },
        );
        let by_bucket = partition_assignment(
            22,
            CursorPartitionSelector::HashBucket {
                bucket: 1,
                buckets: 4,
            },
        );

        cursor
            .assign_partition(by_group.clone())
            .expect("assign group partition");
        cursor
            .assign_partition(by_range.clone())
            .expect("assign range partition");
        cursor
            .assign_partition(by_bucket.clone())
            .expect("assign bucket partition");

        assert_eq!(cursor.partition_assignment(20), Some(&by_group));
        assert_eq!(cursor.partition_assignment(21), Some(&by_range));
        assert_eq!(cursor.partition_assignment(22), Some(&by_bucket));
        assert_eq!(
            cursor
                .partition_assignment(21)
                .map(|entry| entry.consumers.len()),
            Some(2)
        );
    }

    #[test]
    fn delegated_attempts_expose_partition_lease_metadata() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay = NodeId::new("relay-partition");

        let resolution = delegate_partition_to_holder(
            &mut cursor,
            23,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(181),
        );
        assert!(matches!(
            resolution,
            ContestedTransferResolution::Accepted { .. }
        ));

        let attempt = cursor
            .issue_attempt(
                CursorDeliveryMode::Push {
                    window: SequenceWindow::new(64, 66).expect("window"),
                },
                1,
                obligation(182),
            )
            .expect("attempt");

        assert_eq!(
            attempt.cursor_partition_lease(),
            Some(CursorPartitionLease {
                partition: 23,
                leader: CursorLeaseHolder::Relay(relay),
                lease_generation: cursor.current_lease().lease_generation,
            })
        );
    }

    #[test]
    fn relay_transfer_requires_partition_scope_and_registered_partition() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay = NodeId::new("relay-invalid");
        let generation = cursor.current_lease().lease_generation;

        assert_eq!(
            cursor.resolve_contested_transfer(&[CursorTransferProposal::control_capsule(
                CursorLeaseHolder::Relay(relay.clone()),
                generation,
                obligation(183),
            )]),
            Err(ConsumerCursorError::RelayTransferRequiresPartition {
                relay: relay.clone()
            })
        );
        assert_eq!(
            cursor.resolve_contested_transfer(&[CursorTransferProposal::delegated_partition(
                CursorLeaseHolder::Relay(relay),
                99,
                generation,
                obligation(184),
            )]),
            Err(ConsumerCursorError::UnknownCursorPartition { partition: 99 })
        );
    }

    #[test]
    fn partition_checkpoint_reporting_records_summary_for_active_partition() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay = NodeId::new("relay-summary");

        delegate_partition_to_holder(
            &mut cursor,
            24,
            CursorLeaseHolder::Relay(relay.clone()),
            obligation(185),
        );

        let summary = cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 24,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 120,
                delivered_through: 127,
                pending_count: 3,
                consumer_count: 2,
            })
            .expect("checkpoint")
            .clone();

        assert_eq!(
            summary,
            CursorPartitionSummary {
                partition: 24,
                selector: CursorPartitionSelector::ConsumerGroup("group-24".to_owned()),
                leader: CursorLeaseHolder::Relay(relay),
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 120,
                delivered_through: 127,
                pending_count: 3,
                consumer_count: 2,
            }
        );
        assert_eq!(cursor.partition_summary(24), Some(&summary));
    }

    #[test]
    fn partition_checkpoint_reporting_requires_matching_scope_and_generation() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");

        assert_eq!(
            cursor.report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 25,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 0,
                delivered_through: 0,
                pending_count: 0,
                consumer_count: 2,
            }),
            Err(
                ConsumerCursorError::PartitionCheckpointRequiresDelegatedLease {
                    partition: 25,
                    current_scope: CursorLeaseScope::ControlCapsule,
                }
            )
        );

        let relay = NodeId::new("relay-fenced");
        delegate_partition_to_holder(
            &mut cursor,
            25,
            CursorLeaseHolder::Relay(relay),
            obligation(186),
        );

        let current_generation = cursor.current_lease().lease_generation;
        assert_eq!(
            cursor.report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 25,
                lease_generation: current_generation.saturating_sub(1),
                ack_floor: 0,
                delivered_through: 0,
                pending_count: 0,
                consumer_count: 2,
            }),
            Err(ConsumerCursorError::StaleCursorPartitionCheckpoint {
                partition: 25,
                report_generation: current_generation.saturating_sub(1),
                current_generation,
            })
        );
        assert_eq!(
            cursor.report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 25,
                lease_generation: current_generation,
                ack_floor: 0,
                delivered_through: 0,
                pending_count: 0,
                consumer_count: 1,
            }),
            Err(
                ConsumerCursorError::PartitionCheckpointConsumerCountMismatch {
                    partition: 25,
                    reported_consumer_count: 1,
                    assigned_consumer_count: 2,
                }
            )
        );
    }

    #[test]
    fn replacing_partition_assignment_invalidates_stale_summary() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");

        delegate_partition_to_holder(
            &mut cursor,
            26,
            CursorLeaseHolder::Relay(NodeId::new("relay-a")),
            obligation(187),
        );
        cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 26,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 200,
                delivered_through: 208,
                pending_count: 4,
                consumer_count: 2,
            })
            .expect("checkpoint");
        assert!(cursor.partition_summary(26).is_some());

        cursor
            .assign_partition(partition_assignment(
                26,
                CursorPartitionSelector::SubjectSubRange {
                    start: "orders.n".to_owned(),
                    end: "orders.z".to_owned(),
                },
            ))
            .expect("replace assignment");

        assert_eq!(
            cursor
                .partition_assignment(26)
                .map(|assignment| &assignment.selector),
            Some(&CursorPartitionSelector::SubjectSubRange {
                start: "orders.n".to_owned(),
                end: "orders.z".to_owned(),
            })
        );
        assert_eq!(cursor.partition_summary(26), None);
    }

    #[test]
    fn partition_rebalance_updates_assignment_and_invalidates_stale_summary() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let relay_a = NodeId::new("relay-a");
        let relay_b = NodeId::new("relay-b");

        delegate_partition_to_holder(
            &mut cursor,
            26,
            CursorLeaseHolder::Relay(relay_a.clone()),
            obligation(187),
        );
        cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 26,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 200,
                delivered_through: 208,
                pending_count: 4,
                consumer_count: 2,
            })
            .expect("checkpoint");

        let stale_generation = cursor.current_lease().lease_generation.saturating_sub(1);
        assert_eq!(
            cursor
                .rebalance_partition(
                    26,
                    CursorLeaseHolder::Relay(relay_b.clone()),
                    stale_generation,
                    obligation(188),
                )
                .expect("stale rebalance result"),
            ContestedTransferResolution::StaleNoOp {
                current_lease: cursor.current_lease().clone(),
            }
        );

        let accepted = cursor
            .rebalance_partition(
                26,
                CursorLeaseHolder::Relay(relay_b.clone()),
                cursor.current_lease().lease_generation,
                obligation(189),
            )
            .expect("rebalance");
        assert!(matches!(
            accepted,
            ContestedTransferResolution::Accepted { .. }
        ));
        assert_eq!(
            cursor
                .partition_assignment(26)
                .map(|assignment| &assignment.leader),
            Some(&CursorLeaseHolder::Relay(relay_b.clone()))
        );
        assert_eq!(cursor.partition_summary(26), None);
        let checkpoint = cursor
            .report_partition_checkpoint(CursorPartitionCheckpoint {
                partition: 26,
                lease_generation: cursor.current_lease().lease_generation,
                ack_floor: 209,
                delivered_through: 214,
                pending_count: 1,
                consumer_count: 2,
            })
            .expect("post-rebalance checkpoint");
        assert_eq!(checkpoint.leader, CursorLeaseHolder::Relay(relay_b));
    }

    #[test]
    fn reconstruction_is_used_when_no_single_peer_covers_the_full_window() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let window = SequenceWindow::new(40, 45).expect("window");

        cursor
            .failover(NodeId::new("node-b"))
            .expect("make node-b current");

        let capsule = RecoverableCapsule::default()
            .with_window(
                NodeId::new("node-a"),
                SequenceWindow::new(40, 42).expect("left window"),
            )
            .with_window(
                NodeId::new("node-c"),
                SequenceWindow::new(43, 45).expect("right window"),
            );

        assert_eq!(
            cursor.plan_delivery(
                CursorDeliveryMode::Pull(CursorRequest::Window(window)),
                &capsule,
                None
            ),
            Ok(DeliveryPlan::Reconstructed {
                contributors: vec![NodeId::new("node-a"), NodeId::new("node-c")],
            })
        );
    }

    #[test]
    fn contested_transfer_prefers_steward_order_and_filters_stale_proposals() {
        let cell = test_cell();
        let mut cursor = FabricConsumerCursor::new(&cell).expect("cursor");
        let current_generation = cursor.current_lease().lease_generation;

        let resolution = cursor
            .resolve_contested_transfer(&[
                CursorTransferProposal::control_capsule(
                    CursorLeaseHolder::Steward(NodeId::new("node-c")),
                    current_generation,
                    obligation(20),
                ),
                CursorTransferProposal::control_capsule(
                    CursorLeaseHolder::Steward(NodeId::new("node-b")),
                    current_generation,
                    obligation(21),
                ),
                CursorTransferProposal::delegated_partition(
                    CursorLeaseHolder::Relay(NodeId::new("relay-2")),
                    27,
                    current_generation.saturating_sub(1),
                    obligation(22),
                ),
            ])
            .expect("resolve contested transfer");

        assert_eq!(
            resolution,
            ContestedTransferResolution::Accepted {
                new_lease: cursor.current_lease().clone(),
                winning_obligation: obligation(21),
            }
        );
        assert_eq!(
            cursor.current_lease().holder,
            CursorLeaseHolder::Steward(NodeId::new("node-b"))
        );
        assert_eq!(
            cursor.current_lease().lease_generation,
            current_generation + 1
        );
    }

    #[test]
    fn fabric_consumer_creation_preserves_config_and_starts_clean() {
        let cell = test_cell();
        let config = FabricConsumerConfig {
            durable_name: Some("orders-durable".to_owned()),
            filter_subject: Some(SubjectPattern::parse("orders.*").expect("pattern")),
            flow_control: true,
            heartbeat: Some(std::time::Duration::from_secs(5)),
            idle_heartbeat: Some(std::time::Duration::from_secs(15)),
            ..FabricConsumerConfig::default()
        };

        let consumer = FabricConsumer::new(&cell, config.clone()).expect("consumer");
        assert_eq!(consumer.config(), &config);
        assert_eq!(consumer.policy().mode, ConsumerDispatchMode::Push);
        assert!(!consumer.policy().paused);
        assert_eq!(consumer.state().delivered_count, 0);
        assert_eq!(consumer.state().pending_count, 0);
        assert_eq!(consumer.state().ack_floor, 0);
        assert_eq!(consumer.waiting_pull_request_count(), 0);
        assert_eq!(
            consumer.current_lease().holder,
            CursorLeaseHolder::Steward(NodeId::new("node-a"))
        );
    }

    #[test]
    fn fabric_consumer_config_rejects_zero_heartbeat_values() {
        let heartbeat = FabricConsumerConfig {
            heartbeat: Some(Duration::ZERO),
            ..FabricConsumerConfig::default()
        };
        assert_eq!(
            heartbeat.validate(),
            Err(FabricConsumerError::InvalidHeartbeat { field: "heartbeat" })
        );

        let idle_heartbeat = FabricConsumerConfig {
            idle_heartbeat: Some(Duration::ZERO),
            ..FabricConsumerConfig::default()
        };
        assert_eq!(
            idle_heartbeat.validate(),
            Err(FabricConsumerError::InvalidHeartbeat {
                field: "idle_heartbeat",
            })
        );
    }

    #[test]
    fn fabric_consumer_mode_switching_clears_waiting_pull_requests() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(2, ConsumerDemandClass::CatchUp).expect("pull request"),
            )
            .expect("queue pull request");
        assert_eq!(consumer.waiting_pull_request_count(), 1);

        consumer.switch_mode(ConsumerDispatchMode::Push);
        assert_eq!(consumer.policy().mode, ConsumerDispatchMode::Push);
        assert_eq!(consumer.waiting_pull_request_count(), 0);
    }

    #[test]
    fn fabric_consumer_pull_queue_respects_max_waiting() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 1,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(1, ConsumerDemandClass::CatchUp).expect("first request"),
            )
            .expect("queue first");

        assert_eq!(
            consumer.queue_pull_request(
                PullRequest::new(1, ConsumerDemandClass::Tail).expect("second request")
            ),
            Err(FabricConsumerError::MaxWaitingExceeded { limit: 1 })
        );
    }

    #[test]
    fn fabric_consumer_stable_kernel_replaces_priority_overflow_without_audit_log() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 1,
                overflow_policy: ConsumerOverflowPolicy::ReplaceLowestPriority,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");

        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Tail).expect("tail"))
            .expect("replace replay with tail");

        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 20).expect("window"),
        );
        let delivery = match consumer
            .dispatch_next_pull(20, &capsule, None)
            .expect("dispatch tail")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("tail request should dispatch"),
        };

        assert!(matches!(
            delivery.request,
            ScheduledConsumerRequest::Pull(PullRequest {
                demand_class: ConsumerDemandClass::Tail,
                ..
            })
        ));
        assert!(consumer.decision_log().is_empty());
    }

    #[test]
    fn fabric_consumer_priority_groups_dispatch_tail_before_replay() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 20).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");

        let first = match consumer
            .dispatch_next_pull(20, &capsule, None)
            .expect("dispatch first")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("tail request should schedule first"),
        };
        assert!(matches!(
            &first.request,
            ScheduledConsumerRequest::Pull(request)
                if request.demand_class == ConsumerDemandClass::Tail
        ));
        assert_eq!(
            first.window,
            SequenceWindow::new(19, 20).expect("tail window")
        );

        let second = match consumer
            .dispatch_next_pull(20, &capsule, None)
            .expect("dispatch second")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("replay request should schedule second"),
        };
        assert!(matches!(
            &second.request,
            ScheduledConsumerRequest::Pull(request)
                if request.demand_class == ConsumerDemandClass::Replay
        ));
        assert_eq!(
            second.window,
            SequenceWindow::new(1, 2).expect("replay window")
        );
    }

    #[test]
    fn fabric_consumer_audit_backed_overflow_replaces_replay_with_tail_and_records_evidence() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 1,
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                overflow_policy: ConsumerOverflowPolicy::ReplaceLowestPriority,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Replay).expect("replay"))
            .expect("queue replay");
        consumer
            .queue_pull_request(PullRequest::new(1, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail replacement");

        assert_eq!(consumer.waiting_pull_request_count(), 1);
        assert_eq!(consumer.decision_log().len(), 1);
        let overflow = &consumer.decision_log()[0];
        assert_eq!(overflow.kind, ConsumerDecisionKind::Overflow);
        assert_eq!(overflow.action_name, "replace_low_priority");
        assert_eq!(overflow.demand_class, Some(ConsumerDemandClass::Tail));
    }

    #[test]
    fn fabric_consumer_pull_dispatches_audited_pinned_client_leased_delivery() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let relay = NodeId::new("relay-1");
        let window = SequenceWindow::new(1, 2).expect("window");
        let capsule = RecoverableCapsule::default().with_window(relay.clone(), window);

        let transfer = delegate_partition_to_holder(
            &mut consumer.cursor,
            28,
            CursorLeaseHolder::Relay(relay.clone()),
            ObligationId::new_for_test(88, 0),
        );
        assert!(matches!(
            transfer,
            ContestedTransferResolution::Accepted { .. }
        ));

        let ticket = consumer
            .cursor
            .grant_read_ticket(
                relay.clone(),
                window,
                8,
                CacheabilityRule::Private { max_age_ticks: 4 },
            )
            .expect("ticket");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(2, ConsumerDemandClass::CatchUp)
                    .expect("pull request")
                    .with_pinned_client(relay.clone()),
            )
            .expect("queue pull");

        let delivery = match consumer
            .dispatch_next_pull(2, &capsule, Some(&ticket))
            .expect("dispatch pinned")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("pinned request should schedule"),
        };
        assert!(matches!(
            &delivery.plan,
            DeliveryPlan::LeasedRelay { relay: chosen, .. } if chosen == &relay
        ));
        let decision = consumer.decision_log().last().expect("decision record");
        assert_eq!(decision.kind, ConsumerDecisionKind::PullScheduling);
        assert_eq!(decision.action_name, "leased_relay");
        assert_eq!(decision.pinned_client.as_ref(), Some(&relay));
        assert_eq!(decision.obligation_id, Some(delivery.attempt.obligation_id));
    }

    #[test]
    fn fabric_consumer_rejects_pinned_client_ticket_mismatch() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let pinned = NodeId::new("relay-pinned");
        let wrong_relay = NodeId::new("relay-wrong");
        let window = SequenceWindow::new(1, 1).expect("window");
        let capsule = RecoverableCapsule::default().with_window(wrong_relay.clone(), window);

        let transfer = delegate_partition_to_holder(
            &mut consumer.cursor,
            29,
            CursorLeaseHolder::Relay(wrong_relay.clone()),
            ObligationId::new_for_test(89, 0),
        );
        assert!(matches!(
            transfer,
            ContestedTransferResolution::Accepted { .. }
        ));

        let wrong_ticket = consumer
            .cursor
            .grant_read_ticket(
                wrong_relay.clone(),
                window,
                8,
                CacheabilityRule::Private { max_age_ticks: 4 },
            )
            .expect("ticket");

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(1, ConsumerDemandClass::CatchUp)
                    .expect("pull request")
                    .with_pinned_client(pinned.clone()),
            )
            .expect("queue pull");

        assert_eq!(
            consumer.dispatch_next_pull(1, &capsule, Some(&wrong_ticket)),
            Err(FabricConsumerError::PinnedClientTicketMismatch {
                pinned_client: pinned,
                ticket_relay: wrong_relay,
            })
        );
        assert_eq!(consumer.waiting_pull_request_count(), 1);
    }

    #[test]
    fn fabric_consumer_keeps_pull_request_queued_when_dispatch_is_paused() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                flow_control: true,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 4).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::CatchUp).expect("pull"))
            .expect("queue pull");
        consumer.pause().expect("pause");

        assert_eq!(
            consumer.dispatch_next_pull(4, &capsule, None),
            Err(FabricConsumerError::ConsumerPaused)
        );
        assert_eq!(consumer.waiting_pull_request_count(), 1);
    }

    #[test]
    fn fabric_consumer_pull_dispatches_catchup_then_tail_windows() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 12).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(
                PullRequest::new(3, ConsumerDemandClass::CatchUp).expect("catchup request"),
            )
            .expect("queue catchup");

        let first_outcome = consumer
            .dispatch_next_pull(12, &capsule, None)
            .expect("dispatch catchup");
        let first = if let PullDispatchOutcome::Scheduled(delivery) = first_outcome {
            *delivery
        } else {
            assert!(false, "catchup request should schedule");
            return;
        };
        assert_eq!(first.window, SequenceWindow::new(1, 3).expect("window"));
        assert_eq!(consumer.state().pending_count, 3);
        assert_eq!(
            consumer.acknowledge_delivery(&first.attempt),
            Ok(AckResolution::Committed {
                obligation_id: first.attempt.obligation_id,
                against: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
        assert_eq!(consumer.state().pending_count, 0);
        assert_eq!(consumer.state().ack_floor, 3);

        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");
        let tail_outcome = consumer
            .dispatch_next_pull(12, &capsule, None)
            .expect("dispatch tail");
        let tail = if let PullDispatchOutcome::Scheduled(delivery) = tail_outcome {
            *delivery
        } else {
            assert!(false, "tail request should schedule");
            return;
        };
        assert_eq!(tail.window, SequenceWindow::new(11, 12).expect("window"));
    }

    #[test]
    fn fabric_consumer_tail_waits_when_fully_caught_up() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 10).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(10, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue catchup");
        let catchup = match consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("dispatch")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("catchup request should schedule"),
        };
        consumer
            .acknowledge_delivery(&catchup.attempt)
            .expect("ack catchup");
        assert_eq!(consumer.state().ack_floor, 10);

        consumer
            .queue_pull_request(PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");
        let outcome = consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("tail should wait for fresh data");
        assert!(matches!(outcome, PullDispatchOutcome::Waiting(_)));
        assert_eq!(consumer.waiting_pull_request_count(), 1);
    }

    #[test]
    fn fabric_consumer_tail_clamps_to_unacked_suffix() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 10).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);
        consumer
            .queue_pull_request(PullRequest::new(9, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue catchup");
        let catchup = match consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("dispatch")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("catchup request should schedule"),
        };
        consumer
            .acknowledge_delivery(&catchup.attempt)
            .expect("ack catchup");
        assert_eq!(consumer.state().ack_floor, 9);

        consumer
            .queue_pull_request(PullRequest::new(3, ConsumerDemandClass::Tail).expect("tail"))
            .expect("queue tail");
        let tail = match consumer
            .dispatch_next_pull(10, &capsule, None)
            .expect("dispatch tail")
        {
            PullDispatchOutcome::Scheduled(delivery) => *delivery,
            PullDispatchOutcome::Waiting(_) => panic!("tail should schedule newest unacked suffix"),
        };
        assert_eq!(tail.window, SequenceWindow::new(10, 10).expect("suffix"));
    }

    #[test]
    fn fabric_consumer_pause_and_resume_gate_dispatch() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                flow_control: true,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let window = SequenceWindow::new(1, 1).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        consumer.pause().expect("pause");
        assert_eq!(
            consumer.dispatch_push(window, &capsule, None),
            Err(FabricConsumerError::ConsumerPaused)
        );

        consumer.resume();
        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch after resume");
        assert_eq!(delivery.window, window);
    }

    #[test]
    fn fabric_consumer_max_ack_pending_blocks_until_ack_commit() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_ack_pending: 2,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let first_window = SequenceWindow::new(1, 2).expect("window");
        let second_window = SequenceWindow::new(3, 3).expect("window");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 3).expect("capsule"),
        );

        let first = consumer
            .dispatch_push(first_window, &capsule, None)
            .expect("first dispatch");
        assert_eq!(consumer.state().pending_count, 2);
        assert_eq!(
            consumer.dispatch_push(second_window, &capsule, None),
            Err(FabricConsumerError::MaxAckPendingExceeded {
                limit: 2,
                pending: 2,
            })
        );

        assert!(matches!(
            consumer.acknowledge_delivery(&first.attempt),
            Ok(AckResolution::Committed { .. })
        ));
        assert_eq!(consumer.state().pending_count, 0);

        let second = consumer
            .dispatch_push(second_window, &capsule, None)
            .expect("second dispatch");
        assert_eq!(second.window, second_window);
    }

    #[test]
    fn fabric_consumer_ack_commits_obligation_backed_state() {
        let cell = test_cell();
        let owner = FabricConsumerOwner {
            holder: TaskId::new_for_test(41, 0),
            region: RegionId::new_for_test(7, 0),
        };
        let mut consumer = FabricConsumer::new_owned(&cell, FabricConsumerConfig::default(), owner)
            .expect("consumer");
        let window = SequenceWindow::new(5, 6).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        let reserved = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("reserved record");
        assert_eq!(reserved.kind, ObligationKind::Ack);
        assert_eq!(reserved.holder, owner.holder);
        assert_eq!(reserved.region, owner.region);
        assert_eq!(consumer.obligation_stats().pending, 1);
        assert_eq!(consumer.obligation_stats().total_acquired, 1);

        assert!(matches!(
            consumer.acknowledge_delivery(&delivery.attempt),
            Ok(AckResolution::Committed { .. })
        ));

        let committed = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("committed record");
        assert_eq!(committed.state, crate::record::ObligationState::Committed);
        assert_eq!(consumer.obligation_stats().pending, 0);
        assert_eq!(consumer.obligation_stats().total_committed, 1);
    }

    #[test]
    fn fabric_consumer_nack_aborts_obligation_and_old_ack_is_stale() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let window = SequenceWindow::new(7, 7).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        assert_eq!(
            consumer.nack_delivery(&delivery.attempt, ConsumerNackReason::Explicit),
            Ok(NackResolution::Aborted {
                obligation_id: delivery.attempt.obligation_id,
                window,
                reason: ConsumerNackReason::Explicit,
            })
        );

        let record = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("aborted record");
        assert_eq!(record.state, crate::record::ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Explicit));
        assert_eq!(consumer.obligation_stats().total_aborted, 1);
        assert_eq!(
            consumer.acknowledge_delivery(&delivery.attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: delivery.attempt.obligation_id,
                current_generation: consumer.current_lease().lease_generation,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
    }

    #[test]
    fn fabric_consumer_redelivery_mints_new_obligation_and_supersedes_old_attempt() {
        let cell = test_cell();
        let config = FabricConsumerConfig {
            max_deliver: 3,
            ..FabricConsumerConfig::default()
        };
        let mut consumer = FabricConsumer::new(&cell, config).expect("consumer");
        let window = SequenceWindow::new(8, 9).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let first = consumer
            .dispatch_push(window, &capsule, None)
            .expect("first dispatch");
        let redelivery = consumer
            .redeliver_delivery(&first.attempt, &capsule, None)
            .expect("redelivery");

        assert_ne!(
            first.attempt.obligation_id,
            redelivery.attempt.obligation_id
        );
        assert!(consumer.decision_log().is_empty());
        assert_eq!(
            redelivery.attempt.supersedes_obligation_id,
            Some(first.attempt.obligation_id)
        );
        let first_record = consumer
            .ledger
            .get(first.attempt.obligation_id)
            .expect("first record");
        assert_eq!(first_record.state, crate::record::ObligationState::Aborted);
        assert_eq!(
            first_record.abort_reason,
            Some(ObligationAbortReason::Explicit)
        );
        assert_eq!(
            consumer.acknowledge_delivery(&first.attempt),
            Ok(AckResolution::StaleNoOp {
                obligation_id: first.attempt.obligation_id,
                current_generation: consumer.current_lease().lease_generation,
                current_holder: CursorLeaseHolder::Steward(NodeId::new("node-a")),
            })
        );
        assert!(matches!(
            consumer.acknowledge_delivery(&redelivery.attempt),
            Ok(AckResolution::Committed { obligation_id, .. })
                if obligation_id == redelivery.attempt.obligation_id
        ));
        let stats = consumer.obligation_stats();
        assert_eq!(stats.total_acquired, 2);
        assert_eq!(stats.total_aborted, 1);
        assert_eq!(stats.total_committed, 1);
        assert_eq!(stats.pending, 0);
    }

    #[test]
    fn fabric_consumer_audit_backed_redelivery_requires_dead_letter_at_retry_limit() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                max_deliver: 1,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let window = SequenceWindow::new(12, 12).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let first = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        assert_eq!(
            consumer.redeliver_delivery(&first.attempt, &capsule, None),
            Err(FabricConsumerError::RedeliveryRequiresDeadLetter {
                obligation_id: first.attempt.obligation_id,
                delivery_attempt: 2,
            })
        );
        let decision = consumer.decision_log().last().expect("redelivery decision");
        assert_eq!(decision.kind, ConsumerDecisionKind::Redelivery);
        assert_eq!(decision.action_name, "dead_letter");
        assert_eq!(decision.obligation_id, Some(first.attempt.obligation_id));
    }

    #[test]
    fn fabric_consumer_audit_backed_redelivery_defers_under_pending_pressure() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                adaptive_kernel: AdaptiveConsumerKernel::AuditBacked,
                max_deliver: 3,
                max_ack_pending: 1,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        let window = SequenceWindow::new(13, 13).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let first = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        assert_eq!(
            consumer.redeliver_delivery(&first.attempt, &capsule, None),
            Err(FabricConsumerError::RedeliveryDeferred {
                obligation_id: first.attempt.obligation_id,
                delivery_attempt: 2,
            })
        );
        let decision = consumer.decision_log().last().expect("redelivery decision");
        assert_eq!(decision.kind, ConsumerDecisionKind::Redelivery);
        assert_eq!(decision.action_name, "delay");
        assert_eq!(decision.obligation_id, Some(first.attempt.obligation_id));
    }

    #[test]
    fn fabric_consumer_dead_letter_records_reason_and_aborts_obligation() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let window = SequenceWindow::new(10, 10).expect("window");
        let capsule = RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

        let delivery = consumer
            .dispatch_push(window, &capsule, None)
            .expect("dispatch");
        let transfer = consumer
            .dead_letter_delivery(&delivery.attempt, "poison payload")
            .expect("dead letter");

        assert_eq!(transfer.obligation_id, delivery.attempt.obligation_id);
        assert_eq!(transfer.window, window);
        assert_eq!(transfer.reason, "poison payload");
        let record = consumer
            .ledger
            .get(delivery.attempt.obligation_id)
            .expect("dead-letter record");
        assert_eq!(record.state, crate::record::ObligationState::Aborted);
        assert_eq!(record.abort_reason, Some(ObligationAbortReason::Error));
        assert_eq!(consumer.obligation_stats().pending, 0);
        assert_eq!(consumer.obligation_stats().total_aborted, 1);
    }

    #[test]
    fn pull_request_expiry_measured_from_original_enqueue_not_re_enqueue() {
        let cell = test_cell();
        let mut consumer = FabricConsumer::new(
            &cell,
            FabricConsumerConfig {
                max_waiting: 4,
                ..FabricConsumerConfig::default()
            },
        )
        .expect("consumer");
        consumer.switch_mode(ConsumerDispatchMode::Pull);

        // Enqueue a pull request that expires in 10 ticks.
        let request = PullRequest::new(1, ConsumerDemandClass::Tail).expect("request");
        let request = request.with_expires(10);
        consumer.queue_pull_request(request).expect("enqueue");

        // Advance clock 5 ticks, then dispatch — no data available, so it
        // re-enqueues.  The request should still remember its original
        // enqueue time.
        consumer.advance_clock(5);
        let capsule = RecoverableCapsule::default();
        let outcome = consumer
            .dispatch_next_pull(0, &capsule, None)
            .expect("dispatch with no data");
        assert!(matches!(outcome, PullDispatchOutcome::Waiting(_)));
        assert_eq!(consumer.waiting_pull_request_count(), 1);

        // Advance 6 more ticks — original deadline (tick 0 + 10 = 10) is
        // now passed (current tick = 11).  The request must have expired.
        consumer.advance_clock(6);
        let err = consumer.dispatch_next_pull(0, &capsule, None);
        assert!(
            err.is_err(),
            "request should have expired by its original enqueue time"
        );
    }

    #[test]
    fn out_of_order_ack_does_not_advance_floor_past_pending() {
        let cell = test_cell();
        let mut consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let capsule = RecoverableCapsule::default().with_window(
            NodeId::new("node-a"),
            SequenceWindow::new(1, 20).expect("window"),
        );

        consumer.switch_mode(ConsumerDispatchMode::Pull);

        // Dispatch [1,5] and ack it sequentially.  Floor = 5.
        consumer
            .queue_pull_request(PullRequest::new(5, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue");
        let d1 = match consumer.dispatch_next_pull(20, &capsule, None).expect("d") {
            PullDispatchOutcome::Scheduled(d) => *d,
            other => panic!("expected Scheduled, got {other:?}"), // ubs:ignore - test logic
        };
        consumer.acknowledge_delivery(&d1.attempt).expect("ack");
        assert_eq!(consumer.state().ack_floor, 5);

        // Dispatch [6,10] (pending, not yet acked).
        consumer
            .queue_pull_request(PullRequest::new(5, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue");
        let d2 = match consumer.dispatch_next_pull(20, &capsule, None).expect("d") {
            PullDispatchOutcome::Scheduled(d) => *d,
            other => panic!("expected Scheduled, got {other:?}"), // ubs:ignore - test logic
        };
        assert_eq!(d2.window, SequenceWindow::new(6, 10).expect("w"));

        // Dispatch [6,10] again (CatchUp restarts from ack_floor+1=6 since
        // the first [6,10] is pending but CatchUp doesn't skip pending windows).
        // Then ack this second [6,10] — it will advance floor to at most 5
        // because the first [6,10] is still pending.
        consumer
            .queue_pull_request(PullRequest::new(5, ConsumerDemandClass::CatchUp).expect("req"))
            .expect("queue");
        let d3 = match consumer.dispatch_next_pull(20, &capsule, None).expect("d") {
            PullDispatchOutcome::Scheduled(d) => *d,
            other => panic!("expected Scheduled, got {other:?}"), // ubs:ignore - test logic
        };
        consumer.acknowledge_delivery(&d3.attempt).expect("ack d3");

        // Floor must not advance past the still-pending d2 [6,10].
        assert!(
            consumer.state().ack_floor <= 5,
            "ack_floor must not advance past pending [6,10]; got {}",
            consumer.state().ack_floor
        );

        // Now ack d2 [6,10].  Floor should advance to 10.
        consumer.acknowledge_delivery(&d2.attempt).expect("ack d2");
        assert_eq!(
            consumer.state().ack_floor,
            10,
            "ack_floor should advance to 10 once all windows up to 10 are acked"
        );
    }

    // ── ConsumerActor unit tests ──────────────────────────────────

    #[test]
    fn consumer_actor_lifecycle_transitions() {
        let cell = test_cell();
        let config = FabricConsumerConfig {
            durable_name: Some("test-actor".to_owned()),
            ..FabricConsumerConfig::default()
        };
        let consumer = FabricConsumer::new(&cell, config).expect("consumer");
        let actor = ConsumerActor::new(consumer);

        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Running);
        assert_eq!(
            actor.consumer().config().durable_name.as_deref(),
            Some("test-actor")
        );
    }

    #[test]
    fn consumer_actor_pause_and_resume() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let mut actor = ConsumerActor::new(consumer);
        let cx = crate::cx::Cx::for_testing();

        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Running);

        futures_lite::future::block_on(
            <ConsumerActor as crate::gen_server::GenServer>::handle_cast(
                &mut actor,
                &cx,
                ConsumerCast::Pause,
            ),
        );
        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Paused);

        futures_lite::future::block_on(
            <ConsumerActor as crate::gen_server::GenServer>::handle_cast(
                &mut actor,
                &cx,
                ConsumerCast::Resume,
            ),
        );
        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Running);
    }

    #[test]
    fn consumer_actor_stopping_lifecycle() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let mut actor = ConsumerActor::new(consumer);
        let cx = crate::cx::Cx::for_testing();

        futures_lite::future::block_on(<ConsumerActor as crate::gen_server::GenServer>::on_stop(
            &mut actor, &cx,
        ));
        assert_eq!(actor.lifecycle(), ConsumerActorLifecycle::Stopping);
    }

    #[test]
    fn consumer_actor_state_query() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let actor = ConsumerActor::new(consumer);

        let state = actor.consumer().state();
        assert_eq!(state.delivered_count, 0);
        assert_eq!(state.pending_count, 0);
        assert_eq!(state.ack_floor, 0);
    }

    #[test]
    fn consumer_actor_mutable_consumer_access() {
        let cell = test_cell();
        let consumer =
            FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
        let mut actor = ConsumerActor::new(consumer);

        let consumer_ref = actor.consumer_mut();
        assert_eq!(consumer_ref.state().delivered_count, 0);
    }
}
