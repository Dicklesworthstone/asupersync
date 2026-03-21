//! Cut-certified mobility primitives for FABRIC subject cells.
//!
//! A cut certificate captures the minimum state needed to move authority for a
//! hot cell without hand-wavy drain heuristics. Mobility stays explicit: the
//! caller mints a certificate from the current cell, then applies a lawful
//! mobility operation that yields a concrete next `SubjectCell`.

use super::fabric::{CellEpoch, CellId, CellTemperature, DataCapsule, RepairPolicy, SubjectCell};
use super::policy::{ReliabilityControlError, SafetyEnvelope};
use crate::remote::NodeId;
use crate::types::{ObligationId, Time};
use crate::util::DetHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Deterministic digest of consumer-side state captured at a certified cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ConsumerStateDigest(u64);

impl ConsumerStateDigest {
    /// Empty digest used when no consumer-side state has been retained.
    pub const ZERO: Self = Self(0);

    /// Create a new digest from a stable 64-bit value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw digest value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Deterministic digest for a warm-restorable capsule snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CapsuleDigest(u64);

impl CapsuleDigest {
    /// Empty digest indicating that no capsule payload was supplied.
    pub const ZERO: Self = Self(0);

    /// Create a new digest from a stable 64-bit value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw digest value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[must_use]
    const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Proof artifact that a subject cell was cut at a well-defined frontier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CutCertificate {
    /// Cell whose authority this cut certifies.
    pub cell_id: CellId,
    /// Cell epoch fenced into the certificate.
    pub epoch: CellEpoch,
    /// Canonicalized live obligation frontier captured at the cut.
    pub obligation_frontier: Vec<ObligationId>,
    /// Opaque digest of consumer-side state retained at the cut.
    pub consumer_state_digest: ConsumerStateDigest,
    /// Logical time when the cut was minted.
    pub timestamp: Time,
    /// Steward that signed the cut.
    pub signer: NodeId,
}

impl CutCertificate {
    /// Mint a new certificate for the current subject cell state.
    pub fn issue(
        cell: &SubjectCell,
        obligation_frontier: impl IntoIterator<Item = ObligationId>,
        consumer_state_digest: ConsumerStateDigest,
        timestamp: Time,
        signer: NodeId,
    ) -> Result<Self, CutMobilityError> {
        if !contains_node(&cell.steward_set, &signer) {
            return Err(CutMobilityError::SignerNotInStewardSet {
                cell_id: cell.cell_id,
                signer,
            });
        }

        Ok(Self {
            cell_id: cell.cell_id,
            epoch: cell.epoch,
            obligation_frontier: canonicalize_frontier(obligation_frontier),
            consumer_state_digest,
            timestamp,
            signer,
        })
    }

    /// Verify that this certificate still applies to `cell`.
    pub fn validate_for(&self, cell: &SubjectCell) -> Result<(), CutMobilityError> {
        if self.cell_id != cell.cell_id {
            return Err(CutMobilityError::CellMismatch {
                certificate_cell: self.cell_id,
                actual_cell: cell.cell_id,
            });
        }
        if self.epoch != cell.epoch {
            return Err(CutMobilityError::EpochMismatch {
                certificate_epoch: self.epoch,
                actual_epoch: cell.epoch,
            });
        }
        if !contains_node(&cell.steward_set, &self.signer) {
            return Err(CutMobilityError::SignerNotInStewardSet {
                cell_id: cell.cell_id,
                signer: self.signer.clone(),
            });
        }
        Ok(())
    }

    /// Return true if the certificate explicitly captures `obligation`.
    #[must_use]
    pub fn covers_obligation(&self, obligation: ObligationId) -> bool {
        self.obligation_frontier.binary_search(&obligation).is_ok()
    }

    /// Deterministic digest of the cut frontier and attached consumer state.
    #[must_use]
    pub fn obligation_frontier_digest(&self) -> u64 {
        stable_hash((
            "cut-frontier",
            self.cell_id.raw(),
            self.epoch,
            &self.obligation_frontier,
            self.consumer_state_digest.raw(),
            self.timestamp.as_nanos(),
            self.signer.as_str(),
        ))
    }

    /// Deterministic digest of the full certificate payload.
    #[must_use]
    pub fn certificate_digest(&self) -> u64 {
        stable_hash(("cut-certificate", self))
    }
}

/// Lawful state-mobility transitions that may occur from a certified cut.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MobilityOperation {
    /// Urgently drain traffic away from a hot source steward.
    Evacuate {
        /// Current active steward being evacuated.
        from: NodeId,
        /// Steward that will take over authority.
        to: NodeId,
    },
    /// Planned service or consumer handoff under an explicit cut.
    Handoff {
        /// Current active steward handing off authority.
        from: NodeId,
        /// Successor steward taking over authority.
        to: NodeId,
    },
    /// Restore a warm capsule into a rebased epoch and target node.
    WarmRestore {
        /// Node where the warm capsule is restored.
        target: NodeId,
        /// Fresh epoch rebinding the restored cell away from live authority.
        restored_epoch: CellEpoch,
        /// Digest of the capsule payload being restored.
        capsule_digest: CapsuleDigest,
    },
    /// Promote another steward after the current active one fails.
    Failover {
        /// Steward deemed failed for the active lease.
        failed: NodeId,
        /// Steward promoted to continue service.
        promote_to: NodeId,
    },
}

impl MobilityOperation {
    /// Validate this operation against `cell` and `certificate`, then produce
    /// the concrete next cell state.
    pub fn certify(
        &self,
        cell: &SubjectCell,
        certificate: &CutCertificate,
    ) -> Result<CertifiedMobility, CutMobilityError> {
        certificate.validate_for(cell)?;

        let resulting_cell = match self {
            Self::Evacuate { from, to } => certify_evacuation(cell, certificate, from, to)?,
            Self::Handoff { from, to } => certify_handoff(cell, certificate, from, to)?,
            Self::WarmRestore {
                target,
                restored_epoch,
                capsule_digest,
            } => certify_warm_restore(cell, certificate, target, *restored_epoch, *capsule_digest)?,
            Self::Failover { failed, promote_to } => {
                certify_failover(cell, certificate, failed, promote_to)?
            }
        };

        Ok(CertifiedMobility {
            certificate: certificate.clone(),
            operation: self.clone(),
            obligation_frontier_digest: certificate.obligation_frontier_digest(),
            resulting_cell,
        })
    }
}

/// Concrete proof artifact for an applied mobility operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMobility {
    /// Cut certificate authorizing the move.
    pub certificate: CutCertificate,
    /// Operation applied to the certified cut.
    pub operation: MobilityOperation,
    /// Deterministic digest of the obligation frontier the move preserves.
    pub obligation_frontier_digest: u64,
    /// Resulting cell after the mobility operation.
    pub resulting_cell: SubjectCell,
}

impl CertifiedMobility {
    /// Deterministic digest of the transition proof.
    #[must_use]
    pub fn mobility_digest(&self) -> u64 {
        stable_hash((
            "certified-mobility",
            self.certificate.certificate_digest(),
            &self.operation,
            self.obligation_frontier_digest,
            self.resulting_cell.cell_id.raw(),
            self.resulting_cell.epoch,
            self.resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            self.resulting_cell.control_capsule.policy_revision,
        ))
    }
}

impl SubjectCell {
    /// Mint a cut certificate rooted at the current subject cell.
    pub fn issue_cut_certificate(
        &self,
        obligation_frontier: impl IntoIterator<Item = ObligationId>,
        consumer_state_digest: ConsumerStateDigest,
        timestamp: Time,
        signer: NodeId,
    ) -> Result<CutCertificate, CutMobilityError> {
        CutCertificate::issue(
            self,
            obligation_frontier,
            consumer_state_digest,
            timestamp,
            signer,
        )
    }

    /// Apply a cut-certified mobility operation to the current subject cell.
    pub fn certify_mobility(
        &self,
        certificate: &CutCertificate,
        operation: &MobilityOperation,
    ) -> Result<CertifiedMobility, CutMobilityError> {
        operation.certify(self, certificate)
    }
}

/// Deterministic failures while minting or applying cut-certified mobility.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CutMobilityError {
    /// The certificate signer is not one of the cell's currently lawful stewards.
    #[error("cut certificate signer `{signer}` is not in the steward set for `{cell_id}`")]
    SignerNotInStewardSet {
        /// Cell the signer attempted to certify.
        cell_id: CellId,
        /// Unauthorized signer.
        signer: NodeId,
    },
    /// The certificate refers to a different cell id.
    #[error("cut certificate targets `{certificate_cell}` but current cell is `{actual_cell}`")]
    CellMismatch {
        /// Cell encoded into the certificate.
        certificate_cell: CellId,
        /// Cell the caller attempted to move.
        actual_cell: CellId,
    },
    /// The certificate refers to a different epoch.
    #[error(
        "cut certificate epoch {certificate_epoch:?} does not match current epoch {actual_epoch:?}"
    )]
    EpochMismatch {
        /// Epoch encoded into the certificate.
        certificate_epoch: CellEpoch,
        /// Epoch currently owned by the cell.
        actual_epoch: CellEpoch,
    },
    /// The cell has no active sequencer to evacuate or hand off.
    #[error("subject cell `{cell_id}` has no active sequencer")]
    NoActiveSequencer {
        /// Cell lacking an active sequencer.
        cell_id: CellId,
    },
    /// The requested source does not match the active steward.
    #[error("mobility source `{requested}` does not match active sequencer `{active}`")]
    SourceNotActive {
        /// Source requested by the operation.
        requested: NodeId,
        /// Actual active sequencer.
        active: NodeId,
    },
    /// Planned mobility requires the signer to match the active source.
    #[error("cut certificate signer `{signer}` must match mobility source `{active_source}`")]
    SignerMustMatchSource {
        /// Signer attached to the cut certificate.
        signer: NodeId,
        /// Active source steward being moved.
        active_source: NodeId,
    },
    /// The target node is not currently part of the steward set.
    #[error("mobility target `{target}` is not in the steward set for `{cell_id}`")]
    TargetNotInStewardSet {
        /// Cell being moved.
        cell_id: CellId,
        /// Proposed target node.
        target: NodeId,
    },
    /// The requested target is the same as the source or failed node.
    #[error("mobility target `{target}` must differ from source `{current_source}`")]
    TargetMatchesSource {
        /// Source node being moved away from.
        current_source: NodeId,
        /// Target node proposed by the operation.
        target: NodeId,
    },
    /// Failover must be acknowledged by a surviving signer.
    #[error("failover signer `{signer}` cannot also be the failed steward `{failed}`")]
    FailoverSignedByFailedNode {
        /// Signer attached to the certificate.
        signer: NodeId,
        /// Failed active steward.
        failed: NodeId,
    },
    /// Warm restore needs captured consumer state to restore meaningfully.
    #[error("warm restore requires a non-zero consumer-state digest")]
    MissingConsumerStateDigest,
    /// Warm restore must point at a concrete capsule payload.
    #[error("warm restore requires a non-zero capsule digest")]
    MissingCapsuleDigest,
    /// Warm restore must rebind into a newer epoch.
    #[error(
        "warm restore epoch {restored_epoch:?} must be newer than cut epoch {certificate_epoch:?}"
    )]
    StaleRestoreEpoch {
        /// Epoch requested by the restore.
        restored_epoch: CellEpoch,
        /// Epoch attached to the cut certificate.
        certificate_epoch: CellEpoch,
    },
}

fn certify_evacuation(
    cell: &SubjectCell,
    certificate: &CutCertificate,
    from: &NodeId,
    to: &NodeId,
) -> Result<SubjectCell, CutMobilityError> {
    let active = require_active_sequencer(cell)?;
    if from != active {
        return Err(CutMobilityError::SourceNotActive {
            requested: from.clone(),
            active: active.clone(),
        });
    }
    if &certificate.signer != from {
        return Err(CutMobilityError::SignerMustMatchSource {
            signer: certificate.signer.clone(),
            active_source: from.clone(),
        });
    }
    if from == to {
        return Err(CutMobilityError::TargetMatchesSource {
            current_source: from.clone(),
            target: to.clone(),
        });
    }
    if !contains_node(&cell.steward_set, to) {
        return Err(CutMobilityError::TargetNotInStewardSet {
            cell_id: cell.cell_id,
            target: to.clone(),
        });
    }

    let mut moved = advance_control_state(cell);
    moved.control_capsule.active_sequencer = Some(to.clone());
    move_node_to_front(&mut moved.steward_set, to);
    move_node_to_back(&mut moved.steward_set, from);
    move_node_to_front(&mut moved.control_capsule.steward_pool, to);
    move_node_to_back(&mut moved.control_capsule.steward_pool, from);
    Ok(moved)
}

fn certify_handoff(
    cell: &SubjectCell,
    certificate: &CutCertificate,
    from: &NodeId,
    to: &NodeId,
) -> Result<SubjectCell, CutMobilityError> {
    let active = require_active_sequencer(cell)?;
    if from != active {
        return Err(CutMobilityError::SourceNotActive {
            requested: from.clone(),
            active: active.clone(),
        });
    }
    if &certificate.signer != from {
        return Err(CutMobilityError::SignerMustMatchSource {
            signer: certificate.signer.clone(),
            active_source: from.clone(),
        });
    }
    if from == to {
        return Err(CutMobilityError::TargetMatchesSource {
            current_source: from.clone(),
            target: to.clone(),
        });
    }
    if !contains_node(&cell.steward_set, to) {
        return Err(CutMobilityError::TargetNotInStewardSet {
            cell_id: cell.cell_id,
            target: to.clone(),
        });
    }

    let mut moved = advance_control_state(cell);
    moved.control_capsule.active_sequencer = Some(to.clone());
    Ok(moved)
}

fn certify_warm_restore(
    cell: &SubjectCell,
    certificate: &CutCertificate,
    target: &NodeId,
    restored_epoch: CellEpoch,
    capsule_digest: CapsuleDigest,
) -> Result<SubjectCell, CutMobilityError> {
    if certificate.consumer_state_digest == ConsumerStateDigest::ZERO {
        return Err(CutMobilityError::MissingConsumerStateDigest);
    }
    if capsule_digest.is_zero() {
        return Err(CutMobilityError::MissingCapsuleDigest);
    }
    if restored_epoch <= certificate.epoch {
        return Err(CutMobilityError::StaleRestoreEpoch {
            restored_epoch,
            certificate_epoch: certificate.epoch,
        });
    }

    let mut restored = cell.clone();
    restored.epoch = restored_epoch;
    restored.cell_id = CellId::for_partition(restored_epoch, &restored.subject_partition);
    restored.control_capsule.active_sequencer = Some(target.clone());
    restored.control_capsule.sequencer_lease_generation = restored_epoch.generation;
    restored.control_capsule.policy_revision =
        restored.control_capsule.policy_revision.saturating_add(1);
    ensure_node_at_front(&mut restored.steward_set, target.clone());
    ensure_node_at_front(&mut restored.control_capsule.steward_pool, target.clone());
    Ok(restored)
}

fn certify_failover(
    cell: &SubjectCell,
    certificate: &CutCertificate,
    failed: &NodeId,
    promote_to: &NodeId,
) -> Result<SubjectCell, CutMobilityError> {
    let active = require_active_sequencer(cell)?;
    if failed != active {
        return Err(CutMobilityError::SourceNotActive {
            requested: failed.clone(),
            active: active.clone(),
        });
    }
    if &certificate.signer == failed {
        return Err(CutMobilityError::FailoverSignedByFailedNode {
            signer: certificate.signer.clone(),
            failed: failed.clone(),
        });
    }
    if failed == promote_to {
        return Err(CutMobilityError::TargetMatchesSource {
            current_source: failed.clone(),
            target: promote_to.clone(),
        });
    }
    if !contains_node(&cell.steward_set, promote_to) {
        return Err(CutMobilityError::TargetNotInStewardSet {
            cell_id: cell.cell_id,
            target: promote_to.clone(),
        });
    }

    let mut moved = advance_control_state(cell);
    moved.steward_set.retain(|node| node != failed);
    moved
        .control_capsule
        .steward_pool
        .retain(|node| node != failed);
    move_node_to_front(&mut moved.steward_set, promote_to);
    move_node_to_front(&mut moved.control_capsule.steward_pool, promote_to);
    moved.control_capsule.active_sequencer = Some(promote_to.clone());
    Ok(moved)
}

fn require_active_sequencer(cell: &SubjectCell) -> Result<&NodeId, CutMobilityError> {
    cell.control_capsule
        .active_sequencer
        .as_ref()
        .ok_or(CutMobilityError::NoActiveSequencer {
            cell_id: cell.cell_id,
        })
}

fn canonicalize_frontier(
    obligation_frontier: impl IntoIterator<Item = ObligationId>,
) -> Vec<ObligationId> {
    let mut frontier: Vec<_> = obligation_frontier.into_iter().collect();
    frontier.sort_unstable();
    frontier.dedup();
    frontier
}

fn advance_control_state(cell: &SubjectCell) -> SubjectCell {
    let mut next = cell.clone();
    next.control_capsule.sequencer_lease_generation = next
        .control_capsule
        .sequencer_lease_generation
        .saturating_add(1);
    next.control_capsule.policy_revision = next.control_capsule.policy_revision.saturating_add(1);
    next
}

fn contains_node(nodes: &[NodeId], candidate: &NodeId) -> bool {
    nodes.iter().any(|node| node == candidate)
}

fn move_node_to_front(nodes: &mut Vec<NodeId>, candidate: &NodeId) {
    if let Some(index) = nodes.iter().position(|node| node == candidate) {
        let node = nodes.remove(index);
        nodes.insert(0, node);
    }
}

fn move_node_to_back(nodes: &mut Vec<NodeId>, candidate: &NodeId) {
    if let Some(index) = nodes.iter().position(|node| node == candidate) {
        let node = nodes.remove(index);
        nodes.push(node);
    }
}

fn ensure_node_at_front(nodes: &mut Vec<NodeId>, candidate: NodeId) {
    if let Some(index) = nodes.iter().position(|node| node == &candidate) {
        let node = nodes.remove(index);
        nodes.insert(0, node);
    } else {
        nodes.insert(0, candidate);
    }
}

fn stable_hash<T: Hash>(value: T) -> u64 {
    let mut hasher = DetHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Deterministic incident rehearsal
// ---------------------------------------------------------------------------

/// Captured state at an incident site — the starting point for a rehearsal.
///
/// An incident snapshot freezes a subject cell, its cut certificate, and the
/// mobility event that triggered the incident. Operators replay the incident
/// under a different policy to ask "what would have happened instead?"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentSnapshot {
    /// Cell state at the moment the incident was observed.
    pub cell: SubjectCell,
    /// Cut certificate captured at the incident boundary.
    pub certificate: CutCertificate,
    /// The mobility operation that was applied (or attempted) during the incident.
    pub original_operation: MobilityOperation,
    /// Label for the incident (human-readable, used in comparison reports).
    pub label: String,
    /// Logical time at which the snapshot was taken.
    pub snapshot_time: Time,
}

impl IncidentSnapshot {
    /// Capture a new incident snapshot from a cell, certificate, and triggering operation.
    pub fn capture(
        cell: &SubjectCell,
        certificate: &CutCertificate,
        original_operation: MobilityOperation,
        label: impl Into<String>,
        snapshot_time: Time,
    ) -> Result<Self, RehearsalError> {
        let label = label.into();
        certificate
            .validate_for(cell)
            .map_err(|e| RehearsalError::InvalidCertificate {
                label: label.clone(),
                source: e,
            })?;
        Ok(Self {
            cell: cell.clone(),
            certificate: certificate.clone(),
            original_operation,
            label,
            snapshot_time,
        })
    }

    /// Deterministic digest of the incident snapshot for reproducibility tracking.
    #[must_use]
    pub fn snapshot_digest(&self) -> u64 {
        stable_hash((
            "incident-snapshot",
            self.cell.cell_id.raw(),
            self.cell.epoch,
            self.certificate.certificate_digest(),
            &self.original_operation,
            &self.label,
            self.snapshot_time.as_nanos(),
        ))
    }

    /// Replay the original operation to produce the baseline outcome.
    pub fn replay_original(&self) -> Result<CertifiedMobility, CutMobilityError> {
        self.original_operation
            .certify(&self.cell, &self.certificate)
    }

    /// Fork this incident into a rehearsal branch under an alternative policy.
    pub fn fork_rehearsal(
        &self,
        alternative: RehearsalPolicy,
        rehearsal_epoch: CellEpoch,
    ) -> Result<RehearsalFork, RehearsalError> {
        if rehearsal_epoch <= self.cell.epoch {
            return Err(RehearsalError::StaleRehearsalEpoch {
                rehearsal_epoch,
                snapshot_epoch: self.cell.epoch,
            });
        }

        let mut forked_cell = self.cell.clone();
        forked_cell.epoch = rehearsal_epoch;
        forked_cell.cell_id =
            CellId::for_partition(rehearsal_epoch, &forked_cell.subject_partition);

        // Apply policy overrides to the forked cell.
        if let Some(placement) = &alternative.placement_override {
            apply_placement_override(&mut forked_cell, placement);
        }
        if let Some(repair) = &alternative.repair_override {
            forked_cell.repair_policy = repair.clone();
        }
        if let Some(data) = &alternative.data_capsule_override {
            forked_cell.data_capsule = data.clone();
        }
        if let Some(ref stewards) = alternative.steward_override {
            forked_cell.steward_set.clone_from(stewards);
            forked_cell
                .control_capsule
                .steward_pool
                .clone_from(stewards);
            // If the current active_sequencer is no longer in the new set,
            // promote the first new steward so the forked cell is operational.
            if let Some(active) = &forked_cell.control_capsule.active_sequencer {
                if !contains_node(stewards, active) {
                    forked_cell.control_capsule.active_sequencer = stewards.first().cloned();
                }
            }
        }

        // Re-issue a certificate for the forked cell so rehearsal operations
        // validate against the new epoch. If a steward_override removed the
        // original signer, pick the first node in the new steward set so
        // certificate validation does not reject the rehearsal.
        let forked_signer = if contains_node(&forked_cell.steward_set, &self.certificate.signer) {
            self.certificate.signer.clone()
        } else {
            forked_cell.steward_set.first().cloned().ok_or_else(|| {
                RehearsalError::EmptyStewardOverride {
                    label: self.label.clone(),
                }
            })?
        };
        let forked_certificate = CutCertificate {
            cell_id: forked_cell.cell_id,
            epoch: forked_cell.epoch,
            obligation_frontier: self.certificate.obligation_frontier.clone(),
            consumer_state_digest: self.certificate.consumer_state_digest,
            timestamp: self.snapshot_time,
            signer: forked_signer,
        };

        Ok(RehearsalFork {
            snapshot_digest: self.snapshot_digest(),
            label: self.label.clone(),
            forked_cell,
            forked_certificate,
            alternative_policy: alternative,
            rehearsal_epoch,
        })
    }
}

/// Policy overrides applied to a forked rehearsal branch.
///
/// Each field is optional; `None` means "keep the original policy." This lets
/// operators answer questions like "what if we had one more hot steward?" or
/// "what if the budget was shorter?" without constructing a full cell by hand.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RehearsalPolicy {
    /// Override placement (steward counts, latency bounds, etc.).
    pub placement_override: Option<PlacementOverride>,
    /// Override repair policy (witness counts, recoverability target).
    pub repair_override: Option<RepairPolicy>,
    /// Override data capsule (temperature, retention).
    pub data_capsule_override: Option<DataCapsule>,
    /// Override the steward set entirely.
    pub steward_override: Option<Vec<NodeId>>,
    /// Human-readable description of the alternative being tested.
    pub description: String,
}

/// Subset of placement policy fields that can be overridden in a rehearsal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementOverride {
    /// Override for cold steward count.
    pub cold_stewards: Option<usize>,
    /// Override for warm steward count.
    pub warm_stewards: Option<usize>,
    /// Override for hot steward count.
    pub hot_stewards: Option<usize>,
}

fn apply_placement_override(cell: &mut SubjectCell, overrides: &PlacementOverride) {
    // Placement policy lives on the cell's data capsule temperature-aware
    // behavior. We store the override information in the cell's repair policy
    // witness counts as a proxy until first-class PlacementPolicy lives on
    // SubjectCell directly. The override mainly affects how many stewards
    // are expected during the rehearsal comparison.
    //
    // For rehearsal purposes, we adjust the steward set size if the override
    // requests fewer stewards than currently available.
    if let Some(hot) = overrides.hot_stewards {
        cell.repair_policy.hot_witnesses = hot;
    }
    if let Some(cold) = overrides.cold_stewards {
        cell.repair_policy.cold_witnesses = cold;
    }
    // warm_stewards is informational for rehearsal comparison.
}

/// A forked rehearsal branch ready for replaying mobility operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehearsalFork {
    /// Digest of the original incident snapshot this fork derives from.
    pub snapshot_digest: u64,
    /// Label inherited from the incident snapshot.
    pub label: String,
    /// Cell state in the rehearsal branch (policy-adjusted, rebased epoch).
    pub forked_cell: SubjectCell,
    /// Certificate re-issued for the forked cell's epoch.
    pub forked_certificate: CutCertificate,
    /// The alternative policy applied to this branch.
    pub alternative_policy: RehearsalPolicy,
    /// Epoch assigned to the rehearsal branch.
    pub rehearsal_epoch: CellEpoch,
}

impl RehearsalFork {
    /// Replay a mobility operation in the rehearsal branch.
    ///
    /// The replay always produces an outcome — mobility failures are captured
    /// inside `RehearsalOutcome::result` rather than propagated as errors.
    #[must_use]
    pub fn replay(&self, operation: &MobilityOperation) -> RehearsalOutcome {
        let result = operation.certify(&self.forked_cell, &self.forked_certificate);
        RehearsalOutcome {
            snapshot_digest: self.snapshot_digest,
            label: self.label.clone(),
            rehearsal_epoch: self.rehearsal_epoch,
            operation: operation.clone(),
            result,
            policy_description: self.alternative_policy.description.clone(),
        }
    }

    /// Deterministic digest of the fork state.
    #[must_use]
    pub fn fork_digest(&self) -> u64 {
        stable_hash((
            "rehearsal-fork",
            self.snapshot_digest,
            self.forked_cell.cell_id.raw(),
            self.forked_cell.epoch,
            self.rehearsal_epoch,
        ))
    }
}

/// Result of replaying a mobility operation in a rehearsal branch.
#[derive(Debug, Clone)]
pub struct RehearsalOutcome {
    /// Digest of the originating incident snapshot.
    pub snapshot_digest: u64,
    /// Label inherited from the incident snapshot.
    pub label: String,
    /// Epoch of the rehearsal branch.
    pub rehearsal_epoch: CellEpoch,
    /// Operation that was replayed.
    pub operation: MobilityOperation,
    /// Result: `Ok(CertifiedMobility)` if the operation succeeded, or the error.
    pub result: Result<CertifiedMobility, CutMobilityError>,
    /// Description of the alternative policy under test.
    pub policy_description: String,
}

impl RehearsalOutcome {
    /// Whether the rehearsed operation succeeded.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.result.is_ok()
    }

    /// The resulting cell if the operation succeeded.
    #[must_use]
    pub fn resulting_cell(&self) -> Option<&SubjectCell> {
        self.result.as_ref().ok().map(|m| &m.resulting_cell)
    }
}

/// Structured comparison between an original incident and a rehearsed alternative.
#[derive(Debug, Clone)]
pub struct RehearsalComparison {
    /// Label from the incident snapshot.
    pub label: String,
    /// Digest of the incident snapshot both branches derive from.
    pub snapshot_digest: u64,
    /// Outcome of replaying the original operation on the original cell.
    pub original: RehearsalOutcome,
    /// Outcome of replaying an operation on the forked (alternative-policy) cell.
    pub rehearsed: RehearsalOutcome,
    /// Structured divergence between the two outcomes.
    pub divergence: RehearsalDivergence,
}

/// Classification of how the rehearsed outcome diverges from the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehearsalDivergence {
    /// Both succeeded and produced equivalent resulting cells.
    Equivalent,
    /// Both succeeded but the resulting cells differ.
    CellDrift {
        /// Fields that differ between the original and rehearsed resulting cells.
        differences: Vec<String>,
    },
    /// Original succeeded but rehearsal failed.
    RehearsalFailed {
        /// Error from the rehearsal branch.
        error: CutMobilityError,
    },
    /// Original failed but rehearsal succeeded.
    OriginalFailed {
        /// Error from the original operation.
        error: CutMobilityError,
    },
    /// Both failed (possibly with different errors).
    BothFailed {
        /// Error from the original.
        original_error: CutMobilityError,
        /// Error from the rehearsal.
        rehearsal_error: CutMobilityError,
    },
}

impl RehearsalComparison {
    /// Compare the original incident replay against a rehearsed alternative.
    pub fn compare(
        snapshot: &IncidentSnapshot,
        rehearsal_outcome: RehearsalOutcome,
    ) -> Result<Self, RehearsalError> {
        let original_result = snapshot.replay_original();

        let original_outcome = RehearsalOutcome {
            snapshot_digest: snapshot.snapshot_digest(),
            label: snapshot.label.clone(),
            rehearsal_epoch: snapshot.cell.epoch,
            operation: snapshot.original_operation.clone(),
            result: original_result,
            policy_description: "original".to_owned(),
        };

        let divergence = classify_divergence(&original_outcome.result, &rehearsal_outcome.result);

        Ok(Self {
            label: snapshot.label.clone(),
            snapshot_digest: snapshot.snapshot_digest(),
            original: original_outcome,
            rehearsed: rehearsal_outcome,
            divergence,
        })
    }

    /// Whether the rehearsal produced an equivalent outcome to the original.
    #[must_use]
    pub fn is_equivalent(&self) -> bool {
        matches!(self.divergence, RehearsalDivergence::Equivalent)
    }

    /// Deterministic digest of the comparison for evidence ledger integration.
    #[must_use]
    pub fn comparison_digest(&self) -> u64 {
        stable_hash((
            "rehearsal-comparison",
            self.snapshot_digest,
            &self.label,
            matches!(self.divergence, RehearsalDivergence::Equivalent),
        ))
    }

    /// Decide whether a rehearsed policy should be promoted over the current
    /// baseline under an explicit safety envelope.
    #[must_use]
    pub fn evaluate_promotion(
        &self,
        baseline: &CounterfactualScore,
        candidate: &CounterfactualScore,
        envelope: &CounterfactualPromotionEnvelope,
    ) -> CounterfactualPromotionDecision {
        if matches!(self.divergence, RehearsalDivergence::Equivalent) {
            return CounterfactualPromotionDecision::RejectEquivalent;
        }

        if let Some(rejection) = validate_counterfactual_score(baseline, "baseline_") {
            return rejection;
        }
        if let Some(rejection) = validate_counterfactual_score(candidate, "") {
            return rejection;
        }
        if let Err(error) = envelope.validate() {
            return CounterfactualPromotionDecision::RejectInvalidEnvelope { error };
        }

        if candidate.evidence_confidence < envelope.reliability.evidence_threshold {
            return CounterfactualPromotionDecision::RejectInsufficientEvidence {
                observed: candidate.evidence_confidence,
                required: envelope.reliability.evidence_threshold,
            };
        }

        if candidate.violation_rate > envelope.reliability.rollback_violation_threshold {
            return CounterfactualPromotionDecision::RejectRollbackRisk {
                observed: candidate.violation_rate,
                threshold: envelope.reliability.rollback_violation_threshold,
            };
        }

        let Some(rehearsed_cell) = self.rehearsed.resulting_cell() else {
            return CounterfactualPromotionDecision::RejectFailure {
                divergence: self.divergence.clone(),
            };
        };

        let envelope_violations = envelope.evaluate(rehearsed_cell);
        if !envelope_violations.is_empty() {
            return CounterfactualPromotionDecision::RejectEnvelopeViolation {
                reasons: envelope_violations,
            };
        }

        if candidate.policy_gain <= baseline.policy_gain {
            return CounterfactualPromotionDecision::RejectNoImprovement {
                baseline_gain: baseline.policy_gain,
                candidate_gain: candidate.policy_gain,
            };
        }

        CounterfactualPromotionDecision::Promote {
            comparison_digest: self.comparison_digest(),
            policy_description: self.rehearsed.policy_description.clone(),
        }
    }
}

/// Compact scorecard for comparing one rehearsed policy against the baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct CounterfactualScore {
    /// Operator-meaningful improvement score; higher is better.
    pub policy_gain: f64,
    /// Confidence that the rehearsal used enough evidence to justify a shift.
    pub evidence_confidence: f64,
    /// Estimated post-promotion violation rate.
    pub violation_rate: f64,
}

/// Safety limits that a promoted rehearsal must remain inside.
#[derive(Debug, Clone, PartialEq)]
pub struct CounterfactualPromotionEnvelope {
    /// Shared operator envelope compiled elsewhere in the policy plane.
    pub reliability: SafetyEnvelope,
    /// Highest data temperature that may be promoted automatically.
    pub max_temperature: CellTemperature,
    /// Maximum retained inline message blocks allowed after promotion.
    pub max_retained_message_blocks: usize,
    /// Maximum witness fanout allowed for cold cells after promotion.
    pub max_cold_witnesses: usize,
    /// Maximum witness fanout allowed for hot cells after promotion.
    pub max_hot_witnesses: usize,
}

impl Default for CounterfactualPromotionEnvelope {
    fn default() -> Self {
        Self {
            reliability: SafetyEnvelope::default(),
            max_temperature: CellTemperature::Hot,
            max_retained_message_blocks: usize::MAX,
            max_cold_witnesses: usize::MAX,
            max_hot_witnesses: usize::MAX,
        }
    }
}

impl CounterfactualPromotionEnvelope {
    fn validate(&self) -> Result<(), ReliabilityControlError> {
        self.reliability.validate()
    }

    fn evaluate(&self, cell: &SubjectCell) -> Vec<String> {
        let mut violations = Vec::new();
        let steward_count = cell.steward_set.len();

        if steward_count < self.reliability.min_stewards
            || steward_count > self.reliability.max_stewards
        {
            violations.push(format!(
                "steward_count={steward_count} outside [{}, {}]",
                self.reliability.min_stewards, self.reliability.max_stewards
            ));
        }

        let recoverability = u16::from(cell.repair_policy.recoverability_target);
        if recoverability < self.reliability.min_repair_depth
            || recoverability > self.reliability.max_repair_depth
        {
            violations.push(format!(
                "recoverability_target={recoverability} outside [{}, {}]",
                self.reliability.min_repair_depth, self.reliability.max_repair_depth
            ));
        }

        if temperature_rank(cell.data_capsule.temperature) > temperature_rank(self.max_temperature)
        {
            violations.push(format!(
                "temperature={:?} exceeds {:?}",
                cell.data_capsule.temperature, self.max_temperature
            ));
        }

        if cell.data_capsule.retained_message_blocks > self.max_retained_message_blocks {
            violations.push(format!(
                "retained_message_blocks={} exceeds {}",
                cell.data_capsule.retained_message_blocks, self.max_retained_message_blocks
            ));
        }

        if cell.repair_policy.cold_witnesses > self.max_cold_witnesses {
            violations.push(format!(
                "cold_witnesses={} exceeds {}",
                cell.repair_policy.cold_witnesses, self.max_cold_witnesses
            ));
        }

        if cell.repair_policy.hot_witnesses > self.max_hot_witnesses {
            violations.push(format!(
                "hot_witnesses={} exceeds {}",
                cell.repair_policy.hot_witnesses, self.max_hot_witnesses
            ));
        }

        violations
    }
}

/// Promotion verdict for a rehearsed counterfactual branch.
#[derive(Debug, Clone, PartialEq)]
pub enum CounterfactualPromotionDecision {
    /// The rehearsed policy beat the baseline inside the envelope.
    Promote {
        /// Deterministic digest of the comparison that justified promotion.
        comparison_digest: u64,
        /// Human-readable policy description that was promoted.
        policy_description: String,
    },
    /// No material change relative to the baseline.
    RejectEquivalent,
    /// Candidate score contained an invalid numeric value.
    RejectInvalidScore {
        /// Invalid field name.
        field: &'static str,
        /// Value that was rejected.
        value: f64,
    },
    /// The supplied promotion envelope is not internally consistent.
    RejectInvalidEnvelope {
        /// Validation failure explaining which safety bound is malformed.
        error: ReliabilityControlError,
    },
    /// Candidate lacked the evidence required by policy.
    RejectInsufficientEvidence {
        /// Candidate confidence.
        observed: f64,
        /// Required confidence.
        required: f64,
    },
    /// Candidate would exceed the allowed rollback/violation risk.
    RejectRollbackRisk {
        /// Candidate violation rate.
        observed: f64,
        /// Maximum permitted rate.
        threshold: f64,
    },
    /// Candidate violates the explicit envelope bounds.
    RejectEnvelopeViolation {
        /// Human-readable reasons for the rejection.
        reasons: Vec<String>,
    },
    /// Candidate did not improve on the current baseline.
    RejectNoImprovement {
        /// Current baseline score.
        baseline_gain: f64,
        /// Candidate score.
        candidate_gain: f64,
    },
    /// Candidate replay failed and is therefore not promotable.
    RejectFailure {
        /// Divergence classification explaining the rejection.
        divergence: RehearsalDivergence,
    },
}

fn validate_counterfactual_score(
    score: &CounterfactualScore,
    field_prefix: &'static str,
) -> Option<CounterfactualPromotionDecision> {
    if !score.policy_gain.is_finite() {
        return Some(CounterfactualPromotionDecision::RejectInvalidScore {
            field: invalid_score_field(field_prefix, "policy_gain"),
            value: score.policy_gain,
        });
    }

    if !score.evidence_confidence.is_finite()
        || score.evidence_confidence < 0.0
        || score.evidence_confidence > 1.0
    {
        return Some(CounterfactualPromotionDecision::RejectInvalidScore {
            field: invalid_score_field(field_prefix, "evidence_confidence"),
            value: score.evidence_confidence,
        });
    }

    if !score.violation_rate.is_finite() || score.violation_rate < 0.0 || score.violation_rate > 1.0
    {
        return Some(CounterfactualPromotionDecision::RejectInvalidScore {
            field: invalid_score_field(field_prefix, "violation_rate"),
            value: score.violation_rate,
        });
    }

    None
}

fn invalid_score_field(field_prefix: &'static str, field_name: &'static str) -> &'static str {
    match (field_prefix, field_name) {
        ("", "policy_gain") => "policy_gain",
        ("", "evidence_confidence") => "evidence_confidence",
        ("", "violation_rate") => "violation_rate",
        ("baseline_", "policy_gain") => "baseline_policy_gain",
        ("baseline_", "evidence_confidence") => "baseline_evidence_confidence",
        ("baseline_", "violation_rate") => "baseline_violation_rate",
        _ => "invalid_score",
    }
}

fn temperature_rank(temperature: CellTemperature) -> u8 {
    match temperature {
        CellTemperature::Cold => 0,
        CellTemperature::Warm => 1,
        CellTemperature::Hot => 2,
    }
}

fn classify_divergence(
    original: &Result<CertifiedMobility, CutMobilityError>,
    rehearsed: &Result<CertifiedMobility, CutMobilityError>,
) -> RehearsalDivergence {
    match (original, rehearsed) {
        (Ok(orig), Ok(reh)) => {
            let diffs = diff_cells(&orig.resulting_cell, &reh.resulting_cell);
            if diffs.is_empty() {
                RehearsalDivergence::Equivalent
            } else {
                RehearsalDivergence::CellDrift { differences: diffs }
            }
        }
        (Ok(_), Err(e)) => RehearsalDivergence::RehearsalFailed { error: e.clone() },
        (Err(e), Ok(_)) => RehearsalDivergence::OriginalFailed { error: e.clone() },
        (Err(o), Err(r)) => RehearsalDivergence::BothFailed {
            original_error: o.clone(),
            rehearsal_error: r.clone(),
        },
    }
}

fn diff_cells(a: &SubjectCell, b: &SubjectCell) -> Vec<String> {
    let mut diffs = Vec::new();
    if a.cell_id != b.cell_id {
        diffs.push("cell_id".to_owned());
    }
    if a.epoch != b.epoch {
        diffs.push("epoch".to_owned());
    }
    if a.subject_partition != b.subject_partition {
        diffs.push("subject_partition".to_owned());
    }
    if a.steward_set != b.steward_set {
        diffs.push("steward_set".to_owned());
    }
    if a.control_capsule.active_sequencer != b.control_capsule.active_sequencer {
        diffs.push("active_sequencer".to_owned());
    }
    if a.control_capsule.sequencer_lease_generation != b.control_capsule.sequencer_lease_generation
    {
        diffs.push("sequencer_lease_generation".to_owned());
    }
    if a.control_capsule.policy_revision != b.control_capsule.policy_revision {
        diffs.push("policy_revision".to_owned());
    }
    if a.control_capsule.steward_pool != b.control_capsule.steward_pool {
        diffs.push("steward_pool".to_owned());
    }
    if a.data_capsule != b.data_capsule {
        diffs.push("data_capsule".to_owned());
    }
    if a.repair_policy != b.repair_policy {
        diffs.push("repair_policy".to_owned());
    }
    diffs
}

/// Errors specific to rehearsal operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RehearsalError {
    /// The incident snapshot's certificate is invalid for the captured cell.
    #[error("incident snapshot `{label}`: invalid certificate: {source}")]
    InvalidCertificate {
        /// Incident label.
        label: String,
        /// Underlying certificate validation error.
        source: CutMobilityError,
    },
    /// Rehearsal epoch must be strictly newer than the snapshot epoch.
    #[error(
        "rehearsal epoch {rehearsal_epoch:?} must be newer than snapshot epoch {snapshot_epoch:?}"
    )]
    StaleRehearsalEpoch {
        /// Requested rehearsal epoch.
        rehearsal_epoch: CellEpoch,
        /// Epoch in the incident snapshot.
        snapshot_epoch: CellEpoch,
    },
    /// The steward override produced an empty steward set.
    #[error("rehearsal `{label}`: steward_override produced an empty steward set")]
    EmptyStewardOverride {
        /// Incident label.
        label: String,
    },
}

// ---------------------------------------------------------------------------
// Certified cut lattice and reality index
// ---------------------------------------------------------------------------

/// Access/secrecy classification for indexed cuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum CutAccessClass {
    /// Default operator-visible classification.
    #[default]
    Operator,
    /// Restricted to the service that owns the cell.
    ServiceScoped,
    /// Restricted to audit/compliance review.
    AuditOnly,
}

/// Policy regime tag attached to an indexed cut.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRegime {
    /// Policy revision at the time of the cut.
    pub policy_revision: u64,
    /// Human-readable policy label (e.g., "v3-latency-strict").
    pub label: String,
}

/// Materialization state of an indexed cut entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MaterializationState {
    /// The full cut state is retained and immediately queryable.
    Materialized,
    /// The cut can be reconstructed from the certificate and cell snapshot.
    #[default]
    Reconstructible,
    /// The cut has been compacted and only metadata remains.
    Compacted,
}

/// An entry in the certified cut index tracking a single semantically
/// meaningful cut with its metadata, policy regime, and lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutIndexEntry {
    /// Unique identifier for this entry (deterministic digest of the certificate).
    pub entry_id: u64,
    /// The cut certificate this entry indexes.
    pub certificate: CutCertificate,
    /// Cell ID at the time of the cut.
    pub cell_id: CellId,
    /// Epoch at the time of the cut.
    pub epoch: CellEpoch,
    /// Policy regime active when the cut was taken.
    pub policy_regime: PolicyRegime,
    /// Access/secrecy classification.
    pub access_class: CutAccessClass,
    /// Number of live obligations at the cut.
    pub live_obligation_count: usize,
    /// Number of resolved obligations at the cut.
    pub resolved_obligation_count: usize,
    /// IDs of descendant branches (rehearsal forks, canary branches) derived from this cut.
    pub descendant_branches: Vec<u64>,
    /// Current materialization state.
    pub materialization: MaterializationState,
    /// Logical time when this entry was indexed.
    pub indexed_at: Time,
}

impl CutIndexEntry {
    /// Deterministic digest of this entry.
    #[must_use]
    pub fn entry_digest(&self) -> u64 {
        stable_hash((
            "cut-index-entry",
            self.entry_id,
            self.certificate.certificate_digest(),
            self.cell_id.raw(),
            self.epoch,
            &self.policy_regime,
        ))
    }
}

/// Retention policy controlling how long and in what form cuts are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutRetentionPolicy {
    /// Maximum number of materialized cuts to retain per cell.
    pub max_materialized_per_cell: usize,
    /// Maximum age (in logical time nanos) before a cut is compacted.
    pub max_age_nanos: u64,
    /// Minimum number of cuts to keep regardless of age (prevents total eviction).
    pub min_retained_per_cell: usize,
}

impl Default for CutRetentionPolicy {
    fn default() -> Self {
        Self {
            max_materialized_per_cell: 64,
            max_age_nanos: 3_600_000_000_000, // 1 hour in nanos
            min_retained_per_cell: 2,
        }
    }
}

/// Query predicate for searching the cut index.
#[derive(Debug, Clone, Default)]
pub struct CutIndexQuery {
    /// Filter by cell ID.
    pub cell_id: Option<CellId>,
    /// Filter by time range (inclusive lower bound).
    pub after: Option<Time>,
    /// Filter by time range (inclusive upper bound).
    pub before: Option<Time>,
    /// Filter by policy regime label.
    pub policy_label: Option<String>,
    /// Filter by access class (at most this classification).
    pub max_access_class: Option<CutAccessClass>,
    /// Only return cuts that cover this specific obligation.
    pub covers_obligation: Option<ObligationId>,
    /// Only return materialized entries.
    pub materialized_only: bool,
    /// Maximum number of results to return (0 = unlimited).
    pub limit: usize,
}

/// A policy-scoped, retained index of semantically meaningful certified cuts.
///
/// The index enables queries like:
/// - "attach to latest cut causally before incident X"
/// - "fork canary from last certified cut under policy Y"
/// - "show smallest cut explaining this user-visible outcome"
/// - "restore only subtree whose obligations can still be lawfully resumed"
///
/// Retention is bounded: the index applies compaction and materialization
/// policies so it does not grow without bound.
#[derive(Debug, Clone)]
pub struct CutLatticeIndex {
    entries: Vec<CutIndexEntry>,
    retention: CutRetentionPolicy,
}

impl CutLatticeIndex {
    /// Create a new empty index with the given retention policy.
    #[must_use]
    pub fn new(retention: CutRetentionPolicy) -> Self {
        Self {
            entries: Vec::new(),
            retention,
        }
    }

    /// Create a new index with the default retention policy.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(CutRetentionPolicy::default())
    }

    /// Index a new cut certificate with its associated metadata.
    ///
    /// If an entry with the same certificate digest already exists, the
    /// existing entry is returned without modification (idempotent).
    pub fn index_cut(
        &mut self,
        certificate: CutCertificate,
        policy_regime: PolicyRegime,
        access_class: CutAccessClass,
        live_obligation_count: usize,
        resolved_obligation_count: usize,
        indexed_at: Time,
    ) -> u64 {
        let entry_id = certificate.certificate_digest();

        // Idempotent: if we already have this certificate, return its ID.
        if self.entries.iter().any(|e| e.entry_id == entry_id) {
            return entry_id;
        }

        let cell_id = certificate.cell_id;
        let epoch = certificate.epoch;

        let entry = CutIndexEntry {
            entry_id,
            certificate,
            cell_id,
            epoch,
            policy_regime,
            access_class,
            live_obligation_count,
            resolved_obligation_count,
            descendant_branches: Vec::new(),
            materialization: MaterializationState::Materialized,
            indexed_at,
        };

        self.entries.push(entry);
        entry_id
    }

    /// Register a descendant branch (fork/rehearsal) against an existing cut entry.
    pub fn register_descendant(&mut self, entry_id: u64, branch_digest: u64) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.entry_id == entry_id) {
            if !entry.descendant_branches.contains(&branch_digest) {
                entry.descendant_branches.push(branch_digest);
            }
            true
        } else {
            false
        }
    }

    /// Query the index with the given predicate.
    #[must_use]
    pub fn query(&self, q: &CutIndexQuery) -> Vec<&CutIndexEntry> {
        let mut results: Vec<&CutIndexEntry> = self
            .entries
            .iter()
            .filter(|e| {
                if let Some(cell_id) = q.cell_id {
                    if e.cell_id != cell_id {
                        return false;
                    }
                }
                if let Some(after) = q.after {
                    if e.certificate.timestamp < after {
                        return false;
                    }
                }
                if let Some(before) = q.before {
                    if e.certificate.timestamp > before {
                        return false;
                    }
                }
                if let Some(ref label) = q.policy_label {
                    if &e.policy_regime.label != label {
                        return false;
                    }
                }
                if let Some(max_class) = q.max_access_class {
                    if e.access_class > max_class {
                        return false;
                    }
                }
                if let Some(obligation) = q.covers_obligation {
                    if !e.certificate.covers_obligation(obligation) {
                        return false;
                    }
                }
                if q.materialized_only && e.materialization != MaterializationState::Materialized {
                    return false;
                }
                true
            })
            .collect();

        // Sort by timestamp descending (most recent first).
        results.sort_by(|a, b| {
            b.certificate
                .timestamp
                .as_nanos()
                .cmp(&a.certificate.timestamp.as_nanos())
        });

        if q.limit > 0 {
            results.truncate(q.limit);
        }

        results
    }

    /// Return the most recent materialized cut for the given cell, or `None`.
    #[must_use]
    pub fn latest_for_cell(&self, cell_id: CellId) -> Option<&CutIndexEntry> {
        self.query(&CutIndexQuery {
            cell_id: Some(cell_id),
            materialized_only: true,
            limit: 1,
            ..Default::default()
        })
        .into_iter()
        .next()
    }

    /// Return the most recent cut taken under the given policy label.
    #[must_use]
    pub fn latest_for_policy(&self, policy_label: &str) -> Option<&CutIndexEntry> {
        self.query(&CutIndexQuery {
            policy_label: Some(policy_label.to_owned()),
            limit: 1,
            ..Default::default()
        })
        .into_iter()
        .next()
    }

    /// Total number of entries in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Apply retention policy: compact old entries, dematerialize excess entries.
    ///
    /// Returns the number of entries compacted.
    pub fn compact(&mut self, current_time: Time) -> usize {
        let mut compacted = 0;

        // Group entries by cell_id for per-cell retention enforcement.
        let mut cell_ids: Vec<CellId> = self.entries.iter().map(|e| e.cell_id).collect();
        cell_ids.sort_unstable();
        cell_ids.dedup();

        for cell_id in &cell_ids {
            // Collect indices for this cell, sorted by timestamp descending.
            let mut cell_indices: Vec<usize> = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| &e.cell_id == cell_id)
                .map(|(i, _)| i)
                .collect();
            cell_indices.sort_by(|&a, &b| {
                self.entries[b]
                    .certificate
                    .timestamp
                    .as_nanos()
                    .cmp(&self.entries[a].certificate.timestamp.as_nanos())
            });

            // Only rank non-compacted entries so that previously compacted
            // entries don't consume rank slots and cause over-aggressive eviction.
            let active_indices: Vec<usize> = cell_indices
                .iter()
                .copied()
                .filter(|&idx| self.entries[idx].materialization != MaterializationState::Compacted)
                .collect();

            for (rank, &idx) in active_indices.iter().enumerate() {
                let age_nanos = current_time
                    .as_nanos()
                    .saturating_sub(self.entries[idx].indexed_at.as_nanos());
                let exceeds_age = age_nanos > self.retention.max_age_nanos;
                let exceeds_count = rank >= self.retention.max_materialized_per_cell;

                if (exceeds_age || exceeds_count) && rank >= self.retention.min_retained_per_cell {
                    self.entries[idx].materialization = MaterializationState::Compacted;
                    compacted += 1;
                } else if rank >= self.retention.max_materialized_per_cell
                    && rank < self.retention.min_retained_per_cell
                {
                    // Dematerialize but keep metadata.
                    if self.entries[idx].materialization == MaterializationState::Materialized {
                        self.entries[idx].materialization = MaterializationState::Reconstructible;
                    }
                }
            }
        }

        // Evict extremely old compacted entries entirely to prevent unbounded memory growth.
        // We use 2x max_age_nanos as the threshold for complete deletion.
        self.entries.retain(|e| {
            let age_nanos = current_time
                .as_nanos()
                .saturating_sub(e.indexed_at.as_nanos());
            !(e.materialization == MaterializationState::Compacted
                && age_nanos > self.retention.max_age_nanos.saturating_mul(2))
        });

        compacted
    }

    /// Materialize a previously reconstructible entry (no-op if already materialized).
    pub fn materialize(&mut self, entry_id: u64) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.entry_id == entry_id) {
            if entry.materialization == MaterializationState::Reconstructible {
                entry.materialization = MaterializationState::Materialized;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Branch-addressable reality
// ---------------------------------------------------------------------------

/// Type of addressable branch within the hosted boundary.
///
/// Each branch type maps to a different operational workflow:
/// - **Live**: the current production reality
/// - **Lagged**: a certified cut trailing live by a bounded delay
/// - **Replayed**: a past incident replayed under alternative policy
/// - **Canary**: a sandboxed fork for evaluating policy changes on real state
/// - **Forensic**: a frozen branch for post-hoc "explain this outcome" analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BranchType {
    /// The current production reality.
    Live,
    /// A certified cut trailing live by a bounded delay.
    Lagged,
    /// A past incident replayed under alternative policy.
    Replayed,
    /// A sandboxed fork for evaluating policy changes on real state.
    Canary,
    /// A frozen branch for post-hoc forensic analysis.
    Forensic,
}

impl BranchType {
    /// Whether this branch type allows mutations by default.
    #[must_use]
    pub const fn default_mutable(self) -> bool {
        matches!(self, Self::Live | Self::Canary)
    }

    /// Whether this branch type is fenced from production side effects.
    #[must_use]
    pub const fn is_fenced(self) -> bool {
        !matches!(self, Self::Live)
    }
}

/// Access policy governing what operations are permitted on a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BranchAccessPolicy {
    /// Read-only observation — no mutations allowed.
    ReadOnly,
    /// Sandboxed mutations — writes are captured but never propagate to live.
    Sandboxed,
    /// Full read-write access (only valid for Live branches).
    ReadWrite,
}

impl BranchAccessPolicy {
    /// Whether this policy permits writes.
    #[must_use]
    pub const fn allows_writes(self) -> bool {
        matches!(self, Self::Sandboxed | Self::ReadWrite)
    }

    /// Whether writes under this policy propagate to the live branch.
    #[must_use]
    pub const fn propagates_to_live(self) -> bool {
        matches!(self, Self::ReadWrite)
    }
}

/// An addressable branch within the hosted boundary, tied to a certified cut
/// and a specific policy context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchAddress {
    /// Unique identifier for this branch (deterministic from type + cut + policy).
    pub branch_id: u64,
    /// Type of this branch.
    pub branch_type: BranchType,
    /// Cut index entry ID this branch is rooted at (or 0 for Live).
    pub cut_entry_id: u64,
    /// Cell this branch addresses.
    pub cell_id: CellId,
    /// Policy override applied to this branch (empty string = inherit from cut).
    pub policy_label: String,
    /// Access policy governing this branch.
    pub access_policy: BranchAccessPolicy,
    /// Human-readable description.
    pub description: String,
    /// Logical time when the branch was created.
    pub created_at: Time,
}

impl BranchAddress {
    /// Create a new branch address.
    fn new(
        branch_type: BranchType,
        cut_entry_id: u64,
        cell_id: CellId,
        policy_label: impl Into<String>,
        access_policy: BranchAccessPolicy,
        description: impl Into<String>,
        created_at: Time,
    ) -> Self {
        let policy_label = policy_label.into();
        let description = description.into();
        let branch_id = stable_hash((
            "branch-address",
            branch_type,
            cut_entry_id,
            cell_id.raw(),
            &policy_label,
        ));
        Self {
            branch_id,
            branch_type,
            cut_entry_id,
            cell_id,
            policy_label,
            access_policy,
            description,
            created_at,
        }
    }

    /// Deterministic digest of this branch address.
    #[must_use]
    pub fn address_digest(&self) -> u64 {
        self.branch_id
    }
}

/// Error type for branch registry operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchError {
    /// ReadWrite access is only valid for Live branches.
    ReadWriteOnNonLive {
        /// The branch type that was requested.
        branch_type: BranchType,
    },
    /// The referenced cut entry was not found in the index.
    CutNotFound {
        /// The entry ID that was not found.
        entry_id: u64,
    },
    /// Branch with this ID already exists.
    DuplicateBranch {
        /// The duplicate branch ID.
        branch_id: u64,
    },
}

impl std::fmt::Display for BranchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadWriteOnNonLive { branch_type } => {
                write!(f, "ReadWrite access not allowed on {branch_type:?} branch")
            }
            Self::CutNotFound { entry_id } => {
                write!(f, "cut entry {entry_id} not found in index")
            }
            Self::DuplicateBranch { branch_id } => {
                write!(f, "branch {branch_id} already exists")
            }
        }
    }
}

impl std::error::Error for BranchError {}

/// Registry of addressable branches for a cell.
///
/// Manages the lifecycle of branches: creation, lookup, and teardown.
/// Non-operator workflows default to read-only; only Live branches get
/// ReadWrite access.
#[derive(Debug, Clone)]
pub struct BranchRegistry {
    branches: Vec<BranchAddress>,
}

impl BranchRegistry {
    /// Create a new empty branch registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            branches: Vec::new(),
        }
    }

    /// Create the canonical Live branch for a cell.
    pub fn create_live(
        &mut self,
        cell_id: CellId,
        created_at: Time,
    ) -> Result<&BranchAddress, BranchError> {
        let branch = BranchAddress::new(
            BranchType::Live,
            0,
            cell_id,
            "",
            BranchAccessPolicy::ReadWrite,
            "live production branch",
            created_at,
        );
        self.insert(branch)
    }

    /// Create a lagged branch tracking a certified cut.
    pub fn create_lagged(
        &mut self,
        cut_entry_id: u64,
        cell_id: CellId,
        description: impl Into<String>,
        created_at: Time,
        index: &CutLatticeIndex,
    ) -> Result<&BranchAddress, BranchError> {
        Self::require_cut_exists(cut_entry_id, index)?;
        let branch = BranchAddress::new(
            BranchType::Lagged,
            cut_entry_id,
            cell_id,
            "",
            BranchAccessPolicy::ReadOnly,
            description,
            created_at,
        );
        self.insert(branch)
    }

    /// Create a replayed branch from a certified cut under alternative policy.
    pub fn create_replayed(
        &mut self,
        cut_entry_id: u64,
        cell_id: CellId,
        policy_label: impl Into<String>,
        description: impl Into<String>,
        created_at: Time,
        index: &CutLatticeIndex,
    ) -> Result<&BranchAddress, BranchError> {
        Self::require_cut_exists(cut_entry_id, index)?;
        let branch = BranchAddress::new(
            BranchType::Replayed,
            cut_entry_id,
            cell_id,
            policy_label,
            BranchAccessPolicy::ReadOnly,
            description,
            created_at,
        );
        self.insert(branch)
    }

    /// Create a canary branch — sandboxed mutations fenced from production.
    pub fn create_canary(
        &mut self,
        cut_entry_id: u64,
        cell_id: CellId,
        policy_label: impl Into<String>,
        description: impl Into<String>,
        created_at: Time,
        index: &CutLatticeIndex,
    ) -> Result<&BranchAddress, BranchError> {
        Self::require_cut_exists(cut_entry_id, index)?;
        let branch = BranchAddress::new(
            BranchType::Canary,
            cut_entry_id,
            cell_id,
            policy_label,
            BranchAccessPolicy::Sandboxed,
            description,
            created_at,
        );
        self.insert(branch)
    }

    /// Create a forensic branch — frozen, read-only, for post-hoc analysis.
    pub fn create_forensic(
        &mut self,
        cut_entry_id: u64,
        cell_id: CellId,
        description: impl Into<String>,
        created_at: Time,
        index: &CutLatticeIndex,
    ) -> Result<&BranchAddress, BranchError> {
        Self::require_cut_exists(cut_entry_id, index)?;
        let branch = BranchAddress::new(
            BranchType::Forensic,
            cut_entry_id,
            cell_id,
            "",
            BranchAccessPolicy::ReadOnly,
            description,
            created_at,
        );
        self.insert(branch)
    }

    /// Look up a branch by ID.
    #[must_use]
    pub fn get(&self, branch_id: u64) -> Option<&BranchAddress> {
        self.branches.iter().find(|b| b.branch_id == branch_id)
    }

    /// Look up the Live branch for a cell.
    #[must_use]
    pub fn live_for_cell(&self, cell_id: CellId) -> Option<&BranchAddress> {
        self.branches
            .iter()
            .find(|b| b.branch_type == BranchType::Live && b.cell_id == cell_id)
    }

    /// List all branches for a cell.
    #[must_use]
    pub fn branches_for_cell(&self, cell_id: CellId) -> Vec<&BranchAddress> {
        self.branches
            .iter()
            .filter(|b| b.cell_id == cell_id)
            .collect()
    }

    /// List all branches of a given type.
    #[must_use]
    pub fn branches_of_type(&self, branch_type: BranchType) -> Vec<&BranchAddress> {
        self.branches
            .iter()
            .filter(|b| b.branch_type == branch_type)
            .collect()
    }

    /// Total number of registered branches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.branches.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    /// Remove a branch by ID. Returns true if found and removed.
    pub fn remove(&mut self, branch_id: u64) -> bool {
        let before = self.branches.len();
        self.branches.retain(|b| b.branch_id != branch_id);
        self.branches.len() < before
    }

    fn require_cut_exists(entry_id: u64, index: &CutLatticeIndex) -> Result<(), BranchError> {
        if index.entries.iter().any(|e| e.entry_id == entry_id) {
            Ok(())
        } else {
            Err(BranchError::CutNotFound { entry_id })
        }
    }

    fn insert(&mut self, branch: BranchAddress) -> Result<&BranchAddress, BranchError> {
        if self
            .branches
            .iter()
            .any(|b| b.branch_id == branch.branch_id)
        {
            return Err(BranchError::DuplicateBranch {
                branch_id: branch.branch_id,
            });
        }
        self.branches.push(branch);
        Ok(self.branches.last().expect("just pushed"))
    }
}

impl Default for BranchRegistry {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn evacuation_carries_obligation_frontier_proof() {
        let cell = test_cell();
        let certificate = cell
            .issue_cut_certificate(
                [obligation(7), obligation(3), obligation(7)],
                ConsumerStateDigest::new(0xfeed_cafe),
                Time::from_secs(9),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::Evacuate {
                    from: NodeId::new("node-a"),
                    to: NodeId::new("node-b"),
                },
            )
            .expect("evacuation proof");

        assert_eq!(
            certificate.obligation_frontier,
            vec![obligation(3), obligation(7)]
        );
        assert!(certificate.covers_obligation(obligation(3)));
        assert_eq!(
            proof.obligation_frontier_digest,
            certificate.obligation_frontier_digest()
        );
        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("node-b"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.first(),
            Some(&NodeId::new("node-b"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.last(),
            Some(&NodeId::new("node-a"))
        );
        assert_eq!(
            proof
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            cell.control_capsule.sequencer_lease_generation + 1
        );
    }

    #[test]
    fn handoff_uses_explicit_cut_certificate() {
        let cell = test_cell();
        let certificate = cell
            .issue_cut_certificate(
                [obligation(10)],
                ConsumerStateDigest::new(0x1234),
                Time::from_secs(11),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::Handoff {
                    from: NodeId::new("node-a"),
                    to: NodeId::new("node-c"),
                },
            )
            .expect("handoff proof");

        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("node-c"))
        );
        assert_eq!(proof.resulting_cell.steward_set, cell.steward_set);
        assert_eq!(
            proof.resulting_cell.control_capsule.steward_pool,
            cell.control_capsule.steward_pool
        );
        assert_eq!(
            proof.resulting_cell.control_capsule.policy_revision,
            cell.control_capsule.policy_revision + 1
        );
    }

    #[test]
    fn warm_restore_rebinds_epoch_and_cell_id_from_capsule() {
        let cell = test_cell();
        let restored_epoch = CellEpoch::new(8, 1);
        let certificate = cell
            .issue_cut_certificate(
                [obligation(2)],
                ConsumerStateDigest::new(0xface_b00c),
                Time::from_secs(13),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::WarmRestore {
                    target: NodeId::new("edge-restore"),
                    restored_epoch,
                    capsule_digest: CapsuleDigest::new(0x9abc),
                },
            )
            .expect("warm restore proof");

        assert_eq!(proof.resulting_cell.epoch, restored_epoch);
        assert_eq!(
            proof.resulting_cell.cell_id,
            CellId::for_partition(restored_epoch, &cell.subject_partition)
        );
        assert_ne!(proof.resulting_cell.cell_id, cell.cell_id);
        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("edge-restore"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.first(),
            Some(&NodeId::new("edge-restore"))
        );
    }

    #[test]
    fn failover_removes_failed_steward_and_promotes_replacement() {
        let cell = test_cell();
        let certificate = cell
            .issue_cut_certificate(
                [obligation(1), obligation(4)],
                ConsumerStateDigest::new(0x2222),
                Time::from_secs(21),
                NodeId::new("node-b"),
            )
            .expect("certificate");

        let proof = cell
            .certify_mobility(
                &certificate,
                &MobilityOperation::Failover {
                    failed: NodeId::new("node-a"),
                    promote_to: NodeId::new("node-c"),
                },
            )
            .expect("failover proof");

        assert_eq!(
            proof.resulting_cell.control_capsule.active_sequencer,
            Some(NodeId::new("node-c"))
        );
        assert!(
            !proof
                .resulting_cell
                .steward_set
                .contains(&NodeId::new("node-a"))
        );
        assert!(
            !proof
                .resulting_cell
                .control_capsule
                .steward_pool
                .contains(&NodeId::new("node-a"))
        );
        assert_eq!(
            proof.resulting_cell.steward_set.first(),
            Some(&NodeId::new("node-c"))
        );
        assert_eq!(
            proof
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            cell.control_capsule.sequencer_lease_generation + 1
        );
    }

    #[test]
    fn warm_restore_rejects_missing_capsule_or_consumer_state() {
        let cell = test_cell();
        let empty_certificate = cell
            .issue_cut_certificate(
                [],
                ConsumerStateDigest::ZERO,
                Time::from_secs(14),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let err = cell
            .certify_mobility(
                &empty_certificate,
                &MobilityOperation::WarmRestore {
                    target: NodeId::new("edge-restore"),
                    restored_epoch: CellEpoch::new(9, 1),
                    capsule_digest: CapsuleDigest::ZERO,
                },
            )
            .expect_err("restore without state must fail");

        assert_eq!(err, CutMobilityError::MissingConsumerStateDigest);
    }

    // -----------------------------------------------------------------------
    // Incident rehearsal tests
    // -----------------------------------------------------------------------

    fn make_snapshot() -> (SubjectCell, CutCertificate, IncidentSnapshot) {
        let cell = test_cell();
        let cert = cell
            .issue_cut_certificate(
                [obligation(5), obligation(10)],
                ConsumerStateDigest::new(0xdead),
                Time::from_secs(100),
                NodeId::new("node-a"),
            )
            .expect("certificate");

        let snap = IncidentSnapshot::capture(
            &cell,
            &cert,
            MobilityOperation::Evacuate {
                from: NodeId::new("node-a"),
                to: NodeId::new("node-b"),
            },
            "test-outage-1",
            Time::from_secs(100),
        )
        .expect("snapshot");

        (cell, cert, snap)
    }

    #[test]
    fn incident_snapshot_captures_cell_and_certificate() {
        let (cell, cert, snap) = make_snapshot();
        assert_eq!(snap.cell.cell_id, cell.cell_id);
        assert_eq!(
            snap.certificate.certificate_digest(),
            cert.certificate_digest()
        );
        assert_eq!(snap.label, "test-outage-1");
    }

    #[test]
    fn incident_snapshot_digest_is_deterministic() {
        let (_, _, snap1) = make_snapshot();
        let (_, _, snap2) = make_snapshot();
        assert_eq!(snap1.snapshot_digest(), snap2.snapshot_digest());
    }

    #[test]
    fn incident_snapshot_rejects_invalid_certificate() {
        let cell = test_cell();
        let bad_cert = CutCertificate {
            cell_id: cell.cell_id,
            epoch: CellEpoch::new(99, 99),
            obligation_frontier: vec![],
            consumer_state_digest: ConsumerStateDigest::ZERO,
            timestamp: Time::from_secs(1),
            signer: NodeId::new("node-a"),
        };

        let err = IncidentSnapshot::capture(
            &cell,
            &bad_cert,
            MobilityOperation::Evacuate {
                from: NodeId::new("node-a"),
                to: NodeId::new("node-b"),
            },
            "bad-cert",
            Time::from_secs(1),
        )
        .expect_err("should reject mismatched cert");

        assert!(matches!(err, RehearsalError::InvalidCertificate { .. }));
    }

    #[test]
    fn replay_original_produces_same_result_as_direct_certify() {
        let (cell, cert, snap) = make_snapshot();

        let direct = snap
            .original_operation
            .certify(&cell, &cert)
            .expect("direct");
        let replayed = snap.replay_original().expect("replayed");

        assert_eq!(
            direct.resulting_cell.control_capsule.active_sequencer,
            replayed.resulting_cell.control_capsule.active_sequencer,
        );
        assert_eq!(direct.mobility_digest(), replayed.mobility_digest());
    }

    #[test]
    fn fork_rehearsal_rebases_epoch_and_cell_id() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), rehearsal_epoch)
            .expect("fork");

        assert_eq!(fork.forked_cell.epoch, rehearsal_epoch);
        assert_ne!(fork.forked_cell.cell_id, snap.cell.cell_id);
        assert_eq!(fork.forked_certificate.epoch, rehearsal_epoch);
        assert_eq!(fork.forked_certificate.cell_id, fork.forked_cell.cell_id);
        assert_eq!(fork.snapshot_digest, snap.snapshot_digest());
    }

    #[test]
    fn fork_rehearsal_rejects_stale_epoch() {
        let (_, _, snap) = make_snapshot();
        let stale = snap.cell.epoch;

        let err = snap
            .fork_rehearsal(RehearsalPolicy::default(), stale)
            .expect_err("stale epoch must fail");

        assert!(matches!(err, RehearsalError::StaleRehearsalEpoch { .. }));
    }

    #[test]
    fn fork_with_steward_override_replaces_steward_set() {
        let (_, _, snap) = make_snapshot();
        let new_stewards = vec![
            NodeId::new("node-x"),
            NodeId::new("node-y"),
            NodeId::new("node-z"),
        ];

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(new_stewards.clone()),
                    description: "different steward set".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        assert_eq!(fork.forked_cell.steward_set, new_stewards);
        assert_eq!(fork.forked_cell.control_capsule.steward_pool, new_stewards);
        // The original signer (node-a) is NOT in the new steward set.
        // The forked certificate must adapt the signer to node-x so
        // replay validation does not reject the certificate.
        assert_eq!(fork.forked_certificate.signer, NodeId::new("node-x"));
    }

    #[test]
    fn fork_with_steward_override_that_excludes_signer_still_replays() {
        let (_, _, snap) = make_snapshot();
        let new_stewards = vec![NodeId::new("node-x"), NodeId::new("node-y")];

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(new_stewards),
                    description: "entirely new steward set".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork with replaced signers");

        // Replay an evacuation from node-x to node-y in the forked steward set.
        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-x"),
            to: NodeId::new("node-y"),
        });
        assert!(
            outcome.succeeded(),
            "rehearsal with completely replaced steward set must succeed"
        );
    }

    #[test]
    fn fork_with_data_capsule_override() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    data_capsule_override: Some(DataCapsule {
                        temperature: CellTemperature::Hot,
                        retained_message_blocks: 16,
                    }),
                    description: "hot temperature rehearsal".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        assert_eq!(
            fork.forked_cell.data_capsule.temperature,
            CellTemperature::Hot
        );
        assert_eq!(fork.forked_cell.data_capsule.retained_message_blocks, 16);
    }

    #[test]
    fn rehearsal_replay_succeeds_with_same_operation() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), rehearsal_epoch)
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-b"),
        });

        assert!(outcome.succeeded());
        let resulting = outcome.resulting_cell().expect("cell");
        assert_eq!(
            resulting.control_capsule.active_sequencer,
            Some(NodeId::new("node-b"))
        );
    }

    #[test]
    fn rehearsal_replay_with_different_operation() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), rehearsal_epoch)
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Handoff {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-c"),
        });

        assert!(outcome.succeeded());
        assert_eq!(
            outcome
                .resulting_cell()
                .expect("cell")
                .control_capsule
                .active_sequencer,
            Some(NodeId::new("node-c"))
        );
    }

    #[test]
    fn rehearsal_replay_captures_failure() {
        let (_, _, snap) = make_snapshot();
        let rehearsal_epoch = CellEpoch::new(10, 1);

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![NodeId::new("node-a"), NodeId::new("node-c")]),
                    description: "steward set without node-b".to_owned(),
                    ..Default::default()
                },
                rehearsal_epoch,
            )
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-b"),
        });

        assert!(!outcome.succeeded());
    }

    #[test]
    fn comparison_detects_cell_drift() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");

        let rehearsal_outcome = fork.replay(&snap.original_operation);

        let comparison =
            RehearsalComparison::compare(&snap, rehearsal_outcome).expect("comparison");

        // Not equivalent because epoch/cell_id differ (forked branch has new epoch).
        assert!(!comparison.is_equivalent());
        match &comparison.divergence {
            RehearsalDivergence::CellDrift { differences } => {
                assert!(differences.contains(&"cell_id".to_owned()));
                assert!(differences.contains(&"epoch".to_owned()));
            }
            other => panic!("expected CellDrift, got {other:?}"),
        }
    }

    #[test]
    fn comparison_detects_rehearsal_failure() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![NodeId::new("node-a"), NodeId::new("node-c")]),
                    description: "no node-b".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let rehearsal_outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-b"),
        });

        let comparison =
            RehearsalComparison::compare(&snap, rehearsal_outcome).expect("comparison");

        assert!(matches!(
            comparison.divergence,
            RehearsalDivergence::RehearsalFailed { .. }
        ));
    }

    #[test]
    fn comparison_digest_is_deterministic() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&snap.original_operation);
        let c1 = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let fork2 = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome2 = fork2.replay(&snap.original_operation);
        let c2 = RehearsalComparison::compare(&snap, outcome2).expect("comparison");

        assert_eq!(c1.comparison_digest(), c2.comparison_digest());
    }

    #[test]
    fn fork_digest_is_deterministic() {
        let (_, _, snap) = make_snapshot();
        let fork1 = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork1");
        let fork2 = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork2");
        assert_eq!(fork1.fork_digest(), fork2.fork_digest());
    }

    #[test]
    fn rehearsal_with_repair_policy_override() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    repair_override: Some(RepairPolicy {
                        recoverability_target: 5,
                        cold_witnesses: 10,
                        hot_witnesses: 10,
                    }),
                    description: "aggressive repair".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        assert_eq!(fork.forked_cell.repair_policy.recoverability_target, 5);
        assert_eq!(fork.forked_cell.repair_policy.cold_witnesses, 10);

        let outcome = fork.replay(&snap.original_operation);
        assert!(outcome.succeeded());
    }

    #[test]
    fn end_to_end_rehearsal_workflow() {
        // Simulate: "Replay this failover with a different steward set."
        let cell = test_cell();
        let cert = cell
            .issue_cut_certificate(
                [obligation(1), obligation(2), obligation(3)],
                ConsumerStateDigest::new(0xbeef),
                Time::from_secs(200),
                NodeId::new("node-b"),
            )
            .expect("certificate");

        let snap = IncidentSnapshot::capture(
            &cell,
            &cert,
            MobilityOperation::Failover {
                failed: NodeId::new("node-a"),
                promote_to: NodeId::new("node-c"),
            },
            "failover-incident-2026-03-20",
            Time::from_secs(200),
        )
        .expect("snapshot");

        // Question: "What if we had node-d available instead of node-c?"
        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![
                        NodeId::new("node-a"),
                        NodeId::new("node-b"),
                        NodeId::new("node-d"),
                    ]),
                    description: "failover with node-d instead of node-c".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-d"),
        });

        assert!(outcome.succeeded());
        assert_eq!(
            outcome
                .resulting_cell()
                .expect("cell")
                .control_capsule
                .active_sequencer,
            Some(NodeId::new("node-d"))
        );

        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");
        assert!(!comparison.is_equivalent());

        match &comparison.divergence {
            RehearsalDivergence::CellDrift { differences } => {
                assert!(differences.contains(&"active_sequencer".to_owned()));
                assert!(differences.contains(&"steward_set".to_owned()));
            }
            other => panic!("expected CellDrift, got {other:?}"),
        }
    }

    #[test]
    fn promotion_accepts_rehearsal_that_beats_failed_original_within_envelope() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    steward_override: Some(vec![
                        NodeId::new("node-a"),
                        NodeId::new("node-b"),
                        NodeId::new("node-d"),
                    ]),
                    description: "recover with node-d".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let outcome = fork.replay(&MobilityOperation::Evacuate {
            from: NodeId::new("node-a"),
            to: NodeId::new("node-d"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.1,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.8,
                evidence_confidence: 0.95,
                violation_rate: 0.1,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    min_stewards: 2,
                    max_stewards: 4,
                    min_repair_depth: 1,
                    max_repair_depth: 4,
                    evidence_threshold: 0.8,
                    rollback_violation_threshold: 0.2,
                    ..SafetyEnvelope::default()
                },
                max_temperature: CellTemperature::Warm,
                max_retained_message_blocks: 8,
                max_cold_witnesses: 2,
                max_hot_witnesses: 4,
            },
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::Promote { .. }
        ));
    }

    #[test]
    fn promotion_rejects_candidate_below_evidence_threshold() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&snap.original_operation);
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.7,
                evidence_confidence: 0.4,
                violation_rate: 0.1,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    evidence_threshold: 0.8,
                    ..SafetyEnvelope::default()
                },
                ..Default::default()
            },
        );

        assert_eq!(
            decision,
            CounterfactualPromotionDecision::RejectInsufficientEvidence {
                observed: 0.4,
                required: 0.8,
            }
        );
    }

    #[test]
    fn promotion_rejects_candidate_outside_safety_envelope() {
        let (_, _, snap) = make_snapshot();

        let fork = snap
            .fork_rehearsal(
                RehearsalPolicy {
                    repair_override: Some(RepairPolicy {
                        recoverability_target: 6,
                        cold_witnesses: 5,
                        hot_witnesses: 7,
                    }),
                    data_capsule_override: Some(DataCapsule {
                        temperature: CellTemperature::Hot,
                        retained_message_blocks: 32,
                    }),
                    description: "aggressive unsafe branch".to_owned(),
                    ..Default::default()
                },
                CellEpoch::new(10, 1),
            )
            .expect("fork");

        let outcome = fork.replay(&snap.original_operation);
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.9,
                evidence_confidence: 0.95,
                violation_rate: 0.1,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    min_repair_depth: 1,
                    max_repair_depth: 4,
                    evidence_threshold: 0.8,
                    rollback_violation_threshold: 0.2,
                    ..SafetyEnvelope::default()
                },
                max_temperature: CellTemperature::Warm,
                max_retained_message_blocks: 8,
                max_cold_witnesses: 2,
                max_hot_witnesses: 4,
            },
        );

        match decision {
            CounterfactualPromotionDecision::RejectEnvelopeViolation { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("recoverability_target")));
                assert!(reasons.iter().any(|r| r.contains("temperature")));
                assert!(
                    reasons
                        .iter()
                        .any(|r| r.contains("retained_message_blocks"))
                );
                assert!(reasons.iter().any(|r| r.contains("cold_witnesses")));
                assert!(reasons.iter().any(|r| r.contains("hot_witnesses")));
            }
            other => panic!("expected RejectEnvelopeViolation, got {other:?}"),
        }
    }

    #[test]
    fn promotion_rejects_candidate_with_nan_policy_gain() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-b"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: f64::NAN,
                evidence_confidence: 0.95,
                violation_rate: 0.05,
            },
            &CounterfactualPromotionEnvelope::default(),
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::RejectInvalidScore {
                field: "policy_gain",
                value,
            } if value.is_nan()
        ));
    }

    #[test]
    fn promotion_rejects_invalid_envelope_before_threshold_checks() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-b"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: 0.2,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.8,
                evidence_confidence: 0.95,
                violation_rate: 0.05,
            },
            &CounterfactualPromotionEnvelope {
                reliability: SafetyEnvelope {
                    evidence_threshold: f64::NAN,
                    ..SafetyEnvelope::default()
                },
                ..Default::default()
            },
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::RejectInvalidEnvelope {
                error: ReliabilityControlError::InvalidProbability {
                    field: "evidence_threshold",
                    value,
                },
            } if value.is_nan()
        ));
    }

    #[test]
    fn promotion_rejects_baseline_with_nan_policy_gain() {
        let (_, _, snap) = make_snapshot();
        let fork = snap
            .fork_rehearsal(RehearsalPolicy::default(), CellEpoch::new(10, 1))
            .expect("fork");
        let outcome = fork.replay(&MobilityOperation::Failover {
            failed: NodeId::new("node-a"),
            promote_to: NodeId::new("node-b"),
        });
        let comparison = RehearsalComparison::compare(&snap, outcome).expect("comparison");

        let decision = comparison.evaluate_promotion(
            &CounterfactualScore {
                policy_gain: f64::NAN,
                evidence_confidence: 0.9,
                violation_rate: 0.1,
            },
            &CounterfactualScore {
                policy_gain: 0.8,
                evidence_confidence: 0.95,
                violation_rate: 0.05,
            },
            &CounterfactualPromotionEnvelope::default(),
        );

        assert!(matches!(
            decision,
            CounterfactualPromotionDecision::RejectInvalidScore {
                field: "baseline_policy_gain",
                value,
            } if value.is_nan()
        ));
    }

    // -----------------------------------------------------------------------
    // Cut lattice index tests
    // -----------------------------------------------------------------------

    fn make_index_cert(
        cell: &SubjectCell,
        signer: &str,
        obligations: &[u32],
        time_secs: u64,
    ) -> CutCertificate {
        cell.issue_cut_certificate(
            obligations.iter().map(|&i| obligation(i)),
            ConsumerStateDigest::new(0xaaaa),
            Time::from_secs(time_secs),
            NodeId::new(signer),
        )
        .expect("certificate")
    }

    fn make_regime(rev: u64, label: &str) -> PolicyRegime {
        PolicyRegime {
            policy_revision: rev,
            label: label.to_owned(),
        }
    }

    #[test]
    fn index_cut_and_query_by_cell() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let eid = idx.index_cut(
            cert,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        assert_eq!(idx.len(), 1);
        assert!(!idx.is_empty());

        let results = idx.query(&CutIndexQuery {
            cell_id: Some(cell.cell_id),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, eid);
    }

    #[test]
    fn query_by_time_range() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        let results = idx.query(&CutIndexQuery {
            after: Some(Time::from_secs(150)),
            before: Some(Time::from_secs(250)),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].certificate.timestamp, Time::from_secs(200));
    }

    #[test]
    fn query_by_policy_label() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1], 100);
        idx.index_cut(
            cert1,
            make_regime(1, "v1-strict"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        let cert2 = make_index_cert(&cell, "node-a", &[2], 200);
        idx.index_cut(
            cert2,
            make_regime(2, "v2-relaxed"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(200),
        );

        let results = idx.query(&CutIndexQuery {
            policy_label: Some("v1-strict".to_owned()),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].policy_regime.label, "v1-strict");
    }

    #[test]
    fn query_with_obligation_filter() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[5, 10], 100);
        idx.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        let cert2 = make_index_cert(&cell, "node-a", &[20, 30], 200);
        idx.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(200),
        );

        let results = idx.query(&CutIndexQuery {
            covers_obligation: Some(obligation(10)),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert!(results[0].certificate.covers_obligation(obligation(10)));
    }

    #[test]
    fn query_respects_access_class_filter() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1], 100);
        idx.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        let cert2 = make_index_cert(&cell, "node-a", &[2], 200);
        idx.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::AuditOnly,
            1,
            0,
            Time::from_secs(200),
        );

        let results = idx.query(&CutIndexQuery {
            max_access_class: Some(CutAccessClass::Operator),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].access_class, CutAccessClass::Operator);
    }

    #[test]
    fn query_limit_truncates_results() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        for t in [100, 200, 300, 400, 500] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        let results = idx.query(&CutIndexQuery {
            limit: 2,
            ..Default::default()
        });
        assert_eq!(results.len(), 2);
        // Most recent first.
        assert_eq!(results[0].certificate.timestamp, Time::from_secs(500));
        assert_eq!(results[1].certificate.timestamp, Time::from_secs(400));
    }

    #[test]
    fn latest_for_cell_returns_most_recent() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        let latest = idx.latest_for_cell(cell.cell_id).expect("latest");
        assert_eq!(latest.certificate.timestamp, Time::from_secs(300));
    }

    #[test]
    fn latest_for_policy_returns_most_recent() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert = make_index_cert(&cell, "node-a", &[1], 100);
        idx.index_cut(
            cert,
            make_regime(1, "canary-policy"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        let result = idx.latest_for_policy("canary-policy").expect("found");
        assert_eq!(result.policy_regime.label, "canary-policy");
        assert!(idx.latest_for_policy("nonexistent").is_none());
    }

    #[test]
    fn register_descendant_branch() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert = make_index_cert(&cell, "node-a", &[1], 100);
        let eid = idx.index_cut(
            cert,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            1,
            0,
            Time::from_secs(100),
        );

        assert!(idx.register_descendant(eid, 0x1234));
        assert!(idx.register_descendant(eid, 0x5678));
        // Duplicate is idempotent.
        assert!(idx.register_descendant(eid, 0x1234));

        let entry = idx.query(&CutIndexQuery::default());
        assert_eq!(entry[0].descendant_branches, vec![0x1234, 0x5678]);

        // Nonexistent entry returns false.
        assert!(!idx.register_descendant(0xdead, 0x9999));
    }

    #[test]
    fn compact_dematerializes_old_entries() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::new(CutRetentionPolicy {
            max_materialized_per_cell: 2,
            max_age_nanos: 500_000_000_000, // 500s
            min_retained_per_cell: 1,
        });

        // Insert 4 entries at t=100, 200, 300, 400.
        for t in [100, 200, 300, 400] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        assert_eq!(idx.len(), 4);

        // Compact at t=450 — all within age, but exceeds max_materialized=2.
        let compacted = idx.compact(Time::from_secs(450));
        // Entries at rank ≥ 2 with rank ≥ min_retained=1 get compacted.
        // rank 0: t=400 (keep materialized)
        // rank 1: t=300 (keep materialized)
        // rank 2: t=200 (compact — rank ≥ max_materialized AND rank ≥ min_retained)
        // rank 3: t=100 (compact)
        assert_eq!(compacted, 2);

        let materialized = idx.query(&CutIndexQuery {
            materialized_only: true,
            ..Default::default()
        });
        assert_eq!(materialized.len(), 2);
    }

    #[test]
    fn compact_respects_min_retained() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::new(CutRetentionPolicy {
            max_materialized_per_cell: 1,
            max_age_nanos: 1, // Very aggressive age policy.
            min_retained_per_cell: 2,
        });

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        // Even with very aggressive compaction, min_retained=2 keeps 2 alive.
        let compacted = idx.compact(Time::from_secs(10_000));
        assert_eq!(compacted, 1); // Only the 3rd-oldest gets compacted.

        // The 2 most recent are not compacted.
        let all = idx.query(&CutIndexQuery::default());
        let non_compacted: Vec<_> = all
            .iter()
            .filter(|e| e.materialization != MaterializationState::Compacted)
            .collect();
        assert_eq!(non_compacted.len(), 2);
    }

    #[test]
    fn materialize_reconstructible_entry() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::new(CutRetentionPolicy {
            max_materialized_per_cell: 1,
            max_age_nanos: u64::MAX,
            min_retained_per_cell: 3,
        });

        for t in [100, 200, 300] {
            let cert = make_index_cert(&cell, "node-a", &[1], t);
            idx.index_cut(
                cert,
                make_regime(1, "v1"),
                CutAccessClass::Operator,
                1,
                0,
                Time::from_secs(t),
            );
        }

        // Compact to make older entries reconstructible.
        idx.compact(Time::from_secs(400));

        // Find a reconstructible entry.
        let all = idx.query(&CutIndexQuery::default());
        let recon = all
            .iter()
            .find(|e| e.materialization == MaterializationState::Reconstructible);
        if let Some(entry) = recon {
            let eid = entry.entry_id;
            assert!(idx.materialize(eid));

            // Verify it's now materialized.
            let refreshed = idx.query(&CutIndexQuery {
                materialized_only: true,
                ..Default::default()
            });
            assert!(refreshed.iter().any(|e| e.entry_id == eid));
        }
    }

    #[test]
    fn entry_digest_is_deterministic() {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let cert2 = make_index_cert(&cell, "node-a", &[1, 2], 100);

        let eid1 = idx.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        let eid2 = idx.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        assert_eq!(eid1, eid2);

        // Idempotent: second insert is a no-op, only 1 entry exists.
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn entry_digest_deterministic_across_indexes() {
        let cell = test_cell();
        let mut idx1 = CutLatticeIndex::with_defaults();
        let mut idx2 = CutLatticeIndex::with_defaults();

        let cert1 = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let cert2 = make_index_cert(&cell, "node-a", &[1, 2], 100);

        idx1.index_cut(
            cert1,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );
        idx2.index_cut(
            cert2,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );

        let e1 = &idx1.query(&CutIndexQuery::default())[0];
        let e2 = &idx2.query(&CutIndexQuery::default())[0];
        assert_eq!(e1.entry_digest(), e2.entry_digest());
    }

    #[test]
    fn empty_index_queries_return_none() {
        let idx = CutLatticeIndex::with_defaults();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        assert!(
            idx.latest_for_cell(CellId::for_partition(
                CellEpoch::new(1, 1),
                &SubjectPattern::parse("x").expect("pat")
            ))
            .is_none()
        );
        assert!(idx.latest_for_policy("any").is_none());
    }

    // -----------------------------------------------------------------------
    // Branch-addressable reality tests
    // -----------------------------------------------------------------------

    fn make_index_with_entry() -> (SubjectCell, CutLatticeIndex, u64) {
        let cell = test_cell();
        let mut idx = CutLatticeIndex::with_defaults();
        let cert = make_index_cert(&cell, "node-a", &[1, 2], 100);
        let eid = idx.index_cut(
            cert,
            make_regime(1, "v1"),
            CutAccessClass::Operator,
            2,
            0,
            Time::from_secs(100),
        );
        (cell, idx, eid)
    }

    #[test]
    fn branch_type_default_mutability() {
        assert!(BranchType::Live.default_mutable());
        assert!(BranchType::Canary.default_mutable());
        assert!(!BranchType::Lagged.default_mutable());
        assert!(!BranchType::Replayed.default_mutable());
        assert!(!BranchType::Forensic.default_mutable());
    }

    #[test]
    fn branch_type_fencing() {
        assert!(!BranchType::Live.is_fenced());
        assert!(BranchType::Lagged.is_fenced());
        assert!(BranchType::Replayed.is_fenced());
        assert!(BranchType::Canary.is_fenced());
        assert!(BranchType::Forensic.is_fenced());
    }

    #[test]
    fn access_policy_write_semantics() {
        assert!(!BranchAccessPolicy::ReadOnly.allows_writes());
        assert!(BranchAccessPolicy::Sandboxed.allows_writes());
        assert!(BranchAccessPolicy::ReadWrite.allows_writes());

        assert!(!BranchAccessPolicy::ReadOnly.propagates_to_live());
        assert!(!BranchAccessPolicy::Sandboxed.propagates_to_live());
        assert!(BranchAccessPolicy::ReadWrite.propagates_to_live());
    }

    #[test]
    fn create_live_branch() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        assert_eq!(branch.branch_type, BranchType::Live);
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadWrite);
        assert_eq!(branch.cell_id, cell.cell_id);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn create_lagged_branch() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_lagged(eid, cell.cell_id, "trailing live", Time::from_secs(2), &idx)
            .expect("lagged");
        assert_eq!(branch.branch_type, BranchType::Lagged);
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadOnly);
        assert_eq!(branch.cut_entry_id, eid);
    }

    #[test]
    fn create_replayed_branch() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_replayed(
                eid,
                cell.cell_id,
                "v2-strict",
                "replay under strict policy",
                Time::from_secs(3),
                &idx,
            )
            .expect("replayed");
        assert_eq!(branch.branch_type, BranchType::Replayed);
        assert_eq!(branch.policy_label, "v2-strict");
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadOnly);
    }

    #[test]
    fn create_canary_branch_is_sandboxed() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_canary(
                eid,
                cell.cell_id,
                "candidate-policy",
                "canary evaluation",
                Time::from_secs(4),
                &idx,
            )
            .expect("canary");
        assert_eq!(branch.branch_type, BranchType::Canary);
        assert_eq!(branch.access_policy, BranchAccessPolicy::Sandboxed);
        assert!(branch.access_policy.allows_writes());
        assert!(!branch.access_policy.propagates_to_live());
    }

    #[test]
    fn create_forensic_branch() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_forensic(
                eid,
                cell.cell_id,
                "explain ticket-1234",
                Time::from_secs(5),
                &idx,
            )
            .expect("forensic");
        assert_eq!(branch.branch_type, BranchType::Forensic);
        assert_eq!(branch.access_policy, BranchAccessPolicy::ReadOnly);
    }

    #[test]
    fn create_branch_rejects_missing_cut() {
        let (cell, idx, _eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let err = reg
            .create_lagged(0xdead, cell.cell_id, "orphan", Time::from_secs(6), &idx)
            .expect_err("should reject missing cut");
        assert!(matches!(err, BranchError::CutNotFound { .. }));
    }

    #[test]
    fn create_duplicate_branch_rejected() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("first");
        let err = reg
            .create_live(cell.cell_id, Time::from_secs(2))
            .expect_err("duplicate");
        assert!(matches!(err, BranchError::DuplicateBranch { .. }));
    }

    #[test]
    fn lookup_by_id() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_forensic(eid, cell.cell_id, "lookup test", Time::from_secs(7), &idx)
            .expect("forensic");
        let bid = branch.branch_id;

        assert!(reg.get(bid).is_some());
        assert!(reg.get(0xffff).is_none());
    }

    #[test]
    fn live_for_cell() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        assert!(reg.live_for_cell(cell.cell_id).is_none());

        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        assert!(reg.live_for_cell(cell.cell_id).is_some());
    }

    #[test]
    fn branches_for_cell_lists_all() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        reg.create_forensic(eid, cell.cell_id, "forensic", Time::from_secs(2), &idx)
            .expect("forensic");
        reg.create_canary(
            eid,
            cell.cell_id,
            "canary-pol",
            "canary",
            Time::from_secs(3),
            &idx,
        )
        .expect("canary");

        assert_eq!(reg.branches_for_cell(cell.cell_id).len(), 3);
    }

    #[test]
    fn branches_of_type() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg = BranchRegistry::new();
        reg.create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        reg.create_forensic(eid, cell.cell_id, "f1", Time::from_secs(2), &idx)
            .expect("f1");

        assert_eq!(reg.branches_of_type(BranchType::Live).len(), 1);
        assert_eq!(reg.branches_of_type(BranchType::Forensic).len(), 1);
        assert_eq!(reg.branches_of_type(BranchType::Canary).len(), 0);
    }

    #[test]
    fn remove_branch() {
        let cell = test_cell();
        let mut reg = BranchRegistry::new();
        let branch = reg
            .create_live(cell.cell_id, Time::from_secs(1))
            .expect("live");
        let bid = branch.branch_id;

        assert!(reg.remove(bid));
        assert!(reg.is_empty());
        assert!(!reg.remove(bid)); // idempotent
    }

    #[test]
    fn branch_address_digest_is_deterministic() {
        let (cell, idx, eid) = make_index_with_entry();
        let mut reg1 = BranchRegistry::new();
        let mut reg2 = BranchRegistry::new();

        let b1 = reg1
            .create_canary(eid, cell.cell_id, "pol", "test", Time::from_secs(1), &idx)
            .expect("b1");
        let b2 = reg2
            .create_canary(eid, cell.cell_id, "pol", "test", Time::from_secs(2), &idx)
            .expect("b2");

        // Same branch type + cut + cell + policy → same address digest
        // (created_at differs but doesn't affect the address identity).
        assert_eq!(b1.address_digest(), b2.address_digest());
    }

    #[test]
    fn empty_registry() {
        let reg = BranchRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }
}
