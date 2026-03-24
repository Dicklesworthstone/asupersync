//! Recoverable service-capsule artifacts for FABRIC.
//!
//! A recoverable service capsule ties together three explicit artifacts:
//! - the live cell and cut certificate from [`super::cut`],
//! - restore-time authority rebinding from [`super::privacy`], and
//! - compact service-state digests that are small enough to inspect and carry.
//!
//! The goal is not to serialize an entire live runtime. Instead, operators get
//! a bounded, replay-friendly artifact describing what warm state was retained
//! and how it can be lawfully restored under a fresh epoch and scrubbed
//! authority context.

use super::cut::{
    CapsuleDigest, CertifiedMobility, ConsumerStateDigest, CutCertificate, CutMobilityError,
    MobilityOperation,
};
use super::fabric::{CellEpoch, SubjectCell};
use super::privacy::{CellKeyHierarchySpec, KeyHierarchyError, RestoreScrubRequest};
use super::stream::{InMemoryStorageBackend, Stream, StreamConfig, StreamError, StreamSnapshot};
use crate::remote::NodeId;
use crate::types::{ObligationId, RegionId, Time};
use crate::util::DetHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Deterministic digest for one retained service-state section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CapsuleStateDigest(u64);

impl CapsuleStateDigest {
    /// Empty digest used when a section was not retained.
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

/// Deterministic digest for one retained local-evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EvidenceDigest(u64);

impl EvidenceDigest {
    /// Empty digest used when no evidence was retained.
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

/// Compact description of warm-restorable service state retained at a cut.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ServiceCapsuleState {
    /// Digest of retained stream-window state.
    pub stream_window_digest: CapsuleStateDigest,
    /// Digest of retained consumer-cursor state.
    pub consumer_cursor_digest: CapsuleStateDigest,
    /// Digest of retained supervisor state.
    pub supervisor_state_digest: CapsuleStateDigest,
    /// Digest of retained read-model state.
    pub read_model_digest: CapsuleStateDigest,
    /// Digest of retained cache state.
    pub cache_digest: CapsuleStateDigest,
    /// Canonicalized frontier of local evidence retained with the capsule.
    pub local_evidence_frontier: Vec<EvidenceDigest>,
    /// Whether the captured service has been explicitly hibernated.
    pub hibernated: bool,
}

impl ServiceCapsuleState {
    /// Build a bounded service-state capture from its retained digests.
    #[must_use]
    pub fn new(
        stream_window_digest: CapsuleStateDigest,
        consumer_cursor_digest: CapsuleStateDigest,
        supervisor_state_digest: CapsuleStateDigest,
        read_model_digest: CapsuleStateDigest,
        cache_digest: CapsuleStateDigest,
        local_evidence_frontier: impl IntoIterator<Item = EvidenceDigest>,
    ) -> Self {
        Self {
            stream_window_digest,
            consumer_cursor_digest,
            supervisor_state_digest,
            read_model_digest,
            cache_digest,
            local_evidence_frontier: canonicalize_evidence_frontier(local_evidence_frontier),
            hibernated: false,
        }
    }

    /// Return a copy marked as hibernated and ready for warm restore.
    #[must_use]
    pub fn hibernate(&self) -> Self {
        let mut next = self.clone();
        next.hibernated = true;
        next
    }

    /// Return a copy marked as resumed after a successful restore.
    #[must_use]
    pub fn resume(&self) -> Self {
        let mut next = self.clone();
        next.hibernated = false;
        next
    }

    /// Return whether any warm state was retained beyond the cut certificate.
    #[must_use]
    pub fn has_restorable_payload(&self) -> bool {
        !self.stream_window_digest.is_zero()
            || !self.consumer_cursor_digest.is_zero()
            || !self.supervisor_state_digest.is_zero()
            || !self.read_model_digest.is_zero()
            || !self.cache_digest.is_zero()
            || !self.local_evidence_frontier.is_empty()
    }

    /// Deterministic digest of the local evidence frontier.
    #[must_use]
    pub fn evidence_frontier_digest(&self) -> u64 {
        stable_hash(("service-capsule-evidence", &self.local_evidence_frontier))
    }
}

/// Captured warm-restorable service capsule at a certified cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverableServiceCapsule {
    /// Human-readable capsule label.
    pub service_name: String,
    /// Cell whose state was captured.
    pub source_cell: SubjectCell,
    /// Cut certificate fencing the captured state.
    pub cut_certificate: CutCertificate,
    /// Key-hierarchy binding that must be scrubbed before restore.
    pub key_hierarchy: CellKeyHierarchySpec,
    /// Logical time when the capsule was captured.
    pub captured_at: Time,
    /// Compact digests describing the retained state.
    pub state: ServiceCapsuleState,
    /// Deterministic digest of the entire captured capsule payload.
    pub capsule_digest: CapsuleDigest,
}

impl RecoverableServiceCapsule {
    /// Capture a recoverable service capsule from a running cell.
    pub fn capture(
        service_name: impl Into<String>,
        cell: &SubjectCell,
        cut_certificate: &CutCertificate,
        key_hierarchy: CellKeyHierarchySpec,
        state: &ServiceCapsuleState,
        captured_at: Time,
    ) -> Result<Self, ServiceCapsuleError> {
        let service_name = service_name.into();
        if service_name.trim().is_empty() {
            return Err(ServiceCapsuleError::EmptyServiceName);
        }
        if state.hibernated {
            return Err(ServiceCapsuleError::CapturedStateMustStartLive);
        }
        cut_certificate.validate_for(cell)?;
        key_hierarchy.validate()?;
        validate_key_hierarchy_binding(cell, &key_hierarchy)?;
        if cut_certificate.consumer_state_digest == ConsumerStateDigest::ZERO {
            return Err(ServiceCapsuleError::MissingConsumerStateDigest);
        }

        let local_evidence_frontier =
            canonicalize_evidence_frontier(state.local_evidence_frontier.iter().copied());
        let state = ServiceCapsuleState {
            local_evidence_frontier,
            ..state.clone()
        };
        let capsule_digest = compute_capsule_digest(
            &service_name,
            cell,
            cut_certificate,
            &key_hierarchy,
            &state,
            captured_at,
        );

        Ok(Self {
            service_name,
            source_cell: cell.clone(),
            cut_certificate: cut_certificate.clone(),
            key_hierarchy,
            captured_at,
            state,
            capsule_digest,
        })
    }

    /// Mark the captured service capsule as hibernated and ready for restore.
    #[must_use]
    pub fn hibernate(&self) -> Self {
        let mut next = self.clone();
        next.state = self.state.hibernate();
        next.capsule_digest = compute_capsule_digest(
            &next.service_name,
            &next.source_cell,
            &next.cut_certificate,
            &next.key_hierarchy,
            &next.state,
            next.captured_at,
        );
        next
    }

    /// Prepare a warm restore under a scrubbed authority context and fresh epoch.
    pub fn plan_restore(
        &self,
        target: NodeId,
        restored_epoch: CellEpoch,
        scrub_request: &RestoreScrubRequest,
    ) -> Result<ServiceCapsuleRestorePlan, ServiceCapsuleError> {
        if !self.state.hibernated {
            return Err(ServiceCapsuleError::CapsuleMustBeHibernated);
        }

        let scrubbed_key_hierarchy = self.key_hierarchy.scrub_for_restore(scrub_request)?;
        let certified_mobility = self.source_cell.certify_mobility(
            &self.cut_certificate,
            &MobilityOperation::WarmRestore {
                target,
                restored_epoch,
                capsule_digest: self.capsule_digest,
            },
        )?;

        Ok(ServiceCapsuleRestorePlan {
            source_capsule_digest: self.capsule_digest,
            certified_mobility,
            scrubbed_key_hierarchy,
            restored_state: self.state.clone(),
        })
    }
}

/// Restore plan produced from one hibernated capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCapsuleRestorePlan {
    /// Digest of the source capsule being restored.
    pub source_capsule_digest: CapsuleDigest,
    /// Certified mobility artifact rebinding the cell into a fresh epoch.
    pub certified_mobility: CertifiedMobility,
    /// Scrubbed key hierarchy for the restored environment.
    pub scrubbed_key_hierarchy: CellKeyHierarchySpec,
    /// Restored state before resuming service.
    pub restored_state: ServiceCapsuleState,
}

impl ServiceCapsuleRestorePlan {
    /// Resume the restored capsule into an active service state.
    #[must_use]
    pub fn resume(self, resumed_at: Time) -> RestoredServiceCapsule {
        RestoredServiceCapsule {
            source_capsule_digest: self.source_capsule_digest,
            certified_mobility: self.certified_mobility,
            scrubbed_key_hierarchy: self.scrubbed_key_hierarchy,
            resumed_at,
            active_state: self.restored_state.resume(),
        }
    }
}

/// Restored service capsule after a resume transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredServiceCapsule {
    /// Digest of the source hibernated capsule.
    pub source_capsule_digest: CapsuleDigest,
    /// Certified mobility artifact that restored the service.
    pub certified_mobility: CertifiedMobility,
    /// Scrubbed key hierarchy active in the restored environment.
    pub scrubbed_key_hierarchy: CellKeyHierarchySpec,
    /// Logical time when the service resumed.
    pub resumed_at: Time,
    /// Active state after resume.
    pub active_state: ServiceCapsuleState,
}

impl RestoredServiceCapsule {
    /// Return the restored cell that now owns the resumed service state.
    #[must_use]
    pub fn restored_cell(&self) -> &SubjectCell {
        &self.certified_mobility.resulting_cell
    }

    /// Return the consumer-state digest preserved across the restore.
    #[must_use]
    pub fn consumer_state_digest(&self) -> ConsumerStateDigest {
        self.certified_mobility.certificate.consumer_state_digest
    }
}

/// Consumer-side state captured with a stream snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamConsumerSnapshot {
    /// Stable consumer attachment id at capture time.
    pub consumer_id: u64,
}

/// Consumer-side state after restore-time lease invalidation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RestoredStreamConsumerState {
    /// Stable consumer attachment id from the captured stream.
    pub consumer_id: u64,
    /// Restore invalidates captured live leases before replay or staging use.
    pub lease_invalidated: bool,
}

/// Explicit restore-time scrub summary for a recovered stream branch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamRestoreScrubSummary {
    /// Replacement reply-space prefix for the restored environment.
    pub reply_subject_prefix: String,
    /// Import credentials are never preserved across restore.
    pub import_credentials_stripped: bool,
    /// Export credentials are never preserved across restore.
    pub export_credentials_stripped: bool,
    /// Captured live consumer leases are invalidated before restore.
    pub consumer_leases_invalidated: bool,
}

/// Recoverable stream snapshot captured at a cut-certified frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverableStreamSnapshot {
    /// Captured stream state and retained records.
    pub stream_state: StreamSnapshot,
    /// Captured consumer attachment state.
    pub consumer_states: Vec<StreamConsumerSnapshot>,
    /// Canonicalized obligation frontier preserved for replay.
    pub obligation_frontier: Vec<ObligationId>,
    /// Source cell epoch fenced into the cut.
    pub epoch: CellEpoch,
    /// Logical time when the stream snapshot was captured.
    pub timestamp: Time,
    /// Cell whose stream state was captured.
    pub source_cell: SubjectCell,
    /// Cut certificate fencing the captured state.
    pub cut_certificate: CutCertificate,
    /// Key-hierarchy binding that must be scrubbed before restore.
    pub key_hierarchy: CellKeyHierarchySpec,
    /// Deterministic digest of the recoverable stream snapshot payload.
    pub snapshot_digest: CapsuleDigest,
}

impl RecoverableStreamSnapshot {
    /// Capture a recoverable stream snapshot from a stream-side logical cut.
    pub fn capture(
        stream_state: &StreamSnapshot,
        cell: &SubjectCell,
        cut_certificate: &CutCertificate,
        key_hierarchy: CellKeyHierarchySpec,
        timestamp: Time,
    ) -> Result<Self, StreamSnapshotError> {
        cut_certificate.validate_for(cell)?;
        key_hierarchy.validate()?;
        validate_stream_key_hierarchy_binding(cell, &key_hierarchy)?;
        if !stream_state.is_quiescent() && cut_certificate.obligation_frontier.is_empty() {
            return Err(StreamSnapshotError::NonQuiescentWithoutObligationFrontier {
                consumers: stream_state.consumer_ids.len(),
                mirrors: stream_state.mirror_regions.len(),
                sources: stream_state.source_regions.len(),
            });
        }
        if !stream_state.consumer_ids.is_empty()
            && cut_certificate.consumer_state_digest == ConsumerStateDigest::ZERO
        {
            return Err(StreamSnapshotError::MissingConsumerStateDigest);
        }

        let consumer_states = stream_state
            .consumer_ids
            .iter()
            .copied()
            .map(|consumer_id| StreamConsumerSnapshot { consumer_id })
            .collect::<Vec<_>>();
        let snapshot_digest = compute_stream_snapshot_digest(
            stream_state,
            &consumer_states,
            &cut_certificate.obligation_frontier,
            cell,
            cut_certificate,
            &key_hierarchy,
            timestamp,
        );

        Ok(Self {
            stream_state: stream_state.clone(),
            consumer_states,
            obligation_frontier: cut_certificate.obligation_frontier.clone(),
            epoch: cut_certificate.epoch,
            timestamp,
            source_cell: cell.clone(),
            cut_certificate: cut_certificate.clone(),
            key_hierarchy,
            snapshot_digest,
        })
    }

    /// Restore the captured stream into a fresh staging or lab region.
    pub fn restore_into_staging(
        &self,
        target: NodeId,
        restored_region: RegionId,
        restored_epoch: CellEpoch,
        scrub_request: &RestoreScrubRequest,
        reply_subject_prefix: impl Into<String>,
        restored_at: Time,
    ) -> Result<RestoredStreamSnapshot, StreamSnapshotError> {
        let reply_subject_prefix = reply_subject_prefix.into();
        if reply_subject_prefix.trim().is_empty() {
            return Err(StreamSnapshotError::EmptyReplySubjectPrefix);
        }

        let scrubbed_key_hierarchy = self.key_hierarchy.scrub_for_restore(scrub_request)?;
        let certified_mobility = self.source_cell.certify_mobility(
            &self.cut_certificate,
            &MobilityOperation::WarmRestore {
                target,
                restored_epoch,
                capsule_digest: self.snapshot_digest,
            },
        )?;
        let restored_stream = Stream::<InMemoryStorageBackend>::restore_from_snapshot(
            &self.stream_state,
            restored_region,
        )?;
        let restored_stream_state = restored_stream.snapshot()?;
        let restored_consumer_states = self
            .consumer_states
            .iter()
            .map(|consumer| RestoredStreamConsumerState {
                consumer_id: consumer.consumer_id,
                lease_invalidated: true,
            })
            .collect();

        Ok(RestoredStreamSnapshot {
            source_snapshot_digest: self.snapshot_digest,
            certified_mobility,
            scrubbed_key_hierarchy,
            restored_stream_state,
            restored_consumer_states,
            obligation_frontier: self.obligation_frontier.clone(),
            scrub_summary: StreamRestoreScrubSummary {
                reply_subject_prefix,
                import_credentials_stripped: true,
                export_credentials_stripped: true,
                consumer_leases_invalidated: true,
            },
            restored_at,
        })
    }

    /// Fork the captured stream state under a different replay policy.
    pub fn fork_with_config(
        &self,
        restored_region: RegionId,
        config: StreamConfig,
    ) -> Result<StreamSnapshot, StreamSnapshotError> {
        let mut branch = self.stream_state.clone();
        branch.config = config;
        let restored =
            Stream::<InMemoryStorageBackend>::restore_from_snapshot(&branch, restored_region)?;
        restored.snapshot().map_err(StreamSnapshotError::from)
    }
}

/// Restored stream branch after epoch rebinding and authority scrubbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredStreamSnapshot {
    /// Digest of the source stream snapshot.
    pub source_snapshot_digest: CapsuleDigest,
    /// Certified mobility artifact rebinding the stream's source cell.
    pub certified_mobility: CertifiedMobility,
    /// Scrubbed key hierarchy for the restored environment.
    pub scrubbed_key_hierarchy: CellKeyHierarchySpec,
    /// Restored stream state inside the new region.
    pub restored_stream_state: StreamSnapshot,
    /// Restored consumer states with live leases invalidated.
    pub restored_consumer_states: Vec<RestoredStreamConsumerState>,
    /// Preserved obligation frontier captured at the cut.
    pub obligation_frontier: Vec<ObligationId>,
    /// Explicit restore-time scrub summary.
    pub scrub_summary: StreamRestoreScrubSummary,
    /// Logical time when the restored branch resumed.
    pub restored_at: Time,
}

/// Deterministic failures while capturing or restoring service capsules.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceCapsuleError {
    /// Capsule labels must stay human-readable and non-empty.
    #[error("service capsule name must not be empty")]
    EmptyServiceName,
    /// Capture must snapshot a live service before an explicit hibernate step.
    #[error("recoverable service capsule capture requires a live service state")]
    CapturedStateMustStartLive,
    /// Warm restore requires consumer state captured at the cut.
    #[error("recoverable service capsule requires a non-zero consumer-state digest")]
    MissingConsumerStateDigest,
    /// Restores must happen from a hibernated capsule, not a live snapshot.
    #[error("service capsule must be hibernated before restore planning")]
    CapsuleMustBeHibernated,
    /// Cut-certificate validation or mobility certification failed.
    #[error(transparent)]
    Mobility(#[from] CutMobilityError),
    /// Restore-time key scrubbing failed.
    #[error(transparent)]
    KeyHierarchy(#[from] KeyHierarchyError),
    /// The captured key hierarchy must identify the same canonical subject cell.
    #[error(
        "service capsule key hierarchy targets cell binding `{actual}`, expected `{expected}` for the captured subject cell"
    )]
    KeyHierarchyCellBindingMismatch {
        /// Canonical key-hierarchy cell binding derived from the captured subject partition.
        expected: String,
        /// Advertised key-hierarchy cell binding.
        actual: String,
    },
    /// The captured key hierarchy must use the current membership epoch of the source cell.
    #[error(
        "service capsule key hierarchy uses authoritative cell epoch {actual}, expected {expected} for the captured subject cell"
    )]
    KeyHierarchyCellEpochMismatch {
        /// Membership epoch of the captured subject cell.
        expected: u64,
        /// Advertised key-hierarchy cell epoch.
        actual: u64,
    },
}

/// Deterministic failures while capturing or restoring stream snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StreamSnapshotError {
    /// Cut-certificate validation or mobility certification failed.
    #[error(transparent)]
    Mobility(#[from] CutMobilityError),
    /// Restore-time key scrubbing failed.
    #[error(transparent)]
    KeyHierarchy(#[from] KeyHierarchyError),
    /// Stream restore failed while rehydrating storage or rebuildable state.
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// Non-quiescent snapshots must preserve an explicit frontier.
    #[error(
        "non-quiescent stream snapshot requires an explicit obligation frontier: consumers={consumers} mirrors={mirrors} sources={sources}"
    )]
    NonQuiescentWithoutObligationFrontier {
        /// Active consumer attachments at capture time.
        consumers: usize,
        /// Active mirror child regions at capture time.
        mirrors: usize,
        /// Active source child regions at capture time.
        sources: usize,
    },
    /// Active consumer state requires a non-zero cut digest.
    #[error("stream snapshot with active consumers requires a non-zero consumer-state digest")]
    MissingConsumerStateDigest,
    /// Restore must allocate a fresh reply-space prefix.
    #[error("stream snapshot restore reply subject prefix must not be empty")]
    EmptyReplySubjectPrefix,
    /// The captured key hierarchy must identify the same canonical subject cell.
    #[error(
        "stream snapshot key hierarchy targets cell binding `{actual}`, expected `{expected}` for the captured subject cell"
    )]
    KeyHierarchyCellBindingMismatch {
        /// Canonical key-hierarchy cell binding derived from the captured subject partition.
        expected: String,
        /// Advertised key-hierarchy cell binding.
        actual: String,
    },
    /// The captured key hierarchy must use the current membership epoch of the source cell.
    #[error(
        "stream snapshot key hierarchy uses authoritative cell epoch {actual}, expected {expected} for the captured subject cell"
    )]
    KeyHierarchyCellEpochMismatch {
        /// Membership epoch of the captured subject cell.
        expected: u64,
        /// Advertised key-hierarchy cell epoch.
        actual: u64,
    },
}

fn canonicalize_evidence_frontier(
    frontier: impl IntoIterator<Item = EvidenceDigest>,
) -> Vec<EvidenceDigest> {
    let mut frontier: Vec<_> = frontier.into_iter().collect();
    frontier.sort_unstable();
    frontier.dedup();
    frontier
}

fn validate_key_hierarchy_binding(
    cell: &SubjectCell,
    key_hierarchy: &CellKeyHierarchySpec,
) -> Result<(), ServiceCapsuleError> {
    let expected_binding = canonical_key_hierarchy_cell_binding(cell);
    if key_hierarchy.cell.cell_id != expected_binding {
        return Err(ServiceCapsuleError::KeyHierarchyCellBindingMismatch {
            expected: expected_binding,
            actual: key_hierarchy.cell.cell_id.clone(),
        });
    }

    let expected_epoch = cell.epoch.membership_epoch;
    if key_hierarchy.cell.cell_epoch != expected_epoch {
        return Err(ServiceCapsuleError::KeyHierarchyCellEpochMismatch {
            expected: expected_epoch,
            actual: key_hierarchy.cell.cell_epoch,
        });
    }

    Ok(())
}

fn canonical_key_hierarchy_cell_binding(cell: &SubjectCell) -> String {
    format!("cell.{}", cell.subject_partition.canonical_key())
}

fn compute_capsule_digest(
    service_name: &str,
    cell: &SubjectCell,
    cut_certificate: &CutCertificate,
    key_hierarchy: &CellKeyHierarchySpec,
    state: &ServiceCapsuleState,
    captured_at: Time,
) -> CapsuleDigest {
    let mut hasher = DetHasher::default();
    "recoverable-service-capsule".hash(&mut hasher);
    service_name.hash(&mut hasher);
    cell.cell_id.raw().hash(&mut hasher);
    cell.epoch.hash(&mut hasher);
    cut_certificate.certificate_digest().hash(&mut hasher);
    cut_certificate
        .consumer_state_digest
        .raw()
        .hash(&mut hasher);
    key_hierarchy.subgroup.subgroup_epoch.hash(&mut hasher);
    key_hierarchy
        .subgroup
        .subgroup_roster_hash
        .as_str()
        .hash(&mut hasher);
    key_hierarchy.cell.cell_id.as_str().hash(&mut hasher);
    key_hierarchy.cell.cell_epoch.hash(&mut hasher);
    key_hierarchy.cell.roster_hash.as_str().hash(&mut hasher);
    key_hierarchy
        .cell
        .config_epoch_hash
        .as_str()
        .hash(&mut hasher);
    key_hierarchy.cell.cell_rekey_generation.hash(&mut hasher);
    state.stream_window_digest.raw().hash(&mut hasher);
    state.consumer_cursor_digest.raw().hash(&mut hasher);
    state.supervisor_state_digest.raw().hash(&mut hasher);
    state.read_model_digest.raw().hash(&mut hasher);
    state.cache_digest.raw().hash(&mut hasher);
    state.local_evidence_frontier.hash(&mut hasher);
    state.hibernated.hash(&mut hasher);
    captured_at.as_nanos().hash(&mut hasher);

    let digest = hasher.finish();

    CapsuleDigest::new(if digest == 0 { 1 } else { digest })
}

fn stable_hash<T: Hash>(value: T) -> u64 {
    let mut hasher = DetHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

fn validate_stream_key_hierarchy_binding(
    cell: &SubjectCell,
    key_hierarchy: &CellKeyHierarchySpec,
) -> Result<(), StreamSnapshotError> {
    let expected_binding = canonical_key_hierarchy_cell_binding(cell);
    if key_hierarchy.cell.cell_id != expected_binding {
        return Err(StreamSnapshotError::KeyHierarchyCellBindingMismatch {
            expected: expected_binding,
            actual: key_hierarchy.cell.cell_id.clone(),
        });
    }

    let expected_epoch = cell.epoch.membership_epoch;
    if key_hierarchy.cell.cell_epoch != expected_epoch {
        return Err(StreamSnapshotError::KeyHierarchyCellEpochMismatch {
            expected: expected_epoch,
            actual: key_hierarchy.cell.cell_epoch,
        });
    }

    Ok(())
}

fn compute_stream_snapshot_digest(
    stream_state: &StreamSnapshot,
    consumer_states: &[StreamConsumerSnapshot],
    obligation_frontier: &[ObligationId],
    cell: &SubjectCell,
    cut_certificate: &CutCertificate,
    key_hierarchy: &CellKeyHierarchySpec,
    captured_at: Time,
) -> CapsuleDigest {
    let mut hasher = DetHasher::default();
    "recoverable-stream-snapshot".hash(&mut hasher);
    stream_state.hash(&mut hasher);
    consumer_states.hash(&mut hasher);
    obligation_frontier.hash(&mut hasher);
    cell.cell_id.raw().hash(&mut hasher);
    cell.epoch.hash(&mut hasher);
    cut_certificate.certificate_digest().hash(&mut hasher);
    key_hierarchy.subgroup.subgroup_epoch.hash(&mut hasher);
    key_hierarchy
        .subgroup
        .subgroup_roster_hash
        .as_str()
        .hash(&mut hasher);
    key_hierarchy.cell.cell_id.as_str().hash(&mut hasher);
    key_hierarchy.cell.cell_epoch.hash(&mut hasher);
    key_hierarchy.cell.roster_hash.as_str().hash(&mut hasher);
    key_hierarchy
        .cell
        .config_epoch_hash
        .as_str()
        .hash(&mut hasher);
    key_hierarchy.cell.cell_rekey_generation.hash(&mut hasher);
    captured_at.as_nanos().hash(&mut hasher);
    let digest = hasher.finish();

    CapsuleDigest::new(if digest == 0 { 1 } else { digest })
}

#[cfg(test)]
mod tests {
    use super::super::class::DeliveryClass;
    use super::super::fabric::{
        CellTemperature, DataCapsule, NodeRole, PlacementPolicy, RepairPolicy, StewardCandidate,
        StorageClass, SubjectPattern,
    };
    use super::super::privacy::{CellKeyContext, SubgroupKeyContext};
    use super::super::stream::{InMemoryStorageBackend, Stream, StreamConfig};
    use super::super::subject::Subject;
    use super::*;
    use crate::remote::NodeId;
    use crate::types::{ObligationId, RegionId};

    fn candidate(
        name: &str,
        domain: &str,
        storage: StorageClass,
        latency_millis: u32,
    ) -> StewardCandidate {
        StewardCandidate::new(NodeId::new(name), domain)
            .with_role(NodeRole::Steward)
            .with_storage_class(storage)
            .with_latency_millis(latency_millis)
    }

    fn subject_cell() -> SubjectCell {
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 9),
        ];

        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            &candidates,
            &PlacementPolicy::default(),
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
        .expect("subject cell")
    }

    fn key_hierarchy_spec() -> CellKeyHierarchySpec {
        CellKeyHierarchySpec {
            subgroup: SubgroupKeyContext {
                subgroup_epoch: 4,
                subgroup_roster_hash: "subgroup-roster-hash-a".to_owned(),
            },
            cell: CellKeyContext {
                cell_id: "cell.orders.created".to_owned(),
                cell_epoch: 11,
                roster_hash: "cell-roster-hash-a".to_owned(),
                config_epoch_hash: "config-epoch-hash-a".to_owned(),
                cell_rekey_generation: 2,
            },
        }
    }

    fn captured_state() -> ServiceCapsuleState {
        ServiceCapsuleState::new(
            CapsuleStateDigest::new(11),
            CapsuleStateDigest::new(13),
            CapsuleStateDigest::new(17),
            CapsuleStateDigest::new(19),
            CapsuleStateDigest::new(23),
            [
                EvidenceDigest::new(7),
                EvidenceDigest::new(3),
                EvidenceDigest::new(7),
            ],
        )
    }

    fn cut_certificate(cell: &SubjectCell) -> CutCertificate {
        cell.issue_cut_certificate(
            [
                ObligationId::new_for_test(5, 0),
                ObligationId::new_for_test(2, 0),
            ],
            ConsumerStateDigest::new(41),
            Time::from_secs(3),
            cell.steward_set
                .first()
                .cloned()
                .expect("active steward in cut"),
        )
        .expect("cut certificate")
    }

    fn frontierless_cut_certificate(cell: &SubjectCell) -> CutCertificate {
        cell.issue_cut_certificate(
            [],
            ConsumerStateDigest::new(41),
            Time::from_secs(3),
            cell.steward_set
                .first()
                .cloned()
                .expect("active steward in cut"),
        )
        .expect("cut certificate")
    }

    fn test_region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 1)
    }

    fn stream_config(filter: &str) -> StreamConfig {
        StreamConfig {
            subject_filter: SubjectPattern::new(filter),
            ..StreamConfig::default()
        }
    }

    fn quiescent_stream_snapshot() -> StreamSnapshot {
        let mut stream = Stream::new(
            "orders-stream",
            test_region(70),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        stream.snapshot().expect("snapshot")
    }

    fn non_quiescent_stream_snapshot() -> StreamSnapshot {
        let mut stream = Stream::new(
            "orders-stream",
            test_region(71),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        let consumer = stream.attach_consumer();
        stream
            .add_mirror_region(test_region(72))
            .expect("mirror region");
        let snapshot = stream.snapshot().expect("snapshot");
        assert_eq!(snapshot.consumer_ids, vec![consumer]);
        snapshot
    }

    #[test]
    fn capture_builds_capsule_digest_and_canonicalizes_evidence_frontier() {
        let cell = subject_cell();
        let capsule = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture");

        assert_ne!(capsule.capsule_digest, CapsuleDigest::ZERO);
        assert!(capsule.state.has_restorable_payload());
        assert_eq!(
            capsule.state.local_evidence_frontier,
            vec![EvidenceDigest::new(3), EvidenceDigest::new(7)]
        );
    }

    #[test]
    fn capture_rejects_invalid_key_hierarchy_spec() {
        let cell = subject_cell();
        let mut invalid_hierarchy = key_hierarchy_spec();
        invalid_hierarchy.cell.cell_id = "   ".to_owned();

        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            invalid_hierarchy,
            &captured_state(),
            Time::from_secs(5),
        )
        .expect_err("invalid hierarchy must be rejected at capture time");

        assert_eq!(
            err,
            ServiceCapsuleError::KeyHierarchy(KeyHierarchyError::EmptyField { field: "cell_id" })
        );
    }

    #[test]
    fn capture_rejects_key_hierarchy_for_different_subject_binding() {
        let cell = subject_cell();
        let mut wrong_hierarchy = key_hierarchy_spec();
        wrong_hierarchy.cell.cell_id = "cell.payments.captured".to_owned();

        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            wrong_hierarchy,
            &captured_state(),
            Time::from_secs(5),
        )
        .expect_err("mismatched key hierarchy binding must fail closed");

        assert_eq!(
            err,
            ServiceCapsuleError::KeyHierarchyCellBindingMismatch {
                expected: "cell.orders.created".to_owned(),
                actual: "cell.payments.captured".to_owned(),
            }
        );
    }

    #[test]
    fn capture_rejects_key_hierarchy_for_different_membership_epoch() {
        let cell = subject_cell();
        let mut wrong_hierarchy = key_hierarchy_spec();
        wrong_hierarchy.cell.cell_epoch += 1;

        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            wrong_hierarchy,
            &captured_state(),
            Time::from_secs(5),
        )
        .expect_err("mismatched key hierarchy epoch must fail closed");

        assert_eq!(
            err,
            ServiceCapsuleError::KeyHierarchyCellEpochMismatch {
                expected: 11,
                actual: 12,
            }
        );
    }

    #[test]
    fn capture_rejects_pre_hibernated_service_state() {
        let cell = subject_cell();
        let err = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state().hibernate(),
            Time::from_secs(5),
        )
        .expect_err("capture must reject already-hibernated service state");

        assert_eq!(err, ServiceCapsuleError::CapturedStateMustStartLive);
    }

    #[test]
    fn restore_plan_scrubs_authority_and_rebinds_to_fresh_epoch() {
        let cell = subject_cell();
        let capsule = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture")
        .hibernate();
        let restored_epoch = CellEpoch::new(12, 4);
        let restore = capsule
            .plan_restore(
                NodeId::new("restore-node"),
                restored_epoch,
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 9,
                        subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.restored".to_owned(),
                        cell_epoch: 44,
                        roster_hash: "cell-roster-hash-restored".to_owned(),
                        config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                        cell_rekey_generation: 3,
                    },
                },
            )
            .expect("restore plan");

        assert_eq!(
            restore.certified_mobility.resulting_cell.epoch,
            restored_epoch
        );
        assert_ne!(
            restore.certified_mobility.resulting_cell.cell_id,
            cell.cell_id
        );
        assert_eq!(
            restore
                .certified_mobility
                .resulting_cell
                .control_capsule
                .active_sequencer_holder(),
            Some(&NodeId::new("restore-node"))
        );
        assert_eq!(
            restore.scrubbed_key_hierarchy.cell.cell_id,
            "cell.orders.created.restored"
        );
        assert_eq!(restore.scrubbed_key_hierarchy.cell.cell_epoch, 44);
        assert!(restore.restored_state.hibernated);
    }

    #[test]
    fn hibernate_resume_cycle_preserves_capsule_provenance() {
        let cell = subject_cell();
        let hibernated = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture")
        .hibernate();
        let source_digest = hibernated.capsule_digest;
        let restored = hibernated
            .plan_restore(
                NodeId::new("resume-node"),
                CellEpoch::new(12, 3),
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 8,
                        subgroup_roster_hash: "subgroup-roster-hash-b".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.resumed".to_owned(),
                        cell_epoch: 45,
                        roster_hash: "cell-roster-hash-b".to_owned(),
                        config_epoch_hash: "config-epoch-hash-b".to_owned(),
                        cell_rekey_generation: 6,
                    },
                },
            )
            .expect("restore plan")
            .resume(Time::from_secs(8));

        assert_eq!(restored.source_capsule_digest, source_digest);
        assert_eq!(restored.resumed_at, Time::from_secs(8));
        assert!(!restored.active_state.hibernated);
        assert_eq!(
            restored.consumer_state_digest(),
            ConsumerStateDigest::new(41)
        );
    }

    #[test]
    fn cross_environment_transfer_preserves_evidence_frontier_through_restore() {
        let cell = subject_cell();
        let restored = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture")
        .hibernate()
        .plan_restore(
            NodeId::new("edge-node"),
            CellEpoch::new(13, 1),
            &RestoreScrubRequest {
                subgroup: SubgroupKeyContext {
                    subgroup_epoch: 12,
                    subgroup_roster_hash: "subgroup-roster-hash-edge".to_owned(),
                },
                cell: CellKeyContext {
                    cell_id: "cell.orders.created.edge".to_owned(),
                    cell_epoch: 51,
                    roster_hash: "cell-roster-hash-edge".to_owned(),
                    config_epoch_hash: "config-epoch-hash-edge".to_owned(),
                    cell_rekey_generation: 9,
                },
            },
        )
        .expect("restore plan")
        .resume(Time::from_secs(9));

        assert_eq!(
            restored.active_state.local_evidence_frontier,
            vec![EvidenceDigest::new(3), EvidenceDigest::new(7)]
        );
        assert_eq!(restored.scrubbed_key_hierarchy.subgroup.subgroup_epoch, 12);
        assert_eq!(
            restored.restored_cell().subject_partition,
            cell.subject_partition
        );
        assert_eq!(
            restored
                .restored_cell()
                .control_capsule
                .active_sequencer_holder(),
            Some(&NodeId::new("edge-node"))
        );
    }

    #[test]
    fn restore_requires_hibernated_capsule() {
        let cell = subject_cell();
        let capsule = RecoverableServiceCapsule::capture(
            "orders-service",
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            &captured_state(),
            Time::from_secs(5),
        )
        .expect("capsule capture");

        let err = capsule
            .plan_restore(
                NodeId::new("restore-node"),
                CellEpoch::new(12, 3),
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 8,
                        subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.restored".to_owned(),
                        cell_epoch: 45,
                        roster_hash: "cell-roster-hash-restored".to_owned(),
                        config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                        cell_rekey_generation: 6,
                    },
                },
            )
            .expect_err("live snapshot must be hibernated first");

        assert_eq!(err, ServiceCapsuleError::CapsuleMustBeHibernated);
    }

    #[test]
    fn recoverable_stream_snapshot_requires_frontier_for_non_quiescent_capture() {
        let cell = subject_cell();
        let err = RecoverableStreamSnapshot::capture(
            &non_quiescent_stream_snapshot(),
            &cell,
            &frontierless_cut_certificate(&cell),
            key_hierarchy_spec(),
            Time::from_secs(12),
        )
        .expect_err("non-quiescent capture must carry an explicit frontier");

        assert_eq!(
            err,
            StreamSnapshotError::NonQuiescentWithoutObligationFrontier {
                consumers: 1,
                mirrors: 1,
                sources: 0,
            }
        );
    }

    #[test]
    fn recoverable_stream_snapshot_restore_rebinds_epoch_and_scrubs_live_authority() {
        let cell = subject_cell();
        let captured_stream = non_quiescent_stream_snapshot();
        let cut = cut_certificate(&cell);
        let recoverable = RecoverableStreamSnapshot::capture(
            &captured_stream,
            &cell,
            &cut,
            key_hierarchy_spec(),
            Time::from_secs(12),
        )
        .expect("recoverable stream capture");

        let restored = recoverable
            .restore_into_staging(
                NodeId::new("restore-node"),
                test_region(90),
                CellEpoch::new(12, 4),
                &RestoreScrubRequest {
                    subgroup: SubgroupKeyContext {
                        subgroup_epoch: 9,
                        subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                    },
                    cell: CellKeyContext {
                        cell_id: "cell.orders.created.restored".to_owned(),
                        cell_epoch: 44,
                        roster_hash: "cell-roster-hash-restored".to_owned(),
                        config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                        cell_rekey_generation: 3,
                    },
                },
                "_INBOX.restored",
                Time::from_secs(20),
            )
            .expect("restore stream snapshot");

        assert_eq!(
            restored.certified_mobility.resulting_cell.epoch,
            CellEpoch::new(12, 4)
        );
        assert_eq!(
            restored.scrubbed_key_hierarchy.cell.cell_id,
            "cell.orders.created.restored"
        );
        assert_eq!(restored.restored_stream_state.region_id, test_region(90));
        assert_eq!(
            restored.restored_stream_state.storage,
            captured_stream.storage
        );
        assert_eq!(restored.restored_stream_state.state.msg_count, 1);
        assert!(restored.restored_stream_state.is_quiescent());
        assert_eq!(
            restored.restored_stream_state.consumer_ids,
            Vec::<u64>::new()
        );
        assert_eq!(
            restored.restored_consumer_states,
            vec![RestoredStreamConsumerState {
                consumer_id: captured_stream.consumer_ids[0],
                lease_invalidated: true,
            }]
        );
        assert_eq!(restored.obligation_frontier, cut.obligation_frontier);
        assert_eq!(
            restored.scrub_summary.reply_subject_prefix,
            "_INBOX.restored"
        );
        assert!(restored.scrub_summary.import_credentials_stripped);
        assert!(restored.scrub_summary.export_credentials_stripped);
        assert!(restored.scrub_summary.consumer_leases_invalidated);
    }

    #[test]
    fn recoverable_stream_snapshot_can_fork_under_counterfactual_policy() {
        let cell = subject_cell();
        let captured_stream = quiescent_stream_snapshot();
        let recoverable = RecoverableStreamSnapshot::capture(
            &captured_stream,
            &cell,
            &cut_certificate(&cell),
            key_hierarchy_spec(),
            Time::from_secs(12),
        )
        .expect("recoverable stream capture");
        let mut counterfactual_config = captured_stream.config.clone();
        counterfactual_config.delivery_class = DeliveryClass::ForensicReplayable;

        let forked = recoverable
            .fork_with_config(test_region(91), counterfactual_config.clone())
            .expect("forked stream snapshot");

        assert_eq!(forked.region_id, test_region(91));
        assert_eq!(forked.config, counterfactual_config);
        assert_eq!(forked.storage, captured_stream.storage);
        assert_eq!(forked.state.msg_count, captured_stream.state.msg_count);
        assert_eq!(forked.state.first_seq, captured_stream.state.first_seq);
        assert_eq!(forked.state.last_seq, captured_stream.state.last_seq);
        assert_eq!(forked.consumer_ids, Vec::<u64>::new());
    }
}
