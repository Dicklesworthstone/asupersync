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
#[path = "snapshot_inline_tests.rs"]
mod tests;
