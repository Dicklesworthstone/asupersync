//! Receiver-side reconciliation for deduped delta payloads.
//!
//! The receiver may need to place one unique payload at several logical target
//! offsets. This module verifies the unique payload set, inserts each verified
//! payload into the CAS once, and then asks the target manifest to perform the
//! final coverage check before any caller commits reconstructed bytes.

use crate::atp::dedupe::{DeltaDedupCanonicalParts, DeltaDedupPayloadSet, payload_matches_key};
use crate::atp::delta::{
    ContentAddressedChunkStore, DeltaError, DeltaResyncPlan, PersistentChunkManifest,
    reconstruct_manifest_bytes,
};

/// Summary of applying a deduped delta payload set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaReconcileReport {
    /// Unique payloads present in the payload set.
    pub unique_payloads: u64,
    /// Unique payloads newly inserted into the receiver CAS.
    pub inserted_unique_payloads: u64,
    /// Unique payloads that were already present and verified.
    pub reused_receiver_payloads: u64,
    /// Logical duplicate chunks represented by already-sent unique payloads.
    pub duplicate_logical_chunks: u64,
    /// Logical target bytes covered after reconcile.
    pub reconstructed_bytes: u64,
}

/// Receiver result after applying canonical dedupe parts and rebuilding bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaDedupReconstructReport {
    /// Receiver CAS after applying the canonical dedupe parts.
    pub store: ContentAddressedChunkStore,
    /// Receiver-side reconcile accounting.
    pub reconcile: DeltaReconcileReport,
    /// Byte-identical target bytes rebuilt from the verified receiver CAS.
    pub reconstructed_bytes: Vec<u8>,
    /// Metadata plus unique payload bytes, excluding outer envelope framing.
    pub compact_wire_bytes: u64,
    /// Logical missing bytes represented by the canonical parts.
    pub logical_missing_bytes: u64,
}

impl DeltaDedupReconstructReport {
    /// True when the canonical dedupe parts were smaller than all missing chunks.
    #[must_use]
    pub const fn saves_bytes(&self) -> bool {
        self.compact_wire_bytes < self.logical_missing_bytes
    }
}

/// Apply a deduped payload set to a receiver CAS and verify target coverage.
pub fn reconcile_dedup_payload_set(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    payload_set: &DeltaDedupPayloadSet,
) -> Result<(ContentAddressedChunkStore, DeltaReconcileReport), DeltaError> {
    verify_placements(target_manifest, payload_set)?;

    let mut store = receiver_store.clone();
    let mut inserted_unique_payloads = 0u64;
    let mut reused_receiver_payloads = 0u64;

    for payload in &payload_set.payloads {
        payload_matches_key(&payload.payload, &payload.key, payload.representative.index)?;
        let insert = store.insert(&payload.payload)?;
        if insert.inserted {
            inserted_unique_payloads = inserted_unique_payloads
                .checked_add(1)
                .ok_or(DeltaError::ChunkCountOverflow)?;
        } else {
            reused_receiver_payloads = reused_receiver_payloads
                .checked_add(1)
                .ok_or(DeltaError::ChunkCountOverflow)?;
        }
    }

    target_manifest.verify_store_coverage(&store)?;
    let unique_payloads =
        u64::try_from(payload_set.payloads.len()).map_err(|_| DeltaError::ChunkCountOverflow)?;
    Ok((
        store,
        DeltaReconcileReport {
            unique_payloads,
            inserted_unique_payloads,
            reused_receiver_payloads,
            duplicate_logical_chunks: payload_set.send_set.duplicate_missing_chunks,
            reconstructed_bytes: target_manifest.total_size_bytes,
        },
    ))
}

/// Decode canonical dedupe parts and apply them to the receiver CAS.
pub fn reconcile_canonical_dedup_payload_parts(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    plan: &DeltaResyncPlan,
    metadata_bytes: &[u8],
    unique_payload_bytes: &[u8],
) -> Result<(ContentAddressedChunkStore, DeltaReconcileReport), DeltaError> {
    let payload_set =
        DeltaDedupPayloadSet::from_canonical_parts(plan, metadata_bytes, unique_payload_bytes)?;
    reconcile_dedup_payload_set(target_manifest, receiver_store, &payload_set)
}

/// Apply canonical dedupe parts and reconstruct target bytes in one receiver step.
pub fn reconcile_canonical_dedup_parts_and_reconstruct(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    plan: &DeltaResyncPlan,
    parts: &DeltaDedupCanonicalParts,
) -> Result<DeltaDedupReconstructReport, DeltaError> {
    let payload_set = parts.decode_payload_set(plan)?;
    let (store, reconcile) =
        reconcile_dedup_payload_set(target_manifest, receiver_store, &payload_set)?;
    let reconstructed_bytes = reconstruct_manifest_bytes(target_manifest, &store)?;
    Ok(DeltaDedupReconstructReport {
        store,
        reconcile,
        reconstructed_bytes,
        compact_wire_bytes: parts.compact_wire_bytes,
        logical_missing_bytes: parts.logical_missing_bytes,
    })
}

fn verify_placements(
    target_manifest: &PersistentChunkManifest,
    payload_set: &DeltaDedupPayloadSet,
) -> Result<(), DeltaError> {
    if payload_set.payloads.len() != payload_set.send_set.unique_chunks.len() {
        return Err(DeltaError::DeltaSendPlanItemCountMismatch {
            actual: payload_set.payloads.len(),
            expected: payload_set.send_set.unique_chunks.len(),
        });
    }

    for (ordinal, (payload, unique)) in payload_set
        .payloads
        .iter()
        .zip(&payload_set.send_set.unique_chunks)
        .enumerate()
    {
        if payload.key != unique.key || payload.representative != unique.representative {
            return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
        }
    }

    for placement in &payload_set.send_set.placements {
        let Some(target_chunk) = target_manifest.chunks.get(
            usize::try_from(placement.target_chunk.index)
                .map_err(|_| DeltaError::ChunkCountOverflow)?,
        ) else {
            return Err(DeltaError::DeltaSendPlanChunkMismatch {
                ordinal: placement.missing_ordinal,
            });
        };
        if target_chunk != &placement.target_chunk {
            return Err(DeltaError::DeltaSendPlanChunkMismatch {
                ordinal: placement.missing_ordinal,
            });
        }
        let Some(unique) = payload_set
            .send_set
            .unique_chunks
            .get(placement.unique_ordinal)
        else {
            return Err(DeltaError::DeltaSendPlanChunkMismatch {
                ordinal: placement.missing_ordinal,
            });
        };
        if unique.key != crate::atp::dedupe::DeltaChunkKey::from_chunk(target_chunk) {
            return Err(DeltaError::DeltaSendPlanChunkMismatch {
                ordinal: placement.missing_ordinal,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::dedupe::{build_canonical_dedup_payload_parts, build_dedup_payload_set};
    use crate::atp::delta::{
        PersistentChunkManifest, ReceiverCasCoverage,
        plan_incremental_resync_with_receiver_coverage, reconstruct_manifest_bytes,
    };

    fn manifest(
        store: &mut ContentAddressedChunkStore,
        tree_id: &str,
        chunks: &[&[u8]],
    ) -> PersistentChunkManifest {
        let report = store
            .ingest_ordered_chunks(chunks.iter().copied())
            .expect("ingest chunks");
        PersistentChunkManifest::new(tree_id, report.chunks).expect("manifest")
    }

    #[test]
    fn reconcile_places_one_unique_payload_at_multiple_target_offsets() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"repeat"[..], &b"middle"[..], &b"repeat"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        let (store, report) =
            reconcile_dedup_payload_set(&sender, &receiver_store, &payload_set).expect("reconcile");

        assert_eq!(report.unique_payloads, 2);
        assert_eq!(report.inserted_unique_payloads, 2);
        assert_eq!(report.reused_receiver_payloads, 0);
        assert_eq!(report.duplicate_logical_chunks, 1);
        assert_eq!(report.reconstructed_bytes, sender.total_size_bytes);
        let rebuilt = reconstruct_manifest_bytes(&sender, &store).expect("reconstruct");
        assert_eq!(rebuilt, b"repeatmiddlerepeat".as_slice());
    }

    #[test]
    fn reconcile_reports_preseeded_receiver_payload_reuse() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"alpha"[..], &b"beta"[..], &b"alpha"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        receiver_store
            .insert(b"alpha")
            .expect("preseed receiver CAS");
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        let (store, report) =
            reconcile_dedup_payload_set(&sender, &receiver_store, &payload_set).expect("reconcile");

        assert_eq!(report.unique_payloads, 2);
        assert_eq!(report.inserted_unique_payloads, 1);
        assert_eq!(report.reused_receiver_payloads, 1);
        assert_eq!(report.duplicate_logical_chunks, 1);
        assert_eq!(report.reconstructed_bytes, sender.total_size_bytes);
        let rebuilt = reconstruct_manifest_bytes(&sender, &store).expect("reconstruct");
        assert_eq!(rebuilt, b"alphabetaalpha".as_slice());
    }

    #[test]
    fn reconcile_applies_canonical_dedup_payload_parts() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"repeat"[..], &b"middle"[..], &b"repeat"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");
        let metadata = payload_set.send_set.to_canonical_bytes().expect("metadata");
        let payload_bytes = payload_set
            .to_canonical_payload_bytes()
            .expect("payload bytes");

        let (store, report) = reconcile_canonical_dedup_payload_parts(
            &sender,
            &receiver_store,
            &plan,
            &metadata,
            &payload_bytes,
        )
        .expect("canonical reconcile");

        assert_eq!(report.unique_payloads, 2);
        assert_eq!(report.duplicate_logical_chunks, 1);
        assert_eq!(report.reconstructed_bytes, sender.total_size_bytes);
        let rebuilt = reconstruct_manifest_bytes(&sender, &store).expect("reconstruct");
        assert_eq!(rebuilt, b"repeatmiddlerepeat".as_slice());
    }

    #[test]
    fn reconcile_canonical_dedup_parts_reconstructs_target_bytes() {
        let repeated = vec![b'r'; 4096];
        let unique = vec![b'u'; 1024];
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let parts =
            build_canonical_dedup_payload_parts(&plan, &sender_store).expect("canonical parts");

        let report = reconcile_canonical_dedup_parts_and_reconstruct(
            &sender,
            &receiver_store,
            &plan,
            &parts,
        )
        .expect("reconstruct canonical parts");

        assert!(report.saves_bytes());
        assert_eq!(report.compact_wire_bytes, parts.compact_wire_bytes);
        assert_eq!(report.logical_missing_bytes, sender.total_size_bytes);
        assert_eq!(report.reconcile.unique_payloads, 2);
        assert_eq!(report.reconcile.duplicate_logical_chunks, 1);
        assert_eq!(
            report.reconstructed_bytes,
            [repeated.as_slice(), unique.as_slice(), repeated.as_slice()].concat()
        );
        sender
            .verify_store_coverage(&report.store)
            .expect("verified reconstructed store");
    }

    #[test]
    fn reconcile_fails_closed_on_tampered_unique_payload() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(&mut sender_store, "tree-a", &[&b"alpha"[..], &b"alpha"[..]]);
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let mut payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");
        payload_set.payloads[0].payload[0] ^= 0x40;

        let err = reconcile_dedup_payload_set(&sender, &receiver_store, &payload_set)
            .expect_err("tampered payload");

        assert!(matches!(err, DeltaError::ChunkPayloadHashMismatch { .. }));
    }
}
