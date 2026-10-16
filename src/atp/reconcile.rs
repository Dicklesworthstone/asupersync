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
    /// Canonical dedupe metadata bytes received before unique payloads.
    pub metadata_wire_bytes: u64,
    /// Unique payload bytes received after metadata.
    pub unique_payload_wire_bytes: u64,
    /// Metadata plus unique payload bytes, excluding outer envelope framing.
    pub compact_wire_bytes: u64,
    /// Logical missing bytes represented by the canonical parts.
    pub logical_missing_bytes: u64,
    /// Count of logical missing chunks eliminated by dedupe.
    pub duplicate_missing_chunks: u64,
    /// Logical missing bytes eliminated by dedupe.
    pub duplicate_missing_bytes: u64,
}

impl DeltaDedupReconstructReport {
    /// True when the canonical dedupe parts were smaller than all missing chunks.
    #[must_use]
    pub const fn saves_bytes(&self) -> bool {
        self.compact_wire_bytes < self.logical_missing_bytes
    }

    /// Logical missing bytes avoided by applying canonical dedupe parts.
    #[must_use]
    pub const fn saved_wire_bytes(&self) -> u64 {
        self.logical_missing_bytes
            .saturating_sub(self.compact_wire_bytes)
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

/// Reconstruct a target manifest directly from receiver-held CAS bytes.
///
/// This is the zero-payload apply path for rename/reorder-style tree deltas:
/// the target manifest differs, but the receiver already has every target
/// content chunk. The final manifest coverage and byte reconstruction checks
/// remain the commit authority.
pub fn reconcile_existing_receiver_store_and_reconstruct(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    plan: &DeltaResyncPlan,
) -> Result<DeltaDedupReconstructReport, DeltaError> {
    if plan.sender_merkle_root != target_manifest.merkle_root {
        return Err(DeltaError::DeltaSendPlanSenderRootMismatch {
            encoded: plan.sender_merkle_root.clone(),
            expected: target_manifest.merkle_root.clone(),
        });
    }
    if !plan.missing_chunks.is_empty() {
        return Err(DeltaError::DeltaSendPlanItemCountMismatch {
            actual: 0,
            expected: plan.missing_chunks.len(),
        });
    }
    if plan.missing_bytes != 0 {
        return Err(DeltaError::DeltaSendPlanWholeBytesMismatch {
            encoded: 0,
            expected: plan.missing_bytes,
        });
    }

    target_manifest.verify_store_coverage(receiver_store)?;
    let reconstructed_bytes = reconstruct_manifest_bytes(target_manifest, receiver_store)?;
    Ok(DeltaDedupReconstructReport {
        store: receiver_store.clone(),
        reconcile: DeltaReconcileReport {
            unique_payloads: 0,
            inserted_unique_payloads: 0,
            reused_receiver_payloads: 0,
            duplicate_logical_chunks: 0,
            reconstructed_bytes: target_manifest.total_size_bytes,
        },
        reconstructed_bytes,
        metadata_wire_bytes: 0,
        unique_payload_wire_bytes: 0,
        compact_wire_bytes: 0,
        logical_missing_bytes: 0,
        duplicate_missing_chunks: 0,
        duplicate_missing_bytes: 0,
    })
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

/// Decode canonical dedupe wire parts, apply them, and reconstruct target bytes.
pub fn reconcile_canonical_dedup_payload_parts_and_reconstruct(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    plan: &DeltaResyncPlan,
    metadata_bytes: &[u8],
    unique_payload_bytes: &[u8],
) -> Result<DeltaDedupReconstructReport, DeltaError> {
    let payload_set =
        DeltaDedupPayloadSet::from_canonical_parts(plan, metadata_bytes, unique_payload_bytes)?;
    let metadata_wire_bytes =
        u64::try_from(metadata_bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
    let unique_payload_wire_bytes =
        u64::try_from(unique_payload_bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
    let compact_wire_bytes = metadata_wire_bytes
        .checked_add(unique_payload_wire_bytes)
        .ok_or(DeltaError::ChunkSizeOverflow)?;
    reconcile_decoded_dedup_payload_set_and_reconstruct(
        target_manifest,
        receiver_store,
        &payload_set,
        metadata_wire_bytes,
        unique_payload_wire_bytes,
        compact_wire_bytes,
    )
}

/// Apply canonical dedupe parts and reconstruct target bytes in one receiver step.
pub fn reconcile_canonical_dedup_parts_and_reconstruct(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    plan: &DeltaResyncPlan,
    parts: &DeltaDedupCanonicalParts,
) -> Result<DeltaDedupReconstructReport, DeltaError> {
    let payload_set = parts.decode_payload_set(plan)?;
    reconcile_decoded_dedup_payload_set_and_reconstruct(
        target_manifest,
        receiver_store,
        &payload_set,
        parts.metadata_wire_bytes,
        parts.unique_payload_wire_bytes,
        parts.compact_wire_bytes,
    )
}

fn reconcile_decoded_dedup_payload_set_and_reconstruct(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    payload_set: &DeltaDedupPayloadSet,
    metadata_wire_bytes: u64,
    unique_payload_wire_bytes: u64,
    compact_wire_bytes: u64,
) -> Result<DeltaDedupReconstructReport, DeltaError> {
    let (store, reconcile) =
        reconcile_dedup_payload_set(target_manifest, receiver_store, payload_set)?;
    let reconstructed_bytes = reconstruct_manifest_bytes(target_manifest, &store)?;
    Ok(DeltaDedupReconstructReport {
        store,
        reconcile,
        reconstructed_bytes,
        metadata_wire_bytes,
        unique_payload_wire_bytes,
        compact_wire_bytes,
        logical_missing_bytes: payload_set.send_set.logical_missing_bytes,
        duplicate_missing_chunks: payload_set.send_set.duplicate_missing_chunks,
        duplicate_missing_bytes: payload_set.send_set.duplicate_missing_bytes,
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
#[path = "reconcile_inline_tests.rs"]
mod tests;
