//! Delta re-sync content deduplication.
//!
//! `delta.rs` owns the transfer envelope and sub-chunk wire format. This module
//! owns the content-addressed send set that sits underneath that envelope: if a
//! target manifest references the same `(content_id, size)` more than once, the
//! sender should materialize that payload once and let reconcile place it at
//! every logical target position.

use std::collections::BTreeMap;

use crate::atp::delta::{CasChunkRef, ContentAddressedChunkStore, DeltaError, DeltaResyncPlan};
use crate::atp::object::ContentId;

/// Stable dedupe key for one content-addressed chunk payload.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeltaChunkKey {
    /// Domain-separated content id for the chunk bytes.
    pub content_id: ContentId,
    /// Chunk length in bytes.
    pub size_bytes: u64,
}

impl DeltaChunkKey {
    /// Build the key for a manifest chunk.
    #[must_use]
    pub fn from_chunk(chunk: &CasChunkRef) -> Self {
        Self {
            content_id: chunk.content_id.clone(),
            size_bytes: chunk.size_bytes,
        }
    }
}

/// One unique payload the sender must put on the delta stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaUniqueChunk {
    /// Unique content key.
    pub key: DeltaChunkKey,
    /// First logical missing chunk that references this content.
    pub representative: CasChunkRef,
    /// Ordinal in `DeltaResyncPlan::missing_chunks` where the content first appeared.
    pub first_missing_ordinal: usize,
    /// Number of logical missing chunks that share this payload.
    pub logical_ref_count: u64,
}

/// One logical target placement satisfied by a unique payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaChunkPlacement {
    /// Ordinal in `DeltaResyncPlan::missing_chunks`.
    pub missing_ordinal: usize,
    /// Ordinal in [`DeltaDedupSendSet::unique_chunks`].
    pub unique_ordinal: usize,
    /// Logical target chunk reference from the sender manifest.
    pub target_chunk: CasChunkRef,
}

/// Dedupe projection of a delta re-sync plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaDedupSendSet {
    /// Unique payloads to transmit, in first-use order.
    pub unique_chunks: Vec<DeltaUniqueChunk>,
    /// Logical target placements, in negotiated missing-chunk order.
    pub placements: Vec<DeltaChunkPlacement>,
    /// Logical bytes in the original missing set.
    pub logical_missing_bytes: u64,
    /// Bytes represented by unique payloads after content dedupe.
    pub unique_payload_bytes: u64,
    /// Count of logical missing chunks eliminated by dedupe.
    pub duplicate_missing_chunks: u64,
    /// Logical bytes eliminated by dedupe.
    pub duplicate_missing_bytes: u64,
}

impl DeltaDedupSendSet {
    /// Number of unique payloads the sender must materialize.
    #[must_use]
    pub fn unique_chunk_count(&self) -> usize {
        self.unique_chunks.len()
    }

    /// Number of logical missing placements reconstructed by the receiver.
    #[must_use]
    pub fn logical_missing_chunk_count(&self) -> usize {
        self.placements.len()
    }

    /// True when this send set saves bytes versus emitting every missing chunk.
    #[must_use]
    pub const fn saves_bytes(&self) -> bool {
        self.unique_payload_bytes < self.logical_missing_bytes
    }
}

/// Payload bytes for one unique content chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaUniquePayload {
    /// Unique content key.
    pub key: DeltaChunkKey,
    /// Representative logical chunk.
    pub representative: CasChunkRef,
    /// Verified chunk bytes.
    pub payload: Vec<u8>,
}

/// Concrete deduped payload set ready for an envelope owned by `delta.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaDedupPayloadSet {
    /// Dedupe metadata and placements.
    pub send_set: DeltaDedupSendSet,
    /// Unique payload bytes in send-set order.
    pub payloads: Vec<DeltaUniquePayload>,
    /// Actual payload bytes emitted by `payloads`.
    pub payload_bytes: u64,
}

impl DeltaDedupPayloadSet {
    /// Number of unique payloads.
    #[must_use]
    pub fn unique_payload_count(&self) -> usize {
        self.payloads.len()
    }

    /// True when this payload set is smaller than the original logical missing set.
    #[must_use]
    pub const fn saves_bytes(&self) -> bool {
        self.payload_bytes < self.send_set.logical_missing_bytes
    }
}

/// Collapse a delta plan's missing chunks into unique content payloads plus
/// logical target placements.
pub fn dedupe_delta_missing_chunks(
    plan: &DeltaResyncPlan,
) -> Result<DeltaDedupSendSet, DeltaError> {
    let mut by_key: BTreeMap<DeltaChunkKey, usize> = BTreeMap::new();
    let mut unique_chunks: Vec<DeltaUniqueChunk> = Vec::new();
    let mut placements = Vec::with_capacity(plan.missing_chunks.len());
    let mut unique_payload_bytes = 0u64;
    let mut duplicate_missing_chunks = 0u64;
    let mut duplicate_missing_bytes = 0u64;

    for (missing_ordinal, chunk) in plan.missing_chunks.iter().enumerate() {
        let key = DeltaChunkKey::from_chunk(chunk);
        let unique_ordinal = if let Some(&unique_ordinal) = by_key.get(&key) {
            duplicate_missing_chunks = duplicate_missing_chunks
                .checked_add(1)
                .ok_or(DeltaError::ChunkCountOverflow)?;
            duplicate_missing_bytes = duplicate_missing_bytes
                .checked_add(chunk.size_bytes)
                .ok_or(DeltaError::ChunkSizeOverflow)?;
            unique_chunks[unique_ordinal].logical_ref_count = unique_chunks[unique_ordinal]
                .logical_ref_count
                .checked_add(1)
                .ok_or(DeltaError::ChunkCountOverflow)?;
            unique_ordinal
        } else {
            let unique_ordinal = unique_chunks.len();
            by_key.insert(key.clone(), unique_ordinal);
            unique_payload_bytes = unique_payload_bytes
                .checked_add(chunk.size_bytes)
                .ok_or(DeltaError::ChunkSizeOverflow)?;
            unique_chunks.push(DeltaUniqueChunk {
                key,
                representative: chunk.clone(),
                first_missing_ordinal: missing_ordinal,
                logical_ref_count: 1,
            });
            unique_ordinal
        };

        placements.push(DeltaChunkPlacement {
            missing_ordinal,
            unique_ordinal,
            target_chunk: chunk.clone(),
        });
    }

    Ok(DeltaDedupSendSet {
        unique_chunks,
        placements,
        logical_missing_bytes: plan.missing_bytes,
        unique_payload_bytes,
        duplicate_missing_chunks,
        duplicate_missing_bytes,
    })
}

/// Build the deduped payload set from a sender CAS store.
pub fn build_dedup_payload_set(
    plan: &DeltaResyncPlan,
    sender_store: &ContentAddressedChunkStore,
) -> Result<DeltaDedupPayloadSet, DeltaError> {
    let send_set = dedupe_delta_missing_chunks(plan)?;
    let mut payloads = Vec::with_capacity(send_set.unique_chunks.len());
    let mut payload_bytes = 0u64;

    for unique in &send_set.unique_chunks {
        let payload = verified_payload(sender_store, &unique.representative)?;
        payload_bytes = payload_bytes
            .checked_add(u64::try_from(payload.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?)
            .ok_or(DeltaError::ChunkSizeOverflow)?;
        payloads.push(DeltaUniquePayload {
            key: unique.key.clone(),
            representative: unique.representative.clone(),
            payload: payload.to_vec(),
        });
    }

    Ok(DeltaDedupPayloadSet {
        send_set,
        payloads,
        payload_bytes,
    })
}

pub(crate) fn payload_matches_key(
    payload: &[u8],
    key: &DeltaChunkKey,
    chunk_index: u32,
) -> Result<(), DeltaError> {
    let payload_size = u64::try_from(payload.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
    if payload_size != key.size_bytes {
        return Err(DeltaError::ChunkPayloadSizeMismatch {
            index: chunk_index,
            expected: key.size_bytes,
            actual: payload_size,
        });
    }
    let actual = ContentId::from_bytes(payload);
    if actual != key.content_id {
        return Err(DeltaError::ChunkPayloadHashMismatch {
            index: chunk_index,
            expected: key.content_id.clone(),
            actual,
        });
    }
    Ok(())
}

fn verified_payload<'a>(
    store: &'a ContentAddressedChunkStore,
    chunk: &CasChunkRef,
) -> Result<&'a [u8], DeltaError> {
    let Some(payload) = store.get(&chunk.content_id) else {
        return Err(DeltaError::MissingChunk {
            index: chunk.index,
            content_id: chunk.content_id.clone(),
        });
    };
    payload_matches_key(payload, &DeltaChunkKey::from_chunk(chunk), chunk.index)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::delta::{
        PersistentChunkManifest, ReceiverCasCoverage,
        plan_incremental_resync_with_receiver_coverage,
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
    fn dedupe_send_set_transmits_duplicate_content_once() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"alpha"[..], &b"beta"[..], &b"alpha"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);

        let send_set = dedupe_delta_missing_chunks(&plan).expect("dedupe send set");

        assert_eq!(send_set.logical_missing_chunk_count(), 3);
        assert_eq!(send_set.unique_chunk_count(), 2);
        assert_eq!(send_set.logical_missing_bytes, 14);
        assert_eq!(send_set.unique_payload_bytes, 9);
        assert_eq!(send_set.duplicate_missing_chunks, 1);
        assert_eq!(send_set.duplicate_missing_bytes, 5);
        assert!(send_set.saves_bytes());
        assert_eq!(send_set.placements[0].unique_ordinal, 0);
        assert_eq!(send_set.placements[1].unique_ordinal, 1);
        assert_eq!(send_set.placements[2].unique_ordinal, 0);
        assert_eq!(send_set.unique_chunks[0].logical_ref_count, 2);
    }

    #[test]
    fn dedupe_payload_set_verifies_sender_store_payloads() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(
            &mut sender_store,
            "tree-a",
            &[&b"same"[..], &b"unique"[..], &b"same"[..]],
        );
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);

        let payloads = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        assert_eq!(payloads.unique_payload_count(), 2);
        assert_eq!(payloads.payload_bytes, 10);
        assert!(payloads.saves_bytes());
        assert_eq!(payloads.payloads[0].payload, b"same");
        assert_eq!(payloads.payloads[1].payload, b"unique");
    }
}
