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

const DELTA_DEDUP_SEND_SET_MAGIC: &[u8] = b"ASUP_ATP_DELTA_DEDUP_SEND_SET_V1\0";
const ENCODED_CHUNK_REF_BYTES: usize = 4 + 8 + 8 + 32;
const ENCODED_CHUNK_KEY_BYTES: usize = 32 + 8;
const ENCODED_UNIQUE_CHUNK_BYTES: usize = ENCODED_CHUNK_KEY_BYTES + ENCODED_CHUNK_REF_BYTES + 8 + 8;
const ENCODED_PLACEMENT_BYTES: usize = 8 + 8 + ENCODED_CHUNK_REF_BYTES;

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

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.content_id.hash());
        out.extend_from_slice(&self.size_bytes.to_be_bytes());
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

    /// Conservative metadata bytes for this compact send-set descriptor.
    #[must_use]
    pub fn canonical_metadata_bytes(&self) -> usize {
        DELTA_DEDUP_SEND_SET_MAGIC.len()
            + 8
            + 8
            + 8
            + 8
            + 8
            + 8
            + self.unique_chunks.len() * ENCODED_UNIQUE_CHUNK_BYTES
            + self.placements.len() * ENCODED_PLACEMENT_BYTES
    }

    /// Payload + metadata bytes for a compact unique-payload envelope.
    #[must_use]
    pub fn compact_wire_floor_bytes(&self) -> Result<u64, DeltaError> {
        let metadata = u64::try_from(self.canonical_metadata_bytes())
            .map_err(|_| DeltaError::ChunkSizeOverflow)?;
        self.unique_payload_bytes
            .checked_add(metadata)
            .ok_or(DeltaError::ChunkSizeOverflow)
    }

    /// Encode this unique-payload placement manifest deterministically.
    ///
    /// `delta.rs` owns the surrounding transfer envelope. These bytes are the
    /// compact metadata that lets that envelope send each unique payload once
    /// while preserving the negotiated missing-chunk order.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DeltaError> {
        let mut out = Vec::with_capacity(self.canonical_metadata_bytes());
        out.extend_from_slice(DELTA_DEDUP_SEND_SET_MAGIC);
        write_usize_as_u64(&mut out, self.unique_chunks.len())?;
        write_usize_as_u64(&mut out, self.placements.len())?;
        out.extend_from_slice(&self.logical_missing_bytes.to_be_bytes());
        out.extend_from_slice(&self.unique_payload_bytes.to_be_bytes());
        out.extend_from_slice(&self.duplicate_missing_chunks.to_be_bytes());
        out.extend_from_slice(&self.duplicate_missing_bytes.to_be_bytes());
        for unique in &self.unique_chunks {
            unique.key.encode_into(&mut out);
            encode_chunk_ref(&mut out, &unique.representative);
            write_usize_as_u64(&mut out, unique.first_missing_ordinal)?;
            out.extend_from_slice(&unique.logical_ref_count.to_be_bytes());
        }
        for placement in &self.placements {
            write_usize_as_u64(&mut out, placement.missing_ordinal)?;
            write_usize_as_u64(&mut out, placement.unique_ordinal)?;
            encode_chunk_ref(&mut out, &placement.target_chunk);
        }
        Ok(out)
    }

    /// Decode compact placement metadata and verify it still matches the
    /// negotiated base plan.
    pub fn from_canonical_bytes(plan: &DeltaResyncPlan, bytes: &[u8]) -> Result<Self, DeltaError> {
        let mut reader = DedupReader::new(bytes);
        reader.expect_magic(DELTA_DEDUP_SEND_SET_MAGIC)?;
        let unique_count = reader.read_usize()?;
        let placement_count = reader.read_usize()?;
        let logical_missing_bytes = reader.read_u64()?;
        let unique_payload_bytes = reader.read_u64()?;
        let duplicate_missing_chunks = reader.read_u64()?;
        let duplicate_missing_bytes = reader.read_u64()?;
        reader.ensure_remaining_manifest_entries(unique_count, placement_count)?;

        let mut unique_chunks = Vec::with_capacity(unique_count);
        for _ in 0..unique_count {
            let key = reader.read_chunk_key()?;
            let representative = reader.read_chunk_ref()?;
            let first_missing_ordinal = reader.read_usize()?;
            let logical_ref_count = reader.read_u64()?;
            unique_chunks.push(DeltaUniqueChunk {
                key,
                representative,
                first_missing_ordinal,
                logical_ref_count,
            });
        }

        let mut placements = Vec::with_capacity(placement_count);
        for _ in 0..placement_count {
            placements.push(DeltaChunkPlacement {
                missing_ordinal: reader.read_usize()?,
                unique_ordinal: reader.read_usize()?,
                target_chunk: reader.read_chunk_ref()?,
            });
        }
        reader.expect_eof()?;

        let decoded = Self {
            unique_chunks,
            placements,
            logical_missing_bytes,
            unique_payload_bytes,
            duplicate_missing_chunks,
            duplicate_missing_bytes,
        };
        decoded.validate_against_plan(plan)?;
        Ok(decoded)
    }

    /// Verify decoded compact metadata against the negotiated base plan.
    pub fn validate_against_plan(&self, plan: &DeltaResyncPlan) -> Result<(), DeltaError> {
        if self.logical_missing_bytes != plan.missing_bytes {
            return Err(DeltaError::DeltaSendPlanWholeBytesMismatch {
                encoded: self.logical_missing_bytes,
                expected: plan.missing_bytes,
            });
        }
        if self.placements.len() != plan.missing_chunks.len() {
            return Err(DeltaError::DeltaSendPlanItemCountMismatch {
                actual: self.placements.len(),
                expected: plan.missing_chunks.len(),
            });
        }

        let mut recomputed_unique_bytes = 0u64;
        let mut recomputed_duplicate_chunks = 0u64;
        let mut recomputed_duplicate_bytes = 0u64;
        for (unique_ordinal, unique) in self.unique_chunks.iter().enumerate() {
            if unique.logical_ref_count == 0 {
                return Err(DeltaError::DeltaSendPlanChunkMismatch {
                    ordinal: unique.first_missing_ordinal,
                });
            }
            if unique.key != DeltaChunkKey::from_chunk(&unique.representative) {
                return Err(DeltaError::DeltaSendPlanChunkMismatch {
                    ordinal: unique.first_missing_ordinal,
                });
            }
            let Some(expected_first) = plan.missing_chunks.get(unique.first_missing_ordinal) else {
                return Err(DeltaError::DeltaSendPlanChunkMismatch {
                    ordinal: unique.first_missing_ordinal,
                });
            };
            if expected_first != &unique.representative {
                return Err(DeltaError::DeltaSendPlanChunkMismatch {
                    ordinal: unique.first_missing_ordinal,
                });
            }
            recomputed_unique_bytes = recomputed_unique_bytes
                .checked_add(unique.key.size_bytes)
                .ok_or(DeltaError::ChunkSizeOverflow)?;
            if unique.logical_ref_count > 1 {
                let duplicate_refs = unique.logical_ref_count - 1;
                recomputed_duplicate_chunks = recomputed_duplicate_chunks
                    .checked_add(duplicate_refs)
                    .ok_or(DeltaError::ChunkCountOverflow)?;
                recomputed_duplicate_bytes = recomputed_duplicate_bytes
                    .checked_add(
                        duplicate_refs
                            .checked_mul(unique.key.size_bytes)
                            .ok_or(DeltaError::ChunkSizeOverflow)?,
                    )
                    .ok_or(DeltaError::ChunkSizeOverflow)?;
            }

            let placement_refs = self
                .placements
                .iter()
                .filter(|placement| placement.unique_ordinal == unique_ordinal)
                .count();
            if u64::try_from(placement_refs).map_err(|_| DeltaError::ChunkCountOverflow)?
                != unique.logical_ref_count
            {
                return Err(DeltaError::DeltaSendPlanChunkMismatch {
                    ordinal: unique.first_missing_ordinal,
                });
            }
        }

        for (ordinal, placement) in self.placements.iter().enumerate() {
            if placement.missing_ordinal != ordinal {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            }
            let Some(expected_chunk) = plan.missing_chunks.get(ordinal) else {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            };
            if expected_chunk != &placement.target_chunk {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            }
            let Some(unique) = self.unique_chunks.get(placement.unique_ordinal) else {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            };
            if unique.key != DeltaChunkKey::from_chunk(expected_chunk) {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            }
        }

        if recomputed_unique_bytes != self.unique_payload_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.unique_payload_bytes,
                computed: recomputed_unique_bytes,
            });
        }
        if recomputed_duplicate_chunks != self.duplicate_missing_chunks {
            return Err(DeltaError::DeltaSendPlanItemCountMismatch {
                actual: usize::try_from(self.duplicate_missing_chunks)
                    .map_err(|_| DeltaError::ChunkCountOverflow)?,
                expected: usize::try_from(recomputed_duplicate_chunks)
                    .map_err(|_| DeltaError::ChunkCountOverflow)?,
            });
        }
        if recomputed_duplicate_bytes != self.duplicate_missing_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.duplicate_missing_bytes,
                computed: recomputed_duplicate_bytes,
            });
        }
        Ok(())
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

fn write_usize_as_u64(out: &mut Vec<u8>, value: usize) -> Result<(), DeltaError> {
    out.extend_from_slice(
        &u64::try_from(value)
            .map_err(|_| DeltaError::ChunkCountOverflow)?
            .to_be_bytes(),
    );
    Ok(())
}

fn encode_chunk_ref(out: &mut Vec<u8>, chunk: &CasChunkRef) {
    out.extend_from_slice(&chunk.index.to_be_bytes());
    out.extend_from_slice(&chunk.byte_offset.to_be_bytes());
    out.extend_from_slice(&chunk.size_bytes.to_be_bytes());
    out.extend_from_slice(chunk.content_id.hash());
}

struct DedupReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> DedupReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn expect_magic(&mut self, magic: &[u8]) -> Result<(), DeltaError> {
        let got = self.read_exact(magic.len())?;
        if got == magic {
            Ok(())
        } else {
            Err(DeltaError::BadMagic)
        }
    }

    fn expect_eof(&self) -> Result<(), DeltaError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(DeltaError::TrailingBytes {
                trailing: self.bytes.len() - self.cursor,
            })
        }
    }

    fn read_usize(&mut self) -> Result<usize, DeltaError> {
        usize::try_from(self.read_u64()?).map_err(|_| DeltaError::ChunkCountOverflow)
    }

    fn read_u64(&mut self) -> Result<u64, DeltaError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, DeltaError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], DeltaError> {
        self.read_array::<32>()
    }

    fn read_chunk_key(&mut self) -> Result<DeltaChunkKey, DeltaError> {
        Ok(DeltaChunkKey {
            content_id: ContentId::new(self.read_hash()?),
            size_bytes: self.read_u64()?,
        })
    }

    fn read_chunk_ref(&mut self) -> Result<CasChunkRef, DeltaError> {
        Ok(CasChunkRef {
            index: self.read_u32()?,
            byte_offset: self.read_u64()?,
            size_bytes: self.read_u64()?,
            content_id: ContentId::new(self.read_hash()?),
        })
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeltaError> {
        let bytes = self.read_exact(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], DeltaError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(DeltaError::TruncatedManifest)?;
        let Some(bytes) = self.bytes.get(self.cursor..end) else {
            return Err(DeltaError::TruncatedManifest);
        };
        self.cursor = end;
        Ok(bytes)
    }

    fn ensure_remaining_manifest_entries(
        &self,
        unique_count: usize,
        placement_count: usize,
    ) -> Result<(), DeltaError> {
        let unique_bytes = unique_count
            .checked_mul(ENCODED_UNIQUE_CHUNK_BYTES)
            .ok_or(DeltaError::ChunkCountOverflow)?;
        let placement_bytes = placement_count
            .checked_mul(ENCODED_PLACEMENT_BYTES)
            .ok_or(DeltaError::ChunkCountOverflow)?;
        let expected = unique_bytes
            .checked_add(placement_bytes)
            .ok_or(DeltaError::ChunkCountOverflow)?;
        if self.bytes.len().saturating_sub(self.cursor) < expected {
            return Err(DeltaError::TruncatedManifest);
        }
        Ok(())
    }
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

    #[test]
    fn dedupe_send_set_canonical_metadata_round_trips() {
        let repeated = vec![b'x'; 4096];
        let unique = vec![b'y'; 2048];
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
        let send_set = dedupe_delta_missing_chunks(&plan).expect("dedupe send set");

        let encoded = send_set.to_canonical_bytes().expect("encode metadata");
        let decoded =
            DeltaDedupSendSet::from_canonical_bytes(&plan, &encoded).expect("decode metadata");

        assert_eq!(decoded, send_set);
        assert_eq!(encoded.len(), send_set.canonical_metadata_bytes());
        assert_eq!(
            send_set.compact_wire_floor_bytes().unwrap(),
            send_set.unique_payload_bytes + u64::try_from(encoded.len()).unwrap()
        );
        assert!(send_set.compact_wire_floor_bytes().unwrap() < send_set.logical_missing_bytes);
    }

    #[test]
    fn dedupe_send_set_canonical_metadata_fails_closed_on_drift() {
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
        let encoded = send_set.to_canonical_bytes().expect("encode metadata");

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0x80;
        assert_eq!(
            DeltaDedupSendSet::from_canonical_bytes(&plan, &bad_magic).unwrap_err(),
            DeltaError::BadMagic
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            DeltaDedupSendSet::from_canonical_bytes(&plan, &trailing),
            Err(DeltaError::TrailingBytes { trailing: 1 })
        ));

        let mut drifted = send_set.clone();
        drifted.placements[2].unique_ordinal = 1;
        assert!(matches!(
            drifted.validate_against_plan(&plan),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 2 })
        ));
    }
}
