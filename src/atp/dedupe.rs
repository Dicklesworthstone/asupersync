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

/// Canonical dedupe parts ready for a surrounding delta envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaDedupCanonicalParts {
    /// Canonical [`DeltaDedupSendSet`] metadata.
    pub metadata_bytes: Vec<u8>,
    /// Concatenated unique payload bytes in send-set order.
    pub unique_payload_bytes: Vec<u8>,
    /// Number of bytes in `metadata_bytes`.
    pub metadata_wire_bytes: u64,
    /// Number of bytes in `unique_payload_bytes`.
    pub unique_payload_wire_bytes: u64,
    /// Metadata plus unique payload bytes, excluding outer envelope framing.
    pub compact_wire_bytes: u64,
    /// Logical bytes represented by the original missing set.
    pub logical_missing_bytes: u64,
    /// Count of logical missing chunks eliminated by dedupe.
    pub duplicate_missing_chunks: u64,
    /// Logical missing bytes eliminated by dedupe.
    pub duplicate_missing_bytes: u64,
}

impl DeltaDedupCanonicalParts {
    /// Build canonical metadata and unique payload bytes from a verified payload set.
    pub fn from_payload_set(payload_set: &DeltaDedupPayloadSet) -> Result<Self, DeltaError> {
        payload_set.validate_against_send_set()?;
        let metadata_bytes = payload_set.send_set.to_canonical_bytes()?;
        let unique_payload_bytes = payload_set.to_canonical_payload_bytes()?;
        let metadata_wire_bytes =
            u64::try_from(metadata_bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        let unique_payload_wire_bytes =
            u64::try_from(unique_payload_bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        let compact_wire_bytes = metadata_wire_bytes
            .checked_add(unique_payload_wire_bytes)
            .ok_or(DeltaError::ChunkSizeOverflow)?;

        Ok(Self {
            metadata_bytes,
            unique_payload_bytes,
            metadata_wire_bytes,
            unique_payload_wire_bytes,
            compact_wire_bytes,
            logical_missing_bytes: payload_set.send_set.logical_missing_bytes,
            duplicate_missing_chunks: payload_set.send_set.duplicate_missing_chunks,
            duplicate_missing_bytes: payload_set.send_set.duplicate_missing_bytes,
        })
    }

    /// True when the canonical parts are smaller than the logical missing bytes.
    #[must_use]
    pub const fn saves_bytes(&self) -> bool {
        self.compact_wire_bytes < self.logical_missing_bytes
    }

    /// Logical bytes saved by sending canonical parts instead of all missing chunks.
    #[must_use]
    pub fn saved_bytes(&self) -> u64 {
        self.logical_missing_bytes
            .saturating_sub(self.compact_wire_bytes)
    }

    /// Compact bytes plus the caller-owned outer delta envelope overhead.
    pub fn compact_wire_bytes_with_outer_overhead(
        &self,
        outer_envelope_overhead_bytes: u64,
    ) -> Result<u64, DeltaError> {
        self.compact_wire_bytes
            .checked_add(outer_envelope_overhead_bytes)
            .ok_or(DeltaError::ChunkSizeOverflow)
    }

    /// True when compact parts plus outer envelope overhead beat logical bytes.
    pub fn saves_bytes_with_outer_overhead(
        &self,
        outer_envelope_overhead_bytes: u64,
    ) -> Result<bool, DeltaError> {
        Ok(
            self.compact_wire_bytes_with_outer_overhead(outer_envelope_overhead_bytes)?
                < self.logical_missing_bytes,
        )
    }

    /// Logical bytes avoided after accounting for the caller-owned envelope.
    pub fn saved_bytes_with_outer_overhead(
        &self,
        outer_envelope_overhead_bytes: u64,
    ) -> Result<u64, DeltaError> {
        let wire_bytes =
            self.compact_wire_bytes_with_outer_overhead(outer_envelope_overhead_bytes)?;
        Ok(self.logical_missing_bytes.saturating_sub(wire_bytes))
    }

    /// Decode canonical parts into a verified payload set for the receiver.
    pub fn decode_payload_set(
        &self,
        plan: &DeltaResyncPlan,
    ) -> Result<DeltaDedupPayloadSet, DeltaError> {
        let metadata_wire_bytes =
            u64::try_from(self.metadata_bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        if metadata_wire_bytes != self.metadata_wire_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.metadata_wire_bytes,
                computed: metadata_wire_bytes,
            });
        }
        let unique_payload_wire_bytes = u64::try_from(self.unique_payload_bytes.len())
            .map_err(|_| DeltaError::ChunkSizeOverflow)?;
        if unique_payload_wire_bytes != self.unique_payload_wire_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.unique_payload_wire_bytes,
                computed: unique_payload_wire_bytes,
            });
        }
        let compact_wire_bytes = metadata_wire_bytes
            .checked_add(unique_payload_wire_bytes)
            .ok_or(DeltaError::ChunkSizeOverflow)?;
        if compact_wire_bytes != self.compact_wire_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.compact_wire_bytes,
                computed: compact_wire_bytes,
            });
        }

        let payload_set = DeltaDedupPayloadSet::from_canonical_parts(
            plan,
            &self.metadata_bytes,
            &self.unique_payload_bytes,
        )?;
        if payload_set.send_set.logical_missing_bytes != self.logical_missing_bytes {
            return Err(DeltaError::DeltaSendPlanWholeBytesMismatch {
                encoded: self.logical_missing_bytes,
                expected: payload_set.send_set.logical_missing_bytes,
            });
        }
        if payload_set.send_set.duplicate_missing_chunks != self.duplicate_missing_chunks {
            return Err(DeltaError::DeltaSendPlanItemCountMismatch {
                actual: usize::try_from(self.duplicate_missing_chunks)
                    .map_err(|_| DeltaError::ChunkCountOverflow)?,
                expected: usize::try_from(payload_set.send_set.duplicate_missing_chunks)
                    .map_err(|_| DeltaError::ChunkCountOverflow)?,
            });
        }
        if payload_set.send_set.duplicate_missing_bytes != self.duplicate_missing_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.duplicate_missing_bytes,
                computed: payload_set.send_set.duplicate_missing_bytes,
            });
        }
        Ok(payload_set)
    }
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

    /// Payload + metadata bytes for the compact dedupe envelope.
    pub fn compact_wire_bytes(&self) -> Result<u64, DeltaError> {
        self.validate_against_send_set()?;
        let metadata = u64::try_from(self.send_set.canonical_metadata_bytes())
            .map_err(|_| DeltaError::ChunkSizeOverflow)?;
        self.payload_bytes
            .checked_add(metadata)
            .ok_or(DeltaError::ChunkSizeOverflow)
    }

    /// Encode unique payload bytes in send-set order.
    ///
    /// The surrounding delta envelope owns framing. The matching metadata is
    /// [`DeltaDedupSendSet::to_canonical_bytes`].
    pub fn to_canonical_payload_bytes(&self) -> Result<Vec<u8>, DeltaError> {
        self.validate_against_send_set()?;
        let capacity =
            usize::try_from(self.payload_bytes).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        let mut out = Vec::with_capacity(capacity);
        for payload in &self.payloads {
            out.extend_from_slice(&payload.payload);
        }
        Ok(out)
    }

    /// Decode canonical dedupe metadata plus its unique payload byte stream.
    pub fn from_canonical_parts(
        plan: &DeltaResyncPlan,
        metadata_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<Self, DeltaError> {
        let send_set = DeltaDedupSendSet::from_canonical_bytes(plan, metadata_bytes)?;
        let encoded_payload_bytes =
            u64::try_from(payload_bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        if encoded_payload_bytes != send_set.unique_payload_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: encoded_payload_bytes,
                computed: send_set.unique_payload_bytes,
            });
        }

        let mut cursor = 0usize;
        let mut payloads = Vec::with_capacity(send_set.unique_chunks.len());
        for unique in &send_set.unique_chunks {
            let size = usize::try_from(unique.key.size_bytes)
                .map_err(|_| DeltaError::ChunkSizeOverflow)?;
            let end = cursor
                .checked_add(size)
                .ok_or(DeltaError::TruncatedManifest)?;
            let Some(payload) = payload_bytes.get(cursor..end) else {
                return Err(DeltaError::TruncatedManifest);
            };
            payload_matches_key(payload, &unique.key, unique.representative.index)?;
            payloads.push(DeltaUniquePayload {
                key: unique.key.clone(),
                representative: unique.representative.clone(),
                payload: payload.to_vec(),
            });
            cursor = end;
        }
        if cursor != payload_bytes.len() {
            return Err(DeltaError::TrailingBytes {
                trailing: payload_bytes.len() - cursor,
            });
        }

        let decoded = Self {
            send_set,
            payloads,
            payload_bytes: encoded_payload_bytes,
        };
        decoded.validate_against_send_set()?;
        Ok(decoded)
    }

    /// Verify unique payloads are byte-identical to the dedupe send-set keys.
    pub fn validate_against_send_set(&self) -> Result<(), DeltaError> {
        if self.payloads.len() != self.send_set.unique_chunks.len() {
            return Err(DeltaError::DeltaSendPlanItemCountMismatch {
                actual: self.payloads.len(),
                expected: self.send_set.unique_chunks.len(),
            });
        }

        let mut computed_payload_bytes = 0u64;
        for (ordinal, (payload, unique)) in self
            .payloads
            .iter()
            .zip(&self.send_set.unique_chunks)
            .enumerate()
        {
            if payload.key != unique.key || payload.representative != unique.representative {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            }
            payload_matches_key(&payload.payload, &payload.key, payload.representative.index)?;
            computed_payload_bytes = computed_payload_bytes
                .checked_add(
                    u64::try_from(payload.payload.len())
                        .map_err(|_| DeltaError::ChunkSizeOverflow)?,
                )
                .ok_or(DeltaError::ChunkSizeOverflow)?;
        }

        if computed_payload_bytes != self.payload_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.payload_bytes,
                computed: computed_payload_bytes,
            });
        }
        if self.payload_bytes != self.send_set.unique_payload_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.payload_bytes,
                computed: self.send_set.unique_payload_bytes,
            });
        }
        Ok(())
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

/// Build canonical dedupe parts directly from a sender CAS store.
pub fn build_canonical_dedup_payload_parts(
    plan: &DeltaResyncPlan,
    sender_store: &ContentAddressedChunkStore,
) -> Result<DeltaDedupCanonicalParts, DeltaError> {
    let payload_set = build_dedup_payload_set(plan, sender_store)?;
    DeltaDedupCanonicalParts::from_payload_set(&payload_set)
}

/// Build canonical dedupe parts only when they beat logical missing bytes after
/// caller-owned outer envelope overhead is included.
pub fn build_canonical_dedup_payload_parts_if_smaller(
    plan: &DeltaResyncPlan,
    sender_store: &ContentAddressedChunkStore,
    outer_envelope_overhead_bytes: u64,
) -> Result<Option<DeltaDedupCanonicalParts>, DeltaError> {
    let parts = build_canonical_dedup_payload_parts(plan, sender_store)?;
    if parts.saves_bytes_with_outer_overhead(outer_envelope_overhead_bytes)? {
        Ok(Some(parts))
    } else {
        Ok(None)
    }
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
    fn dedupe_payload_set_canonical_parts_round_trip() {
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
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        let metadata = payload_set.send_set.to_canonical_bytes().expect("metadata");
        let payload_bytes = payload_set
            .to_canonical_payload_bytes()
            .expect("payload bytes");
        let decoded = DeltaDedupPayloadSet::from_canonical_parts(&plan, &metadata, &payload_bytes)
            .expect("decode canonical parts");

        assert_eq!(decoded, payload_set);
        assert_eq!(
            payload_set.compact_wire_bytes().unwrap(),
            payload_set.payload_bytes + u64::try_from(metadata.len()).unwrap()
        );
        assert!(payload_set.compact_wire_bytes().unwrap() < sender.total_size_bytes);
    }

    #[test]
    fn canonical_dedup_parts_package_unique_payloads_once() {
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
        let payload_set = parts.decode_payload_set(&plan).expect("payload set");

        assert_eq!(parts.unique_payload_wire_bytes, 5120);
        assert_eq!(parts.logical_missing_bytes, sender.total_size_bytes);
        assert_eq!(parts.duplicate_missing_chunks, 1);
        assert_eq!(parts.duplicate_missing_bytes, 4096);
        assert_eq!(payload_set.unique_payload_count(), 2);
        assert!(parts.saves_bytes());
        assert_eq!(
            parts.compact_wire_bytes,
            parts.metadata_wire_bytes + parts.unique_payload_wire_bytes
        );
        assert_eq!(
            parts.saved_bytes(),
            sender.total_size_bytes - parts.compact_wire_bytes
        );
        assert_eq!(
            parts
                .compact_wire_bytes_with_outer_overhead(128)
                .expect("wire plus outer overhead"),
            parts.compact_wire_bytes + 128
        );
        assert!(
            parts
                .saves_bytes_with_outer_overhead(128)
                .expect("saves with outer overhead")
        );
        assert_eq!(
            parts
                .saved_bytes_with_outer_overhead(128)
                .expect("saved with overhead"),
            sender.total_size_bytes - parts.compact_wire_bytes - 128
        );
    }

    #[test]
    fn canonical_dedup_parts_if_smaller_accounts_outer_envelope() {
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
        let saved_without_outer = parts.saved_bytes();
        assert!(saved_without_outer > 0);

        let selected = build_canonical_dedup_payload_parts_if_smaller(
            &plan,
            &sender_store,
            saved_without_outer - 1,
        )
        .expect("selected compact parts")
        .expect("compact still saves one byte");
        assert_eq!(selected.metadata_bytes, parts.metadata_bytes);
        assert_eq!(selected.unique_payload_bytes, parts.unique_payload_bytes);

        let rejected = build_canonical_dedup_payload_parts_if_smaller(
            &plan,
            &sender_store,
            saved_without_outer,
        )
        .expect("compact selection");
        assert!(rejected.is_none());
    }

    #[test]
    fn canonical_dedup_parts_reject_accounting_drift() {
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

        let mut bad_metadata_len = parts.clone();
        bad_metadata_len.metadata_wire_bytes += 1;
        assert!(matches!(
            bad_metadata_len.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));

        let mut bad_compact_len = parts.clone();
        bad_compact_len.compact_wire_bytes += 1;
        assert!(matches!(
            bad_compact_len.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));

        let mut bad_logical_bytes = parts.clone();
        bad_logical_bytes.logical_missing_bytes -= 1;
        assert!(matches!(
            bad_logical_bytes.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanWholeBytesMismatch { .. })
        ));

        let mut bad_duplicate_chunks = parts.clone();
        bad_duplicate_chunks.duplicate_missing_chunks += 1;
        assert!(matches!(
            bad_duplicate_chunks.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanItemCountMismatch { .. })
        ));

        let mut bad_duplicate_bytes = parts;
        bad_duplicate_bytes.duplicate_missing_bytes += 1;
        assert!(matches!(
            bad_duplicate_bytes.decode_payload_set(&plan),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));
    }

    #[test]
    fn canonical_dedup_parts_are_stable_across_ingest_runs() {
        let repeated = vec![b'r'; 4096];
        let unique = vec![b'u'; 1024];
        let chunks = [repeated.as_slice(), unique.as_slice(), repeated.as_slice()];

        let mut sender_store_a = ContentAddressedChunkStore::new();
        let mut receiver_store_a = ContentAddressedChunkStore::new();
        let sender_a = manifest(&mut sender_store_a, "tree-a", &chunks);
        let receiver_a = manifest(&mut receiver_store_a, "tree-a", &[]);
        let coverage_a = ReceiverCasCoverage::from_manifest(&receiver_a);
        let plan_a = plan_incremental_resync_with_receiver_coverage(
            &sender_a,
            Some(&receiver_a),
            &coverage_a,
        );
        let parts_a = build_canonical_dedup_payload_parts(&plan_a, &sender_store_a)
            .expect("canonical parts a");

        let mut sender_store_b = ContentAddressedChunkStore::new();
        let mut receiver_store_b = ContentAddressedChunkStore::new();
        let sender_b = manifest(&mut sender_store_b, "tree-a", &chunks);
        let receiver_b = manifest(&mut receiver_store_b, "tree-a", &[]);
        let coverage_b = ReceiverCasCoverage::from_manifest(&receiver_b);
        let plan_b = plan_incremental_resync_with_receiver_coverage(
            &sender_b,
            Some(&receiver_b),
            &coverage_b,
        );
        let parts_b = build_canonical_dedup_payload_parts(&plan_b, &sender_store_b)
            .expect("canonical parts b");

        assert_eq!(sender_a.to_canonical_bytes(), sender_b.to_canonical_bytes());
        assert_eq!(plan_a.missing_chunks, plan_b.missing_chunks);
        assert_eq!(parts_a.metadata_bytes, parts_b.metadata_bytes);
        assert_eq!(parts_a.unique_payload_bytes, parts_b.unique_payload_bytes);
        assert_eq!(parts_a.compact_wire_bytes, parts_b.compact_wire_bytes);
    }

    #[test]
    fn dedupe_payload_set_canonical_parts_fail_closed_on_payload_drift() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = manifest(&mut sender_store, "tree-a", &[&b"alpha"[..], &b"beta"[..]]);
        let receiver = manifest(&mut receiver_store, "tree-a", &[]);
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let plan =
            plan_incremental_resync_with_receiver_coverage(&sender, Some(&receiver), &coverage);
        let payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");
        let metadata = payload_set.send_set.to_canonical_bytes().expect("metadata");
        let mut payload_bytes = payload_set
            .to_canonical_payload_bytes()
            .expect("payload bytes");

        payload_bytes[0] ^= 0x40;
        assert!(matches!(
            DeltaDedupPayloadSet::from_canonical_parts(&plan, &metadata, &payload_bytes),
            Err(DeltaError::ChunkPayloadHashMismatch { .. })
        ));
        payload_bytes.pop();
        assert!(matches!(
            DeltaDedupPayloadSet::from_canonical_parts(&plan, &metadata, &payload_bytes),
            Err(DeltaError::DeltaSendPlanPayloadBytesMismatch { .. })
        ));
    }

    #[test]
    fn dedupe_payload_set_rejects_reordered_unique_payloads() {
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
        let mut payload_set = build_dedup_payload_set(&plan, &sender_store).expect("payload set");

        payload_set.payloads.swap(0, 1);

        assert!(matches!(
            payload_set.validate_against_send_set(),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 0 })
        ));
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
    fn dedupe_send_set_canonical_metadata_rejects_invalid_unique_ordinal() {
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
        let mut send_set = dedupe_delta_missing_chunks(&plan).expect("dedupe send set");

        send_set.placements[1].unique_ordinal = send_set.unique_chunks.len();
        let encoded = send_set
            .to_canonical_bytes()
            .expect("encode forged metadata");

        assert_eq!(
            DeltaDedupSendSet::from_canonical_bytes(&plan, &encoded),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 1 })
        );
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
