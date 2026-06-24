//! Delta-transfer primitives for ATP's rsync-killer path.
//!
//! The B-8 delta stack builds on content-defined chunks by persisting chunk
//! identity, order, and size in a Merkle-bound manifest. The chunk store is
//! content-addressed; the manifest keeps the logical object layout and projects
//! directly into the existing transfer journal resume shape.

use crate::atp::dedupe::dedupe_delta_missing_chunks;
use crate::atp::delta_subchunk::{self, SubBlockSignature, SubDeltaOp};
use crate::atp::journal::TransferResumeChunk;
use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
use crate::atp::object::ContentId;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Canonical schema marker for persisted ATP delta manifests.
pub const ATP_DELTA_CHUNK_MANIFEST_SCHEMA: &str = "asupersync.atp.delta.chunk-manifest.v1";

const MANIFEST_MAGIC: &[u8] = b"ASUP_ATP_DELTA_CHUNK_MANIFEST_V1\0";
const MANIFEST_HASH_DOMAIN: &[u8] = b"asupersync.atp.delta.chunk-manifest.root.v1\0";
const SUBDELTA_OPS_MAGIC: &[u8] = b"ASUP_ATP_DELTA_SUBCHUNK_OPS_V1\0";
const DELTA_RESYNC_SEND_PLAN_MAGIC: &[u8] = b"ASUP_ATP_DELTA_RESYNC_SEND_PLAN_V1\0";
const ENCODED_CHUNK_BYTES: usize = 4 + 8 + 8 + 32;
const SUBDELTA_OP_COPY: u8 = 0;
const SUBDELTA_OP_LITERAL: u8 = 1;
const DELTA_SEND_ITEM_WHOLE_CHUNK: u8 = 0;
const DELTA_SEND_ITEM_SUBCHUNK_OPS: u8 = 1;
const DELTA_SEND_ITEM_REPEATED_CHUNK: u8 = 2;
const DELTA_SEND_ITEM_WHOLE_CHUNK_RUN: u8 = 3;
const RECEIVER_HAVE_SET_BASE_WIRE_BYTES: u64 = 32 + 8 + 8;
const RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES: u64 = 32 + 8;

/// Schema marker for receiver-advertised delta have-set negotiation.
pub const ATP_DELTA_RECEIVER_HAVE_SET_SCHEMA: &str = "asupersync.atp.delta.receiver-have-set.v1";

/// A logical object chunk addressed by its content hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CasChunkRef {
    /// Zero-based chunk index in logical object order.
    pub index: u32,
    /// Byte offset in the logical object stream.
    pub byte_offset: u64,
    /// Chunk length in bytes.
    pub size_bytes: u64,
    /// Domain-separated content id for the chunk bytes.
    pub content_id: ContentId,
}

impl CasChunkRef {
    /// Build a chunk reference by hashing the provided bytes.
    pub fn from_bytes(index: u32, byte_offset: u64, bytes: &[u8]) -> Result<Self, DeltaError> {
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        Ok(Self {
            index,
            byte_offset,
            size_bytes,
            content_id: ContentId::from_bytes(bytes),
        })
    }

    /// Build a chunk reference from an existing manifest boundary.
    #[must_use]
    pub const fn from_boundary(boundary: &ChunkBoundary) -> Self {
        Self {
            index: boundary.index,
            byte_offset: boundary.byte_offset,
            size_bytes: boundary.size_bytes,
            content_id: ContentId::new(boundary.content_hash),
        }
    }

    /// Convert this reference into a general ATP chunk boundary.
    #[must_use]
    pub const fn to_boundary(&self, strategy: ChunkStrategy) -> ChunkBoundary {
        ChunkBoundary {
            index: self.index,
            byte_offset: self.byte_offset,
            size_bytes: self.size_bytes,
            content_hash: *self.content_id.hash(),
            strategy,
            metadata: None,
        }
    }

    /// Convert this reference into the existing transfer journal resume shape.
    #[must_use]
    pub const fn to_journal_resume_chunk(&self) -> TransferResumeChunk {
        TransferResumeChunk {
            chunk_offset: self.byte_offset,
            chunk_size: self.size_bytes,
            chunk_hash: *self.content_id.hash(),
        }
    }
}

/// Result of inserting one chunk into the content-addressed store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkStoreInsert {
    /// Content id of the inserted or existing chunk.
    pub content_id: ContentId,
    /// Chunk size in bytes.
    pub size_bytes: u64,
    /// True only when the payload was not already present.
    pub inserted: bool,
}

/// Aggregate report for a logical chunk ingestion pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkStoreInsertReport {
    /// Total logical chunks observed.
    pub total_chunks: u64,
    /// Unique chunks newly stored.
    pub inserted_chunks: u64,
    /// Logical chunks already present in the store.
    pub duplicate_chunks: u64,
    /// Bytes newly stored.
    pub inserted_bytes: u64,
    /// Logical bytes skipped because the content was already present.
    pub duplicate_bytes: u64,
}

impl ChunkStoreInsertReport {
    fn record(&mut self, insert: &ChunkStoreInsert) -> Result<(), DeltaError> {
        self.total_chunks = self
            .total_chunks
            .checked_add(1)
            .ok_or(DeltaError::ChunkCountOverflow)?;

        if insert.inserted {
            self.inserted_chunks = self
                .inserted_chunks
                .checked_add(1)
                .ok_or(DeltaError::ChunkCountOverflow)?;
            self.inserted_bytes = self
                .inserted_bytes
                .checked_add(insert.size_bytes)
                .ok_or(DeltaError::ChunkSizeOverflow)?;
        } else {
            self.duplicate_chunks = self
                .duplicate_chunks
                .checked_add(1)
                .ok_or(DeltaError::ChunkCountOverflow)?;
            self.duplicate_bytes = self
                .duplicate_bytes
                .checked_add(insert.size_bytes)
                .ok_or(DeltaError::ChunkSizeOverflow)?;
        }

        Ok(())
    }
}

/// Result of ingesting a logical object into the chunk store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkStoreIngestReport {
    /// Per-logical-chunk references in object order.
    pub chunks: Vec<CasChunkRef>,
    /// Store deduplication statistics.
    pub store_report: ChunkStoreInsertReport,
}

/// Simple content-addressed chunk store used by ATP delta planning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentAddressedChunkStore {
    chunks: BTreeMap<ContentId, Vec<u8>>,
    verified_coverage: BTreeSet<ReceiverChunkKey>,
    stored_bytes: u64,
}

impl ContentAddressedChunkStore {
    /// Create an empty content-addressed chunk store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            verified_coverage: BTreeSet::new(),
            stored_bytes: 0,
        }
    }

    /// Insert a chunk, deduplicating by [`ContentId`].
    pub fn insert(&mut self, bytes: &[u8]) -> Result<ChunkStoreInsert, DeltaError> {
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        let content_id = ContentId::from_bytes(bytes);
        let inserted = if self.chunks.contains_key(&content_id) {
            false
        } else {
            self.stored_bytes = self
                .stored_bytes
                .checked_add(size_bytes)
                .ok_or(DeltaError::ChunkSizeOverflow)?;
            self.chunks.insert(content_id.clone(), bytes.to_vec());
            true
        };
        self.verified_coverage.insert(ReceiverChunkKey {
            content_id: content_id.clone(),
            size_bytes,
        });

        Ok(ChunkStoreInsert {
            content_id,
            size_bytes,
            inserted,
        })
    }

    /// Ingest chunks in logical order and return manifest-ready references.
    pub fn ingest_ordered_chunks<'a, I>(
        &mut self,
        chunks: I,
    ) -> Result<ChunkStoreIngestReport, DeltaError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut byte_offset = 0u64;
        let mut refs = Vec::new();
        let mut report = ChunkStoreInsertReport::default();

        for (index, bytes) in chunks.into_iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| DeltaError::ChunkCountOverflow)?;
            let insert = self.insert(bytes)?;
            report.record(&insert)?;

            refs.push(CasChunkRef {
                index,
                byte_offset,
                size_bytes: insert.size_bytes,
                content_id: insert.content_id,
            });

            byte_offset = byte_offset
                .checked_add(insert.size_bytes)
                .ok_or(DeltaError::ChunkOffsetOverflow)?;
        }

        Ok(ChunkStoreIngestReport {
            chunks: refs,
            store_report: report,
        })
    }

    /// Whether a content id is available locally.
    #[must_use]
    pub fn contains(&self, content_id: &ContentId) -> bool {
        self.chunks.contains_key(content_id)
            || self
                .verified_coverage
                .iter()
                .any(|chunk| &chunk.content_id == content_id)
    }

    /// Fetch a stored chunk by content id.
    #[must_use]
    pub fn get(&self, content_id: &ContentId) -> Option<&[u8]> {
        self.chunks.get(content_id).map(Vec::as_slice)
    }

    /// Record a chunk whose bytes have already been verified by the caller.
    ///
    /// This is used by negotiated receiver-state exchange: the receiver can
    /// advertise that its local CAS/destination contains a hash-and-size pair
    /// without forcing the sender-side planner to materialize those bytes.
    pub fn insert_verified_coverage(&mut self, content_id: ContentId, size_bytes: u64) {
        self.verified_coverage.insert(ReceiverChunkKey {
            content_id,
            size_bytes,
        });
    }

    /// Whether the store can satisfy exactly this content id and size.
    #[must_use]
    pub fn has_exact_chunk(&self, chunk: &CasChunkRef) -> bool {
        let key = chunk.key();
        if self.verified_coverage.contains(&key) {
            return true;
        }
        store_payload_matches(self, chunk)
    }

    /// Number of unique chunks stored.
    #[must_use]
    pub fn unique_chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Number of unique bytes stored.
    #[must_use]
    pub const fn unique_bytes(&self) -> u64 {
        self.stored_bytes
    }
}

/// Persistent logical object manifest for content-addressed delta chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentChunkManifest {
    /// Stable object/tree identifier owned by the caller.
    pub tree_id: String,
    /// Logical object size represented by this manifest.
    pub total_size_bytes: u64,
    /// Ordered chunk references.
    pub chunks: Vec<CasChunkRef>,
    /// Merkle root over schema, tree id, size, and ordered chunk references.
    pub merkle_root: MerkleRoot,
}

impl PersistentChunkManifest {
    /// Build a manifest, validating contiguous chunk order and offsets.
    pub fn new(tree_id: impl Into<String>, chunks: Vec<CasChunkRef>) -> Result<Self, DeltaError> {
        let tree_id = tree_id.into();
        if tree_id.is_empty() {
            return Err(DeltaError::EmptyTreeId);
        }
        if u32::try_from(tree_id.len()).is_err() {
            return Err(DeltaError::TreeIdTooLong { len: tree_id.len() });
        }

        let total_size_bytes = validate_chunk_layout(&chunks)?;
        let merkle_root = compute_manifest_root(&tree_id, total_size_bytes, &chunks);

        Ok(Self {
            tree_id,
            total_size_bytes,
            chunks,
            merkle_root,
        })
    }

    /// Build from ATP manifest chunk boundaries.
    pub fn from_boundaries(
        tree_id: impl Into<String>,
        boundaries: &[ChunkBoundary],
    ) -> Result<Self, DeltaError> {
        let chunks = boundaries.iter().map(CasChunkRef::from_boundary).collect();
        Self::new(tree_id, chunks)
    }

    /// Return ATP manifest boundaries using the caller's chunking strategy.
    #[must_use]
    pub fn to_boundaries(&self, strategy: ChunkStrategy) -> Vec<ChunkBoundary> {
        self.chunks
            .iter()
            .map(|chunk| chunk.to_boundary(strategy))
            .collect()
    }

    /// Return journal resume chunks without inventing a parallel resume format.
    #[must_use]
    pub fn journal_resume_chunks(&self) -> Vec<TransferResumeChunk> {
        self.chunks
            .iter()
            .map(CasChunkRef::to_journal_resume_chunk)
            .collect()
    }

    /// Encode to deterministic bytes suitable for durable storage.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MANIFEST_MAGIC.len()
                + 4
                + self.tree_id.len()
                + 8
                + 8
                + self.chunks.len() * ENCODED_CHUNK_BYTES
                + 32,
        );
        out.extend_from_slice(MANIFEST_MAGIC);
        write_len_prefixed_bytes(&mut out, self.tree_id.as_bytes());
        out.extend_from_slice(&self.total_size_bytes.to_be_bytes());
        out.extend_from_slice(&(self.chunks.len() as u64).to_be_bytes());
        for chunk in &self.chunks {
            out.extend_from_slice(&chunk.index.to_be_bytes());
            out.extend_from_slice(&chunk.byte_offset.to_be_bytes());
            out.extend_from_slice(&chunk.size_bytes.to_be_bytes());
            out.extend_from_slice(chunk.content_id.hash());
        }
        out.extend_from_slice(self.merkle_root.hash());
        out
    }

    /// Decode deterministic manifest bytes and fail closed on root or geometry drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeltaError> {
        let mut reader = ByteReader::new(bytes);
        reader.expect_magic(MANIFEST_MAGIC)?;
        let tree_id = reader.read_string()?;
        let encoded_total_size = reader.read_u64()?;
        let chunk_count = reader.read_u64()?;
        let chunk_count =
            usize::try_from(chunk_count).map_err(|_| DeltaError::ChunkCountOverflow)?;
        reader.ensure_remaining_chunks(chunk_count)?;

        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            let index = reader.read_u32()?;
            let byte_offset = reader.read_u64()?;
            let size_bytes = reader.read_u64()?;
            let content_id = ContentId::new(reader.read_hash()?);
            chunks.push(CasChunkRef {
                index,
                byte_offset,
                size_bytes,
                content_id,
            });
        }
        let encoded_root = MerkleRoot::new(reader.read_hash()?);
        reader.expect_eof()?;

        let manifest = Self::new(tree_id, chunks)?;
        if manifest.total_size_bytes != encoded_total_size {
            return Err(DeltaError::TotalSizeMismatch {
                encoded: encoded_total_size,
                computed: manifest.total_size_bytes,
            });
        }
        if manifest.merkle_root != encoded_root {
            return Err(DeltaError::ManifestRootMismatch {
                encoded: encoded_root,
                computed: manifest.merkle_root,
            });
        }

        Ok(manifest)
    }

    /// Diff this sender manifest against a receiver manifest at chunk-store granularity.
    #[must_use]
    pub fn diff_against(&self, receiver: &Self) -> ChunkManifestDiff {
        let sender_keys = manifest_chunk_keys(&self.chunks);
        let receiver_keys = manifest_chunk_keys(&receiver.chunks);

        let mut shared_chunks = 0u64;
        let mut missing_chunks = Vec::new();
        let mut missing_bytes = 0u64;

        for chunk in &self.chunks {
            if receiver_keys.contains(&chunk.key()) {
                shared_chunks += 1;
            } else {
                missing_bytes = missing_bytes.saturating_add(chunk.size_bytes);
                missing_chunks.push(chunk.clone());
            }
        }

        let mut stale_chunks = Vec::new();
        let mut stale_bytes = 0u64;
        for chunk in &receiver.chunks {
            if !sender_keys.contains(&chunk.key()) {
                stale_bytes = stale_bytes.saturating_add(chunk.size_bytes);
                stale_chunks.push(chunk.clone());
            }
        }

        ChunkManifestDiff {
            shared_chunks,
            missing_chunks,
            stale_chunks,
            missing_bytes,
            stale_bytes,
        }
    }

    /// Verify every manifest chunk is present in the store with the expected size and id.
    pub fn verify_store_coverage(
        &self,
        store: &ContentAddressedChunkStore,
    ) -> Result<(), DeltaError> {
        for chunk in &self.chunks {
            if store.has_exact_chunk(chunk) {
                continue;
            }
            let Some(payload) = store.get(&chunk.content_id) else {
                return Err(DeltaError::MissingChunk {
                    index: chunk.index,
                    content_id: chunk.content_id.clone(),
                });
            };
            let payload_size =
                u64::try_from(payload.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
            if payload_size != chunk.size_bytes {
                return Err(DeltaError::ChunkPayloadSizeMismatch {
                    index: chunk.index,
                    expected: chunk.size_bytes,
                    actual: payload_size,
                });
            }
            let actual_content_id = ContentId::from_bytes(payload);
            if actual_content_id != chunk.content_id {
                return Err(DeltaError::ChunkPayloadHashMismatch {
                    index: chunk.index,
                    expected: chunk.content_id.clone(),
                    actual: actual_content_id,
                });
            }
        }

        Ok(())
    }
}

/// Sender/receiver chunk-set delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkManifestDiff {
    /// Logical sender chunks already available at the receiver.
    pub shared_chunks: u64,
    /// Sender chunks missing from the receiver store.
    pub missing_chunks: Vec<CasChunkRef>,
    /// Receiver chunks not present in the sender manifest.
    pub stale_chunks: Vec<CasChunkRef>,
    /// Missing sender bytes by logical chunk size.
    pub missing_bytes: u64,
    /// Stale receiver bytes by logical chunk size.
    pub stale_bytes: u64,
}

/// Receiver-side CAS coverage, verified before it is advertised to a sender.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiverCasCoverage {
    chunks: BTreeSet<ReceiverChunkKey>,
}

impl ReceiverCasCoverage {
    /// Create an empty coverage set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            chunks: BTreeSet::new(),
        }
    }

    /// Record one available content-addressed chunk.
    pub fn insert(&mut self, content_id: ContentId, size_bytes: u64) {
        self.chunks.insert(ReceiverChunkKey {
            content_id,
            size_bytes,
        });
    }

    fn insert_key(&mut self, key: ReceiverChunkKey) {
        self.chunks.insert(key);
    }

    /// Record one available manifest chunk.
    pub fn insert_chunk_ref(&mut self, chunk: &CasChunkRef) {
        self.chunks.insert(chunk.key());
    }

    /// Build coverage from every chunk in a manifest.
    #[must_use]
    pub fn from_manifest(manifest: &PersistentChunkManifest) -> Self {
        let mut coverage = Self::new();
        for chunk in &manifest.chunks {
            coverage.insert_chunk_ref(chunk);
        }
        coverage
    }

    /// Whether this coverage set can satisfy a manifest chunk exactly.
    #[must_use]
    pub fn contains_chunk(&self, chunk: &CasChunkRef) -> bool {
        self.chunks.contains(&chunk.key())
    }

    /// Number of unique chunks covered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether no chunks are covered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

/// Receiver have-set bounds enforced before advertising CAS coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverHaveSetLimits {
    /// Maximum unique content-addressed chunks advertised in one negotiation.
    pub max_chunks: usize,
    /// Maximum estimated wire bytes for the advertised have-set.
    pub max_wire_bytes: u64,
}

impl ReceiverHaveSetLimits {
    /// Default cap keeps negotiation bounded while covering very large trees.
    pub const DEFAULT: Self = Self {
        max_chunks: 1_048_576,
        max_wire_bytes: 64 * 1024 * 1024,
    };
}

impl Default for ReceiverHaveSetLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Bounded receiver-advertised CAS have-set for delta manifest negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverHaveSetAdvertisement {
    /// Negotiation schema marker.
    pub schema: &'static str,
    /// Receiver manifest root this advertisement describes.
    pub receiver_merkle_root: MerkleRoot,
    /// Receiver manifest logical byte size this advertisement describes.
    pub receiver_total_size_bytes: u64,
    /// Unique receiver CAS keys proven locally before advertisement.
    chunks: Vec<ReceiverChunkKey>,
    /// Conservative encoded byte count for the control-plane have-set.
    estimated_wire_bytes: u64,
}

impl ReceiverHaveSetAdvertisement {
    /// Build a bounded advertisement from receiver-verified coverage.
    pub fn from_verified_manifest(
        manifest: &PersistentChunkManifest,
        coverage: &ReceiverCasCoverage,
        limits: ReceiverHaveSetLimits,
    ) -> Result<Self, DeltaError> {
        for chunk in &manifest.chunks {
            if !coverage.contains_chunk(chunk) {
                return Err(DeltaError::ReceiverHaveSetMissingChunk { index: chunk.index });
            }
        }

        let chunks = coverage.chunks.iter().cloned().collect::<Vec<_>>();
        let estimated_wire_bytes = receiver_have_set_wire_bytes(chunks.len())?;
        if chunks.len() > limits.max_chunks {
            return Err(DeltaError::ReceiverHaveSetTooManyChunks {
                chunks: chunks.len(),
                max_chunks: limits.max_chunks,
            });
        }
        if estimated_wire_bytes > limits.max_wire_bytes {
            return Err(DeltaError::ReceiverHaveSetTooManyBytes {
                bytes: estimated_wire_bytes,
                max_bytes: limits.max_wire_bytes,
            });
        }

        Ok(Self {
            schema: ATP_DELTA_RECEIVER_HAVE_SET_SCHEMA,
            receiver_merkle_root: manifest.merkle_root.clone(),
            receiver_total_size_bytes: manifest.total_size_bytes,
            chunks,
            estimated_wire_bytes,
        })
    }

    /// Number of unique receiver CAS chunks advertised.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether no receiver CAS chunks are advertised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Conservative encoded byte count for this control-plane advertisement.
    #[must_use]
    pub const fn estimated_wire_bytes(&self) -> u64 {
        self.estimated_wire_bytes
    }

    /// Whether this advertisement is bound to the supplied receiver manifest.
    #[must_use]
    pub fn describes_manifest(&self, manifest: &PersistentChunkManifest) -> bool {
        self.schema == ATP_DELTA_RECEIVER_HAVE_SET_SCHEMA
            && self.receiver_merkle_root == manifest.merkle_root
            && self.receiver_total_size_bytes == manifest.total_size_bytes
    }

    /// Convert into sender-side coverage for delta planning.
    #[must_use]
    pub fn to_coverage(&self) -> ReceiverCasCoverage {
        let mut coverage = ReceiverCasCoverage::new();
        for chunk in &self.chunks {
            coverage.insert_key(chunk.clone());
        }
        coverage
    }
}

/// Deterministic send mode for an incremental re-sync attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaResyncMode {
    /// Sender and receiver manifests are byte-for-byte equivalent; no payload is needed.
    AlreadyInSync,
    /// Send only the listed content-addressed chunks, then commit the new manifest.
    DeltaChunks,
    /// Use the existing full-object RaptorQ path instead of the delta path.
    FullObjectFallback,
}

/// Conservative reason the delta planner selected full-object fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaResyncFallbackReason {
    /// The receiver had no prior Merkle manifest to diff against.
    NoReceiverManifest,
    /// The receiver's prior manifest references CAS chunks that are unavailable or corrupt.
    ReceiverCasCoverageIncomplete,
    /// The missing-chunk payload is at least as large as the full sender object.
    DeltaNotSmallerThanFullObject,
}

/// End-to-end delta re-sync plan consumed by the CLI/transport wiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaResyncPlan {
    /// Selected transfer mode.
    pub mode: DeltaResyncMode,
    /// Populated only when `mode == FullObjectFallback`.
    pub fallback_reason: Option<DeltaResyncFallbackReason>,
    /// Current sender Merkle root.
    pub sender_merkle_root: MerkleRoot,
    /// Receiver prior Merkle root when one was supplied.
    pub receiver_merkle_root: Option<MerkleRoot>,
    /// Sender chunks that must be packed into the delta RaptorQ stream.
    pub missing_chunks: Vec<CasChunkRef>,
    /// Logical bytes represented by `missing_chunks`.
    pub missing_bytes: u64,
    /// Sender chunks already covered by the receiver manifest or receiver CAS.
    pub shared_chunks: u64,
    /// Receiver chunks not present in the sender manifest.
    pub stale_chunks: Vec<CasChunkRef>,
    /// Logical bytes represented by `stale_chunks`.
    pub stale_bytes: u64,
}

impl DeltaResyncPlan {
    /// Whether the plan sends chunk payloads through the delta RaptorQ stream.
    #[must_use]
    pub const fn uses_delta_chunks(&self) -> bool {
        matches!(self.mode, DeltaResyncMode::DeltaChunks)
    }

    /// Whether callers should route to the existing full-object transfer.
    #[must_use]
    pub const fn requires_full_object_fallback(&self) -> bool {
        matches!(self.mode, DeltaResyncMode::FullObjectFallback)
    }

    /// Content ids to request from the sender-side CAS for delta packing.
    #[must_use]
    pub fn missing_content_ids(&self) -> Vec<ContentId> {
        self.missing_chunks
            .iter()
            .map(|chunk| chunk.content_id.clone())
            .collect()
    }
}

/// Receiver-advertised signature for one old chunk.
///
/// The receiver builds this from locally verified old bytes; the sender uses it
/// to emit a byte-precise sub-chunk op stream from the best overlapping prior
/// chunk instead of sending the whole new chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverSubchunkSignature {
    /// Receiver manifest chunk that was signed.
    pub chunk: CasChunkRef,
    /// Fixed-size sub-block signature for the receiver's old chunk bytes.
    pub signature: SubBlockSignature,
}

/// Concrete payload item emitted by the delta send path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaResyncSendItem {
    /// Whole missing content-addressed chunk payload.
    WholeChunk {
        chunk: CasChunkRef,
        payload: Vec<u8>,
    },
    /// Byte-precise op stream reconstructing `target_chunk` from `base_chunk`.
    SubchunkOps {
        target_chunk: CasChunkRef,
        base_chunk: CasChunkRef,
        target_sha256: [u8; 32],
        encoded_ops: Vec<u8>,
    },
    /// Logical missing chunk whose content was already carried by an earlier item.
    RepeatedChunk {
        chunk: CasChunkRef,
        source_ordinal: usize,
    },
}

impl DeltaResyncSendItem {
    /// Target logical chunk reconstructed by this payload item.
    #[must_use]
    pub const fn target_chunk(&self) -> &CasChunkRef {
        match self {
            Self::WholeChunk { chunk, .. }
            | Self::SubchunkOps {
                target_chunk: chunk,
                ..
            }
            | Self::RepeatedChunk { chunk, .. } => chunk,
        }
    }

    /// Payload bytes emitted on the delta stream for this item.
    #[must_use]
    pub fn payload_bytes(&self) -> usize {
        match self {
            Self::WholeChunk { payload, .. } => payload.len(),
            Self::SubchunkOps { encoded_ops, .. } => encoded_ops.len(),
            Self::RepeatedChunk { .. } => 0,
        }
    }

    /// Whether this item sends a sub-chunk op stream instead of a whole chunk.
    #[must_use]
    pub const fn is_subchunk_ops(&self) -> bool {
        matches!(self, Self::SubchunkOps { .. })
    }

    /// Whether this item carries a whole chunk payload.
    #[must_use]
    pub const fn is_whole_chunk(&self) -> bool {
        matches!(self, Self::WholeChunk { .. })
    }
}

/// Concrete mixed whole/sub-chunk payload selected for a re-sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaResyncSendPlan {
    /// Delta planner metadata that selected the missing/stale chunk set.
    pub base_plan: DeltaResyncPlan,
    /// Ordered payload items to emit.
    pub items: Vec<DeltaResyncSendItem>,
    /// Actual encoded payload bytes emitted by `items`.
    pub payload_bytes: u64,
    /// Logical whole-chunk bytes represented by the missing set before B-8.10.
    pub whole_chunk_bytes: u64,
}

/// Sender-produced delta wire payload plus byte-accounting metadata.
///
/// This is the transport-facing packet shape for the re-sync benchmark path:
/// callers send only `wire_payload`, while the remaining fields make the
/// bytes-on-wire decision auditable without reparsing the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaResyncWirePayload {
    /// Negotiated base plan the receiver must use to decode `wire_payload`.
    pub base_plan: DeltaResyncPlan,
    /// Deterministic envelope bytes emitted on the delta transfer stream.
    pub wire_payload: Vec<u8>,
    /// Number of bytes in `wire_payload`.
    pub wire_payload_bytes: u64,
    /// Actual item payload bytes before envelope metadata.
    pub payload_bytes: u64,
    /// Logical whole-chunk bytes represented by the missing set.
    pub whole_chunk_bytes: u64,
    /// Count of items carried as sub-chunk op streams.
    pub subchunk_count: usize,
    /// Count of items carried as whole chunks.
    pub whole_chunk_count: usize,
}

/// Receiver result after applying a delta wire payload and rebuilding bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaResyncApplyReport {
    /// Receiver CAS after applying whole chunks and reconstructed sub-deltas.
    pub store: ContentAddressedChunkStore,
    /// Byte-identical logical object reconstructed from `target_manifest`.
    pub reconstructed_bytes: Vec<u8>,
    /// Number of received envelope bytes.
    pub wire_payload_bytes: u64,
    /// Actual item payload bytes before envelope metadata.
    pub payload_bytes: u64,
    /// Logical whole-chunk bytes represented by the missing set.
    pub whole_chunk_bytes: u64,
    /// Count of applied sub-chunk op streams.
    pub subchunk_count: usize,
    /// Count of applied whole chunks.
    pub whole_chunk_count: usize,
}

/// Sender decision for an incremental re-sync transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaResyncTransmission {
    /// Final transfer plan after sub-chunk delta promotion, if any.
    pub plan: DeltaResyncPlan,
    /// Delta envelope to send. `None` means already-in-sync or full-object fallback.
    pub wire_payload: Option<DeltaResyncWirePayload>,
    /// Sender object size used for full-object fallback comparisons.
    pub full_object_bytes: u64,
}

impl DeltaResyncSendPlan {
    /// Count of payload items encoded as sub-chunk op streams.
    #[must_use]
    pub fn subchunk_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.is_subchunk_ops())
            .count()
    }

    /// Count of payload items still emitted as whole chunks.
    #[must_use]
    pub fn whole_chunk_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.is_whole_chunk())
            .count()
    }

    /// Whether this concrete payload is smaller than a full-object send.
    #[must_use]
    pub const fn beats_full_object(&self, full_object_bytes: u64) -> bool {
        self.payload_bytes < full_object_bytes
    }

    /// Encode this concrete send plan into its deterministic transfer envelope.
    ///
    /// The receiver decodes this envelope with the negotiated base plan, applies
    /// each item in order, and then verifies the target manifest coverage before
    /// committing reconstructed bytes.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, DeltaError> {
        validate_send_plan_items(&self.base_plan, &self.items)?;
        if self.whole_chunk_bytes != self.base_plan.missing_bytes {
            return Err(DeltaError::DeltaSendPlanWholeBytesMismatch {
                encoded: self.whole_chunk_bytes,
                expected: self.base_plan.missing_bytes,
            });
        }

        let computed_payload_bytes = send_items_payload_bytes(&self.items)?;
        if computed_payload_bytes != self.payload_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: self.payload_bytes,
                computed: computed_payload_bytes,
            });
        }

        let mut out = Vec::new();
        out.extend_from_slice(DELTA_RESYNC_SEND_PLAN_MAGIC);
        out.extend_from_slice(self.base_plan.sender_merkle_root.hash());
        match &self.base_plan.receiver_merkle_root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(root.hash());
            }
            None => out.push(0),
        }
        out.extend_from_slice(
            &u64::try_from(self.items.len())
                .map_err(|_| DeltaError::ChunkCountOverflow)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.payload_bytes.to_be_bytes());
        out.extend_from_slice(&self.whole_chunk_bytes.to_be_bytes());

        if whole_chunk_run_can_derive_chunks_from_base(&self.base_plan, &self.items) {
            out.push(DELTA_SEND_ITEM_WHOLE_CHUNK_RUN);
            out.extend_from_slice(&0u64.to_be_bytes());
            out.extend_from_slice(
                &u64::try_from(self.items.len())
                    .map_err(|_| DeltaError::ChunkCountOverflow)?
                    .to_be_bytes(),
            );
            for item in &self.items {
                let DeltaResyncSendItem::WholeChunk { payload, .. } = item else {
                    unreachable!("whole chunk run eligibility excludes non-whole items");
                };
                out.extend_from_slice(payload);
            }
        } else {
            for item in &self.items {
                match item {
                    DeltaResyncSendItem::WholeChunk { chunk, payload } => {
                        out.push(DELTA_SEND_ITEM_WHOLE_CHUNK);
                        encode_chunk_ref(&mut out, chunk);
                        write_u64_prefixed_bytes(&mut out, payload)?;
                    }
                    DeltaResyncSendItem::SubchunkOps {
                        target_chunk,
                        base_chunk,
                        target_sha256,
                        encoded_ops,
                    } => {
                        out.push(DELTA_SEND_ITEM_SUBCHUNK_OPS);
                        encode_chunk_ref(&mut out, target_chunk);
                        encode_chunk_ref(&mut out, base_chunk);
                        out.extend_from_slice(target_sha256);
                        write_u64_prefixed_bytes(&mut out, encoded_ops)?;
                    }
                    DeltaResyncSendItem::RepeatedChunk {
                        chunk,
                        source_ordinal,
                    } => {
                        out.push(DELTA_SEND_ITEM_REPEATED_CHUNK);
                        encode_chunk_ref(&mut out, chunk);
                        out.extend_from_slice(
                            &u64::try_from(*source_ordinal)
                                .map_err(|_| DeltaError::ChunkCountOverflow)?
                                .to_be_bytes(),
                        );
                    }
                }
            }
        }

        Ok(out)
    }

    /// Decode a deterministic transfer envelope against the negotiated base plan.
    pub fn from_wire_bytes(base_plan: DeltaResyncPlan, bytes: &[u8]) -> Result<Self, DeltaError> {
        let mut reader = ByteReader::new(bytes);
        reader.expect_magic(DELTA_RESYNC_SEND_PLAN_MAGIC)?;

        let sender_merkle_root = MerkleRoot::new(reader.read_hash()?);
        if sender_merkle_root != base_plan.sender_merkle_root {
            return Err(DeltaError::DeltaSendPlanSenderRootMismatch {
                encoded: sender_merkle_root,
                expected: base_plan.sender_merkle_root.clone(),
            });
        }

        let receiver_merkle_root = match reader.read_u8()? {
            0 => None,
            1 => Some(MerkleRoot::new(reader.read_hash()?)),
            tag => return Err(DeltaError::InvalidDeltaSendPlanReceiverRootTag { tag }),
        };
        if receiver_merkle_root != base_plan.receiver_merkle_root {
            return Err(DeltaError::DeltaSendPlanReceiverRootMismatch {
                encoded: receiver_merkle_root,
                expected: base_plan.receiver_merkle_root.clone(),
            });
        }

        let item_count =
            usize::try_from(reader.read_u64()?).map_err(|_| DeltaError::ChunkCountOverflow)?;
        if item_count != base_plan.missing_chunks.len() {
            return Err(DeltaError::DeltaSendPlanItemCountMismatch {
                actual: item_count,
                expected: base_plan.missing_chunks.len(),
            });
        }

        let encoded_payload_bytes = reader.read_u64()?;
        let whole_chunk_bytes = reader.read_u64()?;
        if whole_chunk_bytes != base_plan.missing_bytes {
            return Err(DeltaError::DeltaSendPlanWholeBytesMismatch {
                encoded: whole_chunk_bytes,
                expected: base_plan.missing_bytes,
            });
        }

        let mut items = Vec::with_capacity(item_count);
        let mut ordinal = 0usize;
        while ordinal < item_count {
            let item = match reader.read_u8()? {
                DELTA_SEND_ITEM_WHOLE_CHUNK => DeltaResyncSendItem::WholeChunk {
                    chunk: decode_chunk_ref(&mut reader)?,
                    payload: reader.read_u64_prefixed_bytes()?.to_vec(),
                },
                DELTA_SEND_ITEM_SUBCHUNK_OPS => DeltaResyncSendItem::SubchunkOps {
                    target_chunk: decode_chunk_ref(&mut reader)?,
                    base_chunk: decode_chunk_ref(&mut reader)?,
                    target_sha256: reader.read_hash()?,
                    encoded_ops: reader.read_u64_prefixed_bytes()?.to_vec(),
                },
                DELTA_SEND_ITEM_REPEATED_CHUNK => DeltaResyncSendItem::RepeatedChunk {
                    chunk: decode_chunk_ref(&mut reader)?,
                    source_ordinal: usize::try_from(reader.read_u64()?)
                        .map_err(|_| DeltaError::ChunkCountOverflow)?,
                },
                DELTA_SEND_ITEM_WHOLE_CHUNK_RUN => {
                    let start_ordinal = usize::try_from(reader.read_u64()?)
                        .map_err(|_| DeltaError::ChunkCountOverflow)?;
                    let run_len = usize::try_from(reader.read_u64()?)
                        .map_err(|_| DeltaError::ChunkCountOverflow)?;
                    if run_len == 0 {
                        return Err(DeltaError::DeltaSendPlanItemCountMismatch {
                            actual: 0,
                            expected: item_count.saturating_sub(ordinal),
                        });
                    }
                    if start_ordinal != ordinal {
                        return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
                    }
                    let run_end = ordinal
                        .checked_add(run_len)
                        .ok_or(DeltaError::ChunkCountOverflow)?;
                    if run_end > item_count {
                        return Err(DeltaError::DeltaSendPlanItemCountMismatch {
                            actual: run_end,
                            expected: item_count,
                        });
                    }
                    while ordinal < run_end {
                        let chunk = base_plan.missing_chunks[ordinal].clone();
                        let payload_len = usize::try_from(chunk.size_bytes)
                            .map_err(|_| DeltaError::ChunkSizeOverflow)?;
                        let payload = reader.read_exact(payload_len)?.to_vec();
                        items.push(DeltaResyncSendItem::WholeChunk { chunk, payload });
                        ordinal += 1;
                    }
                    continue;
                }
                tag => return Err(DeltaError::InvalidDeltaSendItemTag { tag }),
            };

            if item.target_chunk() != &base_plan.missing_chunks[ordinal] {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            }
            items.push(item);
            ordinal += 1;
        }
        reader.expect_eof()?;
        validate_send_plan_items(&base_plan, &items)?;

        let computed_payload_bytes = send_items_payload_bytes(&items)?;
        if computed_payload_bytes != encoded_payload_bytes {
            return Err(DeltaError::DeltaSendPlanPayloadBytesMismatch {
                encoded: encoded_payload_bytes,
                computed: computed_payload_bytes,
            });
        }

        Ok(Self {
            base_plan,
            items,
            payload_bytes: encoded_payload_bytes,
            whole_chunk_bytes,
        })
    }
}

impl DeltaResyncWirePayload {
    /// Encode a concrete send plan into its transport payload with accounting.
    pub fn from_send_plan(send_plan: DeltaResyncSendPlan) -> Result<Self, DeltaError> {
        let subchunk_count = send_plan.subchunk_count();
        let whole_chunk_count = send_plan.whole_chunk_count();
        let payload_bytes = send_plan.payload_bytes;
        let whole_chunk_bytes = send_plan.whole_chunk_bytes;
        let base_plan = send_plan.base_plan.clone();
        let wire_payload = send_plan.to_wire_bytes()?;
        let wire_payload_bytes =
            u64::try_from(wire_payload.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;

        Ok(Self {
            base_plan,
            wire_payload,
            wire_payload_bytes,
            payload_bytes,
            whole_chunk_bytes,
            subchunk_count,
            whole_chunk_count,
        })
    }

    /// Whether the encoded transfer payload is smaller than a full-object send.
    #[must_use]
    pub const fn beats_full_object(&self, full_object_bytes: u64) -> bool {
        self.wire_payload_bytes < full_object_bytes
    }
}

impl DeltaResyncTransmission {
    /// Whether this transmission has an actual delta envelope.
    #[must_use]
    pub const fn uses_delta_wire_payload(&self) -> bool {
        self.wire_payload.is_some()
    }

    /// Whether the sender and receiver are already byte-identical.
    #[must_use]
    pub const fn already_in_sync(&self) -> bool {
        matches!(self.plan.mode, DeltaResyncMode::AlreadyInSync)
    }

    /// Whether the caller must use the existing full-object transfer path.
    #[must_use]
    pub const fn requires_full_object_fallback(&self) -> bool {
        matches!(self.plan.mode, DeltaResyncMode::FullObjectFallback) && self.wire_payload.is_none()
    }
}

/// Plan an ATP incremental re-sync using prior manifest + receiver CAS state.
///
/// This is the fail-closed decision point for B-8.8 CLI wiring: no prior
/// manifest, incomplete receiver CAS coverage, or a worst-case whole-file change
/// deterministically selects the existing full-object path. Valid delta plans
/// keep wire bytes isomorphic by sending only content-addressed chunks and
/// leaving final whole-object/Merkle verification to the existing commit gate.
#[must_use]
pub fn plan_incremental_resync(
    sender: &PersistentChunkManifest,
    receiver: Option<&PersistentChunkManifest>,
    receiver_store: &ContentAddressedChunkStore,
) -> DeltaResyncPlan {
    let Some(receiver) = receiver else {
        return full_object_plan(sender, None, DeltaResyncFallbackReason::NoReceiverManifest);
    };

    if receiver.verify_store_coverage(receiver_store).is_err() {
        return full_object_plan(
            sender,
            Some(receiver),
            DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete,
        );
    }

    let mut coverage = ReceiverCasCoverage::from_manifest(receiver);
    for chunk in &sender.chunks {
        if store_has_exact_chunk(receiver_store, chunk) {
            coverage.insert_chunk_ref(chunk);
        }
    }
    plan_incremental_resync_with_receiver_coverage(sender, Some(receiver), &coverage)
}

/// Plan an ATP incremental re-sync from receiver-advertised CAS coverage.
///
/// The receiver must verify this coverage locally before sending it. The sender
/// still gets deterministic fallback semantics, while the receiver's final
/// whole-object SHA/Merkle verification remains the fail-closed authority.
#[must_use]
pub fn plan_incremental_resync_with_receiver_coverage(
    sender: &PersistentChunkManifest,
    receiver: Option<&PersistentChunkManifest>,
    receiver_coverage: &ReceiverCasCoverage,
) -> DeltaResyncPlan {
    let receiver_merkle_root = receiver.map(|manifest| manifest.merkle_root.clone());
    let Some(receiver) = receiver else {
        return full_object_plan(sender, None, DeltaResyncFallbackReason::NoReceiverManifest);
    };

    if receiver
        .chunks
        .iter()
        .any(|chunk| !receiver_coverage.contains_chunk(chunk))
    {
        return full_object_plan(
            sender,
            Some(receiver),
            DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete,
        );
    }

    if sender.merkle_root == receiver.merkle_root {
        return DeltaResyncPlan {
            mode: DeltaResyncMode::AlreadyInSync,
            fallback_reason: None,
            sender_merkle_root: sender.merkle_root.clone(),
            receiver_merkle_root,
            missing_chunks: Vec::new(),
            missing_bytes: 0,
            shared_chunks: sender.chunks.len() as u64,
            stale_chunks: Vec::new(),
            stale_bytes: 0,
        };
    }

    let receiver_keys = manifest_chunk_keys(&receiver.chunks);
    let sender_keys = manifest_chunk_keys(&sender.chunks);
    let mut missing_chunks = Vec::new();
    let mut missing_bytes = 0u64;
    let mut shared_chunks = 0u64;

    for chunk in &sender.chunks {
        if receiver_keys.contains(&chunk.key()) || receiver_coverage.contains_chunk(chunk) {
            shared_chunks += 1;
            continue;
        }
        missing_bytes = missing_bytes.saturating_add(chunk.size_bytes);
        missing_chunks.push(chunk.clone());
    }

    let mut stale_chunks = Vec::new();
    let mut stale_bytes = 0u64;
    for chunk in &receiver.chunks {
        if !sender_keys.contains(&chunk.key()) {
            stale_bytes = stale_bytes.saturating_add(chunk.size_bytes);
            stale_chunks.push(chunk.clone());
        }
    }

    if missing_bytes >= sender.total_size_bytes {
        return DeltaResyncPlan {
            mode: DeltaResyncMode::FullObjectFallback,
            fallback_reason: Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject),
            sender_merkle_root: sender.merkle_root.clone(),
            receiver_merkle_root,
            missing_chunks,
            missing_bytes,
            shared_chunks,
            stale_chunks,
            stale_bytes,
        };
    }

    DeltaResyncPlan {
        mode: DeltaResyncMode::DeltaChunks,
        fallback_reason: None,
        sender_merkle_root: sender.merkle_root.clone(),
        receiver_merkle_root,
        missing_chunks,
        missing_bytes,
        shared_chunks,
        stale_chunks,
        stale_bytes,
    }
}

/// Plan an ATP incremental re-sync from a bounded receiver have-set advertisement.
#[must_use]
pub fn plan_incremental_resync_with_receiver_have_set(
    sender: &PersistentChunkManifest,
    receiver: Option<&PersistentChunkManifest>,
    advertisement: Option<&ReceiverHaveSetAdvertisement>,
) -> DeltaResyncPlan {
    let Some(receiver) = receiver else {
        return full_object_plan(sender, None, DeltaResyncFallbackReason::NoReceiverManifest);
    };
    let Some(advertisement) = advertisement else {
        return full_object_plan(
            sender,
            Some(receiver),
            DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete,
        );
    };
    if !advertisement.describes_manifest(receiver) {
        return full_object_plan(
            sender,
            Some(receiver),
            DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete,
        );
    }

    let coverage = advertisement.to_coverage();
    plan_incremental_resync_with_receiver_coverage(sender, Some(receiver), &coverage)
}

/// Plan an ATP incremental re-sync from a receiver manifest whose CAS coverage
/// has already been verified by the receiver before it persisted the state.
///
/// This entry point exists for CLI bootstraps where the sender can fetch the
/// receiver's last committed manifest but not the receiver's private CAS bytes.
/// Callers must only pass manifests read from a receiver-maintained state file
/// that was emitted after local store coverage and final tree verification.
#[must_use]
pub fn plan_incremental_resync_from_verified_receiver_manifest(
    sender: &PersistentChunkManifest,
    receiver: Option<&PersistentChunkManifest>,
) -> DeltaResyncPlan {
    let receiver_merkle_root = receiver.map(|manifest| manifest.merkle_root.clone());
    let Some(receiver) = receiver else {
        return full_object_plan(sender, None, DeltaResyncFallbackReason::NoReceiverManifest);
    };

    if sender.merkle_root == receiver.merkle_root {
        return DeltaResyncPlan {
            mode: DeltaResyncMode::AlreadyInSync,
            fallback_reason: None,
            sender_merkle_root: sender.merkle_root.clone(),
            receiver_merkle_root,
            missing_chunks: Vec::new(),
            missing_bytes: 0,
            shared_chunks: sender.chunks.len() as u64,
            stale_chunks: Vec::new(),
            stale_bytes: 0,
        };
    }

    let receiver_keys = manifest_chunk_keys(&receiver.chunks);
    let sender_keys = manifest_chunk_keys(&sender.chunks);
    let mut missing_chunks = Vec::new();
    let mut missing_bytes = 0u64;
    let mut shared_chunks = 0u64;

    for chunk in &sender.chunks {
        if receiver_keys.contains(&chunk.key()) {
            shared_chunks += 1;
            continue;
        }
        missing_bytes = missing_bytes.saturating_add(chunk.size_bytes);
        missing_chunks.push(chunk.clone());
    }

    let mut stale_chunks = Vec::new();
    let mut stale_bytes = 0u64;
    for chunk in &receiver.chunks {
        if !sender_keys.contains(&chunk.key()) {
            stale_bytes = stale_bytes.saturating_add(chunk.size_bytes);
            stale_chunks.push(chunk.clone());
        }
    }

    if missing_bytes >= sender.total_size_bytes {
        return DeltaResyncPlan {
            mode: DeltaResyncMode::FullObjectFallback,
            fallback_reason: Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject),
            sender_merkle_root: sender.merkle_root.clone(),
            receiver_merkle_root,
            missing_chunks,
            missing_bytes,
            shared_chunks,
            stale_chunks,
            stale_bytes,
        };
    }

    DeltaResyncPlan {
        mode: DeltaResyncMode::DeltaChunks,
        fallback_reason: None,
        sender_merkle_root: sender.merkle_root.clone(),
        receiver_merkle_root,
        missing_chunks,
        missing_bytes,
        shared_chunks,
        stale_chunks,
        stale_bytes,
    }
}

/// Build receiver-side sub-chunk signatures from verified old chunk bytes.
pub fn build_receiver_subchunk_signatures(
    receiver: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    block_size: usize,
) -> Result<Vec<ReceiverSubchunkSignature>, DeltaError> {
    let mut signatures = Vec::with_capacity(receiver.chunks.len());
    for chunk in &receiver.chunks {
        let payload = verified_chunk_payload(receiver_store, chunk)?;
        signatures.push(ReceiverSubchunkSignature {
            chunk: chunk.clone(),
            signature: delta_subchunk::signature(payload, block_size),
        });
    }
    Ok(signatures)
}

/// Build the concrete sender payload for a delta re-sync.
///
/// Whole missing chunks remain the fallback, but when the receiver provided a
/// positional old-chunk signature this emits a compact sub-chunk op stream if
/// the encoded op stream is smaller than the whole target chunk.
pub fn build_delta_resync_send_plan(
    base_plan: &DeltaResyncPlan,
    sender_store: &ContentAddressedChunkStore,
    receiver_manifest: &PersistentChunkManifest,
    receiver_signatures: &[ReceiverSubchunkSignature],
) -> Result<DeltaResyncSendPlan, DeltaError> {
    let mut items = Vec::with_capacity(base_plan.missing_chunks.len());
    let mut payload_bytes = 0u64;

    for chunk in &base_plan.missing_chunks {
        let payload = verified_chunk_payload(sender_store, chunk)?;
        let item =
            build_delta_resync_send_item(chunk, payload, receiver_manifest, receiver_signatures)?;
        payload_bytes = payload_bytes
            .checked_add(
                u64::try_from(item.payload_bytes()).map_err(|_| DeltaError::ChunkSizeOverflow)?,
            )
            .ok_or(DeltaError::ChunkSizeOverflow)?;
        items.push(item);
    }

    compact_repeated_send_plan_if_smaller(DeltaResyncSendPlan {
        base_plan: base_plan.clone(),
        items,
        payload_bytes,
        whole_chunk_bytes: base_plan.missing_bytes,
    })
}

/// Build the concrete sender-side wire payload for a delta re-sync.
///
/// This composes planning, whole/sub-chunk selection, deterministic envelope
/// encoding, and byte accounting into the single object a transport needs to
/// send. It intentionally does not decide whether delta should be used; callers
/// pass the already-negotiated base plan so fallback policy stays explicit.
pub fn build_delta_resync_wire_payload(
    base_plan: &DeltaResyncPlan,
    sender_store: &ContentAddressedChunkStore,
    receiver_manifest: &PersistentChunkManifest,
    receiver_signatures: &[ReceiverSubchunkSignature],
) -> Result<DeltaResyncWirePayload, DeltaError> {
    let send_plan = build_delta_resync_send_plan(
        base_plan,
        sender_store,
        receiver_manifest,
        receiver_signatures,
    )?;
    DeltaResyncWirePayload::from_send_plan(send_plan)
}

/// Plan and build the sender-side delta transmission for one re-sync.
///
/// This is the end-to-end sender decision used by an edited-file re-sync: it
/// sends a delta envelope when either the chunk-level plan is smaller than the
/// full object or a sub-chunk op stream makes the otherwise-full-object change
/// smaller on the wire.
pub fn build_delta_resync_transmission(
    sender: &PersistentChunkManifest,
    sender_store: &ContentAddressedChunkStore,
    receiver: Option<&PersistentChunkManifest>,
    receiver_store: &ContentAddressedChunkStore,
    subchunk_block_size: usize,
) -> Result<DeltaResyncTransmission, DeltaError> {
    let base_plan = plan_incremental_resync(sender, receiver, receiver_store);
    let Some(receiver_manifest) = receiver else {
        return Ok(DeltaResyncTransmission {
            plan: base_plan,
            wire_payload: None,
            full_object_bytes: sender.total_size_bytes,
        });
    };

    match base_plan.mode {
        DeltaResyncMode::AlreadyInSync => Ok(DeltaResyncTransmission {
            plan: base_plan,
            wire_payload: None,
            full_object_bytes: sender.total_size_bytes,
        }),
        DeltaResyncMode::DeltaChunks => {
            let signatures = build_receiver_subchunk_signatures(
                receiver_manifest,
                receiver_store,
                subchunk_block_size,
            )?;
            let wire_payload = build_delta_resync_wire_payload(
                &base_plan,
                sender_store,
                receiver_manifest,
                &signatures,
            )?;
            Ok(DeltaResyncTransmission {
                plan: base_plan,
                wire_payload: Some(wire_payload),
                full_object_bytes: sender.total_size_bytes,
            })
        }
        DeltaResyncMode::FullObjectFallback
            if base_plan.fallback_reason
                == Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject) =>
        {
            let signatures = build_receiver_subchunk_signatures(
                receiver_manifest,
                receiver_store,
                subchunk_block_size,
            )?;
            let mut subdelta_plan = base_plan.clone();
            subdelta_plan.mode = DeltaResyncMode::DeltaChunks;
            subdelta_plan.fallback_reason = None;
            let wire_payload = build_delta_resync_wire_payload(
                &subdelta_plan,
                sender_store,
                receiver_manifest,
                &signatures,
            )?;
            if wire_payload.beats_full_object(sender.total_size_bytes) {
                Ok(DeltaResyncTransmission {
                    plan: subdelta_plan,
                    wire_payload: Some(wire_payload),
                    full_object_bytes: sender.total_size_bytes,
                })
            } else {
                Ok(DeltaResyncTransmission {
                    plan: base_plan,
                    wire_payload: None,
                    full_object_bytes: sender.total_size_bytes,
                })
            }
        }
        DeltaResyncMode::FullObjectFallback => Ok(DeltaResyncTransmission {
            plan: base_plan,
            wire_payload: None,
            full_object_bytes: sender.total_size_bytes,
        }),
    }
}

/// Apply a concrete delta send payload to receiver state and verify target coverage.
pub fn apply_delta_resync_send_plan(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    send_plan: &DeltaResyncSendPlan,
) -> Result<ContentAddressedChunkStore, DeltaError> {
    let mut store = receiver_store.clone();
    for item in &send_plan.items {
        match item {
            DeltaResyncSendItem::WholeChunk { payload, .. } => {
                store.insert(payload)?;
            }
            DeltaResyncSendItem::SubchunkOps {
                target_chunk,
                base_chunk,
                target_sha256,
                encoded_ops,
            } => {
                let old = verified_chunk_payload(&store, base_chunk)?;
                let ops = decode_subdelta_ops(encoded_ops)?;
                let rebuilt = delta_subchunk::reconstruct_verified(old, &ops, target_sha256)
                    .map_err(|source| DeltaError::SubDeltaReconstruction {
                        index: target_chunk.index,
                        source,
                    })?;
                store.insert(&rebuilt)?;
            }
            DeltaResyncSendItem::RepeatedChunk { chunk, .. } => {
                verified_chunk_payload(&store, chunk)?;
            }
        }
    }
    target_manifest.verify_store_coverage(&store)?;
    Ok(store)
}

/// Decode and apply a delta transfer envelope, then verify target coverage.
pub fn apply_delta_resync_wire_payload(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    base_plan: DeltaResyncPlan,
    wire_payload: &[u8],
) -> Result<ContentAddressedChunkStore, DeltaError> {
    let send_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan, wire_payload)?;
    apply_delta_resync_send_plan(target_manifest, receiver_store, &send_plan)
}

/// Decode, apply, and reconstruct a delta wire payload in one receiver step.
///
/// The returned bytes are assembled only after target manifest coverage verifies,
/// so callers can commit them directly to the destination path/tree and refresh
/// receiver delta state from the returned store.
pub fn apply_delta_resync_wire_payload_and_reconstruct(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    base_plan: DeltaResyncPlan,
    wire_payload: &[u8],
) -> Result<DeltaResyncApplyReport, DeltaError> {
    let send_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan, wire_payload)?;
    let wire_payload_bytes =
        u64::try_from(wire_payload.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
    let payload_bytes = send_plan.payload_bytes;
    let whole_chunk_bytes = send_plan.whole_chunk_bytes;
    let subchunk_count = send_plan.subchunk_count();
    let whole_chunk_count = send_plan.whole_chunk_count();
    let store = apply_delta_resync_send_plan(target_manifest, receiver_store, &send_plan)?;
    let reconstructed_bytes = reconstruct_manifest_bytes(target_manifest, &store)?;

    Ok(DeltaResyncApplyReport {
        store,
        reconstructed_bytes,
        wire_payload_bytes,
        payload_bytes,
        whole_chunk_bytes,
        subchunk_count,
        whole_chunk_count,
    })
}

/// Apply a sender transmission and reconstruct target bytes when it is a delta.
///
/// `Ok(None)` is the explicit full-object fallback signal. Already-in-sync
/// transmissions return a zero-byte report after verifying the receiver store
/// can reconstruct the target manifest.
pub fn apply_delta_resync_transmission(
    target_manifest: &PersistentChunkManifest,
    receiver_store: &ContentAddressedChunkStore,
    transmission: &DeltaResyncTransmission,
) -> Result<Option<DeltaResyncApplyReport>, DeltaError> {
    if let Some(wire_payload) = &transmission.wire_payload {
        return apply_delta_resync_wire_payload_and_reconstruct(
            target_manifest,
            receiver_store,
            wire_payload.base_plan.clone(),
            &wire_payload.wire_payload,
        )
        .map(Some);
    }

    if transmission.already_in_sync() {
        target_manifest.verify_store_coverage(receiver_store)?;
        let reconstructed_bytes = reconstruct_manifest_bytes(target_manifest, receiver_store)?;
        return Ok(Some(DeltaResyncApplyReport {
            store: receiver_store.clone(),
            reconstructed_bytes,
            wire_payload_bytes: 0,
            payload_bytes: 0,
            whole_chunk_bytes: 0,
            subchunk_count: 0,
            whole_chunk_count: 0,
        }));
    }

    Ok(None)
}

/// Reconstruct a manifest's logical byte stream from a verified chunk store.
pub fn reconstruct_manifest_bytes(
    manifest: &PersistentChunkManifest,
    store: &ContentAddressedChunkStore,
) -> Result<Vec<u8>, DeltaError> {
    let capacity =
        usize::try_from(manifest.total_size_bytes).map_err(|_| DeltaError::ChunkSizeOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    for chunk in &manifest.chunks {
        bytes.extend_from_slice(verified_chunk_payload(store, chunk)?);
    }
    Ok(bytes)
}

/// Encode sub-delta ops into the compact hot-path wire representation.
pub fn encode_subdelta_ops(ops: &[SubDeltaOp]) -> Result<Vec<u8>, DeltaError> {
    let mut out = Vec::new();
    out.extend_from_slice(SUBDELTA_OPS_MAGIC);
    out.extend_from_slice(
        &u64::try_from(ops.len())
            .map_err(|_| DeltaError::ChunkCountOverflow)?
            .to_be_bytes(),
    );
    for op in ops {
        match op {
            SubDeltaOp::Copy { old_offset, len } => {
                out.push(SUBDELTA_OP_COPY);
                out.extend_from_slice(&old_offset.to_be_bytes());
                out.extend_from_slice(&len.to_be_bytes());
            }
            SubDeltaOp::Literal(bytes) => {
                out.push(SUBDELTA_OP_LITERAL);
                out.extend_from_slice(
                    &u64::try_from(bytes.len())
                        .map_err(|_| DeltaError::ChunkSizeOverflow)?
                        .to_be_bytes(),
                );
                out.extend_from_slice(bytes);
            }
        }
    }
    Ok(out)
}

/// Decode the compact hot-path sub-delta op-stream representation.
pub fn decode_subdelta_ops(bytes: &[u8]) -> Result<Vec<SubDeltaOp>, DeltaError> {
    let mut reader = ByteReader::new(bytes);
    reader.expect_magic(SUBDELTA_OPS_MAGIC)?;
    let op_count =
        usize::try_from(reader.read_u64()?).map_err(|_| DeltaError::ChunkCountOverflow)?;
    let mut ops = Vec::with_capacity(op_count);
    for _ in 0..op_count {
        let tag = reader.read_u8()?;
        match tag {
            SUBDELTA_OP_COPY => {
                let old_offset = reader.read_u64()?;
                let len = reader.read_u32()?;
                ops.push(SubDeltaOp::Copy { old_offset, len });
            }
            SUBDELTA_OP_LITERAL => {
                let len = usize::try_from(reader.read_u64()?)
                    .map_err(|_| DeltaError::ChunkSizeOverflow)?;
                ops.push(SubDeltaOp::Literal(reader.read_exact(len)?.to_vec()));
            }
            other => return Err(DeltaError::InvalidSubDeltaOpTag { tag: other }),
        }
    }
    reader.expect_eof()?;
    Ok(ops)
}

/// Delta manifest/store validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    /// Manifest tree id was empty.
    EmptyTreeId,
    /// Manifest tree id was too large for canonical encoding.
    TreeIdTooLong { len: usize },
    /// Manifest tree id bytes were not valid UTF-8.
    InvalidTreeIdUtf8,
    /// More chunks were observed than the manifest format can represent.
    ChunkCountOverflow,
    /// Chunk size arithmetic overflowed.
    ChunkSizeOverflow,
    /// Chunk offset arithmetic overflowed.
    ChunkOffsetOverflow,
    /// Chunk index was not contiguous.
    NonContiguousIndex { expected: u32, actual: u32 },
    /// Chunk byte offset was not contiguous.
    NonContiguousOffset { expected: u64, actual: u64 },
    /// A logical chunk was empty.
    EmptyChunk { index: u32 },
    /// Persisted bytes had the wrong magic prefix.
    BadMagic,
    /// Persisted bytes ended before a complete manifest could be decoded.
    TruncatedManifest,
    /// Persisted bytes had trailing data after the manifest.
    TrailingBytes { trailing: usize },
    /// Manifest encoded size disagreed with computed size.
    TotalSizeMismatch { encoded: u64, computed: u64 },
    /// Manifest encoded root disagreed with computed root.
    ManifestRootMismatch {
        encoded: MerkleRoot,
        computed: MerkleRoot,
    },
    /// Manifest references a chunk that is absent from the local store.
    MissingChunk { index: u32, content_id: ContentId },
    /// Store payload size disagreed with the manifest.
    ChunkPayloadSizeMismatch {
        index: u32,
        expected: u64,
        actual: u64,
    },
    /// Store payload bytes hashed to a different id than the manifest expected.
    ChunkPayloadHashMismatch {
        index: u32,
        expected: ContentId,
        actual: ContentId,
    },
    /// A sub-chunk op stream failed while reconstructing the target chunk.
    SubDeltaReconstruction {
        index: u32,
        source: delta_subchunk::SubDeltaError,
    },
    /// A compact sub-delta op stream used an unknown operation tag.
    InvalidSubDeltaOpTag { tag: u8 },
    /// A delta send-plan envelope used an unknown payload item tag.
    InvalidDeltaSendItemTag { tag: u8 },
    /// A delta send-plan envelope used an unknown receiver-root tag.
    InvalidDeltaSendPlanReceiverRootTag { tag: u8 },
    /// Delta send-plan envelope targeted a different sender manifest root.
    DeltaSendPlanSenderRootMismatch {
        encoded: MerkleRoot,
        expected: MerkleRoot,
    },
    /// Delta send-plan envelope targeted a different receiver manifest root.
    DeltaSendPlanReceiverRootMismatch {
        encoded: Option<MerkleRoot>,
        expected: Option<MerkleRoot>,
    },
    /// Delta send-plan item order did not match the negotiated missing chunks.
    DeltaSendPlanChunkMismatch { ordinal: usize },
    /// Delta send-plan item count did not match the negotiated missing chunks.
    DeltaSendPlanItemCountMismatch { actual: usize, expected: usize },
    /// Delta send-plan encoded payload bytes disagreed with item payloads.
    DeltaSendPlanPayloadBytesMismatch { encoded: u64, computed: u64 },
    /// Delta send-plan whole-chunk baseline disagreed with the base plan.
    DeltaSendPlanWholeBytesMismatch { encoded: u64, expected: u64 },
    /// Receiver tried to advertise a manifest chunk it had not verified locally.
    ReceiverHaveSetMissingChunk { index: u32 },
    /// Receiver have-set exceeds the configured chunk-count budget.
    ReceiverHaveSetTooManyChunks { chunks: usize, max_chunks: usize },
    /// Receiver have-set exceeds the configured control-plane byte budget.
    ReceiverHaveSetTooManyBytes { bytes: u64, max_bytes: u64 },
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTreeId => write!(f, "delta manifest tree id is empty"),
            Self::TreeIdTooLong { len } => {
                write!(f, "delta manifest tree id is too long: {len} bytes")
            }
            Self::InvalidTreeIdUtf8 => write!(f, "delta manifest tree id is not valid UTF-8"),
            Self::ChunkCountOverflow => write!(f, "delta manifest chunk count overflowed"),
            Self::ChunkSizeOverflow => write!(f, "delta manifest chunk size overflowed"),
            Self::ChunkOffsetOverflow => write!(f, "delta manifest chunk offset overflowed"),
            Self::NonContiguousIndex { expected, actual } => write!(
                f,
                "delta manifest chunk index is not contiguous: expected {expected}, got {actual}"
            ),
            Self::NonContiguousOffset { expected, actual } => write!(
                f,
                "delta manifest chunk offset is not contiguous: expected {expected}, got {actual}"
            ),
            Self::EmptyChunk { index } => {
                write!(f, "delta manifest chunk {index} has zero length")
            }
            Self::BadMagic => write!(f, "delta manifest has an invalid magic prefix"),
            Self::TruncatedManifest => write!(f, "delta manifest is truncated"),
            Self::TrailingBytes { trailing } => {
                write!(f, "delta manifest has {trailing} trailing bytes")
            }
            Self::TotalSizeMismatch { encoded, computed } => write!(
                f,
                "delta manifest size mismatch: encoded {encoded}, computed {computed}"
            ),
            Self::ManifestRootMismatch { encoded, computed } => write!(
                f,
                "delta manifest Merkle root mismatch: encoded {encoded}, computed {computed}"
            ),
            Self::MissingChunk { index, content_id } => {
                write!(
                    f,
                    "delta manifest chunk {index} is missing from store: {content_id}"
                )
            }
            Self::ChunkPayloadSizeMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "delta manifest chunk {index} size mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkPayloadHashMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "delta manifest chunk {index} content id mismatch: expected {expected}, got {actual}"
            ),
            Self::SubDeltaReconstruction { index, source } => {
                write!(
                    f,
                    "delta sub-chunk reconstruction failed at chunk {index}: {source}"
                )
            }
            Self::InvalidSubDeltaOpTag { tag } => {
                write!(f, "delta sub-chunk op stream used invalid tag {tag}")
            }
            Self::InvalidDeltaSendItemTag { tag } => {
                write!(f, "delta send-plan envelope used invalid item tag {tag}")
            }
            Self::InvalidDeltaSendPlanReceiverRootTag { tag } => {
                write!(
                    f,
                    "delta send-plan envelope used invalid receiver-root tag {tag}"
                )
            }
            Self::DeltaSendPlanSenderRootMismatch { encoded, expected } => write!(
                f,
                "delta send-plan sender root mismatch: encoded {encoded}, expected {expected}"
            ),
            Self::DeltaSendPlanReceiverRootMismatch { encoded, expected } => write!(
                f,
                "delta send-plan receiver root mismatch: encoded {encoded:?}, expected {expected:?}"
            ),
            Self::DeltaSendPlanChunkMismatch { ordinal } => write!(
                f,
                "delta send-plan item {ordinal} does not match the negotiated missing chunk"
            ),
            Self::DeltaSendPlanItemCountMismatch { actual, expected } => write!(
                f,
                "delta send-plan item count mismatch: got {actual}, expected {expected}"
            ),
            Self::DeltaSendPlanPayloadBytesMismatch { encoded, computed } => write!(
                f,
                "delta send-plan payload byte count mismatch: encoded {encoded}, computed {computed}"
            ),
            Self::DeltaSendPlanWholeBytesMismatch { encoded, expected } => write!(
                f,
                "delta send-plan whole-chunk byte count mismatch: encoded {encoded}, expected {expected}"
            ),
            Self::ReceiverHaveSetMissingChunk { index } => {
                write!(
                    f,
                    "delta receiver have-set missing verified coverage for chunk {index}"
                )
            }
            Self::ReceiverHaveSetTooManyChunks { chunks, max_chunks } => write!(
                f,
                "delta receiver have-set advertised {chunks} chunks above the limit {max_chunks}"
            ),
            Self::ReceiverHaveSetTooManyBytes { bytes, max_bytes } => write!(
                f,
                "delta receiver have-set estimated {bytes} wire bytes above the limit {max_bytes}"
            ),
        }
    }
}

impl std::error::Error for DeltaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SubDeltaReconstruction { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Content-addressed receiver coverage key used during delta planning.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceiverChunkKey {
    /// Domain-separated content id for the covered chunk.
    content_id: ContentId,
    /// Chunk length in bytes.
    size_bytes: u64,
}

impl CasChunkRef {
    fn key(&self) -> ReceiverChunkKey {
        ReceiverChunkKey {
            content_id: self.content_id.clone(),
            size_bytes: self.size_bytes,
        }
    }
}

fn manifest_chunk_keys(chunks: &[CasChunkRef]) -> BTreeSet<ReceiverChunkKey> {
    chunks.iter().map(CasChunkRef::key).collect()
}

fn encode_chunk_ref(out: &mut Vec<u8>, chunk: &CasChunkRef) {
    out.extend_from_slice(&chunk.index.to_be_bytes());
    out.extend_from_slice(&chunk.byte_offset.to_be_bytes());
    out.extend_from_slice(&chunk.size_bytes.to_be_bytes());
    out.extend_from_slice(chunk.content_id.hash());
}

fn decode_chunk_ref(reader: &mut ByteReader<'_>) -> Result<CasChunkRef, DeltaError> {
    Ok(CasChunkRef {
        index: reader.read_u32()?,
        byte_offset: reader.read_u64()?,
        size_bytes: reader.read_u64()?,
        content_id: ContentId::new(reader.read_hash()?),
    })
}

fn write_u64_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DeltaError> {
    out.extend_from_slice(
        &u64::try_from(bytes.len())
            .map_err(|_| DeltaError::ChunkSizeOverflow)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn whole_chunk_run_can_derive_chunks_from_base(
    base_plan: &DeltaResyncPlan,
    items: &[DeltaResyncSendItem],
) -> bool {
    !items.is_empty()
        && items
            .iter()
            .zip(&base_plan.missing_chunks)
            .all(|(item, expected_chunk)| {
                matches!(item, DeltaResyncSendItem::WholeChunk { chunk, .. } if chunk == expected_chunk)
            })
}

fn compact_repeated_send_plan_if_smaller(
    send_plan: DeltaResyncSendPlan,
) -> Result<DeltaResyncSendPlan, DeltaError> {
    let dedup = dedupe_delta_missing_chunks(&send_plan.base_plan)?;
    if dedup.duplicate_missing_chunks == 0 {
        return Ok(send_plan);
    }

    let original_wire_bytes = u64::try_from(send_plan.to_wire_bytes()?.len())
        .map_err(|_| DeltaError::ChunkSizeOverflow)?;
    let mut first_by_key: BTreeMap<ReceiverChunkKey, usize> = BTreeMap::new();
    let mut compact_items = Vec::with_capacity(send_plan.items.len());
    let mut compact_payload_bytes = 0u64;

    for item in send_plan.items.iter().cloned() {
        let chunk = item.target_chunk().clone();
        let key = chunk.key();
        if let Some(&source_ordinal) = first_by_key.get(&key) {
            compact_items.push(DeltaResyncSendItem::RepeatedChunk {
                chunk,
                source_ordinal,
            });
            continue;
        }

        let ordinal = compact_items.len();
        compact_payload_bytes = compact_payload_bytes
            .checked_add(
                u64::try_from(item.payload_bytes()).map_err(|_| DeltaError::ChunkSizeOverflow)?,
            )
            .ok_or(DeltaError::ChunkSizeOverflow)?;
        first_by_key.insert(key, ordinal);
        compact_items.push(item);
    }

    let compact = DeltaResyncSendPlan {
        base_plan: send_plan.base_plan.clone(),
        items: compact_items,
        payload_bytes: compact_payload_bytes,
        whole_chunk_bytes: send_plan.whole_chunk_bytes,
    };
    let compact_wire_bytes =
        u64::try_from(compact.to_wire_bytes()?.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
    if compact_wire_bytes < original_wire_bytes {
        Ok(compact)
    } else {
        Ok(send_plan)
    }
}

fn send_items_payload_bytes(items: &[DeltaResyncSendItem]) -> Result<u64, DeltaError> {
    let mut payload_bytes = 0u64;
    for item in items {
        payload_bytes = payload_bytes
            .checked_add(
                u64::try_from(item.payload_bytes()).map_err(|_| DeltaError::ChunkSizeOverflow)?,
            )
            .ok_or(DeltaError::ChunkSizeOverflow)?;
    }
    Ok(payload_bytes)
}

fn validate_send_plan_items(
    base_plan: &DeltaResyncPlan,
    items: &[DeltaResyncSendItem],
) -> Result<(), DeltaError> {
    if items.len() != base_plan.missing_chunks.len() {
        return Err(DeltaError::DeltaSendPlanItemCountMismatch {
            actual: items.len(),
            expected: base_plan.missing_chunks.len(),
        });
    }
    for (ordinal, (item, expected_chunk)) in items.iter().zip(&base_plan.missing_chunks).enumerate()
    {
        if item.target_chunk() != expected_chunk {
            return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
        }
        if let DeltaResyncSendItem::RepeatedChunk {
            chunk,
            source_ordinal,
        } = item
        {
            if *source_ordinal >= ordinal {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            }
            let source_chunk = items[*source_ordinal].target_chunk();
            if source_chunk.key() != chunk.key() {
                return Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal });
            }
        }
    }
    Ok(())
}

fn receiver_have_set_wire_bytes(chunks: usize) -> Result<u64, DeltaError> {
    let chunks = u64::try_from(chunks).map_err(|_| DeltaError::ChunkCountOverflow)?;
    chunks
        .checked_mul(RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES)
        .and_then(|chunk_bytes| chunk_bytes.checked_add(RECEIVER_HAVE_SET_BASE_WIRE_BYTES))
        .ok_or(DeltaError::ChunkSizeOverflow)
}

fn full_object_plan(
    sender: &PersistentChunkManifest,
    receiver: Option<&PersistentChunkManifest>,
    reason: DeltaResyncFallbackReason,
) -> DeltaResyncPlan {
    DeltaResyncPlan {
        mode: DeltaResyncMode::FullObjectFallback,
        fallback_reason: Some(reason),
        sender_merkle_root: sender.merkle_root.clone(),
        receiver_merkle_root: receiver.map(|manifest| manifest.merkle_root.clone()),
        missing_chunks: sender.chunks.clone(),
        missing_bytes: sender.total_size_bytes,
        shared_chunks: 0,
        stale_chunks: receiver
            .map(|manifest| manifest.chunks.clone())
            .unwrap_or_default(),
        stale_bytes: receiver
            .map(|manifest| manifest.total_size_bytes)
            .unwrap_or_default(),
    }
}

fn build_delta_resync_send_item(
    target_chunk: &CasChunkRef,
    target_payload: &[u8],
    receiver_manifest: &PersistentChunkManifest,
    receiver_signatures: &[ReceiverSubchunkSignature],
) -> Result<DeltaResyncSendItem, DeltaError> {
    let whole = || DeltaResyncSendItem::WholeChunk {
        chunk: target_chunk.clone(),
        payload: target_payload.to_vec(),
    };

    let same_index_base = receiver_manifest
        .chunks
        .get(usize::try_from(target_chunk.index).map_err(|_| DeltaError::ChunkCountOverflow)?);
    let mut best: Option<(&CasChunkRef, Vec<u8>)> = None;

    for signature in receiver_signatures {
        if !is_subdelta_base_candidate(target_chunk, &signature.chunk, same_index_base) {
            continue;
        }

        let ops = delta_subchunk::diff(target_payload, &signature.signature);
        let encoded_ops = encode_subdelta_ops(&ops)?;
        if encoded_ops.len() >= target_payload.len() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(_, best_ops)| encoded_ops.len() < best_ops.len())
        {
            best = Some((&signature.chunk, encoded_ops));
        }
    }

    let Some((base_chunk, encoded_ops)) = best else {
        return Ok(whole());
    };
    Ok(DeltaResyncSendItem::SubchunkOps {
        target_chunk: target_chunk.clone(),
        base_chunk: base_chunk.clone(),
        target_sha256: Sha256::digest(target_payload).into(),
        encoded_ops,
    })
}

fn is_subdelta_base_candidate(
    target: &CasChunkRef,
    base: &CasChunkRef,
    same_index_base: Option<&CasChunkRef>,
) -> bool {
    chunks_byte_ranges_overlap(target, base)
        || same_index_base.is_some_and(|same_index| same_index.key() == base.key())
}

fn chunks_byte_ranges_overlap(left: &CasChunkRef, right: &CasChunkRef) -> bool {
    let left_end = left.byte_offset.saturating_add(left.size_bytes);
    let right_end = right.byte_offset.saturating_add(right.size_bytes);
    left.byte_offset < right_end && right.byte_offset < left_end
}

fn store_has_exact_chunk(store: &ContentAddressedChunkStore, chunk: &CasChunkRef) -> bool {
    store.has_exact_chunk(chunk)
}

fn verified_chunk_payload<'a>(
    store: &'a ContentAddressedChunkStore,
    chunk: &CasChunkRef,
) -> Result<&'a [u8], DeltaError> {
    let Some(payload) = store.get(&chunk.content_id) else {
        return Err(DeltaError::MissingChunk {
            index: chunk.index,
            content_id: chunk.content_id.clone(),
        });
    };
    let payload_size = u64::try_from(payload.len()).map_err(|_| DeltaError::ChunkSizeOverflow)?;
    if payload_size != chunk.size_bytes {
        return Err(DeltaError::ChunkPayloadSizeMismatch {
            index: chunk.index,
            expected: chunk.size_bytes,
            actual: payload_size,
        });
    }
    let actual_content_id = ContentId::from_bytes(payload);
    if actual_content_id != chunk.content_id {
        return Err(DeltaError::ChunkPayloadHashMismatch {
            index: chunk.index,
            expected: chunk.content_id.clone(),
            actual: actual_content_id,
        });
    }
    Ok(payload)
}

fn store_payload_matches(store: &ContentAddressedChunkStore, chunk: &CasChunkRef) -> bool {
    let Some(payload) = store.get(&chunk.content_id) else {
        return false;
    };
    let Ok(payload_len) = u64::try_from(payload.len()) else {
        return false;
    };
    payload_len == chunk.size_bytes && ContentId::from_bytes(payload) == chunk.content_id
}

fn validate_chunk_layout(chunks: &[CasChunkRef]) -> Result<u64, DeltaError> {
    let mut expected_offset = 0u64;
    for (expected_index, chunk) in chunks.iter().enumerate() {
        let expected_index =
            u32::try_from(expected_index).map_err(|_| DeltaError::ChunkCountOverflow)?;
        if chunk.index != expected_index {
            return Err(DeltaError::NonContiguousIndex {
                expected: expected_index,
                actual: chunk.index,
            });
        }
        if chunk.byte_offset != expected_offset {
            return Err(DeltaError::NonContiguousOffset {
                expected: expected_offset,
                actual: chunk.byte_offset,
            });
        }
        if chunk.size_bytes == 0 {
            return Err(DeltaError::EmptyChunk { index: chunk.index });
        }
        expected_offset = expected_offset
            .checked_add(chunk.size_bytes)
            .ok_or(DeltaError::ChunkOffsetOverflow)?;
    }

    Ok(expected_offset)
}

fn compute_manifest_root(
    tree_id: &str,
    total_size_bytes: u64,
    chunks: &[CasChunkRef],
) -> MerkleRoot {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_HASH_DOMAIN);
    hash_len_prefixed_bytes(&mut hasher, ATP_DELTA_CHUNK_MANIFEST_SCHEMA.as_bytes());
    hash_len_prefixed_bytes(&mut hasher, tree_id.as_bytes());
    hasher.update(total_size_bytes.to_be_bytes());
    hasher.update((chunks.len() as u64).to_be_bytes());
    for chunk in chunks {
        hasher.update(chunk.index.to_be_bytes());
        hasher.update(chunk.byte_offset.to_be_bytes());
        hasher.update(chunk.size_bytes.to_be_bytes());
        hasher.update(chunk.content_id.hash());
    }

    MerkleRoot::new(hasher.finalize().into())
}

fn hash_len_prefixed_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn write_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> ByteReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn expect_magic(&mut self, magic: &[u8]) -> Result<(), DeltaError> {
        let prefix = self.read_exact(magic.len())?;
        if prefix == magic {
            Ok(())
        } else {
            Err(DeltaError::BadMagic)
        }
    }

    fn read_string(&mut self) -> Result<String, DeltaError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DeltaError::InvalidTreeIdUtf8)
    }

    fn read_u32(&mut self) -> Result<u32, DeltaError> {
        Ok(u32::from_be_bytes(
            self.read_exact(4)?
                .try_into()
                .map_err(|_| DeltaError::TruncatedManifest)?,
        ))
    }

    fn read_u8(&mut self) -> Result<u8, DeltaError> {
        Ok(*self
            .read_exact(1)?
            .first()
            .ok_or(DeltaError::TruncatedManifest)?)
    }

    fn read_u64(&mut self) -> Result<u64, DeltaError> {
        Ok(u64::from_be_bytes(
            self.read_exact(8)?
                .try_into()
                .map_err(|_| DeltaError::TruncatedManifest)?,
        ))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], DeltaError> {
        self.read_exact(32)?
            .try_into()
            .map_err(|_| DeltaError::TruncatedManifest)
    }

    fn read_u64_prefixed_bytes(&mut self) -> Result<&'a [u8], DeltaError> {
        let len = usize::try_from(self.read_u64()?).map_err(|_| DeltaError::ChunkSizeOverflow)?;
        self.read_exact(len)
    }

    fn ensure_remaining_chunks(&self, chunk_count: usize) -> Result<(), DeltaError> {
        let required = chunk_count
            .checked_mul(ENCODED_CHUNK_BYTES)
            .and_then(|chunk_bytes| chunk_bytes.checked_add(32))
            .ok_or(DeltaError::ChunkSizeOverflow)?;
        if self.bytes.len().saturating_sub(self.cursor) < required {
            return Err(DeltaError::TruncatedManifest);
        }
        Ok(())
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

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], DeltaError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(DeltaError::TruncatedManifest)?;
        if end > self.bytes.len() {
            return Err(DeltaError::TruncatedManifest);
        }

        let slice = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ingest_manifest(
        store: &mut ContentAddressedChunkStore,
        tree_id: &str,
        chunks: Vec<&[u8]>,
    ) -> PersistentChunkManifest {
        let ingest = store.ingest_ordered_chunks(chunks).expect("ingest chunks");
        PersistentChunkManifest::new(tree_id, ingest.chunks).expect("manifest")
    }

    fn fixed_chunks(bytes: &[u8], chunk_size: usize) -> Vec<&[u8]> {
        bytes.chunks(chunk_size).collect()
    }

    #[test]
    fn content_addressed_store_deduplicates_repeated_chunks() {
        let mut store = ContentAddressedChunkStore::new();
        let ingest = store
            .ingest_ordered_chunks(vec![
                b"alpha".as_slice(),
                b"beta".as_slice(),
                b"alpha".as_slice(),
            ])
            .expect("ingest");

        assert_eq!(store.unique_chunk_count(), 2);
        assert_eq!(store.unique_bytes(), 9);
        assert_eq!(ingest.store_report.total_chunks, 3);
        assert_eq!(ingest.store_report.inserted_chunks, 2);
        assert_eq!(ingest.store_report.duplicate_chunks, 1);
        assert_eq!(ingest.store_report.inserted_bytes, 9);
        assert_eq!(ingest.store_report.duplicate_bytes, 5);
        assert_eq!(ingest.chunks[0].byte_offset, 0);
        assert_eq!(ingest.chunks[1].byte_offset, 5);
        assert_eq!(ingest.chunks[2].byte_offset, 9);
        assert_eq!(ingest.chunks[0].content_id, ingest.chunks[2].content_id);
    }

    #[test]
    fn manifest_round_trips_canonical_bytes_and_journal_resume_chunks() {
        let mut store = ContentAddressedChunkStore::new();
        let manifest = ingest_manifest(
            &mut store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );

        let decoded = PersistentChunkManifest::from_canonical_bytes(&manifest.to_canonical_bytes())
            .expect("decode");
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.total_size_bytes, 9);
        assert_eq!(decoded.journal_resume_chunks().len(), 2);
        assert_eq!(decoded.journal_resume_chunks()[0].chunk_offset, 0);
        assert_eq!(decoded.journal_resume_chunks()[0].chunk_size, 5);
        assert_eq!(
            decoded.journal_resume_chunks()[0].chunk_hash,
            *decoded.chunks[0].content_id.hash()
        );
        decoded
            .verify_store_coverage(&store)
            .expect("store covers manifest");
    }

    #[test]
    fn manifest_root_changes_when_chunk_content_changes() {
        let mut left_store = ContentAddressedChunkStore::new();
        let mut right_store = ContentAddressedChunkStore::new();
        let left = ingest_manifest(
            &mut left_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let right = ingest_manifest(
            &mut right_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"zeta".as_slice()],
        );

        assert_ne!(left.merkle_root, right.merkle_root);
        assert_ne!(left.to_canonical_bytes(), right.to_canonical_bytes());
    }

    #[test]
    fn manifest_decode_fails_closed_on_root_tamper() {
        let mut store = ContentAddressedChunkStore::new();
        let manifest = ingest_manifest(&mut store, "tree-a", vec![b"alpha".as_slice()]);
        let mut encoded = manifest.to_canonical_bytes();
        let last = encoded.last_mut().expect("root byte");
        *last ^= 0x80;

        let err = PersistentChunkManifest::from_canonical_bytes(&encoded).expect_err("tamper");
        assert!(matches!(err, DeltaError::ManifestRootMismatch { .. }));
    }

    #[test]
    fn manifest_rejects_non_contiguous_layout() {
        let chunk = CasChunkRef {
            index: 1,
            byte_offset: 0,
            size_bytes: 5,
            content_id: ContentId::from_bytes(b"alpha"),
        };

        let err = PersistentChunkManifest::new("tree-a", vec![chunk]).expect_err("bad index");
        assert_eq!(
            err,
            DeltaError::NonContiguousIndex {
                expected: 0,
                actual: 1
            }
        );
    }

    #[test]
    fn manifest_diff_reports_missing_and_stale_chunk_sets() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"beta".as_slice(), b"delta".as_slice()],
        );

        let diff = sender.diff_against(&receiver);

        assert_eq!(diff.shared_chunks, 1);
        assert_eq!(diff.missing_chunks.len(), 2);
        assert_eq!(diff.stale_chunks.len(), 1);
        assert_eq!(diff.missing_bytes, 10);
        assert_eq!(diff.stale_bytes, 5);
        assert_eq!(diff.missing_chunks[0].byte_offset, 0);
        assert_eq!(diff.missing_chunks[1].byte_offset, 9);
    }

    #[test]
    fn resync_planner_falls_back_without_prior_manifest() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver_store = ContentAddressedChunkStore::new();

        let plan = plan_incremental_resync(&sender, None, &receiver_store);

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::NoReceiverManifest)
        );
        assert_eq!(plan.missing_chunks, sender.chunks);
        assert_eq!(plan.missing_bytes, sender.total_size_bytes);
    }

    #[test]
    fn resync_planner_noops_when_manifest_and_cas_match() {
        let mut receiver_store = ContentAddressedChunkStore::new();
        let manifest = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );

        let plan = plan_incremental_resync(&manifest, Some(&manifest), &receiver_store);

        assert_eq!(plan.mode, DeltaResyncMode::AlreadyInSync);
        assert_eq!(plan.fallback_reason, None);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.shared_chunks, 2);
    }

    #[test]
    fn resync_planner_schedules_only_receiver_missing_chunks() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );

        let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);

        assert!(plan.uses_delta_chunks());
        assert_eq!(plan.fallback_reason, None);
        assert_eq!(plan.shared_chunks, 2);
        assert_eq!(plan.missing_chunks.len(), 1);
        assert_eq!(
            plan.missing_chunks[0].content_id,
            ContentId::from_bytes(b"gamma")
        );
        assert_eq!(
            plan.missing_content_ids(),
            vec![ContentId::from_bytes(b"gamma")]
        );
        assert_eq!(plan.missing_bytes, 5);
    }

    #[test]
    fn resync_planner_uses_receiver_cas_even_when_prior_layout_differs() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"old".as_slice()],
        );
        receiver_store
            .insert(b"beta")
            .expect("receiver has beta in CAS");

        let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);

        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.shared_chunks, 2);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.missing_bytes, 0);
        assert_eq!(plan.stale_chunks.len(), 1);
    }

    #[test]
    fn receiver_have_set_advertisement_drives_delta_plan() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            Default::default(),
        )
        .expect("receiver have-set");

        assert_eq!(advertisement.schema, ATP_DELTA_RECEIVER_HAVE_SET_SCHEMA);
        assert_eq!(advertisement.len(), 2);
        assert_eq!(
            advertisement.estimated_wire_bytes(),
            RECEIVER_HAVE_SET_BASE_WIRE_BYTES + 2 * RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES
        );
        assert!(advertisement.describes_manifest(&receiver));

        let plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&receiver),
            Some(&advertisement),
        );

        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.shared_chunks, 2);
        assert_eq!(plan.missing_chunks.len(), 1);
        assert_eq!(
            plan.missing_chunks[0].content_id,
            ContentId::from_bytes(b"gamma")
        );
        assert_eq!(plan.missing_bytes, 5);
    }

    #[test]
    fn receiver_have_set_advertises_extra_verified_cas_for_shifted_layouts() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"old".as_slice()],
        );
        let mut coverage = ReceiverCasCoverage::from_manifest(&receiver);
        coverage.insert(ContentId::from_bytes(b"beta"), 4);

        let advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits::DEFAULT,
        )
        .expect("receiver have-set");
        let plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&receiver),
            Some(&advertisement),
        );

        assert_eq!(advertisement.len(), 3);
        assert_eq!(
            advertisement.estimated_wire_bytes(),
            RECEIVER_HAVE_SET_BASE_WIRE_BYTES + 3 * RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES
        );
        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(plan.shared_chunks, 2);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.missing_bytes, 0);
        assert_eq!(plan.stale_chunks.len(), 1);
    }

    #[test]
    fn receiver_have_set_round_trips_to_sender_coverage() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"old".as_slice()],
        );
        let mut direct_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        direct_coverage.insert(ContentId::from_bytes(b"beta"), 4);

        let advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &direct_coverage,
            ReceiverHaveSetLimits::DEFAULT,
        )
        .expect("receiver have-set");
        let advertised_coverage = advertisement.to_coverage();

        assert_eq!(advertised_coverage.len(), direct_coverage.len());
        assert!(!advertised_coverage.is_empty());
        for chunk in &receiver.chunks {
            assert!(advertised_coverage.contains_chunk(chunk));
        }
        assert!(advertised_coverage.contains_chunk(&sender.chunks[1]));

        let direct_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &direct_coverage,
        );
        let advertised_plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&receiver),
            Some(&advertisement),
        );

        assert_eq!(advertised_plan, direct_plan);
        assert_eq!(advertised_plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(advertised_plan.shared_chunks, 2);
        assert!(advertised_plan.missing_chunks.is_empty());
        assert_eq!(advertised_plan.stale_chunks.len(), 1);
    }

    #[test]
    fn receiver_have_set_fails_closed_without_verified_coverage() {
        let mut receiver_store = ContentAddressedChunkStore::new();
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let mut coverage = ReceiverCasCoverage::new();
        coverage.insert_chunk_ref(&receiver.chunks[0]);

        let err = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits::DEFAULT,
        )
        .expect_err("unverified chunk must not be advertised");

        assert_eq!(err, DeltaError::ReceiverHaveSetMissingChunk { index: 1 });
    }

    #[test]
    fn receiver_have_set_enforces_chunk_and_wire_budgets() {
        let mut receiver_store = ContentAddressedChunkStore::new();
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let coverage = ReceiverCasCoverage::from_manifest(&receiver);

        let err = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits {
                max_chunks: 1,
                max_wire_bytes: u64::MAX,
            },
        )
        .expect_err("chunk budget must cap advertisement");
        assert_eq!(
            err,
            DeltaError::ReceiverHaveSetTooManyChunks {
                chunks: 2,
                max_chunks: 1,
            }
        );

        let err = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &receiver,
            &coverage,
            ReceiverHaveSetLimits {
                max_chunks: usize::MAX,
                max_wire_bytes: RECEIVER_HAVE_SET_BASE_WIRE_BYTES,
            },
        )
        .expect_err("wire budget must cap advertisement");
        assert_eq!(
            err,
            DeltaError::ReceiverHaveSetTooManyBytes {
                bytes: RECEIVER_HAVE_SET_BASE_WIRE_BYTES + 2 * RECEIVER_HAVE_SET_CHUNK_WIRE_BYTES,
                max_bytes: RECEIVER_HAVE_SET_BASE_WIRE_BYTES,
            }
        );
    }

    #[test]
    fn stale_receiver_have_set_falls_back_to_full_object() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut old_receiver_store = ContentAddressedChunkStore::new();
        let mut current_receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        );
        let old_receiver = ingest_manifest(
            &mut old_receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"beta".as_slice()],
        );
        let current_receiver = ingest_manifest(
            &mut current_receiver_store,
            "tree-a",
            vec![b"alpha".as_slice(), b"delta".as_slice()],
        );
        let old_coverage = ReceiverCasCoverage::from_manifest(&old_receiver);
        let stale_advertisement = ReceiverHaveSetAdvertisement::from_verified_manifest(
            &old_receiver,
            &old_coverage,
            Default::default(),
        )
        .expect("old receiver have-set");

        let plan = plan_incremental_resync_with_receiver_have_set(
            &sender,
            Some(&current_receiver),
            Some(&stale_advertisement),
        );

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete)
        );
        assert_eq!(plan.missing_bytes, sender.total_size_bytes);
    }

    #[test]
    fn resync_planner_falls_back_when_receiver_cas_does_not_cover_prior_manifest() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "tree-a", vec![b"alpha".as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "tree-a", vec![b"alpha".as_slice()]);
        let empty_receiver_store = ContentAddressedChunkStore::new();

        let plan = plan_incremental_resync(&sender, Some(&receiver), &empty_receiver_store);

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete)
        );
    }

    #[test]
    fn resync_planner_falls_back_when_delta_is_not_smaller_than_full_object() {
        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![b"new-a".as_slice(), b"new-b".as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "tree-a",
            vec![b"old-a".as_slice(), b"old-b".as_slice()],
        );

        let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);

        assert!(plan.requires_full_object_fallback());
        assert_eq!(
            plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );
        assert_eq!(plan.missing_chunks, sender.chunks);
        assert_eq!(plan.missing_bytes, sender.total_size_bytes);
    }

    #[test]
    fn send_plan_emits_subchunk_ops_and_reconstructs_byte_identical() {
        let old = (0..(64 * 1024))
            .map(|idx| ((idx * 17 + idx / 5 + 41) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        for byte in &mut new[24 * 1024..25 * 1024] {
            *byte ^= 0x5a;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "tree-a", vec![new.as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "tree-a", vec![old.as_slice()]);
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(base_plan.missing_bytes, sender.total_size_bytes);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.subchunk_count(), 1);
        assert_eq!(send_plan.whole_chunk_count(), 0);
        assert!(send_plan.beats_full_object(sender.total_size_bytes));
        assert!(send_plan.payload_bytes < send_plan.whole_chunk_bytes);

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        assert!(u64::try_from(wire_payload.len()).expect("wire len") < sender.total_size_bytes);
        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let mut tampered_root = wire_payload.clone();
        tampered_root[DELTA_RESYNC_SEND_PLAN_MAGIC.len()] ^= 0x80;
        let err = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &tampered_root)
            .expect_err("root tamper");
        assert!(matches!(
            err,
            DeltaError::DeltaSendPlanSenderRootMismatch { .. }
        ));

        let DeltaResyncSendItem::SubchunkOps { encoded_ops, .. } = &send_plan.items[0] else {
            panic!("expected sub-chunk op stream");
        };
        let decoded_ops = decode_subdelta_ops(encoded_ops).expect("decode op stream");
        assert!(decoded_ops
            .iter()
            .any(|op| matches!(op, SubDeltaOp::Literal(_))));

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(rebuilt, new);

        let applied_from_wire =
            apply_delta_resync_wire_payload(&sender, &receiver_store, base_plan, &wire_payload)
                .expect("apply wire payload");
        let rebuilt_from_wire =
            reconstruct_manifest_bytes(&sender, &applied_from_wire).expect("reconstruct wire");
        assert_eq!(rebuilt_from_wire, new);
    }

    #[test]
    fn send_plan_mixes_subchunk_and_whole_chunks_then_reconstructs_byte_identical() {
        let old_a = (0..(64 * 1024))
            .map(|idx| ((idx * 19 + idx / 3 + 7) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new_a = old_a.clone();
        for byte in &mut new_a[31 * 1024..32 * 1024] {
            *byte ^= 0x33;
        }
        let new_b = (0..(24 * 1024))
            .map(|idx| ((idx * 23 + idx / 11 + 5) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "tree-a",
            vec![new_a.as_slice(), new_b.as_slice()],
        );
        let receiver = ingest_manifest(&mut receiver_store, "tree-a", vec![old_a.as_slice()]);
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(base_plan.missing_chunks.len(), 2);
        assert_eq!(base_plan.missing_bytes, sender.total_size_bytes);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.subchunk_count(), 1);
        assert_eq!(send_plan.whole_chunk_count(), 1);
        assert!(send_plan.payload_bytes < send_plan.whole_chunk_bytes);

        assert!(matches!(
            &send_plan.items[0],
            DeltaResyncSendItem::SubchunkOps { .. }
        ));
        assert!(matches!(
            &send_plan.items[1],
            DeltaResyncSendItem::WholeChunk { .. }
        ));

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply mixed send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(rebuilt, [new_a.as_slice(), new_b.as_slice()].concat());

        let applied_from_wire =
            apply_delta_resync_wire_payload(&sender, &receiver_store, base_plan, &wire_payload)
                .expect("apply mixed wire payload");
        let rebuilt_from_wire =
            reconstruct_manifest_bytes(&sender, &applied_from_wire).expect("reconstruct wire");
        assert_eq!(
            rebuilt_from_wire,
            [new_a.as_slice(), new_b.as_slice()].concat()
        );
    }

    #[test]
    fn send_plan_compacts_appended_whole_chunk_run_then_reconstructs() {
        let base = (0..(64 * 1024))
            .map(|idx| ((idx * 17 + idx / 5 + 41) % 251) as u8)
            .collect::<Vec<_>>();
        let append_a = (0..(32 * 1024))
            .map(|idx| ((idx * 23 + idx / 11 + 13) % 253) as u8)
            .collect::<Vec<_>>();
        let append_b = (0..(32 * 1024))
            .map(|idx| ((idx * 29 + idx / 7 + 19) % 251) as u8)
            .collect::<Vec<_>>();
        let append_c = (0..(16 * 1024))
            .map(|idx| ((idx * 31 + idx / 3 + 47) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "append-file",
            vec![
                base.as_slice(),
                append_a.as_slice(),
                append_b.as_slice(),
                append_c.as_slice(),
            ],
        );
        let receiver = ingest_manifest(&mut receiver_store, "append-file", vec![base.as_slice()]);
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(base_plan.shared_chunks, 1);
        assert_eq!(base_plan.missing_chunks.len(), 3);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.whole_chunk_count(), 3);
        assert_eq!(send_plan.subchunk_count(), 0);
        assert_eq!(send_plan.payload_bytes, send_plan.whole_chunk_bytes);

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        let header_bytes = DELTA_RESYNC_SEND_PLAN_MAGIC.len() + 32 + 1 + 32 + 8 + 8 + 8;
        assert_eq!(
            wire_payload[header_bytes], DELTA_SEND_ITEM_WHOLE_CHUNK_RUN,
            "append should use one implicit whole-chunk run"
        );

        let run_overhead = header_bytes + 1 + 8 + 8;
        assert_eq!(
            wire_payload.len(),
            usize::try_from(send_plan.payload_bytes).expect("payload bytes fit") + run_overhead
        );
        let explicit_whole_item_overhead = 1 + ENCODED_CHUNK_BYTES + 8;
        let legacy_whole_wire_len = usize::try_from(send_plan.payload_bytes)
            .expect("payload bytes fit")
            + header_bytes
            + send_plan.items.len() * explicit_whole_item_overhead;
        assert!(
            wire_payload.len() + 128 < legacy_whole_wire_len,
            "implicit append run should remove per-chunk ref/length metadata"
        );

        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let applied = apply_delta_resync_wire_payload_and_reconstruct(
            &sender,
            &receiver_store,
            base_plan,
            &wire_payload,
        )
        .expect("apply append run");
        assert_eq!(
            applied.reconstructed_bytes,
            [
                base.as_slice(),
                append_a.as_slice(),
                append_b.as_slice(),
                append_c.as_slice()
            ]
            .concat()
        );
        assert_eq!(applied.whole_chunk_count, 3);
        assert_eq!(applied.subchunk_count, 0);
    }

    #[test]
    fn send_plan_chooses_best_overlapping_subchunk_base_after_cdc_drift() {
        let wrong_base = (0..(16 * 1024))
            .map(|idx| ((idx * 5 + 91) % 251) as u8)
            .collect::<Vec<_>>();
        let good_base = (0..(64 * 1024))
            .map(|idx| ((idx * 23 + idx / 7 + 11) % 253) as u8)
            .collect::<Vec<_>>();
        let mut target = good_base[..32 * 1024].to_vec();
        for byte in &mut target[12 * 1024..13 * 1024] {
            *byte ^= 0x63;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "edited-file", vec![target.as_slice()]);
        let receiver = ingest_manifest(
            &mut receiver_store,
            "edited-file",
            vec![wrong_base.as_slice(), good_base.as_slice()],
        );
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            base_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.subchunk_count(), 1);
        assert_eq!(send_plan.whole_chunk_count(), 0);
        assert!(send_plan.payload_bytes < send_plan.whole_chunk_bytes / 4);
        let DeltaResyncSendItem::SubchunkOps { base_chunk, .. } = &send_plan.items[0] else {
            panic!("expected subchunk ops");
        };
        assert_eq!(
            base_chunk.content_id, receiver.chunks[1].content_id,
            "sender should choose the compact overlapping base, not the poor same-index base"
        );

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(rebuilt, target);
    }

    #[test]
    fn send_plan_dedupes_repeated_missing_chunks_then_reconstructs() {
        let repeated = (0..(8 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 43) % 251) as u8)
            .collect::<Vec<_>>();
        let unique = (0..(2 * 1024))
            .map(|idx| ((idx * 11 + idx / 3 + 97) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "repeated-file",
            vec![repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = ingest_manifest(&mut receiver_store, "repeated-file", Vec::new());
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.missing_chunks.len(), 3);
        assert_eq!(base_plan.missing_bytes, sender.total_size_bytes);

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        assert_eq!(send_plan.whole_chunk_count(), 2);
        assert_eq!(send_plan.subchunk_count(), 0);
        assert_eq!(
            send_plan.payload_bytes,
            u64::try_from(repeated.len() + unique.len()).expect("payload len")
        );
        assert!(matches!(
            send_plan.items[2],
            DeltaResyncSendItem::RepeatedChunk {
                source_ordinal: 0,
                ..
            }
        ));

        let wire_payload = send_plan.to_wire_bytes().expect("wire encode");
        assert!(
            u64::try_from(wire_payload.len()).expect("wire len")
                < sender.total_size_bytes - u64::try_from(repeated.len()).expect("repeat len") / 2
        );
        let decoded_plan = DeltaResyncSendPlan::from_wire_bytes(base_plan.clone(), &wire_payload)
            .expect("wire decode");
        assert_eq!(decoded_plan, send_plan);

        let applied = apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan)
            .expect("apply send plan");
        let rebuilt = reconstruct_manifest_bytes(&sender, &applied).expect("reconstruct target");
        assert_eq!(
            rebuilt,
            [repeated.as_slice(), unique.as_slice(), repeated.as_slice()].concat()
        );

        let applied_from_wire =
            apply_delta_resync_wire_payload(&sender, &receiver_store, base_plan, &wire_payload)
                .expect("apply wire payload");
        let rebuilt_from_wire =
            reconstruct_manifest_bytes(&sender, &applied_from_wire).expect("reconstruct wire");
        assert_eq!(rebuilt_from_wire, rebuilt);
    }

    #[test]
    fn send_plan_rejects_repeated_chunk_source_ordinal_forgery() {
        let repeated = (0..(8 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 43) % 251) as u8)
            .collect::<Vec<_>>();
        let unique = (0..(2 * 1024))
            .map(|idx| ((idx * 11 + idx / 3 + 97) % 253) as u8)
            .collect::<Vec<_>>();

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "repeated-file",
            vec![repeated.as_slice(), unique.as_slice(), repeated.as_slice()],
        );
        let receiver = ingest_manifest(&mut receiver_store, "repeated-file", Vec::new());
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );
        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let send_plan =
            build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
                .expect("send plan");

        let DeltaResyncSendItem::RepeatedChunk {
            chunk,
            source_ordinal,
        } = &send_plan.items[2]
        else {
            panic!("expected compacted repeated chunk");
        };
        assert_eq!(*source_ordinal, 0);

        let mut self_referential = send_plan.clone();
        self_referential.items[2] = DeltaResyncSendItem::RepeatedChunk {
            chunk: chunk.clone(),
            source_ordinal: 2,
        };
        assert!(matches!(
            self_referential.to_wire_bytes(),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 2 })
        ));

        let mut wrong_source = send_plan.clone();
        wrong_source.items[2] = DeltaResyncSendItem::RepeatedChunk {
            chunk: chunk.clone(),
            source_ordinal: 1,
        };
        assert!(matches!(
            wrong_source.to_wire_bytes(),
            Err(DeltaError::DeltaSendPlanChunkMismatch { ordinal: 2 })
        ));
    }

    #[test]
    fn wire_payload_report_transmits_delta_and_reconstructs_bench_object() {
        let shared = (0..(32 * 1024))
            .map(|idx| ((idx * 13 + 11) % 251) as u8)
            .collect::<Vec<_>>();
        let old_changed = (0..(64 * 1024))
            .map(|idx| ((idx * 17 + idx / 7 + 3) % 253) as u8)
            .collect::<Vec<_>>();
        let mut new_changed = old_changed.clone();
        for byte in &mut new_changed[28 * 1024..29 * 1024] {
            *byte ^= 0x71;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "bench-file",
            vec![shared.as_slice(), new_changed.as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "bench-file",
            vec![shared.as_slice(), old_changed.as_slice()],
        );
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );

        assert_eq!(base_plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(base_plan.shared_chunks, 1);
        assert_eq!(base_plan.missing_chunks.len(), 1);
        assert_eq!(
            base_plan.missing_bytes,
            u64::try_from(new_changed.len()).expect("test chunk len")
        );

        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let payload =
            build_delta_resync_wire_payload(&base_plan, &sender_store, &receiver, &signatures)
                .expect("wire payload");

        assert_eq!(payload.base_plan, base_plan);
        assert_eq!(payload.subchunk_count, 1);
        assert_eq!(payload.whole_chunk_count, 0);
        assert!(payload.payload_bytes < payload.whole_chunk_bytes);
        assert!(payload.beats_full_object(sender.total_size_bytes));

        let applied = apply_delta_resync_wire_payload_and_reconstruct(
            &sender,
            &receiver_store,
            payload.base_plan.clone(),
            &payload.wire_payload,
        )
        .expect("apply and reconstruct");

        assert_eq!(applied.wire_payload_bytes, payload.wire_payload_bytes);
        assert_eq!(applied.payload_bytes, payload.payload_bytes);
        assert_eq!(applied.whole_chunk_bytes, payload.whole_chunk_bytes);
        assert_eq!(applied.subchunk_count, 1);
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(
            applied.reconstructed_bytes,
            [shared.as_slice(), new_changed.as_slice()].concat()
        );
        sender
            .verify_store_coverage(&applied.store)
            .expect("target coverage");
    }

    #[test]
    fn wire_apply_report_rejects_payload_accounting_mismatch() {
        let shared = (0..(32 * 1024))
            .map(|idx| ((idx * 7 + 19) % 251) as u8)
            .collect::<Vec<_>>();
        let old_changed = (0..(64 * 1024))
            .map(|idx| ((idx * 29 + idx / 13 + 17) % 253) as u8)
            .collect::<Vec<_>>();
        let mut new_changed = old_changed.clone();
        for byte in &mut new_changed[20 * 1024..21 * 1024] {
            *byte ^= 0x4d;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "bench-file",
            vec![shared.as_slice(), new_changed.as_slice()],
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "bench-file",
            vec![shared.as_slice(), old_changed.as_slice()],
        );
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver);
        let base_plan = plan_incremental_resync_with_receiver_coverage(
            &sender,
            Some(&receiver),
            &receiver_coverage,
        );
        let signatures = build_receiver_subchunk_signatures(
            &receiver,
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("receiver signatures");
        let payload =
            build_delta_resync_wire_payload(&base_plan, &sender_store, &receiver, &signatures)
                .expect("wire payload");

        let mut tampered = payload.wire_payload.clone();
        let receiver_root_bytes = if payload.base_plan.receiver_merkle_root.is_some() {
            32
        } else {
            0
        };
        let payload_bytes_offset =
            DELTA_RESYNC_SEND_PLAN_MAGIC.len() + 32 + 1 + receiver_root_bytes + 8;
        tampered[payload_bytes_offset + 7] ^= 0x01;

        let err = apply_delta_resync_wire_payload_and_reconstruct(
            &sender,
            &receiver_store,
            payload.base_plan,
            &tampered,
        )
        .expect_err("payload accounting mismatch must fail closed");
        assert!(matches!(
            err,
            DeltaError::DeltaSendPlanPayloadBytesMismatch { .. }
        ));
    }

    #[test]
    fn transmission_promotes_sparse_edited_file_to_delta_wire_payload() {
        let old = (0..(96 * 1024))
            .map(|idx| ((idx * 29 + idx / 5 + 97) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        for byte in &mut new[44 * 1024..45 * 1024] {
            *byte ^= 0xa6;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "edited-file", vec![new.as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "edited-file", vec![old.as_slice()]);

        let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
        assert_eq!(chunk_level_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            chunk_level_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let transmission = build_delta_resync_transmission(
            &sender,
            &sender_store,
            Some(&receiver),
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("transmission");

        assert!(transmission.uses_delta_wire_payload());
        assert_eq!(transmission.plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(transmission.plan.fallback_reason, None);
        let wire_payload = transmission
            .wire_payload
            .as_ref()
            .expect("delta wire payload");
        assert_eq!(wire_payload.subchunk_count, 1);
        assert_eq!(wire_payload.whole_chunk_count, 0);
        assert!(wire_payload.payload_bytes < wire_payload.whole_chunk_bytes);
        assert!(wire_payload.wire_payload_bytes < sender.total_size_bytes / 4);

        let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
            .expect("apply transmission")
            .expect("delta apply report");

        assert_eq!(applied.reconstructed_bytes, new);
        assert_eq!(applied.subchunk_count, 1);
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(applied.wire_payload_bytes, wire_payload.wire_payload_bytes);
    }

    #[test]
    fn transmission_promotes_scattered_byte_flips_to_delta_wire_payload() {
        let old = (0..(512 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 17) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        let scattered_edits = old.len() / 100;
        for edit in 0..scattered_edits {
            let pos = (edit * 7919 + 104_729) % new.len();
            new[pos] ^= 0xa5;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(&mut sender_store, "scattered-file", vec![new.as_slice()]);
        let receiver = ingest_manifest(&mut receiver_store, "scattered-file", vec![old.as_slice()]);

        let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
        assert_eq!(chunk_level_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            chunk_level_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let transmission = build_delta_resync_transmission(
            &sender,
            &sender_store,
            Some(&receiver),
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("transmission");

        assert!(transmission.uses_delta_wire_payload());
        assert_eq!(transmission.plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(transmission.plan.fallback_reason, None);
        let wire_payload = transmission
            .wire_payload
            .as_ref()
            .expect("delta wire payload");
        assert_eq!(wire_payload.subchunk_count, 1);
        assert_eq!(wire_payload.whole_chunk_count, 0);
        assert!(wire_payload.beats_full_object(sender.total_size_bytes));
        assert!(wire_payload.wire_payload_bytes < sender.total_size_bytes * 3 / 4);

        let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
            .expect("apply transmission")
            .expect("delta apply report");

        assert_eq!(applied.reconstructed_bytes, new);
        assert_eq!(applied.subchunk_count, 1);
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(applied.wire_payload_bytes, wire_payload.wire_payload_bytes);
    }

    #[test]
    fn transmission_keeps_scattered_multichunk_edits_on_delta_wire_path() {
        let chunk_size = 64 * 1024;
        let old = (0..(8 * chunk_size))
            .map(|idx| ((idx * 37 + idx / 11 + 53) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        let scattered_edits = old.len() / 100;
        for edit in 0..scattered_edits {
            let pos = (edit * 7919 + 104_729) % new.len();
            new[pos] ^= 0xa5;
        }

        let mut sender_store = ContentAddressedChunkStore::new();
        let mut receiver_store = ContentAddressedChunkStore::new();
        let sender = ingest_manifest(
            &mut sender_store,
            "scattered-multichunk-file",
            fixed_chunks(&new, chunk_size),
        );
        let receiver = ingest_manifest(
            &mut receiver_store,
            "scattered-multichunk-file",
            fixed_chunks(&old, chunk_size),
        );

        let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
        assert_eq!(chunk_level_plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(
            chunk_level_plan.fallback_reason,
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
        );

        let transmission = build_delta_resync_transmission(
            &sender,
            &sender_store,
            Some(&receiver),
            &receiver_store,
            delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
        )
        .expect("transmission");

        assert!(transmission.uses_delta_wire_payload());
        assert_eq!(transmission.plan.mode, DeltaResyncMode::DeltaChunks);
        assert_eq!(transmission.plan.fallback_reason, None);
        let wire_payload = transmission
            .wire_payload
            .as_ref()
            .expect("delta wire payload");
        assert_eq!(wire_payload.subchunk_count, sender.chunks.len());
        assert_eq!(wire_payload.whole_chunk_count, 0);
        assert!(wire_payload.beats_full_object(sender.total_size_bytes));

        let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
            .expect("apply transmission")
            .expect("delta apply report");

        assert_eq!(applied.reconstructed_bytes, new);
        assert_eq!(applied.subchunk_count, sender.chunks.len());
        assert_eq!(applied.whole_chunk_count, 0);
        assert_eq!(applied.wire_payload_bytes, wire_payload.wire_payload_bytes);
    }
}
