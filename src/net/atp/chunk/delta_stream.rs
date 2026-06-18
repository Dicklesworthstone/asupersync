//! Delta chunk packing for RaptorQ-backed ATP transfers.
//!
//! B-8.3 reconciles chunk-id sets. This module takes the receiver-missing set,
//! verifies that every requested chunk is present and hash-correct, then packs
//! those chunks into deterministic source objects that the RaptorQ transport
//! can spray as loss-tolerant symbols.

use super::ChunkingProfileError;
use super::cas::{CasManifestChunk, CasMerkleManifest, ChunkAddress, ContentAddressedChunkStore};
use super::dedupe::CdcChunkData;
use super::reconcile::ChunkFingerprint;
use crate::atp::manifest::{RaptorQSymbol, RepairGroupId};
use crate::atp::object::{ContentId, ObjectId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DELTA_OBJECT_DOMAIN: &[u8] = b"asupersync::atp::delta-chunks::object::v1\0";
const CHUNK_RECORD_DOMAIN: &[u8] = b"asupersync::atp::delta-chunks::record::v1\0";
const REASSEMBLY_TREE_DOMAIN: &[u8] = b"asupersync::atp::delta-reassembly::tree::v1\0";

/// Chunk bytes available for delta transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaChunkPayload {
    /// Content fingerprint selected by B-8.3.
    pub fingerprint: ChunkFingerprint,
    /// Verified chunk bytes.
    pub bytes: Vec<u8>,
}

impl DeltaChunkPayload {
    /// Create a payload from raw bytes, deriving the SHA-256 fingerprint.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            fingerprint: ChunkFingerprint::new(sha256(&bytes)),
            bytes,
        }
    }

    /// Bind CDC metadata to supplied bytes and fail closed on any mismatch.
    pub fn from_cdc_chunk(
        chunk: &CdcChunkData,
        bytes: Vec<u8>,
    ) -> Result<Self, ChunkingProfileError> {
        let observed_size = u64::try_from(bytes.len()).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "delta chunk length exceeds u64::MAX".to_string(),
            )
        })?;
        if observed_size != chunk.size_bytes {
            return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                "delta chunk size mismatch for offset {}: expected {}, observed {}",
                chunk.byte_offset, chunk.size_bytes, observed_size
            )));
        }

        let observed_hash = sha256(&bytes);
        if observed_hash != chunk.content_hash {
            return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                "delta chunk hash mismatch for offset {}",
                chunk.byte_offset
            )));
        }

        Ok(Self {
            fingerprint: ChunkFingerprint::new(chunk.content_hash),
            bytes,
        })
    }
}

/// Delta-to-RaptorQ packing configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRaptorQConfig {
    /// Fixed RaptorQ source symbol size.
    pub symbol_size: u32,
    /// Maximum coalesced delta object payload before starting a new object.
    pub max_object_payload_bytes: usize,
    /// Repair-symbol budget as a percentage of source symbols.
    pub repair_overhead_percent: u16,
}

impl Default for DeltaRaptorQConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1280,
            max_object_payload_bytes: 1024 * 1024,
            repair_overhead_percent: 20,
        }
    }
}

impl DeltaRaptorQConfig {
    fn validate(&self) -> Result<(), ChunkingProfileError> {
        if self.symbol_size == 0 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "delta RaptorQ symbol_size must be greater than zero".to_string(),
            ));
        }
        if self.max_object_payload_bytes == 0 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "delta RaptorQ max object payload must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// Source-symbol payload bound to a manifest-level RaptorQ descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRaptorQSymbol {
    /// Manifest descriptor for the source symbol.
    pub descriptor: RaptorQSymbol,
    /// Padded symbol payload. Length always equals `descriptor.size_bytes`.
    pub payload: Vec<u8>,
}

/// One coalesced delta object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRaptorQObject {
    /// Content-addressed object id for the encoded chunk-record payload.
    pub object_id: ObjectId,
    /// Missing chunks carried by this object in canonical order.
    pub chunk_fingerprints: Vec<ChunkFingerprint>,
    /// Unpadded delta object payload length.
    pub payload_len: usize,
    /// Source symbols emitted for this object.
    pub source_symbols: Vec<DeltaRaptorQSymbol>,
    /// Repair-symbol budget for downstream fountain scheduling.
    pub repair_symbol_budget: u32,
}

/// Complete delta transfer plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRaptorQPlan {
    /// Coalesced delta objects to send.
    pub objects: Vec<DeltaRaptorQObject>,
    /// Requested chunks that were absent from the local provider.
    pub missing_unavailable: BTreeSet<ChunkFingerprint>,
}

impl DeltaRaptorQPlan {
    /// Total source symbols across all coalesced objects.
    #[must_use]
    pub fn total_source_symbols(&self) -> usize {
        self.objects
            .iter()
            .map(|object| object.source_symbols.len())
            .sum()
    }

    /// Total repair-symbol budget across all coalesced objects.
    #[must_use]
    pub fn total_repair_symbol_budget(&self) -> u32 {
        self.objects.iter().fold(0u32, |sum, object| {
            sum.saturating_add(object.repair_symbol_budget)
        })
    }

    /// Total unpadded bytes across all coalesced delta objects.
    #[must_use]
    pub fn total_delta_payload_bytes(&self) -> usize {
        self.objects.iter().map(|object| object.payload_len).sum()
    }

    /// True when no delta object needs to be sent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

/// Build a RaptorQ-oriented delta transfer plan from a receiver-missing set.
pub fn plan_delta_raptorq_stream<I>(
    receiver_missing: &BTreeSet<ChunkFingerprint>,
    available_chunks: I,
    config: &DeltaRaptorQConfig,
) -> Result<DeltaRaptorQPlan, ChunkingProfileError>
where
    I: IntoIterator<Item = DeltaChunkPayload>,
{
    config.validate()?;

    if receiver_missing.is_empty() {
        return Ok(DeltaRaptorQPlan {
            objects: Vec::new(),
            missing_unavailable: BTreeSet::new(),
        });
    }

    let mut available = BTreeMap::new();
    for chunk in available_chunks {
        if sha256(&chunk.bytes) != *chunk.fingerprint.as_bytes() {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "delta chunk provider returned bytes that do not match fingerprint".to_string(),
            ));
        }
        available.insert(chunk.fingerprint, chunk.bytes);
    }

    let mut objects = Vec::new();
    let mut current_payload = new_delta_object_payload();
    let mut current_chunks = Vec::new();
    let mut missing_unavailable = BTreeSet::new();

    for fingerprint in receiver_missing {
        let Some(bytes) = available.remove(fingerprint) else {
            missing_unavailable.insert(*fingerprint);
            continue;
        };
        let record = encode_chunk_record(*fingerprint, &bytes)?;
        if record.len() > config.max_object_payload_bytes {
            return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                "single delta chunk record {} exceeds max object payload {}",
                record.len(),
                config.max_object_payload_bytes
            )));
        }
        if current_payload.len() + record.len() > config.max_object_payload_bytes
            && !current_chunks.is_empty()
        {
            objects.push(finalize_object(
                std::mem::replace(&mut current_payload, new_delta_object_payload()),
                std::mem::take(&mut current_chunks),
                config,
            )?);
        }

        current_payload.extend_from_slice(&record);
        current_chunks.push(*fingerprint);
    }

    if !current_chunks.is_empty() {
        objects.push(finalize_object(current_payload, current_chunks, config)?);
    }

    if !missing_unavailable.is_empty() {
        return Err(ChunkingProfileError::InvalidChunkParameters(format!(
            "{} receiver-missing chunks were not available for delta transfer",
            missing_unavailable.len()
        )));
    }

    Ok(DeltaRaptorQPlan {
        objects,
        missing_unavailable,
    })
}

/// Decode a B-8.4 delta object payload after RaptorQ has reconstructed it.
pub fn decode_delta_object_payload(
    payload: &[u8],
) -> Result<Vec<DeltaChunkPayload>, ChunkingProfileError> {
    if !payload.starts_with(DELTA_OBJECT_DOMAIN) {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "delta object payload has an invalid domain".to_string(),
        ));
    }

    let mut cursor = DELTA_OBJECT_DOMAIN.len();
    let mut chunks = Vec::new();
    while cursor < payload.len() {
        if payload[cursor..].len() < CHUNK_RECORD_DOMAIN.len() + 32 + 8 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "truncated delta chunk record header".to_string(),
            ));
        }
        if &payload[cursor..cursor + CHUNK_RECORD_DOMAIN.len()] != CHUNK_RECORD_DOMAIN {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "delta chunk record has an invalid domain".to_string(),
            ));
        }
        cursor += CHUNK_RECORD_DOMAIN.len();

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&payload[cursor..cursor + 32]);
        cursor += 32;

        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&payload[cursor..cursor + 8]);
        cursor += 8;
        let len = usize::try_from(u64::from_be_bytes(len_bytes)).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "delta chunk record length exceeds usize::MAX".to_string(),
            )
        })?;
        if payload[cursor..].len() < len {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "truncated delta chunk record payload".to_string(),
            ));
        }

        let bytes = payload[cursor..cursor + len].to_vec();
        cursor += len;
        if sha256(&bytes) != fingerprint {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "delta chunk record hash mismatch".to_string(),
            ));
        }
        chunks.push(DeltaChunkPayload {
            fingerprint: ChunkFingerprint::new(fingerprint),
            bytes,
        });
    }

    Ok(chunks)
}

/// Source-side commitments the receiver must satisfy before committing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaReassemblyExpectation {
    /// Expected Merkle root from the source CAS manifest.
    pub manifest_root: [u8; 32],
    /// Expected whole-tree digest over path names and file SHA-256 values.
    pub tree_digest: [u8; 32],
}

impl DeltaReassemblyExpectation {
    /// Create explicit fail-closed receiver commitments.
    #[must_use]
    pub const fn new(manifest_root: [u8; 32], tree_digest: [u8; 32]) -> Self {
        Self {
            manifest_root,
            tree_digest,
        }
    }

    /// Build receiver commitments from an already-trusted source manifest/files.
    #[must_use]
    pub fn from_manifest_and_files(
        manifest: &CasMerkleManifest,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self::new(manifest.root(), delta_tree_digest(files))
    }
}

/// One staged output file that passed manifest and whole-tree verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaReassembledFile {
    /// Transfer-relative path.
    pub rel_path: String,
    /// Fully reassembled file bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`.
    pub content_hash: [u8; 32],
}

/// Prepared commit. Destination mutation is separated from verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaReassemblyCommit {
    /// Verified staged files, sorted by relative path.
    pub files: Vec<DeltaReassembledFile>,
    /// Verified CAS manifest root.
    pub manifest_root: [u8; 32],
    /// Verified whole-tree digest.
    pub tree_digest: [u8; 32],
    /// Logical bytes represented by the manifest.
    pub total_bytes: u64,
}

impl DeltaReassemblyCommit {
    /// Atomically publish staged files into a mutable destination map.
    #[must_use]
    pub fn commit_into(
        self,
        destination: &mut BTreeMap<String, Vec<u8>>,
    ) -> DeltaReassemblyCommitReceipt {
        let mut staged = destination.clone();
        let mut committed_paths = Vec::with_capacity(self.files.len());
        for file in &self.files {
            staged.insert(file.rel_path.clone(), file.bytes.clone());
            committed_paths.push(file.rel_path.clone());
        }
        *destination = staged;
        DeltaReassemblyCommitReceipt {
            committed: true,
            committed_paths,
            manifest_root: self.manifest_root,
            tree_digest: self.tree_digest,
            total_bytes: self.total_bytes,
        }
    }
}

/// Result of a verified reassembly commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaReassemblyCommitReceipt {
    /// True only after destination mutation completed.
    pub committed: bool,
    /// Transfer-relative paths published to the destination.
    pub committed_paths: Vec<String>,
    /// Verified CAS manifest root.
    pub manifest_root: [u8; 32],
    /// Verified whole-tree digest.
    pub tree_digest: [u8; 32],
    /// Logical bytes represented by the committed manifest.
    pub total_bytes: u64,
}

/// Prepare a receiver-side commit from local CAS chunks plus decoded delta chunks.
pub fn prepare_delta_reassembly_commit<I>(
    target_manifest: &CasMerkleManifest,
    receiver_cas: &ContentAddressedChunkStore,
    decoded_chunks: I,
    expectation: DeltaReassemblyExpectation,
) -> Result<DeltaReassemblyCommit, ChunkingProfileError>
where
    I: IntoIterator<Item = DeltaChunkPayload>,
{
    if target_manifest.root() != expectation.manifest_root {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "delta reassembly manifest root does not match source commitment".to_string(),
        ));
    }

    let decoded = decoded_chunk_map(decoded_chunks)?;
    let mut files = BTreeMap::<String, ReassemblyFileBuilder>::new();
    let mut rebuilt_chunks = Vec::with_capacity(target_manifest.entries().len());

    for entry in target_manifest.entries() {
        let bytes = resolve_manifest_chunk(entry.address, receiver_cas, &decoded)?;
        let observed = ChunkAddress::from_bytes(&bytes);
        if observed != entry.address {
            return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                "delta reassembly chunk hash/size mismatch for {} at offset {}",
                entry.rel_path, entry.byte_offset
            )));
        }

        let file = files.entry(entry.rel_path.clone()).or_default();
        if file.next_offset != entry.byte_offset {
            return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                "delta reassembly non-contiguous chunk for {}: expected offset {}, observed {}",
                entry.rel_path, file.next_offset, entry.byte_offset
            )));
        }
        file.next_offset = file
            .next_offset
            .checked_add(entry.address.size_bytes)
            .ok_or_else(|| {
                ChunkingProfileError::InvalidChunkParameters(
                    "delta reassembly file length overflow".to_string(),
                )
            })?;
        file.bytes.extend_from_slice(&bytes);
        rebuilt_chunks.push(CasManifestChunk {
            rel_path: entry.rel_path.clone(),
            byte_offset: entry.byte_offset,
            address: observed,
        });
    }

    let rebuilt_manifest =
        CasMerkleManifest::from_chunks(target_manifest.tree_id().to_string(), rebuilt_chunks)?;
    if rebuilt_manifest.root() != target_manifest.root()
        || rebuilt_manifest.total_bytes() != target_manifest.total_bytes()
    {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "delta reassembly Merkle manifest mismatch".to_string(),
        ));
    }

    let staged_files: BTreeMap<String, Vec<u8>> = files
        .into_iter()
        .map(|(path, builder)| (path, builder.bytes))
        .collect();
    let tree_digest = delta_tree_digest(&staged_files);
    if tree_digest != expectation.tree_digest {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "delta reassembly whole-tree digest mismatch".to_string(),
        ));
    }

    let files = staged_files
        .into_iter()
        .map(|(rel_path, bytes)| DeltaReassembledFile {
            content_hash: sha256(&bytes),
            rel_path,
            bytes,
        })
        .collect();

    Ok(DeltaReassemblyCommit {
        files,
        manifest_root: rebuilt_manifest.root(),
        tree_digest,
        total_bytes: rebuilt_manifest.total_bytes(),
    })
}

/// Verify and publish a delta reassembly commit without mutating on failure.
pub fn verify_and_commit_delta_reassembly<I>(
    target_manifest: &CasMerkleManifest,
    receiver_cas: &ContentAddressedChunkStore,
    decoded_chunks: I,
    expectation: DeltaReassemblyExpectation,
    destination: &mut BTreeMap<String, Vec<u8>>,
) -> Result<DeltaReassemblyCommitReceipt, ChunkingProfileError>
where
    I: IntoIterator<Item = DeltaChunkPayload>,
{
    let commit = prepare_delta_reassembly_commit(
        target_manifest,
        receiver_cas,
        decoded_chunks,
        expectation,
    )?;
    Ok(commit.commit_into(destination))
}

/// Deterministic whole-tree digest over committed file names and file hashes.
#[must_use]
pub fn delta_tree_digest(files: &BTreeMap<String, Vec<u8>>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REASSEMBLY_TREE_DOMAIN);
    hasher.update((files.len() as u64).to_be_bytes());
    for (path, bytes) in files {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(sha256(bytes));
    }
    hasher.finalize().into()
}

#[derive(Debug, Clone, Default)]
struct ReassemblyFileBuilder {
    next_offset: u64,
    bytes: Vec<u8>,
}

fn decoded_chunk_map<I>(
    decoded_chunks: I,
) -> Result<BTreeMap<ChunkFingerprint, Vec<u8>>, ChunkingProfileError>
where
    I: IntoIterator<Item = DeltaChunkPayload>,
{
    let mut decoded = BTreeMap::new();
    for chunk in decoded_chunks {
        if sha256(&chunk.bytes) != *chunk.fingerprint.as_bytes() {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "decoded delta chunk bytes do not match fingerprint".to_string(),
            ));
        }
        if let Some(previous) = decoded.get(&chunk.fingerprint) {
            if previous != &chunk.bytes {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "decoded delta chunk has conflicting duplicate bytes".to_string(),
                ));
            }
        } else {
            decoded.insert(chunk.fingerprint, chunk.bytes);
        }
    }
    Ok(decoded)
}

fn resolve_manifest_chunk(
    address: ChunkAddress,
    receiver_cas: &ContentAddressedChunkStore,
    decoded: &BTreeMap<ChunkFingerprint, Vec<u8>>,
) -> Result<Vec<u8>, ChunkingProfileError> {
    if let Some(bytes) = receiver_cas.get(&address) {
        return Ok(bytes.to_vec());
    }
    decoded
        .get(&ChunkFingerprint::new(address.content_hash))
        .cloned()
        .ok_or_else(|| {
            ChunkingProfileError::InvalidChunkParameters(
                "delta reassembly missing chunk in CAS and decoded stream".to_string(),
            )
        })
}

fn finalize_object(
    payload: Vec<u8>,
    chunk_fingerprints: Vec<ChunkFingerprint>,
    config: &DeltaRaptorQConfig,
) -> Result<DeltaRaptorQObject, ChunkingProfileError> {
    let object_id = ObjectId::content(ContentId::from_bytes(&payload));
    let symbol_size = usize::try_from(config.symbol_size).map_err(|_| {
        ChunkingProfileError::InvalidChunkParameters(
            "delta RaptorQ symbol_size exceeds usize::MAX".to_string(),
        )
    })?;
    let source_symbol_count = payload.len().div_ceil(symbol_size).max(1);
    let source_symbol_count_u32 = u32::try_from(source_symbol_count).map_err(|_| {
        ChunkingProfileError::InvalidChunkParameters(
            "delta RaptorQ source symbol count exceeds u32::MAX".to_string(),
        )
    })?;
    let group_id = RepairGroupId::new(&object_id, 0, source_symbol_count_u32);
    let mut source_symbols = Vec::with_capacity(source_symbol_count);

    for index in 0..source_symbol_count {
        let start = index * symbol_size;
        let end = (start + symbol_size).min(payload.len());
        let mut symbol_payload = vec![0u8; symbol_size];
        if start < payload.len() {
            symbol_payload[..end - start].copy_from_slice(&payload[start..end]);
        }
        let index_u32 = u32::try_from(index).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "delta RaptorQ symbol index exceeds u32::MAX".to_string(),
            )
        })?;

        source_symbols.push(DeltaRaptorQSymbol {
            descriptor: RaptorQSymbol {
                index: index_u32,
                esi: index_u32,
                size_bytes: config.symbol_size,
                content_hash: sha256(&symbol_payload),
                is_source: true,
                repair_group_id: Some(group_id.clone()),
                auth_tag: None,
            },
            payload: symbol_payload,
        });
    }

    Ok(DeltaRaptorQObject {
        object_id,
        chunk_fingerprints,
        payload_len: payload.len(),
        source_symbols,
        repair_symbol_budget: repair_symbol_budget(
            source_symbol_count_u32,
            config.repair_overhead_percent,
        ),
    })
}

fn repair_symbol_budget(source_symbols: u32, overhead_percent: u16) -> u32 {
    let numerator = u64::from(source_symbols) * u64::from(overhead_percent);
    numerator.div_ceil(100).try_into().unwrap_or(u32::MAX)
}

fn new_delta_object_payload() -> Vec<u8> {
    DELTA_OBJECT_DOMAIN.to_vec()
}

fn encode_chunk_record(
    fingerprint: ChunkFingerprint,
    bytes: &[u8],
) -> Result<Vec<u8>, ChunkingProfileError> {
    let len = u64::try_from(bytes.len()).map_err(|_| {
        ChunkingProfileError::InvalidChunkParameters(
            "delta chunk record length exceeds u64::MAX".to_string(),
        )
    })?;
    let mut record = Vec::with_capacity(CHUNK_RECORD_DOMAIN.len() + 32 + 8 + bytes.len());
    record.extend_from_slice(CHUNK_RECORD_DOMAIN);
    record.extend_from_slice(fingerprint.as_bytes());
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(bytes);
    Ok(record)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(bytes: &[u8]) -> DeltaChunkPayload {
        DeltaChunkPayload::from_bytes(bytes.to_vec())
    }

    fn cas_chunk(path: &str, offset: u64, bytes: &[u8]) -> CasManifestChunk {
        CasManifestChunk {
            rel_path: path.to_string(),
            byte_offset: offset,
            address: ChunkAddress::from_bytes(bytes),
        }
    }

    #[test]
    fn missing_chunks_pack_into_one_coalesced_delta_object() {
        let a = chunk(b"alpha");
        let b = chunk(b"beta");
        let extra = chunk(b"extra");
        let requested = BTreeSet::from([a.fingerprint, b.fingerprint]);

        let plan = plan_delta_raptorq_stream(
            &requested,
            [extra, b.clone(), a.clone()],
            &DeltaRaptorQConfig {
                symbol_size: 256,
                max_object_payload_bytes: 4096,
                repair_overhead_percent: 25,
            },
        )
        .expect("delta plan should build");

        assert_eq!(plan.objects.len(), 1);
        let expected_order = requested.iter().copied().collect::<Vec<_>>();
        assert_eq!(plan.objects[0].chunk_fingerprints, expected_order);
        assert_eq!(
            plan.total_delta_payload_bytes(),
            plan.objects[0].payload_len
        );
        assert_eq!(plan.total_source_symbols(), 1);
        assert_eq!(plan.total_repair_symbol_budget(), 1);
        assert!(plan.objects[0].source_symbols[0].descriptor.is_source);
    }

    #[test]
    fn absent_requested_chunk_fails_closed() {
        let a = chunk(b"alpha");
        let missing = chunk(b"missing");
        let requested = BTreeSet::from([a.fingerprint, missing.fingerprint]);

        let result = plan_delta_raptorq_stream(&requested, [a], &DeltaRaptorQConfig::default());

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("not available")
        ));
    }

    #[test]
    fn cdc_payload_constructor_rejects_hash_mismatch() {
        let chunk = CdcChunkData {
            byte_offset: 0,
            size_bytes: 5,
            content_hash: sha256(b"alpha"),
        };

        let result = DeltaChunkPayload::from_cdc_chunk(&chunk, b"bravo".to_vec());

        assert!(matches!(
            result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("hash mismatch")
        ));
    }

    #[test]
    fn decoded_delta_object_payload_round_trips_and_rejects_corruption() {
        let a = chunk(b"alpha");
        let b = chunk(b"beta");
        let requested = BTreeSet::from([a.fingerprint, b.fingerprint]);
        let plan = plan_delta_raptorq_stream(
            &requested,
            [a.clone(), b.clone()],
            &DeltaRaptorQConfig {
                symbol_size: 256,
                max_object_payload_bytes: 4096,
                repair_overhead_percent: 20,
            },
        )
        .expect("delta plan");
        let object = &plan.objects[0];
        let mut payload = Vec::new();
        for symbol in &object.source_symbols {
            payload.extend_from_slice(&symbol.payload);
        }
        payload.truncate(object.payload_len);

        let decoded = decode_delta_object_payload(&payload).expect("decoded payload");
        let decoded_fingerprints = decoded
            .iter()
            .map(|chunk| chunk.fingerprint)
            .collect::<BTreeSet<_>>();
        assert_eq!(decoded_fingerprints, requested);

        let last = payload.last_mut().expect("payload byte");
        *last ^= 0xff;
        assert!(matches!(
            decode_delta_object_payload(&payload),
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("hash mismatch")
        ));
    }

    #[test]
    fn reassembly_commits_cas_and_decoded_chunks_after_full_verification() {
        let expected_files = BTreeMap::from([
            ("a.txt".to_string(), b"alpha-bravo".to_vec()),
            ("b.txt".to_string(), b"charlie".to_vec()),
        ]);
        let manifest = CasMerkleManifest::from_chunks(
            "tree",
            [
                cas_chunk("a.txt", 0, b"alpha-"),
                cas_chunk("a.txt", 6, b"bravo"),
                cas_chunk("b.txt", 0, b"charlie"),
            ],
        )
        .expect("manifest");
        let expectation =
            DeltaReassemblyExpectation::from_manifest_and_files(&manifest, &expected_files);
        let mut cas = ContentAddressedChunkStore::new();
        cas.insert_chunk(b"alpha-", None).expect("cas alpha");
        cas.insert_chunk(b"charlie", None).expect("cas charlie");
        let mut destination = BTreeMap::from([("a.txt".to_string(), b"old".to_vec())]);

        let receipt = verify_and_commit_delta_reassembly(
            &manifest,
            &cas,
            [DeltaChunkPayload::from_bytes(b"bravo".to_vec())],
            expectation,
            &mut destination,
        )
        .expect("verified commit");

        assert!(receipt.committed);
        assert_eq!(receipt.manifest_root, manifest.root());
        assert_eq!(destination, expected_files);
    }

    #[test]
    fn reassembly_fails_closed_without_mutating_destination() {
        let expected_files = BTreeMap::from([("a.txt".to_string(), b"alpha".to_vec())]);
        let manifest = CasMerkleManifest::from_chunks("tree", [cas_chunk("a.txt", 0, b"alpha")])
            .expect("manifest");
        let expectation =
            DeltaReassemblyExpectation::from_manifest_and_files(&manifest, &expected_files);
        let cas = ContentAddressedChunkStore::new();
        let mut destination = BTreeMap::from([("a.txt".to_string(), b"old".to_vec())]);

        let missing = verify_and_commit_delta_reassembly(
            &manifest,
            &cas,
            Vec::new(),
            expectation,
            &mut destination,
        );
        assert!(matches!(
            missing,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("missing chunk")
        ));
        assert_eq!(destination["a.txt"], b"old".to_vec());

        let corrupt = DeltaChunkPayload {
            fingerprint: ChunkFingerprint::new(sha256(b"alpha")),
            bytes: b"bravo".to_vec(),
        };
        let corrupt_result = verify_and_commit_delta_reassembly(
            &manifest,
            &cas,
            [corrupt],
            expectation,
            &mut destination,
        );
        assert!(matches!(
            corrupt_result,
            Err(ChunkingProfileError::InvalidChunkParameters(message))
                if message.contains("do not match fingerprint")
        ));
        assert_eq!(destination["a.txt"], b"old".to_vec());
    }
}
