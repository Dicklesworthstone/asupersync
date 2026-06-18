//! Delta chunk packing for RaptorQ-backed ATP transfers.
//!
//! B-8.3 reconciles chunk-id sets. This module takes the receiver-missing set,
//! verifies that every requested chunk is present and hash-correct, then packs
//! those chunks into deterministic source objects that the RaptorQ transport
//! can spray as loss-tolerant symbols.

use super::ChunkingProfileError;
use super::dedupe::CdcChunkData;
use super::reconcile::ChunkFingerprint;
use crate::atp::manifest::{RaptorQSymbol, RepairGroupId};
use crate::atp::object::{ContentId, ObjectId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DELTA_OBJECT_DOMAIN: &[u8] = b"asupersync::atp::delta-chunks::object::v1\0";
const CHUNK_RECORD_DOMAIN: &[u8] = b"asupersync::atp::delta-chunks::record::v1\0";

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
}
