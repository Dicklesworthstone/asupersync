//! Content-defined chunking and deduplication for ATP-C6.
//!
//! This module implements content-defined chunking (CDC) algorithms and deduplication
//! infrastructure for efficient cross-transfer chunk reuse. Provides rolling hash
//! boundary detection, chunk identity management, and secure cache lookup that doesn't
//! leak unauthorized object graph membership.

use super::ChunkingProfileError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// Parameters for content-defined chunking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdcParameters {
    pub window_size: usize,
    pub min_chunk_size: u64,
    pub max_chunk_size: u64,
    pub normalization_constant: u64,
}

/// Criteria for chunk reuse in deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkReuseCriteria {
    pub max_age_seconds: u64,
    pub min_proof_strength: crate::atp::manifest::ProofStrength,
    pub require_same_algorithm: bool,
}

/// Verification data for chunk integrity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkVerification {
    pub algorithm: String,
    pub proof_strength: crate::atp::manifest::ProofStrength,
}

/// Chunk data result from CDC boundary computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdcChunkData {
    pub byte_offset: u64,
    pub size_bytes: u64,
    pub content_hash: [u8; 32],
}

/// Conservative lower bound for incremental re-sync bytes-on-wire.
#[derive(Debug, Clone, PartialEq)]
pub struct DeltaFloorEstimate {
    pub receiver_unique_chunk_count: usize,
    pub sender_unique_chunk_count: usize,
    pub shared_chunk_count: usize,
    pub sender_missing_chunk_count: usize,
    pub receiver_stale_chunk_count: usize,
    pub sender_missing_bytes: u64,
    pub receiver_stale_bytes: u64,
    pub symmetric_difference_bytes: u64,
    pub estimated_floor_bytes_on_wire: u64,
    pub observed_gap_to_floor: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ChunkSetKey {
    content_hash: [u8; 32],
    size_bytes: u64,
}

impl From<&CdcChunkData> for ChunkSetKey {
    fn from(chunk: &CdcChunkData) -> Self {
        Self {
            content_hash: chunk.content_hash,
            size_bytes: chunk.size_bytes,
        }
    }
}

/// Content-defined chunking engine with rolling hash boundary detection.
pub struct CdcEngine;

impl CdcEngine {
    /// Create a new CDC engine.
    pub fn new() -> Self {
        Self
    }

    /// Compute content-defined chunk boundaries using FastCDC-style gear hash.
    pub fn compute_cdc_boundaries(
        &mut self,
        data: &[u8],
        params: &CdcParameters,
    ) -> Result<Vec<CdcChunkData>, ChunkingProfileError> {
        Self::validate_params(params)?;

        if data.is_empty() {
            return Ok(Vec::new());
        }

        let data_len = Self::usize_to_u64(data.len(), "CDC input length")?;
        let mut chunks = Vec::new();
        let mut rolling_hash = RollingHash::new(params.window_size);
        let mut last_boundary = 0u64;

        // FastCDC uses a stricter mask before the target size and a looser mask
        // after it, which keeps average chunks near the requested range without
        // forcing every chunk to the maximum size.
        let mask_bits = Self::compute_mask_bits_from_constant(params.normalization_constant);
        let normal_mask = Self::boundary_mask(mask_bits);
        let small_mask = Self::boundary_mask(mask_bits.saturating_add(1).min(63));
        let large_mask = Self::boundary_mask(mask_bits.saturating_sub(1).max(1));
        let target_chunk_size =
            params.min_chunk_size + (params.max_chunk_size - params.min_chunk_size) / 2;

        for (i, &byte) in data.iter().enumerate() {
            rolling_hash.update(byte);

            let current_pos = Self::usize_to_u64(i, "CDC boundary index")?
                .checked_add(1)
                .ok_or_else(|| {
                    ChunkingProfileError::InvalidChunkParameters(format!(
                        "CDC boundary position overflow at index {i}"
                    ))
                })?;
            let chunk_size = current_pos - last_boundary;

            if Self::should_cut_chunk(
                data,
                i + 1,
                chunk_size,
                rolling_hash.hash(),
                params,
                target_chunk_size,
                small_mask,
                normal_mask,
                large_mask,
            ) {
                Self::push_chunk(&mut chunks, data, last_boundary, current_pos)?;
                last_boundary = current_pos;
                rolling_hash.reset();
            }
        }

        // Add final chunk if needed
        if last_boundary < data_len {
            let final_size = data_len - last_boundary;
            if final_size < params.min_chunk_size && !chunks.is_empty() {
                let previous_start = chunks.last().map_or(0, |chunk| chunk.byte_offset);
                if data_len - previous_start <= params.max_chunk_size {
                    chunks.pop();
                    last_boundary = previous_start;
                }
            }
            Self::push_chunk(&mut chunks, data, last_boundary, data_len)?;
        }

        Ok(chunks)
    }

    /// Estimate the absolute information floor for a re-sync where the receiver
    /// already has `receiver_existing` chunks and the sender wants
    /// `sender_target`. The floor is the unique target chunk bytes absent from
    /// the receiver's content-addressed set; any real protocol can only exceed
    /// it with manifest/reconciliation/FEC/auth overhead.
    pub fn estimate_delta_floor(
        receiver_existing: &[CdcChunkData],
        sender_target: &[CdcChunkData],
        observed_bytes_on_wire: Option<u64>,
    ) -> DeltaFloorEstimate {
        let receiver_set: BTreeSet<ChunkSetKey> =
            receiver_existing.iter().map(ChunkSetKey::from).collect();
        let sender_set: BTreeSet<ChunkSetKey> =
            sender_target.iter().map(ChunkSetKey::from).collect();

        let shared_chunk_count = sender_set.intersection(&receiver_set).count();
        let sender_missing_chunk_count = sender_set.difference(&receiver_set).count();
        let receiver_stale_chunk_count = receiver_set.difference(&sender_set).count();
        let sender_missing_bytes = sender_set
            .difference(&receiver_set)
            .fold(0u64, |sum, chunk| sum.saturating_add(chunk.size_bytes));
        let receiver_stale_bytes = receiver_set
            .difference(&sender_set)
            .fold(0u64, |sum, chunk| sum.saturating_add(chunk.size_bytes));
        let symmetric_difference_bytes = sender_missing_bytes.saturating_add(receiver_stale_bytes);
        let observed_gap_to_floor = observed_bytes_on_wire.and_then(|observed| {
            if sender_missing_bytes == 0 {
                None
            } else {
                Some(observed as f64 / sender_missing_bytes as f64)
            }
        });

        DeltaFloorEstimate {
            receiver_unique_chunk_count: receiver_set.len(),
            sender_unique_chunk_count: sender_set.len(),
            shared_chunk_count,
            sender_missing_chunk_count,
            receiver_stale_chunk_count,
            sender_missing_bytes,
            receiver_stale_bytes,
            symmetric_difference_bytes,
            estimated_floor_bytes_on_wire: sender_missing_bytes,
            observed_gap_to_floor,
        }
    }

    fn validate_params(params: &CdcParameters) -> Result<(), ChunkingProfileError> {
        if params.window_size == 0 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "CDC window size must be greater than zero".to_string(),
            ));
        }
        if params.min_chunk_size == 0 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "CDC min chunk size must be greater than zero".to_string(),
            ));
        }
        if params.max_chunk_size < params.min_chunk_size {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "CDC max chunk size must be greater than or equal to min chunk size".to_string(),
            ));
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn should_cut_chunk(
        data: &[u8],
        current_pos: usize,
        chunk_size: u64,
        hash: u64,
        params: &CdcParameters,
        target_chunk_size: u64,
        small_mask: u64,
        normal_mask: u64,
        large_mask: u64,
    ) -> bool {
        if chunk_size < params.min_chunk_size {
            return false;
        }
        if chunk_size >= params.max_chunk_size {
            return true;
        }
        if Self::is_structural_boundary(data, current_pos) {
            return true;
        }

        let mask = match chunk_size.cmp(&target_chunk_size) {
            std::cmp::Ordering::Less => small_mask,
            std::cmp::Ordering::Equal => normal_mask,
            std::cmp::Ordering::Greater => large_mask,
        };

        (hash & mask) == 0
    }

    fn is_structural_boundary(data: &[u8], current_pos: usize) -> bool {
        current_pos > 0
            && current_pos <= data.len()
            && matches!(data[current_pos - 1], b'\n' | b'\r')
    }

    /// Compute mask bits from normalization constant.
    fn compute_mask_bits_from_constant(constant: u64) -> u32 {
        // Use hash-based mapping to ensure deterministic chunking
        // Each unique constant maps to a unique mask bit value
        let mut hasher = Sha256::new();
        hasher.update(constant.to_be_bytes());
        let hash = hasher.finalize();

        // Extract first 4 bytes as u32 and map to range 8-23
        let hash_u32 = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
        let bits = (hash_u32 % 16) + 8; // Range: 8-23 bits (256B to 8MB average)
        bits
    }

    fn boundary_mask(bits: u32) -> u64 {
        if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }

    fn push_chunk(
        chunks: &mut Vec<CdcChunkData>,
        data: &[u8],
        start: u64,
        end: u64,
    ) -> Result<(), ChunkingProfileError> {
        let start_index = Self::u64_to_usize(start, "CDC chunk start")?;
        let end_index = Self::u64_to_usize(end, "CDC chunk end")?;
        let chunk_data = &data[start_index..end_index];
        let content_hash = Self::compute_content_hash(chunk_data);

        chunks.push(CdcChunkData {
            byte_offset: start,
            size_bytes: end - start,
            content_hash,
        });

        Ok(())
    }

    fn usize_to_u64(value: usize, label: &str) -> Result<u64, ChunkingProfileError> {
        u64::try_from(value).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(format!(
                "{label} {value} exceeds u64::MAX"
            ))
        })
    }

    fn u64_to_usize(value: u64, label: &str) -> Result<usize, ChunkingProfileError> {
        usize::try_from(value).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(format!(
                "{label} {value} exceeds usize::MAX"
            ))
        })
    }

    /// Compute SHA-256 hash of chunk data.
    fn compute_content_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

const GEAR_TABLE: [u64; 256] = build_gear_table();

const fn build_gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut index = 0usize;
    while index < 256 {
        table[index] = splitmix64((index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        index += 1;
    }
    table
}

const fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

/// Gear hash for FastCDC content-defined chunking.
pub struct RollingHash {
    hash: u64,
}

impl RollingHash {
    /// Create new gear hash. The window size is retained in the API because
    /// callers provide it as part of the CDC profile, but FastCDC gear hashing
    /// advances one byte at a time and does not need to subtract an old byte.
    pub fn new(_window_size: usize) -> Self {
        Self { hash: 0 }
    }

    /// Add byte to the gear hash.
    pub fn update(&mut self, byte: u8) {
        self.hash = (self.hash << 1).wrapping_add(GEAR_TABLE[usize::from(byte)]);
    }

    /// Advance the gear hash. The old byte is intentionally ignored.
    pub fn roll(&mut self, _old_byte: u8, new_byte: u8) {
        self.update(new_byte);
    }

    /// Get current hash value.
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// Reset the gear hash at a chunk boundary.
    pub fn reset(&mut self) {
        self.hash = 0;
    }
}

/// Chunk identity for deduplication.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkIdentity {
    /// SHA-256 hash of chunk content.
    pub content_hash: [u8; 32],
    /// Chunk size in bytes.
    pub size_bytes: u64,
    /// Capability scope for authorized access.
    pub capability_scope: String,
    /// Chunk verification data.
    pub verification: ChunkVerification,
}

impl ChunkIdentity {
    /// Create chunk identity directly from data.
    pub fn from_data(
        data: &[u8],
        capability_scope: &str,
        proof_strength: crate::atp::manifest::ProofStrength,
    ) -> Self {
        let content_hash = Self::compute_content_hash(data);
        let size_bytes = data.len() as u64;
        Self {
            content_hash,
            size_bytes,
            capability_scope: capability_scope.to_string(),
            verification: ChunkVerification {
                algorithm: "sha256".to_string(),
                proof_strength,
            },
        }
    }

    /// Compute SHA-256 hash of data.
    fn compute_content_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Get identity string for deduplication keys.
    pub fn identity_string(&self) -> String {
        let hash_hex = hex_hash(&self.content_hash);
        format!("{}:{}:{}", hash_hex, self.size_bytes, self.capability_scope)
    }
}

/// Chunk cache for cross-transfer reuse.
pub struct ChunkCache {
    /// Mapping from chunk identity to cached chunk data.
    chunks: HashMap<ChunkIdentity, CachedChunk>,
    /// Index by content hash for fast lookup.
    content_hash_index: HashMap<[u8; 32], BTreeSet<ChunkIdentity>>,
    /// Current cache size in bytes.
    current_size: u64,
    /// Maximum cache size in bytes.
    max_size: u64,
    /// Cache hit count.
    cache_hits: u64,
    /// Cache miss count.
    cache_misses: u64,
}

/// Cached chunk data with metadata.
#[derive(Debug, Clone)]
pub struct CachedChunk {
    /// Chunk data.
    pub data: Vec<u8>,
    /// When this chunk was last accessed.
    pub last_accessed: std::time::SystemTime,
    /// How many times this chunk has been reused.
    pub reuse_count: u32,
    /// Original source object (for debugging/tracing).
    pub source_object: Option<String>,
}

impl ChunkCache {
    /// Create new chunk cache with size limit.
    pub fn new(max_size: u64) -> Self {
        Self {
            chunks: HashMap::new(),
            content_hash_index: HashMap::new(),
            current_size: 0,
            max_size,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Store chunk in cache.
    pub fn store_chunk(
        &mut self,
        identity: &ChunkIdentity,
        data: &[u8],
    ) -> Result<(), ChunkingProfileError> {
        let data_len = u64::try_from(data.len()).map_err(|_| {
            ChunkingProfileError::InvalidChunkParameters(
                "chunk data length exceeds supported size".to_string(),
            )
        })?;

        // Validate chunk data matches identity
        if data_len != identity.size_bytes {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "chunk data size doesn't match identity".to_string(),
            ));
        }
        if data_len > self.max_size {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "chunk data exceeds cache size limit".to_string(),
            ));
        }

        let computed_hash = ChunkIdentity::compute_content_hash(data);
        if computed_hash != identity.content_hash {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "chunk data hash doesn't match identity".to_string(),
            ));
        }

        // Replacement must not double-count the same identity.
        self.remove_chunk(identity);

        // Make space if needed
        let target_size = self.max_size.saturating_sub(data_len);
        while self.current_size > target_size && !self.chunks.is_empty() {
            self.evict_least_recently_used();
        }

        // Store chunk
        let cached_chunk = CachedChunk {
            data: data.to_vec(),
            last_accessed: std::time::SystemTime::now(),
            reuse_count: 0,
            source_object: None,
        };

        self.current_size += data_len;

        // Update content hash index
        self.content_hash_index
            .entry(identity.content_hash)
            .or_default()
            .insert(identity.clone());

        self.chunks.insert(identity.clone(), cached_chunk);

        Ok(())
    }

    /// Lookup chunk by identity.
    pub fn lookup_chunk(&mut self, identity: &ChunkIdentity) -> Option<Vec<u8>> {
        if let Some(chunk) = self.chunks.get_mut(identity) {
            chunk.last_accessed = std::time::SystemTime::now();
            chunk.reuse_count += 1;
            self.cache_hits += 1;
            Some(chunk.data.clone())
        } else {
            self.cache_misses += 1;
            None
        }
    }

    /// Retrieve chunk by identity.
    pub fn retrieve_chunk(
        &mut self,
        identity: &ChunkIdentity,
    ) -> Result<Option<Vec<u8>>, ChunkingProfileError> {
        Ok(self.lookup_chunk(identity))
    }

    /// Find chunks with same content hash but different context.
    pub fn find_similar_chunks(&self, content_hash: [u8; 32]) -> Vec<&ChunkIdentity> {
        self.content_hash_index
            .get(&content_hash)
            .map(|identities| identities.iter().collect())
            .unwrap_or_default()
    }

    /// Check if chunk can be reused given capability scope.
    pub fn can_reuse_chunk(&self, chunk_identity: &ChunkIdentity, requesting_scope: &str) -> bool {
        // Empty scopes are explicit globally reusable cache entries. Non-empty
        // scopes must match the requester's registered dedupe context.
        chunk_identity.capability_scope.is_empty()
            || chunk_identity.capability_scope == requesting_scope
    }

    fn meets_reuse_criteria(
        &self,
        chunk_identity: &ChunkIdentity,
        criteria: &ChunkReuseCriteria,
    ) -> bool {
        if chunk_identity.verification.proof_strength < criteria.min_proof_strength {
            return false;
        }

        if criteria.require_same_algorithm && chunk_identity.verification.algorithm != "sha256" {
            return false;
        }

        let Some(cached_chunk) = self.chunks.get(chunk_identity) else {
            return false;
        };

        let Ok(age) = std::time::SystemTime::now().duration_since(cached_chunk.last_accessed)
        else {
            return false;
        };

        age.as_secs() <= criteria.max_age_seconds
    }

    /// Evict least recently used chunk.
    fn evict_least_recently_used(&mut self) {
        let oldest_identity = self
            .chunks
            .iter()
            .min_by_key(|(_, chunk)| chunk.last_accessed)
            .map(|(identity, _)| identity.clone());

        if let Some(identity) = oldest_identity {
            self.remove_chunk(&identity);
        }
    }

    /// Remove chunk from cache.
    fn remove_chunk(&mut self, identity: &ChunkIdentity) {
        if self.chunks.remove(identity).is_some() {
            self.current_size = self.current_size.saturating_sub(identity.size_bytes);

            // Update content hash index
            if let Some(identities) = self.content_hash_index.get_mut(&identity.content_hash) {
                identities.remove(identity);
                if identities.is_empty() {
                    self.content_hash_index.remove(&identity.content_hash);
                }
            }
        }
    }

    /// Get cache statistics (alias for backward compatibility).
    pub fn stats(&self) -> ChunkCacheStats {
        self.get_statistics()
    }

    /// Get cache statistics.
    pub fn get_statistics(&self) -> ChunkCacheStats {
        let total_reuse_count: u32 = self.chunks.values().map(|c| c.reuse_count).sum();

        ChunkCacheStats {
            total_chunks: self.chunks.len(),
            current_size: self.current_size,
            max_size: self.max_size,
            total_reuse_count,
            utilization: if self.max_size == 0 {
                0.0
            } else {
                self.current_size as f64 / self.max_size as f64
            },
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
        }
    }
}

/// Chunk cache statistics.
#[derive(Debug, Clone)]
pub struct ChunkCacheStats {
    /// Total number of cached chunks.
    pub total_chunks: usize,
    /// Current cache size in bytes.
    pub current_size: u64,
    /// Maximum cache size in bytes.
    pub max_size: u64,
    /// Total number of chunk reuses.
    pub total_reuse_count: u32,
    /// Cache utilization (0.0 to 1.0).
    pub utilization: f64,
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of cache misses.
    pub cache_misses: u64,
}

/// br-asupersync-7tcipb item 4: default upper bound on the number of distinct
/// transfers whose per-transfer chunk/stat state [`ChunkReuseManager`] retains.
/// `transfer_chunks` / `transfer_stats` are keyed by `transfer_id`, which can be
/// attacker-influenced, so without a bound a peer that issues a flood of unique
/// transfer ids would grow these maps without limit (memory DoS). The cache
/// itself is already LRU-capped; this bounds the per-transfer key space.
const DEFAULT_MAX_TRACKED_TRANSFERS: usize = 4096;

/// Cross-transfer chunk reuse manager.
pub struct ChunkReuseManager {
    /// Chunk cache.
    cache: ChunkCache,
    /// Registered transfer chunks.
    transfer_chunks: BTreeMap<String, Vec<ChunkIdentity>>,
    /// Reuse statistics per transfer.
    transfer_stats: BTreeMap<String, TransferReuseStats>,
    /// br-asupersync-7tcipb item 4: FIFO insertion order of distinct tracked
    /// transfer ids (each id appears at most once). Drives oldest-first eviction
    /// once the tracked-transfer count would exceed `max_tracked_transfers`.
    transfer_order: VecDeque<String>,
    /// br-asupersync-7tcipb item 4: upper bound on distinct tracked transfers.
    max_tracked_transfers: usize,
}

/// Reuse statistics for a transfer.
#[derive(Debug, Clone)]
pub struct TransferReuseStats {
    pub total_chunks_reused: u64,
    pub bytes_saved: u64,
    pub deduplication_ratio: f64,
}

impl ChunkReuseManager {
    /// Create new chunk reuse manager.
    pub fn new() -> Self {
        Self::with_max_tracked_transfers(DEFAULT_MAX_TRACKED_TRANSFERS)
    }

    /// br-asupersync-7tcipb item 4: create a manager that retains per-transfer
    /// state for at most `max_tracked_transfers` distinct transfers. Once that
    /// bound would be exceeded, the oldest-registered transfer is evicted from
    /// both `transfer_chunks` and `transfer_stats` (FIFO), so a peer flooding
    /// the manager with unique transfer ids cannot grow them without bound.
    /// `max_tracked_transfers` is clamped to at least 1.
    #[must_use]
    pub fn with_max_tracked_transfers(max_tracked_transfers: usize) -> Self {
        Self {
            cache: ChunkCache::new(100 * 1024 * 1024), // 100MB default cache
            transfer_chunks: BTreeMap::new(),
            transfer_stats: BTreeMap::new(),
            transfer_order: VecDeque::new(),
            max_tracked_transfers: max_tracked_transfers.max(1),
        }
    }

    /// br-asupersync-7tcipb item 4: number of distinct transfers currently
    /// tracked, always `<= max_tracked_transfers`. Exposed for observability so
    /// operators can confirm the dedupe manager is not growing without bound.
    #[must_use]
    pub fn tracked_transfer_count(&self) -> usize {
        self.transfer_order.len()
    }

    /// br-asupersync-7tcipb item 4: record a (possibly new) transfer id in FIFO
    /// order, evicting the oldest transfer(s) from both per-transfer maps if
    /// tracking a new id would exceed `max_tracked_transfers`.
    ///
    /// MUST be called BEFORE inserting `transfer_id` into either map: "absent
    /// from both maps" is how a first-seen id is detected, which keeps each id
    /// enqueued exactly once and prevents an id present in only one map from
    /// being double-counted.
    fn note_transfer(&mut self, transfer_id: &str) {
        let already_tracked = self.transfer_chunks.contains_key(transfer_id)
            || self.transfer_stats.contains_key(transfer_id);
        if already_tracked {
            return;
        }
        while self.transfer_order.len() >= self.max_tracked_transfers {
            let Some(oldest) = self.transfer_order.pop_front() else {
                break;
            };
            self.transfer_chunks.remove(&oldest);
            self.transfer_stats.remove(&oldest);
        }
        self.transfer_order.push_back(transfer_id.to_string());
    }

    /// Register a chunk for a transfer.
    pub fn register_transfer_chunk(
        &mut self,
        transfer_id: &str,
        identity: &ChunkIdentity,
    ) -> Result<(), ChunkingProfileError> {
        // br-asupersync-7tcipb item 4: bound tracked transfers before inserting.
        self.note_transfer(transfer_id);
        self.transfer_chunks
            .entry(transfer_id.to_string())
            .or_default()
            .push(identity.clone());
        Ok(())
    }

    /// Lookup the dedupe capability scope for a transfer.
    fn capability_scope_for_transfer(&self, transfer_id: &str) -> Option<String> {
        let Some(identities) = self.transfer_chunks.get(transfer_id) else {
            return Some(transfer_scope(transfer_id));
        };

        let mut registered_scope = None;
        for identity in identities {
            if identity.capability_scope.is_empty() {
                continue;
            }

            match &registered_scope {
                Some(scope) if scope != &identity.capability_scope => return None,
                Some(_) => {}
                None => registered_scope = Some(identity.capability_scope.clone()),
            }
        }

        registered_scope.or_else(|| Some(String::new()))
    }

    /// Find reusable chunks for a transfer.
    pub fn find_reusable_chunks(
        &self,
        transfer_id: &str,
        content_hashes: &[[u8; 32]],
        criteria: &ChunkReuseCriteria,
    ) -> Vec<ChunkIdentity> {
        let mut reusable: Vec<ChunkIdentity> = Vec::new();
        let mut seen_requested_hashes = BTreeSet::new();
        let mut reusable_content_indices: BTreeMap<([u8; 32], u64), usize> = BTreeMap::new();

        let requesting_scope = self
            .capability_scope_for_transfer(transfer_id)
            .unwrap_or_default();

        for &hash in content_hashes {
            if !seen_requested_hashes.insert(hash) {
                continue;
            }

            let similar = self.cache.find_similar_chunks(hash);
            for chunk in similar {
                if self.cache.can_reuse_chunk(chunk, &requesting_scope)
                    && self.cache.meets_reuse_criteria(chunk, criteria)
                {
                    let content_key = (chunk.content_hash, chunk.size_bytes);
                    if let Some(&index) = reusable_content_indices.get(&content_key) {
                        if chunk.verification.proof_strength
                            > reusable[index].verification.proof_strength
                        {
                            reusable[index] = chunk.clone();
                        }
                    } else {
                        reusable_content_indices.insert(content_key, reusable.len());
                        reusable.push(chunk.clone());
                    }
                }
            }
        }

        reusable
    }

    /// Register chunk reuse for a transfer.
    pub fn register_chunk_reuse(
        &mut self,
        transfer_id: &str,
        identity: &ChunkIdentity,
        _source_transfer_id: &str,
    ) -> Result<(), ChunkingProfileError> {
        // br-asupersync-7tcipb item 4: bound tracked transfers before inserting.
        self.note_transfer(transfer_id);
        let stats = self
            .transfer_stats
            .entry(transfer_id.to_string())
            .or_insert_with(|| TransferReuseStats {
                total_chunks_reused: 0,
                bytes_saved: 0,
                deduplication_ratio: 0.0,
            });

        stats.total_chunks_reused += 1;
        stats.bytes_saved += identity.size_bytes;

        // Update deduplication ratio (simple approximation)
        stats.deduplication_ratio =
            stats.bytes_saved as f64 / (stats.bytes_saved as f64 + 1_000_000.0);

        Ok(())
    }

    /// Get reuse statistics for a transfer.
    pub fn get_reuse_statistics(&self, transfer_id: &str) -> Option<TransferReuseStats> {
        self.transfer_stats.get(transfer_id).cloned()
    }

    /// Store chunk for future reuse (kept for backward compatibility).
    pub fn store_chunk_for_reuse(
        &mut self,
        chunk_data: &[u8],
        transfer_id: &str,
    ) -> Result<ChunkIdentity, ChunkingProfileError> {
        let identity = ChunkIdentity::from_data(
            chunk_data,
            &transfer_scope(transfer_id),
            crate::atp::manifest::ProofStrength::Basic,
        );

        self.cache.store_chunk(&identity, chunk_data)?;
        self.register_transfer_chunk(transfer_id, &identity)?;

        Ok(identity)
    }
}

/// Convert hash to hex string.
fn hex_hash(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn transfer_scope(transfer_id: &str) -> String {
    format!("transfer-{transfer_id}")
}

#[cfg(test)]
mod active_tests {
    use super::*;
    use crate::atp::manifest::ProofStrength;

    fn criteria() -> ChunkReuseCriteria {
        ChunkReuseCriteria {
            max_age_seconds: 3600,
            min_proof_strength: ProofStrength::Basic,
            require_same_algorithm: true,
        }
    }

    fn fastcdc_params() -> CdcParameters {
        CdcParameters {
            window_size: 64,
            min_chunk_size: 512,
            max_chunk_size: 4096,
            normalization_constant: 0x1021,
        }
    }

    fn fastcdc_fixture(record_count: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for record_index in 0..record_count {
            data.extend_from_slice(format!("record-{record_index:04}:").as_bytes());
            for payload_index in 0..80 {
                data.push(b'a' + ((record_index + payload_index) % 26) as u8);
            }
            data.push(b'\n');
        }
        data
    }

    fn chunk_hash_set(chunks: &[CdcChunkData]) -> std::collections::BTreeSet<[u8; 32]> {
        chunks.iter().map(|chunk| chunk.content_hash).collect()
    }

    fn test_cdc_chunk(byte_offset: u64, data: &[u8]) -> CdcChunkData {
        CdcChunkData {
            byte_offset,
            size_bytes: data.len() as u64,
            content_hash: CdcEngine::compute_content_hash(data),
        }
    }

    #[test]
    fn gear_hash_matches_known_vector() {
        let mut hash = RollingHash::new(64);
        for &byte in b"asupersync-fastcdc" {
            hash.update(byte);
        }

        assert_eq!(hash.hash(), 0x5240_b854_273d_098e);
    }

    #[test]
    fn fastcdc_chunks_cover_input_byte_exactly() {
        let mut engine = CdcEngine::new();
        let params = fastcdc_params();
        let data = fastcdc_fixture(220);

        let chunks = engine.compute_cdc_boundaries(&data, &params).unwrap();

        assert!(!chunks.is_empty());
        let mut reconstructed = Vec::new();
        let mut expected_offset = 0u64;
        for chunk in &chunks {
            assert_eq!(chunk.byte_offset, expected_offset);
            assert!(chunk.size_bytes <= params.max_chunk_size);

            let start = usize::try_from(chunk.byte_offset).unwrap();
            let end = usize::try_from(chunk.byte_offset + chunk.size_bytes).unwrap();
            reconstructed.extend_from_slice(&data[start..end]);
            expected_offset += chunk.size_bytes;
        }

        assert_eq!(expected_offset, data.len() as u64);
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn fastcdc_resynchronizes_after_prefix_and_insert() {
        let mut engine = CdcEngine::new();
        let params = fastcdc_params();
        let original = fastcdc_fixture(420);

        let mut prefixed = b"new-header-line\n".to_vec();
        prefixed.extend_from_slice(&original);

        let insert_at = original.len() / 2;
        let mut inserted = original[..insert_at].to_vec();
        inserted.extend_from_slice(b"inserted-record:payload payload payload\n");
        inserted.extend_from_slice(&original[insert_at..]);

        let original_chunks = engine.compute_cdc_boundaries(&original, &params).unwrap();
        let prefixed_chunks = engine.compute_cdc_boundaries(&prefixed, &params).unwrap();
        let inserted_chunks = engine.compute_cdc_boundaries(&inserted, &params).unwrap();

        let original_hashes = chunk_hash_set(&original_chunks);
        let prefixed_hashes = chunk_hash_set(&prefixed_chunks);
        let inserted_hashes = chunk_hash_set(&inserted_chunks);
        let prefix_common = original_hashes.intersection(&prefixed_hashes).count();
        let insert_common = original_hashes.intersection(&inserted_hashes).count();

        assert!(prefix_common * 3 >= original_hashes.len() * 2);
        assert!(insert_common * 2 >= original_hashes.len());
    }

    #[test]
    fn delta_floor_zero_when_receiver_already_has_target_chunks() {
        let chunks = vec![
            test_cdc_chunk(0, b"alpha"),
            test_cdc_chunk(5, b"beta"),
            test_cdc_chunk(9, b"gamma"),
        ];

        let estimate = CdcEngine::estimate_delta_floor(&chunks, &chunks, Some(0));

        assert_eq!(estimate.receiver_unique_chunk_count, 3);
        assert_eq!(estimate.sender_unique_chunk_count, 3);
        assert_eq!(estimate.shared_chunk_count, 3);
        assert_eq!(estimate.sender_missing_chunk_count, 0);
        assert_eq!(estimate.estimated_floor_bytes_on_wire, 0);
        assert_eq!(estimate.observed_gap_to_floor, None);
    }

    #[test]
    fn delta_floor_counts_unique_missing_target_chunks_once() {
        let old_a = test_cdc_chunk(0, b"alpha");
        let old_b = test_cdc_chunk(5, b"beta");
        let new_c = test_cdc_chunk(5, b"carrot");
        let duplicate_new_c = test_cdc_chunk(11, b"carrot");

        let estimate = CdcEngine::estimate_delta_floor(
            &[old_a.clone(), old_b],
            &[old_a, new_c, duplicate_new_c],
            Some(18),
        );

        assert_eq!(estimate.shared_chunk_count, 1);
        assert_eq!(estimate.sender_missing_chunk_count, 1);
        assert_eq!(estimate.receiver_stale_chunk_count, 1);
        assert_eq!(estimate.sender_missing_bytes, 6);
        assert_eq!(estimate.receiver_stale_bytes, 4);
        assert_eq!(estimate.symmetric_difference_bytes, 10);
        assert_eq!(estimate.estimated_floor_bytes_on_wire, 6);
        assert_eq!(estimate.observed_gap_to_floor, Some(3.0));
    }

    #[test]
    fn same_transfer_reuses_own_scoped_chunk() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[identity.content_hash], &criteria());

        assert_eq!(reusable, vec![identity]);
    }

    #[test]
    fn different_transfer_cannot_reuse_private_scope() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-b", &[identity.content_hash], &criteria());

        assert!(reusable.is_empty());
    }

    #[test]
    fn conflicting_registered_scopes_fail_closed_to_global_only_reuse() {
        let mut manager = ChunkReuseManager::new();
        let private_a = ChunkIdentity::from_data(b"aaa", "scope-a", ProofStrength::Basic);
        let private_b = ChunkIdentity::from_data(b"bbb", "scope-b", ProofStrength::Basic);
        let global = ChunkIdentity::from_data(b"ccc", "", ProofStrength::Basic);

        manager
            .register_transfer_chunk("mixed", &private_a)
            .unwrap();
        manager
            .register_transfer_chunk("mixed", &private_b)
            .unwrap();
        manager.cache.store_chunk(&private_a, b"aaa").unwrap();
        manager.cache.store_chunk(&private_b, b"bbb").unwrap();
        manager.cache.store_chunk(&global, b"ccc").unwrap();

        let reusable = manager.find_reusable_chunks(
            "mixed",
            &[
                private_a.content_hash,
                private_b.content_hash,
                global.content_hash,
            ],
            &criteria(),
        );

        assert_eq!(reusable, vec![global]);
    }

    #[test]
    fn replacing_same_identity_does_not_inflate_cache_size() {
        let data = b"repeat";
        let identity = ChunkIdentity::from_data(data, "scope-a", ProofStrength::Basic);
        let mut cache = ChunkCache::new(1024);

        cache.store_chunk(&identity, data).unwrap();
        cache.store_chunk(&identity, data).unwrap();

        let stats = cache.get_statistics();
        assert_eq!(stats.total_chunks, 1);
        assert_eq!(stats.current_size, data.len() as u64);
    }

    #[test]
    fn oversized_chunk_is_rejected_without_cache_growth() {
        let data = b"too-large";
        let identity = ChunkIdentity::from_data(data, "scope-a", ProofStrength::Basic);
        let mut cache = ChunkCache::new(1);

        let err = cache.store_chunk(&identity, data).unwrap_err();

        assert!(matches!(
            err,
            ChunkingProfileError::InvalidChunkParameters(_)
        ));
        assert_eq!(cache.get_statistics().current_size, 0);
    }

    #[test]
    fn zero_sized_cache_reports_zero_utilization() {
        let cache = ChunkCache::new(0);

        assert_eq!(cache.get_statistics().utilization, 0.0);
    }

    #[test]
    fn reuse_criteria_rejects_low_proof_chunks() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();
        let strict_criteria = ChunkReuseCriteria {
            min_proof_strength: ProofStrength::Enhanced,
            ..criteria()
        };

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[identity.content_hash], &strict_criteria);

        assert!(reusable.is_empty());
    }

    #[test]
    fn reuse_criteria_rejects_stale_chunks() {
        let mut manager = ChunkReuseManager::new();
        let identity = manager
            .store_chunk_for_reuse(b"chunk-data", "transfer-a")
            .unwrap();
        manager
            .cache
            .chunks
            .get_mut(&identity)
            .unwrap()
            .last_accessed = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap();
        let stale_rejecting_criteria = ChunkReuseCriteria {
            max_age_seconds: 1,
            ..criteria()
        };

        let reusable = manager.find_reusable_chunks(
            "transfer-a",
            &[identity.content_hash],
            &stale_rejecting_criteria,
        );

        assert!(reusable.is_empty());
    }

    #[test]
    fn reuse_criteria_rejects_non_canonical_algorithm_when_required() {
        let mut manager = ChunkReuseManager::new();
        let mut identity =
            ChunkIdentity::from_data(b"chunk-data", "transfer-transfer-a", ProofStrength::Basic);
        identity.verification.algorithm = "custom-hash".to_string();
        manager.cache.store_chunk(&identity, b"chunk-data").unwrap();
        manager
            .register_transfer_chunk("transfer-a", &identity)
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[identity.content_hash], &criteria());

        assert!(reusable.is_empty());
    }

    #[test]
    fn same_content_in_multiple_authorized_scopes_returns_one_candidate() {
        let mut manager = ChunkReuseManager::new();
        let data = b"shared-content";
        let scoped =
            ChunkIdentity::from_data(data, "transfer-transfer-a", ProofStrength::Cryptographic);
        let global = ChunkIdentity::from_data(data, "", ProofStrength::Basic);

        manager.cache.store_chunk(&scoped, data).unwrap();
        manager.cache.store_chunk(&global, data).unwrap();
        manager
            .register_transfer_chunk("transfer-a", &scoped)
            .unwrap();

        let reusable =
            manager.find_reusable_chunks("transfer-a", &[scoped.content_hash], &criteria());

        assert_eq!(reusable.len(), 1);
        assert_eq!(reusable[0].content_hash, scoped.content_hash);
        assert_eq!(reusable[0].size_bytes, scoped.size_bytes);
        assert_eq!(
            reusable[0].verification.proof_strength,
            ProofStrength::Cryptographic
        );
    }
}
