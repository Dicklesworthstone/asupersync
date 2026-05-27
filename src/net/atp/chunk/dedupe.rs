//! Content-defined chunking and deduplication for ATP-C6.
//!
//! This module implements content-defined chunking (CDC) algorithms and deduplication
//! infrastructure for efficient cross-transfer chunk reuse. Provides rolling hash
//! boundary detection, chunk identity management, and secure cache lookup that doesn't
//! leak unauthorized object graph membership.

use super::ChunkingProfileError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

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

/// Content-defined chunking engine with rolling hash boundary detection.
pub struct CdcEngine;

impl CdcEngine {
    /// Create a new CDC engine.
    pub fn new() -> Self {
        Self
    }

    /// Compute content-defined chunk boundaries using rolling hash.
    pub fn compute_cdc_boundaries(
        &mut self,
        data: &[u8],
        params: &CdcParameters,
    ) -> Result<Vec<CdcChunkData>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut chunks = Vec::new();
        let mut rolling_hash = RollingHash::new(params.window_size);
        let mut last_boundary = 0u64;

        // Use normalization constant to compute boundary mask
        let mask_bits = Self::compute_mask_bits_from_constant(params.normalization_constant);
        let boundary_mask = (1u64 << mask_bits) - 1;

        // Initialize rolling hash with first window
        let initial_window = data.len().min(params.window_size);
        for &byte in &data[..initial_window] {
            rolling_hash.update(byte);
        }

        // Scan for boundaries
        for (i, &byte) in data.iter().enumerate().skip(params.window_size) {
            // Update rolling hash
            let old_byte = data[i - params.window_size];
            rolling_hash.roll(old_byte, byte);

            let current_pos = i as u64 + 1;
            let chunk_size = current_pos - last_boundary;

            // Check for boundary conditions
            let hash_boundary = (rolling_hash.hash() & boundary_mask) == 0;
            let min_size_reached = chunk_size >= params.min_chunk_size;
            let max_size_reached = chunk_size >= params.max_chunk_size;

            if (hash_boundary && min_size_reached) || max_size_reached {
                // Create chunk data for the completed chunk
                let chunk_data = &data[last_boundary as usize..current_pos as usize];
                let content_hash = Self::compute_content_hash(chunk_data);

                chunks.push(CdcChunkData {
                    byte_offset: last_boundary,
                    size_bytes: current_pos - last_boundary,
                    content_hash,
                });

                last_boundary = current_pos;
            }
        }

        // Add final chunk if needed
        if last_boundary < data.len() as u64 {
            let chunk_data = &data[last_boundary as usize..];
            let content_hash = Self::compute_content_hash(chunk_data);

            chunks.push(CdcChunkData {
                byte_offset: last_boundary,
                size_bytes: data.len() as u64 - last_boundary,
                content_hash,
            });
        }

        Ok(chunks)
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

    /// Compute SHA-256 hash of chunk data.
    fn compute_content_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Rolling hash for content-defined chunking.
pub struct RollingHash {
    window_size: usize,
    window: Vec<u8>,
    position: usize,
    hash_a: u64,
    hash_b: u64,
}

impl RollingHash {
    /// Create new rolling hash with given window size.
    pub fn new(window_size: usize) -> Self {
        let window_size = std::cmp::max(1, window_size);
        Self {
            window_size,
            window: vec![0; window_size],
            position: 0,
            hash_a: 0,
            hash_b: 0,
        }
    }

    /// Add byte to rolling hash (for initial window).
    pub fn update(&mut self, byte: u8) {
        if self.position < self.window_size {
            self.window[self.position] = byte; // ubs:ignore
            self.hash_a = self.hash_a.wrapping_add(byte as u64);
            self.hash_b = self.hash_b.wrapping_add(self.hash_a);
            self.position += 1;
        }
    }

    /// Roll the hash by removing old_byte and adding new_byte.
    pub fn roll(&mut self, old_byte: u8, new_byte: u8) {
        // Update hash values using Adler-style rolling hash
        self.hash_a = self
            .hash_a
            .wrapping_sub(old_byte as u64)
            .wrapping_add(new_byte as u64);
        self.hash_b = self
            .hash_b
            .wrapping_sub((self.window_size as u64).wrapping_mul(old_byte as u64))
            .wrapping_add(self.hash_a);

        // Update window
        let idx = self.position % self.window_size;
        self.window[idx] = new_byte; // ubs:ignore
        self.position += 1;
    }

    /// Get current hash value.
    pub fn hash(&self) -> u64 {
        (self.hash_b << 32) | (self.hash_a & 0xFFFFFFFF)
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

/// Cross-transfer chunk reuse manager.
pub struct ChunkReuseManager {
    /// Chunk cache.
    cache: ChunkCache,
    /// Registered transfer chunks.
    transfer_chunks: BTreeMap<String, Vec<ChunkIdentity>>,
    /// Reuse statistics per transfer.
    transfer_stats: BTreeMap<String, TransferReuseStats>,
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
        Self {
            cache: ChunkCache::new(100 * 1024 * 1024), // 100MB default cache
            transfer_chunks: BTreeMap::new(),
            transfer_stats: BTreeMap::new(),
        }
    }

    /// Register a chunk for a transfer.
    pub fn register_transfer_chunk(
        &mut self,
        transfer_id: &str,
        identity: &ChunkIdentity,
    ) -> Result<(), ChunkingProfileError> {
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
        _criteria: &ChunkReuseCriteria,
    ) -> Vec<ChunkIdentity> {
        let mut reusable = Vec::new();

        let requesting_scope = self
            .capability_scope_for_transfer(transfer_id)
            .unwrap_or_default();

        for &hash in content_hashes {
            let similar = self.cache.find_similar_chunks(hash);
            for chunk in similar {
                if self.cache.can_reuse_chunk(chunk, &requesting_scope) {
                    reusable.push(chunk.clone());
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
}
