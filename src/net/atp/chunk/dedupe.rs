//! Content-defined chunking and deduplication for ATP-C6.
//!
//! This module implements content-defined chunking (CDC) algorithms and deduplication
//! infrastructure for efficient cross-transfer chunk reuse. Provides rolling hash
//! boundary detection, chunk identity management, and secure cache lookup that doesn't
//! leak unauthorized object graph membership.

use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, ChunkMetadata};
use super::{ChunkingProfileError, profiles::ChunkingProfile};
use std::collections::{HashMap, BTreeMap, BTreeSet};
use sha2::{Digest, Sha256};

/// Content-defined chunking engine with rolling hash boundary detection.
pub struct CdcEngine;

impl CdcEngine {
    /// Compute content-defined chunk boundaries using rolling hash.
    pub fn compute_cdc_boundaries(
        data: &[u8],
        window_size: usize,
        target_chunk_size: u64,
        min_chunk_size: u64,
        max_chunk_size: u64,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut boundaries = Vec::new();
        let mut rolling_hash = RollingHash::new(window_size);
        let mut last_boundary = 0u64;

        // Compute boundary mask for target chunk size
        let mask_bits = Self::compute_mask_bits(target_chunk_size);
        let boundary_mask = (1u64 << mask_bits) - 1;

        // Initialize rolling hash with first window
        let initial_window = data.len().min(window_size);
        for &byte in &data[..initial_window] {
            rolling_hash.update(byte);
        }

        // Scan for boundaries
        for (i, &byte) in data.iter().enumerate().skip(window_size) {
            // Update rolling hash
            let old_byte = data[i - window_size];
            rolling_hash.roll(old_byte, byte);

            let current_pos = i as u64 + 1;
            let chunk_size = current_pos - last_boundary;

            // Check for boundary conditions
            let hash_boundary = (rolling_hash.hash() & boundary_mask) == 0;
            let min_size_reached = chunk_size >= min_chunk_size;
            let max_size_reached = chunk_size >= max_chunk_size;

            if (hash_boundary && min_size_reached) || max_size_reached {
                boundaries.push(current_pos);
                last_boundary = current_pos;
            }
        }

        // Add final boundary if needed
        if last_boundary < data.len() as u64 {
            boundaries.push(data.len() as u64);
        }

        Ok(boundaries)
    }

    /// Compute mask bits for target chunk size.
    fn compute_mask_bits(target_size: u64) -> u32 {
        // Use log2 of target size to determine mask bits
        let bits = (target_size as f64).log2() as u32;
        bits.max(8).min(20) // Reasonable range: 256B to 1MB average
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
            self.window[self.position] = byte;
            self.hash_a = self.hash_a.wrapping_add(byte as u64);
            self.hash_b = self.hash_b.wrapping_add(self.hash_a);
            self.position += 1;
        }
    }

    /// Roll the hash by removing old_byte and adding new_byte.
    pub fn roll(&mut self, old_byte: u8, new_byte: u8) {
        // Update hash values using Adler-style rolling hash
        self.hash_a = self.hash_a.wrapping_sub(old_byte as u64).wrapping_add(new_byte as u64);
        self.hash_b = self.hash_b.wrapping_sub(self.window_size as u64 * old_byte as u64).wrapping_add(self.hash_a);

        // Update window
        let idx = self.position % self.window_size;
        self.window[idx] = new_byte;
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
    pub size: u64,
    /// Chunking algorithm/profile that produced this chunk.
    pub chunking_profile: String,
    /// Optional context hash for capability scoping.
    pub context_hash: Option<[u8; 32]>,
}

impl ChunkIdentity {
    /// Create chunk identity from boundary and data.
    pub fn from_boundary_and_data(
        boundary: &ChunkBoundary,
        chunking_profile: &str,
        context_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            content_hash: boundary.content_hash,
            size: boundary.size_bytes,
            chunking_profile: chunking_profile.to_string(),
            context_hash,
        }
    }

    /// Create chunk identity directly from data.
    pub fn from_data(
        data: &[u8],
        chunking_profile: &str,
        context_hash: Option<[u8; 32]>,
    ) -> Self {
        let content_hash = Self::compute_content_hash(data);
        Self {
            content_hash,
            size: data.len() as u64,
            chunking_profile: chunking_profile.to_string(),
            context_hash,
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
        let hash_hex = hex::encode(self.content_hash);
        let context_hex = self.context_hash
            .map(|h| hex::encode(h))
            .unwrap_or_else(|| "none".to_string());
        format!("{}:{}:{}:{}", hash_hex, self.size, self.chunking_profile, context_hex)
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
        }
    }

    /// Store chunk in cache.
    pub fn store_chunk(&mut self, identity: ChunkIdentity, data: Vec<u8>, source_object: Option<String>) -> Result<(), ChunkingProfileError> {
        // Validate chunk data matches identity
        if data.len() != identity.size as usize {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "chunk data size doesn't match identity".to_string(),
            ));
        }

        let computed_hash = ChunkIdentity::compute_content_hash(&data);
        if computed_hash != identity.content_hash {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "chunk data hash doesn't match identity".to_string(),
            ));
        }

        // Make space if needed
        while self.current_size + data.len() as u64 > self.max_size && !self.chunks.is_empty() {
            self.evict_least_recently_used();
        }

        // Store chunk
        let cached_chunk = CachedChunk {
            data,
            last_accessed: std::time::SystemTime::now(),
            reuse_count: 0,
            source_object,
        };

        self.current_size += identity.size;

        // Update content hash index
        self.content_hash_index
            .entry(identity.content_hash)
            .or_default()
            .insert(identity.clone());

        self.chunks.insert(identity, cached_chunk);

        Ok(())
    }

    /// Lookup chunk by identity.
    pub fn lookup_chunk(&mut self, identity: &ChunkIdentity) -> Option<&Vec<u8>> {
        if let Some(chunk) = self.chunks.get_mut(identity) {
            chunk.last_accessed = std::time::SystemTime::now();
            chunk.reuse_count += 1;
            Some(&chunk.data)
        } else {
            None
        }
    }

    /// Find chunks with same content hash but different context.
    pub fn find_similar_chunks(&self, content_hash: [u8; 32]) -> Vec<&ChunkIdentity> {
        self.content_hash_index
            .get(&content_hash)
            .map(|identities| identities.iter().collect())
            .unwrap_or_default()
    }

    /// Check if chunk can be reused given capability scope.
    pub fn can_reuse_chunk(
        &self,
        chunk_identity: &ChunkIdentity,
        requesting_context: Option<[u8; 32]>,
    ) -> bool {
        // If chunk has no context hash, it's globally reusable
        if chunk_identity.context_hash.is_none() {
            return true;
        }

        // If requesting context matches chunk context, allow reuse
        chunk_identity.context_hash == requesting_context
    }

    /// Evict least recently used chunk.
    fn evict_least_recently_used(&mut self) {
        let oldest_identity = self.chunks
            .iter()
            .min_by_key(|(_, chunk)| chunk.last_accessed)
            .map(|(identity, _)| identity.clone());

        if let Some(identity) = oldest_identity {
            self.remove_chunk(&identity);
        }
    }

    /// Remove chunk from cache.
    fn remove_chunk(&mut self, identity: &ChunkIdentity) {
        if let Some(chunk) = self.chunks.remove(identity) {
            self.current_size = self.current_size.saturating_sub(identity.size);

            // Update content hash index
            if let Some(identities) = self.content_hash_index.get_mut(&identity.content_hash) {
                identities.remove(identity);
                if identities.is_empty() {
                    self.content_hash_index.remove(&identity.content_hash);
                }
            }
        }
    }

    /// Get cache statistics.
    pub fn stats(&self) -> ChunkCacheStats {
        let total_reuse_count: u32 = self.chunks.values().map(|c| c.reuse_count).sum();

        ChunkCacheStats {
            total_chunks: self.chunks.len(),
            current_size: self.current_size,
            max_size: self.max_size,
            total_reuse_count,
            utilization: self.current_size as f64 / self.max_size as f64,
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
}

/// Cross-transfer chunk reuse manager.
pub struct ChunkReuseManager {
    /// Chunk cache.
    cache: ChunkCache,
    /// Active deduplication contexts.
    active_contexts: BTreeMap<String, [u8; 32]>,
}

impl ChunkReuseManager {
    /// Create new chunk reuse manager.
    pub fn new(max_cache_size: u64) -> Self {
        Self {
            cache: ChunkCache::new(max_cache_size),
            active_contexts: BTreeMap::new(),
        }
    }

    /// Register deduplication context for a transfer.
    pub fn register_context(&mut self, transfer_id: &str, context_hash: [u8; 32]) {
        self.active_contexts.insert(transfer_id.to_string(), context_hash);
    }

    /// Unregister deduplication context.
    pub fn unregister_context(&mut self, transfer_id: &str) {
        self.active_contexts.remove(transfer_id);
    }

    /// Attempt to reuse chunk from cache.
    pub fn try_reuse_chunk(
        &mut self,
        chunk_identity: &ChunkIdentity,
        transfer_id: &str,
    ) -> Option<Vec<u8>> {
        let requesting_context = self.active_contexts.get(transfer_id).copied();

        // Check if chunk can be reused given capability scope
        if !self.cache.can_reuse_chunk(chunk_identity, requesting_context) {
            return None;
        }

        // Try direct lookup
        if let Some(data) = self.cache.lookup_chunk(chunk_identity) {
            return Some(data.clone());
        }

        // Try finding similar chunks with different context
        let similar_chunks = self.cache.find_similar_chunks(chunk_identity.content_hash);
        for similar_identity in similar_chunks {
            if self.cache.can_reuse_chunk(similar_identity, requesting_context) {
                if let Some(data) = self.cache.lookup_chunk(similar_identity) {
                    return Some(data.clone());
                }
            }
        }

        None
    }

    /// Store chunk for future reuse.
    pub fn store_chunk_for_reuse(
        &mut self,
        chunk_data: &[u8],
        chunking_profile: &str,
        transfer_id: &str,
        source_object: Option<String>,
    ) -> Result<ChunkIdentity, ChunkingProfileError> {
        let context_hash = self.active_contexts.get(transfer_id).copied();
        let identity = ChunkIdentity::from_data(chunk_data, chunking_profile, context_hash);

        self.cache.store_chunk(identity.clone(), chunk_data.to_vec(), source_object)?;

        Ok(identity)
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> ChunkCacheStats {
        self.cache.stats()
    }

    /// Validate cached chunk against manifest.
    pub fn validate_cached_chunk(
        &self,
        chunk_identity: &ChunkIdentity,
        expected_boundary: &ChunkBoundary,
    ) -> bool {
        // Check content hash matches
        if chunk_identity.content_hash != expected_boundary.content_hash {
            return false;
        }

        // Check size matches
        if chunk_identity.size != expected_boundary.size_bytes {
            return false;
        }

        // Additional validation could include checking chunk strategy compatibility
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_hash() {
        let mut hash = RollingHash::new(4);

        // Initialize with "abcd"
        for &byte in b"abcd" {
            hash.update(byte);
        }
        let initial_hash = hash.hash();

        // Roll to "bcde"
        hash.roll(b'a', b'e');
        let rolled_hash = hash.hash();

        // Should be different
        assert_ne!(initial_hash, rolled_hash);
    }

    #[test]
    fn test_cdc_boundaries() {
        let data = vec![0u8; 10000]; // 10KB of zeros
        let boundaries = CdcEngine::compute_cdc_boundaries(
            &data,
            32,    // window_size
            1024,  // target_chunk_size
            512,   // min_chunk_size
            2048,  // max_chunk_size
        ).unwrap();

        assert!(!boundaries.is_empty());
        assert_eq!(boundaries.last(), Some(&(data.len() as u64)));

        // Check all boundaries are within limits
        let mut last_pos = 0u64;
        for &boundary in &boundaries {
            let chunk_size = boundary - last_pos;
            assert!(chunk_size >= 512 || boundary == data.len() as u64);
            assert!(chunk_size <= 2048);
            last_pos = boundary;
        }
    }

    #[test]
    fn test_chunk_identity() {
        let data = b"hello world";
        let identity = ChunkIdentity::from_data(data, "test-profile", None);

        assert_eq!(identity.size, data.len() as u64);
        assert_eq!(identity.chunking_profile, "test-profile");
        assert_eq!(identity.context_hash, None);

        let identity_string = identity.identity_string();
        assert!(identity_string.contains("test-profile"));
        assert!(identity_string.contains(&identity.size.to_string()));
    }

    #[test]
    fn test_chunk_cache() {
        let mut cache = ChunkCache::new(1000); // 1KB cache

        let data1 = vec![1u8; 400];
        let identity1 = ChunkIdentity::from_data(&data1, "test", None);

        let data2 = vec![2u8; 400];
        let identity2 = ChunkIdentity::from_data(&data2, "test", None);

        let data3 = vec![3u8; 400];
        let identity3 = ChunkIdentity::from_data(&data3, "test", None);

        // Store first two chunks
        cache.store_chunk(identity1.clone(), data1.clone(), None).unwrap();
        cache.store_chunk(identity2.clone(), data2.clone(), None).unwrap();

        // Both should be present
        assert!(cache.lookup_chunk(&identity1).is_some());
        assert!(cache.lookup_chunk(&identity2).is_some());

        // Store third chunk (should evict oldest)
        cache.store_chunk(identity3.clone(), data3.clone(), None).unwrap();

        // First chunk should be evicted
        assert!(cache.lookup_chunk(&identity1).is_none());
        assert!(cache.lookup_chunk(&identity2).is_some());
        assert!(cache.lookup_chunk(&identity3).is_some());
    }

    #[test]
    fn test_chunk_reuse_manager() {
        let mut manager = ChunkReuseManager::new(1000);
        let transfer_id = "test-transfer";
        let context_hash = [1u8; 32];

        manager.register_context(transfer_id, context_hash);

        let data = b"test chunk data";
        let identity = manager.store_chunk_for_reuse(data, "test-profile", transfer_id, None).unwrap();

        // Should be able to reuse from same context
        let reused_data = manager.try_reuse_chunk(&identity, transfer_id);
        assert_eq!(reused_data.as_deref(), Some(data.as_slice()));

        // Different transfer without context should not be able to reuse
        let other_transfer = "other-transfer";
        let other_reused = manager.try_reuse_chunk(&identity, other_transfer);
        assert!(other_reused.is_none());
    }

    #[test]
    fn test_capability_scoped_reuse() {
        let mut cache = ChunkCache::new(1000);

        let data = vec![1u8; 100];
        let context_a = Some([1u8; 32]);
        let context_b = Some([2u8; 32]);

        let identity_a = ChunkIdentity::from_data(&data, "test", context_a);
        let identity_b = ChunkIdentity::from_data(&data, "test", context_b);

        cache.store_chunk(identity_a.clone(), data.clone(), None).unwrap();

        // Same context should allow reuse
        assert!(cache.can_reuse_chunk(&identity_a, context_a));

        // Different context should not allow reuse
        assert!(!cache.can_reuse_chunk(&identity_a, context_b));

        // No context (global) should allow reuse
        let identity_global = ChunkIdentity::from_data(&data, "test", None);
        cache.store_chunk(identity_global.clone(), data.clone(), None).unwrap();
        assert!(cache.can_reuse_chunk(&identity_global, context_a));
        assert!(cache.can_reuse_chunk(&identity_global, context_b));
    }
}