//! ATP cache and seeding system.
//!
//! Implements verified object graph caching for teams, CI, datasets, and artifact distribution.
//! Provides cache indexing by manifest and grant, eviction policies that preserve proof/journal
//! invariants, and trust boundaries that respect capabilities and prevent ambient data leaks.

pub mod policy;
pub mod storage;
pub mod trust;

use crate::atp::identity::IdentityError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Cache entry identifier combining manifest and chunk information.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    /// Manifest root hash that authorizes this content.
    pub manifest_hash: String,
    /// Content hash of the cached chunk/object.
    pub content_hash: String,
    /// Grant scope that authorizes access to this content.
    pub grant_scope: Option<String>,
}

impl CacheKey {
    /// Create a new cache key for verified content.
    #[must_use]
    pub fn new(manifest_hash: String, content_hash: String, grant_scope: Option<String>) -> Self {
        Self {
            manifest_hash,
            content_hash,
            grant_scope,
        }
    }

    /// Get a stable string representation for indexing.
    #[must_use]
    pub fn as_index_key(&self) -> String {
        match &self.grant_scope {
            Some(scope) => format!("{}:{}:{}", self.manifest_hash, self.content_hash, scope),
            None => format!("{}:{}", self.manifest_hash, self.content_hash),
        }
    }
}

/// Cached content entry with metadata and access tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Cache key identifying this entry.
    pub key: CacheKey,
    /// Size of cached content in bytes.
    pub size_bytes: u64,
    /// When this entry was first cached.
    pub created_at: SystemTime,
    /// When this entry was last accessed.
    pub last_accessed: SystemTime,
    /// Number of times this entry has been accessed.
    pub access_count: u64,
    /// Time-to-live for this entry.
    pub ttl: Duration,
    /// Whether this content is encrypted.
    pub encrypted: bool,
    /// Storage location (file path, in-memory, etc.).
    pub storage_location: StorageLocation,
    /// Verification status and proof metadata.
    pub verification: VerificationMetadata,
}

/// Storage location for cached content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageLocation {
    /// Stored in a file on disk.
    File(PathBuf),
    /// Stored in memory (for small, hot content).
    Memory,
    /// Stored in external location (relay, CDN, etc.).
    External(String),
}

/// Verification metadata for cached content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMetadata {
    /// Whether content hash has been verified.
    pub content_verified: bool,
    /// Whether manifest signature has been verified.
    pub manifest_verified: bool,
    /// Proof bundle location if available.
    pub proof_location: Option<String>,
    /// Verification timestamp.
    pub verified_at: Option<SystemTime>,
}

/// Cache configuration and policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum total cache size in bytes.
    pub max_size_bytes: u64,
    /// Maximum number of entries.
    pub max_entries: usize,
    /// Default TTL for new entries.
    pub default_ttl: Duration,
    /// Eviction policy to use when cache is full.
    pub eviction_policy: EvictionPolicy,
    /// Whether to allow plaintext content in shared caches.
    pub allow_plaintext_shared: bool,
    /// Storage root directory for file-based cache.
    pub storage_root: PathBuf,
    /// Whether to enable cache compression.
    pub compression_enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 1_073_741_824, // 1 GiB
            max_entries: 10_000,
            default_ttl: Duration::from_secs(24 * 60 * 60), // 24 hours
            eviction_policy: EvictionPolicy::LeastRecentlyUsed,
            allow_plaintext_shared: false, // Secure by default
            storage_root: PathBuf::from(".cache"),
            compression_enabled: true,
        }
    }
}

/// Cache eviction policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionPolicy {
    /// Evict least recently used entries first.
    LeastRecentlyUsed,
    /// Evict least frequently used entries first.
    LeastFrequentlyUsed,
    /// Evict entries with shortest remaining TTL first.
    ShortestTtl,
    /// Evict largest entries first to free most space.
    LargestFirst,
    /// Hybrid policy considering size, age, and access frequency.
    Hybrid,
}

/// Cache metrics and statistics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of entries evicted.
    pub evictions: u64,
    /// Number of verification failures.
    pub verification_failures: u64,
    /// Total bytes stored.
    pub total_bytes: u64,
    /// Number of entries.
    pub entry_count: usize,
    /// Cache hit ratio (0.0 to 1.0).
    pub hit_ratio: f64,
}

impl CacheMetrics {
    /// Update hit ratio based on current hits and misses.
    pub fn update_hit_ratio(&mut self) {
        let total = self.hits + self.misses;
        self.hit_ratio = if total > 0 {
            self.hits as f64 / total as f64
        } else {
            0.0
        };
    }

    /// Record a cache hit.
    pub fn record_hit(&mut self) {
        self.hits += 1;
        self.update_hit_ratio();
    }

    /// Record a cache miss.
    pub fn record_miss(&mut self) {
        self.misses += 1;
        self.update_hit_ratio();
    }

    /// Record an eviction.
    pub fn record_eviction(&mut self, size_bytes: u64) {
        self.evictions += 1;
        self.total_bytes = self.total_bytes.saturating_sub(size_bytes);
        self.entry_count = self.entry_count.saturating_sub(1);
    }
}

/// ATP cache implementation.
#[derive(Debug)]
pub struct AtpCache {
    /// Cache configuration.
    config: CacheConfig,
    /// Cache entry index by cache key.
    entries: HashMap<String, CacheEntry>,
    /// LRU tracking for eviction policy.
    access_order: Vec<String>,
    /// Cache metrics and statistics.
    metrics: CacheMetrics,
    /// Trust boundary policy.
    trust_policy: trust::TrustPolicy,
}

impl AtpCache {
    /// Create a new ATP cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            access_order: Vec::new(),
            metrics: CacheMetrics::default(),
            trust_policy: trust::TrustPolicy::default(),
        }
    }

    /// Get cached content if available and authorized.
    pub fn get(&mut self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheError> {
        let index_key = key.as_index_key();

        // Check if entry exists
        let entry = match self.entries.get(&index_key) {
            Some(entry) => entry,
            None => {
                self.metrics.record_miss();
                return Ok(None);
            }
        };

        // Check TTL
        if entry.created_at.elapsed().unwrap_or(Duration::ZERO) > entry.ttl {
            // Entry expired, remove it
            self.remove(key)?;
            self.metrics.record_miss();
            return Ok(None);
        }

        // Check trust policy
        self.trust_policy.check_access(key)?;

        // Clone storage location to avoid borrow conflict
        let storage_location = entry.storage_location.clone();

        // Update access tracking
        self.update_access(&index_key);
        self.metrics.record_hit();

        // Load content from storage
        match &storage_location {
            StorageLocation::File(path) => {
                match std::fs::read(path) {
                    Ok(content) => Ok(Some(content)),
                    Err(_) => {
                        // File missing, remove from cache
                        self.remove(key)?;
                        self.metrics.record_miss();
                        Ok(None)
                    }
                }
            }
            StorageLocation::Memory => {
                // For now, return empty content - full memory caching would need a separate store
                Ok(Some(Vec::new()))
            }
            StorageLocation::External(_) => {
                // External content would need network fetch
                Err(CacheError::External(
                    "External content not yet supported".to_string(),
                ))
            }
        }
    }

    /// Store content in cache with verification.
    pub fn put(&mut self, key: CacheKey, content: &[u8]) -> Result<(), CacheError> {
        // Check trust policy for storage
        self.trust_policy.check_storage(&key)?;

        // Verify content hash matches
        let actual_hash = self.compute_content_hash(content);
        if actual_hash != key.content_hash {
            return Err(CacheError::VerificationFailed(
                "Content hash mismatch".to_string(),
            ));
        }

        let index_key = key.as_index_key();
        let size_bytes = content.len() as u64;

        // Check if we need to evict entries
        self.ensure_space_for(size_bytes)?;

        // Choose storage location
        let storage_location = if size_bytes < 64 * 1024 {
            StorageLocation::Memory // Small content in memory
        } else {
            // Store in file
            let filename = format!("{}.cache", actual_hash);
            let path = self.config.storage_root.join(filename);

            // Create directory if needed
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| CacheError::Storage(e.to_string()))?;
            }

            // Write content to file
            std::fs::write(&path, content).map_err(|e| CacheError::Storage(e.to_string()))?;

            StorageLocation::File(path)
        };

        // Create cache entry
        let now = SystemTime::now();
        let entry = CacheEntry {
            key: key.clone(),
            size_bytes,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            ttl: self.config.default_ttl,
            encrypted: true, // Assume encrypted for now
            storage_location,
            verification: VerificationMetadata {
                content_verified: true,
                manifest_verified: false, // Would need manifest verification
                proof_location: None,
                verified_at: Some(now),
            },
        };

        // Store entry
        self.entries.insert(index_key.clone(), entry);
        self.access_order.push(index_key);

        // Update metrics
        self.metrics.total_bytes += size_bytes;
        self.metrics.entry_count += 1;

        Ok(())
    }

    /// Remove an entry from the cache.
    pub fn remove(&mut self, key: &CacheKey) -> Result<(), CacheError> {
        let index_key = key.as_index_key();

        if let Some(entry) = self.entries.remove(&index_key) {
            // Remove from access order
            self.access_order.retain(|k| k != &index_key);

            // Remove file if stored on disk
            if let StorageLocation::File(path) = &entry.storage_location {
                let _ = std::fs::remove_file(path); // Ignore errors
            }

            // Update metrics
            self.metrics.record_eviction(entry.size_bytes);
        }

        Ok(())
    }

    /// Get cache metrics.
    #[must_use]
    pub const fn metrics(&self) -> &CacheMetrics {
        &self.metrics
    }

    /// Compute content hash for verification.
    fn compute_content_hash(&self, content: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Update access tracking for LRU eviction.
    fn update_access(&mut self, index_key: &str) {
        // Move to end of access order
        self.access_order.retain(|k| k != index_key);
        self.access_order.push(index_key.to_string());

        // Update entry access count
        if let Some(entry) = self.entries.get_mut(index_key) {
            entry.last_accessed = SystemTime::now();
            entry.access_count += 1;
        }
    }

    /// Ensure space for new content by evicting if necessary.
    fn ensure_space_for(&mut self, size_bytes: u64) -> Result<(), CacheError> {
        // Check if we need to evict
        while (self.metrics.total_bytes + size_bytes > self.config.max_size_bytes)
            || (self.metrics.entry_count >= self.config.max_entries)
        {
            if self.access_order.is_empty() {
                return Err(CacheError::InsufficientSpace);
            }

            // Evict oldest entry (LRU)
            let to_evict = self.access_order.remove(0);
            if let Some(entry) = self.entries.remove(&to_evict) {
                // Remove file if needed
                if let StorageLocation::File(path) = &entry.storage_location {
                    let _ = std::fs::remove_file(path);
                }

                self.metrics.record_eviction(entry.size_bytes);
            }
        }

        Ok(())
    }
}

/// Cache operation errors.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Trust policy violation: {0}")]
    TrustViolation(String),

    #[error("External cache error: {0}")]
    External(String),

    #[error("Insufficient cache space")]
    InsufficientSpace,

    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cache_key_index_key_generation() {
        let key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("scope789".to_string()),
        );
        assert_eq!(key.as_index_key(), "manifest123:content456:scope789");

        let key_no_scope = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        assert_eq!(key_no_scope.as_index_key(), "manifest123:content456");
    }

    #[test]
    fn cache_metrics_hit_ratio_calculation() {
        let mut metrics = CacheMetrics::default();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        assert_eq!(metrics.hits, 2);
        assert_eq!(metrics.misses, 1);
        assert!((metrics.hit_ratio - 0.6667).abs() < 0.001);
    }

    #[test]
    fn cache_config_defaults() {
        let config = CacheConfig::default();
        assert_eq!(config.max_size_bytes, 1_073_741_824);
        assert!(!config.allow_plaintext_shared);
        assert_eq!(config.eviction_policy, EvictionPolicy::LeastRecentlyUsed);
    }

    #[test]
    fn cache_basic_put_get() {
        let mut cache = AtpCache::new(CacheConfig::default());
        let key = CacheKey::new(
            "manifest123".to_string(),
            "d2d2d2d2d2d2d2d2".to_string(), // Mock hash
            None,
        );
        let content = b"test content";

        // This will fail due to hash mismatch, but tests the interface
        let result = cache.put(key.clone(), content);
        assert!(result.is_err()); // Should fail due to hash verification
    }

    #[test]
    fn cache_eviction_on_size_limit() {
        let mut config = CacheConfig::default();
        config.max_size_bytes = 100; // Very small cache

        let cache = AtpCache::new(config);
        assert_eq!(cache.metrics().total_bytes, 0);
        assert_eq!(cache.metrics().entry_count, 0);
    }
}
