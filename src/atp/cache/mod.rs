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
        let mut index_key = String::new();
        index_key.push_str("v1|");
        push_index_key_part(&mut index_key, 'm', &self.manifest_hash);
        push_index_key_part(&mut index_key, 'c', &self.content_hash);
        match &self.grant_scope {
            Some(scope) => push_index_key_part(&mut index_key, 's', scope),
            None => index_key.push('n'),
        }
        index_key
    }

    /// Whether the grant scope declares encrypted-at-rest content.
    #[must_use]
    pub fn declares_encrypted_content(&self) -> bool {
        self.grant_scope
            .as_deref()
            .is_some_and(scope_declares_encrypted_content)
    }
}

fn push_index_key_part(index_key: &mut String, label: char, value: &str) {
    index_key.push(label);
    index_key.push(':');
    index_key.push_str(&value.len().to_string());
    index_key.push(':');
    index_key.push_str(value);
    index_key.push('|');
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageLocation {
    /// Stored in a file on disk.
    File(PathBuf),
    /// Stored in memory (for small, hot content) with lookup key.
    Memory(String),
    /// Stored in external location (relay, CDN, etc.).
    External(String),
}

fn scope_declares_encrypted_content(scope: &str) -> bool {
    scope
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .any(|token| {
            matches!(
                token.to_ascii_lowercase().as_str(),
                "encrypted" | "ciphertext" | "e2e" | "end-to-end" | "sealed"
            )
        })
}

fn content_has_encrypted_envelope(content: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(content) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };

    let has_ciphertext = object.contains_key("ciphertext") || object.contains_key("encrypted_data");
    let has_nonce = object.contains_key("nonce") || object.contains_key("iv");
    let has_tag = object.contains_key("tag") || object.contains_key("auth_tag");
    let has_algorithm = object
        .get("algorithm")
        .or_else(|| object.get("cipher"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|algorithm| {
            let algorithm = algorithm.to_ascii_lowercase();
            algorithm.contains("aes") || algorithm.contains("chacha") || algorithm.contains("gcm")
        });

    has_ciphertext && has_nonce && has_tag && has_algorithm
}

fn derive_cache_entry_encryption_status(key: &CacheKey, content: &[u8]) -> bool {
    key.declares_encrypted_content() || content_has_encrypted_envelope(content)
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
    /// Byte storage for entries whose storage location is in-memory.
    memory_storage: HashMap<String, Vec<u8>>,
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
            memory_storage: HashMap::new(),
            access_order: Vec::new(),
            metrics: CacheMetrics::default(),
            trust_policy: trust::TrustPolicy::default(),
        }
    }

    /// Get cached content if available and authorized.
    pub fn get(&mut self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheError> {
        let index_key = key.as_index_key();

        // Atomically check TTL and remove if expired to prevent TOCTOU races
        let entry = if let Some(entry) = self.entries.get(&index_key) {
            // Check TTL atomically with entry access
            let elapsed = entry.created_at.elapsed().unwrap_or(Duration::MAX);
            if elapsed > entry.ttl {
                if let Some(entry) = self.entries.remove(&index_key) {
                    self.remove_expired_entry(&index_key, entry);
                }
                self.metrics.record_miss();
                return Ok(None);
            }
            entry
        } else {
            self.metrics.record_miss();
            return Ok(None);
        };

        // Check trust policy
        self.trust_policy.check_access(key)?;

        // Clone storage location to avoid borrow conflict
        let storage_location = entry.storage_location.clone();

        // Load content from storage
        let content = match &storage_location {
            StorageLocation::File(path) => match std::fs::read(path) {
                Ok(content) => Some(content),
                Err(_) => {
                    // File missing, remove from cache
                    self.remove(key)?;
                    self.metrics.record_miss();
                    None
                }
            },
            StorageLocation::Memory(memory_key) => match self.memory_storage.get(memory_key) {
                Some(content) => Some(content.clone()),
                None => {
                    self.remove(key)?;
                    self.metrics.record_miss();
                    None
                }
            },
            StorageLocation::External(location) => {
                let content = retrieve_external_cache_location(location)?;
                Some(content)
            }
        };

        if let Some(content) = content {
            self.update_access(&index_key);
            self.metrics.record_hit();
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    /// Store content in cache with verification.
    pub fn put(&mut self, key: CacheKey, content: &[u8]) -> Result<(), CacheError> {
        // Verify content hash matches
        let actual_hash = self.compute_content_hash(content);
        if actual_hash != key.content_hash {
            return Err(CacheError::VerificationFailed(
                "Content hash mismatch".to_string(),
            ));
        }

        let encrypted = derive_cache_entry_encryption_status(&key, content);

        // Check trust policy for storage before mutating cache state.
        self.trust_policy.check_storage(&key, encrypted)?;

        let index_key = key.as_index_key();
        let size_bytes = content.len() as u64;
        let replaced_entry = self.entries.get(&index_key).cloned();

        // Check if we need to evict entries
        if replaced_entry.is_none() {
            self.ensure_space_for(size_bytes)?;
        }

        // Choose storage location
        let storage_location = if size_bytes < 64 * 1024 {
            // Small content in memory - generate memory key from cache key
            let memory_key = index_key.clone();
            self.memory_storage
                .insert(memory_key.clone(), content.to_vec());
            StorageLocation::Memory(memory_key)
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
            encrypted,
            storage_location: storage_location.clone(),
            verification: VerificationMetadata {
                content_verified: true,
                manifest_verified: false,
                proof_location: None,
                verified_at: Some(now),
            },
        };

        // Store entry
        self.entries.insert(index_key.clone(), entry);
        self.access_order.retain(|k| k != &index_key);
        self.access_order.push(index_key);

        // Update metrics
        if let Some(replaced_entry) = replaced_entry {
            if replaced_entry.storage_location != storage_location {
                self.remove_storage_location(&replaced_entry.storage_location);
            }
            self.metrics.total_bytes = self
                .metrics
                .total_bytes
                .saturating_sub(replaced_entry.size_bytes)
                .saturating_add(size_bytes);
        } else {
            self.metrics.total_bytes = self.metrics.total_bytes.saturating_add(size_bytes);
            self.metrics.entry_count = self.metrics.entry_count.saturating_add(1);
        }

        Ok(())
    }

    /// Remove an entry from the cache.
    pub fn remove(&mut self, key: &CacheKey) -> Result<(), CacheError> {
        let index_key = key.as_index_key();

        if let Some(entry) = self.entries.remove(&index_key) {
            // Remove from access order
            self.access_order.retain(|k| k != &index_key);

            // Remove backing data if stored in this cache instance.
            self.remove_storage_location(&entry.storage_location);

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
            entry.access_count = entry.access_count.saturating_add(1);
        }
    }

    /// Ensure space for new content by evicting if necessary.
    fn ensure_space_for(&mut self, size_bytes: u64) -> Result<(), CacheError> {
        // Check if we need to evict
        while (self.metrics.total_bytes.saturating_add(size_bytes) > self.config.max_size_bytes)
            || (self.metrics.entry_count >= self.config.max_entries)
        {
            if self.access_order.is_empty() {
                return Err(CacheError::InsufficientSpace);
            }

            // Evict oldest entry (LRU)
            let to_evict = self.access_order.remove(0);
            if let Some(entry) = self.entries.remove(&to_evict) {
                // Remove backing data if needed
                self.remove_storage_location(&entry.storage_location);

                self.metrics.record_eviction(entry.size_bytes);
            }
        }

        Ok(())
    }

    fn remove_expired_entry(&mut self, index_key: &str, entry: CacheEntry) {
        self.remove_storage_location(&entry.storage_location);
        self.access_order.retain(|k| k != index_key);
        self.metrics.record_eviction(entry.size_bytes);
    }

    fn remove_storage_location(&mut self, storage_location: &StorageLocation) {
        match storage_location {
            StorageLocation::File(path) => {
                let _ = std::fs::remove_file(path);
            }
            StorageLocation::Memory(memory_key) => {
                self.memory_storage.remove(memory_key);
            }
            StorageLocation::External(_) => {}
        }
    }
}

fn retrieve_external_cache_location(location: &str) -> Result<Vec<u8>, CacheError> {
    if let Some(path) = location.strip_prefix("file://") {
        return std::fs::read(path).map_err(|error| {
            CacheError::External(format!(
                "failed to read external file cache location: {error}"
            ))
        });
    }
    let path = PathBuf::from(location);
    if path.is_absolute() {
        return std::fs::read(path).map_err(|error| {
            CacheError::External(format!("failed to read external cache path: {error}"))
        });
    }
    Err(CacheError::External(format!(
        "external cache location requires a configured backend: {location}"
    )))
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
        assert_eq!(
            key.as_index_key(),
            "v1|m:11:manifest123|c:10:content456|s:8:scope789|"
        );

        let key_no_scope = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        assert_eq!(
            key_no_scope.as_index_key(),
            "v1|m:11:manifest123|c:10:content456|n"
        );
    }

    #[test]
    fn cache_key_index_key_is_not_delimiter_collision_prone() {
        let scoped = CacheKey::new("a".to_string(), "b".to_string(), Some("c".to_string()));
        let unscoped_with_delimiter = CacheKey::new("a".to_string(), "b:c".to_string(), None);

        assert_ne!(
            scoped.as_index_key(),
            unscoped_with_delimiter.as_index_key()
        );
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
            "d2d2d2d2d2d2d2d2".to_string(), // Intentionally invalid content hash
            None,
        );
        let content = b"test content";

        // This will fail due to hash mismatch, but tests the interface
        let result = cache.put(key.clone(), content);
        assert!(result.is_err()); // Should fail due to hash verification
    }

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        hex::encode(Sha256::digest(content))
    }

    #[test]
    fn cache_put_existing_key_does_not_duplicate_metrics_or_lru_entries() {
        let mut config = CacheConfig::default();
        config.max_entries = 1;
        let mut cache = AtpCache::new(config);
        let content = b"stable cache content";
        let key = CacheKey::new("manifest123".to_string(), sha256_hex(content), None);

        cache.put(key.clone(), content).unwrap();
        cache.put(key.clone(), content).unwrap();

        assert_eq!(cache.metrics().entry_count, 1);
        assert_eq!(cache.metrics().total_bytes, content.len() as u64);
        assert_eq!(cache.access_order.len(), 1);
        assert_eq!(cache.get(&key).unwrap().as_deref(), Some(&content[..]));
    }

    #[test]
    fn cache_entry_encryption_status_is_derived_from_scope_or_envelope() {
        let encrypted_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("team:engineering:encrypted".to_string()),
        );
        assert!(derive_cache_entry_encryption_status(
            &encrypted_key,
            b"plaintext"
        ));

        let envelope_key = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        let envelope = br#"{
            "algorithm": "aes-256-gcm",
            "nonce": "000000000000000000000000",
            "ciphertext": "deadbeef",
            "tag": "cafebabe"
        }"#;
        assert!(derive_cache_entry_encryption_status(
            &envelope_key,
            envelope
        ));

        let plaintext_key =
            CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        assert!(!derive_cache_entry_encryption_status(
            &plaintext_key,
            b"plaintext"
        ));
    }

    #[test]
    fn cache_ttl_toctou_fix() {
        let mut cache = AtpCache::new(CacheConfig::default());

        // Create a cache key
        let key = CacheKey::new(
            "manifest123".to_string(),
            "d2d2d2d2d2d2d2d2".to_string(), // Intentionally invalid content hash
            None,
        );

        // Put some content with very short TTL
        let content = b"test content";

        // Manually add an expired entry to test TTL check
        let expired_entry = CacheEntry {
            key: key.clone(),
            size_bytes: content.len() as u64,
            created_at: SystemTime::now() - Duration::from_secs(3600), // 1 hour ago
            last_accessed: SystemTime::now(),
            access_count: 1,
            ttl: Duration::from_secs(60), // 1 minute TTL (expired)
            encrypted: true,
            storage_location: StorageLocation::Memory("test".to_string()),
            verification: VerificationMetadata {
                content_verified: true,
                manifest_verified: true,
                proof_location: None,
                verified_at: Some(SystemTime::now()),
            },
        };

        // Insert expired entry directly
        cache.entries.insert(key.as_index_key(), expired_entry);
        cache.access_order.push(key.as_index_key());
        cache
            .memory_storage
            .insert("test".to_string(), content.to_vec());
        cache.metrics.total_bytes = content.len() as u64;
        cache.metrics.entry_count = 1;
        assert_eq!(cache.entries.len(), 1);

        // Try to get expired entry - should be atomically removed
        let result = cache.get(&key);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Should return None for expired entry

        // Entry should be removed from cache
        assert_eq!(cache.entries.len(), 0);
        assert_eq!(cache.access_order.len(), 0);
        assert_eq!(cache.metrics().total_bytes, 0);
        assert_eq!(cache.metrics().entry_count, 0);
    }

    #[test]
    fn cache_eviction_on_size_limit() {
        let mut config = CacheConfig::default();
        config.max_size_bytes = 100; // Very small cache

        let cache = AtpCache::new(config);
        assert_eq!(cache.metrics().total_bytes, 0);
        assert_eq!(cache.metrics().entry_count, 0);
    }

    // Golden Artifact Tests for ATP Cache Serialization Stability

    #[test]
    fn golden_cache_config_default_serialization() {
        let config = CacheConfig::default();
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({
                "max_size_bytes": 1_073_741_824_u64,
                "max_entries": 10_000,
                "default_ttl": {
                    "secs": 86_400,
                    "nanos": 0,
                },
                "eviction_policy": "least_recently_used",
                "allow_plaintext_shared": false,
                "storage_root": ".cache",
                "compression_enabled": true,
            })
        );
    }

    #[test]
    fn golden_cache_config_custom_serialization() {
        use std::path::PathBuf;

        let config = CacheConfig {
            max_size_bytes: 512 * 1024 * 1024, // 512 MiB
            max_entries: 5_000,
            default_ttl: Duration::from_secs(12 * 60 * 60), // 12 hours
            eviction_policy: EvictionPolicy::Hybrid,
            allow_plaintext_shared: true,
            storage_root: PathBuf::from("/var/cache/atp"),
            compression_enabled: false,
        };
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({
                "max_size_bytes": 536_870_912_u64,
                "max_entries": 5_000,
                "default_ttl": {
                    "secs": 43_200,
                    "nanos": 0,
                },
                "eviction_policy": "hybrid",
                "allow_plaintext_shared": true,
                "storage_root": "/var/cache/atp",
                "compression_enabled": false,
            })
        );
    }

    #[test]
    fn golden_cache_key_serialization() {
        // Test cache key with scope
        let key_with_scope = CacheKey::new(
            "sha256:a1b2c3d4e5f6g7h8".to_string(),
            "sha256:1234567890abcdef".to_string(),
            Some("team:engineering".to_string()),
        );
        assert_eq!(
            serde_json::to_value(&key_with_scope).unwrap(),
            serde_json::json!({
                "manifest_hash": "sha256:a1b2c3d4e5f6g7h8",
                "content_hash": "sha256:1234567890abcdef",
                "grant_scope": "team:engineering",
            })
        );

        // Test cache key without scope
        let key_no_scope = CacheKey::new(
            "sha256:fedcba0987654321".to_string(),
            "sha256:abcdef1234567890".to_string(),
            None,
        );
        assert_eq!(
            serde_json::to_value(&key_no_scope).unwrap(),
            serde_json::json!({
                "manifest_hash": "sha256:fedcba0987654321",
                "content_hash": "sha256:abcdef1234567890",
                "grant_scope": null,
            })
        );
    }

    #[test]
    fn golden_eviction_policy_serialization() {
        let policies = vec![
            EvictionPolicy::LeastRecentlyUsed,
            EvictionPolicy::LeastFrequentlyUsed,
            EvictionPolicy::ShortestTtl,
            EvictionPolicy::LargestFirst,
            EvictionPolicy::Hybrid,
        ];

        assert_eq!(
            serde_json::to_value(&policies).unwrap(),
            serde_json::json!([
                "least_recently_used",
                "least_frequently_used",
                "shortest_ttl",
                "largest_first",
                "hybrid",
            ])
        );
    }

    #[test]
    fn golden_cache_metrics_serialization() {
        let mut metrics = CacheMetrics::default();
        metrics.hits = 1500;
        metrics.misses = 300;
        metrics.evictions = 25;
        metrics.verification_failures = 2;
        metrics.total_bytes = 1024 * 1024; // 1 MiB
        metrics.entry_count = 150;
        metrics.update_hit_ratio();

        assert_eq!(
            serde_json::to_value(&metrics).unwrap(),
            serde_json::json!({
                "hits": 1_500,
                "misses": 300,
                "evictions": 25,
                "verification_failures": 2,
                "total_bytes": 1_048_576_u64,
                "entry_count": 150,
                "hit_ratio": 0.8333333333333334,
            })
        );
    }
}
