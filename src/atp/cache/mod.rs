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

/// Whole-value match of an envelope's declared AEAD algorithm against a known
/// allowlist (br-asupersync-28i28f). The previous
/// `contains("aes"|"chacha"|"gcm")` substring test failed OPEN — e.g.
/// `"definitely-not-a-real-gcm"` passed. Separators and case are normalized so
/// canonical spellings and their hyphen/underscore variants all match, but
/// arbitrary strings that merely embed an AEAD token no longer do. This is a
/// well-formedness / anti-forgery ratchet, NOT a cryptographic verification.
fn is_known_aead_algorithm(algorithm: &str) -> bool {
    let normalized: String = algorithm
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    matches!(
        normalized.as_str(),
        "aes128gcm"
            | "aes192gcm"
            | "aes256gcm"
            | "aes128gcmsiv"
            | "aes256gcmsiv"
            | "chacha20poly1305"
            | "xchacha20poly1305"
            | "aeadaes128gcm"
            | "aeadaes256gcm"
            | "aeadchacha20poly1305"
            | "aeadxchacha20poly1305"
            | "a128gcm"
            | "a192gcm"
            | "a256gcm"
    )
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
        .is_some_and(is_known_aead_algorithm);

    has_ciphertext && has_nonce && has_tag && has_algorithm
}

fn derive_cache_entry_encryption_status(_key: &CacheKey, content: &[u8]) -> bool {
    // br-asupersync-28i28f: an attacker-controlled grant-scope STRING (e.g.
    // `team:encrypted`) must NOT satisfy the shared-cache encryption gate on its
    // own, or a seeder stores plaintext under an "encrypted" scope and it leaks
    // on an encryption-required shared/relay/CDN cache. Only a real AEAD envelope
    // counts here; `CacheKey::declares_encrypted_content()` stays a public
    // advisory predicate but is no longer proof and no longer gates storage.
    // NOTE: this byte heuristic is still not a cryptographic proof — the full fix
    // (28i28f mitigation (c)) is an authenticated encryption status bound to the
    // actual encryption operation, which this does not yet provide.
    content_has_encrypted_envelope(content)
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
#[path = "mod_inline_tests.rs"]
mod tests;
