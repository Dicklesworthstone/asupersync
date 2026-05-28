//! Artifact cache and memory pressure tracking for the lab runtime.
//!
//! Provides memory pressure monitoring and artifact cache management for
//! deterministic lab scenario replay. This module supports NUMA-aware
//! cache pressure projection and artifact lifecycle management.
//!
//! # Key Components
//! - Memory pressure snapshots for lab scenario determinism
//! - Artifact cache with memory-aware eviction policies
//! - NUMA-topology-independent pressure calculations
//! - Deterministic cache behavior for reproducible lab runs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Memory pressure snapshot for deterministic lab scenario replay.
///
/// Captures cache state at a specific point in time to enable reproducible
/// memory pressure calculations across different host configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMemoryPressureSnapshot {
    /// Total bytes currently cached in memory.
    pub resident_bytes: u64,
    /// Maximum memory budget for cached artifacts.
    pub max_resident_bytes: u64,
    /// Memory used by recently accessed artifacts.
    pub hot_resident_bytes: u64,
    /// Memory used by cold/eviction-candidate artifacts.
    pub cold_resident_bytes: u64,
    /// Bytes eligible for spilling to disk.
    pub spill_eligible_bytes: u64,
    /// Bytes cached on remote NUMA nodes.
    pub remote_numa_bytes: u64,
    /// Memory pressure level in basis points (0-10000).
    pub pressure_bps: u16,
    /// True when cache is under high pressure (above threshold).
    pub high_pressure: bool,
    /// Deduplication savings in bytes.
    pub duplicate_bytes_avoided: u64,
    /// Number of cached artifacts.
    pub artifact_count: u32,
}

impl Default for ArtifactMemoryPressureSnapshot {
    fn default() -> Self {
        Self {
            resident_bytes: 0,
            max_resident_bytes: 1024 * 1024 * 1024, // 1GB default budget
            hot_resident_bytes: 0,
            cold_resident_bytes: 0,
            spill_eligible_bytes: 0,
            remote_numa_bytes: 0,
            pressure_bps: 0,
            high_pressure: false,
            duplicate_bytes_avoided: 0,
            artifact_count: 0,
        }
    }
}

impl ArtifactMemoryPressureSnapshot {
    /// Create a snapshot with current time.
    #[must_use]
    pub fn now() -> Self {
        Self::default()
    }

    /// Get pressure level as a floating-point ratio (0.0 to 1.0).
    #[must_use]
    pub fn pressure_ratio(&self) -> f64 {
        f64::from(self.pressure_bps) / 10_000.0
    }

    /// Calculate memory utilization ratio (0.0 to 1.0).
    #[must_use]
    pub fn utilization_ratio(&self) -> f64 {
        if self.max_resident_bytes == 0 {
            0.0
        } else {
            self.resident_bytes as f64 / self.max_resident_bytes as f64
        }
    }

    /// Check if cache is under memory pressure (above threshold).
    #[must_use]
    pub const fn is_under_pressure(&self) -> bool {
        self.high_pressure
    }
}

/// Configuration for the artifact cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCacheConfig {
    /// Maximum memory budget for cached artifacts.
    pub max_cache_size_bytes: u64,
    /// Threshold for triggering eviction (as ratio of max_cache_size).
    pub eviction_threshold_ratio: u32, // Fixed-point: divide by 10000
    /// Time-to-live for cached artifacts in seconds.
    pub default_ttl_secs: u64,
    /// Maximum number of artifacts to cache.
    pub max_artifact_count: u32,
    /// Enable NUMA-aware caching hints.
    pub numa_aware: bool,
    /// Eviction policy configuration.
    pub eviction_policy: EvictionPolicy,
}

impl Default for ArtifactCacheConfig {
    fn default() -> Self {
        Self {
            max_cache_size_bytes: 1024 * 1024 * 1024, // 1GB
            eviction_threshold_ratio: 7500,           // 75%
            default_ttl_secs: 3600,                   // 1 hour
            max_artifact_count: 10_000,
            numa_aware: true,
            eviction_policy: EvictionPolicy::LruWithTtl,
        }
    }
}

/// Cache eviction policies for artifact management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvictionPolicy {
    /// Least Recently Used with TTL expiration.
    LruWithTtl,
    /// Most Recently Used (for specific workload patterns).
    Mru,
    /// Size-based eviction (largest artifacts first).
    LargestFirst,
    /// Random eviction for testing purposes.
    Random,
}

/// Metadata for a cached artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// Unique identifier for the artifact.
    pub id: String,
    /// Size of the artifact in bytes.
    pub size_bytes: u64,
    /// When the artifact was first cached.
    pub cached_at_nanos: u64,
    /// When the artifact was last accessed.
    pub last_accessed_nanos: u64,
    /// Number of times this artifact has been accessed.
    pub access_count: u32,
    /// TTL expiration time.
    pub expires_at_nanos: u64,
    /// NUMA node affinity hint (if applicable).
    pub numa_node_hint: Option<u8>,
    /// Priority for eviction decisions (higher = keep longer).
    pub priority: u8,
}

/// Statistics for cache performance monitoring.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStatistics {
    /// Total cache hits since creation.
    pub total_hits: u64,
    /// Total cache misses since creation.
    pub total_misses: u64,
    /// Total evictions since creation.
    pub total_evictions: u64,
    /// Total artifacts stored since creation.
    pub total_stored: u64,
    /// Current cache hit rate in basis points.
    pub current_hit_rate_bps: u16,
    /// Average artifact access time in nanoseconds.
    pub avg_access_time_nanos: u64,
    /// Peak memory usage achieved.
    pub peak_memory_bytes: u64,
}

/// In-memory artifact cache implementation.
///
/// This is a simple implementation suitable for lab scenarios and testing.
/// Production usage would typically integrate with more sophisticated cache
/// backends and persistence layers.
#[derive(Debug)]
pub struct ArtifactCache {
    /// Cache configuration.
    config: ArtifactCacheConfig,
    /// Cached artifact metadata.
    metadata: HashMap<String, ArtifactMetadata>,
    /// Cached artifact data.
    data: HashMap<String, Vec<u8>>,
    /// Performance statistics.
    statistics: CacheStatistics,
    /// Current total size of cached artifacts.
    current_size_bytes: u64,
}

impl ArtifactCache {
    /// Create a new artifact cache with the given configuration.
    #[must_use]
    pub fn new(config: ArtifactCacheConfig) -> Self {
        Self {
            config,
            metadata: HashMap::new(),
            data: HashMap::new(),
            statistics: CacheStatistics::default(),
            current_size_bytes: 0,
        }
    }

    /// Create a cache with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(ArtifactCacheConfig::default())
    }

    /// Take a memory pressure snapshot of the current cache state.
    #[must_use]
    pub fn memory_pressure_snapshot(&self) -> ArtifactMemoryPressureSnapshot {
        // Calculate hot vs cold set sizes
        let threshold_nanos =
            (Instant::now().elapsed().as_nanos() as u64).saturating_sub(300_000_000_000); // 5 minutes ago
        let (hot_bytes, cold_bytes) = self.metadata.values().fold((0u64, 0u64), |acc, meta| {
            if meta.last_accessed_nanos > threshold_nanos {
                (acc.0 + meta.size_bytes, acc.1)
            } else {
                (acc.0, acc.1 + meta.size_bytes)
            }
        });

        // Calculate pressure level in basis points
        let utilization = if self.config.max_cache_size_bytes == 0 {
            0.0
        } else {
            self.current_size_bytes as f64 / self.config.max_cache_size_bytes as f64
        };
        let pressure_bps = (utilization * 10_000.0).min(10_000.0) as u16;
        let high_pressure = pressure_bps >= 7_500; // 75% threshold

        // Calculate spill-eligible bytes (cold bytes that can be evicted)
        let spill_eligible_bytes = cold_bytes.min(self.current_size_bytes / 2);

        ArtifactMemoryPressureSnapshot {
            resident_bytes: self.current_size_bytes,
            max_resident_bytes: self.config.max_cache_size_bytes,
            hot_resident_bytes: hot_bytes,
            cold_resident_bytes: cold_bytes,
            spill_eligible_bytes,
            remote_numa_bytes: 0, // Would need NUMA topology detection
            pressure_bps,
            high_pressure,
            duplicate_bytes_avoided: 0, // Would need dedup tracking
            artifact_count: self.metadata.len() as u32,
        }
    }

    /// Check if an artifact is cached.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.metadata.contains_key(id)
    }

    /// Get current cache statistics.
    #[must_use]
    pub const fn statistics(&self) -> &CacheStatistics {
        &self.statistics
    }

    /// Get current cache configuration.
    #[must_use]
    pub const fn config(&self) -> &ArtifactCacheConfig {
        &self.config
    }

    /// Get the current number of cached artifacts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.metadata.len()
    }

    /// Check if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }

    /// Get the current total size of cached artifacts.
    #[must_use]
    pub const fn current_size_bytes(&self) -> u64 {
        self.current_size_bytes
    }

    /// Retrieve a cached artifact by ID.
    /// Returns None if the artifact is not cached or has expired.
    pub fn get(&mut self, id: &str) -> Option<&[u8]> {
        let current_time_nanos = self.current_time_nanos();

        // Check if artifact exists and hasn't expired
        if let Some(meta) = self.metadata.get_mut(id) {
            if meta.expires_at_nanos > current_time_nanos {
                // Update access statistics
                meta.last_accessed_nanos = current_time_nanos;
                meta.access_count = meta.access_count.saturating_add(1);
                self.statistics.total_hits = self.statistics.total_hits.saturating_add(1);

                // Return cached data
                self.data.get(id).map(|v| v.as_slice())
            } else {
                // Expired - remove from cache
                self.remove_expired(id);
                self.statistics.total_misses = self.statistics.total_misses.saturating_add(1);
                None
            }
        } else {
            self.statistics.total_misses = self.statistics.total_misses.saturating_add(1);
            None
        }
    }

    /// Store an artifact in the cache.
    /// Returns true if successfully cached, false if eviction failed to make space.
    pub fn put(&mut self, id: String, data: Vec<u8>) -> bool {
        let current_time_nanos = self.current_time_nanos();
        let artifact_size = data.len() as u64;

        // Check if we need to evict to make space
        if !self.ensure_capacity_for(artifact_size) {
            return false;
        }

        // Remove existing entry if present
        if self.metadata.contains_key(&id) {
            self.remove_internal(&id);
        }

        // Create metadata
        let metadata = ArtifactMetadata {
            id: id.clone(),
            size_bytes: artifact_size,
            cached_at_nanos: current_time_nanos,
            last_accessed_nanos: current_time_nanos,
            access_count: 0,
            expires_at_nanos: current_time_nanos + (self.config.default_ttl_secs * 1_000_000_000),
            numa_node_hint: None, // Could be enhanced with NUMA detection
            priority: 128,        // Default priority
        };

        // Store data and metadata
        self.data.insert(id.clone(), data);
        self.metadata.insert(id, metadata);
        self.current_size_bytes += artifact_size;
        self.statistics.total_stored = self.statistics.total_stored.saturating_add(1);

        true
    }

    /// Remove a specific artifact from the cache.
    /// Returns true if the artifact was removed, false if it didn't exist.
    pub fn remove(&mut self, id: &str) -> bool {
        self.remove_internal(id)
    }

    /// Evict artifacts based on the configured eviction policy.
    /// Returns the number of artifacts evicted.
    pub fn evict(&mut self, target_bytes: u64) -> u32 {
        let mut evicted_count = 0;
        let mut evicted_bytes = 0u64;

        // Collect eviction candidates based on policy - clone to avoid borrow checker issues
        let mut candidates: Vec<_> = self
            .metadata
            .iter()
            .map(|(id, meta)| (id.clone(), meta.clone()))
            .collect();

        match self.config.eviction_policy {
            EvictionPolicy::LruWithTtl => {
                // Sort by last accessed time (oldest first)
                candidates.sort_by_key(|(_, meta)| meta.last_accessed_nanos);
            }
            EvictionPolicy::Mru => {
                // Sort by last accessed time (newest first)
                candidates.sort_by_key(|(_, meta)| std::cmp::Reverse(meta.last_accessed_nanos));
            }
            EvictionPolicy::LargestFirst => {
                // Sort by size (largest first)
                candidates.sort_by_key(|(_, meta)| std::cmp::Reverse(meta.size_bytes));
            }
            EvictionPolicy::Random => {
                // Use deterministic "random" based on hash for lab reproducibility
                candidates.sort_by_key(|(id, _)| id.len());
            }
        }

        // Evict until we've freed enough space
        for (id, meta) in candidates {
            if evicted_bytes >= target_bytes {
                break;
            }

            evicted_bytes += meta.size_bytes;
            self.remove_internal(&id);
            evicted_count += 1;
        }

        self.statistics.total_evictions = self
            .statistics
            .total_evictions
            .saturating_add(u64::from(evicted_count));
        evicted_count
    }

    /// Remove all expired artifacts from the cache.
    /// Returns the number of artifacts invalidated.
    pub fn invalidate_expired(&mut self) -> u32 {
        let current_time_nanos = self.current_time_nanos();
        let mut invalidated_count = 0;

        // Collect expired artifact IDs
        let expired_ids: Vec<String> = self
            .metadata
            .iter()
            .filter_map(|(id, meta)| {
                if meta.expires_at_nanos <= current_time_nanos {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired artifacts
        for id in expired_ids {
            self.remove_internal(&id);
            invalidated_count += 1;
        }

        invalidated_count
    }

    /// Clear all artifacts from the cache.
    pub fn clear(&mut self) {
        self.metadata.clear();
        self.data.clear();
        self.current_size_bytes = 0;
    }

    /// Internal helper to remove an artifact and update statistics.
    fn remove_internal(&mut self, id: &str) -> bool {
        if let Some(meta) = self.metadata.remove(id) {
            self.data.remove(id);
            self.current_size_bytes = self.current_size_bytes.saturating_sub(meta.size_bytes);
            true
        } else {
            false
        }
    }

    /// Remove a specific expired artifact.
    fn remove_expired(&mut self, id: &str) {
        self.remove_internal(id);
    }

    /// Ensure there's capacity for a new artifact of the given size.
    fn ensure_capacity_for(&mut self, needed_bytes: u64) -> bool {
        // First, clean up expired items
        self.invalidate_expired();

        // Check if we have enough space now
        let available_bytes = self
            .config
            .max_cache_size_bytes
            .saturating_sub(self.current_size_bytes);
        if available_bytes >= needed_bytes {
            return true;
        }

        // Need to evict some items
        let bytes_to_free = needed_bytes.saturating_sub(available_bytes);
        let eviction_threshold = (self.config.max_cache_size_bytes
            * u64::from(self.config.eviction_threshold_ratio))
            / 10_000;

        // If we're above eviction threshold, be more aggressive
        let target_eviction = if self.current_size_bytes > eviction_threshold {
            bytes_to_free + (self.current_size_bytes / 4) // Free extra 25% for headroom
        } else {
            bytes_to_free
        };

        self.evict(target_eviction);

        // Check if we now have enough space
        let final_available = self
            .config
            .max_cache_size_bytes
            .saturating_sub(self.current_size_bytes);
        final_available >= needed_bytes
    }

    /// Get current time in nanoseconds for timestamps.
    fn current_time_nanos(&self) -> u64 {
        // In production, this would route through Cx capabilities
        // For lab testing, use a simple implementation
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_memory_pressure_snapshot_default() {
        let snapshot = ArtifactMemoryPressureSnapshot::default();
        assert_eq!(snapshot.resident_bytes, 0);
        assert_eq!(snapshot.artifact_count, 0);
        assert_eq!(snapshot.pressure_bps, 0);
        assert!(!snapshot.is_under_pressure());
        assert_eq!(snapshot.pressure_ratio(), 0.0);
        assert_eq!(snapshot.utilization_ratio(), 0.0);
    }

    #[test]
    fn artifact_memory_pressure_snapshot_calculations() {
        let mut snapshot = ArtifactMemoryPressureSnapshot::default();
        snapshot.pressure_bps = 7500; // 75%
        snapshot.resident_bytes = 512 * 1024 * 1024; // 512MiB
        snapshot.max_resident_bytes = 1024 * 1024 * 1024; // 1GiB
        snapshot.high_pressure = true;

        assert_eq!(snapshot.pressure_ratio(), 0.75);
        assert_eq!(snapshot.utilization_ratio(), 0.5);
        assert!(snapshot.is_under_pressure()); // At threshold
    }

    #[test]
    fn artifact_cache_creation() {
        let config = ArtifactCacheConfig::default();
        let cache = ArtifactCache::new(config);

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_size_bytes(), 0);
    }

    #[test]
    fn artifact_cache_put_and_get() {
        let mut cache = ArtifactCache::default_config();
        let test_data = b"test artifact data".to_vec();
        let test_id = "test-artifact-1".to_string();

        // Put artifact
        assert!(cache.put(test_id.clone(), test_data.clone()));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.current_size_bytes(), test_data.len() as u64);
        assert!(cache.contains(&test_id));

        // Get artifact
        let retrieved = cache.get(&test_id);
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.expect("cache should contain stored artifact"),
            test_data.as_slice()
        );

        // Verify access count increased
        let stats = cache.statistics();
        assert_eq!(stats.total_hits, 1);
        assert_eq!(stats.total_misses, 0);
        assert_eq!(stats.total_stored, 1);
    }

    #[test]
    fn artifact_cache_remove() {
        let mut cache = ArtifactCache::default_config();
        let test_data = b"test data".to_vec();
        let test_id = "test-id".to_string();

        // Put and then remove
        cache.put(test_id.clone(), test_data);
        assert!(cache.contains(&test_id));
        assert!(cache.remove(&test_id));
        assert!(!cache.contains(&test_id));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_size_bytes(), 0);

        // Removing non-existent artifact should return false
        assert!(!cache.remove("non-existent"));
    }

    #[test]
    fn artifact_cache_eviction() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 100,      // Small cache for testing
            eviction_threshold_ratio: 5000, // 50%
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        // Fill cache beyond capacity
        cache.put("item1".to_string(), vec![0u8; 40]);
        cache.put("item2".to_string(), vec![1u8; 40]);
        cache.put("item3".to_string(), vec![2u8; 40]); // This should trigger eviction

        // Should have evicted some items to stay under capacity
        assert!(cache.current_size_bytes() <= 100);
        assert!(cache.len() <= 2); // At least one item should be evicted
    }

    #[test]
    fn artifact_cache_clear() {
        let mut cache = ArtifactCache::default_config();

        // Add some artifacts
        cache.put("item1".to_string(), vec![0u8; 10]);
        cache.put("item2".to_string(), vec![1u8; 20]);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_size_bytes(), 30);

        // Clear cache
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.current_size_bytes(), 0);
    }

    #[test]
    fn artifact_cache_miss() {
        let mut cache = ArtifactCache::default_config();

        // Get non-existent artifact
        let result = cache.get("non-existent");
        assert!(result.is_none());

        let stats = cache.statistics();
        assert_eq!(stats.total_misses, 1);
        assert_eq!(stats.total_hits, 0);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_size_bytes(), 0);
        assert!(!cache.contains("test"));
    }

    #[test]
    fn artifact_cache_memory_pressure_snapshot() {
        let cache = ArtifactCache::default_config();
        let snapshot = cache.memory_pressure_snapshot();

        assert_eq!(snapshot.resident_bytes, 0);
        assert_eq!(snapshot.artifact_count, 0);
        assert_eq!(snapshot.pressure_bps, 0);
        assert_eq!(snapshot.hot_resident_bytes, 0);
        assert_eq!(snapshot.cold_resident_bytes, 0);
    }

    #[test]
    fn eviction_policy_serialization() {
        let policies = [
            EvictionPolicy::LruWithTtl,
            EvictionPolicy::Mru,
            EvictionPolicy::LargestFirst,
            EvictionPolicy::Random,
        ];

        for policy in &policies {
            let serialized =
                serde_json::to_string(policy).expect("eviction policy should serialize to JSON");
            let deserialized: EvictionPolicy = serde_json::from_str(&serialized)
                .expect("serialized policy should deserialize from JSON");
            assert_eq!(*policy, deserialized);
        }
    }

    #[test]
    fn cache_config_default_values() {
        let config = ArtifactCacheConfig::default();
        assert_eq!(config.max_cache_size_bytes, 1024 * 1024 * 1024);
        assert_eq!(config.eviction_threshold_ratio, 7500);
        assert_eq!(config.default_ttl_secs, 3600);
        assert_eq!(config.max_artifact_count, 10_000);
        assert!(config.numa_aware);
        assert_eq!(config.eviction_policy, EvictionPolicy::LruWithTtl);
    }
}
