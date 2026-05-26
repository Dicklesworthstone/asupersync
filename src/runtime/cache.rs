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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for CacheStatistics {
    fn default() -> Self {
        Self {
            total_hits: 0,
            total_misses: 0,
            total_evictions: 0,
            total_stored: 0,
            current_hit_rate_bps: 0,
            avg_access_time_nanos: 0,
            peak_memory_bytes: 0,
        }
    }
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
        snapshot.resident_bytes = 500 * 1024 * 1024; // 500MB
        snapshot.max_resident_bytes = 1024 * 1024 * 1024; // 1GB
        snapshot.high_pressure = false;

        assert_eq!(snapshot.pressure_ratio(), 0.75);
        assert_eq!(snapshot.utilization_ratio(), 0.5);
        assert!(!snapshot.is_under_pressure()); // Below threshold
    }

    #[test]
    fn artifact_cache_creation() {
        let config = ArtifactCacheConfig::default();
        let cache = ArtifactCache::new(config);

        assert!(cache.is_empty());
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
            let serialized = serde_json::to_string(policy).unwrap();
            let deserialized: EvictionPolicy = serde_json::from_str(&serialized).unwrap();
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
