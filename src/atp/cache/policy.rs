//! Cache eviction and retention policies.
//!
//! Implements intelligent cache eviction that preserves proof/journal invariants
//! and optimizes for different use cases (hot data, long-term storage, etc.).

use super::{CacheEntry, EvictionPolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

/// Cache policy manager for eviction and retention decisions.
#[derive(Debug)]
pub struct CachePolicyManager {
    /// Active eviction policy.
    eviction_policy: EvictionPolicy,
    /// Retention policies by content type.
    retention_policies: BTreeMap<String, RetentionPolicy>,
    /// Proof-preserving constraints.
    proof_constraints: ProofConstraints,
}

impl CachePolicyManager {
    /// Create a new cache policy manager.
    #[must_use]
    pub fn new(eviction_policy: EvictionPolicy) -> Self {
        Self {
            eviction_policy,
            retention_policies: BTreeMap::new(),
            proof_constraints: ProofConstraints::default(),
        }
    }

    /// Select entries for eviction to free the specified amount of space.
    pub fn select_for_eviction(
        &self,
        entries: &BTreeMap<String, CacheEntry>,
        target_bytes: u64,
    ) -> Vec<String> {
        let mut candidates: Vec<_> = entries.iter().collect();

        // Sort candidates based on eviction policy
        match self.eviction_policy {
            EvictionPolicy::LeastRecentlyUsed => {
                candidates.sort_by_key(|(_, entry)| entry.last_accessed);
            }
            EvictionPolicy::LeastFrequentlyUsed => {
                candidates.sort_by_key(|(_, entry)| entry.access_count);
            }
            EvictionPolicy::ShortestTtl => {
                candidates.sort_by_key(|(_, entry)| {
                    remaining_ttl(entry.created_at, entry.ttl).unwrap_or(Duration::ZERO)
                });
            }
            EvictionPolicy::LargestFirst => {
                candidates.sort_by_key(|(_, entry)| std::cmp::Reverse(entry.size_bytes));
            }
            EvictionPolicy::Hybrid => {
                candidates.sort_by(|(_, a), (_, b)| {
                    self.hybrid_score(b)
                        .partial_cmp(&self.hybrid_score(a))
                        .unwrap()
                });
            }
        }

        // Select entries until we have enough space
        let mut selected = Vec::new();
        let mut freed_bytes = 0_u64;

        for (key, entry) in candidates {
            // Check if this entry can be evicted (proof constraints)
            if !self.can_evict_safely(entry) {
                continue;
            }

            selected.push(key.clone());
            freed_bytes = freed_bytes.saturating_add(entry.size_bytes);

            if freed_bytes >= target_bytes {
                break;
            }
        }

        selected
    }

    /// Check if an entry can be safely evicted without breaking proof invariants.
    fn can_evict_safely(&self, entry: &CacheEntry) -> bool {
        // Don't evict entries with active proof bundles
        if entry.verification.proof_location.is_some() {
            if self.proof_constraints.preserve_proof_bundles {
                return false;
            }
        }

        // Don't evict recently verified content if configured
        if let Some(verified_at) = entry.verification.verified_at {
            if verified_at.elapsed().unwrap_or(Duration::MAX)
                < self.proof_constraints.min_verification_age
            {
                return false;
            }
        }

        if entry.access_count < self.proof_constraints.min_access_count {
            return false;
        }

        if let Some(policy) = self.retention_policy_for(entry) {
            let age = entry.created_at.elapsed().unwrap_or(Duration::MAX);
            if policy.critical_for_proofs && self.proof_constraints.preserve_proof_bundles {
                return false;
            }
            if age < policy.min_retention {
                return false;
            }
            if age > policy.max_retention {
                return true;
            }
        }

        true
    }

    /// Calculate hybrid score for multi-factor eviction policy.
    fn hybrid_score(&self, entry: &CacheEntry) -> f64 {
        let age_hours = entry
            .last_accessed
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_secs_f64()
            / 3600.0;

        let size_mb = entry.size_bytes as f64 / (1024.0 * 1024.0);
        let access_frequency = entry.access_count as f64;

        let retention_penalty = self
            .retention_policy_for(entry)
            .map_or(0.0, |policy| f64::from(policy.priority));

        // Higher score means the entry is colder, larger, older, and cheaper to evict.
        (age_hours + size_mb) / (access_frequency + 1.0 + retention_penalty)
    }

    fn retention_policy_for(&self, entry: &CacheEntry) -> Option<&RetentionPolicy> {
        let grant_scope_policy = entry
            .key
            .grant_scope
            .as_ref()
            .and_then(|scope| self.retention_policies.get(scope));
        grant_scope_policy
            .or_else(|| self.retention_policies.get(storage_policy_key(entry)))
            .or_else(|| self.retention_policies.get("default"))
    }

    /// Add a retention policy for specific content types.
    pub fn add_retention_policy(&mut self, content_type: String, policy: RetentionPolicy) {
        self.retention_policies.insert(content_type, policy);
    }

    /// Update proof constraints.
    pub fn set_proof_constraints(&mut self, constraints: ProofConstraints) {
        self.proof_constraints = constraints;
    }

    /// Get current eviction policy.
    #[must_use]
    pub const fn eviction_policy(&self) -> EvictionPolicy {
        self.eviction_policy
    }
}

fn storage_policy_key(entry: &CacheEntry) -> &'static str {
    match (&entry.storage_location, entry.encrypted) {
        (super::StorageLocation::Memory(_), true) => "memory/encrypted",
        (super::StorageLocation::Memory(_), false) => "memory/plaintext",
        (super::StorageLocation::File(_), true) => "file/encrypted",
        (super::StorageLocation::File(_), false) => "file/plaintext",
        (super::StorageLocation::External(_), true) => "external/encrypted",
        (super::StorageLocation::External(_), false) => "external/plaintext",
    }
}

fn remaining_ttl(created_at: SystemTime, ttl: Duration) -> Option<Duration> {
    let age = created_at.elapsed().ok()?;
    Some(ttl.saturating_sub(age))
}

/// Retention policy for specific content types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Minimum time to retain content.
    pub min_retention: Duration,
    /// Maximum time to retain content.
    pub max_retention: Duration,
    /// Priority level for retention (higher = keep longer).
    pub priority: u32,
    /// Whether this content type is critical for proof integrity.
    pub critical_for_proofs: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            min_retention: Duration::from_secs(60 * 60), // 1 hour
            max_retention: Duration::from_secs(7 * 24 * 60 * 60), // 1 week
            priority: 5,                                 // Medium priority
            critical_for_proofs: false,
        }
    }
}

/// Constraints for preserving proof and journal invariants during eviction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConstraints {
    /// Whether to preserve entries with active proof bundles.
    pub preserve_proof_bundles: bool,
    /// Minimum age before verified content can be evicted.
    pub min_verification_age: Duration,
    /// Whether to preserve journal entries.
    pub preserve_journal_entries: bool,
    /// Minimum access count before considering eviction.
    pub min_access_count: u64,
}

impl Default for ProofConstraints {
    fn default() -> Self {
        Self {
            preserve_proof_bundles: true,
            min_verification_age: Duration::from_secs(5 * 60), // 5 minutes
            preserve_journal_entries: true,
            min_access_count: 0,
        }
    }
}

/// Cache maintenance scheduler for background cleanup.
#[derive(Debug)]
pub struct CacheMaintenanceScheduler {
    /// Last maintenance run.
    last_run: SystemTime,
    /// Maintenance interval.
    interval: Duration,
    /// Metrics from last maintenance.
    last_metrics: MaintenanceMetrics,
}

impl CacheMaintenanceScheduler {
    /// Create a new maintenance scheduler.
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            last_run: SystemTime::UNIX_EPOCH,
            interval,
            last_metrics: MaintenanceMetrics::default(),
        }
    }

    /// Check if maintenance is due.
    #[must_use]
    pub fn is_due(&self) -> bool {
        self.last_run.elapsed().unwrap_or(Duration::MAX) >= self.interval
    }

    /// Run maintenance tasks and return metrics.
    pub fn run_maintenance(
        &mut self,
        entries: &mut BTreeMap<String, CacheEntry>,
        _policy: &CachePolicyManager,
    ) -> MaintenanceMetrics {
        let start_time = SystemTime::now();
        let mut metrics = MaintenanceMetrics::default();

        // Remove expired entries atomically to prevent TOCTOU races
        // Perform expiration check and removal in single pass
        entries.retain(|_key, entry| {
            let elapsed = entry.created_at.elapsed().unwrap_or(Duration::MAX);
            let is_expired = elapsed > entry.ttl;

            if is_expired {
                metrics.expired_entries += 1;
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });

        // Clean up orphaned files
        // This would scan the cache directory and remove files not in the index

        // Update metrics
        self.last_run = SystemTime::now();
        metrics.duration = start_time.elapsed().unwrap_or(Duration::ZERO);
        self.last_metrics = metrics.clone();

        metrics
    }

    /// Get metrics from last maintenance run.
    #[must_use]
    pub const fn last_metrics(&self) -> &MaintenanceMetrics {
        &self.last_metrics
    }
}

/// Metrics from cache maintenance operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaintenanceMetrics {
    /// Number of expired entries removed.
    pub expired_entries: u64,
    /// Number of orphaned files cleaned up.
    pub orphaned_files: u64,
    /// Number of verification failures found.
    pub verification_failures: u64,
    /// Duration of maintenance operation.
    pub duration: Duration,
}

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn cache_maintenance_toctou_fix() {
        let policy = CachePolicyManager::new(EvictionPolicy::LeastRecentlyUsed);
        let mut maintenance = CacheMaintenanceScheduler::new(Duration::ZERO);

        let mut entries = BTreeMap::new();

        // Add an expired entry
        let expired_entry = CacheEntry {
            key: crate::atp::cache::CacheKey::new("m".to_string(), "expired".to_string(), None),
            size_bytes: 100,
            created_at: SystemTime::now() - Duration::from_secs(2000), // 2000 seconds ago
            last_accessed: SystemTime::now(),
            access_count: 1,
            ttl: Duration::from_secs(1000), // TTL of 1000 seconds (so it's expired)
            encrypted: true,
            storage_location: crate::atp::cache::StorageLocation::Memory("test:key".to_string()),
            verification: crate::atp::cache::VerificationMetadata {
                content_verified: true,
                manifest_verified: true,
                proof_location: None,
                verified_at: Some(SystemTime::now()),
            },
        };

        // Add a valid (non-expired) entry
        let valid_entry = CacheEntry {
            key: crate::atp::cache::CacheKey::new("m".to_string(), "valid".to_string(), None),
            size_bytes: 200,
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 1,
            ttl: Duration::from_secs(86400), // 24 hours TTL (not expired)
            encrypted: true,
            storage_location: crate::atp::cache::StorageLocation::Memory("test:key".to_string()),
            verification: crate::atp::cache::VerificationMetadata {
                content_verified: true,
                manifest_verified: true,
                proof_location: None,
                verified_at: Some(SystemTime::now()),
            },
        };

        entries.insert("expired".to_string(), expired_entry);
        entries.insert("valid".to_string(), valid_entry);

        assert_eq!(entries.len(), 2);

        // Run maintenance - should remove expired entry but keep valid one
        let metrics = maintenance.run_maintenance(&mut entries, &policy);

        // Should have removed exactly 1 expired entry
        assert_eq!(metrics.expired_entries, 1);
        assert_eq!(entries.len(), 1);

        // Should still have the valid entry
        assert!(entries.contains_key("valid"));
        assert!(!entries.contains_key("expired"));
    }

    #[test]
    fn eviction_policy_lru_ordering() {
        let mut manager = CachePolicyManager::new(EvictionPolicy::LeastRecentlyUsed);

        let mut entries = BTreeMap::new();

        let old_entry = CacheEntry {
            key: crate::atp::cache::CacheKey::new("m".to_string(), "c1".to_string(), None),
            size_bytes: 100,
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now() - Duration::from_secs(3600), // 1 hour ago
            access_count: 1,
            ttl: Duration::from_secs(86400),
            encrypted: true,
            storage_location: crate::atp::cache::StorageLocation::Memory("test:key".to_string()),
            verification: crate::atp::cache::VerificationMetadata {
                content_verified: true,
                manifest_verified: true,
                proof_location: None,
                verified_at: Some(SystemTime::now()),
            },
        };

        let new_entry = CacheEntry {
            key: crate::atp::cache::CacheKey::new("m".to_string(), "c2".to_string(), None),
            size_bytes: 200,
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(), // Just accessed
            access_count: 5,
            ttl: Duration::from_secs(86400),
            encrypted: true,
            storage_location: crate::atp::cache::StorageLocation::Memory("test:key".to_string()),
            verification: crate::atp::cache::VerificationMetadata {
                content_verified: true,
                manifest_verified: true,
                proof_location: None,
                verified_at: Some(SystemTime::now()),
            },
        };

        entries.insert("old".to_string(), old_entry);
        entries.insert("new".to_string(), new_entry);

        let to_evict = manager.select_for_eviction(&entries, 150);

        // Should select the old entry first (LRU)
        assert!(!to_evict.is_empty());
        assert_eq!(to_evict[0], "old");
    }

    #[test]
    fn proof_constraints_prevent_eviction() {
        let mut manager = CachePolicyManager::new(EvictionPolicy::LeastRecentlyUsed);

        let constraints = ProofConstraints {
            preserve_proof_bundles: true,
            min_verification_age: Duration::from_secs(300), // 5 minutes
            preserve_journal_entries: true,
            min_access_count: 0,
        };
        manager.set_proof_constraints(constraints);

        let entry_with_proof = CacheEntry {
            key: crate::atp::cache::CacheKey::new("m".to_string(), "c1".to_string(), None),
            size_bytes: 100,
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now() - Duration::from_secs(3600),
            access_count: 1,
            ttl: Duration::from_secs(86400),
            encrypted: true,
            storage_location: crate::atp::cache::StorageLocation::Memory("test:key".to_string()),
            verification: crate::atp::cache::VerificationMetadata {
                content_verified: true,
                manifest_verified: true,
                proof_location: Some("proof123".to_string()), // Has proof bundle
                verified_at: Some(SystemTime::now()),
            },
        };

        assert!(!manager.can_evict_safely(&entry_with_proof));
    }

    #[test]
    fn maintenance_scheduler_timing() {
        let mut scheduler = CacheMaintenanceScheduler::new(Duration::from_secs(3600));
        assert!(scheduler.is_due()); // Should be due initially

        scheduler.last_run = SystemTime::now();
        assert!(!scheduler.is_due()); // Should not be due immediately after run
    }

    #[test]
    fn retention_policy_defaults() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.min_retention, Duration::from_secs(60 * 60));
        assert!(!policy.critical_for_proofs);
        assert_eq!(policy.priority, 5);
    }
}
