//! DNS caching layer.
//!
//! Provides a thread-safe cache for DNS lookup results with TTL-based expiration.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::lookup::LookupIp;

/// Configuration for the DNS cache.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in the cache.
    pub max_entries: usize,
    /// Minimum TTL (floor) for cache entries.
    pub min_ttl: Duration,
    /// Maximum TTL (ceiling) for cache entries.
    pub max_ttl: Duration,
    /// TTL for negative cache entries (NXDOMAIN).
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(86400), // 24 hours
            negative_ttl: Duration::from_secs(30),
        }
    }
}

/// A cache entry with expiration time.
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    data: T,
    expires_at: Instant,
    inserted_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(data: T, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            data,
            expires_at: now + ttl,
            inserted_at: now,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// Thread-safe DNS cache.
#[derive(Debug)]
pub struct DnsCache {
    ip_cache: RwLock<HashMap<String, CacheEntry<LookupIp>>>,
    config: CacheConfig,
    stats: RwLock<CacheStats>,
}

impl DnsCache {
    /// Creates a new DNS cache with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Creates a new DNS cache with custom configuration.
    #[must_use]
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            ip_cache: RwLock::new(HashMap::new()),
            config,
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Looks up an IP address result from the cache.
    pub fn get_ip(&self, host: &str) -> Option<LookupIp> {
        let entry = {
            let cache = self.ip_cache.read().expect("cache lock poisoned");
            cache.get(host).cloned()
        };

        match entry {
            Some(entry) if !entry.is_expired() => {
                self.stats.write().expect("stats lock poisoned").hits += 1;

                // Clone and return with original TTL for simplicity
                // A more sophisticated implementation would adjust the TTL
                Some(entry.data)
            }
            Some(_) => {
                let mut refreshed: Option<LookupIp> = None;
                let mut evicted = false;
                {
                    let mut cache = self.ip_cache.write().expect("cache lock poisoned");
                    if let Some(entry) = cache.get(host) {
                        if entry.is_expired() {
                            cache.remove(host);
                            evicted = true;
                        } else {
                            refreshed = Some(entry.data.clone());
                        }
                    }
                }

                let mut stats = self.stats.write().expect("stats lock poisoned");
                if let Some(data) = refreshed {
                    stats.hits += 1;
                    return Some(data);
                }
                stats.misses += 1;
                if evicted {
                    stats.evictions += 1;
                }
                None
            }
            None => {
                self.stats.write().expect("stats lock poisoned").misses += 1;
                None
            }
        }
    }

    /// Inserts an IP address lookup result into the cache.
    pub fn put_ip(&self, host: &str, lookup: &LookupIp) {
        let ttl = self.clamp_ttl(lookup.ttl());

        let mut cache = self.ip_cache.write().expect("cache lock poisoned");

        // Evict if at capacity
        if cache.len() >= self.config.max_entries {
            self.evict_expired_locked(&mut cache);

            // If still at capacity, remove oldest
            if cache.len() >= self.config.max_entries {
                if let Some(oldest_key) = Self::find_oldest_key(&cache) {
                    cache.remove(&oldest_key);
                    let mut stats = self.stats.write().expect("stats lock poisoned");
                    stats.evictions += 1;
                }
            }
        }

        cache.insert(host.to_string(), CacheEntry::new(lookup.clone(), ttl));
    }

    /// Removes an entry from the cache.
    pub fn remove(&self, host: &str) {
        let mut cache = self.ip_cache.write().expect("cache lock poisoned");
        cache.remove(host);
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        {
            let mut cache = self.ip_cache.write().expect("cache lock poisoned");
            cache.clear();
        }

        {
            let mut stats = self.stats.write().expect("stats lock poisoned");
            *stats = CacheStats::default();
        }
    }

    /// Evicts expired entries from the cache.
    pub fn evict_expired(&self) {
        let mut cache = self.ip_cache.write().expect("cache lock poisoned");
        self.evict_expired_locked(&mut cache);
    }

    /// Returns cache statistics.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn stats(&self) -> CacheStats {
        let cache = self.ip_cache.read().expect("cache lock poisoned");
        let stats = self.stats.read().expect("stats lock poisoned");

        CacheStats {
            size: cache.len(),
            hits: stats.hits,
            misses: stats.misses,
            evictions: stats.evictions,
            hit_rate: if stats.hits + stats.misses > 0 {
                stats.hits as f64 / (stats.hits + stats.misses) as f64
            } else {
                0.0
            },
        }
    }

    fn clamp_ttl(&self, ttl: Duration) -> Duration {
        ttl.max(self.config.min_ttl).min(self.config.max_ttl)
    }

    fn evict_expired_locked(&self, cache: &mut HashMap<String, CacheEntry<LookupIp>>) {
        let before = cache.len();
        cache.retain(|_, entry| !entry.is_expired());
        let evicted = before - cache.len();

        if evicted > 0 {
            let mut stats = self.stats.write().expect("stats lock poisoned");
            stats.evictions += evicted as u64;
        }
    }

    fn find_oldest_key(cache: &HashMap<String, CacheEntry<LookupIp>>) -> Option<String> {
        cache
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(key, _)| key.clone())
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about cache usage.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of entries currently in the cache.
    pub size: usize,
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of entries evicted.
    pub evictions: u64,
    /// Hit rate (hits / (hits + misses)).
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn cache_hit_miss() {
        init_test("cache_hit_miss");
        let cache = DnsCache::new();

        // Miss
        let miss = cache.get_ip("example.com");
        crate::assert_with_log!(miss.is_none(), "cache miss", true, miss.is_none());
        let misses = cache.stats().misses;
        crate::assert_with_log!(misses == 1, "misses", 1, misses);
        let hits = cache.stats().hits;
        crate::assert_with_log!(hits == 0, "hits", 0, hits);

        // Insert
        let lookup = LookupIp::new(
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
            Duration::from_secs(300),
        );
        cache.put_ip("example.com", &lookup);

        // Hit
        let result = cache.get_ip("example.com");
        crate::assert_with_log!(result.is_some(), "cache hit", true, result.is_some());
        let hits = cache.stats().hits;
        crate::assert_with_log!(hits == 1, "hits", 1, hits);
        crate::test_complete!("cache_hit_miss");
    }

    #[test]
    fn cache_expiration() {
        init_test("cache_expiration");
        let config = CacheConfig {
            min_ttl: Duration::from_millis(1),
            max_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let cache = DnsCache::with_config(config);

        let lookup = LookupIp::new(
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
            Duration::from_millis(1), // Very short TTL
        );
        cache.put_ip("example.com", &lookup);

        // Should be in cache immediately
        let immediate = cache.get_ip("example.com");
        crate::assert_with_log!(
            immediate.is_some(),
            "immediate hit",
            true,
            immediate.is_some()
        );

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Should be expired
        let expired = cache.get_ip("example.com");
        crate::assert_with_log!(expired.is_none(), "expired", true, expired.is_none());
        let size = cache.stats().size;
        crate::assert_with_log!(size == 0, "expired evicted", 0, size);
        crate::test_complete!("cache_expiration");
    }

    #[test]
    fn cache_clear() {
        init_test("cache_clear");
        let cache = DnsCache::new();

        let lookup = LookupIp::new(
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
            Duration::from_secs(300),
        );
        cache.put_ip("example.com", &lookup);
        let size = cache.stats().size;
        crate::assert_with_log!(size > 0, "size > 0", ">0", size);

        cache.clear();
        let size = cache.stats().size;
        crate::assert_with_log!(size == 0, "size 0", 0, size);
        crate::test_complete!("cache_clear");
    }

    #[test]
    fn cache_ttl_clamping() {
        init_test("cache_ttl_clamping");
        let config = CacheConfig {
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(3600),
            ..Default::default()
        };
        let cache = DnsCache::with_config(config);

        // TTL below minimum should be clamped
        let lookup = LookupIp::new(
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
            Duration::from_secs(10), // Below minimum
        );
        cache.put_ip("example.com", &lookup);

        // Entry should exist
        let result = cache.get_ip("example.com");
        crate::assert_with_log!(result.is_some(), "entry exists", true, result.is_some());
        crate::test_complete!("cache_ttl_clamping");
    }
}
