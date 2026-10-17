//! DNS caching layer.
//!
//! Provides a thread-safe cache for DNS lookup results with TTL-based expiration.

use crate::types::Time;
use parking_lot::RwLock;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::error::DnsError;
use super::lookup::LookupIp;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

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
            min_ttl: Duration::from_mins(1),
            max_ttl: Duration::from_hours(24), // 24 hours
            negative_ttl: Duration::from_secs(30),
        }
    }
}

/// A cache entry with expiration time.
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    data: T,
    expires_at: Time,
    inserted_at: Time,
}

impl<T> CacheEntry<T> {
    fn new_at(data: T, ttl: Duration, now: Time) -> Self {
        Self {
            data,
            expires_at: now.saturating_add_nanos(duration_to_nanos(ttl)),
            inserted_at: now,
        }
    }

    fn is_expired_at(&self, now: Time) -> bool {
        now >= self.expires_at
    }
}

#[derive(Debug, Clone)]
enum CachedIpEntry {
    Positive(LookupIp),
    NegativeNoRecords,
}

/// Thread-safe DNS cache.
#[derive(Debug)]
pub struct DnsCache {
    ip_cache: RwLock<HashMap<String, CacheEntry<CachedIpEntry>>>,
    config: CacheConfig,
    time_getter: fn() -> Time,
    stat_hits: AtomicU64,
    stat_misses: AtomicU64,
    stat_evictions: AtomicU64,
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
        Self::with_time_getter(config, wall_clock_now)
    }

    /// Creates a new DNS cache with a custom configuration and time source.
    #[must_use]
    pub fn with_time_getter(config: CacheConfig, time_getter: fn() -> Time) -> Self {
        Self {
            ip_cache: RwLock::new(HashMap::new()),
            config,
            time_getter,
            stat_hits: AtomicU64::new(0),
            stat_misses: AtomicU64::new(0),
            stat_evictions: AtomicU64::new(0),
        }
    }

    /// Returns the time source used by this cache.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }

    fn get_ip_entry(&self, host: &str) -> Option<CachedIpEntry> {
        let key = normalize_host_key(host);
        let now = (self.time_getter)();

        // Fast path: check expiry under read lock, clone only the data.
        {
            let cache = self.ip_cache.read();
            if let Some(entry) = cache.get(key.as_ref()) {
                if !entry.is_expired_at(now) {
                    self.stat_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry.data.clone());
                }
            } else {
                self.stat_misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        // Slow path: entry was expired — upgrade to write lock to evict.
        let mut evicted_expired = false;
        let refreshed = {
            let mut cache = self.ip_cache.write();
            let expired = cache
                .get(key.as_ref())
                .is_some_and(|entry| entry.is_expired_at(now));
            if expired {
                cache.remove(key.as_ref());
                evicted_expired = true;
                None
            } else {
                // Another thread may have refreshed the entry between locks.
                cache.get(key.as_ref()).map(|entry| entry.data.clone())
            }
        };
        if evicted_expired {
            self.stat_evictions.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(data) = refreshed {
            self.stat_hits.fetch_add(1, Ordering::Relaxed);
            return Some(data);
        }
        self.stat_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Looks up an IP address result from the cache.
    pub fn get_ip(&self, host: &str) -> Option<LookupIp> {
        match self.get_ip_entry(host)? {
            CachedIpEntry::Positive(lookup) => Some(lookup),
            CachedIpEntry::NegativeNoRecords => None,
        }
    }

    /// Looks up a cached IP result, including negative no-record entries.
    pub fn get_ip_result(&self, host: &str) -> Option<Result<LookupIp, DnsError>> {
        Some(match self.get_ip_entry(host)? {
            CachedIpEntry::Positive(lookup) => Ok(lookup),
            CachedIpEntry::NegativeNoRecords => Err(DnsError::NoRecords(host.to_string())),
        })
    }

    fn put_ip_entry(&self, host: &str, entry: CachedIpEntry, ttl: Duration) {
        if self.config.max_entries == 0 {
            let evicted = {
                let mut cache = self.ip_cache.write();
                if cache.is_empty() {
                    0
                } else {
                    let evicted = cache.len();
                    cache.clear();
                    evicted
                }
            };
            if evicted > 0 {
                self.stat_evictions
                    .fetch_add(evicted as u64, Ordering::Relaxed);
            }
            return;
        }

        let key = normalize_host_key(host);
        let now = (self.time_getter)();

        let mut cache = self.ip_cache.write();
        let is_update = cache.contains_key(key.as_ref());

        // Evict only when inserting a new key at capacity.
        // Updating an existing key must not evict unrelated entries.
        if !is_update && cache.len() >= self.config.max_entries {
            self.evict_expired_locked(&mut cache, now);

            // If still at capacity, remove oldest
            if cache.len() >= self.config.max_entries {
                if let Some(oldest_key) = Self::find_oldest_key(&cache) {
                    cache.remove(&oldest_key);
                    self.stat_evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        cache.insert(key.into_owned(), CacheEntry::new_at(entry, ttl, now));
    }

    /// Inserts an IP address lookup result into the cache.
    pub fn put_ip(&self, host: &str, lookup: &LookupIp) {
        if lookup.ttl().is_zero() {
            self.remove(host);
            return;
        }

        let ttl = self.clamp_ttl(lookup.ttl());
        self.put_ip_entry(host, CachedIpEntry::Positive(lookup.clone()), ttl);
    }

    /// Inserts a negative no-record result into the cache.
    pub fn put_negative_ip_no_records(&self, host: &str) {
        if self.config.negative_ttl.is_zero() {
            self.remove(host);
            return;
        }

        let ttl = self.clamp_negative_ttl(self.config.negative_ttl);
        if ttl.is_zero() {
            self.remove(host);
            return;
        }
        self.put_ip_entry(host, CachedIpEntry::NegativeNoRecords, ttl);
    }

    /// Removes an entry from the cache.
    pub fn remove(&self, host: &str) {
        let key = normalize_host_key(host);
        let mut cache = self.ip_cache.write();
        cache.remove(key.as_ref());
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        let mut cache = self.ip_cache.write();
        cache.clear();
        drop(cache);

        self.stat_hits.store(0, Ordering::Relaxed);
        self.stat_misses.store(0, Ordering::Relaxed);
        self.stat_evictions.store(0, Ordering::Relaxed);
    }

    /// Evicts expired entries from the cache.
    pub fn evict_expired(&self) {
        let now = (self.time_getter)();
        let mut cache = self.ip_cache.write();
        self.evict_expired_locked(&mut cache, now);
    }

    /// Returns cache statistics.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn stats(&self) -> CacheStats {
        let cache = self.ip_cache.read();
        let hits = self.stat_hits.load(Ordering::Relaxed);
        let misses = self.stat_misses.load(Ordering::Relaxed);
        let evictions = self.stat_evictions.load(Ordering::Relaxed);

        CacheStats {
            size: cache.len(),
            hits,
            misses,
            evictions,
            hit_rate: if hits + misses > 0 {
                hits as f64 / (hits + misses) as f64
            } else {
                0.0
            },
        }
    }

    fn clamp_ttl(&self, ttl: Duration) -> Duration {
        ttl.max(self.config.min_ttl).min(self.config.max_ttl)
    }

    fn clamp_negative_ttl(&self, ttl: Duration) -> Duration {
        // `negative_ttl` is already an explicit policy knob for NXDOMAIN/no-record
        // caching. The positive-answer minimum TTL must not extend failures.
        ttl.min(self.config.max_ttl)
    }

    fn evict_expired_locked(
        &self,
        cache: &mut HashMap<String, CacheEntry<CachedIpEntry>>,
        now: Time,
    ) {
        let before = cache.len();
        cache.retain(|_, entry| !entry.is_expired_at(now));
        let evicted = before - cache.len();

        if evicted > 0 {
            self.stat_evictions
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }

    fn find_oldest_key(cache: &HashMap<String, CacheEntry<CachedIpEntry>>) -> Option<String> {
        cache
            .iter()
            .min_by(|(left_key, left_entry), (right_key, right_entry)| {
                left_entry
                    .inserted_at
                    .cmp(&right_entry.inserted_at)
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, _)| key.clone())
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_host_key(host: &str) -> Cow<'_, str> {
    if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(host.to_ascii_lowercase())
    } else {
        Cow::Borrowed(host)
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
#[path = "cache_inline_tests.rs"]
mod tests;
