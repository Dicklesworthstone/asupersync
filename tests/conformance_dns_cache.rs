//! Conformance tests for DNS cache TTL eviction and NXDOMAIN negative caching.
//!
//! These tests verify the expected behavior and contracts for the DNS cache,
//! including TTL-based expiration, negative caching of NXDOMAIN results,
//! LRU eviction policies, and configuration validation.
//!
//! The tests cover both positive and negative caching scenarios with various
//! TTL configurations and capacity constraints.

use asupersync::net::dns::{CacheConfig, DnsCache, DnsError, LookupIp};
use asupersync::types::Time;
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Test time source for deterministic cache testing
thread_local! {
    static TEST_TIME: Cell<u64> = const { Cell::new(0) };
}

fn test_time() -> Time {
    Time::from_nanos(TEST_TIME.with(Cell::get))
}

fn advance_time_by(duration: Duration) {
    let nanos = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
    TEST_TIME.with(|time| time.set(time.get().saturating_add(nanos)));
}

fn set_test_time(nanos: u64) {
    TEST_TIME.with(|time| time.set(nanos));
}

/// Helper to create a test lookup result
fn create_test_lookup(_host: &str, ip: IpAddr, ttl: Duration) -> LookupIp {
    LookupIp::new(vec![ip], ttl)
}

/// Conformance test contracts for DNS cache behavior
pub trait DnsCacheConformance {
    /// Create a cache with custom configuration and time source
    fn create_cache(config: CacheConfig, time_getter: fn() -> Time) -> Self;

    /// Insert a positive IP lookup result
    fn cache_positive_result(&self, host: &str, lookup: &LookupIp);

    /// Insert a negative NXDOMAIN result
    fn cache_negative_result(&self, host: &str);

    /// Retrieve cached IP result (positive only)
    fn get_cached_ip(&self, host: &str) -> Option<LookupIp>;

    /// Retrieve cached result including negative entries
    fn get_cached_result(&self, host: &str) -> Option<Result<LookupIp, DnsError>>;

    /// Force expiry cleanup
    fn evict_expired_entries(&self);

    /// Get cache statistics
    fn get_statistics(&self) -> (usize, u64, u64, u64, f64); // size, hits, misses, evictions, hit_rate

    /// Clear all cache entries
    fn clear_cache(&self);

    /// Remove specific entry
    fn remove_entry(&self, host: &str);
}

impl DnsCacheConformance for DnsCache {
    fn create_cache(config: CacheConfig, time_getter: fn() -> Time) -> Self {
        DnsCache::with_time_getter(config, time_getter)
    }

    fn cache_positive_result(&self, host: &str, lookup: &LookupIp) {
        self.put_ip(host, lookup);
    }

    fn cache_negative_result(&self, host: &str) {
        self.put_negative_ip_no_records(host);
    }

    fn get_cached_ip(&self, host: &str) -> Option<LookupIp> {
        self.get_ip(host)
    }

    fn get_cached_result(&self, host: &str) -> Option<Result<LookupIp, DnsError>> {
        self.get_ip_result(host)
    }

    fn evict_expired_entries(&self) {
        self.evict_expired();
    }

    fn get_statistics(&self) -> (usize, u64, u64, u64, f64) {
        let stats = self.stats();
        (
            stats.size,
            stats.hits,
            stats.misses,
            stats.evictions,
            stats.hit_rate,
        )
    }

    fn clear_cache(&self) {
        self.clear();
    }

    fn remove_entry(&self, host: &str) {
        self.remove(host);
    }
}

#[test]
fn test_ttl_expiration_behavior() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(10),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(30),
    };
    let cache = DnsCache::create_cache(config, test_time);

    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let lookup = create_test_lookup("example.com", ip, Duration::from_secs(60));

    // Cache a positive result
    cache.cache_positive_result("example.com", &lookup);

    // Verify it's retrievable immediately
    assert!(cache.get_cached_ip("example.com").is_some());
    let (size, hits, misses, _, _) = cache.get_statistics();
    assert_eq!(size, 1);
    assert_eq!(hits, 1);
    assert_eq!(misses, 0);

    // Advance time to just before expiration
    advance_time_by(Duration::from_secs(59));
    assert!(cache.get_cached_ip("example.com").is_some());
    let (size, hits, misses, evictions, _) = cache.get_statistics();
    assert_eq!(size, 1);
    assert_eq!(hits, 2);
    assert_eq!(misses, 0);
    assert_eq!(evictions, 0);

    // Advance time past expiration
    advance_time_by(Duration::from_secs(2));
    assert!(cache.get_cached_ip("example.com").is_none());
    let (size, hits, misses, evictions, _) = cache.get_statistics();
    assert_eq!(size, 0); // Entry should be removed
    assert_eq!(hits, 2);
    assert_eq!(misses, 1);
    assert_eq!(evictions, 1); // Expired entry evicted
}

#[test]
fn test_ttl_clamping_min_max() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(300),  // 5 minutes minimum
        max_ttl: Duration::from_secs(1800), // 30 minutes maximum
        negative_ttl: Duration::from_secs(60),
    };
    let cache = DnsCache::create_cache(config, test_time);

    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Test TTL below minimum gets clamped to min_ttl
    let short_lookup = create_test_lookup("short.com", ip, Duration::from_secs(10)); // Below min_ttl
    cache.cache_positive_result("short.com", &short_lookup);

    // Should still be cached after original TTL expires but before min_ttl
    advance_time_by(Duration::from_secs(200)); // 3+ minutes, past original but under min_ttl
    assert!(cache.get_cached_ip("short.com").is_some());

    // Test TTL above maximum gets clamped to max_ttl
    let long_lookup = create_test_lookup("long.com", ip, Duration::from_secs(7200)); // Above max_ttl
    cache.cache_positive_result("long.com", &long_lookup);

    // Should be expired after max_ttl from long.com insertion even though original was longer.
    advance_time_by(Duration::from_secs(1801));
    assert!(cache.get_cached_ip("long.com").is_none());
}

#[test]
fn test_nxdomain_negative_caching() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(10),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(120), // 2 minutes for negative results
    };
    let cache = DnsCache::create_cache(config, test_time);

    // Cache a negative result (NXDOMAIN)
    cache.cache_negative_result("nonexistent.com");

    // Verify negative result is cached
    match cache.get_cached_result("nonexistent.com") {
        Some(Err(DnsError::NoRecords(_))) => {} // Expected
        other => panic!("Expected cached negative result, got: {:?}", other),
    }

    // Should return None for get_ip (positive results only)
    assert!(cache.get_cached_ip("nonexistent.com").is_none());

    let (size, hits, misses, evictions, hit_rate) = cache.get_statistics();
    assert_eq!(size, 1);
    assert_eq!(hits, 2);
    assert_eq!(misses, 0);
    assert_eq!(evictions, 0);
    assert!(hit_rate > 0.0);

    // Advance time past negative TTL
    advance_time_by(Duration::from_secs(130));

    // Negative result should be expired
    assert!(cache.get_cached_result("nonexistent.com").is_none());
    let (size, hits, misses, evictions, _) = cache.get_statistics();
    assert_eq!(size, 0);
    assert_eq!(hits, 2);
    assert_eq!(misses, 1);
    assert_eq!(evictions, 1);
}

#[test]
fn test_cache_capacity_and_lru_eviction() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 3, // Small capacity to test eviction
        min_ttl: Duration::from_secs(10),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(60),
    };
    let cache = DnsCache::create_cache(config, test_time);

    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
    let ip4 = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4));

    // Fill cache to capacity
    cache.cache_positive_result(
        "host1.com",
        &create_test_lookup("host1.com", ip1, Duration::from_secs(300)),
    );
    advance_time_by(Duration::from_millis(10)); // Ensure different insertion times
    cache.cache_positive_result(
        "host2.com",
        &create_test_lookup("host2.com", ip2, Duration::from_secs(300)),
    );
    advance_time_by(Duration::from_millis(10));
    cache.cache_positive_result(
        "host3.com",
        &create_test_lookup("host3.com", ip3, Duration::from_secs(300)),
    );

    let (size, _, _, evictions, _) = cache.get_statistics();
    assert_eq!(size, 3);
    assert_eq!(evictions, 0);

    // All entries should be retrievable
    assert!(cache.get_cached_ip("host1.com").is_some());
    assert!(cache.get_cached_ip("host2.com").is_some());
    assert!(cache.get_cached_ip("host3.com").is_some());

    advance_time_by(Duration::from_millis(10));

    // Adding fourth entry should evict oldest (host1.com)
    cache.cache_positive_result(
        "host4.com",
        &create_test_lookup("host4.com", ip4, Duration::from_secs(300)),
    );

    let (size, _, _, evictions, _) = cache.get_statistics();
    assert_eq!(size, 3);
    assert_eq!(evictions, 1);

    // host1.com should be evicted, others should remain
    assert!(cache.get_cached_ip("host1.com").is_none());
    assert!(cache.get_cached_ip("host2.com").is_some());
    assert!(cache.get_cached_ip("host3.com").is_some());
    assert!(cache.get_cached_ip("host4.com").is_some());
}

#[test]
fn test_zero_capacity_cache() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 0, // Zero capacity - should not cache anything
        min_ttl: Duration::from_secs(10),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(60),
    };
    let cache = DnsCache::create_cache(config, test_time);

    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let lookup = create_test_lookup("google.com", ip, Duration::from_secs(300));

    // Try to cache a result
    cache.cache_positive_result("google.com", &lookup);

    // Should not be cached
    assert!(cache.get_cached_ip("google.com").is_none());
    let (size, hits, misses, _, _) = cache.get_statistics();
    assert_eq!(size, 0);
    assert_eq!(hits, 0);
    assert_eq!(misses, 1);

    // Try negative caching
    cache.cache_negative_result("nowhere.com");
    assert!(cache.get_cached_result("nowhere.com").is_none());
}

#[test]
fn test_zero_ttl_entries_not_cached() {
    set_test_time(0);

    let config = CacheConfig::default();
    let cache = DnsCache::create_cache(config, test_time);

    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    // Lookup with zero TTL should not be cached
    let zero_ttl_lookup = create_test_lookup("zero-ttl.com", ip, Duration::ZERO);
    cache.cache_positive_result("zero-ttl.com", &zero_ttl_lookup);

    assert!(cache.get_cached_ip("zero-ttl.com").is_none());
    let (size, _, _, _, _) = cache.get_statistics();
    assert_eq!(size, 0);

    // Same for negative caching with zero negative_ttl
    let zero_neg_config = CacheConfig {
        negative_ttl: Duration::ZERO,
        ..CacheConfig::default()
    };
    let zero_neg_cache = DnsCache::create_cache(zero_neg_config, test_time);

    zero_neg_cache.cache_negative_result("zero-neg.com");
    assert!(zero_neg_cache.get_cached_result("zero-neg.com").is_none());
}

#[test]
fn test_case_insensitive_host_matching() {
    set_test_time(0);

    let config = CacheConfig::default();
    let cache = DnsCache::create_cache(config, test_time);

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let lookup = create_test_lookup("Example.COM", ip, Duration::from_secs(300));

    // Cache with mixed case
    cache.cache_positive_result("Example.COM", &lookup);

    // Should be retrievable with different cases
    assert!(cache.get_cached_ip("example.com").is_some());
    assert!(cache.get_cached_ip("EXAMPLE.COM").is_some());
    assert!(cache.get_cached_ip("Example.Com").is_some());

    let (size, hits, misses, _, _) = cache.get_statistics();
    assert_eq!(size, 1); // Only one entry regardless of case variations
    assert_eq!(hits, 3);
    assert_eq!(misses, 0);
}

#[test]
fn test_cache_update_vs_new_entry_eviction() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 2,
        min_ttl: Duration::from_secs(10),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(60),
    };
    let cache = DnsCache::create_cache(config, test_time);

    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));

    // Fill cache to capacity
    cache.cache_positive_result(
        "host1.com",
        &create_test_lookup("host1.com", ip1, Duration::from_secs(300)),
    );
    advance_time_by(Duration::from_millis(10));
    cache.cache_positive_result(
        "host2.com",
        &create_test_lookup("host2.com", ip2, Duration::from_secs(300)),
    );

    let (size, _, _, evictions, _) = cache.get_statistics();
    assert_eq!(size, 2);
    assert_eq!(evictions, 0);

    advance_time_by(Duration::from_millis(10));

    // Update existing entry (should not trigger eviction)
    let updated_ip1 = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1));
    cache.cache_positive_result(
        "host1.com",
        &create_test_lookup("host1.com", updated_ip1, Duration::from_secs(300)),
    );

    let (size, _, _, evictions, _) = cache.get_statistics();
    assert_eq!(size, 2); // Still 2 entries
    assert_eq!(evictions, 0); // No evictions for update

    // Verify the entry was updated
    if let Some(lookup) = cache.get_cached_ip("host1.com") {
        assert!(lookup.iter().any(|&ip| ip == updated_ip1));
    } else {
        panic!("Updated entry should still be in cache");
    }

    advance_time_by(Duration::from_millis(10));

    // Adding new entry should trigger eviction of oldest
    cache.cache_positive_result(
        "host3.com",
        &create_test_lookup("host3.com", ip3, Duration::from_secs(300)),
    );

    let (size, _, _, evictions, _) = cache.get_statistics();
    assert_eq!(size, 2);
    assert_eq!(evictions, 1); // One eviction for new entry

    // host2.com should be evicted (oldest after update), host1.com and host3.com remain
    assert!(cache.get_cached_ip("host1.com").is_some());
    assert!(cache.get_cached_ip("host2.com").is_none());
    assert!(cache.get_cached_ip("host3.com").is_some());
}

#[test]
fn test_mixed_positive_negative_caching() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 10,
        min_ttl: Duration::from_secs(30),
        max_ttl: Duration::from_secs(1800),
        negative_ttl: Duration::from_secs(60),
    };
    let cache = DnsCache::create_cache(config, test_time);

    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let positive_lookup = create_test_lookup("exists.com", ip, Duration::from_secs(300));

    // Cache both positive and negative results
    cache.cache_positive_result("exists.com", &positive_lookup);
    cache.cache_negative_result("nonexistent.com");

    // Verify both types are cached correctly
    assert!(cache.get_cached_ip("exists.com").is_some());
    assert!(cache.get_cached_ip("nonexistent.com").is_none());

    match cache.get_cached_result("exists.com") {
        Some(Ok(_)) => {}
        other => panic!("Expected positive result, got: {:?}", other),
    }

    match cache.get_cached_result("nonexistent.com") {
        Some(Err(DnsError::NoRecords(_))) => {}
        other => panic!("Expected negative result, got: {:?}", other),
    }

    let (size, _, _, _, _) = cache.get_statistics();
    assert_eq!(size, 2);

    // Advance past negative TTL but not positive TTL
    advance_time_by(Duration::from_secs(90));

    // Positive should remain, negative should be expired
    assert!(cache.get_cached_ip("exists.com").is_some());
    assert!(cache.get_cached_result("nonexistent.com").is_none());

    let (size, _, _, evictions, _) = cache.get_statistics();
    assert_eq!(size, 1); // Only positive entry remains
    assert_eq!(evictions, 1); // Negative entry evicted
}

#[test]
fn test_explicit_eviction_and_clear() {
    set_test_time(0);

    let config = CacheConfig::default();
    let cache = DnsCache::create_cache(config, test_time);

    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let lookup1 = create_test_lookup("temp1.com", ip, Duration::from_secs(100));
    let lookup2 = create_test_lookup("temp2.com", ip, Duration::from_secs(200));

    cache.cache_positive_result("temp1.com", &lookup1);
    cache.cache_positive_result("temp2.com", &lookup2);
    cache.cache_negative_result("temp3.com");

    let (size, _, _, _, _) = cache.get_statistics();
    assert_eq!(size, 3);

    // Test explicit removal
    cache.remove_entry("temp1.com");
    assert!(cache.get_cached_ip("temp1.com").is_none());
    assert!(cache.get_cached_ip("temp2.com").is_some());

    let (size, _, _, _, _) = cache.get_statistics();
    assert_eq!(size, 2);

    // Test manual expiry eviction
    advance_time_by(Duration::from_secs(150)); // temp1 would be expired, temp2 still valid
    cache.evict_expired_entries();

    // temp3's negative entry should be expired (TTL 30 seconds by default)
    assert!(cache.get_cached_ip("temp2.com").is_some());
    assert!(cache.get_cached_result("temp3.com").is_none());

    let (size, _, _, evictions, _) = cache.get_statistics();
    assert_eq!(size, 1); // Only temp2 remains
    assert_eq!(evictions, 1); // temp3 evicted

    // Test cache clear
    cache.clear_cache();
    let (size, hits, misses, evictions, hit_rate) = cache.get_statistics();
    assert_eq!(size, 0);
    assert_eq!(hits, 0); // Stats reset
    assert_eq!(misses, 0);
    assert_eq!(evictions, 0);
    assert!((hit_rate).abs() < f64::EPSILON);
}

#[test]
fn test_statistics_accuracy() {
    set_test_time(0);

    let config = CacheConfig::default();
    let cache = DnsCache::create_cache(config, test_time);

    let (size, hits, misses, evictions, hit_rate) = cache.get_statistics();
    assert_eq!(size, 0);
    assert_eq!(hits, 0);
    assert_eq!(misses, 0);
    assert_eq!(evictions, 0);
    assert!((hit_rate).abs() < f64::EPSILON);

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let lookup = create_test_lookup("stats.com", ip, Duration::from_secs(300));

    // Cache miss
    assert!(cache.get_cached_ip("stats.com").is_none());
    let (_, hits, misses, _, hit_rate) = cache.get_statistics();
    assert_eq!(hits, 0);
    assert_eq!(misses, 1);
    assert!((hit_rate).abs() < f64::EPSILON);

    // Cache result
    cache.cache_positive_result("stats.com", &lookup);

    // Cache hit
    assert!(cache.get_cached_ip("stats.com").is_some());
    let (size, hits, misses, _, hit_rate) = cache.get_statistics();
    assert_eq!(size, 1);
    assert_eq!(hits, 1);
    assert_eq!(misses, 1);
    assert!((hit_rate - 0.5).abs() < f64::EPSILON); // 1 hit / 2 total = 0.5

    // Another hit
    assert!(cache.get_cached_ip("stats.com").is_some());
    let (_, hits, misses, _, hit_rate) = cache.get_statistics();
    assert_eq!(hits, 2);
    assert_eq!(misses, 1);
    assert!((hit_rate - (2.0 / 3.0)).abs() < f64::EPSILON); // 2 hits / 3 total = 0.667

    // Expire entry and trigger eviction stat
    advance_time_by(Duration::from_secs(400));
    assert!(cache.get_cached_ip("stats.com").is_none());
    let (size, hits, misses, evictions, _) = cache.get_statistics();
    assert_eq!(size, 0);
    assert_eq!(hits, 2);
    assert_eq!(misses, 2); // +1 for the miss after expiry
    assert_eq!(evictions, 1); // Expired entry evicted
}
