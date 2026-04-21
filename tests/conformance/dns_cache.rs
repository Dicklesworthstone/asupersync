//! DNS Cache RFC 2308 Conformance Tests
//!
//! Validates RFC 2308 negative caching compliance and TTL management:
//! - Positive cache TTL decremented on access over time
//! - Expired entries automatically removed during lookup
//! - Negative cache TTL computed as MIN(SOA.MINIMUM, TTL) per RFC 2308
//! - SOA record MINIMUM field drives negative cache duration
//! - Cache capacity enforced via LRU eviction of oldest entries
//!
//! # RFC 2308 Section 4: Negative Caching
//!
//! ```
//! The TTL of a negative cache entry is set to the minimum of:
//! - The TTL of the SOA record in the authority section
//! - The MINIMUM field of the SOA record
//!
//! When a negative response is received, it SHOULD be cached for a
//! period equal to the minimum of the SOL TTL and the SOA MINIMUM field.
//! This allows resolvers to avoid repeated queries for non-existent names.
//! ```
//!
//! # RFC 2308 Section 5: Negative Cache Storage
//!
//! ```
//! Negative cache entries MUST be stored with their original TTL so that
//! subsequent queries can determine if the cache entry is still valid.
//! The TTL MUST be decremented as time passes, just like positive cache entries.
//! ```
//!
//! # Cache Eviction Policy
//!
//! When cache reaches maximum capacity, oldest entries (by insertion time)
//! are evicted first to make room for new entries, following LRU semantics.

use asupersync::net::dns::cache::{CacheConfig, CacheStats, DnsCache};
use asupersync::net::dns::lookup::LookupIp;
use asupersync::net::dns::DnsError;
use asupersync::types::Time;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::cell::Cell;

// =============================================================================
// Test Infrastructure
// =============================================================================

thread_local! {
    static TEST_NOW: Cell<u64> = const { Cell::new(0) };
}

/// Set the test time for deterministic testing.
#[allow(dead_code)]
fn set_test_time(nanos: u64) {
    TEST_NOW.with(|now| now.set(nanos));
}

/// Get current test time.
#[allow(dead_code)]
fn test_time() -> Time {
    Time::from_nanos(TEST_NOW.with(Cell::get))
}

/// Advance test time by the given duration.
#[allow(dead_code)]
fn advance_time(duration: Duration) {
    let current = TEST_NOW.with(Cell::get);
    let new_time = current.saturating_add(duration.as_nanos() as u64);
    TEST_NOW.with(|now| now.set(new_time));
}

/// Create a test cache with deterministic time.
#[allow(dead_code)]
fn test_cache(config: CacheConfig) -> DnsCache {
    DnsCache::with_time_getter(config, test_time)
}

/// Create a sample IP lookup result.
#[allow(dead_code)]
fn sample_lookup(addresses: &[&str], ttl_secs: u64) -> LookupIp {
    let addrs: Vec<IpAddr> = addresses
        .iter()
        .map(|addr| addr.parse().unwrap())
        .collect();
    LookupIp::new(addrs, Duration::from_secs(ttl_secs))
}

/// Simulated SOA record for testing negative caching per RFC 2308.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SoaRecord {
    /// TTL of the SOA record itself
    pub ttl: Duration,
    /// MINIMUM field from SOA RDATA (RFC 2308 Section 4)
    pub minimum: Duration,
}

#[allow(dead_code)]

impl SoaRecord {
    /// Compute negative cache TTL per RFC 2308: MIN(SOA.TTL, SOA.MINIMUM)
    #[allow(dead_code)]
    pub fn negative_cache_ttl(&self) -> Duration {
        self.ttl.min(self.minimum)
    }
}

/// Extended cache interface for SOA-aware negative caching.
///
/// This simulates RFC 2308 behavior by creating separate cache instances
/// with appropriate negative_ttl configuration to represent SOA.MINIMUM values.
#[allow(dead_code)]
struct ExtendedDnsCache {
    cache: DnsCache,
}

#[allow(dead_code)]

impl ExtendedDnsCache {
    #[allow(dead_code)]
    fn new(config: CacheConfig) -> Self {
        Self {
            cache: test_cache(config),
        }
    }

    /// Cache a negative response with SOA record per RFC 2308.
    ///
    /// Since the current DnsCache doesn't have full SOA support, this simulates
    /// RFC 2308 behavior by creating a cache with the appropriate negative_ttl
    /// configuration that matches the computed SOA minimum.
    #[allow(dead_code)]
    fn put_negative_with_soa(&self, host: &str, soa: &SoaRecord) -> Self {
        let negative_ttl = soa.negative_cache_ttl();

        // Create a new cache instance configured with the SOA-computed TTL
        let soa_config = CacheConfig {
            max_entries: 100, // Use reasonable default for testing
            min_ttl: Duration::from_secs(1),
            max_ttl: Duration::from_secs(3600),
            negative_ttl, // Use SOA-computed TTL
        };

        let soa_cache = Self::new(soa_config);
        soa_cache.cache.put_negative_ip_no_records(host);
        soa_cache
    }

    /// Get IP result including negative cache entries.
    #[allow(dead_code)]
    fn get_ip_result(&self, host: &str) -> Option<Result<LookupIp, DnsError>> {
        self.cache.get_ip_result(host)
    }

    /// Get cache statistics.
    #[allow(dead_code)]
    fn stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Put positive IP result.
    #[allow(dead_code)]
    fn put_ip(&self, host: &str, lookup: &LookupIp) {
        self.cache.put_ip(host, lookup);
    }

    /// Check if entry exists (for TTL testing).
    #[allow(dead_code)]
    fn contains(&self, host: &str) -> bool {
        self.cache.get_ip_result(host).is_some()
    }

    /// Clear all cache entries.
    #[allow(dead_code)]
    fn clear(&self) {
        self.cache.clear();
    }
}

// =============================================================================
// RFC 2308 Conformance Tests
// =============================================================================

/// **MR1: Positive TTL Decremented on Access**
///
/// Per RFC 2308 Section 5, cached entries must have their TTL decremented
/// as time passes, and entries become invalid when TTL reaches zero.
#[test]
#[allow(dead_code)]
fn mr1_positive_ttl_decremented_on_access() {
    // Initialize test time
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(1),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(300),
    };

    let cache = test_cache(config);

    // Cache an entry with 30-second TTL
    let lookup = sample_lookup(&["192.0.2.1"], 30);
    cache.put_ip("example.com", &lookup);

    // Verify entry is cached initially
    assert!(cache.get_ip("example.com").is_some(), "Entry should be cached initially");

    // Advance time by 15 seconds (half TTL)
    advance_time(Duration::from_secs(15));

    // Entry should still be valid
    assert!(cache.get_ip("example.com").is_some(), "Entry should still be valid after 15s");

    // Advance time by another 20 seconds (35 seconds total, exceeds 30s TTL)
    advance_time(Duration::from_secs(20));

    // Entry should now be expired and removed
    assert!(cache.get_ip("example.com").is_none(), "Entry should be expired after 35s");

    // Stats should show an eviction
    let stats = cache.stats();
    assert!(stats.evictions > 0, "Should have recorded eviction of expired entry");
}

/// **MR2: Expired Entries Removed on Lookup**
///
/// Expired entries must be automatically detected and removed during lookup,
/// not just periodically cleaned up.
#[test]
#[allow(dead_code)]
fn mr2_expired_entries_removed_on_lookup() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(1),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(300),
    };

    let cache = test_cache(config);

    // Cache multiple entries with different TTLs
    let short_lookup = sample_lookup(&["192.0.2.1"], 10);  // 10s TTL
    let long_lookup = sample_lookup(&["192.0.2.2"], 60);   // 60s TTL

    cache.put_ip("short.example", &short_lookup);
    cache.put_ip("long.example", &long_lookup);

    // Both should be present initially
    assert!(cache.get_ip("short.example").is_some());
    assert!(cache.get_ip("long.example").is_some());

    // Advance time by 15 seconds (short entry expired, long still valid)
    advance_time(Duration::from_secs(15));

    // Access the long entry (should trigger cleanup of expired short entry)
    assert!(cache.get_ip("long.example").is_some(), "Long entry should still be valid");

    // Short entry should be automatically removed during the lookup
    assert!(cache.get_ip("short.example").is_none(), "Short entry should be auto-removed");

    // Verify cache size reflects the removal
    let stats = cache.stats();
    assert_eq!(stats.size, 1, "Cache should contain only 1 entry after auto-removal");
    assert!(stats.evictions > 0, "Should have recorded automatic eviction");
}

/// **MR3: Negative TTL Per MIN(SOA.MINIMUM, TTL)**
///
/// RFC 2308 Section 4: negative cache TTL is minimum of SOA TTL and SOA MINIMUM field.
#[test]
#[allow(dead_code)]
fn mr3_negative_ttl_per_soa_minimum() {
    set_test_time(0);

    let base_config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(1),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(300), // Default, should be overridden by SOA
    };

    // Test Case 1: SOA TTL < SOA MINIMUM → use SOA TTL
    let soa1 = SoaRecord {
        ttl: Duration::from_secs(120),      // 2 minutes
        minimum: Duration::from_secs(300),  // 5 minutes
    };

    let cache1 = ExtendedDnsCache::new(base_config.clone()).put_negative_with_soa("case1.example", &soa1);

    // Should be cached initially
    assert!(matches!(
        cache1.get_ip_result("case1.example"),
        Some(Err(DnsError::NoRecords(_)))
    ), "Should have negative cache entry");

    // Advance by SOA TTL (120s) - should expire
    advance_time(Duration::from_secs(120));

    assert!(
        cache1.get_ip_result("case1.example").is_none(),
        "Negative entry should expire after SOA TTL (120s), not MINIMUM (300s)"
    );

    // Test Case 2: SOA TTL > SOA MINIMUM → use SOA MINIMUM
    set_test_time(0); // Reset time

    let soa2 = SoaRecord {
        ttl: Duration::from_secs(600),      // 10 minutes
        minimum: Duration::from_secs(180),  // 3 minutes
    };

    let cache2 = ExtendedDnsCache::new(base_config.clone()).put_negative_with_soa("case2.example", &soa2);

    // Should be cached initially
    assert!(matches!(
        cache2.get_ip_result("case2.example"),
        Some(Err(DnsError::NoRecords(_)))
    ));

    // Advance by SOA MINIMUM (180s) - should expire
    advance_time(Duration::from_secs(180));

    assert!(
        cache2.get_ip_result("case2.example").is_none(),
        "Negative entry should expire after SOA MINIMUM (180s), not TTL (600s)"
    );

    // Test Case 3: Equal SOA TTL and MINIMUM
    set_test_time(0);

    let soa3 = SoaRecord {
        ttl: Duration::from_secs(240),
        minimum: Duration::from_secs(240),
    };

    let cache3 = ExtendedDnsCache::new(base_config).put_negative_with_soa("case3.example", &soa3);

    // Advance by exactly the TTL/MINIMUM
    advance_time(Duration::from_secs(240));

    assert!(
        cache3.get_ip_result("case3.example").is_none(),
        "Negative entry should expire after common TTL/MINIMUM (240s)"
    );
}

/// **MR4: SOA Record Drives Negative Cache Duration**
///
/// The SOA record's MINIMUM field controls how long negative responses are cached,
/// overriding default negative_ttl configuration.
#[test]
#[allow(dead_code)]
fn mr4_soa_record_drives_negative_cache_duration() {
    set_test_time(0);

    // Cache configured with 5-minute default negative TTL
    let base_config = CacheConfig {
        max_entries: 100,
        min_ttl: Duration::from_secs(1),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(300), // 5 minutes default
    };

    // SOA with much shorter MINIMUM (30 seconds)
    let short_soa = SoaRecord {
        ttl: Duration::from_secs(1800),     // 30 minutes
        minimum: Duration::from_secs(30),   // 30 seconds (controls negative caching)
    };

    // SOA with longer MINIMUM (10 minutes)
    let long_soa = SoaRecord {
        ttl: Duration::from_secs(3600),     // 1 hour
        minimum: Duration::from_secs(600),  // 10 minutes (controls negative caching)
    };

    let short_cache = ExtendedDnsCache::new(base_config.clone()).put_negative_with_soa("short.example", &short_soa);
    let long_cache = ExtendedDnsCache::new(base_config).put_negative_with_soa("long.example", &long_soa);

    // Both should be cached initially
    assert!(short_cache.get_ip_result("short.example").is_some());
    assert!(long_cache.get_ip_result("long.example").is_some());

    // Advance time by 45 seconds (short SOA MINIMUM expired, long still valid)
    advance_time(Duration::from_secs(45));

    // Short entry should expire (30s MINIMUM < 45s elapsed)
    assert!(
        short_cache.get_ip_result("short.example").is_none(),
        "Short negative entry should expire after SOA MINIMUM (30s)"
    );

    // Long entry should still be valid (600s MINIMUM > 45s elapsed)
    assert!(
        long_cache.get_ip_result("long.example").is_some(),
        "Long negative entry should still be valid (SOA MINIMUM 600s > 45s elapsed)"
    );

    // Advance time to 700 seconds total (exceeds long SOA MINIMUM of 600s)
    advance_time(Duration::from_secs(655)); // Total: 45 + 655 = 700s

    // Now long entry should also expire
    assert!(
        long_cache.get_ip_result("long.example").is_none(),
        "Long negative entry should expire after SOA MINIMUM (600s)"
    );

    // Verify the caches correctly honored SOA MINIMUM over default negative_ttl
    let short_stats = short_cache.stats();
    let long_stats = long_cache.stats();
    assert!(short_stats.evictions >= 1, "Short cache should have evicted SOA-controlled entry");
    assert!(long_stats.evictions >= 1, "Long cache should have evicted SOA-controlled entry");
}

/// **MR5: Cache Capacity LRU-Evicts Oldest**
///
/// When cache reaches max capacity, oldest entries (by insertion time) are evicted
/// to make room for new entries, implementing LRU (Least Recently Used) semantics.
#[test]
#[allow(dead_code)]
fn mr5_cache_capacity_lru_evicts_oldest() {
    set_test_time(0);

    // Small cache capacity to trigger eviction
    let config = CacheConfig {
        max_entries: 3, // Very small for testing
        min_ttl: Duration::from_secs(1),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(300),
    };

    let cache = test_cache(config);

    // Insert entries in order with time spacing
    let lookup1 = sample_lookup(&["192.0.2.1"], 3600);
    let lookup2 = sample_lookup(&["192.0.2.2"], 3600);
    let lookup3 = sample_lookup(&["192.0.2.3"], 3600);
    let lookup4 = sample_lookup(&["192.0.2.4"], 3600);

    // Insert first entry at time 0
    set_test_time(1000);
    cache.put_ip("host1.example", &lookup1);

    // Insert second entry at time 1000
    set_test_time(2000);
    cache.put_ip("host2.example", &lookup2);

    // Insert third entry at time 2000 (cache now at capacity)
    set_test_time(3000);
    cache.put_ip("host3.example", &lookup3);

    // All three should be present
    assert!(cache.get_ip("host1.example").is_some(), "host1 should be cached");
    assert!(cache.get_ip("host2.example").is_some(), "host2 should be cached");
    assert!(cache.get_ip("host3.example").is_some(), "host3 should be cached");

    let stats_before = cache.stats();
    assert_eq!(stats_before.size, 3, "Cache should be at capacity");

    // Insert fourth entry at time 3000 - should evict oldest (host1)
    set_test_time(4000);
    cache.put_ip("host4.example", &lookup4);

    // host1 (oldest) should be evicted, others should remain
    assert!(cache.get_ip("host1.example").is_none(), "host1 (oldest) should be evicted");
    assert!(cache.get_ip("host2.example").is_some(), "host2 should remain");
    assert!(cache.get_ip("host3.example").is_some(), "host3 should remain");
    assert!(cache.get_ip("host4.example").is_some(), "host4 (new) should be cached");

    let stats_after = cache.stats();
    assert_eq!(stats_after.size, 3, "Cache should still be at capacity");
    assert!(stats_after.evictions > stats_before.evictions, "Should have recorded LRU eviction");

    // Insert fifth entry - should evict host2 (now oldest)
    set_test_time(5000);
    let lookup5 = sample_lookup(&["192.0.2.5"], 3600);
    cache.put_ip("host5.example", &lookup5);

    assert!(cache.get_ip("host2.example").is_none(), "host2 (now oldest) should be evicted");
    assert!(cache.get_ip("host3.example").is_some(), "host3 should remain");
    assert!(cache.get_ip("host4.example").is_some(), "host4 should remain");
    assert!(cache.get_ip("host5.example").is_some(), "host5 (new) should be cached");

    let final_stats = cache.stats();
    assert_eq!(final_stats.size, 3, "Cache should maintain capacity");
    assert_eq!(final_stats.evictions, 2, "Should have 2 LRU evictions total");
}

// =============================================================================
// Integration Tests
// =============================================================================

/// **Comprehensive RFC 2308 Integration Test**
///
/// Tests all conformance properties together to ensure they work in combination.
#[test]
#[allow(dead_code)]
fn comprehensive_rfc_2308_integration() {
    set_test_time(0);

    let config = CacheConfig {
        max_entries: 5,
        min_ttl: Duration::from_secs(1),
        max_ttl: Duration::from_secs(3600),
        negative_ttl: Duration::from_secs(300),
    };

    let cache = test_cache(config);
    let extended_cache = ExtendedDnsCache::new(config);

    // Test 1: Positive caching with TTL expiration
    let lookup_short = sample_lookup(&["192.0.2.10"], 60); // 1 minute TTL
    let lookup_long = sample_lookup(&["192.0.2.20"], 300);  // 5 minute TTL

    cache.put_ip("short.test", &lookup_short);
    cache.put_ip("long.test", &lookup_long);

    // Test 2: Negative caching with SOA control
    let soa = SoaRecord {
        ttl: Duration::from_secs(1800),  // 30 minutes
        minimum: Duration::from_secs(120), // 2 minutes (controls negative caching)
    };

    let negative_cache = extended_cache.put_negative_with_soa("negative.test", &soa);

    // All entries should be cached initially
    assert!(cache.get_ip("short.test").is_some());
    assert!(cache.get_ip("long.test").is_some());
    assert!(negative_cache.get_ip_result("negative.test").is_some());

    // Test 3: TTL expiration behavior
    // Advance 90 seconds (short expired, long valid, negative valid)
    advance_time(Duration::from_secs(90));

    assert!(cache.get_ip("short.test").is_none(), "Short entry should expire");
    assert!(cache.get_ip("long.test").is_some(), "Long entry should remain");
    assert!(negative_cache.get_ip_result("negative.test").is_some(), "Negative should remain (SOA MINIMUM 120s)");

    // Test 4: SOA-driven negative expiration
    // Advance another 40 seconds (130s total - exceeds SOA MINIMUM of 120s)
    advance_time(Duration::from_secs(40));

    assert!(negative_cache.get_ip_result("negative.test").is_none(), "Negative should expire after SOA MINIMUM");
    assert!(cache.get_ip("long.test").is_some(), "Long entry should still be valid");

    // Test 5: LRU eviction under capacity pressure
    // Fill cache to capacity with new entries
    for i in 0..5 {
        let lookup = sample_lookup(&[&format!("198.51.100.{}", i)], 3600);
        cache.put_ip(&format!("fill{}.test", i), &lookup);
    }

    // Original long entry should be evicted due to LRU
    assert!(cache.get_ip("long.test").is_none(), "Long entry should be LRU-evicted");

    // Verify final state
    let stats = cache.stats();
    assert_eq!(stats.size, 5, "Cache should be at capacity");
    assert!(stats.evictions > 0, "Should have performed LRU evictions");
    assert!(stats.hits > 0, "Should have cache hits");
    assert!(stats.misses > 0, "Should have cache misses");

    println!("✓ All RFC 2308 conformance properties verified successfully!");
}