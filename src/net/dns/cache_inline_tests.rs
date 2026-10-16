    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::cell::Cell;
    use std::net::IpAddr;

    thread_local! {
        static TEST_NOW: Cell<u64> = const { Cell::new(0) };
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW.with(|now| now.set(nanos));
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(Cell::get))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // =========================================================================
    // Wave 46 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn cache_config_debug_clone_default() {
        let def = CacheConfig::default();
        assert_eq!(def.max_entries, 10_000);
        assert_eq!(def.min_ttl, Duration::from_mins(1));
        assert_eq!(def.negative_ttl, Duration::from_secs(30));
        let dbg = format!("{def:?}");
        assert!(dbg.contains("CacheConfig"), "{dbg}");
        let cloned = def.clone();
        assert_eq!(cloned.max_entries, def.max_entries);
    }

    #[test]
    fn cache_stats_debug_clone_default() {
        let stats = CacheStats::default();
        assert_eq!(stats.size, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions, 0);
        assert!(
            (stats.hit_rate).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            stats.hit_rate
        );
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("CacheStats"), "{dbg}");
        let cloned = stats.clone();
        assert_eq!(cloned.size, stats.size);
    }

    #[test]
    fn dns_cache_debug_default() {
        let cache = DnsCache::default();
        let dbg = format!("{cache:?}");
        assert!(dbg.contains("DnsCache"), "{dbg}");
    }

    #[test]
    fn dns_cache_with_time_getter() {
        let cache = DnsCache::with_time_getter(CacheConfig::default(), test_time);
        assert_eq!((cache.time_getter())().as_nanos(), 0);
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
    fn cache_lookup_is_case_insensitive() {
        init_test("cache_lookup_is_case_insensitive");
        let cache = DnsCache::new();
        let lookup = LookupIp::new(
            vec!["192.0.2.10".parse::<IpAddr>().unwrap()],
            Duration::from_secs(300),
        );

        cache.put_ip("Example.COM", &lookup);

        let lower = cache.get_ip("example.com");
        let upper = cache.get_ip("EXAMPLE.COM");
        crate::assert_with_log!(lower.is_some(), "lower lookup hit", true, lower.is_some());
        crate::assert_with_log!(upper.is_some(), "upper lookup hit", true, upper.is_some());

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 1, "cache size", 1, stats.size);
        crate::assert_with_log!(stats.hits == 2, "cache hits", 2, stats.hits);
        crate::test_complete!("cache_lookup_is_case_insensitive");
    }

    #[test]
    fn cache_distinguishes_absolute_trailing_dot_hostnames() {
        init_test("cache_distinguishes_absolute_trailing_dot_hostnames");
        let cache = DnsCache::new();
        let dotted = LookupIp::new(
            vec!["192.0.2.20".parse::<IpAddr>().unwrap()],
            Duration::from_secs(300),
        );
        let plain = LookupIp::new(
            vec!["192.0.2.21".parse::<IpAddr>().unwrap()],
            Duration::from_secs(300),
        );
        let expected_dotted: IpAddr = "192.0.2.20".parse().unwrap();
        let expected_plain: IpAddr = "192.0.2.21".parse().unwrap();

        cache.put_ip("example.com.", &dotted);
        cache.put_ip("example.com", &plain);

        let dotted_result = cache.get_ip("EXAMPLE.COM.");
        let plain_result = cache.get_ip("EXAMPLE.COM");
        crate::assert_with_log!(
            dotted_result.as_ref().and_then(LookupIp::first) == Some(expected_dotted),
            "absolute hostname cache key stays distinct",
            Some(expected_dotted),
            format!("{dotted_result:?}")
        );
        crate::assert_with_log!(
            plain_result.as_ref().and_then(LookupIp::first) == Some(expected_plain),
            "relative hostname cache key stays distinct",
            Some(expected_plain),
            format!("{plain_result:?}")
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 2, "cache size", 2, stats.size);
        crate::assert_with_log!(stats.hits == 2, "cache hits", 2, stats.hits);
        crate::test_complete!("cache_distinguishes_absolute_trailing_dot_hostnames");
    }

    #[test]
    fn cache_negative_no_records_hits_and_expires() {
        init_test("cache_negative_no_records_hits_and_expires");
        set_test_time(0);
        let config = CacheConfig {
            min_ttl: Duration::from_millis(1),
            negative_ttl: Duration::from_millis(10),
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        cache.put_negative_ip_no_records("missing.example");

        let first = cache.get_ip_result("missing.example");
        let second = cache.get_ip_result("MISSING.EXAMPLE");
        crate::assert_with_log!(first.is_some(), "negative hit", true, first.is_some());
        crate::assert_with_log!(
            second.is_some(),
            "case-insensitive negative hit",
            true,
            second.is_some()
        );
        crate::assert_with_log!(
            matches!(first, Some(Err(DnsError::NoRecords(ref host))) if host == "missing.example"),
            "negative entry returns NoRecords",
            true,
            format!("{first:?}")
        );
        crate::assert_with_log!(
            matches!(second, Some(Err(DnsError::NoRecords(ref host))) if host == "MISSING.EXAMPLE"),
            "negative entry preserves queried host in error",
            true,
            format!("{second:?}")
        );
        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 1, "negative cache size", 1, stats.size);
        crate::assert_with_log!(stats.hits == 2, "negative cache hits", 2, stats.hits);

        set_test_time(
            Duration::from_millis(11)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let expired = cache.get_ip_result("missing.example");
        crate::assert_with_log!(
            expired.is_none(),
            "negative entry expires via negative_ttl",
            true,
            expired.is_none()
        );
        let stats = cache.stats();
        crate::assert_with_log!(
            stats.size == 0,
            "expired negative entry evicted",
            0,
            stats.size
        );
        crate::assert_with_log!(
            stats.evictions == 1,
            "expired negative eviction counted",
            1,
            stats.evictions
        );
        crate::test_complete!("cache_negative_no_records_hits_and_expires");
    }

    #[test]
    fn cache_negative_ttl_is_not_floored_by_positive_min_ttl() {
        init_test("cache_negative_ttl_is_not_floored_by_positive_min_ttl");
        set_test_time(0);
        let config = CacheConfig {
            min_ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_secs(30),
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        cache.put_negative_ip_no_records("missing.example");

        set_test_time(Duration::from_secs(29).as_nanos().min(u128::from(u64::MAX)) as u64);
        let before_negative_ttl = cache.get_ip_result("missing.example");
        crate::assert_with_log!(
            matches!(before_negative_ttl, Some(Err(DnsError::NoRecords(_)))),
            "negative entry remains before configured negative_ttl",
            true,
            format!("{before_negative_ttl:?}")
        );

        set_test_time(Duration::from_secs(31).as_nanos().min(u128::from(u64::MAX)) as u64);
        let after_negative_ttl = cache.get_ip_result("missing.example");
        crate::assert_with_log!(
            after_negative_ttl.is_none(),
            "negative entry expires at configured negative_ttl, not positive min_ttl",
            true,
            after_negative_ttl.is_none()
        );

        let stats = cache.stats();
        crate::assert_with_log!(
            stats.size == 0,
            "expired negative entry evicted",
            0,
            stats.size
        );
        crate::assert_with_log!(
            stats.evictions == 1,
            "negative expiry counted once",
            1,
            stats.evictions
        );
        crate::test_complete!("cache_negative_ttl_is_not_floored_by_positive_min_ttl");
    }

    #[test]
    fn cache_negative_ttl_is_capped_by_configured_max_ttl() {
        init_test("cache_negative_ttl_is_capped_by_configured_max_ttl");
        set_test_time(0);
        let config = CacheConfig {
            min_ttl: Duration::from_millis(1),
            max_ttl: Duration::from_millis(10),
            negative_ttl: Duration::from_secs(1),
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        cache.put_negative_ip_no_records("missing.example");

        set_test_time(
            Duration::from_millis(9)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let before_ceiling = cache.get_ip_result("missing.example");
        crate::assert_with_log!(
            matches!(before_ceiling, Some(Err(DnsError::NoRecords(_)))),
            "negative entry remains cached before configured ceiling",
            true,
            format!("{before_ceiling:?}")
        );

        set_test_time(
            Duration::from_millis(11)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let after_ceiling = cache.get_ip_result("missing.example");
        crate::assert_with_log!(
            after_ceiling.is_none(),
            "negative entry expires at configured max_ttl ceiling",
            true,
            after_ceiling.is_none()
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 0, "expired entry evicted", 0, stats.size);
        crate::assert_with_log!(
            stats.evictions == 1,
            "negative ceiling expiry counted once",
            1,
            stats.evictions
        );
        crate::test_complete!("cache_negative_ttl_is_capped_by_configured_max_ttl");
    }

    #[test]
    fn cache_expiration() {
        init_test("cache_expiration");
        set_test_time(0);
        let config = CacheConfig {
            min_ttl: Duration::from_millis(1),
            max_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

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

        // Advance deterministically beyond the cached TTL.
        set_test_time(
            Duration::from_millis(10)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );

        // Should be expired
        let expired = cache.get_ip("example.com");
        crate::assert_with_log!(expired.is_none(), "expired", true, expired.is_none());
        let size = cache.stats().size;
        crate::assert_with_log!(size == 0, "expired evicted", 0, size);
        crate::test_complete!("cache_expiration");
    }

    #[test]
    fn cache_evict_expired_uses_time_getter_without_sleep() {
        init_test("cache_evict_expired_uses_time_getter_without_sleep");
        set_test_time(0);
        let config = CacheConfig {
            min_ttl: Duration::from_millis(1),
            max_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        let lookup = LookupIp::new(
            vec!["192.0.2.4".parse::<IpAddr>().expect("ip parse")],
            Duration::from_millis(1),
        );
        cache.put_ip("expired.example", &lookup);
        crate::assert_with_log!(
            cache.stats().size == 1,
            "entry inserted",
            1,
            cache.stats().size
        );

        set_test_time(
            Duration::from_millis(10)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        cache.evict_expired();

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 0, "expired entry removed", 0, stats.size);
        crate::assert_with_log!(stats.evictions == 1, "single eviction", 1, stats.evictions);
        crate::test_complete!("cache_evict_expired_uses_time_getter_without_sleep");
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
            min_ttl: Duration::from_mins(1),
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

    #[test]
    fn cache_zero_ttl_positive_answers_are_not_retained() {
        init_test("cache_zero_ttl_positive_answers_are_not_retained");
        set_test_time(0);
        let cache = DnsCache::with_time_getter(CacheConfig::default(), test_time);

        let lookup = LookupIp::new(
            vec!["192.0.2.77".parse::<IpAddr>().expect("ip parse")],
            Duration::ZERO,
        );
        cache.put_ip("zero.example", &lookup);

        let result = cache.get_ip("zero.example");
        crate::assert_with_log!(
            result.is_none(),
            "zero-ttl answer is not cached",
            true,
            result.is_none()
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 0, "cache size stays zero", 0, stats.size);
        crate::test_complete!("cache_zero_ttl_positive_answers_are_not_retained");
    }

    #[test]
    fn cache_zero_ttl_positive_answers_clear_existing_entry() {
        init_test("cache_zero_ttl_positive_answers_clear_existing_entry");
        set_test_time(0);
        let cache = DnsCache::with_time_getter(CacheConfig::default(), test_time);

        let cached = LookupIp::new(
            vec!["192.0.2.10".parse::<IpAddr>().expect("ip parse")],
            Duration::from_secs(300),
        );
        cache.put_ip("replace.example", &cached);
        crate::assert_with_log!(
            cache.get_ip("replace.example").is_some(),
            "seeded entry exists",
            true,
            cache.get_ip("replace.example").is_some()
        );

        let zero_ttl = LookupIp::new(
            vec!["192.0.2.99".parse::<IpAddr>().expect("ip parse")],
            Duration::ZERO,
        );
        cache.put_ip("replace.example", &zero_ttl);

        let result = cache.get_ip("replace.example");
        crate::assert_with_log!(
            result.is_none(),
            "zero-ttl refresh clears stale cached entry",
            true,
            result.is_none()
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 0, "cache size returns to zero", 0, stats.size);
        crate::test_complete!("cache_zero_ttl_positive_answers_clear_existing_entry");
    }

    #[test]
    fn cache_zero_ttl_negative_answers_are_not_retained() {
        init_test("cache_zero_ttl_negative_answers_are_not_retained");
        set_test_time(0);
        let config = CacheConfig {
            negative_ttl: Duration::ZERO,
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        cache.put_negative_ip_no_records("missing.example");

        let result = cache.get_ip_result("missing.example");
        crate::assert_with_log!(
            result.is_none(),
            "zero-ttl negative answer is not cached",
            true,
            result.is_none()
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 0, "cache size stays zero", 0, stats.size);
        crate::test_complete!("cache_zero_ttl_negative_answers_are_not_retained");
    }

    #[test]
    fn cache_zero_ttl_negative_answers_clear_existing_entry() {
        init_test("cache_zero_ttl_negative_answers_clear_existing_entry");
        set_test_time(0);
        let config = CacheConfig {
            negative_ttl: Duration::ZERO,
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        let cached = LookupIp::new(
            vec!["192.0.2.88".parse::<IpAddr>().expect("ip parse")],
            Duration::from_secs(300),
        );
        cache.put_ip("replace.example", &cached);
        crate::assert_with_log!(
            cache.get_ip("replace.example").is_some(),
            "seeded entry exists",
            true,
            cache.get_ip("replace.example").is_some()
        );

        cache.put_negative_ip_no_records("replace.example");

        let result = cache.get_ip_result("replace.example");
        crate::assert_with_log!(
            result.is_none(),
            "zero-ttl negative refresh clears stale cached entry",
            true,
            result.is_none()
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 0, "cache size returns to zero", 0, stats.size);
        crate::test_complete!("cache_zero_ttl_negative_answers_clear_existing_entry");
    }

    #[test]
    fn cache_positive_nonzero_ttl_still_honors_minimum_floor() {
        init_test("cache_positive_nonzero_ttl_still_honors_minimum_floor");
        set_test_time(0);
        let config = CacheConfig {
            min_ttl: Duration::from_millis(10),
            max_ttl: Duration::from_secs(1),
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        let lookup = LookupIp::new(
            vec!["192.0.2.55".parse::<IpAddr>().expect("ip parse")],
            Duration::from_millis(1),
        );
        cache.put_ip("floor.example", &lookup);

        set_test_time(
            Duration::from_millis(5)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let before_floor = cache.get_ip("floor.example");
        crate::assert_with_log!(
            before_floor.is_some(),
            "positive nonzero ttl still honors configured floor",
            true,
            before_floor.is_some()
        );

        set_test_time(
            Duration::from_millis(11)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let after_floor = cache.get_ip("floor.example");
        crate::assert_with_log!(
            after_floor.is_none(),
            "entry expires after floored ttl elapses",
            true,
            after_floor.is_none()
        );

        crate::test_complete!("cache_positive_nonzero_ttl_still_honors_minimum_floor");
    }

    #[test]
    fn cache_positive_ttl_is_capped_by_configured_max_ttl() {
        init_test("cache_positive_ttl_is_capped_by_configured_max_ttl");
        set_test_time(0);
        let config = CacheConfig {
            min_ttl: Duration::from_millis(1),
            max_ttl: Duration::from_millis(10),
            ..Default::default()
        };
        let cache = DnsCache::with_time_getter(config, test_time);

        let lookup = LookupIp::new(
            vec!["192.0.2.56".parse::<IpAddr>().expect("ip parse")],
            Duration::from_secs(1),
        );
        cache.put_ip("ceiling.example", &lookup);

        set_test_time(
            Duration::from_millis(9)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let before_ceiling = cache.get_ip("ceiling.example");
        crate::assert_with_log!(
            before_ceiling.is_some(),
            "positive ttl remains cached before configured ceiling",
            true,
            before_ceiling.is_some()
        );

        set_test_time(
            Duration::from_millis(11)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let after_ceiling = cache.get_ip("ceiling.example");
        crate::assert_with_log!(
            after_ceiling.is_none(),
            "positive ttl expires at configured ceiling",
            true,
            after_ceiling.is_none()
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 0, "expired entry evicted", 0, stats.size);
        crate::assert_with_log!(
            stats.evictions == 1,
            "positive ceiling expiry counted once",
            1,
            stats.evictions
        );
        crate::test_complete!("cache_positive_ttl_is_capped_by_configured_max_ttl");
    }

    #[test]
    fn cache_max_entries_zero_disables_inserts() {
        init_test("cache_max_entries_zero");
        let config = CacheConfig {
            max_entries: 0,
            ..Default::default()
        };
        let cache = DnsCache::with_config(config);

        let lookup = LookupIp::new(
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
            Duration::from_secs(300),
        );
        cache.put_ip("example.com", &lookup);

        let result = cache.get_ip("example.com");
        crate::assert_with_log!(result.is_none(), "no entry", true, result.is_none());
        let size = cache.stats().size;
        crate::assert_with_log!(size == 0, "size 0", 0, size);
        crate::test_complete!("cache_max_entries_zero");
    }

    #[test]
    fn cache_update_existing_key_at_capacity_does_not_evict_other_entry() {
        init_test("cache_update_existing_key_at_capacity_does_not_evict_other_entry");
        let config = CacheConfig {
            max_entries: 2,
            ..Default::default()
        };
        let cache = DnsCache::with_config(config);

        let a1 = LookupIp::new(
            vec!["192.0.2.1".parse::<IpAddr>().expect("ip parse")],
            Duration::from_secs(300),
        );
        let b1 = LookupIp::new(
            vec!["192.0.2.2".parse::<IpAddr>().expect("ip parse")],
            Duration::from_secs(300),
        );
        let b2 = LookupIp::new(
            vec!["192.0.2.20".parse::<IpAddr>().expect("ip parse")],
            Duration::from_secs(300),
        );

        cache.put_ip("a.example", &a1);
        cache.put_ip("b.example", &b1);
        cache.put_ip("b.example", &b2);

        let a = cache.get_ip("a.example");
        let b = cache.get_ip("b.example");
        crate::assert_with_log!(a.is_some(), "a still present", true, a.is_some());
        crate::assert_with_log!(b.is_some(), "b still present", true, b.is_some());

        let b_first = b.and_then(|lookup| lookup.first());
        crate::assert_with_log!(
            b_first == Some("192.0.2.20".parse::<IpAddr>().expect("ip parse")),
            "b updated in place",
            "192.0.2.20",
            format!("{b_first:?}")
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 2, "size remains at capacity", 2, stats.size);
        crate::assert_with_log!(
            stats.evictions == 0,
            "no unrelated eviction on update",
            0,
            stats.evictions
        );
        crate::test_complete!("cache_update_existing_key_at_capacity_does_not_evict_other_entry");
    }

    #[test]
    fn cache_capacity_eviction_breaks_equal_insert_times_deterministically() {
        init_test("cache_capacity_eviction_breaks_equal_insert_times_deterministically");
        let config = CacheConfig {
            max_entries: 2,
            ..Default::default()
        };
        // The cache's clock, not the wall clock: on the wall clock both entries
        // had expired once the test process was 300 s old, and the eviction
        // under test never ran.
        set_test_time(42);
        let cache = DnsCache::with_time_getter(config, test_time);
        let inserted_at = Time::from_nanos(42);
        let ttl = Duration::from_secs(300);

        let alpha = LookupIp::new(vec!["192.0.2.1".parse::<IpAddr>().expect("ip parse")], ttl);
        let zeta = LookupIp::new(vec!["192.0.2.2".parse::<IpAddr>().expect("ip parse")], ttl);
        let middle = LookupIp::new(vec!["192.0.2.3".parse::<IpAddr>().expect("ip parse")], ttl);

        {
            let mut entries = cache.ip_cache.write();
            entries.insert(
                "zeta.example".to_string(),
                CacheEntry {
                    data: CachedIpEntry::Positive(zeta),
                    inserted_at,
                    expires_at: inserted_at.saturating_add_nanos(duration_to_nanos(ttl)),
                },
            );
            entries.insert(
                "alpha.example".to_string(),
                CacheEntry {
                    data: CachedIpEntry::Positive(alpha),
                    inserted_at,
                    expires_at: inserted_at.saturating_add_nanos(duration_to_nanos(ttl)),
                },
            );
        }

        cache.put_ip("middle.example", &middle);

        let alpha_cached = cache.get_ip("alpha.example");
        let zeta_cached = cache.get_ip("zeta.example");
        let middle_cached = cache.get_ip("middle.example");
        crate::assert_with_log!(
            alpha_cached.is_none(),
            "lexicographically smallest equal-age key evicted first",
            true,
            alpha_cached.is_none()
        );
        crate::assert_with_log!(
            zeta_cached.is_some(),
            "later lexical key remains when insert times tie",
            true,
            zeta_cached.is_some()
        );
        crate::assert_with_log!(
            middle_cached.is_some(),
            "new entry inserted after deterministic eviction",
            true,
            middle_cached.is_some()
        );

        let stats = cache.stats();
        crate::assert_with_log!(stats.size == 2, "size stays at capacity", 2, stats.size);
        crate::assert_with_log!(
            stats.evictions == 1,
            "single eviction recorded",
            1,
            stats.evictions
        );
        crate::test_complete!(
            "cache_capacity_eviction_breaks_equal_insert_times_deterministically"
        );
    }
