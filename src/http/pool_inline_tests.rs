    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn make_time(ms: u64) -> Time {
        Time::from_millis(ms)
    }

    #[test]
    fn pool_key_creation() {
        let key = PoolKey::new("example.com", 8080, true);
        assert_eq!(key.host, "example.com");
        assert_eq!(key.port, 8080);
        assert!(key.is_https);

        let plain_key = PoolKey::http("example.com", None);
        assert_eq!(plain_key.port, 80);
        assert!(!plain_key.is_https);

        let tls_key = PoolKey::https("example.com", None);
        assert_eq!(tls_key.port, 443);
        assert!(tls_key.is_https);
    }

    #[test]
    fn pool_config_builder() {
        let config = PoolConfig::builder()
            .max_connections_per_host(10)
            .max_total_connections(200)
            .idle_timeout(Duration::from_secs(60))
            .build();

        assert_eq!(config.max_connections_per_host, 10);
        assert_eq!(config.max_total_connections, 200);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn pool_register_and_acquire() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        let now = make_time(1000);

        // Register a connecting connection
        let id = pool.register_connecting(key.clone(), now, 2);
        assert_eq!(id, 1);

        // Can't acquire while connecting
        assert!(pool.try_acquire(&key, now).is_none());

        // Mark as connected
        assert!(pool.mark_connected(&key, id, now));

        // Now we can acquire it
        let acquired = pool.try_acquire(&key, now);
        assert_eq!(acquired, Some(id));

        // Can't acquire again (it's in use)
        assert!(pool.try_acquire(&key, now).is_none());

        // Release it
        assert!(pool.release(&key, id, now));

        // Can acquire again
        let acquired = pool.try_acquire(&key, now);
        assert_eq!(acquired, Some(id));
    }

    #[test]
    fn pool_connection_limits() {
        let config = PoolConfig::builder()
            .max_connections_per_host(2)
            .max_total_connections(5)
            .build();
        let mut pool = Pool::with_config(config);
        let now = make_time(1000);

        let key1 = PoolKey::https("host1.com", None);
        let key2 = PoolKey::https("host2.com", None);

        // Can create connections up to per-host limit
        assert!(pool.can_create_connection(&key1, now));
        pool.register_connecting(key1.clone(), now, 2);
        assert!(pool.can_create_connection(&key1, now));
        pool.register_connecting(key1.clone(), now, 2);
        assert!(!pool.can_create_connection(&key1, now)); // At limit for host1

        // Can still create for different host
        assert!(pool.can_create_connection(&key2, now));
        pool.register_connecting(key2.clone(), now, 2);
        pool.register_connecting(key2.clone(), now, 2);

        // One more overall
        pool.register_connecting(key2, now, 2);

        // Now at total limit
        let key3 = PoolKey::https("host3.com", None);
        assert!(!pool.can_create_connection(&key3, now));
    }

    #[test]
    fn pool_cleanup_expired() {
        let config = PoolConfig::builder()
            .idle_timeout(Duration::from_millis(100))
            .build();
        let mut pool = Pool::with_config(config);
        let key = PoolKey::https("example.com", None);

        // Create a connection at time 0
        let id = pool.register_connecting(key.clone(), make_time(0), 2);
        assert!(pool.mark_connected(&key, id, make_time(0)));

        // Not expired at time 50
        let removed = pool.cleanup_expired(make_time(50));
        assert_eq!(removed, 0);
        assert!(pool.get_connection_meta(&key, id).is_some());

        // Expired at time 150
        let removed = pool.cleanup_expired(make_time(150));
        assert_eq!(removed, 1);
        assert!(pool.get_connection_meta(&key, id).is_none());
    }

    #[test]
    fn cleanup_expired_entries_returns_removed_connection_ids() {
        let config = PoolConfig::builder()
            .idle_timeout(Duration::from_millis(100))
            .build();
        let mut pool = Pool::with_config(config);
        let key = PoolKey::https("example.com", None);

        let expired_id = pool.register_connecting(key.clone(), make_time(0), 2);
        assert!(pool.mark_connected(&key, expired_id, make_time(0)));
        let live_id = pool.register_connecting(key.clone(), make_time(80), 2);
        assert!(pool.mark_connected(&key, live_id, make_time(80)));

        let removed = pool.cleanup_expired_entries(make_time(150));
        assert_eq!(removed, vec![(key.clone(), expired_id)]);
        assert!(pool.get_connection_meta(&key, expired_id).is_none());
        assert!(pool.get_connection_meta(&key, live_id).is_some());
    }

    #[test]
    fn evict_idle_for_frees_the_least_recently_used_idle_connection_of_another_host() {
        let config = PoolConfig::builder()
            .max_connections_per_host(2)
            .max_total_connections(3)
            .build();
        let mut pool = Pool::with_config(config);
        let older = PoolKey::http("older.example", None);
        let newer = PoolKey::http("newer.example", None);
        let busy = PoolKey::http("busy.example", None);
        let fresh = PoolKey::http("fresh.example", None);

        let older_id = pool.register_connecting(older.clone(), make_time(0), 1);
        assert!(pool.mark_connected(&older, older_id, make_time(10)));
        let newer_id = pool.register_connecting(newer.clone(), make_time(0), 1);
        assert!(pool.mark_connected(&newer, newer_id, make_time(20)));
        let busy_id = pool.register_connecting(busy.clone(), make_time(0), 1);
        assert!(pool.mark_connected(&busy, busy_id, make_time(5)));
        assert_eq!(pool.try_acquire(&busy, make_time(30)), Some(busy_id));

        assert!(!pool.can_create_connection(&fresh, make_time(30)));
        assert_eq!(
            pool.evict_idle_for(&fresh, make_time(30)),
            Some((older.clone(), older_id)),
            "the least recently used idle connection makes room; in-use ones never do"
        );
        assert!(pool.get_connection_meta(&older, older_id).is_none());
        assert!(pool.can_create_connection(&fresh, make_time(30)));
        assert_eq!(
            pool.evict_idle_for(&fresh, make_time(30)),
            None,
            "no eviction below the total limit"
        );
    }

    #[test]
    fn evict_idle_for_never_evicts_for_a_host_at_its_own_limit_or_when_nothing_is_idle() {
        let config = PoolConfig::builder()
            .max_connections_per_host(1)
            .max_total_connections(2)
            .build();
        let mut pool = Pool::with_config(config);
        let full = PoolKey::http("full.example", None);
        let idle = PoolKey::http("idle.example", None);

        let full_id = pool.register_connecting(full.clone(), make_time(0), 1);
        assert!(pool.mark_connected(&full, full_id, make_time(0)));
        assert_eq!(pool.try_acquire(&full, make_time(1)), Some(full_id));
        let idle_id = pool.register_connecting(idle.clone(), make_time(0), 1);
        assert!(pool.mark_connected(&idle, idle_id, make_time(0)));

        assert_eq!(
            pool.evict_idle_for(&full, make_time(1)),
            None,
            "an eviction cannot help a host at its own limit"
        );
        assert!(pool.get_connection_meta(&idle, idle_id).is_some());

        assert_eq!(pool.try_acquire(&idle, make_time(1)), Some(idle_id));
        let other = PoolKey::http("other.example", None);
        assert_eq!(
            pool.evict_idle_for(&other, make_time(1)),
            None,
            "in-use connections are never evicted"
        );
    }

    #[test]
    fn pool_can_create_connection_ignores_expired_idle() {
        let config = PoolConfig::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .idle_timeout(Duration::from_millis(100))
            .build();
        let mut pool = Pool::with_config(config);
        let key = PoolKey::https("example.com", None);

        let id = pool.register_connecting(key.clone(), make_time(0), 2);
        assert!(pool.mark_connected(&key, id, make_time(0)));

        assert!(
            pool.can_create_connection(&key, make_time(150)),
            "expired idle connection should not block creation"
        );
    }

    #[test]
    fn pool_stats() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        let now = make_time(1000);

        let id1 = pool.register_connecting(key.clone(), now, 2);
        let id2 = pool.register_connecting(key.clone(), now, 2);

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.connecting, 2);
        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.connections_created, 2);

        assert!(pool.mark_connected(&key, id1, now));
        assert!(pool.mark_connected(&key, id2, now));

        let stats = pool.stats();
        assert_eq!(stats.idle_connections, 2);
        assert_eq!(stats.connecting, 0);

        pool.try_acquire(&key, now);

        let stats = pool.stats();
        assert_eq!(stats.idle_connections, 1);
        assert_eq!(stats.in_use_connections, 1);
    }

    #[test]
    fn connection_meta_expiry() {
        let mut meta = PooledConnectionMeta::new(1, make_time(0), 2);
        let timeout = Duration::from_millis(100);

        // Not expired while connecting
        assert!(!meta.is_expired(make_time(200), timeout));

        // Mark idle
        meta.mark_idle(make_time(100));

        // Not expired yet
        assert!(!meta.is_expired(make_time(150), timeout));

        // Expired after timeout
        assert!(meta.is_expired(make_time(250), timeout));
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        // Removing from empty pool should not panic
        pool.remove(&key, 999);
        assert_eq!(pool.stats().connections_closed, 0);
    }

    #[test]
    fn release_nonexistent_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        // Releasing a nonexistent connection should not panic
        assert!(!pool.release(&key, 999, make_time(0)));
    }

    #[test]
    fn mark_connected_nonexistent_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        assert!(!pool.mark_connected(&key, 999, make_time(0)));
    }

    #[test]
    fn release_connecting_connection_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        let id = pool.register_connecting(key.clone(), make_time(0), 2);

        assert!(!pool.release(&key, id, make_time(50)));

        let meta = pool
            .get_connection_meta(&key, id)
            .expect("connecting connection should remain present");
        assert_eq!(meta.state, PooledConnectionState::Connecting);
        assert_eq!(meta.last_used, make_time(0));
    }

    #[test]
    fn mark_connected_in_use_connection_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        let id = pool.register_connecting(key.clone(), make_time(0), 2);
        assert!(pool.mark_connected(&key, id, make_time(10)));
        assert_eq!(pool.try_acquire(&key, make_time(20)), Some(id));

        assert!(!pool.mark_connected(&key, id, make_time(50)));

        let meta = pool
            .get_connection_meta(&key, id)
            .expect("in-use connection should remain present");
        assert_eq!(meta.state, PooledConnectionState::InUse);
        assert_eq!(meta.last_used, make_time(10));
        assert_eq!(meta.requests_served, 1);
    }

    #[test]
    fn release_unhealthy_connection_is_noop() {
        let mut meta = PooledConnectionMeta::new(1, make_time(0), 2);
        assert!(meta.mark_connected(make_time(10)));
        meta.mark_unhealthy();

        assert!(!meta.release(make_time(50)));
        assert_eq!(meta.state, PooledConnectionState::Unhealthy);
        assert_eq!(meta.last_used, make_time(10));
    }

    #[test]
    fn pool_default_config() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_host, 6);
        assert_eq!(config.max_total_connections, 100);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn acquire_prefers_idle_over_expired() {
        let config = PoolConfig::builder()
            .idle_timeout(Duration::from_millis(100))
            .build();
        let mut pool = Pool::with_config(config);
        let key = PoolKey::https("example.com", None);

        // Create two connections at time 0
        let id1 = pool.register_connecting(key.clone(), make_time(0), 2);
        assert!(pool.mark_connected(&key, id1, make_time(0)));
        let id2 = pool.register_connecting(key.clone(), make_time(50), 2);
        assert!(pool.mark_connected(&key, id2, make_time(50)));

        // At time 120: id1 is expired (idle 120ms), id2 is not (idle 70ms)
        let acquired = pool.try_acquire(&key, make_time(120));
        assert_eq!(acquired, Some(id2));
    }

    #[test]
    fn acquire_uses_lowest_idle_id_for_deterministic_tie_break() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        let now = make_time(100);

        let id1 = pool.register_connecting(key.clone(), now, 2);
        let id2 = pool.register_connecting(key.clone(), now, 2);
        let id3 = pool.register_connecting(key.clone(), now, 2);

        assert!(pool.mark_connected(&key, id1, now));
        assert!(pool.mark_connected(&key, id2, now));
        assert!(pool.mark_connected(&key, id3, now));

        let acquired = pool.try_acquire(&key, now);
        assert_eq!(acquired, Some(id1));

        let acquired = pool.try_acquire(&key, now);
        assert_eq!(acquired, Some(id2));

        let acquired = pool.try_acquire(&key, now);
        assert_eq!(acquired, Some(id3));
    }

    #[test]
    fn metamorphic_connection_reuse_ignores_ineligible_noise() {
        let config = PoolConfig::builder()
            .idle_timeout(Duration::from_millis(100))
            .build();
        let key = PoolKey::https("example.com", None);
        let now = make_time(100);

        let mut baseline = Pool::with_config(config.clone());
        let baseline_id = baseline.register_connecting(key.clone(), make_time(10), 2);
        assert!(baseline.mark_connected(&key, baseline_id, make_time(10)));
        let baseline_acquired = baseline.try_acquire(&key, now);
        assert_eq!(baseline_acquired, Some(baseline_id));

        let mut transformed = Pool::with_config(config);
        let valid_id = transformed.register_connecting(key.clone(), make_time(10), 2);
        assert!(transformed.mark_connected(&key, valid_id, make_time(10)));

        let expired_id = transformed.register_connecting(key.clone(), make_time(0), 2);
        assert!(transformed.mark_connected(&key, expired_id, make_time(0)));

        let transformed_acquired = transformed.try_acquire(&key, now);
        assert_eq!(
            transformed_acquired, baseline_acquired,
            "expired idle noise must not perturb reuse of the valid idle connection"
        );

        let connecting_noise_id = transformed.register_connecting(key.clone(), make_time(20), 2);
        let transformed_again = transformed.try_acquire(&key, now);
        assert_eq!(
            transformed_again, None,
            "adding only connecting noise must not fabricate reusable capacity after the valid idle connection was consumed"
        );
        let connecting_meta = transformed
            .get_connection_meta(&key, connecting_noise_id)
            .expect("connecting entry remains tracked");
        assert_eq!(connecting_meta.state, PooledConnectionState::Connecting);
    }

    #[test]
    fn metamorphic_target_host_reuse_is_stable_under_unrelated_host_churn() {
        let config = PoolConfig::builder()
            .idle_timeout(Duration::from_millis(100))
            .build();
        let target_key = PoolKey::https("example.com", None);
        let noise_key = PoolKey::https("other.example", None);

        let mut baseline = Pool::with_config(config.clone());
        let baseline_id1 = baseline.register_connecting(target_key.clone(), make_time(10), 2);
        let baseline_id2 = baseline.register_connecting(target_key.clone(), make_time(20), 2);
        assert!(baseline.mark_connected(&target_key, baseline_id1, make_time(10)));
        assert!(baseline.mark_connected(&target_key, baseline_id2, make_time(20)));

        let baseline_first = baseline.try_acquire(&target_key, make_time(50));
        assert_eq!(baseline_first, Some(baseline_id1));
        assert!(baseline.release(&target_key, baseline_id1, make_time(60)));
        let baseline_second = baseline.try_acquire(&target_key, make_time(60));
        assert_eq!(baseline_second, Some(baseline_id1));

        let mut transformed = Pool::with_config(config);
        let transformed_id1 = transformed.register_connecting(target_key.clone(), make_time(10), 2);
        let transformed_id2 = transformed.register_connecting(target_key.clone(), make_time(20), 2);
        assert!(transformed.mark_connected(&target_key, transformed_id1, make_time(10)));
        assert!(transformed.mark_connected(&target_key, transformed_id2, make_time(20)));

        let noise_idle_id = transformed.register_connecting(noise_key.clone(), make_time(5), 2);
        assert!(transformed.mark_connected(&noise_key, noise_idle_id, make_time(5)));
        let noise_connecting_id =
            transformed.register_connecting(noise_key.clone(), make_time(30), 2);

        let transformed_first = transformed.try_acquire(&target_key, make_time(50));
        assert_eq!(
            transformed_first, baseline_first,
            "unrelated host activity must not perturb the first reuse choice for the target host"
        );

        assert!(transformed.release(&target_key, transformed_id1, make_time(60)));
        let transformed_second = transformed.try_acquire(&target_key, make_time(60));
        assert_eq!(
            transformed_second, baseline_second,
            "unrelated host churn must not perturb subsequent reuse ordering for the target host"
        );

        let noise_idle_meta = transformed
            .get_connection_meta(&noise_key, noise_idle_id)
            .expect("idle noise entry remains tracked");
        assert_eq!(noise_idle_meta.state, PooledConnectionState::Idle);

        let noise_connecting_meta = transformed
            .get_connection_meta(&noise_key, noise_connecting_id)
            .expect("connecting noise entry remains tracked");
        assert_eq!(
            noise_connecting_meta.state,
            PooledConnectionState::Connecting
        );
    }

    #[test]
    fn pool_key_debug_clone_eq_ord_hash() {
        use std::collections::HashSet;
        let a = PoolKey::new("example.com", 443, true);
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, PoolKey::new("other.com", 443, true));
        assert!(a < PoolKey::new("zexample.com", 443, true));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("example.com"));
        assert!(dbg.contains("443"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn pooled_connection_state_debug_clone_copy_eq() {
        let a = PooledConnectionState::Idle;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, PooledConnectionState::InUse);
        assert_ne!(a, PooledConnectionState::Connecting);
        assert_ne!(a, PooledConnectionState::Unhealthy);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Idle"));
    }
