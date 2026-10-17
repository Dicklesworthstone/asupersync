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
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::thread;

    thread_local! {
        static TEST_NOW: Cell<u64> = const { Cell::new(0) };
    }

    type ResolverResult = Result<HashSet<SocketAddr>, std::io::Error>;

    fn set_test_time(nanos: u64) {
        TEST_NOW.with(|now| now.set(nanos));
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn socket_set(addrs: &[&str]) -> HashSet<SocketAddr> {
        addrs.iter().map(|addr| addr.parse().unwrap()).collect()
    }

    fn scripted_resolver(
        script: Vec<ResolverResult>,
    ) -> impl Fn(&str, u16) -> ResolverResult + Send + Sync + 'static {
        let script = Arc::new(StdMutex::new(VecDeque::from(script)));
        move |_, _| {
            script
                .lock()
                .expect("resolver script lock poisoned")
                .pop_front()
                .expect("resolver script exhausted")
        }
    }

    // ================================================================
    // Change
    // ================================================================

    #[test]
    fn change_insert_display() {
        let change = Change::Insert("10.0.0.1:80".to_string());
        assert_eq!(format!("{change}"), "+10.0.0.1:80");
    }

    #[test]
    fn change_remove_display() {
        let change = Change::Remove("10.0.0.1:80".to_string());
        assert_eq!(format!("{change}"), "-10.0.0.1:80");
    }

    #[test]
    fn change_eq() {
        let a = Change::Insert(42);
        let b = Change::Insert(42);
        let c = Change::Remove(42);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn change_debug_clone() {
        let change = Change::Insert(1);
        let dbg = format!("{change:?}");
        assert!(dbg.contains("Insert"));
        let cloned = change.clone();
        assert_eq!(cloned, change);
    }

    // ================================================================
    // StaticList
    // ================================================================

    #[test]
    fn static_list_first_poll_returns_inserts() {
        init_test("static_list_first_poll_returns_inserts");
        let list = StaticList::new(vec![1, 2, 3]);
        let changes = list.poll_discover().unwrap();
        assert_eq!(changes.len(), 3);
        assert!(changes.contains(&Change::Insert(1)));
        assert!(changes.contains(&Change::Insert(2)));
        assert!(changes.contains(&Change::Insert(3)));
        crate::test_complete!("static_list_first_poll_returns_inserts");
    }

    #[test]
    fn static_list_subsequent_polls_empty() {
        init_test("static_list_subsequent_polls_empty");
        let list = StaticList::new(vec![1, 2]);
        let _ = list.poll_discover().unwrap();
        let changes = list.poll_discover().unwrap();
        assert!(changes.is_empty());
        crate::test_complete!("static_list_subsequent_polls_empty");
    }

    #[test]
    fn static_list_endpoints() {
        let list = StaticList::new(vec![10, 20]);
        assert_eq!(list.endpoints(), vec![10, 20]);
    }

    #[test]
    fn static_list_first_poll_deduplicates_duplicate_endpoints() {
        init_test("static_list_first_poll_deduplicates_duplicate_endpoints");
        let list = StaticList::new(vec![1, 2, 1, 3, 2]);
        let changes = list.poll_discover().unwrap();
        assert_eq!(
            changes,
            vec![Change::Insert(1), Change::Insert(2), Change::Insert(3)]
        );
        crate::test_complete!("static_list_first_poll_deduplicates_duplicate_endpoints");
    }

    #[test]
    fn static_list_endpoints_deduplicate_preserving_first_seen_order() {
        init_test("static_list_endpoints_deduplicate_preserving_first_seen_order");
        let list = StaticList::new(vec![3, 1, 3, 2, 1, 4]);
        assert_eq!(list.endpoints(), vec![3, 1, 2, 4]);
        crate::test_complete!("static_list_endpoints_deduplicate_preserving_first_seen_order");
    }

    #[test]
    fn static_list_empty() {
        let list = StaticList::<i32>::new(vec![]);
        let changes = list.poll_discover().unwrap();
        assert!(changes.is_empty());
        assert!(list.endpoints().is_empty());
    }

    #[test]
    fn static_list_debug() {
        let list = StaticList::new(vec![1, 2]);
        let dbg = format!("{list:?}");
        assert!(dbg.contains("StaticList"));
    }

    // ================================================================
    // ActiveHealthDiscovery
    // ================================================================

    #[test]
    fn active_health_discovery_filters_retries_and_readds_endpoints_with_backoff() {
        init_test("active_health_discovery_filters_retries_and_readds_endpoints_with_backoff");
        set_test_time(0);
        let outcomes = Arc::new(StdMutex::new(HashMap::from([
            (
                "http".to_string(),
                VecDeque::from([ProbeOutcome::Healthy, ProbeOutcome::Healthy]),
            ),
            (
                "grpc".to_string(),
                VecDeque::from([ProbeOutcome::Unhealthy, ProbeOutcome::Healthy]),
            ),
            (
                "tcp".to_string(),
                VecDeque::from([ProbeOutcome::Healthy, ProbeOutcome::Healthy]),
            ),
        ])));
        let outcomes_for_probe = Arc::clone(&outcomes);
        let discovery = ActiveHealthDiscovery::new(
            StaticList::new(vec![
                "http".to_string(),
                "grpc".to_string(),
                "tcp".to_string(),
            ]),
            ActiveHealthConfig::new(HealthProbeKind::http("/health"))
                .probe_interval(Duration::from_secs(10))
                .failure_backoff(ProbeBackoff::new(
                    Duration::from_secs(5),
                    Duration::from_secs(20),
                ))
                .with_time_getter(test_time),
            move |endpoint: &String, kind: &HealthProbeKind| {
                assert_eq!(kind, &HealthProbeKind::http("/health"));
                outcomes_for_probe
                    .lock()
                    .expect("probe outcome script lock poisoned")
                    .get_mut(endpoint)
                    .expect("endpoint should have a probe script")
                    .pop_front()
                    .expect("endpoint probe script exhausted")
            },
        );

        let first = discovery.poll_discover().unwrap();
        assert_eq!(
            first,
            vec![
                Change::Insert("http".to_string()),
                Change::Insert("tcp".to_string())
            ]
        );
        assert_eq!(
            discovery.endpoints(),
            vec!["http".to_string(), "tcp".to_string()]
        );

        let grpc_health = discovery
            .endpoint_health(&"grpc".to_string())
            .expect("grpc endpoint should have health state");
        assert_eq!(grpc_health.status, EndpointHealthStatus::Unhealthy);
        assert_eq!(grpc_health.consecutive_failures, 1);
        assert_eq!(grpc_health.probe_count, 1);
        assert_eq!(grpc_health.transition_count, 1);
        assert_eq!(grpc_health.next_probe_at, Some(Time::from_secs(5)));

        set_test_time(Time::from_secs(4).as_nanos());
        assert_eq!(
            discovery.poll_discover().unwrap(),
            Vec::<Change<String>>::new()
        );
        assert_eq!(
            discovery
                .endpoint_health(&"grpc".to_string())
                .expect("grpc health state should remain present")
                .probe_count,
            1,
            "failed endpoint must respect active-probe backoff"
        );

        set_test_time(Time::from_secs(5).as_nanos());
        let recovered = discovery.poll_discover().unwrap();
        assert_eq!(recovered, vec![Change::Insert("grpc".to_string())]);
        assert_eq!(
            discovery.endpoints(),
            vec!["http".to_string(), "grpc".to_string(), "tcp".to_string()]
        );

        let grpc_health = discovery
            .endpoint_health(&"grpc".to_string())
            .expect("grpc endpoint should still have health state");
        assert_eq!(grpc_health.status, EndpointHealthStatus::Healthy);
        assert_eq!(grpc_health.consecutive_failures, 0);
        assert_eq!(grpc_health.probe_count, 2);
        assert_eq!(grpc_health.transition_count, 2);
        assert_eq!(grpc_health.next_probe_at, Some(Time::from_secs(15)));
        crate::test_complete!(
            "active_health_discovery_filters_retries_and_readds_endpoints_with_backoff"
        );
    }

    // ================================================================
    // DnsDiscoveryConfig
    // ================================================================

    #[test]
    fn dns_config_new() {
        init_test("dns_config_new");
        let config = DnsDiscoveryConfig::new("example.com", 80);
        assert_eq!(config.hostname, "example.com");
        assert_eq!(config.port, 80);
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        crate::test_complete!("dns_config_new");
    }

    #[test]
    fn dns_config_poll_interval() {
        let config =
            DnsDiscoveryConfig::new("example.com", 80).poll_interval(Duration::from_secs(60));
        assert_eq!(config.poll_interval, Duration::from_secs(60));
    }

    #[test]
    fn dns_config_with_time_getter() {
        let config = DnsDiscoveryConfig::new("example.com", 80).with_time_getter(test_time);
        assert_eq!((config.time_getter())().as_nanos(), 0);
    }

    #[test]
    fn dns_config_debug_clone() {
        let config = DnsDiscoveryConfig::new("host", 443);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("DnsDiscoveryConfig"));
        assert_eq!(config.hostname, "host");
    }

    // ================================================================
    // DnsServiceDiscovery
    // ================================================================

    #[test]
    fn dns_discovery_new() {
        init_test("dns_discovery_new");
        let discovery = DnsServiceDiscovery::from_host("localhost", 80);
        assert_eq!(discovery.hostname(), "localhost");
        assert_eq!(discovery.port(), 80);
        assert_eq!(discovery.resolve_count(), 0);
        assert_eq!(discovery.error_count(), 0);
        crate::test_complete!("dns_discovery_new");
    }

    #[test]
    fn dns_discovery_default_resolver_accepts_ip_literal() {
        init_test("dns_discovery_default_resolver_accepts_ip_literal");
        let discovery = DnsServiceDiscovery::from_host("127.0.0.1", 8080);

        let changes = discovery.poll_discover().unwrap();
        assert_eq!(
            changes,
            vec![Change::Insert("127.0.0.1:8080".parse().unwrap())]
        );
        assert_eq!(discovery.resolve_count(), 1);

        crate::test_complete!("dns_discovery_default_resolver_accepts_ip_literal");
    }

    #[test]
    fn dns_discovery_no_change_within_interval() {
        init_test("dns_discovery_no_change_within_interval");
        let addrs = socket_set(&["127.0.0.1:80"]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(300))
                .with_resolver(move |hostname, port| {
                    assert_eq!(hostname, "service.test");
                    assert_eq!(port, 80);
                    Ok(addrs.clone())
                }),
        );

        let _ = discovery.poll_discover().unwrap();
        // Second poll should return empty (within poll interval).
        let changes = discovery.poll_discover().unwrap();
        assert!(changes.is_empty());
        assert_eq!(discovery.resolve_count(), 1);
        crate::test_complete!("dns_discovery_no_change_within_interval");
    }

    #[test]
    fn dns_discovery_invalidate_forces_resolve() {
        init_test("dns_discovery_invalidate_forces_resolve");
        let resolver = scripted_resolver(vec![
            Ok(socket_set(&["127.0.0.1:80"])),
            Ok(socket_set(&["127.0.0.1:80"])),
        ]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(300))
                .with_resolver(resolver),
        );

        let _ = discovery.poll_discover().unwrap();
        assert_eq!(discovery.resolve_count(), 1);

        discovery.invalidate();
        let _ = discovery.poll_discover().unwrap();
        assert_eq!(discovery.resolve_count(), 2);
        crate::test_complete!("dns_discovery_invalidate_forces_resolve");
    }

    #[test]
    fn dns_discovery_endpoints_follow_custom_resolver() {
        init_test("dns_discovery_endpoints_follow_custom_resolver");
        let addrs = socket_set(&["127.0.0.1:80", "127.0.0.2:80"]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .with_resolver(move |_, _| Ok(addrs.clone())),
        );
        assert!(discovery.endpoints().is_empty());
        let _ = discovery.poll_discover().unwrap();
        assert_eq!(
            discovery.endpoints(),
            vec![
                "127.0.0.1:80".parse().unwrap(),
                "127.0.0.2:80".parse().unwrap(),
            ]
        );
        crate::test_complete!("dns_discovery_endpoints_follow_custom_resolver");
    }

    #[test]
    fn dns_discovery_custom_resolver_can_reenter_without_deadlock() {
        init_test("dns_discovery_custom_resolver_can_reenter_without_deadlock");
        let discovery_handle = Arc::new(StdMutex::new(None::<Arc<DnsServiceDiscovery>>));
        let discovery_handle_for_resolver = Arc::clone(&discovery_handle);
        let observed = Arc::new(StdMutex::new(None::<(u64, Vec<SocketAddr>)>));
        let observed_for_resolver = Arc::clone(&observed);
        let addrs = socket_set(&["127.0.0.1:80"]);

        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80).with_resolver(move |_, _| {
                let discovery = discovery_handle_for_resolver
                    .lock()
                    .expect("discovery handle lock poisoned")
                    .as_ref()
                    .cloned()
                    .expect("discovery handle installed before poll");
                let snapshot = (discovery.resolve_count(), discovery.endpoints());
                *observed_for_resolver
                    .lock()
                    .expect("observed snapshot lock poisoned") = Some(snapshot);
                Ok(addrs.clone())
            }),
        ));
        *discovery_handle
            .lock()
            .expect("discovery handle lock poisoned") = Some(Arc::clone(&discovery));

        let (tx, rx) = mpsc::channel();
        let discovery_for_thread = Arc::clone(&discovery);
        let worker = thread::spawn(move || {
            let result = discovery_for_thread.poll_discover();
            tx.send(result)
                .expect("reentrant resolver test channel should be open");
        });

        let result = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("poll_discover should not deadlock when the resolver re-enters discovery");
        worker
            .join()
            .expect("reentrant resolver worker should not panic");

        assert_eq!(
            result.unwrap(),
            vec![Change::Insert("127.0.0.1:80".parse().unwrap())]
        );
        assert_eq!(
            *observed.lock().expect("observed snapshot lock poisoned"),
            Some((0, Vec::new()))
        );
        assert_eq!(discovery.resolve_count(), 1);
        crate::test_complete!("dns_discovery_custom_resolver_can_reenter_without_deadlock");
    }

    #[test]
    fn dns_discovery_recovers_after_a_resolver_panic() {
        init_test("dns_discovery_recovers_after_a_resolver_panic");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_resolver = Arc::clone(&calls);
        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    if calls_for_resolver.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("resolver bug");
                    }
                    Ok(socket_set(&["127.0.0.1:80"]))
                }),
        ));

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = discovery.poll_discover();
        }));
        assert!(panicked.is_err(), "the resolver panic propagates");

        // The in-flight slot was left set, so the next poll waited forever
        // for a resolution that would never finish.
        let (tx, rx) = mpsc::channel();
        let next = Arc::clone(&discovery);
        thread::spawn(move || {
            let _ = tx.send(next.poll_discover());
        });
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the next poll must not block after a resolver panic");
        let changes = result.expect("the next resolution succeeds");
        assert_eq!(changes.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dns_discovery_concurrent_followers_coalesce_onto_inflight_success() {
        init_test("dns_discovery_concurrent_followers_coalesce_onto_inflight_success");
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let release_first = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        let release_first_for_resolver = Arc::clone(&release_first);
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_for_resolver = Arc::clone(&call_count);
        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    match call_count_for_resolver.fetch_add(1, Ordering::SeqCst) {
                        0 => {
                            first_started_tx
                                .send(())
                                .expect("first-started channel should be open");
                            let (lock, ready) = &*release_first_for_resolver;
                            let mut released = lock.lock().expect("release lock poisoned");
                            while !*released {
                                released = ready.wait(released).expect("release wait poisoned");
                            }
                            drop(released);
                            Ok(socket_set(&["127.0.0.1:80"]))
                        }
                        other => {
                            panic!("concurrent follower should not start resolver call {other}")
                        }
                    }
                }),
        ));

        let first_discovery = Arc::clone(&discovery);
        let first_worker = thread::spawn(move || first_discovery.poll_discover());
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first resolver call should start");

        let second_discovery = Arc::clone(&discovery);
        let second_worker = thread::spawn(move || second_discovery.poll_discover());

        // Wait for the follower to park on the resolve-done condvar before
        // releasing the leader. Joining the follower synchronously would
        // deadlock because the leader is still captive inside its resolver.
        let waiter_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while discovery.waiter_count() < 1 {
            assert!(
                std::time::Instant::now() <= waiter_deadline,
                "follower never parked on resolve_done within 5s"
            );
            thread::yield_now();
        }

        let (lock, ready) = &*release_first;
        *lock.lock().expect("release lock poisoned") = true;
        ready.notify_all();

        let second_result = second_worker
            .join()
            .expect("second worker should not panic")
            .expect("second poll should succeed");
        assert_eq!(second_result, Vec::<Change<SocketAddr>>::new());

        let first_result = first_worker
            .join()
            .expect("first worker should not panic")
            .expect("first poll should not fail");
        assert_eq!(
            first_result,
            vec![Change::Insert("127.0.0.1:80".parse().unwrap())]
        );
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(discovery.endpoints(), vec!["127.0.0.1:80".parse().unwrap()]);
        assert_eq!(discovery.resolve_count(), 1);
        crate::test_complete!("dns_discovery_concurrent_followers_coalesce_onto_inflight_success");
    }

    #[test]
    fn dns_discovery_concurrent_followers_share_inflight_failure() {
        init_test("dns_discovery_concurrent_followers_share_inflight_failure");
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let release_first = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        let release_first_for_resolver = Arc::clone(&release_first);
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_for_resolver = Arc::clone(&call_count);
        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    match call_count_for_resolver.fetch_add(1, Ordering::SeqCst) {
                        0 => {
                            first_started_tx
                                .send(())
                                .expect("first-started channel should be open");
                            let (lock, ready) = &*release_first_for_resolver;
                            let mut released = lock.lock().expect("release lock poisoned");
                            while !*released {
                                released = ready.wait(released).expect("release wait poisoned");
                            }
                            drop(released);
                            Err(std::io::Error::other("shared failure"))
                        }
                        other => {
                            panic!("concurrent follower should not start resolver call {other}")
                        }
                    }
                }),
        ));

        let first_discovery = Arc::clone(&discovery);
        let first_worker = thread::spawn(move || first_discovery.poll_discover());
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first resolver call should start");

        let second_discovery = Arc::clone(&discovery);
        let second_worker = thread::spawn(move || second_discovery.poll_discover());

        // Ensure the follower has parked on the condvar before releasing the
        // leader. Otherwise the scheduler may let the leader finish first,
        // in which case the follower would take the `needs_resolve` branch
        // and invoke the resolver a second time (panicking the test).
        let waiter_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while discovery.waiter_count() < 1 {
            assert!(
                std::time::Instant::now() <= waiter_deadline,
                "follower never parked on resolve_done within 5s"
            );
            thread::yield_now();
        }

        let (lock, ready) = &*release_first;
        *lock.lock().expect("release lock poisoned") = true;
        ready.notify_all();

        let first_err = first_worker
            .join()
            .expect("first worker should not panic")
            .expect_err("leader should report resolver failure");
        let second_err = second_worker
            .join()
            .expect("second worker should not panic")
            .expect_err("follower should receive shared resolver failure");
        assert_eq!(
            first_err.to_string(),
            "DNS resolution failed: shared failure"
        );
        assert_eq!(
            second_err.to_string(),
            "DNS resolution failed: shared failure"
        );
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert!(discovery.endpoints().is_empty());
        assert_eq!(discovery.resolve_count(), 0);
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_concurrent_followers_share_inflight_failure");
    }

    #[test]
    fn dns_discovery_new_refresh_after_failure_retries_normally() {
        init_test("dns_discovery_new_refresh_after_failure_retries_normally");
        let resolver = scripted_resolver(vec![
            Err(std::io::Error::other("first failure")),
            Ok(socket_set(&["127.0.0.1:80"])),
        ]);
        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(resolver),
        ));

        let first_err = discovery
            .poll_discover()
            .expect_err("first refresh should fail");
        assert_eq!(
            first_err.to_string(),
            "DNS resolution failed: first failure"
        );

        let first_result = discovery
            .poll_discover()
            .expect("next refresh should retry successfully");
        assert_eq!(
            first_result,
            vec![Change::Insert("127.0.0.1:80".parse().unwrap())]
        );
        assert_eq!(discovery.endpoints(), vec!["127.0.0.1:80".parse().unwrap()]);
        assert_eq!(discovery.resolve_count(), 1);
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_new_refresh_after_failure_retries_normally");
    }

    #[test]
    fn dns_changes_are_sorted_and_grouped() {
        let current: HashSet<SocketAddr> = [
            "127.0.0.3:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let new_addrs: HashSet<SocketAddr> = [
            "127.0.0.2:80".parse().unwrap(),
            "127.0.0.3:80".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        let changes = dns_changes(&current, &new_addrs);

        assert_eq!(
            changes,
            vec![
                Change::Insert("127.0.0.2:80".parse().unwrap()),
                Change::Remove("127.0.0.1:80".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn dns_discovery_endpoints_are_sorted() {
        let discovery = DnsServiceDiscovery::from_host("127.0.0.1", 80);
        discovery.state.lock().current = [
            "127.0.0.3:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            "127.0.0.2:80".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            discovery.endpoints(),
            vec![
                "127.0.0.1:80".parse().unwrap(),
                "127.0.0.2:80".parse().unwrap(),
                "127.0.0.3:80".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn dns_discovery_debug() {
        let discovery = DnsServiceDiscovery::from_host("127.0.0.1", 80);
        let dbg = format!("{discovery:?}");
        assert!(dbg.contains("DnsServiceDiscovery"));
        assert!(dbg.contains("127.0.0.1"));
    }

    #[test]
    fn dns_discovery_resolver_error_propagates() {
        init_test("dns_discovery_resolver_error_propagates");
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );
        let result = discovery.poll_discover();
        assert!(result.is_err());
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_resolver_error_propagates");
    }

    #[test]
    fn dns_discovery_failed_resolution_respects_poll_interval() {
        init_test("dns_discovery_failed_resolution_respects_poll_interval");
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(300))
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );

        let result = discovery.poll_discover();
        assert!(result.is_err());
        assert_eq!(discovery.error_count(), 1);
        assert!(discovery.state.lock().last_resolve.is_some());

        let second = discovery.poll_discover().unwrap();
        assert!(
            second.is_empty(),
            "retry should be rate-limited by poll_interval"
        );
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_failed_resolution_respects_poll_interval");
    }

    #[test]
    fn dns_discovery_time_getter_respects_poll_interval_without_sleep() {
        init_test("dns_discovery_time_getter_respects_poll_interval_without_sleep");
        set_test_time(0);
        let resolver = scripted_resolver(vec![
            Ok(socket_set(&["127.0.0.1:80"])),
            Ok(socket_set(&["127.0.0.1:80"])),
        ]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(30))
                .with_time_getter(test_time)
                .with_resolver(resolver),
        );

        let first = discovery.poll_discover().unwrap();
        assert!(!first.is_empty());
        assert_eq!(discovery.resolve_count(), 1);

        set_test_time(Duration::from_secs(10).as_nanos().min(u128::from(u64::MAX)) as u64);
        let second = discovery.poll_discover().unwrap();
        assert!(second.is_empty());
        assert_eq!(discovery.resolve_count(), 1);

        set_test_time(Duration::from_secs(30).as_nanos().min(u128::from(u64::MAX)) as u64);
        let third = discovery.poll_discover().unwrap();
        assert!(third.is_empty());
        assert_eq!(discovery.resolve_count(), 2);
        crate::test_complete!("dns_discovery_time_getter_respects_poll_interval_without_sleep");
    }

    #[test]
    fn dns_discovery_time_getter_controls_failed_resolution_cooldown() {
        init_test("dns_discovery_time_getter_controls_failed_resolution_cooldown");
        set_test_time(0);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(30))
                .with_time_getter(test_time)
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );

        assert!(discovery.poll_discover().is_err());
        assert_eq!(discovery.error_count(), 1);

        set_test_time(Duration::from_secs(10).as_nanos().min(u128::from(u64::MAX)) as u64);
        let second = discovery.poll_discover().unwrap();
        assert!(second.is_empty());
        assert_eq!(discovery.error_count(), 1);

        set_test_time(Duration::from_secs(30).as_nanos().min(u128::from(u64::MAX)) as u64);
        assert!(discovery.poll_discover().is_err());
        assert_eq!(discovery.error_count(), 2);
        crate::test_complete!("dns_discovery_time_getter_controls_failed_resolution_cooldown");
    }

    #[test]
    fn dns_discovery_invalidate_forces_retry_after_failed_resolution() {
        init_test("dns_discovery_invalidate_forces_retry_after_failed_resolution");
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(300))
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );

        let first = discovery.poll_discover();
        assert!(first.is_err());
        assert_eq!(discovery.error_count(), 1);

        discovery.invalidate();

        let second = discovery.poll_discover();
        assert!(second.is_err());
        assert_eq!(discovery.error_count(), 2);
        crate::test_complete!("dns_discovery_invalidate_forces_retry_after_failed_resolution");
    }

    // ================================================================
    // Regression: last_resolve uses decision-time `now`
    // ================================================================

    #[test]
    fn dns_discovery_last_resolve_uses_decision_time_not_post_resolve_time() {
        init_test("dns_discovery_last_resolve_uses_decision_time_not_post_resolve_time");
        // Before the fix, poll_discover() called time_getter() a second time
        // after resolve() returned to set last_resolve. With virtual time that
        // advances between calls, this pushed the cooldown window forward,
        // making the next re-resolution happen later than expected.
        //
        // After the fix, last_resolve is set to the `now` captured at the
        // start of poll_discover(), so the cooldown is anchored to the
        // decision point.
        set_test_time(1_000_000_000); // 1s
        let resolver = scripted_resolver(vec![
            Ok(socket_set(&["127.0.0.1:80"])),
            Ok(socket_set(&["127.0.0.1:80"])),
        ]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(10))
                .with_time_getter(test_time)
                .with_resolver(resolver),
        );

        let first = discovery.poll_discover().unwrap();
        assert!(!first.is_empty());

        // Verify that last_resolve was set to the decision time (1s),
        // not a later time. Advance virtual clock to exactly 1s + 10s = 11s.
        // If last_resolve used the decision time, this should trigger a
        // new resolution (11s - 1s = 10s >= poll_interval).
        set_test_time(11_000_000_000); // 11s
        let second = discovery.poll_discover().unwrap();
        // Should resolve again because 11s - 1s = 10s >= 10s poll_interval
        assert_eq!(
            discovery.resolve_count(),
            2,
            "last_resolve should anchor to decision time, allowing re-resolve at exactly poll_interval"
        );
        // second may be empty (same addresses) but resolution happened
        let _ = second;
        crate::test_complete!(
            "dns_discovery_last_resolve_uses_decision_time_not_post_resolve_time"
        );
    }

    // ================================================================
    // DnsDiscoveryError
    // ================================================================

    #[test]
    fn dns_error_display() {
        let io_err = std::io::Error::other("test");
        let err = DnsDiscoveryError::Resolve(io_err);
        let display = format!("{err}");
        assert!(display.contains("DNS resolution failed"));
    }

    #[test]
    fn dns_error_debug() {
        let io_err = std::io::Error::other("test");
        let err = DnsDiscoveryError::Resolve(io_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Resolve"));
    }

    #[test]
    fn dns_error_source() {
        use std::error::Error;
        let io_err = std::io::Error::other("test");
        let err = DnsDiscoveryError::Resolve(io_err);
        assert!(err.source().is_some());
    }

    // ================================================================
    // StaticList with SocketAddr
    // ================================================================

    #[test]
    fn static_list_socket_addrs() {
        init_test("static_list_socket_addrs");
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
        ];
        let list = StaticList::new(addrs.clone());

        let changes = list.poll_discover().unwrap();
        assert_eq!(changes.len(), 2);

        let endpoints = list.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.contains(&addrs[0]));
        assert!(endpoints.contains(&addrs[1]));
        crate::test_complete!("static_list_socket_addrs");
    }

    // ================================================================
    // Golden Tests: DNS Refresh Race Safety
    // ================================================================

    /// GT1: DNS refresh vs. in-flight request ordering
    ///
    /// Property: While a DNS refresh is in flight, followers must observe a
    /// stable (pre-refresh) endpoint snapshot and coalesce onto the leader's
    /// resolution rather than double-fire the resolver. Only the leader's
    /// resolved addresses are applied to the published endpoint set, and that
    /// application is atomic across the inflight window.
    #[test]
    fn golden_test_dns_refresh_vs_inflight_request_ordering() {
        init_test("golden_test_dns_refresh_vs_inflight_request_ordering");

        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (complete_first_tx, complete_first_rx) = mpsc::channel();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_for_resolver = Arc::clone(&call_count);

        let complete_first_rx = Arc::new(StdMutex::new(complete_first_rx));

        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    let call = call_count_for_resolver.fetch_add(1, Ordering::SeqCst);
                    match call {
                        0 => {
                            first_started_tx.send(()).expect("first started signal");
                            complete_first_rx
                                .lock()
                                .unwrap()
                                .recv()
                                .expect("wait for completion signal");
                            Ok(socket_set(&["10.0.0.1:80"]))
                        }
                        other => panic!("coalesced follower must not start resolver call {other}"),
                    }
                }),
        ));

        // Start first resolution in background (it parks inside the resolver
        // until we signal it to complete).
        let discovery_clone = Arc::clone(&discovery);
        let first_worker = thread::spawn(move || discovery_clone.poll_discover());

        // Wait for first resolution to start so we know the leader has claimed
        // the in-flight slot.
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first resolution should start");

        // While first resolution is in-flight, endpoints must still reflect
        // the pre-refresh (empty) snapshot. GT1 forbids partial publication.
        let endpoints_during_inflight = discovery.endpoints();
        assert!(
            endpoints_during_inflight.is_empty(),
            "Endpoints should be empty while resolution is in-flight"
        );

        // Spawn the follower and wait for it to park on the resolve-done
        // condvar before we release the leader. A synchronous join here would
        // deadlock because the leader is still captive inside its resolver.
        let discovery_clone2 = Arc::clone(&discovery);
        let second_worker = thread::spawn(move || discovery_clone2.poll_discover());

        let waiter_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while discovery.waiter_count() < 1 {
            assert!(
                std::time::Instant::now() <= waiter_deadline,
                "follower never parked on resolve_done within 5s"
            );
            thread::yield_now();
        }

        // Release the leader. It will publish its result atomically, then
        // notify any coalesced followers.
        complete_first_tx
            .send(())
            .expect("complete first resolution");

        let first_result = first_worker
            .join()
            .expect("first worker")
            .expect("first should succeed");
        assert_eq!(
            first_result,
            vec![Change::Insert("10.0.0.1:80".parse().unwrap())],
            "leader publishes its own resolution atomically"
        );

        // GT1: coalesced follower must return Ok(empty) and must not re-enter
        // the resolver (asserted by the resolver's panic arm).
        let second_result = second_worker
            .join()
            .expect("second worker should not panic")
            .expect("second should succeed");
        assert!(
            second_result.is_empty(),
            "coalesced follower observes the leader's commit, not a new change list"
        );

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(discovery.resolve_count(), 1);
        assert_eq!(
            discovery.endpoints(),
            vec!["10.0.0.1:80".parse().unwrap()],
            "Endpoints reflect the leader's committed resolution"
        );

        crate::test_complete!("golden_test_dns_refresh_vs_inflight_request_ordering");
    }

    /// GT2: Endpoint add/remove atomicity
    ///
    /// Property: When DNS returns a new set of endpoints, additions and
    /// removals should be atomic - either all changes are applied or none.
    #[test]
    fn golden_test_endpoint_add_remove_atomicity() {
        init_test("golden_test_endpoint_add_remove_atomicity");

        let resolver = scripted_resolver(vec![
            // Initial set
            Ok(socket_set(&["10.0.0.1:80", "10.0.0.2:80"])),
            // Atomic change: remove 10.0.0.1, add 10.0.0.3, keep 10.0.0.2
            Ok(socket_set(&["10.0.0.2:80", "10.0.0.3:80"])),
            // Another atomic change: add back 10.0.0.1, remove 10.0.0.2
            Ok(socket_set(&["10.0.0.1:80", "10.0.0.3:80"])),
        ]);

        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(resolver),
        );

        // First poll: establish initial set
        let changes1 = discovery.poll_discover().unwrap();
        assert_eq!(changes1.len(), 2);
        assert!(changes1.contains(&Change::Insert("10.0.0.1:80".parse().unwrap())));
        assert!(changes1.contains(&Change::Insert("10.0.0.2:80".parse().unwrap())));

        let endpoints1 = discovery.endpoints();
        assert_eq!(endpoints1.len(), 2);

        // Second poll: atomic change (remove one, add one)
        let changes2 = discovery.poll_discover().unwrap();
        assert_eq!(changes2.len(), 2);
        assert!(changes2.contains(&Change::Remove("10.0.0.1:80".parse().unwrap())));
        assert!(changes2.contains(&Change::Insert("10.0.0.3:80".parse().unwrap())));

        // GT2: All changes applied atomically
        let endpoints2 = discovery.endpoints();
        assert_eq!(
            endpoints2,
            vec![
                "10.0.0.2:80".parse().unwrap(),
                "10.0.0.3:80".parse().unwrap(),
            ]
        );

        // Third poll: another atomic change
        let changes3 = discovery.poll_discover().unwrap();
        assert_eq!(changes3.len(), 2);
        assert!(changes3.contains(&Change::Insert("10.0.0.1:80".parse().unwrap())));
        assert!(changes3.contains(&Change::Remove("10.0.0.2:80".parse().unwrap())));

        // GT2: Final state reflects complete atomic transition
        let endpoints3 = discovery.endpoints();
        assert_eq!(
            endpoints3,
            vec![
                "10.0.0.1:80".parse().unwrap(),
                "10.0.0.3:80".parse().unwrap(),
            ]
        );

        crate::test_complete!("golden_test_endpoint_add_remove_atomicity");
    }

    /// GT3: Generation counter monotonic
    ///
    /// Property: The generation counter must be strictly monotonic -
    /// each new resolution attempt gets a higher generation than the previous.
    /// In the concurrent case, followers coalesce onto the leader so exactly
    /// one resolver call fires and exactly one worker observes changes.
    #[test]
    fn golden_test_generation_counter_monotonic() {
        init_test("golden_test_generation_counter_monotonic");

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_for_resolver = Arc::clone(&call_count);
        let release_leader = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        let release_leader_for_resolver = Arc::clone(&release_leader);
        let (leader_started_tx, leader_started_rx) = mpsc::channel();

        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    let n = call_count_for_resolver.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        leader_started_tx
                            .send(())
                            .expect("leader-started channel should be open");
                        let (lock, cvar) = &*release_leader_for_resolver;
                        let mut released = lock.lock().expect("release lock poisoned");
                        while !*released {
                            released = cvar.wait(released).expect("release wait poisoned");
                        }
                        drop(released);
                        Ok(socket_set(&["10.0.0.1:80"]))
                    } else {
                        // Subsequent sequential invalidate/poll cycles run a
                        // plain resolver; each must bump the generation so
                        // the monotonicity assertion holds.
                        Ok(socket_set(&[&format!("10.0.0.{}:80", n + 1)]))
                    }
                }),
        ));

        // Spawn leader first, wait until it is captive in the resolver so
        // that every subsequent worker will observe `in_flight_generation`.
        let leader_discovery = Arc::clone(&discovery);
        let leader_worker = thread::spawn(move || leader_discovery.poll_discover());
        leader_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("leader resolver call should start");

        // Spawn four followers that must all park on the condvar.
        let follower_workers: Vec<_> = (0..4)
            .map(|_| {
                let discovery_clone = Arc::clone(&discovery);
                thread::spawn(move || discovery_clone.poll_discover())
            })
            .collect();

        // Wait until every follower has parked before releasing the leader.
        let waiter_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while discovery.waiter_count() < 4 {
            assert!(
                std::time::Instant::now() <= waiter_deadline,
                "only {} follower(s) parked on resolve_done within 5s",
                discovery.waiter_count()
            );
            thread::yield_now();
        }

        // Release the leader.
        {
            let (lock, cvar) = &*release_leader;
            *lock.lock().expect("release lock poisoned") = true;
            cvar.notify_all();
        }

        // GT3: exactly one worker (the leader) observes the change; all four
        // followers coalesce onto it and return Ok(empty).
        let leader_result = leader_worker
            .join()
            .expect("leader worker should not panic")
            .expect("leader should succeed");
        assert_eq!(
            leader_result,
            vec![Change::Insert("10.0.0.1:80".parse().unwrap())]
        );

        let mut non_empty = 1; // the leader already counted
        for follower in follower_workers {
            let changes = follower
                .join()
                .expect("follower worker should not panic")
                .expect("follower should succeed");
            if !changes.is_empty() {
                non_empty += 1;
            }
        }
        assert_eq!(
            non_empty, 1,
            "Only one concurrent resolution should produce changes due to coalescing"
        );
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(discovery.resolve_count(), 1);

        // Verify that subsequent resolutions get higher generations by testing sequentially
        let mut last_resolve_count = discovery.resolve_count();

        for i in 0..3 {
            discovery.invalidate(); // Force new resolution
            let _ = discovery.poll_discover();
            let current_count = discovery.resolve_count();

            // GT3: Resolve count should be strictly increasing (monotonic)
            assert!(
                current_count > last_resolve_count,
                "Generation {} should be higher than previous",
                i
            );
            last_resolve_count = current_count;
        }

        crate::test_complete!("golden_test_generation_counter_monotonic");
    }

    /// GT4: Race-free endpoint lookup
    ///
    /// Property: Reading endpoints while DNS refresh is happening should
    /// always return a consistent snapshot - never a partial or mixed state.
    #[test]
    fn golden_test_race_free_endpoint_lookup() {
        init_test("golden_test_race_free_endpoint_lookup");

        let (resolution_started_tx, resolution_started_rx) = mpsc::channel();
        let (continue_resolution_tx, continue_resolution_rx) = mpsc::channel();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_for_resolver = Arc::clone(&call_count);

        let continue_resolution_rx = Arc::new(StdMutex::new(continue_resolution_rx));

        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    let call = call_count_for_resolver.fetch_add(1, Ordering::SeqCst);
                    match call {
                        0 => Ok(socket_set(&["10.0.0.1:80"])),
                        1 => {
                            resolution_started_tx
                                .send(())
                                .expect("signal resolution start");
                            continue_resolution_rx
                                .lock()
                                .unwrap()
                                .recv()
                                .expect("wait for continue signal");
                            Ok(socket_set(&["10.0.0.2:80", "10.0.0.3:80"]))
                        }
                        _ => panic!("unexpected call {}", call),
                    }
                }),
        ));

        // Establish initial state
        let initial_changes = discovery.poll_discover().unwrap();
        assert_eq!(
            initial_changes,
            vec![Change::Insert("10.0.0.1:80".parse().unwrap())]
        );

        // Start background resolution
        let discovery_clone = Arc::clone(&discovery);
        let background_worker = thread::spawn(move || discovery_clone.poll_discover());

        // Wait for background resolution to start
        resolution_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background resolution should start");

        // Perform many concurrent endpoint lookups while resolution is in progress
        let lookup_workers: Vec<_> = (0..10)
            .map(|_| {
                let discovery_clone = Arc::clone(&discovery);
                thread::spawn(move || {
                    // GT4: Each lookup should return consistent snapshot
                    let endpoints = discovery_clone.endpoints();

                    // Verify consistency: should be either old state or new state, never mixed
                    if endpoints.len() == 1 {
                        assert_eq!(endpoints, vec!["10.0.0.1:80".parse().unwrap()]);
                    } else if endpoints.len() == 2 {
                        assert_eq!(
                            endpoints,
                            vec![
                                "10.0.0.2:80".parse().unwrap(),
                                "10.0.0.3:80".parse().unwrap(),
                            ]
                        );
                    } else {
                        panic!("Inconsistent endpoint count: {}", endpoints.len());
                    }

                    endpoints.len()
                })
            })
            .collect();

        // Allow some lookups to run, then complete the resolution
        thread::sleep(Duration::from_millis(10));
        continue_resolution_tx.send(()).expect("signal continue");

        // Wait for background resolution to complete
        let background_result = background_worker
            .join()
            .expect("background worker should complete")
            .expect("background resolution should succeed");

        assert_eq!(
            background_result,
            vec![
                Change::Insert("10.0.0.2:80".parse().unwrap()),
                Change::Insert("10.0.0.3:80".parse().unwrap()),
                Change::Remove("10.0.0.1:80".parse().unwrap()),
            ]
        );

        // Collect lookup results
        let mut old_state_count = 0;
        let mut new_state_count = 0;

        for worker in lookup_workers {
            let endpoint_count = worker.join().expect("lookup worker should complete");
            match endpoint_count {
                1 => old_state_count += 1,
                2 => new_state_count += 1,
                _ => panic!("Invalid endpoint count"),
            }
        }

        // GT4: All lookups should have seen consistent state
        assert!(
            old_state_count > 0 || new_state_count > 0,
            "Should have observed at least one consistent state"
        );

        // Final state should be the new state
        assert_eq!(
            discovery.endpoints(),
            vec![
                "10.0.0.2:80".parse().unwrap(),
                "10.0.0.3:80".parse().unwrap(),
            ]
        );

        crate::test_complete!("golden_test_race_free_endpoint_lookup");
    }

    /// GT5: Concurrent refresh coalesced
    ///
    /// Property: Multiple concurrent refresh requests should be coalesced
    /// into a single DNS resolution to avoid thundering herd.
    #[test]
    fn golden_test_concurrent_refresh_coalesced() {
        init_test("golden_test_concurrent_refresh_coalesced");

        let resolution_count = Arc::new(AtomicUsize::new(0));
        let resolution_count_for_resolver = Arc::clone(&resolution_count);
        let (leader_started_tx, leader_started_rx) = mpsc::channel();
        let release_leader = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        let release_leader_for_resolver = Arc::clone(&release_leader);

        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    let count = resolution_count_for_resolver.fetch_add(1, Ordering::SeqCst);
                    if count == 0 {
                        leader_started_tx
                            .send(())
                            .expect("leader-started channel should be open");
                        let (lock, cvar) = &*release_leader_for_resolver;
                        let mut released = lock.lock().expect("release lock poisoned");
                        while !*released {
                            released = cvar.wait(released).expect("release wait poisoned");
                        }
                        drop(released);
                    } else {
                        panic!("coalesced follower should not start resolver call {count}");
                    }
                    Ok(socket_set(&[&format!("10.0.0.{}:80", count + 1)]))
                }),
        ));

        // Start a leader that will park inside the resolver, then spawn
        // followers that must each observe the in-flight slot and park on
        // the condvar. Using `waiter_count` makes the synchronisation
        // deterministic; the old "sleep 1ms" stagger raced with the
        // scheduler and let some followers miss the in-flight window.
        let leader_discovery = Arc::clone(&discovery);
        let leader_worker = thread::spawn(move || leader_discovery.poll_discover());
        leader_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("leader resolver call should start");

        let follower_workers: Vec<_> = (0..4)
            .map(|_| {
                let discovery_clone = Arc::clone(&discovery);
                thread::spawn(move || discovery_clone.poll_discover())
            })
            .collect();

        let waiter_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while discovery.waiter_count() < 4 {
            assert!(
                std::time::Instant::now() <= waiter_deadline,
                "only {} follower(s) parked on resolve_done within 5s",
                discovery.waiter_count()
            );
            thread::yield_now();
        }

        // Allow the leader to complete. It will then notify all followers.
        {
            let (lock, cvar) = &*release_leader;
            *lock.lock().expect("release lock poisoned") = true;
            cvar.notify_all();
        }

        // Collect results: leader sees Insert, followers see empty.
        let mut successful_results = 0;
        let mut empty_results = 0;

        let leader_changes = leader_worker
            .join()
            .expect("leader worker should complete")
            .expect("leader should succeed");
        if leader_changes.is_empty() {
            empty_results += 1;
        } else {
            successful_results += 1;
            assert_eq!(leader_changes.len(), 1);
            assert_eq!(
                leader_changes[0],
                Change::Insert("10.0.0.1:80".parse().unwrap())
            );
        }

        for worker in follower_workers {
            let changes = worker
                .join()
                .expect("follower worker should complete")
                .expect("follower should succeed");
            if changes.is_empty() {
                empty_results += 1;
            } else {
                successful_results += 1;
            }
        }

        // GT5: Only one resolution should have occurred despite multiple concurrent requests
        let total_resolutions = resolution_count.load(Ordering::SeqCst);
        assert_eq!(
            total_resolutions, 1,
            "Concurrent refreshes should be coalesced into single resolution"
        );

        // GT5: Only one worker should get the changes, others get empty results
        assert_eq!(
            successful_results, 1,
            "Only one worker should receive changes"
        );
        assert_eq!(
            empty_results, 4,
            "Other workers should receive empty results due to coalescing"
        );

        // Verify final state
        assert_eq!(discovery.resolve_count(), 1);
        assert_eq!(discovery.endpoints(), vec!["10.0.0.1:80".parse().unwrap()]);

        crate::test_complete!("golden_test_concurrent_refresh_coalesced");
    }
