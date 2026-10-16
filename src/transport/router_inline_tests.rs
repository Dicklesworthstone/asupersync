    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::Cx;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::error::SinkError;
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use serde_json::json;
    use std::collections::HashSet;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Poll};

    fn test_endpoint(id: u64) -> Endpoint {
        Endpoint::new(EndpointId(id), format!("node-{id}:8080"))
    }

    fn object_id_for_hash_primary(
        seed: u64,
        endpoints: &[Arc<Endpoint>],
        target: EndpointId,
    ) -> ObjectId {
        let lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, seed);
        for key in 0..10_000 {
            let object_id = ObjectId::new_for_test(key);
            if lb
                .select(endpoints, Some(object_id))
                .is_some_and(|endpoint| endpoint.id == target)
            {
                return object_id;
            }
        }
        panic!("fixture could not find object id for primary {target}");
    }

    fn test_authenticated_symbol(esi: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, esi);
        let symbol = Symbol::new(id, vec![esi as u8], SymbolKind::Source);
        AuthenticatedSymbol::new_verified(symbol, AuthenticationTag::zero())
    }

    #[cfg(feature = "messaging-fabric")]
    fn test_admin_cx() -> Cx {
        let cx = Cx::for_testing();
        cx.grant_fabric_capability(FabricCapability::AdminControl)
            .expect("admin capability grant should be valid");
        cx
    }

    fn scrub_endpoint_region(region: Option<RegionId>) -> Option<&'static str> {
        let _ = region?;
        Some("<region>")
    }

    fn scrub_route_key(key: &RouteKey) -> &'static str {
        match key {
            RouteKey::Object(_) => "object:<object>",
            RouteKey::Region(_) => "region:<region>",
            RouteKey::ObjectAndRegion(_, _) => "object+region:<object>:<region>",
            RouteKey::Default => "default",
        }
    }

    fn routing_entry_snapshot(entry: &RoutingEntry) -> serde_json::Value {
        json!({
            "strategy": format!("{:?}", entry.load_balancer.strategy),
            "priority": entry.priority,
            "ttl_ms": entry.ttl.map(Time::as_millis),
            "endpoint_ids": entry
                .endpoints
                .iter()
                .map(|endpoint| endpoint.id.to_string())
                .collect::<Vec<_>>(),
        })
    }

    fn routing_table_snapshot(table: &RoutingTable) -> serde_json::Value {
        let mut endpoints = table.endpoints.read().values().cloned().collect::<Vec<_>>();
        endpoints.sort_unstable_by_key(|endpoint| endpoint.id);

        let mut routes = table
            .routes
            .read()
            .iter()
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect::<Vec<_>>();
        routes.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));

        json!({
            "route_count": table.route_count(),
            "dispatchable_endpoint_ids": table
                .dispatchable_endpoints()
                .into_iter()
                .map(|endpoint| endpoint.id.to_string())
                .collect::<Vec<_>>(),
            "endpoints": endpoints
                .into_iter()
                .map(|endpoint| json!({
                    "id": endpoint.id.to_string(),
                    "address": endpoint.address,
                    "state": format!("{:?}", endpoint.state()),
                    "weight": endpoint.weight,
                    "region": scrub_endpoint_region(endpoint.region),
                }))
                .collect::<Vec<_>>(),
            "default_route": table
                .default_route
                .read()
                .as_ref()
                .map(routing_entry_snapshot),
            "routes": routes
                .into_iter()
                .map(|(key, entry)| json!({
                    "key": scrub_route_key(&key),
                    "entry": routing_entry_snapshot(&entry),
                }))
                .collect::<Vec<_>>(),
        })
    }

    struct InterruptedSink;

    impl SymbolSink for InterruptedSink {
        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Err(SinkError::Io {
                source: io::Error::new(io::ErrorKind::Interrupted, "synthetic interrupt"),
            }))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    struct CancellingInterruptedSink {
        cancel_cx: Cx,
    }

    impl SymbolSink for CancellingInterruptedSink {
        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            self.cancel_cx.set_cancel_requested(true);
            Poll::Ready(Err(SinkError::Io {
                source: io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
            }))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    struct ReentrantDispatchSink {
        dispatcher: Arc<SymbolDispatcher>,
        cx: Cx,
        reentrant_failed_fast: Arc<AtomicBool>,
    }

    impl SymbolSink for ReentrantDispatchSink {
        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            let this = self.get_mut();
            let nested = future::block_on(this.dispatcher.dispatch_with_strategy(
                &this.cx,
                test_authenticated_symbol(7001),
                DispatchStrategy::Unicast,
            ));

            match nested {
                Err(DispatchError::SendFailed { reason, .. })
                    if reason.contains("reentrant dispatch") =>
                {
                    this.reentrant_failed_fast.store(true, Ordering::Release);
                    Poll::Ready(Ok(()))
                }
                other => Poll::Ready(Err(SinkError::SendFailed {
                    reason: format!("nested same-endpoint dispatch did not fail fast: {other:?}"),
                })),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    // Test 1: Endpoint state predicates
    #[test]
    fn test_endpoint_state() {
        let conformance = [
            (EndpointState::Healthy, true, true),
            (EndpointState::Degraded, true, true),
            (EndpointState::Unhealthy, false, true),
            (EndpointState::Draining, false, true),
            (EndpointState::Removed, false, false),
        ];

        for (state, can_receive, is_available) in conformance {
            assert_eq!(
                state.can_receive(),
                can_receive,
                "{state:?} dispatchability changed"
            );
            assert_eq!(
                state.is_available(),
                is_available,
                "{state:?} availability changed"
            );
        }
    }

    // Test 2: Endpoint statistics
    #[test]
    fn test_endpoint_statistics() {
        let endpoint = test_endpoint(1);

        endpoint.record_success(Time::from_secs(1));
        endpoint.record_success(Time::from_secs(2));
        endpoint.record_failure(Time::from_secs(3));

        assert_eq!(endpoint.symbols_sent.load(Ordering::Relaxed), 2);
        assert_eq!(endpoint.failures.load(Ordering::Relaxed), 1);

        // Failure rate: 1 / (2 + 1) = 0.333...
        let rate = endpoint.failure_rate();
        assert!(rate > 0.3 && rate < 0.34);
    }

    #[test]
    fn endpoint_exports_path_quality_snapshot() {
        let endpoint = test_endpoint(1);
        endpoint.record_success(Time::from_secs(1));
        endpoint.record_success(Time::from_secs(2));
        endpoint.record_failure(Time::from_secs(3));

        let quality = endpoint.encoding_path_quality(44, 3);

        assert_eq!(quality.rtt_ewma_ms, 44);
        assert_eq!(quality.loss_ewma_permille, 333);
        assert_eq!(quality.reorder_depth, 3);
    }

    // Test 3: Load balancer round robin
    #[test]
    fn test_load_balancer_round_robin() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);

        let endpoints: Vec<Arc<Endpoint>> = (1..=3).map(|i| Arc::new(test_endpoint(i))).collect();

        let e1 = lb.select(&endpoints, None);
        let e2 = lb.select(&endpoints, None);
        let e3 = lb.select(&endpoints, None);
        let e4 = lb.select(&endpoints, None); // Should wrap around

        assert_eq!(e1.unwrap().id, EndpointId(1));
        assert_eq!(e2.unwrap().id, EndpointId(2));
        assert_eq!(e3.unwrap().id, EndpointId(3));
        assert_eq!(e4.unwrap().id, EndpointId(1));
    }

    // Test 4: Load balancer least connections
    #[test]
    fn test_load_balancer_least_connections() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::LeastConnections);

        let e1 = Arc::new(test_endpoint(1));
        let e2 = Arc::new(test_endpoint(2));
        let e3 = Arc::new(test_endpoint(3));

        e1.active_connections.store(5, Ordering::Relaxed);
        e2.active_connections.store(2, Ordering::Relaxed);
        e3.active_connections.store(10, Ordering::Relaxed);

        let endpoints = vec![e1, e2.clone(), e3];

        let selected = lb.select(&endpoints, None).unwrap();
        assert_eq!(selected.id, e2.id); // Least connections
    }

    #[test]
    fn test_load_balancer_least_connections_selects_single_max_load_endpoint() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::LeastConnections);
        let endpoint = Arc::new(test_endpoint(1));
        endpoint
            .active_connections
            .store(u32::MAX, Ordering::Relaxed);

        let selected = lb
            .select(std::slice::from_ref(&endpoint), None)
            .expect("single healthy endpoint must still be selectable at max load");
        assert_eq!(selected.id, endpoint.id);

        let selected_n = lb.select_n(std::slice::from_ref(&endpoint), 1, None);
        assert_eq!(selected_n.len(), 1);
        assert_eq!(selected_n[0].id, endpoint.id);
    }

    #[test]
    fn test_load_balancer_weighted_least_connections() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::WeightedLeastConnections);

        let e1 = Arc::new(test_endpoint(1).with_weight(1));
        let e2 = Arc::new(test_endpoint(2).with_weight(4));
        let e3 = Arc::new(test_endpoint(3).with_weight(2));

        e1.active_connections.store(2, Ordering::Relaxed); // 2.0
        e2.active_connections.store(4, Ordering::Relaxed); // 1.0
        e3.active_connections.store(3, Ordering::Relaxed); // 1.5

        let endpoints = vec![e1, e2.clone(), e3];
        let selected = lb.select(&endpoints, None).unwrap();
        assert_eq!(selected.id, e2.id);
    }

    // Test 5: Load balancer hash-based
    #[test]
    fn test_load_balancer_hash_based() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::HashBased);

        let endpoints: Vec<Arc<Endpoint>> = (1..=3).map(|i| Arc::new(test_endpoint(i))).collect();

        let oid = ObjectId::new_for_test(42);

        // Same ObjectId should always select same endpoint
        let s1 = lb.select(&endpoints, Some(oid));
        let s2 = lb.select(&endpoints, Some(oid));
        assert_eq!(s1.unwrap().id, s2.unwrap().id);
    }

    // br-asupersync-v535in: HashBased now uses consistent hashing,
    // so removing or adding a single endpoint must NOT remap the
    // majority of object_ids. This is the security/correctness
    // contract that broke pre-fix when the strategy used `hash %
    // count` — every endpoint change shuffled every key.
    #[test]
    fn test_load_balancer_hash_based_sticky_under_endpoint_changes_v535in() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::HashBased);

        // 16 endpoints, 1024 sample keys. Record where each key
        // routes initially.
        let endpoints_full: Vec<Arc<Endpoint>> =
            (1..=16).map(|i| Arc::new(test_endpoint(i))).collect();
        let initial: Vec<EndpointId> = (0..1024)
            .map(|k| {
                let oid = ObjectId::new_for_test(k as u64);
                lb.select(&endpoints_full, Some(oid)).unwrap().id
            })
            .collect();

        // Remove the LAST endpoint and re-route every key.
        let endpoints_minus1: Vec<Arc<Endpoint>> = endpoints_full[..15].to_vec();
        let after_remove: Vec<EndpointId> = (0..1024)
            .map(|k| {
                let oid = ObjectId::new_for_test(k as u64);
                lb.select(&endpoints_minus1, Some(oid)).unwrap().id
            })
            .collect();

        // Every key that previously hit endpoints 1..15 (i.e., NOT
        // the removed one) must still hit the SAME endpoint. With
        // modulo hashing, removing one endpoint shifts the count
        // from 16 to 15 and `hash % count` re-maps every key —
        // typical remap rate is 15/16 ≈ 94%. With consistent
        // hashing, only keys that previously hit the removed
        // endpoint must remap (the ~1/16 share). The threshold here
        // is conservative: assert that >= 80% of keys are sticky.
        let stickies = initial
            .iter()
            .zip(after_remove.iter())
            .filter(|(a, b)| a == b)
            .count();
        assert!(
            stickies >= 800,
            "consistent hashing must preserve sticky routing for >= 80% of keys after \
             a single endpoint removal; got {stickies}/1024 stuck (modulo-hash baseline \
             would be near 64/1024 by symmetry)"
        );
        // And no key that previously hit endpoints 1..=15 should
        // suddenly hit a different surviving endpoint.
        let removed_id = endpoints_full[15].id;
        let mismatches = initial
            .iter()
            .zip(after_remove.iter())
            .filter(|(before, after)| **before != removed_id && before != after)
            .count();
        // mismatches should be 0 with strict consistent hashing.
        // We allow up to 5% slop for ring boundary effects since
        // healthy() is filtered before ring construction.
        assert!(
            mismatches <= 51,
            "non-trivial cross-endpoint remapping after single removal: {mismatches}/1024 (must be <= ~5%)",
        );
    }

    #[test]
    fn test_load_balancer_hash_based_select_n_is_order_invariant() {
        let lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, 0x0057_AF1D_u64);
        let endpoints: Vec<Arc<Endpoint>> = (1..=8).map(|i| Arc::new(test_endpoint(i))).collect();
        let permuted = vec![
            endpoints[5].clone(),
            endpoints[2].clone(),
            endpoints[7].clone(),
            endpoints[1].clone(),
            endpoints[4].clone(),
            endpoints[0].clone(),
            endpoints[6].clone(),
            endpoints[3].clone(),
        ];
        let oid = ObjectId::new_for_test(42);

        let selected: Vec<_> = lb
            .select_n(&endpoints, 3, Some(oid))
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();
        let permuted_selected: Vec<_> = lb
            .select_n(&permuted, 3, Some(oid))
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();

        assert_eq!(
            selected, permuted_selected,
            "hash-based fanout must depend on membership, not endpoint iteration order",
        );

        let unique_ids: HashSet<_> = selected.iter().copied().collect();
        assert_eq!(unique_ids.len(), selected.len());
    }

    #[test]
    fn test_load_balancer_hash_based_select_n_preserves_survivors_under_endpoint_removal_m0izs9() {
        let lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, 0x0057_AF1D_u64);
        let oid = ObjectId::new_for_test(42);

        // Original membership: 8 endpoints
        let endpoints: Vec<Arc<Endpoint>> = (1..=8).map(|i| Arc::new(test_endpoint(i))).collect();

        // Select 3 endpoints from full membership
        let original_selected: Vec<_> = lb
            .select_n(&endpoints, 3, Some(oid))
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();

        // Remove endpoints 2 and 6 (membership churn)
        let reduced_endpoints: Vec<Arc<Endpoint>> = endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.id != EndpointId::new(2) && endpoint.id != EndpointId::new(6)
            })
            .cloned()
            .collect();

        // Select 3 endpoints from reduced membership
        let churn_selected: Vec<_> = lb
            .select_n(&reduced_endpoints, 3, Some(oid))
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();

        // Find survivors: endpoints that were selected originally and are still in the pool
        let surviving_in_original: Vec<_> = original_selected
            .iter()
            .filter(|&&id| reduced_endpoints.iter().any(|e| e.id == id))
            .copied()
            .collect();

        let surviving_in_churn: Vec<_> = churn_selected
            .iter()
            .filter(|&&id| original_selected.contains(&id))
            .copied()
            .collect();

        // Hash-based routing should preserve stickiness for survivors
        assert_eq!(
            surviving_in_original, surviving_in_churn,
            "hash-based select_n must preserve survivors under membership churn"
        );

        // All selections should still be unique
        let unique_original: HashSet<_> = original_selected.iter().copied().collect();
        assert_eq!(unique_original.len(), original_selected.len());
        let unique_churn: HashSet<_> = churn_selected.iter().copied().collect();
        assert_eq!(unique_churn.len(), churn_selected.len());
    }

    #[test]
    fn test_bounded_load_hash_keeps_primary_when_within_capacity() {
        let seed = 0xB011_D1ED_u64;
        let config = BoundedLoadConfig::new(0, 1, 1);
        let hash_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, seed);
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed)
            .with_bounded_load_config(config);
        let endpoints: Vec<Arc<Endpoint>> = (1..=4)
            .map(|id| Arc::new(test_endpoint(id).with_weight(2)))
            .collect();
        let object_id = ObjectId::new_for_test(42);

        let primary = hash_lb
            .select(&endpoints, Some(object_id))
            .expect("hash primary");
        let selected = bounded_lb
            .select(&endpoints, Some(object_id))
            .expect("bounded-load selection");
        let decision = bounded_lb.bounded_load_decision(&endpoints, Some(object_id));

        assert_eq!(selected.id, primary.id);
        assert_eq!(decision.primary, Some(primary.id));
        assert_eq!(decision.selected, Some(primary.id));
        assert_eq!(
            decision.reason,
            BoundedLoadRebalanceReason::PrimaryWithinCapacity
        );
    }

    #[test]
    fn test_bounded_load_capacity_extreme_policy_saturates() {
        let config = BoundedLoadConfig::new(u32::MAX, 1, u32::MAX);
        let endpoint = test_endpoint(1).with_weight(u32::MAX);

        // br-asupersync-qfgsh1: extreme u32 policy inputs are treated as overflow
        // attacks and clamped to a bounded, safe capacity rather than allowed to
        // saturate to u32::MAX (which would defeat the load-bound). The contract is
        // that capacity_for never panics and never returns an unbounded value: with
        // min_capacity == 1 the bounded fallback floors at the minimum capacity.
        let capacity = config.capacity_for(&endpoint);
        assert_eq!(
            capacity, 1,
            "bounded-load capacity must clamp extreme inputs to the bounded fallback instead of saturating to u32::MAX or panicking"
        );
        assert!(
            capacity <= 100_000,
            "bounded-load capacity must stay within the hardened upper bound"
        );
    }

    #[test]
    fn test_bounded_load_hash_rebalances_over_capacity_primary() {
        let seed = 0xB011_D1ED_u64;
        let config = BoundedLoadConfig::new(0, 1, 1);
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed)
            .with_bounded_load_config(config);
        let endpoints: Vec<Arc<Endpoint>> = (1..=4)
            .map(|id| Arc::new(test_endpoint(id).with_weight(1)))
            .collect();
        let primary_id = EndpointId::new(1);
        let object_id = object_id_for_hash_primary(seed, &endpoints, primary_id);
        endpoints[0].active_connections.store(1, Ordering::Relaxed);

        let selected = bounded_lb
            .select(&endpoints, Some(object_id))
            .expect("bounded-load selection");
        let decision = bounded_lb.bounded_load_decision(&endpoints, Some(object_id));
        let primary_telemetry = decision
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == primary_id)
            .expect("primary telemetry");

        assert_ne!(selected.id, primary_id);
        assert_eq!(decision.primary, Some(primary_id));
        assert_eq!(decision.selected, Some(selected.id));
        assert_eq!(
            decision.reason,
            BoundedLoadRebalanceReason::PrimaryOverCapacityRebalanced
        );
        assert_eq!(primary_telemetry.actual_load, 1);
        assert_eq!(primary_telemetry.capacity, 1);
        assert!(!primary_telemetry.within_capacity);
    }

    #[test]
    fn test_bounded_load_hash_all_over_capacity_falls_back_to_primary() {
        let seed = 0xB011_D1ED_u64;
        let config = BoundedLoadConfig::new(0, 1, 1);
        let hash_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, seed);
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed)
            .with_bounded_load_config(config);
        let endpoints: Vec<Arc<Endpoint>> = (1..=4)
            .map(|id| Arc::new(test_endpoint(id).with_weight(1)))
            .collect();
        for endpoint in &endpoints {
            endpoint.active_connections.store(1, Ordering::Relaxed);
        }
        let object_id = ObjectId::new_for_test(777);

        let primary = hash_lb
            .select(&endpoints, Some(object_id))
            .expect("hash primary");
        let selected = bounded_lb
            .select(&endpoints, Some(object_id))
            .expect("bounded-load selection");
        let decision = bounded_lb.bounded_load_decision(&endpoints, Some(object_id));

        assert_eq!(selected.id, primary.id);
        assert_eq!(decision.primary, Some(primary.id));
        assert_eq!(decision.selected, Some(primary.id));
        assert_eq!(
            decision.reason,
            BoundedLoadRebalanceReason::AllEndpointsOverCapacityFallback
        );
        assert!(
            decision
                .endpoints
                .iter()
                .all(|endpoint| !endpoint.within_capacity)
        );
    }

    #[test]
    fn test_bounded_load_hash_select_n_prefers_under_capacity_unique_endpoints() {
        let seed = 0xB011_D1ED_u64;
        let config = BoundedLoadConfig::new(0, 1, 1);
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed)
            .with_bounded_load_config(config);
        let endpoints: Vec<Arc<Endpoint>> = (1..=5)
            .map(|id| Arc::new(test_endpoint(id).with_weight(1)))
            .collect();
        endpoints[0].active_connections.store(1, Ordering::Relaxed);
        endpoints[1].active_connections.store(1, Ordering::Relaxed);

        let selected = bounded_lb.select_n(&endpoints, 3, Some(ObjectId::new_for_test(99)));
        let unique: HashSet<_> = selected.iter().map(|endpoint| endpoint.id).collect();

        assert_eq!(selected.len(), 3);
        assert_eq!(unique.len(), selected.len());
        assert!(
            selected
                .iter()
                .all(|endpoint| endpoint.connection_count() < config.capacity_for(endpoint)),
            "select_n should fill from under-capacity endpoints when enough are available"
        );
    }

    #[test]
    fn test_bounded_load_hash_select_n_all_over_capacity_falls_back_to_hrw_order() {
        let seed = 0xB011_D1ED_u64;
        let config = BoundedLoadConfig::new(0, 1, 1);
        let hash_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, seed);
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed)
            .with_bounded_load_config(config);
        let endpoints: Vec<Arc<Endpoint>> = (1..=5)
            .map(|id| Arc::new(test_endpoint(id).with_weight(1)))
            .collect();
        for endpoint in &endpoints {
            endpoint
                .active_connections
                .store(config.capacity_for(endpoint), Ordering::Relaxed);
        }
        let object_id = ObjectId::new_for_test(0xE2);

        let selected = bounded_lb.select_n(&endpoints, 3, Some(object_id));
        let expected = hash_lb.select_n(&endpoints, 3, Some(object_id));
        let selected_ids: Vec<_> = selected.iter().map(|endpoint| endpoint.id).collect();
        let expected_ids: Vec<_> = expected.iter().map(|endpoint| endpoint.id).collect();
        let unique: HashSet<_> = selected_ids.iter().copied().collect();

        assert_eq!(
            selected_ids, expected_ids,
            "all-over-capacity bounded-load fanout must retain deterministic HRW fallback order"
        );
        assert_eq!(unique.len(), selected_ids.len());
        assert!(
            selected
                .iter()
                .all(|endpoint| endpoint.connection_count() >= config.capacity_for(endpoint)),
            "fixture must exercise the all-over-capacity fallback path"
        );
    }

    #[test]
    fn test_bounded_load_hash_preserves_survivors_under_endpoint_removal() {
        let lb =
            LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, 0x0057_AF1D_u64)
                .with_bounded_load_config(BoundedLoadConfig::new(250, 1, 1));
        let endpoints_full: Vec<Arc<Endpoint>> =
            (1..=16).map(|i| Arc::new(test_endpoint(i))).collect();
        let initial: Vec<EndpointId> = (0..1024)
            .map(|key| {
                lb.select(&endpoints_full, Some(ObjectId::new_for_test(key)))
                    .expect("initial bounded-load route")
                    .id
            })
            .collect();

        let endpoints_minus1: Vec<Arc<Endpoint>> = endpoints_full[..15].to_vec();
        let after_remove: Vec<EndpointId> = (0..1024)
            .map(|key| {
                lb.select(&endpoints_minus1, Some(ObjectId::new_for_test(key)))
                    .expect("bounded-load route after removal")
                    .id
            })
            .collect();

        let stickies = initial
            .iter()
            .zip(after_remove.iter())
            .filter(|(before, after)| before == after)
            .count();
        let removed_id = endpoints_full[15].id;
        let mismatches = initial
            .iter()
            .zip(after_remove.iter())
            .filter(|(before, after)| **before != removed_id && before != after)
            .count();

        assert!(
            stickies >= 800,
            "bounded-load HRW should preserve sticky routing for >= 80% of keys after removal; got {stickies}/1024"
        );
        assert!(
            mismatches <= 51,
            "bounded-load HRW should not churn surviving primaries; got {mismatches}/1024"
        );
    }

    #[test]
    fn test_bounded_load_hash_skew_scenario_logs_operator_artifact() {
        let seed = 0x51A0_B0A7_u64;
        let config = BoundedLoadConfig::new(0, 1, 2);
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed)
            .with_bounded_load_config(config);
        let endpoints: Vec<Arc<Endpoint>> = (1..=4)
            .map(|id| Arc::new(test_endpoint(id).with_weight(1)))
            .collect();
        let primary_id = EndpointId::new(1);
        let object_id = object_id_for_hash_primary(seed, &endpoints, primary_id);
        endpoints[0].active_connections.store(5, Ordering::Relaxed);
        endpoints[1].active_connections.store(1, Ordering::Relaxed);
        endpoints[2].active_connections.store(0, Ordering::Relaxed);
        endpoints[3].active_connections.store(0, Ordering::Relaxed);

        let decision = bounded_lb.bounded_load_decision(&endpoints, Some(object_id));
        let artifact = json!({
            "scenario": "bounded_load_hash_hot_primary",
            "seed": seed,
            "object_id": format!("{:?}", object_id),
            "config": {
                "epsilon_milli": config.epsilon_milli,
                "min_capacity": config.min_capacity,
                "capacity_per_weight": config.capacity_per_weight,
            },
            "primary": decision.primary.map(|id| id.to_string()),
            "selected": decision.selected.map(|id| id.to_string()),
            "reason": format!("{:?}", decision.reason),
            "endpoints": decision
                .endpoints
                .iter()
                .map(|endpoint| json!({
                    "endpoint_id": endpoint.endpoint_id.to_string(),
                    "actual_load": endpoint.actual_load,
                    "capacity": endpoint.capacity,
                    "within_capacity": endpoint.within_capacity,
                    "is_primary": endpoint.is_primary,
                    "is_selected": endpoint.is_selected,
                }))
                .collect::<Vec<_>>(),
        });
        println!(
            "bounded_load_hash_skew_artifact={}",
            serde_json::to_string_pretty(&artifact).expect("artifact is json")
        );

        assert_eq!(decision.primary, Some(primary_id));
        assert_ne!(decision.selected, Some(primary_id));
        assert_eq!(
            decision.reason,
            BoundedLoadRebalanceReason::PrimaryOverCapacityRebalanced
        );
        assert!(decision.endpoints.iter().any(|endpoint| {
            endpoint.is_selected && endpoint.within_capacity && endpoint.endpoint_id != primary_id
        }));
    }

    fn assert_bounded_load_log_keyset(fields: &BTreeMap<String, String>) {
        // br-asupersync-36grbm: Updated to use security-hardened bucketed field names
        // that prevent timing attacks and endpoint reconnaissance.
        let expected = [
            "available_endpoint_bucket",
            "decision_id",
            "endpoint_pressure_aggregate",
            "fairness_policy_id",
            "fairness_state",
            "overloaded_endpoint_bucket",
            "primary_selection_occurred",
            "rebalance_reason",
            "rejected_endpoint_bucket",
            "selection_occurred",
            "strategy_id",
            "within_capacity_endpoint_bucket",
        ];
        let actual = fields.keys().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_bounded_load_rebalance_reason_ids_are_stable() {
        assert_eq!(
            BoundedLoadRebalanceReason::NoHealthyEndpoints.reason_id(),
            "no-healthy-endpoints"
        );
        assert_eq!(
            BoundedLoadRebalanceReason::NoObjectIdFallback.reason_id(),
            "no-object-id-fallback"
        );
        assert_eq!(
            BoundedLoadRebalanceReason::PrimaryWithinCapacity.reason_id(),
            "primary-within-capacity"
        );
        assert_eq!(
            BoundedLoadRebalanceReason::PrimaryOverCapacityRebalanced.reason_id(),
            "primary-over-capacity-rebalanced"
        );
        assert_eq!(
            BoundedLoadRebalanceReason::AllEndpointsOverCapacityFallback.reason_id(),
            "all-endpoints-over-capacity-fallback"
        );
    }

    #[test]
    fn test_bounded_load_decision_log_fields_capture_rejected_pressure() {
        let seed = 0x51A0_B0A7_u64;
        let config = BoundedLoadConfig::new(0, 1, 1);
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed)
            .with_bounded_load_config(config);
        let endpoints: Vec<Arc<Endpoint>> = (1..=4)
            .map(|id| Arc::new(test_endpoint(id).with_weight(1)))
            .collect();
        let primary_id = EndpointId::new(1);
        let object_id = object_id_for_hash_primary(seed, &endpoints, primary_id);
        endpoints[0].active_connections.store(3, Ordering::Relaxed);
        endpoints[1].active_connections.store(0, Ordering::Relaxed);
        endpoints[2].active_connections.store(1, Ordering::Relaxed);
        endpoints[3].active_connections.store(0, Ordering::Relaxed);

        let decision = bounded_lb.bounded_load_decision(&endpoints, Some(object_id));
        let fields = decision.log_fields();
        let rejected_ids = decision.rejected_endpoint_ids();

        assert_bounded_load_log_keyset(&fields);
        assert_eq!(
            fields.get("decision_id").map(String::as_str),
            Some(BoundedLoadDecision::DECISION_ID)
        );
        assert_eq!(
            fields.get("strategy_id").map(String::as_str),
            Some("bounded-load-hash")
        );
        assert_eq!(
            fields.get("fairness_policy_id").map(String::as_str),
            Some(BoundedLoadDecision::FAIRNESS_POLICY_ID)
        );
        // br-asupersync-36grbm: log_fields() is security-hardened and exposes only
        // bucketed aggregates and boolean indicators (no raw endpoint IDs or exact
        // counts) to prevent timing/reconnaissance attacks. Raw endpoint identities
        // are still available via the non-logged rejected_endpoint_ids() accessor.
        assert_eq!(
            fields.get("rebalance_reason").map(String::as_str),
            Some("primary-over-capacity-rebalanced")
        );
        assert_eq!(
            fields.get("primary_selection_occurred").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            fields.get("selection_occurred").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            fields.get("available_endpoint_bucket").map(String::as_str),
            Some("3-5")
        );
        assert_eq!(
            fields.get("rejected_endpoint_bucket").map(String::as_str),
            Some("3-5")
        );
        assert_eq!(
            fields.get("overloaded_endpoint_bucket").map(String::as_str),
            Some("1-2")
        );
        assert_eq!(
            fields
                .get("within_capacity_endpoint_bucket")
                .map(String::as_str),
            Some("1-2")
        );
        let fairness_state = fields
            .get("fairness_state")
            .map(String::as_str)
            .expect("bounded-load logs carry fairness_state");
        assert!(fairness_state.contains("policy=hrw-bounded-load"));
        assert!(fairness_state.contains("primary_selected=true"));
        assert!(fairness_state.contains("selection_occurred=true"));
        assert!(fairness_state.contains("available_bucket=3-5"));
        assert!(fairness_state.contains("rejected_bucket=3-5"));
        assert!(fairness_state.contains("overloaded_bucket=1-2"));
        assert!(fairness_state.contains("within_capacity_bucket=1-2"));
        assert_eq!(
            fields
                .get("endpoint_pressure_aggregate")
                .map(String::as_str),
            Some("total_bucket=3-5;within_capacity_bucket=1-2;over_capacity_bucket=1-2")
        );
        // The raw (non-logged) accessor still exposes the rejected endpoints, with the
        // selected endpoint omitted from the rejected alternatives.
        assert_eq!(
            rejected_ids.len(),
            3,
            "selected endpoint must be omitted from rejected alternatives"
        );
        assert!(rejected_ids.contains(&primary_id));
    }

    #[test]
    fn test_bounded_load_decision_log_fields_cover_no_selection_edges() {
        let seed = 0xB011_D1ED_u64;
        let bounded_lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::BoundedLoadHash, seed);
        let endpoints: Vec<Arc<Endpoint>> = (1..=2)
            .map(|id| Arc::new(test_endpoint(id).with_weight(1)))
            .collect();

        let missing_key_decision = bounded_lb.bounded_load_decision(&endpoints, None);
        let missing_key_fields = missing_key_decision.log_fields();
        assert_bounded_load_log_keyset(&missing_key_fields);
        assert_eq!(
            missing_key_fields
                .get("rebalance_reason")
                .map(String::as_str),
            Some("no-object-id-fallback")
        );
        // br-asupersync-36grbm: hardened log_fields omits raw endpoint IDs/exact
        // counts; with no object id there is no selection, so the boolean
        // indicators are false and counts are bucketed.
        assert_eq!(
            missing_key_fields
                .get("selection_occurred")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            missing_key_fields
                .get("primary_selection_occurred")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            missing_key_fields.get("fairness_state").map(String::as_str),
            Some(
                "policy=hrw-bounded-load;primary_selected=false;selection_occurred=false;available_bucket=1-2;rejected_bucket=1-2;overloaded_bucket=0;within_capacity_bucket=1-2"
            )
        );
        assert_eq!(
            missing_key_fields
                .get("rejected_endpoint_bucket")
                .map(String::as_str),
            Some("1-2")
        );
        // The raw (non-logged) accessor still surfaces the rejected endpoints.
        assert_eq!(
            missing_key_decision.rejected_endpoint_ids().as_slice(),
            &[EndpointId::new(1), EndpointId::new(2)]
        );

        for endpoint in &endpoints {
            endpoint.set_state(EndpointState::Unhealthy);
        }
        let no_healthy_decision =
            bounded_lb.bounded_load_decision(&endpoints, Some(ObjectId::new_for_test(7)));
        let no_healthy_fields = no_healthy_decision.log_fields();
        assert_bounded_load_log_keyset(&no_healthy_fields);
        assert_eq!(
            no_healthy_fields
                .get("rebalance_reason")
                .map(String::as_str),
            Some("no-healthy-endpoints")
        );
        // br-asupersync-36grbm: Updated to use bucketed field names and values
        assert_eq!(
            no_healthy_fields
                .get("available_endpoint_bucket")
                .map(String::as_str),
            Some("0")
        );
        assert_eq!(
            no_healthy_fields
                .get("endpoint_pressure_aggregate")
                .map(String::as_str),
            Some("total_bucket=0;within_capacity_bucket=0;over_capacity_bucket=0")
        );
        assert_eq!(
            no_healthy_fields.get("fairness_state").map(String::as_str),
            Some(
                "policy=hrw-bounded-load;primary_selected=false;selection_occurred=false;available_bucket=0;rejected_bucket=0;overloaded_bucket=0;within_capacity_bucket=0"
            )
        );
    }

    #[test]
    fn test_load_balancer_random_select_n_returns_unique_healthy() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::Random);
        let endpoints: Vec<Arc<Endpoint>> = (0..10)
            .map(|i| {
                let endpoint = test_endpoint(i);
                if i % 3 == 0 {
                    Arc::new(endpoint.with_state(EndpointState::Unhealthy))
                } else {
                    Arc::new(endpoint)
                }
            })
            .collect();

        let selected = lb.select_n(&endpoints, 3, None);
        assert_eq!(selected.len(), 3);
        assert!(
            selected
                .iter()
                .all(|endpoint| endpoint.state().can_receive())
        );

        let unique_ids: HashSet<_> = selected.iter().map(|endpoint| endpoint.id).collect();
        assert_eq!(unique_ids.len(), selected.len());
    }

    #[test]
    fn test_load_balancer_random_select_n_returns_all_healthy_when_n_large() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::Random);
        let endpoints = vec![
            Arc::new(test_endpoint(1).with_state(EndpointState::Healthy)),
            Arc::new(test_endpoint(2).with_state(EndpointState::Unhealthy)),
            Arc::new(test_endpoint(3).with_state(EndpointState::Degraded)),
            Arc::new(test_endpoint(4).with_state(EndpointState::Draining)),
            Arc::new(test_endpoint(5).with_state(EndpointState::Healthy)),
        ];

        let selected = lb.select_n(&endpoints, 16, None);
        let mut selected_ids: Vec<_> = selected.iter().map(|endpoint| endpoint.id).collect();
        selected_ids.sort();
        assert_eq!(
            selected_ids,
            vec![EndpointId::new(1), EndpointId::new(3), EndpointId::new(5)]
        );
    }

    #[test]
    fn test_load_balancer_random_select_n_single_matches_select_sequence() {
        let lb_select = LoadBalancer::new(LoadBalanceStrategy::Random);
        let lb_select_n = LoadBalancer::new(LoadBalanceStrategy::Random);
        let endpoints: Vec<Arc<Endpoint>> = (0..8)
            .map(|i| {
                let endpoint = test_endpoint(i);
                if i % 4 == 0 {
                    Arc::new(endpoint.with_state(EndpointState::Unhealthy))
                } else {
                    Arc::new(endpoint)
                }
            })
            .collect();

        for _ in 0..64 {
            let selected = lb_select
                .select(&endpoints, None)
                .map(|endpoint| endpoint.id);
            let selected_n = lb_select_n
                .select_n(&endpoints, 1, None)
                .first()
                .map(|endpoint| endpoint.id);
            assert_eq!(selected, selected_n);
        }
    }

    #[test]
    fn test_load_balancer_random_select_single_is_uniform_over_healthy() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::Random);
        let endpoints = vec![
            Arc::new(test_endpoint(0).with_state(EndpointState::Healthy)),
            Arc::new(test_endpoint(100).with_state(EndpointState::Unhealthy)),
            Arc::new(test_endpoint(1).with_state(EndpointState::Healthy)),
            Arc::new(test_endpoint(101).with_state(EndpointState::Draining)),
            Arc::new(test_endpoint(2).with_state(EndpointState::Healthy)),
        ];

        let mut counts = [0usize; 3];
        for _ in 0..3000 {
            let selected = lb.select_n(&endpoints, 1, None);
            assert_eq!(selected.len(), 1);
            let id = selected[0].id;
            if id == EndpointId::new(0) {
                counts[0] += 1;
            } else if id == EndpointId::new(1) {
                counts[1] += 1;
            } else if id == EndpointId::new(2) {
                counts[2] += 1;
            } else {
                panic!("selected unhealthy endpoint: {id:?}"); // ubs:ignore - test logic
            }
        }

        assert_eq!(counts.iter().sum::<usize>(), 3000);
        // 3000 draws over 3 healthy endpoints should stay close to 1000 each.
        for count in counts {
            assert!((900..=1100).contains(&count), "non-uniform count: {count}");
        }
    }

    #[test]
    fn test_load_balancer_random_select_n_small_all_healthy_is_unique() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::Random);
        let endpoints: Vec<Arc<Endpoint>> = (0..16).map(|i| Arc::new(test_endpoint(i))).collect();

        for _ in 0..64 {
            let selected = lb.select_n(&endpoints, 3, None);
            assert_eq!(selected.len(), 3);
            assert!(
                selected
                    .iter()
                    .all(|endpoint| endpoint.state().can_receive())
            );
            let unique_ids: HashSet<_> = selected.iter().map(|endpoint| endpoint.id).collect();
            assert_eq!(unique_ids.len(), selected.len());
        }
    }

    #[test]
    fn test_load_balancer_weighted_least_connections_select_n_uses_weights() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::WeightedLeastConnections);

        let e1 = Arc::new(test_endpoint(1).with_weight(1));
        let e2 = Arc::new(test_endpoint(2).with_weight(4));
        let e3 = Arc::new(test_endpoint(3).with_weight(2));
        let e4 = Arc::new(test_endpoint(4).with_weight(2));

        e1.active_connections.store(4, Ordering::Relaxed); // 4.0
        e2.active_connections.store(4, Ordering::Relaxed); // 1.0
        e3.active_connections.store(4, Ordering::Relaxed); // 2.0
        e4.active_connections.store(1, Ordering::Relaxed); // 0.5

        let endpoints = vec![e1, e2.clone(), e3, e4.clone()];
        let selected = lb.select_n(&endpoints, 2, None);
        let selected_ids: Vec<_> = selected.iter().map(|endpoint| endpoint.id).collect();
        assert_eq!(selected_ids, vec![e4.id, e2.id]);
    }

    #[test]
    fn test_load_balancer_least_connections_select_n_preserves_input_order_on_ties() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::LeastConnections);

        let e1 = Arc::new(test_endpoint(1));
        let e2 = Arc::new(test_endpoint(2));
        let e3 = Arc::new(test_endpoint(3));
        let e4 = Arc::new(test_endpoint(4));

        e1.active_connections.store(2, Ordering::Relaxed);
        e2.active_connections.store(2, Ordering::Relaxed);
        e3.active_connections.store(2, Ordering::Relaxed);
        e4.active_connections.store(5, Ordering::Relaxed);

        let endpoints = vec![e1.clone(), e2.clone(), e3.clone(), e4];
        let selected = lb.select_n(&endpoints, 3, None);
        let selected_ids: Vec<_> = selected.iter().map(|endpoint| endpoint.id).collect();
        assert_eq!(selected_ids, vec![e1.id, e2.id, e3.id]);
    }

    #[test]
    fn test_load_balancer_weighted_least_connections_select_n_preserves_input_order_on_ties() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::WeightedLeastConnections);

        let e1 = Arc::new(test_endpoint(1).with_weight(1));
        let e2 = Arc::new(test_endpoint(2).with_weight(2));
        let e3 = Arc::new(test_endpoint(3).with_weight(3));
        let e4 = Arc::new(test_endpoint(4).with_weight(1));

        e1.active_connections.store(3, Ordering::Relaxed); // 3.0
        e2.active_connections.store(6, Ordering::Relaxed); // 3.0
        e3.active_connections.store(9, Ordering::Relaxed); // 3.0
        e4.active_connections.store(7, Ordering::Relaxed); // 7.0

        let endpoints = vec![e1.clone(), e2.clone(), e3.clone(), e4];
        let selected = lb.select_n(&endpoints, 3, None);
        let selected_ids: Vec<_> = selected.iter().map(|endpoint| endpoint.id).collect();
        assert_eq!(selected_ids, vec![e1.id, e2.id, e3.id]);
    }

    #[test]
    fn test_load_balancer_weighted_round_robin_select_n_honors_weight_ring() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::WeightedRoundRobin);

        let heavy = Arc::new(test_endpoint(1).with_weight(5));
        let medium = Arc::new(test_endpoint(2).with_weight(1));
        let light = Arc::new(test_endpoint(3).with_weight(1));
        let endpoints = vec![heavy.clone(), medium.clone(), light.clone()];

        let first: Vec<_> = lb
            .select_n(&endpoints, 2, None)
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();
        let second: Vec<_> = lb
            .select_n(&endpoints, 2, None)
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();
        let third: Vec<_> = lb
            .select_n(&endpoints, 2, None)
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();

        assert_eq!(first, vec![heavy.id, medium.id]);
        assert_eq!(second, vec![light.id, heavy.id]);
        assert_eq!(third, vec![heavy.id, medium.id]);
    }

    #[test]
    fn test_load_balancer_weighted_round_robin_select_n_handles_extreme_weight_skew() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::WeightedRoundRobin);

        let heavy = Arc::new(test_endpoint(1).with_weight(u32::MAX));
        let light = Arc::new(test_endpoint(2).with_weight(1));
        let endpoints = vec![heavy.clone(), light.clone()];

        let selected: Vec<_> = lb
            .select_n(&endpoints, 2, None)
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();

        assert_eq!(selected, vec![heavy.id, light.id]);
    }

    #[test]
    fn metamorphic_weighted_round_robin_select_n_ignores_unreceivable_and_zero_weight_decoys() {
        fn weighted_rr_sequence(endpoints: &[Arc<Endpoint>]) -> Vec<Vec<EndpointId>> {
            let lb = LoadBalancer::with_test_salt(LoadBalanceStrategy::WeightedRoundRobin, 0x5EED);
            (0..4)
                .map(|_| {
                    lb.select_n(endpoints, 2, None)
                        .into_iter()
                        .map(|endpoint| endpoint.id)
                        .collect()
                })
                .collect()
        }

        let heavy = Arc::new(test_endpoint(1).with_weight(5));
        let medium = Arc::new(test_endpoint(2).with_weight(1));
        let light = Arc::new(test_endpoint(3).with_weight(1));
        let baseline = vec![heavy.clone(), medium.clone(), light.clone()];

        let unreceivable_decoy = Arc::new(
            test_endpoint(99)
                .with_weight(u32::MAX)
                .with_state(EndpointState::Unhealthy),
        );
        let zero_weight_decoy = Arc::new(test_endpoint(100).with_weight(0));
        let with_decoys = vec![zero_weight_decoy, unreceivable_decoy, heavy, medium, light];

        assert_eq!(
            weighted_rr_sequence(&baseline),
            weighted_rr_sequence(&with_decoys),
            "weighted round-robin fanout must ignore endpoints that cannot consume ring slots"
        );
    }

    // Test 6: Routing table basic operations
    #[test]
    fn test_routing_table_basic() {
        let table = RoutingTable::new();

        let _e1 = table.register_endpoint(test_endpoint(1));
        let e2 = table.register_endpoint(test_endpoint(2));

        assert!(table.get_endpoint(EndpointId(1)).is_some());
        assert!(table.get_endpoint(EndpointId(999)).is_none());

        let entry = RoutingEntry::new(vec![e2], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        assert_eq!(table.route_count(), 1);
    }

    // Test 7: Routing table lookup with fallback
    #[test]
    fn test_routing_table_lookup() {
        let table = RoutingTable::new();

        let e1 = table.register_endpoint(test_endpoint(1));
        let e2 = table.register_endpoint(test_endpoint(2));

        // Add default route
        let default = RoutingEntry::new(vec![e1], Time::ZERO);
        table.add_route(RouteKey::Default, default);

        // Add specific object route
        let oid = ObjectId::new_for_test(42);
        let specific = RoutingEntry::new(vec![e2], Time::ZERO);
        table.add_route(RouteKey::Object(oid), specific);

        // Lookup specific route
        let found = table.lookup(&RouteKey::Object(oid), Time::ZERO);
        assert!(found.is_some());

        // Lookup unknown object falls back to default
        let other_oid = ObjectId::new_for_test(999);
        let found = table.lookup(&RouteKey::Object(other_oid), Time::ZERO);
        assert!(found.is_some()); // Default route
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn test_remove_endpoint_scrubs_routes_and_restores_default_fallback() {
        let table = Arc::new(RoutingTable::new());
        let specific = table.register_endpoint(test_endpoint(1));
        let fallback = table.register_endpoint(test_endpoint(2));

        let object_id = ObjectId::new_for_test(42);
        table.add_route(
            RouteKey::Object(object_id),
            RoutingEntry::new(vec![specific.clone()], Time::ZERO),
        );
        table.add_route(
            RouteKey::Default,
            RoutingEntry::new(vec![fallback.clone()], Time::ZERO),
        );

        let router = SymbolRouter::new(table.clone());
        let symbol = Symbol::new_for_test(42, 0, 0, &[1, 2, 3]);

        let initial = router
            .route(&symbol, Time::ZERO)
            .expect("initial specific route");
        assert_eq!(initial.endpoint.id, specific.id);

        let test_cx = test_admin_cx();
        let removed = table
            .remove_endpoint(&test_cx, specific.id)
            .expect("remove_endpoint should succeed")
            .expect("specific endpoint removed");
        assert_eq!(removed.id, specific.id);
        assert!(table.get_endpoint(specific.id).is_none());

        let routed = router
            .route(&symbol, Time::ZERO)
            .expect("fallback route after removal");
        assert_eq!(routed.endpoint.id, fallback.id);

        assert!(
            table
                .lookup_without_default(&RouteKey::Object(object_id), Time::ZERO)
                .is_none(),
            "endpoint removal must prune now-empty keyed routes so default fallback can apply"
        );
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn test_remove_endpoint_drops_empty_default_route() {
        let table = Arc::new(RoutingTable::new());
        let endpoint = table.register_endpoint(test_endpoint(7));
        table.add_route(
            RouteKey::Default,
            RoutingEntry::new(vec![endpoint.clone()], Time::ZERO),
        );

        let test_cx = test_admin_cx();
        let removed = table
            .remove_endpoint(&test_cx, endpoint.id)
            .expect("remove_endpoint should succeed")
            .expect("default endpoint removed");
        assert_eq!(removed.id, endpoint.id);
        assert!(table.lookup(&RouteKey::Default, Time::ZERO).is_none());
        assert!(table.dispatchable_endpoints().is_empty());

        let router = SymbolRouter::new(table);
        let symbol = Symbol::new_for_test(1, 0, 0, &[9]);
        assert!(matches!(
            router.route(&symbol, Time::ZERO),
            Err(RoutingError::NoRoute { .. })
        ));
    }

    #[test]
    fn test_remove_endpoint_requires_admin_capability() {
        let table = RoutingTable::new();
        let endpoint = table.register_endpoint(test_endpoint(11));
        let test_cx = Cx::for_testing();

        let error = table
            .remove_endpoint(&test_cx, endpoint.id)
            .expect_err("plain test context must not administer endpoints");

        assert_eq!(error.kind(), ErrorKind::AdmissionDenied);
        assert!(table.get_endpoint(endpoint.id).is_some());
    }

    // Test 8: Routing entry TTL
    #[test]
    fn test_routing_entry_ttl() {
        let entry = RoutingEntry::new(vec![], Time::from_secs(100)).with_ttl(Time::from_secs(60));

        assert!(!entry.is_expired(Time::from_secs(150)));
        assert!(entry.is_expired(Time::from_secs(160)));
        assert!(entry.is_expired(Time::from_secs(170)));
    }

    // Test 9: Routing table prune expired
    #[test]
    fn test_routing_table_prune() {
        let table = RoutingTable::new();

        let e1 = table.register_endpoint(test_endpoint(1));

        // Add routes with different TTLs
        let entry1 =
            RoutingEntry::new(vec![e1.clone()], Time::from_secs(0)).with_ttl(Time::from_secs(10));
        let entry2 = RoutingEntry::new(vec![e1], Time::from_secs(0)).with_ttl(Time::from_secs(100));

        table.add_route(RouteKey::Object(ObjectId::new_for_test(1)), entry1);
        table.add_route(RouteKey::Object(ObjectId::new_for_test(2)), entry2);

        assert_eq!(table.route_count(), 2);

        // Prune at time 50 - should remove first entry
        let pruned = table.prune_expired(Time::from_secs(50));
        assert_eq!(pruned, 1);
        assert_eq!(table.route_count(), 1);
    }

    #[test]
    fn test_routing_table_prune_includes_default_route() {
        let table = RoutingTable::new();
        let e1 = table.register_endpoint(test_endpoint(1));

        // Add a default route with a short TTL.
        let default_entry =
            RoutingEntry::new(vec![e1], Time::from_secs(0)).with_ttl(Time::from_secs(10));
        table.add_route(RouteKey::Default, default_entry);
        assert_eq!(table.route_count(), 1);

        // Prune at time 50 — the expired default route must be removed.
        let pruned = table.prune_expired(Time::from_secs(50));
        assert_eq!(pruned, 1);
        assert_eq!(table.route_count(), 0);
    }

    // Test 10: SymbolRouter basic routing
    #[test]
    fn test_symbol_router() {
        let table = Arc::new(RoutingTable::new());
        let e1 = table.register_endpoint(test_endpoint(1));

        let entry = RoutingEntry::new(vec![e1], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let result = router.route(&symbol, Time::ZERO);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().endpoint.id, EndpointId(1));
    }

    // Test 10.0: SymbolRouter respects `without_fallback`.
    #[test]
    fn test_symbol_router_without_fallback() {
        let table = Arc::new(RoutingTable::new());
        let e1 = table.register_endpoint(test_endpoint(1));

        // Default route exists, but there is no object-specific route.
        let entry = RoutingEntry::new(vec![e1], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table).without_fallback();

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let result = router.route(&symbol, Time::ZERO);

        assert!(
            result.is_err(),
            "without_fallback should reject default-only route"
        );
    }

    // Test 10.1: SymbolRouter failover to healthy endpoint
    #[test]
    fn test_symbol_router_failover() {
        let table = Arc::new(RoutingTable::new());

        let primary =
            table.register_endpoint(test_endpoint(1).with_state(EndpointState::Unhealthy));
        let backup = table.register_endpoint(test_endpoint(2).with_state(EndpointState::Healthy));

        let entry = RoutingEntry::new(vec![primary, backup.clone()], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::FirstAvailable);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table);
        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let result = router.route(&symbol, Time::ZERO).expect("route");

        assert_eq!(result.endpoint.id, backup.id);
    }

    #[test]
    fn test_symbol_router_object_route_with_only_unhealthy_endpoints_returns_no_healthy() {
        let table = Arc::new(RoutingTable::new());
        let object_id = ObjectId::new_for_test(77);
        let unhealthy =
            table.register_endpoint(test_endpoint(1).with_state(EndpointState::Unhealthy));
        let entry = RoutingEntry::new(vec![unhealthy], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::FirstAvailable);
        table.add_route(RouteKey::Object(object_id), entry);

        let router = SymbolRouter::new(table);
        let symbol = Symbol::new_for_test(77, 0, 0, &[1, 2, 3]);

        let result = router.route(&symbol, Time::ZERO);
        assert!(matches!(
            result,
            Err(RoutingError::NoHealthyEndpoints { object_id: oid }) if oid == object_id
        ));
    }

    #[test]
    fn test_symbol_router_unhealthy_default_route_returns_no_healthy() {
        let table = Arc::new(RoutingTable::new());
        let object_id = ObjectId::new_for_test(88);
        let unhealthy =
            table.register_endpoint(test_endpoint(1).with_state(EndpointState::Unhealthy));
        let entry = RoutingEntry::new(vec![unhealthy], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::FirstAvailable);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table);
        let symbol = Symbol::new_for_test(88, 0, 0, &[1, 2, 3]);

        let result = router.route(&symbol, Time::ZERO);
        assert!(matches!(
            result,
            Err(RoutingError::NoHealthyEndpoints { object_id: oid }) if oid == object_id
        ));
    }

    #[test]
    fn test_symbol_router_without_any_route_still_returns_no_route() {
        let table = Arc::new(RoutingTable::new());
        let router = SymbolRouter::new(table);
        let object_id = ObjectId::new_for_test(99);
        let symbol = Symbol::new_for_test(99, 0, 0, &[1, 2, 3]);

        let result = router.route(&symbol, Time::ZERO);
        assert!(matches!(
            result,
            Err(RoutingError::NoRoute { object_id: oid, .. }) if oid == object_id
        ));
    }

    #[test]
    fn test_symbol_router_local_preference_unicast() {
        let table = Arc::new(RoutingTable::new());
        let local_region = RegionId::new_for_test(7, 0);
        let remote_region = RegionId::new_for_test(8, 0);

        let remote = table.register_endpoint(
            test_endpoint(1)
                .with_region(remote_region)
                .with_state(EndpointState::Healthy),
        );
        let local = table.register_endpoint(
            test_endpoint(2)
                .with_region(local_region)
                .with_state(EndpointState::Healthy),
        );

        let object_id = ObjectId::new_for_test(42);
        let entry = RoutingEntry::new(vec![remote, local.clone()], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::FirstAvailable);
        table.add_route(RouteKey::Object(object_id), entry);

        let router = SymbolRouter::new(table).with_local_preference(local_region);
        let symbol = Symbol::new_for_test(42, 0, 0, &[1, 2, 3]);
        let result = router
            .route(&symbol, Time::ZERO)
            .expect("route with local preference");

        assert_eq!(result.endpoint.id, local.id);
        assert!(!result.is_fallback);
    }

    // Test 11: SymbolRouter multicast
    #[test]
    fn test_symbol_router_multicast() {
        let table = Arc::new(RoutingTable::new());
        let e1 = table.register_endpoint(test_endpoint(1));
        let e2 = table.register_endpoint(test_endpoint(2));
        let e3 = table.register_endpoint(test_endpoint(3));

        let entry = RoutingEntry::new(vec![e1, e2, e3], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let results = router.route_multicast(&symbol, 2, Time::ZERO);

        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 2);
    }

    #[test]
    fn test_symbol_router_multicast_weighted_round_robin_respects_weights_across_calls() {
        let table = Arc::new(RoutingTable::new());
        let heavy = table.register_endpoint(test_endpoint(1).with_weight(5));
        let medium = table.register_endpoint(test_endpoint(2).with_weight(1));
        let light = table.register_endpoint(test_endpoint(3).with_weight(1));

        let object_id = ObjectId::new_for_test(77);
        let entry = RoutingEntry::new(
            vec![heavy.clone(), medium.clone(), light.clone()],
            Time::ZERO,
        )
        .with_strategy(LoadBalanceStrategy::WeightedRoundRobin);
        table.add_route(RouteKey::Object(object_id), entry);

        let router = SymbolRouter::new(table);
        let symbol = Symbol::new_for_test(77, 0, 0, &[7, 7]);

        let first: Vec<_> = router
            .route_multicast(&symbol, 2, Time::ZERO)
            .expect("first weighted multicast")
            .into_iter()
            .map(|route| route.endpoint.id)
            .collect();
        let second: Vec<_> = router
            .route_multicast(&symbol, 2, Time::ZERO)
            .expect("second weighted multicast")
            .into_iter()
            .map(|route| route.endpoint.id)
            .collect();
        let third: Vec<_> = router
            .route_multicast(&symbol, 2, Time::ZERO)
            .expect("third weighted multicast")
            .into_iter()
            .map(|route| route.endpoint.id)
            .collect();

        assert_eq!(first, vec![heavy.id, medium.id]);
        assert_eq!(second, vec![light.id, heavy.id]);
        assert_eq!(third, vec![heavy.id, medium.id]);
    }

    #[test]
    fn test_symbol_router_local_preference_multicast_fills_local_first() {
        let table = Arc::new(RoutingTable::new());
        let local_region = RegionId::new_for_test(11, 0);
        let remote_region = RegionId::new_for_test(12, 0);

        let local_a = table.register_endpoint(
            test_endpoint(1)
                .with_region(local_region)
                .with_state(EndpointState::Healthy),
        );
        let remote = table.register_endpoint(
            test_endpoint(2)
                .with_region(remote_region)
                .with_state(EndpointState::Healthy),
        );
        let local_b = table.register_endpoint(
            test_endpoint(3)
                .with_region(local_region)
                .with_state(EndpointState::Healthy),
        );

        let object_id = ObjectId::new_for_test(9);
        let entry = RoutingEntry::new(vec![local_a.clone(), remote, local_b.clone()], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::RoundRobin);
        table.add_route(RouteKey::Object(object_id), entry);

        let router = SymbolRouter::new(table).with_local_preference(local_region);
        let symbol = Symbol::new_for_test(9, 0, 0, &[9]);
        let multicast_routes = router
            .route_multicast(&symbol, 2, Time::ZERO)
            .expect("multicast with local preference");

        let selected: HashSet<_> = multicast_routes
            .into_iter()
            .map(|route| route.endpoint.id)
            .collect();
        let expected: HashSet<_> = [local_a.id, local_b.id].into_iter().collect();
        assert_eq!(selected, expected);
    }

    // Test 12: DispatchResult quorum check
    #[test]
    fn test_dispatch_result_quorum() {
        let result = DispatchResult {
            successes: 3,
            failures: 1,
            sent_to: smallvec![EndpointId(1), EndpointId(2), EndpointId(3)],
            failed_endpoints: SmallVec::new(),
            duration: Time::ZERO,
        };

        assert!(result.quorum_reached(2));
        assert!(result.quorum_reached(3));
        assert!(!result.quorum_reached(4));
        assert!(result.any_succeeded());
        assert!(!result.all_succeeded()); // Has failures
    }

    #[test]
    fn dispatch_result_unicast_stays_inline() {
        let result = DispatchResult {
            successes: 1,
            failures: 0,
            sent_to: smallvec![EndpointId(7)],
            failed_endpoints: SmallVec::new(),
            duration: Time::ZERO,
        };

        assert!(!result.sent_to.spilled());
        assert!(!result.failed_endpoints.spilled());
    }

    // Test 13: Endpoint connection tracking
    #[test]
    fn test_endpoint_connections() {
        let endpoint = test_endpoint(1);

        assert_eq!(endpoint.connection_count(), 0);

        endpoint.acquire_connection();
        endpoint.acquire_connection();
        assert_eq!(endpoint.connection_count(), 2);

        endpoint.release_connection();
        assert_eq!(endpoint.connection_count(), 1);
    }

    #[test]
    fn test_endpoint_release_connection_saturates() {
        let endpoint = test_endpoint(1);
        endpoint.release_connection();
        assert_eq!(endpoint.connection_count(), 0);
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn test_routing_table_updates_endpoint_state() {
        let table = RoutingTable::new();
        let endpoint = table.register_endpoint(test_endpoint(9));
        let test_cx = test_admin_cx();

        assert_eq!(endpoint.state(), EndpointState::Healthy);
        assert!(
            table
                .update_endpoint_state(&test_cx, EndpointId(9), EndpointState::Draining)
                .expect("update_endpoint_state should succeed")
        );
        assert_eq!(endpoint.state(), EndpointState::Draining);
        assert!(
            !table
                .update_endpoint_state(&test_cx, EndpointId(999), EndpointState::Healthy)
                .expect("update_endpoint_state should succeed")
        );
    }

    #[test]
    fn test_update_endpoint_state_requires_admin_capability() {
        let table = RoutingTable::new();
        let endpoint = table.register_endpoint(test_endpoint(12));
        let test_cx = Cx::for_testing();

        let error = table
            .update_endpoint_state(&test_cx, endpoint.id, EndpointState::Removed)
            .expect_err("plain test context must not mutate endpoint state");

        assert_eq!(error.kind(), ErrorKind::AdmissionDenied);
        assert_eq!(endpoint.state(), EndpointState::Healthy);
    }

    #[test]
    fn test_routing_table_dispatchable_endpoints_include_degraded_in_id_order() {
        let table = RoutingTable::new();
        let degraded =
            table.register_endpoint(test_endpoint(3).with_state(EndpointState::Degraded));
        let healthy = table.register_endpoint(test_endpoint(1).with_state(EndpointState::Healthy));
        let _unhealthy =
            table.register_endpoint(test_endpoint(2).with_state(EndpointState::Unhealthy));
        let _draining =
            table.register_endpoint(test_endpoint(4).with_state(EndpointState::Draining));
        let _removed = table.register_endpoint(test_endpoint(5).with_state(EndpointState::Removed));

        let ids: Vec<_> = table
            .dispatchable_endpoints()
            .into_iter()
            .map(|endpoint| endpoint.id)
            .collect();

        assert_eq!(ids, vec![healthy.id, degraded.id]);
    }

    #[test]
    fn test_symbol_dispatcher_broadcast_uses_dispatchable_endpoints_in_id_order() {
        let table = Arc::new(RoutingTable::new());
        let degraded =
            table.register_endpoint(test_endpoint(3).with_state(EndpointState::Degraded));
        let healthy_a =
            table.register_endpoint(test_endpoint(1).with_state(EndpointState::Healthy));
        let healthy_b =
            table.register_endpoint(test_endpoint(2).with_state(EndpointState::Healthy));

        let router = Arc::new(SymbolRouter::new(table));
        let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
        let cx: Cx = Cx::for_testing();

        let result = future::block_on(dispatcher.dispatch_with_strategy(
            &cx,
            test_authenticated_symbol(7),
            DispatchStrategy::Broadcast,
        ))
        .expect("broadcast dispatch should succeed");

        let sent_to: Vec<_> = result.sent_to.into_iter().collect();
        assert_eq!(sent_to, vec![healthy_a.id, healthy_b.id, degraded.id]);
    }

    #[test]
    fn test_symbol_dispatcher_quorum_uses_lowest_dispatchable_ids_first() {
        let table = Arc::new(RoutingTable::new());
        let degraded =
            table.register_endpoint(test_endpoint(3).with_state(EndpointState::Degraded));
        let healthy_a =
            table.register_endpoint(test_endpoint(1).with_state(EndpointState::Healthy));
        let healthy_b =
            table.register_endpoint(test_endpoint(2).with_state(EndpointState::Healthy));

        let router = Arc::new(SymbolRouter::new(table));
        let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
        let cx: Cx = Cx::for_testing();

        let result = future::block_on(dispatcher.dispatch_with_strategy(
            &cx,
            test_authenticated_symbol(8),
            DispatchStrategy::QuorumCast { required: 2 },
        ))
        .expect("quorum dispatch should succeed");

        let sent_to: Vec<_> = result.sent_to.iter().copied().collect();
        assert_eq!(sent_to, vec![healthy_a.id, healthy_b.id]);
        assert_eq!(result.successes, 2);
        assert_eq!(result.failures, 0);
        assert!(result.quorum_reached(2));
        assert!(!sent_to.contains(&degraded.id));
    }

    #[test]
    fn test_symbol_dispatcher_unicast_interrupted_io_without_cancel_stays_send_failure() {
        let table = Arc::new(RoutingTable::new());
        let endpoint = table.register_endpoint(test_endpoint(41));
        table.add_route(
            RouteKey::Default,
            RoutingEntry::new(vec![endpoint.clone()], Time::ZERO),
        );

        let router = Arc::new(SymbolRouter::new(table));
        let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());
        dispatcher.add_sink(endpoint.id, Box::new(InterruptedSink));

        let cx: Cx = Cx::for_testing();
        let result = future::block_on(dispatcher.dispatch_with_strategy(
            &cx,
            test_authenticated_symbol(41),
            DispatchStrategy::Unicast,
        ));

        assert!(matches!(
            result,
            Err(DispatchError::SendFailed {
                endpoint: failed_endpoint,
                ..
            }) if failed_endpoint == endpoint.id
        ));
        assert_eq!(endpoint.failures.load(Ordering::Relaxed), 1);
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn test_symbol_dispatcher_broadcast_mid_send_cancel_returns_cancelled() {
        let table = Arc::new(RoutingTable::new());
        let endpoint = table.register_endpoint(test_endpoint(52));

        let router = Arc::new(SymbolRouter::new(table));
        let dispatcher = SymbolDispatcher::new(router, DispatchConfig::default());

        let cx: Cx = Cx::for_testing();
        dispatcher.add_sink(
            endpoint.id,
            Box::new(CancellingInterruptedSink {
                cancel_cx: cx.clone(),
            }),
        );

        let result = future::block_on(dispatcher.dispatch_with_strategy(
            &cx,
            test_authenticated_symbol(52),
            DispatchStrategy::Broadcast,
        ));

        assert!(matches!(result, Err(DispatchError::Cancelled)));
        assert_eq!(endpoint.failures.load(Ordering::Relaxed), 0);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn test_symbol_dispatcher_reentrant_same_endpoint_dispatch_fails_fast() {
        let table = Arc::new(RoutingTable::new());
        let endpoint = table.register_endpoint(test_endpoint(61));
        table.add_route(
            RouteKey::Default,
            RoutingEntry::new(vec![endpoint.clone()], Time::ZERO),
        );

        let router = Arc::new(SymbolRouter::new(table));
        let dispatcher = Arc::new(SymbolDispatcher::new(router, DispatchConfig::default()));
        let cx: Cx = Cx::for_testing();
        let reentrant_failed_fast = Arc::new(AtomicBool::new(false));

        dispatcher.add_sink(
            endpoint.id,
            Box::new(ReentrantDispatchSink {
                dispatcher: Arc::clone(&dispatcher),
                cx: cx.clone(),
                reentrant_failed_fast: Arc::clone(&reentrant_failed_fast),
            }),
        );

        let result = future::block_on(dispatcher.dispatch_with_strategy(
            &cx,
            test_authenticated_symbol(61),
            DispatchStrategy::Unicast,
        ));

        assert!(
            result.is_ok(),
            "outer dispatch should complete after nested reentry is rejected: {result:?}"
        );
        assert!(
            reentrant_failed_fast.load(Ordering::Acquire),
            "nested same-task dispatch must fail before waiting on the endpoint sink mutex"
        );
    }

    // Test 14: RoutingError display
    #[test]
    fn test_routing_error_display() {
        let oid = ObjectId::new_for_test(42);

        let no_route = RoutingError::NoRoute {
            object_id: oid,
            reason: "test".into(),
        };
        assert!(no_route.to_string().contains("no route"));

        let no_healthy = RoutingError::NoHealthyEndpoints { object_id: oid };
        assert!(no_healthy.to_string().contains("healthy"));
    }

    // Test 15: DispatchError display
    #[test]
    fn test_dispatch_error_display() {
        let overloaded = DispatchError::Overloaded;
        assert!(overloaded.to_string().contains("overloaded"));

        let quorum = DispatchError::QuorumNotReached {
            achieved: 2,
            required: 3,
        };
        assert!(quorum.to_string().contains("quorum"));
        assert!(quorum.to_string().contains('2'));
        assert!(quorum.to_string().contains('3'));
    }

    // Pure data-type tests (wave 17 – CyanBarn)

    #[test]
    fn endpoint_id_debug_display() {
        let id = EndpointId::new(42);
        assert!(format!("{id:?}").contains("42"));
        assert_eq!(id.to_string(), "Endpoint(42)");
    }

    #[test]
    fn endpoint_id_clone_copy_eq() {
        let id = EndpointId::new(7);
        let id2 = id;
        assert_eq!(id, id2);
    }

    #[test]
    fn endpoint_id_ord_hash() {
        let a = EndpointId::new(1);
        let b = EndpointId::new(2);
        assert!(a < b);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn endpoint_state_debug_clone_copy_eq() {
        let s = EndpointState::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("Healthy"));
    }

    #[test]
    fn endpoint_state_as_u8_roundtrip() {
        let states = [
            EndpointState::Healthy,
            EndpointState::Degraded,
            EndpointState::Unhealthy,
            EndpointState::Draining,
            EndpointState::Removed,
        ];
        for &s in &states {
            assert_eq!(EndpointState::from_u8(s.as_u8()), s);
        }
    }

    #[test]
    fn endpoint_state_from_u8_invalid() {
        let s = EndpointState::from_u8(255);
        assert_eq!(s, EndpointState::Removed);
    }

    #[test]
    fn endpoint_debug() {
        let ep = Endpoint::new(EndpointId::new(1), "addr:80");
        let dbg = format!("{ep:?}");
        assert!(dbg.contains("Endpoint"));
    }

    #[test]
    fn endpoint_with_weight_region() {
        let region = RegionId::new_for_test(1, 0);
        let ep = Endpoint::new(EndpointId::new(5), "host:80")
            .with_weight(200)
            .with_region(region);
        assert_eq!(ep.weight, 200);
        assert_eq!(ep.region, Some(region));
    }

    #[test]
    fn endpoint_with_state_setter() {
        let ep = Endpoint::new(EndpointId::new(1), "h:80").with_state(EndpointState::Draining);
        assert_eq!(ep.state(), EndpointState::Draining);
        ep.set_state(EndpointState::Healthy);
        assert_eq!(ep.state(), EndpointState::Healthy);
    }

    #[test]
    fn endpoint_failure_rate_zero() {
        let ep = Endpoint::new(EndpointId::new(1), "h:80");
        assert!((ep.failure_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn endpoint_connection_guard_drops() {
        let ep = Endpoint::new(EndpointId::new(1), "h:80");
        {
            let _guard = ep.acquire_connection_guard();
            assert_eq!(ep.connection_count(), 1);
        }
        assert_eq!(ep.connection_count(), 0);
    }

    #[test]
    fn load_balance_strategy_debug_clone_copy_eq_default() {
        let s = LoadBalanceStrategy::default();
        assert_eq!(s, LoadBalanceStrategy::RoundRobin);
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("RoundRobin"));
    }

    #[test]
    fn route_key_debug_clone_eq_ord_hash() {
        let oid = ObjectId::new_for_test(1);
        let k1 = RouteKey::Object(oid);
        let k2 = k1.clone();
        assert_eq!(k1, k2);
        assert!(format!("{k1:?}").contains("Object"));
        assert!(k1 <= k2);

        let mut set = HashSet::new();
        set.insert(k1);
        set.insert(RouteKey::Default);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn route_key_constructors() {
        let oid = ObjectId::new_for_test(1);
        let rid = RegionId::new_for_test(2, 0);
        assert_eq!(RouteKey::object(oid), RouteKey::Object(oid));
        assert_eq!(RouteKey::region(rid), RouteKey::Region(rid));
    }

    #[test]
    fn dispatch_strategy_debug_clone_copy_eq_default() {
        let s = DispatchStrategy::default();
        assert_eq!(s, DispatchStrategy::Unicast);
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("Unicast"));
    }

    #[test]
    fn dispatch_config_debug_clone_default() {
        let cfg = DispatchConfig::default();
        let cfg2 = cfg;
        assert_eq!(cfg2.max_retries, 3);
        assert!(format!("{cfg2:?}").contains("DispatchConfig"));
    }

    #[test]
    fn dispatcher_stats_debug() {
        let stats = DispatcherStats {
            active_dispatches: 0,
            total_dispatched: 100,
            total_failures: 5,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("100"));
    }

    #[test]
    fn routing_error_debug_clone() {
        let err = RoutingError::EmptyTable;
        let err2 = err;
        assert!(format!("{err2:?}").contains("EmptyTable"));
    }

    #[test]
    fn routing_error_display_all_variants() {
        let oid = ObjectId::new_for_test(1);
        let e1 = RoutingError::NoRoute {
            object_id: oid,
            reason: "gone".into(),
        };
        assert!(e1.to_string().contains("no route"));
        assert!(e1.to_string().contains("gone"));

        let e2 = RoutingError::NoHealthyEndpoints { object_id: oid };
        assert!(e2.to_string().contains("healthy"));

        let e3 = RoutingError::EmptyTable;
        assert!(e3.to_string().contains("empty"));
    }

    #[test]
    fn routing_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(RoutingError::EmptyTable);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn dispatch_error_debug_clone() {
        let err = DispatchError::Timeout;
        let err2 = err;
        assert!(format!("{err2:?}").contains("Timeout"));
    }

    #[test]
    fn dispatch_error_display_all_variants() {
        let e1 = DispatchError::RoutingFailed(RoutingError::EmptyTable);
        assert!(e1.to_string().contains("routing failed"));

        let e2 = DispatchError::SendFailed {
            endpoint: EndpointId::new(3),
            reason: "down".into(),
        };
        assert!(e2.to_string().contains("send"));

        let e3 = DispatchError::NoEndpoints;
        assert!(e3.to_string().contains("no endpoints"));

        let e4 = DispatchError::InsufficientEndpoints {
            available: 1,
            required: 3,
        };
        assert!(e4.to_string().contains("insufficient"));

        let e5 = DispatchError::Timeout;
        assert!(e5.to_string().contains("timeout"));
    }

    #[test]
    fn dispatch_error_from_routing_error() {
        let re = RoutingError::EmptyTable;
        let de = DispatchError::from(re);
        assert!(matches!(de, DispatchError::RoutingFailed(_)));
    }

    #[test]
    fn dispatch_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(DispatchError::Timeout);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn routing_entry_with_priority() {
        let entry = RoutingEntry::new(vec![], Time::ZERO).with_priority(10);
        assert_eq!(entry.priority, 10);
    }

    #[test]
    fn routing_entry_select_endpoint_empty() {
        let entry = RoutingEntry::new(vec![], Time::ZERO);
        assert!(entry.select_endpoint(None).is_none());
    }

    #[test]
    fn load_balancer_debug() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::Random);
        assert!(format!("{lb:?}").contains("Random"));
    }

    #[test]
    fn routing_table_debug() {
        let table = RoutingTable::new();
        assert!(format!("{table:?}").contains("RoutingTable"));
    }

    #[test]
    fn routing_table_state_snapshot_scrubbed() {
        let table = RoutingTable::new();
        let region = RegionId::new_for_test(9, 2);
        let object_id = ObjectId::new_for_test(44);

        let primary = table.register_endpoint(
            test_endpoint(1)
                .with_weight(200)
                .with_region(region)
                .with_state(EndpointState::Healthy),
        );
        let backup = table.register_endpoint(
            test_endpoint(2)
                .with_weight(50)
                .with_state(EndpointState::Degraded),
        );
        let draining = table.register_endpoint(
            test_endpoint(3)
                .with_weight(10)
                .with_state(EndpointState::Draining),
        );

        table.add_route(
            RouteKey::Default,
            RoutingEntry::new(vec![backup.clone()], Time::ZERO)
                .with_priority(90)
                .with_strategy(LoadBalanceStrategy::FirstAvailable),
        );
        table.add_route(
            RouteKey::Object(object_id),
            RoutingEntry::new(vec![primary, backup], Time::ZERO)
                .with_priority(10)
                .with_ttl(Time::from_secs(30))
                .with_strategy(LoadBalanceStrategy::WeightedRoundRobin),
        );
        table.add_route(
            RouteKey::Region(region),
            RoutingEntry::new(vec![draining], Time::ZERO)
                .with_priority(40)
                .with_strategy(LoadBalanceStrategy::RoundRobin),
        );

        insta::assert_json_snapshot!(
            "routing_table_state_scrubbed",
            routing_table_snapshot(&table)
        );
    }

    // ================================================================
    // br-asupersync-5ypgzi — per-router HashRing salt
    // ================================================================

    /// Two LoadBalancer instances built via `LoadBalancer::new` (which
    /// sources the salt from OsEntropy) MUST observe different salts
    /// with overwhelming probability. The 64-bit OS-entropy seed
    /// makes a collision astronomically unlikely; if this test
    /// flakes, the OsEntropy plumbing has regressed.
    #[test]
    fn load_balancer_new_seeds_distinct_hash_ring_salts() {
        let lb1 = LoadBalancer::new(LoadBalanceStrategy::HashBased);
        let lb2 = LoadBalancer::new(LoadBalanceStrategy::HashBased);
        assert_ne!(
            lb1.hash_ring_salt(),
            lb2.hash_ring_salt(),
            "two LoadBalancer instances built via ::new must use different salts"
        );
    }

    /// `LoadBalancer::with_test_salt` produces deterministic salts —
    /// useful for tests / lab runs.
    #[test]
    fn load_balancer_with_test_salt_is_deterministic() {
        let lb1 = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, 12345);
        let lb2 = LoadBalancer::with_test_salt(LoadBalanceStrategy::HashBased, 12345);
        assert_eq!(lb1.hash_ring_salt(), lb2.hash_ring_salt());
        assert_eq!(lb1.hash_ring_salt(), 12345);
    }

    /// br-asupersync-qfgsh1: Test that capacity overflow attacks are prevented.
    /// Extreme endpoint weights and configuration parameters should be clamped
    /// to safe values instead of causing integer overflow or unlimited capacity.
    #[test]
    fn bounded_load_config_prevents_capacity_overflow_attacks() {
        // Test configuration parameter clamping
        let extreme_config = BoundedLoadConfig::new(
            u32::MAX, // extreme epsilon_milli
            u32::MAX, // extreme min_capacity
            u32::MAX, // extreme capacity_per_weight
        );

        // Configuration should be clamped to safe values
        assert!(extreme_config.epsilon_milli <= 5_000);
        assert!(extreme_config.min_capacity <= 10_000);
        assert!(extreme_config.capacity_per_weight <= 1_000);

        // Test endpoint weight overflow protection
        let normal_config = BoundedLoadConfig::new(250, 1, 1);

        // Create endpoint with extreme weight designed to cause overflow
        let extreme_endpoint = test_endpoint(1).with_weight(u32::MAX);

        // capacity_for should handle overflow safely and return bounded capacity
        let capacity = normal_config.capacity_for(&extreme_endpoint);

        // Should return a reasonable bounded capacity, not u32::MAX or unlimited
        assert!(capacity > 0);
        assert!(capacity <= 100_000); // Should be within reasonable bounds
        assert!(capacity >= normal_config.min_capacity);

        // Test that normal weights still work correctly
        let normal_endpoint = test_endpoint(2).with_weight(10);
        let normal_capacity = normal_config.capacity_for(&normal_endpoint);

        // Normal case should produce expected capacity calculation
        assert!(normal_capacity >= normal_config.min_capacity);
        assert!(normal_capacity <= 1_000); // Should be reasonable for weight=10

        // Test that extreme values don't bypass load balancing
        assert!(normal_config.accepts(&extreme_endpoint)); // Should accept some connections

        // But not unlimited - simulate high connection count
        let high_conn_endpoint = test_endpoint(3).with_weight(u32::MAX);
        high_conn_endpoint
            .active_connections
            .store(100_000, std::sync::atomic::Ordering::Relaxed);

        // With many active connections, should reject further connections
        assert!(!normal_config.accepts(&high_conn_endpoint));
    }
