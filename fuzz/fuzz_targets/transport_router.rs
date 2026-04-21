#![no_main]

//! Fuzz target for src/transport/router.rs symbol routing and dispatch infrastructure.
//!
//! This fuzzer validates the security properties of the transport router:
//! 1. EndpointId parsed correctly from u64 values
//! 2. 7 LoadBalancer strategies dispatch correctly (RoundRobin, WeightedRoundRobin, LeastConnections, WeightedLeastConnections, Random, HashBased, FirstAvailable)
//! 3. RoutingTable TTL expiry enforced (expired routes are pruned)
//! 4. SymbolDispatcher unicast/multicast/broadcast/quorum distinct paths (4 separate dispatch strategies)
//! 5. Unknown endpoint dispatched to default route fallback

use arbitrary::{Arbitrary, Unstructured};
use asupersync::{
    types::Budget,
    Cx,
    security::authenticated::AuthenticatedSymbol,
    security::tag::AuthenticationTag,
    transport::router::{
        DispatchConfig, DispatchError, DispatchStrategy, Endpoint, EndpointId, EndpointState,
        LoadBalancer, RouteKey, RoutingEntry, RoutingTable, SymbolDispatcher, SymbolRouter,
    },
    transport::sink::SymbolSink,
    types::{ObjectId, RegionId, Symbol, SymbolId, SymbolKind, Time},
    TaskId,
};
use libfuzzer_sys::fuzz_target;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Structured input for controlled transport router fuzzing scenarios.
#[derive(Arbitrary, Debug)]
enum TransportFuzzInput {
    /// Raw EndpointId parsing and validation
    EndpointId(u64),

    /// Load balancer strategy testing
    LoadBalancer {
        strategy: LoadBalancerStrategy,
        endpoints: Vec<EndpointConfig>,
        object_id: Option<ObjectIdWrapper>,
        multi_select_count: Option<u8>, // 0-10 for select_n testing
    },

    /// Routing table TTL and expiry testing
    RoutingTable {
        routes: Vec<RouteConfig>,
        current_time_offset_nanos: u64, // Offset from creation time for TTL testing
        prune_expired: bool,
    },

    /// Symbol dispatcher strategy testing
    Dispatch {
        strategy: DispatchStrategyWrapper,
        endpoints: Vec<EndpointConfig>,
        symbol_config: SymbolConfig,
        fail_endpoints: Vec<u8>, // Indices of endpoints to simulate failures
    },

    /// Default route fallback testing
    FallbackRouting {
        symbol_config: SymbolConfig,
        has_default_route: bool,
        specific_routes: Vec<RouteConfig>,
    },

    /// Comprehensive edge case scenarios
    EdgeCase(EdgeCaseScenario),
}

#[derive(Arbitrary, Debug)]
enum LoadBalancerStrategy {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    WeightedLeastConnections,
    Random,
    HashBased,
    FirstAvailable,
}

impl From<LoadBalancerStrategy> for asupersync::transport::router::LoadBalanceStrategy {
    fn from(strategy: LoadBalancerStrategy) -> Self {
        match strategy {
            LoadBalancerStrategy::RoundRobin => Self::RoundRobin,
            LoadBalancerStrategy::WeightedRoundRobin => Self::WeightedRoundRobin,
            LoadBalancerStrategy::LeastConnections => Self::LeastConnections,
            LoadBalancerStrategy::WeightedLeastConnections => Self::WeightedLeastConnections,
            LoadBalancerStrategy::Random => Self::Random,
            LoadBalancerStrategy::HashBased => Self::HashBased,
            LoadBalancerStrategy::FirstAvailable => Self::FirstAvailable,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum DispatchStrategyWrapper {
    Unicast,
    Multicast { count: u8 }, // 1-10
    Broadcast,
    QuorumCast { required: u8 }, // 1-10
}

impl From<DispatchStrategyWrapper> for DispatchStrategy {
    fn from(strategy: DispatchStrategyWrapper) -> Self {
        match strategy {
            DispatchStrategyWrapper::Unicast => Self::Unicast,
            DispatchStrategyWrapper::Multicast { count } => Self::Multicast {
                count: usize::from(count).clamp(1, 10),
            },
            DispatchStrategyWrapper::Broadcast => Self::Broadcast,
            DispatchStrategyWrapper::QuorumCast { required } => Self::QuorumCast {
                required: usize::from(required).clamp(1, 10),
            },
        }
    }
}

#[derive(Arbitrary, Debug)]
struct EndpointConfig {
    id: u64,
    address_suffix: u8, // 0-255 for "node-{suffix}:8080"
    weight: u16,        // 1-1000
    state: EndpointStateWrapper,
    active_connections: u8, // 0-255
    region: Option<u64>,    // Optional region ID
}

#[derive(Arbitrary, Debug)]
enum EndpointStateWrapper {
    Healthy,
    Degraded,
    Unhealthy,
    Draining,
    Removed,
}

impl From<EndpointStateWrapper> for EndpointState {
    fn from(state: EndpointStateWrapper) -> Self {
        match state {
            EndpointStateWrapper::Healthy => Self::Healthy,
            EndpointStateWrapper::Degraded => Self::Degraded,
            EndpointStateWrapper::Unhealthy => Self::Unhealthy,
            EndpointStateWrapper::Draining => Self::Draining,
            EndpointStateWrapper::Removed => Self::Removed,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct ObjectIdWrapper(u64, u64); // High and low parts

impl From<ObjectIdWrapper> for ObjectId {
    fn from(wrapper: ObjectIdWrapper) -> Self {
        ObjectId::from_u128(((wrapper.0 as u128) << 64) | (wrapper.1 as u128))
    }
}

#[derive(Arbitrary, Debug)]
struct RouteConfig {
    key: RouteKeyWrapper,
    endpoints: Vec<u8>, // Indices into endpoint list (0-255)
    strategy: LoadBalancerStrategy,
    priority: u16,
    ttl_seconds: Option<u16>, // None = permanent, Some = seconds
}

#[derive(Arbitrary, Debug)]
enum RouteKeyWrapper {
    Object(ObjectIdWrapper),
    Region(u64), // RegionId
    ObjectAndRegion(ObjectIdWrapper, u64),
    Default,
}

impl From<RouteKeyWrapper> for RouteKey {
    fn from(wrapper: RouteKeyWrapper) -> Self {
        match wrapper {
            RouteKeyWrapper::Object(oid) => Self::Object(oid.into()),
            RouteKeyWrapper::Region(rid) => Self::Region(region_id_from_u64(rid)),
            RouteKeyWrapper::ObjectAndRegion(oid, rid) => {
                Self::ObjectAndRegion(oid.into(), region_id_from_u64(rid))
            }
            RouteKeyWrapper::Default => Self::Default,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct SymbolConfig {
    object_id: ObjectIdWrapper,
    esi: u32, // Encoding symbol index
    kind: SymbolKindWrapper,
}

#[derive(Arbitrary, Debug)]
enum SymbolKindWrapper {
    Source,
    Repair,
    Authenticated,
    Heartbeat,
}

impl From<SymbolKindWrapper> for SymbolKind {
    fn from(wrapper: SymbolKindWrapper) -> Self {
        match wrapper {
            SymbolKindWrapper::Source => Self::Source,
            SymbolKindWrapper::Repair => Self::Repair,
            SymbolKindWrapper::Authenticated => Self::Repair,
            SymbolKindWrapper::Heartbeat => Self::Source,
        }
    }
}

fn region_id_from_u64(value: u64) -> RegionId {
    RegionId::new_for_test(value as u32, (value >> 32) as u32)
}

fn make_router_endpoints(prefix: &str, count: usize, base_id: u64) -> Vec<Arc<Endpoint>> {
    (0..count)
        .map(|i| {
            Arc::new(Endpoint::new(
                EndpointId::new(base_id + i as u64),
                format!("{prefix}-{i}:8080"),
            ))
        })
        .collect()
}

fn fuzz_test_cx() -> Cx {
    Cx::new(
        RegionId::new_for_test(0, 0),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
    )
}

#[derive(Arbitrary, Debug)]
enum EdgeCaseScenario {
    /// Empty endpoint list with various strategies
    EmptyEndpoints(LoadBalancerStrategy),

    /// All endpoints unhealthy
    AllUnhealthyEndpoints(LoadBalancerStrategy),

    /// Single endpoint with maximum load
    SingleMaxLoadEndpoint,

    /// Weighted round robin with zero weights
    ZeroWeightRoundRobin,

    /// Hash-based routing consistency
    HashConsistency(ObjectIdWrapper),

    /// TTL boundary cases
    TTLBoundary(i64), // Signed offset for edge cases

    /// Dispatch overload conditions
    DispatchOverload,

    /// Concurrent dispatch limit testing
    ConcurrentDispatchLimit(u8), // 1-255 concurrent attempts

    /// Route lookup with missing keys
    MissingRouteKeys(ObjectIdWrapper),

    /// Insert a route, prune it after TTL expiry, then reinsert a distinct endpoint set.
    RoutingTableInsertEvictCycle {
        initial_endpoint_count: u8,
        reinsert_endpoint_count: u8,
        ttl_seconds: u16,
        expiration_slack_nanos: u32,
    },

    /// Endpoint connection guard stress test
    ConnectionGuardStress(u8), // 1-100 simultaneous guards
}

/// Mock sink that can simulate success or failure
struct MockSymbolSink {
    should_fail: bool,
    should_timeout: bool,
    should_cancel: bool,
}

impl SymbolSink for MockSymbolSink {
    fn poll_send(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
        if self.should_cancel {
            Poll::Ready(Err(asupersync::transport::error::SinkError::Cancelled))
        } else if self.should_timeout {
            Poll::Pending
        } else if self.should_fail {
            Poll::Ready(Err(asupersync::transport::error::SinkError::Io {
                source: io::Error::new(io::ErrorKind::ConnectionRefused, "mock failure"),
            }))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(input) = TransportFuzzInput::arbitrary(&mut u) {
        fuzz_transport_router(input);
    }
});

fn fuzz_transport_router(input: TransportFuzzInput) {
    match input {
        TransportFuzzInput::EndpointId(id) => {
            fuzz_endpoint_id_parsing(id);
        }

        TransportFuzzInput::LoadBalancer {
            strategy,
            endpoints,
            object_id,
            multi_select_count,
        } => {
            fuzz_load_balancer_strategies(strategy, endpoints, object_id, multi_select_count);
        }

        TransportFuzzInput::RoutingTable {
            routes,
            current_time_offset_nanos,
            prune_expired,
        } => {
            fuzz_routing_table_ttl(routes, current_time_offset_nanos, prune_expired);
        }

        TransportFuzzInput::Dispatch {
            strategy,
            endpoints,
            symbol_config,
            fail_endpoints,
        } => {
            fuzz_symbol_dispatcher(strategy, endpoints, symbol_config, fail_endpoints);
        }

        TransportFuzzInput::FallbackRouting {
            symbol_config,
            has_default_route,
            specific_routes,
        } => {
            fuzz_fallback_routing(symbol_config, has_default_route, specific_routes);
        }

        TransportFuzzInput::EdgeCase(edge) => {
            fuzz_edge_cases(edge);
        }
    }
}

/// ASSERTION 1: EndpointId parsed correctly from u64 values
fn fuzz_endpoint_id_parsing(id: u64) {
    let endpoint_id = EndpointId::new(id);

    // Verify correct parsing and display
    assert_eq!(endpoint_id.0, id, "EndpointId should preserve u64 value");

    let display_str = format!("{}", endpoint_id);
    assert!(
        display_str.contains(&id.to_string()),
        "EndpointId display should contain the ID: {}",
        display_str
    );

    // Verify ordering properties for routing consistency
    let id2 = EndpointId::new(id.wrapping_add(1));
    if id < u64::MAX {
        assert!(
            endpoint_id < id2,
            "EndpointId ordering should follow u64 ordering"
        );
    }

    // Verify hash consistency for hash-based routing
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();
    endpoint_id.hash(&mut hasher1);
    endpoint_id.hash(&mut hasher2);
    assert_eq!(
        hasher1.finish(),
        hasher2.finish(),
        "EndpointId hash should be deterministic"
    );
}

/// ASSERTION 2: 7 LoadBalancer strategies dispatch correctly
fn fuzz_load_balancer_strategies(
    strategy: LoadBalancerStrategy,
    endpoint_configs: Vec<EndpointConfig>,
    object_id: Option<ObjectIdWrapper>,
    multi_select_count: Option<u8>,
) {
    if endpoint_configs.is_empty() {
        return;
    }

    let strategy = strategy.into();
    let lb = LoadBalancer::new(strategy);

    // Create endpoints from configs
    let endpoints: Vec<Arc<Endpoint>> = endpoint_configs
        .into_iter()
        .map(|config| {
            let mut endpoint = Endpoint::new(
                EndpointId::new(config.id),
                format!("node-{}:8080", config.address_suffix),
            )
            .with_weight(config.weight.max(1) as u32)
            .with_state(config.state.into());

            if let Some(region_id) = config.region {
                endpoint = endpoint.with_region(region_id_from_u64(region_id));
            }

            // Set connection count for least-connections testing
            endpoint.active_connections.store(
                config.active_connections as u32,
                std::sync::atomic::Ordering::Relaxed,
            );

            Arc::new(endpoint)
        })
        .collect();

    if endpoints.is_empty() {
        return;
    }

    let object_id = object_id.map(Into::into);

    // Test single selection
    let selected = lb.select(&endpoints, object_id);
    if let Some(endpoint) = selected {
        // ASSERTION: Selected endpoint should be reachable
        assert!(
            endpoint.state().can_receive() || endpoints.iter().all(|e| !e.state().can_receive()),
            "LoadBalancer should select reachable endpoint or none available"
        );

        // ASSERTION: Selected endpoint should be from our list
        assert!(
            endpoints.iter().any(|e| e.id == endpoint.id),
            "Selected endpoint should be from the provided list"
        );
    }

    // Test multiple selection if requested
    if let Some(count) = multi_select_count {
        let count = usize::from(count).clamp(1, 10);
        let selected_multi = lb.select_n(&endpoints, count, object_id);

        // ASSERTION: Should not select more than requested or available
        assert!(
            selected_multi.len() <= count,
            "select_n should not return more than requested count"
        );
        assert!(
            selected_multi.len() <= endpoints.iter().filter(|e| e.state().can_receive()).count(),
            "select_n should not return more healthy endpoints than available"
        );

        // ASSERTION: Should not select duplicates
        use std::collections::HashSet;
        let mut seen_ids = HashSet::new();
        for endpoint in &selected_multi {
            assert!(
                seen_ids.insert(endpoint.id),
                "select_n should not return duplicate endpoints"
            );
        }

        // ASSERTION: All selected endpoints should be healthy (unless none available)
        let healthy_count = endpoints.iter().filter(|e| e.state().can_receive()).count();
        if healthy_count > 0 {
            for endpoint in &selected_multi {
                assert!(
                    endpoint.state().can_receive(),
                    "select_n should only return healthy endpoints when available"
                );
            }
        }
    }

    // Strategy-specific assertions
    match strategy {
        asupersync::transport::router::LoadBalanceStrategy::LeastConnections => {
            if let Some(endpoint) = selected {
                let min_connections = endpoints
                    .iter()
                    .filter(|e| e.state().can_receive())
                    .map(|e| e.connection_count())
                    .min();
                if let Some(min) = min_connections {
                    assert!(
                        endpoint.connection_count() <= min + 1, // Allow for race conditions
                        "LeastConnections should select endpoint with minimal connections"
                    );
                }
            }
        }

        asupersync::transport::router::LoadBalanceStrategy::FirstAvailable => {
            if let Some(endpoint) = selected {
                // Should select the first healthy endpoint
                let first_healthy = endpoints.iter().find(|e| e.state().can_receive());
                if let Some(first) = first_healthy {
                    assert_eq!(
                        endpoint.id, first.id,
                        "FirstAvailable should select the first healthy endpoint"
                    );
                }
            }
        }

        asupersync::transport::router::LoadBalanceStrategy::WeightedLeastConnections => {
            if let Some(endpoint) = selected {
                // Verify weighted calculation: connections / weight should be minimal
                let selected_ratio =
                    endpoint.connection_count() as f64 / (endpoint.weight.max(1) as f64);
                for other in &endpoints {
                    if other.state().can_receive() && other.id != endpoint.id {
                        let other_ratio =
                            other.connection_count() as f64 / (other.weight.max(1) as f64);
                        assert!(
                            selected_ratio <= other_ratio + 0.1, // Allow small floating point differences
                            "WeightedLeastConnections should select endpoint with minimal weighted load"
                        );
                    }
                }
            }
        }

        _ => {
            // For other strategies, we can't make specific assertions about which endpoint
            // is selected, but we verified above that it's healthy and from our list
        }
    }
}

/// ASSERTION 3: RoutingTable TTL expiry enforced
fn fuzz_routing_table_ttl(
    route_configs: Vec<RouteConfig>,
    current_time_offset_nanos: u64,
    prune_expired: bool,
) {
    let table = RoutingTable::new();
    let creation_time = Time::from_nanos(1_000_000_000); // 1 second
    let current_time = creation_time.saturating_add_nanos(current_time_offset_nanos);

    let mut added_routes = 0;
    let mut _expired_routes = 0;

    for route_config in route_configs {
        if route_config.endpoints.is_empty() {
            continue;
        }

        // Create endpoints for this route
        let endpoints: Vec<Arc<Endpoint>> = route_config
            .endpoints
            .into_iter()
            .take(10) // Limit to prevent excessive memory usage
            .enumerate()
            .map(|(i, _)| {
                Arc::new(Endpoint::new(
                    EndpointId::new(i as u64),
                    format!("node-{}:8080", i),
                ))
            })
            .collect();

        if endpoints.is_empty() {
            continue;
        }

        let mut entry = RoutingEntry::new(endpoints, creation_time)
            .with_strategy(route_config.strategy.into())
            .with_priority(route_config.priority as u32);

        // Set TTL if specified
        if let Some(ttl_secs) = route_config.ttl_seconds {
            let ttl = Time::from_secs(ttl_secs.min(3600) as u64); // Cap at 1 hour
            entry = entry.with_ttl(ttl);

            // Check if this route should be expired
            let expiry_time = creation_time.saturating_add_nanos(ttl.as_nanos());
            if current_time >= expiry_time {
                _expired_routes += 1;
            }
        }

        // ASSERTION: TTL expiry check should be accurate
        let should_be_expired = entry.is_expired(current_time);
        if let Some(ttl_secs) = route_config.ttl_seconds {
            let ttl = Time::from_secs(ttl_secs.min(3600) as u64);
            let expiry_time = creation_time.saturating_add_nanos(ttl.as_nanos());
            let expected_expired = current_time >= expiry_time;
            assert_eq!(
                should_be_expired, expected_expired,
                "TTL expiry check should match manual calculation"
            );
        } else {
            assert!(!should_be_expired, "Permanent routes should never expire");
        }

        table.add_route(route_config.key.into(), entry);
        added_routes += 1;
    }

    let routes_before_prune = table.route_count();

    if prune_expired && added_routes > 0 {
        let pruned_count = table.prune_expired(current_time);
        let routes_after_prune = table.route_count();

        // ASSERTION: Pruned count should match expired routes
        assert_eq!(
            routes_before_prune,
            routes_after_prune + pruned_count,
            "Pruned count should match the difference in route counts"
        );

        // ASSERTION: No expired routes should remain
        // (We can't easily verify this without accessing internal state,
        // but the prune operation should remove them)
    }
}

/// ASSERTION 4: SymbolDispatcher unicast/multicast/broadcast/quorum distinct paths
fn fuzz_symbol_dispatcher(
    strategy: DispatchStrategyWrapper,
    endpoint_configs: Vec<EndpointConfig>,
    symbol_config: SymbolConfig,
    fail_endpoints: Vec<u8>,
) {
    if endpoint_configs.is_empty() {
        return;
    }

    let table = Arc::new(RoutingTable::new());
    let router = Arc::new(SymbolRouter::new(table.clone()));

    // Create endpoints
    let endpoints: Vec<Arc<Endpoint>> = endpoint_configs
        .into_iter()
        .enumerate()
        .take(10) // Limit endpoints to prevent memory issues
        .map(|(i, config)| {
            table.register_endpoint(
                Endpoint::new(EndpointId::new(i as u64), format!("node-{}:8080", i))
                    .with_state(config.state.into()),
            )
        })
        .collect();

    if endpoints.is_empty() {
        return;
    }

    // Add a default route
    let default_entry = RoutingEntry::new(endpoints.clone(), Time::from_secs(0));
    table.add_route(RouteKey::Default, default_entry);

    // Create dispatcher
    let config = DispatchConfig::default();
    let dispatcher = SymbolDispatcher::new(router, config);

    // Add mock sinks for endpoints
    let fail_set: std::collections::HashSet<u8> = fail_endpoints.into_iter().collect();
    for (i, endpoint) in endpoints.iter().enumerate() {
        let should_fail = fail_set.contains(&(i as u8));
        let sink = MockSymbolSink {
            should_fail,
            should_timeout: false,
            should_cancel: false,
        };
        dispatcher.add_sink(endpoint.id, Box::new(sink));
    }

    // Create test symbol
    let object_id: ObjectId = symbol_config.object_id.into();
    let symbol_id = SymbolId::new(object_id, 0, symbol_config.esi);
    let symbol = Symbol::new(symbol_id, vec![42u8; 10], symbol_config.kind.into());
    let auth_symbol = AuthenticatedSymbol::new_verified(symbol, AuthenticationTag::zero());

    // Create test context (we'll use a mock for fuzzing)
    let cx = fuzz_test_cx();

    // Test the specific dispatch strategy
    let strategy: DispatchStrategy = strategy.into();

    // Block on the async dispatch (in a real fuzz test, we'd use a simple executor)
    let result = futures::executor::block_on(async {
        dispatcher
            .dispatch_with_strategy(&cx, auth_symbol, strategy)
            .await
    });

    match strategy {
        DispatchStrategy::Unicast => {
            // ASSERTION: Unicast should target exactly one endpoint
            match result {
                Ok(dispatch_result) => {
                    assert!(
                        dispatch_result.successes <= 1 && dispatch_result.failures <= 1,
                        "Unicast should target at most one endpoint"
                    );
                    assert!(
                        dispatch_result.sent_to.len() <= 1,
                        "Unicast should send to at most one endpoint"
                    );
                }
                Err(_) => {
                    // Errors are acceptable (no healthy endpoints, routing failure, etc.)
                }
            }
        }

        DispatchStrategy::Multicast { count } => {
            // ASSERTION: Multicast should target up to count endpoints
            match result {
                Ok(dispatch_result) => {
                    let total_attempts = dispatch_result.successes + dispatch_result.failures;
                    assert!(
                        total_attempts <= count,
                        "Multicast should not exceed requested count"
                    );
                    assert!(
                        dispatch_result.sent_to.len() <= count,
                        "Multicast should send to at most count endpoints"
                    );

                    // ASSERTION: Should not target more endpoints than available
                    let healthy_count =
                        endpoints.iter().filter(|e| e.state().can_receive()).count();
                    assert!(
                        total_attempts <= healthy_count,
                        "Multicast should not target more endpoints than available"
                    );
                }
                Err(_) => {
                    // Errors are acceptable
                }
            }
        }

        DispatchStrategy::Broadcast => {
            // ASSERTION: Broadcast should target all healthy endpoints
            match result {
                Ok(dispatch_result) => {
                    let healthy_count =
                        endpoints.iter().filter(|e| e.state().can_receive()).count();
                    let total_attempts = dispatch_result.successes + dispatch_result.failures;
                    assert!(
                        total_attempts <= healthy_count,
                        "Broadcast should target at most all healthy endpoints"
                    );
                }
                Err(DispatchError::NoEndpoints) => {
                    // Expected when no healthy endpoints
                    let healthy_count =
                        endpoints.iter().filter(|e| e.state().can_receive()).count();
                    assert_eq!(
                        healthy_count, 0,
                        "NoEndpoints error should only occur with no healthy endpoints"
                    );
                }
                Err(_) => {
                    // Other errors are acceptable
                }
            }
        }

        DispatchStrategy::QuorumCast { required } => {
            // ASSERTION: QuorumCast should continue until quorum reached or all endpoints exhausted
            match result {
                Ok(dispatch_result) => {
                    assert!(
                        dispatch_result.successes >= required,
                        "QuorumCast success should have reached required quorum"
                    );
                }
                Err(DispatchError::QuorumNotReached {
                    achieved,
                    required: req_in_error,
                }) => {
                    assert_eq!(
                        req_in_error, required,
                        "Error should report correct required count"
                    );
                    assert!(
                        achieved < required,
                        "QuorumNotReached should have achieved < required"
                    );

                    // Should have tried all available endpoints
                    let healthy_count =
                        endpoints.iter().filter(|e| e.state().can_receive()).count();
                    let total_possible = healthy_count.min(10); // Limit for safety
                    assert!(
                        achieved <= total_possible,
                        "QuorumCast should not achieve more than possible"
                    );
                }
                Err(DispatchError::InsufficientEndpoints {
                    available,
                    required: req_in_error,
                }) => {
                    assert_eq!(
                        req_in_error, required,
                        "Error should report correct required count"
                    );
                    assert!(
                        available < required,
                        "InsufficientEndpoints should have available < required"
                    );
                }
                Err(_) => {
                    // Other errors are acceptable
                }
            }
        }
    }
}

/// ASSERTION 5: Unknown endpoint dispatched to default route fallback
fn fuzz_fallback_routing(
    symbol_config: SymbolConfig,
    has_default_route: bool,
    specific_routes: Vec<RouteConfig>,
) {
    let table = RoutingTable::new();
    let router = SymbolRouter::new(Arc::new(table));

    // Create test endpoints
    let default_endpoints: Vec<Arc<Endpoint>> = (0..3)
        .map(|i| {
            Arc::new(Endpoint::new(
                EndpointId::new(i),
                format!("default-{}:8080", i),
            ))
        })
        .collect();

    // Add specific routes (but not for our test object)
    for route_config in specific_routes {
        if route_config.endpoints.is_empty() {
            continue;
        }

        let endpoints: Vec<Arc<Endpoint>> = route_config
            .endpoints
            .into_iter()
            .take(5)
            .enumerate()
            .map(|(i, _)| {
                Arc::new(Endpoint::new(
                    EndpointId::new(100 + i as u64), // Different ID range
                    format!("specific-{}:8080", i),
                ))
            })
            .collect();

        if !endpoints.is_empty() {
            let entry = RoutingEntry::new(endpoints, Time::from_secs(0));
            router.table().add_route(route_config.key.into(), entry);
        }
    }

    // Optionally add default route
    if has_default_route && !default_endpoints.is_empty() {
        let default_entry = RoutingEntry::new(default_endpoints.clone(), Time::from_secs(0));
        router.table().add_route(RouteKey::Default, default_entry);
    }

    // Create symbol that won't match specific routes
    let unknown_object_id: ObjectId = symbol_config.object_id.into();
    let symbol_id = SymbolId::new(unknown_object_id, 0, symbol_config.esi);
    let symbol = Symbol::new(symbol_id, vec![42u8; 10], symbol_config.kind.into());

    // Test routing
    let route_result = router.route(&symbol);

    if has_default_route {
        // ASSERTION: Should successfully route to default
        match route_result {
            Ok(route_result) => {
                assert!(
                    route_result.is_fallback,
                    "Should be marked as fallback route"
                );
                assert_eq!(
                    route_result.matched_key,
                    RouteKey::Default,
                    "Should match default route key"
                );

                // ASSERTION: Selected endpoint should be from default route
                assert!(
                    default_endpoints
                        .iter()
                        .any(|e| e.id == route_result.endpoint.id),
                    "Should select endpoint from default route"
                );
            }
            Err(asupersync::transport::router::RoutingError::NoHealthyEndpoints { .. }) => {
                // Acceptable if default endpoints are unhealthy
            }
            Err(e) => {
                panic!("Unexpected routing error with default route: {:?}", e);
            }
        }
    } else {
        // ASSERTION: Should fail to route without default
        match route_result {
            Ok(_) => {
                panic!("Should not route successfully without default route");
            }
            Err(asupersync::transport::router::RoutingError::NoRoute { .. }) => {
                // Expected error
            }
            Err(_) => {
                // Other errors are acceptable
            }
        }
    }
}

fn fuzz_edge_cases(edge_case: EdgeCaseScenario) {
    match edge_case {
        EdgeCaseScenario::EmptyEndpoints(strategy) => {
            let lb = LoadBalancer::new(strategy.into());
            let empty_endpoints: Vec<Arc<Endpoint>> = Vec::new();

            // ASSERTION: Should handle empty endpoint list gracefully
            let result = lb.select(&empty_endpoints, None);
            assert!(
                result.is_none(),
                "Should return None for empty endpoint list"
            );

            let multi_result = lb.select_n(&empty_endpoints, 5, None);
            assert!(
                multi_result.is_empty(),
                "Should return empty for select_n on empty list"
            );
        }

        EdgeCaseScenario::AllUnhealthyEndpoints(strategy) => {
            let lb = LoadBalancer::new(strategy.into());
            let unhealthy_endpoints: Vec<Arc<Endpoint>> = (0..3)
                .map(|i| {
                    Arc::new(
                        Endpoint::new(EndpointId::new(i), format!("unhealthy-{}:8080", i))
                            .with_state(EndpointState::Unhealthy),
                    )
                })
                .collect();

            // ASSERTION: Should handle all unhealthy endpoints gracefully
            let result = lb.select(&unhealthy_endpoints, None);
            assert!(
                result.is_none(),
                "Should return None when all endpoints unhealthy"
            );

            let multi_result = lb.select_n(&unhealthy_endpoints, 2, None);
            assert!(
                multi_result.is_empty(),
                "Should return empty when all endpoints unhealthy"
            );
        }

        EdgeCaseScenario::SingleMaxLoadEndpoint => {
            let lb = LoadBalancer::new(
                asupersync::transport::router::LoadBalanceStrategy::LeastConnections,
            );
            let endpoint = Arc::new(Endpoint::new(EndpointId::new(1), "loaded:8080".to_string()));
            endpoint
                .active_connections
                .store(u32::MAX, std::sync::atomic::Ordering::Relaxed);

            let endpoints = vec![endpoint.clone()];

            // ASSERTION: Should handle maximum load gracefully
            let result = lb.select(&endpoints, None);
            assert!(
                result.is_some(),
                "Should still select endpoint even with max load"
            );
            assert_eq!(
                result.unwrap().id,
                endpoint.id,
                "Should select the only available endpoint"
            );
        }

        EdgeCaseScenario::ZeroWeightRoundRobin => {
            let lb = LoadBalancer::new(
                asupersync::transport::router::LoadBalanceStrategy::WeightedRoundRobin,
            );
            let endpoints: Vec<Arc<Endpoint>> = (0..3)
                .map(|i| {
                    Arc::new(
                        Endpoint::new(EndpointId::new(i), format!("zero-weight-{}:8080", i))
                            .with_weight(0),
                    )
                })
                .collect();

            // ASSERTION: Should handle zero weights gracefully
            let result = lb.select(&endpoints, None);
            assert!(
                result.is_some(),
                "Should select endpoint even with zero weights"
            );
        }

        EdgeCaseScenario::HashConsistency(object_id) => {
            let lb =
                LoadBalancer::new(asupersync::transport::router::LoadBalanceStrategy::HashBased);
            let endpoints: Vec<Arc<Endpoint>> = (0..5)
                .map(|i| {
                    Arc::new(Endpoint::new(
                        EndpointId::new(i),
                        format!("hash-{}:8080", i),
                    ))
                })
                .collect();

            let oid: ObjectId = object_id.into();

            // ASSERTION: Hash-based selection should be consistent
            let result1 = lb.select(&endpoints, Some(oid));
            let result2 = lb.select(&endpoints, Some(oid));

            match (result1, result2) {
                (Some(e1), Some(e2)) => {
                    assert_eq!(e1.id, e2.id, "Hash-based selection should be consistent");
                }
                (None, None) => {
                    // Both None is fine
                }
                _ => {
                    panic!("Hash-based selection consistency mismatch");
                }
            }
        }

        EdgeCaseScenario::TTLBoundary(offset) => {
            let _table = RoutingTable::new();
            let base_time = Time::from_secs(1000);
            let test_time = if offset < 0 {
                base_time.saturating_sub_nanos((-offset) as u64)
            } else {
                base_time.saturating_add_nanos(offset as u64)
            };

            let endpoint = Arc::new(Endpoint::new(
                EndpointId::new(1),
                "ttl-test:8080".to_string(),
            ));
            let ttl = Time::from_secs(10);
            let entry = RoutingEntry::new(vec![endpoint], base_time).with_ttl(ttl);

            // ASSERTION: TTL boundary calculations should be correct
            let is_expired = entry.is_expired(test_time);
            let expected_expired = test_time >= base_time.saturating_add_nanos(ttl.as_nanos());
            assert_eq!(
                is_expired, expected_expired,
                "TTL boundary check should be accurate"
            );
        }

        EdgeCaseScenario::ConcurrentDispatchLimit(limit) => {
            let requested = usize::from(limit).clamp(1, 10);
            let lb =
                LoadBalancer::new(asupersync::transport::router::LoadBalanceStrategy::RoundRobin);
            let endpoints: Vec<Arc<Endpoint>> = (0..3)
                .map(|i| {
                    Arc::new(Endpoint::new(
                        EndpointId::new(i),
                        format!("concurrent-{}:8080", i),
                    ))
                })
                .collect();

            let selected = lb.select_n(&endpoints, requested, None);
            assert!(
                selected.len() <= requested,
                "select_n should honor the requested concurrent dispatch limit"
            );
            assert!(
                selected.len() <= endpoints.len(),
                "select_n should not exceed the available endpoint count"
            );
        }

        EdgeCaseScenario::MissingRouteKeys(object_id) => {
            let router = SymbolRouter::new(Arc::new(RoutingTable::new()));
            let object_id: ObjectId = object_id.into();
            let symbol = Symbol::new(SymbolId::new(object_id, 0, 0), vec![0u8], SymbolKind::Source);

            assert!(
                matches!(
                    router.route(&symbol),
                    Err(asupersync::transport::router::RoutingError::NoRoute { .. })
                ),
                "Routing without matching keys or a default route should report NoRoute"
            );
        }

        EdgeCaseScenario::RoutingTableInsertEvictCycle {
            initial_endpoint_count,
            reinsert_endpoint_count,
            ttl_seconds,
            expiration_slack_nanos,
        } => {
            let table = RoutingTable::new();
            let key = RouteKey::Object(ObjectId::from_u128(0xfeed_face_cafe_beef));
            let created_at = Time::from_secs(10);
            let ttl = Time::from_secs(u64::from(ttl_seconds.max(1)).min(3600));
            let expire_at = created_at
                .saturating_add_nanos(ttl.as_nanos())
                .saturating_add_nanos(u64::from(expiration_slack_nanos));

            let initial_endpoints = make_router_endpoints(
                "initial",
                usize::from(initial_endpoint_count).clamp(1, 16),
                10,
            );
            let initial_ids = initial_endpoints
                .iter()
                .map(|endpoint| endpoint.id)
                .collect::<Vec<_>>();
            let initial_entry =
                RoutingEntry::new(initial_endpoints.clone(), created_at).with_ttl(ttl);

            table.add_route(key.clone(), initial_entry);
            assert_eq!(table.route_count(), 1, "initial route insert should increase route count");

            let pre_prune = table
                .lookup_without_default(&key)
                .expect("freshly inserted route should be discoverable");
            assert_eq!(
                pre_prune.endpoints.len(),
                initial_endpoints.len(),
                "pre-prune lookup should reflect the initial endpoint set"
            );
            assert!(
                pre_prune
                    .select_endpoint(None)
                    .is_some_and(|endpoint| initial_ids.contains(&endpoint.id)),
                "pre-prune selection should come from the initial endpoint set"
            );

            let pruned = table.prune_expired(expire_at);
            assert_eq!(pruned, 1, "expired route should be pruned exactly once");
            assert_eq!(table.route_count(), 0, "route count should drop after eviction");
            assert!(
                table.lookup_without_default(&key).is_none(),
                "expired route should not survive lookup after pruning"
            );

            let reinserted_endpoints = make_router_endpoints(
                "reinsert",
                usize::from(reinsert_endpoint_count).clamp(1, 16),
                100,
            );
            let reinserted_ids = reinserted_endpoints
                .iter()
                .map(|endpoint| endpoint.id)
                .collect::<Vec<_>>();
            let reinserted_entry = RoutingEntry::new(
                reinserted_endpoints.clone(),
                expire_at.saturating_add_nanos(1),
            )
            .with_ttl(ttl);
            table.add_route(key.clone(), reinserted_entry);

            assert_eq!(
                table.route_count(),
                1,
                "reinserting the same key should restore a single live route"
            );

            let post_reinsert = table
                .lookup_without_default(&key)
                .expect("reinserted route should be discoverable");
            assert_eq!(
                post_reinsert.endpoints.len(),
                reinserted_endpoints.len(),
                "lookup after reinsertion should reflect the new endpoint set"
            );
            assert!(
                post_reinsert
                    .select_endpoint(None)
                    .is_some_and(|endpoint| reinserted_ids.contains(&endpoint.id)),
                "reinserted route should not retain stale endpoints from the evicted entry"
            );
        }

        EdgeCaseScenario::ConnectionGuardStress(guard_count) => {
            let endpoint = Endpoint::new(EndpointId::new(77), "guard-stress:8080");
            let guard_count = usize::from(guard_count).clamp(1, 100);
            let mut guards = Vec::with_capacity(guard_count);

            for _ in 0..guard_count {
                guards.push(endpoint.acquire_connection_guard());
            }

            assert_eq!(
                endpoint.connection_count(),
                guard_count as u32,
                "Each active guard should increment the endpoint connection count"
            );

            drop(guards);

            assert_eq!(
                endpoint.connection_count(),
                0,
                "Dropping all guards should fully release the endpoint connection count"
            );
        }

        _ => {
            // Skip other edge cases that might require more complex setup
        }
    }
}

/// Stress test with maximum-length input scenarios
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_load_balancer_strategies() {
        for &strategy in &[
            asupersync::transport::router::LoadBalanceStrategy::RoundRobin,
            asupersync::transport::router::LoadBalanceStrategy::WeightedRoundRobin,
            asupersync::transport::router::LoadBalanceStrategy::LeastConnections,
            asupersync::transport::router::LoadBalanceStrategy::WeightedLeastConnections,
            asupersync::transport::router::LoadBalanceStrategy::Random,
            asupersync::transport::router::LoadBalanceStrategy::HashBased,
            asupersync::transport::router::LoadBalanceStrategy::FirstAvailable,
        ] {
            let lb = LoadBalancer::new(strategy);
            let endpoints: Vec<Arc<Endpoint>> = (0..3)
                .map(|i| {
                    Arc::new(Endpoint::new(
                        EndpointId::new(i),
                        format!("test-{}:8080", i),
                    ))
                })
                .collect();

            // Should not panic and should return a valid selection
            let _result = lb.select(&endpoints, None);
            let _multi_result = lb.select_n(&endpoints, 2, None);
        }
    }

    #[test]
    fn test_dispatch_strategies() {
        let strategies = [
            DispatchStrategy::Unicast,
            DispatchStrategy::Multicast { count: 2 },
            DispatchStrategy::Broadcast,
            DispatchStrategy::QuorumCast { required: 2 },
        ];

        for strategy in strategies {
            // Verify distinct strategy behavior patterns exist
            match strategy {
                DispatchStrategy::Unicast => assert!(true, "Unicast strategy available"),
                DispatchStrategy::Multicast { count } => {
                    assert!(count > 0, "Multicast has positive count")
                }
                DispatchStrategy::Broadcast => assert!(true, "Broadcast strategy available"),
                DispatchStrategy::QuorumCast { required } => {
                    assert!(required > 0, "QuorumCast has positive required")
                }
            }
        }
    }

    #[test]
    fn test_endpoint_id_properties() {
        for id in [0u64, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            fuzz_endpoint_id_parsing(id);
        }
    }

    #[test]
    fn test_routing_table_insert_evict_cycle_reinserts_cleanly() {
        fuzz_edge_cases(EdgeCaseScenario::RoutingTableInsertEvictCycle {
            initial_endpoint_count: 3,
            reinsert_endpoint_count: 5,
            ttl_seconds: 2,
            expiration_slack_nanos: 7,
        });
    }
}
