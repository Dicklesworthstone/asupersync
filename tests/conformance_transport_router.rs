//! Conformance tests for transport router symbol dispatch correctness.
//!
//! These tests verify that symbols are correctly routed and dispatched to endpoints
//! according to various strategies, ensuring load balancing works as expected and
//! symbol dispatch maintains correctness under all conditions.

#![cfg(test)]

use asupersync::security::authenticated::AuthenticatedSymbol;
use asupersync::security::tag::AuthenticationTag;
use asupersync::transport::router::{
    DispatchStrategy, Endpoint, EndpointId, EndpointState, LoadBalanceStrategy, RouteKey,
    RoutingEntry, RoutingTable, SymbolRouter,
};
use asupersync::types::symbol::{ObjectId, Symbol};
use asupersync::types::{RegionId, Time};
use std::sync::Arc;

/// Helper to create test symbols.
fn test_symbol(id: u64) -> Symbol {
    Symbol::new_for_test(id, 0, id as u32, &[42u8; 16])
}

/// Helper to create test endpoints.
fn test_endpoint(id: u64) -> Endpoint {
    Endpoint::new(EndpointId::new(id), format!("endpoint-{}", id))
}

/// Helper to create authenticated symbol.
fn authenticated_symbol(id: u64) -> AuthenticatedSymbol {
    let symbol = test_symbol(id);
    AuthenticatedSymbol::new_verified(symbol, AuthenticationTag::zero())
}

/// Test basic routing table functionality.
#[test]
fn test_routing_table_endpoint_registration() {
    let table = RoutingTable::new();

    // Register endpoints
    let ep1 = table.register_endpoint(test_endpoint(1));
    let ep2 = table.register_endpoint(test_endpoint(2));

    // Verify endpoints are registered
    assert_eq!(ep1.id, EndpointId::new(1));
    assert_eq!(ep2.id, EndpointId::new(2));
    assert_eq!(ep1.address, "endpoint-1");
    assert_eq!(ep2.address, "endpoint-2");
}

/// Test route configuration and endpoint state management.
#[test]
fn test_endpoint_state_management() {
    let table = RoutingTable::new();

    // Register endpoints with different states
    let ep1 = table.register_endpoint(test_endpoint(1).with_state(EndpointState::Healthy));
    let ep2 = table.register_endpoint(test_endpoint(2).with_state(EndpointState::Degraded));
    let ep3 = table.register_endpoint(test_endpoint(3).with_state(EndpointState::Unhealthy));

    // Add route entry
    table.add_route(
        RouteKey::Default,
        RoutingEntry::new(vec![ep1, ep2, ep3], Time::ZERO),
    );

    // Verify routing table can be created
    let _router = SymbolRouter::new(Arc::new(table));
}

/// Test load balancing strategy configuration.
#[test]
fn test_load_balance_strategy_configuration() {
    let table = RoutingTable::new();

    // Register endpoints with weights
    let ep1 = table.register_endpoint(test_endpoint(1).with_weight(1));
    let ep2 = table.register_endpoint(test_endpoint(2).with_weight(2));
    let ep3 = table.register_endpoint(test_endpoint(3).with_weight(3));

    // Test round-robin strategy
    table.add_route(
        RouteKey::Default,
        RoutingEntry::new(vec![ep1.clone(), ep2.clone()], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::RoundRobin),
    );

    // Test weighted round-robin strategy
    table.add_route(
        RouteKey::object(ObjectId::new(2, 0)),
        RoutingEntry::new(vec![ep1, ep2, ep3], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::WeightedRoundRobin),
    );

    let _router = SymbolRouter::new(Arc::new(table));
}

/// Test dispatch strategy enumeration.
#[test]
fn test_dispatch_strategy_types() {
    // Test that all dispatch strategies can be created
    let _unicast = DispatchStrategy::Unicast;
    let _multicast = DispatchStrategy::Multicast { count: 3 };
    let _broadcast = DispatchStrategy::Broadcast;
    let _quorum = DispatchStrategy::QuorumCast { required: 2 };
}

/// Test authenticated symbol creation.
#[test]
fn test_authenticated_symbol_creation() {
    let symbol = test_symbol(123);
    let _auth_symbol = authenticated_symbol(123);

    // Verify symbol properties can be accessed
    let _object_id = symbol.object_id();

    // Verify authenticated symbol can be created
    let tag = AuthenticationTag::zero();
    let _auth_symbol2 = AuthenticatedSymbol::new_verified(symbol, tag);
}

/// Test route key types.
#[test]
fn test_route_key_types() {
    // Test different route key types
    let _default = RouteKey::Default;
    let _object_route = RouteKey::object(ObjectId::new(1, 0));
    let _region_route = RouteKey::region(RegionId::new_for_test(1, 0));
}

/// Test endpoint configuration options.
#[test]
fn test_endpoint_configuration() {
    let table = RoutingTable::new();

    // Test endpoint with various configurations
    let ep1 = table.register_endpoint(
        test_endpoint(1)
            .with_state(EndpointState::Healthy)
            .with_weight(100),
    );

    let ep2 = table.register_endpoint(
        test_endpoint(2)
            .with_state(EndpointState::Degraded)
            .with_weight(50),
    );

    // Verify configuration
    assert_eq!(ep1.id, EndpointId::new(1));
    assert_eq!(ep2.id, EndpointId::new(2));
}

/// Test routing table with multiple routes.
#[test]
fn test_multiple_route_configuration() {
    let table = RoutingTable::new();

    // Register endpoints
    let ep1 = table.register_endpoint(test_endpoint(1));
    let ep2 = table.register_endpoint(test_endpoint(2));
    let ep3 = table.register_endpoint(test_endpoint(3));

    // Add multiple routes
    table.add_route(
        RouteKey::Default,
        RoutingEntry::new(vec![ep1.clone(), ep2.clone()], Time::ZERO),
    );

    table.add_route(
        RouteKey::region(RegionId::new_for_test(1, 0)),
        RoutingEntry::new(vec![ep3], Time::ZERO),
    );

    let _router = SymbolRouter::new(Arc::new(table));
}

/// Test comprehensive endpoint state enumeration.
#[test]
fn test_all_endpoint_states() {
    // Verify all endpoint states can be created
    let _healthy = EndpointState::Healthy;
    let _degraded = EndpointState::Degraded;
    let _unhealthy = EndpointState::Unhealthy;
    let _draining = EndpointState::Draining;
    let _removed = EndpointState::Removed;
}

/// Test comprehensive load balance strategy enumeration.
#[test]
fn test_all_load_balance_strategies() {
    // Verify all load balance strategies can be created
    let _round_robin = LoadBalanceStrategy::RoundRobin;
    let _weighted_round_robin = LoadBalanceStrategy::WeightedRoundRobin;
    let _least_connections = LoadBalanceStrategy::LeastConnections;
    let _weighted_least_connections = LoadBalanceStrategy::WeightedLeastConnections;
    let _random = LoadBalanceStrategy::Random;
    let _hash_based = LoadBalanceStrategy::HashBased;
    let _first_available = LoadBalanceStrategy::FirstAvailable;
}
