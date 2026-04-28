#![no_main]

//! Structure-aware route-resolution fuzzer for `src/transport/router.rs`.
//!
//! This target models contention as adversarial interleavings of endpoint
//! registration/state/removal with route-table updates and immediate resolution
//! on the same object IDs. The invariants are structural rather than
//! strategy-specific: resolved endpoints must come from the currently matched
//! route, default fallback must only occur when the object route cannot serve
//! traffic, and endpoint removal must scrub dispatchable state plus empty
//! routes.

use arbitrary::Arbitrary;
use asupersync::{
    transport::router::{
        Endpoint, EndpointId, EndpointState, LoadBalanceStrategy, RouteKey, RoutingEntry,
        RoutingError, RoutingTable, SymbolRouter,
    },
    types::{ObjectId, RegionId, Symbol, Time},
};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const MAX_INITIAL_ENDPOINTS: usize = 12;
const MAX_OPERATIONS: usize = 96;
const MAX_ROUTE_ENDPOINTS: usize = 8;
const MAX_MULTICAST_COUNT: usize = 6;

#[derive(Arbitrary, Debug)]
struct RouterScenario {
    initial_endpoints: Vec<EndpointSeed>,
    operations: Vec<RouterOp>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct EndpointSeed {
    slot: u8,
    weight: u8,
    region: Option<u8>,
    state: EndpointStateInput,
}

#[derive(Arbitrary, Debug, Clone)]
enum RouterOp {
    EnsureEndpoint(EndpointSeed),
    SetEndpointState {
        slot: u8,
        state: EndpointStateInput,
    },
    RemoveEndpoint {
        slot: u8,
    },
    PutObjectRoute {
        object: u16,
        endpoint_slots: Vec<u8>,
        strategy: StrategyInput,
        ttl_nanos: Option<u16>,
    },
    RemoveObjectRoute {
        object: u16,
    },
    PutDefaultRoute {
        endpoint_slots: Vec<u8>,
        strategy: StrategyInput,
        ttl_nanos: Option<u16>,
    },
    RemoveDefaultRoute,
    AdvanceTime {
        delta_nanos: u16,
    },
    PruneExpired,
    Resolve {
        object: u16,
    },
    ResolveMulticast {
        object: u16,
        count: u8,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum EndpointStateInput {
    Healthy,
    Degraded,
    Unhealthy,
    Draining,
    Removed,
}

impl From<EndpointStateInput> for EndpointState {
    fn from(value: EndpointStateInput) -> Self {
        match value {
            EndpointStateInput::Healthy => Self::Healthy,
            EndpointStateInput::Degraded => Self::Degraded,
            EndpointStateInput::Unhealthy => Self::Unhealthy,
            EndpointStateInput::Draining => Self::Draining,
            EndpointStateInput::Removed => Self::Removed,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StrategyInput {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    WeightedLeastConnections,
    Random,
    HashBased,
    FirstAvailable,
}

impl From<StrategyInput> for LoadBalanceStrategy {
    fn from(value: StrategyInput) -> Self {
        match value {
            StrategyInput::RoundRobin => Self::RoundRobin,
            StrategyInput::WeightedRoundRobin => Self::WeightedRoundRobin,
            StrategyInput::LeastConnections => Self::LeastConnections,
            StrategyInput::WeightedLeastConnections => Self::WeightedLeastConnections,
            StrategyInput::Random => Self::Random,
            StrategyInput::HashBased => Self::HashBased,
            StrategyInput::FirstAvailable => Self::FirstAvailable,
        }
    }
}

#[derive(Debug, Clone)]
struct ShadowEndpoint {
    state: EndpointState,
}

#[derive(Debug, Clone)]
struct ShadowRoute {
    endpoint_ids: Vec<EndpointId>,
    ttl: Option<Time>,
    created_at: Time,
}

impl ShadowRoute {
    fn is_expired(&self, now: Time) -> bool {
        self.ttl
            .is_some_and(|ttl| now >= self.created_at.saturating_add_nanos(ttl.as_nanos()))
    }
}

struct ShadowModel {
    now: Time,
    endpoints: BTreeMap<EndpointId, ShadowEndpoint>,
    object_routes: BTreeMap<ObjectId, ShadowRoute>,
    default_route: Option<ShadowRoute>,
}

impl ShadowModel {
    fn new() -> Self {
        Self {
            now: Time::ZERO,
            endpoints: BTreeMap::new(),
            object_routes: BTreeMap::new(),
            default_route: None,
        }
    }

    fn scrub_endpoint(&mut self, endpoint_id: EndpointId) {
        self.endpoints.remove(&endpoint_id);
        self.object_routes.retain(|_, route| {
            route.endpoint_ids.retain(|id| *id != endpoint_id);
            !route.endpoint_ids.is_empty()
        });
        if let Some(default_route) = self.default_route.as_mut() {
            default_route.endpoint_ids.retain(|id| *id != endpoint_id);
            if default_route.endpoint_ids.is_empty() {
                self.default_route = None;
            }
        }
    }

    fn prune_expired(&mut self) -> usize {
        let before = self.object_routes.len() + usize::from(self.default_route.is_some());
        self.object_routes
            .retain(|_, route| !route.is_expired(self.now));
        if self
            .default_route
            .as_ref()
            .is_some_and(|route| route.is_expired(self.now))
        {
            self.default_route = None;
        }
        before - (self.object_routes.len() + usize::from(self.default_route.is_some()))
    }

    fn route_count(&self) -> usize {
        self.object_routes.len() + usize::from(self.default_route.is_some())
    }
}

#[derive(Debug)]
enum ExpectedRouteOutcome {
    Routed {
        matched_key: RouteKey,
        is_fallback: bool,
        candidate_ids: BTreeSet<EndpointId>,
    },
    NoHealthy,
    NoRoute,
}

fuzz_target!(|scenario: RouterScenario| {
    run_scenario(scenario);
});

fn run_scenario(mut scenario: RouterScenario) {
    scenario.initial_endpoints.truncate(MAX_INITIAL_ENDPOINTS);
    scenario.operations.truncate(MAX_OPERATIONS);

    let table = Arc::new(RoutingTable::new());
    let router = SymbolRouter::new(table.clone());
    let mut model = ShadowModel::new();

    for endpoint in scenario.initial_endpoints {
        ensure_endpoint(&table, &mut model, endpoint);
    }
    assert_global_invariants(&table, &model);

    for op in scenario.operations {
        match op {
            RouterOp::EnsureEndpoint(endpoint) => ensure_endpoint(&table, &mut model, endpoint),
            RouterOp::SetEndpointState { slot, state } => {
                set_endpoint_state(&table, &mut model, slot, state);
            }
            RouterOp::RemoveEndpoint { slot } => remove_endpoint(&table, &mut model, slot),
            RouterOp::PutObjectRoute {
                object,
                endpoint_slots,
                strategy,
                ttl_nanos,
            } => put_object_route(
                &table,
                &mut model,
                object,
                &endpoint_slots,
                strategy,
                ttl_nanos,
            ),
            RouterOp::RemoveObjectRoute { object } => {
                remove_object_route(&table, &mut model, object);
            }
            RouterOp::PutDefaultRoute {
                endpoint_slots,
                strategy,
                ttl_nanos,
            } => put_default_route(&table, &mut model, &endpoint_slots, strategy, ttl_nanos),
            RouterOp::RemoveDefaultRoute => remove_default_route(&table, &mut model),
            RouterOp::AdvanceTime { delta_nanos } => {
                model.now = model
                    .now
                    .saturating_add_nanos(u64::from(delta_nanos).saturating_add(1));
            }
            RouterOp::PruneExpired => prune_expired(&table, &mut model),
            RouterOp::Resolve { object } => assert_resolve(&router, &model, object),
            RouterOp::ResolveMulticast { object, count } => {
                assert_multicast(&router, &model, object, count);
            }
        }

        assert_global_invariants(&table, &model);
    }
}

fn ensure_endpoint(table: &RoutingTable, model: &mut ShadowModel, seed: EndpointSeed) {
    let endpoint_id = endpoint_id(seed.slot);
    let state = EndpointState::from(seed.state);

    if let Some(endpoint) = model.endpoints.get_mut(&endpoint_id) {
        assert!(
            table.update_endpoint_state(endpoint_id, state),
            "existing endpoint must accept state update"
        );
        endpoint.state = state;
        return;
    }

    let mut endpoint = Endpoint::new(endpoint_id, format!("endpoint-{}", seed.slot))
        .with_weight(u32::from(seed.weight).max(1))
        .with_state(state);
    if let Some(region) = seed.region {
        endpoint = endpoint.with_region(region_id(region));
    }
    table.register_endpoint(endpoint);
    model
        .endpoints
        .insert(endpoint_id, ShadowEndpoint { state });
}

fn set_endpoint_state(
    table: &RoutingTable,
    model: &mut ShadowModel,
    slot: u8,
    state: EndpointStateInput,
) {
    let endpoint_id = endpoint_id(slot);
    let expected_present = model.endpoints.contains_key(&endpoint_id);
    let actual = table.update_endpoint_state(endpoint_id, state.into());
    assert_eq!(
        actual, expected_present,
        "endpoint state update presence must match shadow state"
    );
    if let Some(endpoint) = model.endpoints.get_mut(&endpoint_id) {
        endpoint.state = state.into();
    }
}

fn remove_endpoint(table: &RoutingTable, model: &mut ShadowModel, slot: u8) {
    let endpoint_id = endpoint_id(slot);
    let removed = table.remove_endpoint(endpoint_id);
    let expected = model.endpoints.contains_key(&endpoint_id);
    assert_eq!(
        removed.is_some(),
        expected,
        "endpoint removal result must match shadow state"
    );
    if expected {
        model.scrub_endpoint(endpoint_id);
    }
}

fn put_object_route(
    table: &RoutingTable,
    model: &mut ShadowModel,
    object: u16,
    endpoint_slots: &[u8],
    strategy: StrategyInput,
    ttl_nanos: Option<u16>,
) {
    let object_id = object_id(object);
    let (endpoints, endpoint_ids) = selected_route_endpoints(table, endpoint_slots);
    table.add_route(
        RouteKey::Object(object_id),
        build_entry(endpoints, model.now, strategy, ttl_nanos),
    );
    model.object_routes.insert(
        object_id,
        ShadowRoute {
            endpoint_ids,
            ttl: ttl_nanos.map(ttl_from_input),
            created_at: model.now,
        },
    );
}

fn remove_object_route(table: &RoutingTable, model: &mut ShadowModel, object: u16) {
    let object_id = object_id(object);
    let actual = table.remove_route(&RouteKey::Object(object_id));
    let expected = model.object_routes.remove(&object_id).is_some();
    assert_eq!(
        actual, expected,
        "object route removal must match shadow state"
    );
}

fn put_default_route(
    table: &RoutingTable,
    model: &mut ShadowModel,
    endpoint_slots: &[u8],
    strategy: StrategyInput,
    ttl_nanos: Option<u16>,
) {
    let (endpoints, endpoint_ids) = selected_route_endpoints(table, endpoint_slots);
    table.add_route(
        RouteKey::Default,
        build_entry(endpoints, model.now, strategy, ttl_nanos),
    );
    model.default_route = Some(ShadowRoute {
        endpoint_ids,
        ttl: ttl_nanos.map(ttl_from_input),
        created_at: model.now,
    });
}

fn remove_default_route(table: &RoutingTable, model: &mut ShadowModel) {
    let actual = table.remove_route(&RouteKey::Default);
    let expected = model.default_route.take().is_some();
    assert_eq!(
        actual, expected,
        "default route removal must match shadow state"
    );
}

fn prune_expired(table: &RoutingTable, model: &mut ShadowModel) {
    let actual = table.prune_expired(model.now);
    let expected = model.prune_expired();
    assert_eq!(
        actual, expected,
        "pruned route count must match shadow model"
    );
}

fn assert_resolve(router: &SymbolRouter, model: &ShadowModel, object: u16) {
    let object_id = object_id(object);
    let symbol = test_symbol(object);
    let actual_route = router
        .table()
        .lookup_without_default(&RouteKey::Object(object_id), model.now);
    match model.object_routes.get(&object_id) {
        Some(route) if !route.is_expired(model.now) => {
            let actual_route = actual_route.expect("live object route must resolve in lookup");
            assert_eq!(
                entry_endpoint_ids(&actual_route),
                route.endpoint_ids,
                "lookup_without_default must expose the current object-route endpoint set"
            );
        }
        _ => assert!(
            actual_route.is_none(),
            "expired or absent object route must not be returned by lookup_without_default"
        ),
    }

    match (
        expected_route(model, object_id),
        router.route(&symbol, model.now),
    ) {
        (
            ExpectedRouteOutcome::Routed {
                matched_key,
                is_fallback,
                candidate_ids,
            },
            Ok(route),
        ) => {
            assert_eq!(route.matched_key, matched_key, "matched route key drifted");
            assert_eq!(route.is_fallback, is_fallback, "fallback flag drifted");
            assert!(
                candidate_ids.contains(&route.endpoint.id),
                "resolved endpoint must come from the active candidate set"
            );
        }
        (
            ExpectedRouteOutcome::NoHealthy,
            Err(RoutingError::NoHealthyEndpoints { object_id: got }),
        ) if got == object_id => {}
        (ExpectedRouteOutcome::NoRoute, Err(RoutingError::NoRoute { object_id: got, .. }))
            if got == object_id => {}
        (expected, actual) => {
            panic!("route resolution mismatch: expected={expected:?} actual={actual:?}");
        }
    }
}

fn assert_multicast(router: &SymbolRouter, model: &ShadowModel, object: u16, count: u8) {
    let requested = usize::from(count).clamp(1, MAX_MULTICAST_COUNT);
    let object_id = object_id(object);
    let symbol = test_symbol(object);

    match (
        expected_route(model, object_id),
        router.route_multicast(&symbol, requested, model.now),
    ) {
        (
            ExpectedRouteOutcome::Routed {
                matched_key,
                is_fallback,
                candidate_ids,
            },
            Ok(routes),
        ) => {
            assert!(
                !routes.is_empty(),
                "multicast with live candidates must return at least one endpoint"
            );
            assert!(
                routes.len() <= requested,
                "multicast returned more endpoints than requested"
            );
            assert!(
                routes.len() <= candidate_ids.len(),
                "multicast returned more endpoints than were available"
            );

            let unique_ids: BTreeSet<_> = routes.iter().map(|route| route.endpoint.id).collect();
            assert_eq!(
                unique_ids.len(),
                routes.len(),
                "multicast must not duplicate endpoints"
            );

            for route in routes {
                assert_eq!(route.matched_key, matched_key, "matched route key drifted");
                assert_eq!(route.is_fallback, is_fallback, "fallback flag drifted");
                assert!(
                    candidate_ids.contains(&route.endpoint.id),
                    "multicast endpoint must come from the active candidate set"
                );
            }
        }
        (
            ExpectedRouteOutcome::NoHealthy,
            Err(RoutingError::NoHealthyEndpoints { object_id: got }),
        ) if got == object_id => {}
        (ExpectedRouteOutcome::NoRoute, Err(RoutingError::NoRoute { object_id: got, .. }))
            if got == object_id => {}
        (expected, actual) => {
            panic!("multicast resolution mismatch: expected={expected:?} actual={actual:?}");
        }
    }
}

fn assert_global_invariants(table: &RoutingTable, model: &ShadowModel) {
    assert_eq!(
        table.route_count(),
        model.route_count(),
        "route_count drifted from shadow model"
    );

    let dispatchable: Vec<_> = table
        .dispatchable_endpoints()
        .into_iter()
        .map(|endpoint| endpoint.id)
        .collect();
    let expected_dispatchable: Vec<_> = model
        .endpoints
        .iter()
        .filter_map(|(endpoint_id, endpoint)| endpoint.state.can_receive().then_some(*endpoint_id))
        .collect();
    assert_eq!(
        dispatchable, expected_dispatchable,
        "dispatchable endpoints drifted from shadow model"
    );

    for (endpoint_id, endpoint) in &model.endpoints {
        let actual = table
            .get_endpoint(*endpoint_id)
            .expect("shadow endpoint must exist in routing table");
        assert_eq!(
            actual.state(),
            endpoint.state,
            "endpoint state drifted from shadow model"
        );
    }
}

fn expected_route(model: &ShadowModel, object_id: ObjectId) -> ExpectedRouteOutcome {
    let primary = model
        .object_routes
        .get(&object_id)
        .filter(|route| !route.is_expired(model.now));
    if let Some(primary_route) = primary {
        let candidates = healthy_candidates(model, primary_route);
        if !candidates.is_empty() {
            return ExpectedRouteOutcome::Routed {
                matched_key: RouteKey::Object(object_id),
                is_fallback: false,
                candidate_ids: candidates,
            };
        }
    }

    if let Some(default_route) = model
        .default_route
        .as_ref()
        .filter(|route| !route.is_expired(model.now))
    {
        let candidates = healthy_candidates(model, default_route);
        if !candidates.is_empty() {
            return ExpectedRouteOutcome::Routed {
                matched_key: RouteKey::Default,
                is_fallback: true,
                candidate_ids: candidates,
            };
        }
        return ExpectedRouteOutcome::NoHealthy;
    }

    if primary.is_some() {
        ExpectedRouteOutcome::NoHealthy
    } else {
        ExpectedRouteOutcome::NoRoute
    }
}

fn healthy_candidates(model: &ShadowModel, route: &ShadowRoute) -> BTreeSet<EndpointId> {
    route
        .endpoint_ids
        .iter()
        .copied()
        .filter(|endpoint_id| {
            model
                .endpoints
                .get(endpoint_id)
                .is_some_and(|endpoint| endpoint.state.can_receive())
        })
        .collect()
}

fn selected_route_endpoints(
    table: &RoutingTable,
    endpoint_slots: &[u8],
) -> (Vec<Arc<Endpoint>>, Vec<EndpointId>) {
    let mut seen = BTreeSet::new();
    let mut endpoints = Vec::new();
    let mut endpoint_ids = Vec::new();

    for slot in endpoint_slots.iter().take(MAX_ROUTE_ENDPOINTS) {
        let endpoint_id = endpoint_id(*slot);
        if !seen.insert(endpoint_id) {
            continue;
        }
        if let Some(endpoint) = table.get_endpoint(endpoint_id) {
            endpoints.push(endpoint);
            endpoint_ids.push(endpoint_id);
        }
    }

    (endpoints, endpoint_ids)
}

fn build_entry(
    endpoints: Vec<Arc<Endpoint>>,
    now: Time,
    strategy: StrategyInput,
    ttl_nanos: Option<u16>,
) -> RoutingEntry {
    let mut entry = RoutingEntry::new(endpoints, now).with_strategy(strategy.into());
    if let Some(ttl) = ttl_nanos.map(ttl_from_input) {
        entry = entry.with_ttl(ttl);
    }
    entry
}

fn entry_endpoint_ids(entry: &RoutingEntry) -> Vec<EndpointId> {
    entry.endpoints.iter().map(|endpoint| endpoint.id).collect()
}

fn endpoint_id(slot: u8) -> EndpointId {
    EndpointId::new(u64::from(slot).saturating_add(1))
}

fn object_id(object: u16) -> ObjectId {
    ObjectId::new_for_test(u64::from(object).saturating_add(1))
}

fn region_id(region: u8) -> RegionId {
    RegionId::new_for_test(u32::from(region).saturating_add(1), 0)
}

fn test_symbol(object: u16) -> Symbol {
    Symbol::new_for_test(
        u64::from(object).saturating_add(1),
        0,
        0,
        &[object as u8, (object >> 8) as u8],
    )
}

fn ttl_from_input(ttl_nanos: u16) -> Time {
    Time::from_nanos(u64::from(ttl_nanos).saturating_add(1))
}
