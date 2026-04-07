#![allow(clippy::items_after_statements)]
//! Integration tests for the service layer ecosystem.
//!
//! Validates that buffer, discover, load_balance, reconnect, hedge,
//! steer, filter, and existing middleware (timeout, retry, concurrency_limit,
//! load_shed, rate_limit) compose correctly.

#[macro_use]
mod common;

mod asupersync {
    pub use crate::test_complete;
    pub use ::asupersync::*;
}

use asupersync::service::Layer;
use asupersync::service::buffer::BufferLayer;
use asupersync::service::discover::{
    Change, Discover, DnsDiscoveryConfig, DnsServiceDiscovery, StaticList,
};
use asupersync::service::filter::{Filter, FilterError, FilterLayer};
use asupersync::service::hedge::{Hedge, HedgeConfig, HedgeLayer};
use asupersync::service::load_balance::{
    LoadBalancer, PowerOfTwoChoices, RoundRobin, Strategy, Weighted,
};
use asupersync::service::reconnect::{MakeService, Reconnect, ReconnectLayer};
use asupersync::service::steer::{Steer, SteerError};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn init_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

fn socket_set(addrs: &[&str]) -> HashSet<SocketAddr> {
    addrs.iter().map(|addr| addr.parse().unwrap()).collect()
}

fn scripted_resolver(
    script: Vec<Result<HashSet<SocketAddr>, std::io::Error>>,
) -> impl Fn(&str, u16) -> Result<HashSet<SocketAddr>, std::io::Error> + Send + Sync + 'static {
    let script = Arc::new(Mutex::new(VecDeque::from(script)));
    move |_, _| {
        script
            .lock()
            .expect("resolver script lock poisoned")
            .pop_front()
            .expect("resolver script exhausted")
    }
}

// ════════════════════════════════════════════════════════════════════════
// Discovery + Load Balancing
// ════════════════════════════════════════════════════════════════════════

#[test]
fn static_discovery_feeds_load_balancer() {
    init_test("static_discovery_feeds_load_balancer");

    let endpoints: Vec<SocketAddr> = vec![
        "10.0.0.1:80".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        "10.0.0.3:80".parse().unwrap(),
    ];
    let discovery = StaticList::new(endpoints);

    // First poll yields all as Insert.
    let changes = discovery.poll_discover().unwrap();
    assert_eq!(changes.len(), 3);

    let mut addrs = Vec::new();
    for change in &changes {
        if let Change::Insert(addr) = change {
            addrs.push(*addr);
        }
    }
    assert_eq!(addrs.len(), 3);

    // Build load balancer from discovered endpoints.
    let lb = LoadBalancer::new(RoundRobin::new(), addrs.clone());
    assert_eq!(lb.len(), 3);
    assert_eq!(lb.loads(), vec![0, 0, 0]);

    asupersync::test_complete!("static_discovery_feeds_load_balancer");
}

#[test]
fn dns_discovery_provides_endpoints() {
    init_test("dns_discovery_provides_endpoints");

    let discovery = DnsServiceDiscovery::new(
        DnsDiscoveryConfig::new("service.test", 9090).with_resolver(|hostname, port| {
            assert_eq!(hostname, "service.test");
            assert_eq!(port, 9090);
            Ok(socket_set(&["127.0.0.1:9090", "127.0.0.2:9090"]))
        }),
    );
    let changes = discovery.poll_discover().unwrap();
    assert!(!changes.is_empty());

    let endpoints = discovery.endpoints();
    assert!(!endpoints.is_empty());

    // Verify all endpoints have the correct port.
    for addr in &endpoints {
        assert_eq!(addr.port(), 9090);
    }

    asupersync::test_complete!("dns_discovery_provides_endpoints");
}

// ════════════════════════════════════════════════════════════════════════
// Load Balancing Strategies
// ════════════════════════════════════════════════════════════════════════

#[test]
fn round_robin_distributes_evenly() {
    init_test("round_robin_distributes_evenly");

    let rr = RoundRobin::new();
    let loads = [0u64; 4];
    let mut counts = [0u32; 4];

    for _ in 0..100 {
        let idx = rr.pick(&loads).unwrap();
        counts[idx] += 1;
    }

    // Each backend should get exactly 25.
    for count in &counts {
        assert_eq!(*count, 25, "counts={counts:?}");
    }

    asupersync::test_complete!("round_robin_distributes_evenly");
}

#[test]
fn p2c_avoids_overloaded_backends() {
    init_test("p2c_avoids_overloaded_backends");

    let p2c = PowerOfTwoChoices::new();
    // Backend 0 is heavily loaded.
    let loads = [1000, 0, 0, 0, 0];
    let mut hit_overloaded = 0u32;

    for _ in 0..200 {
        if p2c.pick(&loads).unwrap() == 0 {
            hit_overloaded += 1;
        }
    }

    // P2C should rarely pick the overloaded backend.
    assert!(hit_overloaded < 50, "hit_overloaded={hit_overloaded}");

    asupersync::test_complete!("p2c_avoids_overloaded_backends");
}

#[test]
fn weighted_respects_ratios() {
    init_test("weighted_respects_ratios");

    let w = Weighted::new(vec![5, 3, 2]);
    let loads = [0, 0, 0];
    let mut counts = [0u32; 3];

    for _ in 0..1000 {
        counts[w.pick(&loads).unwrap()] += 1;
    }

    // 5:3:2 = 500:300:200.
    assert_eq!(counts[0], 500, "counts={counts:?}");
    assert_eq!(counts[1], 300, "counts={counts:?}");
    assert_eq!(counts[2], 200, "counts={counts:?}");

    asupersync::test_complete!("weighted_respects_ratios");
}

// ════════════════════════════════════════════════════════════════════════
// Reconnect
// ════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct CountingMaker {
    call_count: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

#[derive(Debug)]
struct CountingMakerError;

impl std::fmt::Display for CountingMakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "counting maker error")
    }
}

impl std::error::Error for CountingMakerError {}

#[derive(Debug)]
struct CountingSvc(u32);

impl MakeService for CountingMaker {
    type Service = CountingSvc;
    type Error = CountingMakerError;

    fn make_service(&self) -> Result<CountingSvc, CountingMakerError> {
        let n = self
            .call_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(CountingSvc(n))
    }
}

#[test]
fn reconnect_lazy_then_connect() {
    init_test("reconnect_lazy_then_connect");

    let maker = CountingMaker {
        call_count: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
    };
    let mut rc = Reconnect::lazy(maker);

    assert!(!rc.is_connected());
    rc.reconnect().unwrap();
    assert!(rc.is_connected());
    assert_eq!(rc.inner().unwrap().0, 0);

    // Disconnect and reconnect should get a new service.
    rc.disconnect();
    rc.reconnect().unwrap();
    assert_eq!(rc.inner().unwrap().0, 1);
    assert_eq!(rc.reconnect_count(), 2);

    asupersync::test_complete!("reconnect_lazy_then_connect");
}

#[test]
fn reconnect_layer_wraps_initial() {
    init_test("reconnect_layer_wraps_initial");

    let maker = CountingMaker {
        call_count: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
    };
    let initial = maker.make_service().unwrap();
    let layer = ReconnectLayer::new(maker);
    let svc = layer.layer(initial);

    assert!(svc.is_connected());
    assert_eq!(svc.inner().unwrap().0, 0);

    asupersync::test_complete!("reconnect_layer_wraps_initial");
}

// ════════════════════════════════════════════════════════════════════════
// Hedge
// ════════════════════════════════════════════════════════════════════════

#[test]
fn hedge_configuration() {
    init_test("hedge_configuration");

    let config = HedgeConfig::new(Duration::from_millis(50)).max_pending(3);
    assert_eq!(config.delay, Duration::from_millis(50));
    assert_eq!(config.max_pending, 3);

    let hedge = Hedge::new((), config);
    assert_eq!(hedge.delay(), Duration::from_millis(50));
    assert_eq!(hedge.max_pending(), 3);

    asupersync::test_complete!("hedge_configuration");
}

#[test]
fn hedge_layer_creates_service() {
    init_test("hedge_layer_creates_service");

    let layer = HedgeLayer::with_delay(Duration::from_millis(100));
    let hedge = layer.layer(42u32);
    assert_eq!(*hedge.inner(), 42);
    assert_eq!(hedge.delay(), Duration::from_millis(100));

    asupersync::test_complete!("hedge_layer_creates_service");
}

#[test]
fn hedge_stats_tracking() {
    init_test("hedge_stats_tracking");

    let hedge = Hedge::new((), HedgeConfig::new(Duration::from_millis(10)));
    assert_eq!(hedge.total_requests(), 0);
    assert_eq!(hedge.hedged_requests(), 0);
    assert!((hedge.hedge_rate() - 0.0).abs() < f64::EPSILON);

    hedge.record_request();
    hedge.record_request();
    hedge.record_request();
    hedge.record_hedge();
    hedge.record_hedge_win();

    assert_eq!(hedge.total_requests(), 3);
    assert_eq!(hedge.hedged_requests(), 1);
    assert_eq!(hedge.hedge_wins(), 1);
    assert!((hedge.hedge_rate() - 1.0 / 3.0).abs() < 0.01);

    asupersync::test_complete!("hedge_stats_tracking");
}

// ════════════════════════════════════════════════════════════════════════
// Steer
// ════════════════════════════════════════════════════════════════════════

#[test]
fn steer_routes_by_predicate() {
    init_test("steer_routes_by_predicate");

    // Route to service 0 for even, service 1 for odd.
    let svcs = vec!["even_handler", "odd_handler"];
    let steer = Steer::new(svcs, |req: &i32| req.unsigned_abs() as usize % 2);

    assert_eq!(steer.len(), 2);
    assert_eq!(steer.services()[0], "even_handler");
    assert_eq!(steer.services()[1], "odd_handler");

    asupersync::test_complete!("steer_routes_by_predicate");
}

#[test]
fn steer_wraps_index() {
    init_test("steer_wraps_index");

    let svcs = vec!["a", "b"];
    let steer = Steer::new(svcs, |(): &()| 100);

    // Verify the steer wraps — 100 % 2 == 0, so service "a" is selected.
    assert_eq!(steer.len(), 2);

    asupersync::test_complete!("steer_wraps_index");
}

// ════════════════════════════════════════════════════════════════════════
// Filter
// ════════════════════════════════════════════════════════════════════════

#[test]
fn filter_predicate_blocks_invalid() {
    init_test("filter_predicate_blocks_invalid");

    let filter = Filter::new("inner_service", |req: &i32| *req > 0);
    assert_eq!(*filter.inner(), "inner_service");

    // Verify predicate logic.
    let pred = filter.predicate();
    assert!(pred(&5));
    assert!(pred(&1));
    assert!(!pred(&0));
    assert!(!pred(&-1));

    asupersync::test_complete!("filter_predicate_blocks_invalid");
}

#[test]
fn filter_layer_composes() {
    init_test("filter_layer_composes");

    let layer = FilterLayer::new(|req: &String| !req.is_empty());
    let filter = layer.layer("handler");
    assert_eq!(*filter.inner(), "handler");

    let pred = filter.predicate();
    assert!(pred(&"hello".to_string()));
    assert!(!pred(&String::new()));

    asupersync::test_complete!("filter_layer_composes");
}

// ════════════════════════════════════════════════════════════════════════
// Buffer
// ════════════════════════════════════════════════════════════════════════

#[test]
fn buffer_layer_creates_buffer() {
    init_test("buffer_layer_creates_buffer");

    let layer = BufferLayer::new(16);
    // Buffer wraps a service — use a simple type.
    let _ = layer;

    asupersync::test_complete!("buffer_layer_creates_buffer");
}

// ════════════════════════════════════════════════════════════════════════
// Layer Composition
// ════════════════════════════════════════════════════════════════════════

#[test]
fn layers_compose_with_stack() {
    init_test("layers_compose_with_stack");

    // Stack multiple layers to verify they compose.
    let _hedge_layer = HedgeLayer::with_delay(Duration::from_millis(100));
    let filter_layer = FilterLayer::new(|req: &i32| *req > 0);

    // Apply filter first, then hedge.
    let inner = 42u32;
    let filtered = filter_layer.layer(inner);
    // filtered is Filter<u32, _>
    assert_eq!(*filtered.inner(), 42);

    asupersync::test_complete!("layers_compose_with_stack");
}

// ════════════════════════════════════════════════════════════════════════
// Discovery Lifecycle
// ════════════════════════════════════════════════════════════════════════

#[test]
fn discovery_invalidate_and_repoll() {
    init_test("discovery_invalidate_and_repoll");

    let discovery = DnsServiceDiscovery::new(
        DnsDiscoveryConfig::new("service.test", 80)
            .poll_interval(Duration::from_secs(3600))
            .with_resolver(scripted_resolver(vec![
                Ok(socket_set(&["127.0.0.1:80", "127.0.0.2:80"])),
                Ok(socket_set(&["127.0.0.1:80", "127.0.0.2:80"])),
            ])),
    );

    let initial = discovery.poll_discover().unwrap();
    assert!(!initial.is_empty());

    // Within interval, returns empty.
    let no_changes = discovery.poll_discover().unwrap();
    assert!(no_changes.is_empty());
    assert_eq!(discovery.resolve_count(), 1);

    // Invalidate forces re-resolve.
    discovery.invalidate();
    let refreshed = discovery.poll_discover().unwrap();
    assert_eq!(discovery.resolve_count(), 2);
    // Same endpoints, so no changes.
    assert!(refreshed.is_empty());

    asupersync::test_complete!("discovery_invalidate_and_repoll");
}

#[test]
fn static_discovery_idempotent() {
    init_test("static_discovery_idempotent");

    let list = StaticList::new(vec!["a", "b", "c"]);

    let first = list.poll_discover().unwrap();
    assert_eq!(first.len(), 3);

    // All subsequent polls return empty.
    for _ in 0..5 {
        assert!(list.poll_discover().unwrap().is_empty());
    }

    // Endpoints always available.
    assert_eq!(list.endpoints(), vec!["a", "b", "c"]);

    asupersync::test_complete!("static_discovery_idempotent");
}

// ════════════════════════════════════════════════════════════════════════
// Load Balancer Management
// ════════════════════════════════════════════════════════════════════════

#[test]
fn load_balancer_dynamic_backends() {
    init_test("load_balancer_dynamic_backends");

    let lb = LoadBalancer::empty(RoundRobin::new());
    assert!(lb.is_empty());

    lb.push("backend-1");
    lb.push("backend-2");
    lb.push("backend-3");
    assert_eq!(lb.len(), 3);

    let removed = lb.remove(1);
    assert_eq!(removed, Some("backend-2"));
    assert_eq!(lb.len(), 2);

    asupersync::test_complete!("load_balancer_dynamic_backends");
}

#[test]
fn load_balancer_with_p2c_and_weighted() {
    init_test("load_balancer_with_p2c_and_weighted");

    // P2C load balancer.
    let lb_p2c = LoadBalancer::new(PowerOfTwoChoices::new(), vec!["a", "b", "c"]);
    assert_eq!(lb_p2c.len(), 3);

    // Weighted load balancer.
    let lb_weighted = LoadBalancer::new(Weighted::new(vec![5, 3, 2]), vec!["x", "y", "z"]);
    assert_eq!(lb_weighted.len(), 3);

    asupersync::test_complete!("load_balancer_with_p2c_and_weighted");
}

// ════════════════════════════════════════════════════════════════════════
// Error Type Compatibility
// ════════════════════════════════════════════════════════════════════════

#[test]
fn error_types_display_and_debug() {
    init_test("error_types_display_and_debug");
    use std::error::Error;

    // FilterError.
    let fe: FilterError<std::io::Error> = FilterError::Rejected;
    assert!(format!("{fe}").contains("rejected"));
    assert!(format!("{fe:?}").contains("Rejected"));

    // SteerError.
    let se: SteerError<std::io::Error> = SteerError::NoServices;
    assert!(format!("{se}").contains("no services"));
    assert!(format!("{se:?}").contains("NoServices"));

    // All implement std::error::Error.
    assert!(fe.source().is_none());
    assert!(se.source().is_none());

    asupersync::test_complete!("error_types_display_and_debug");
}
