//! Runnable proof for bounded-load consistent hashing (bead
//! `asupersync-dist-otp-completeness-8y37kz.5`).
//!
//! The bounded-load core and its 5 ACs are implemented in
//! `src/distributed/consistent_hash.rs`; this supplies the focused, runnable
//! proof that the `--lib` test binary could not run reliably under fleet
//! saturation. It validates:
//!
//! - AC1: no bounded-load decision selects a node at/over the computed cap
//!   unless every node is full (the deterministic least-loaded fallback);
//! - AC4: a hot key that plain hashing would pin entirely to one node is spread
//!   across the ring, flattening peak load to well under a third of the
//!   unbounded peak;
//! - AC3: bounded assignment is deterministic for a fixed seed.
//!
//! Run with: `cargo test --test bounded_load_consistent_hash_proof --features test-internals`.

use asupersync::distributed::{BoundedLoadConfig, BoundedLoadFallback, HashRing};
use std::collections::HashMap;

fn ring5() -> HashRing {
    let mut ring = HashRing::new(64, 99);
    for node in ["n0", "n1", "n2", "n3", "n4"] {
        ring.add_node(node);
    }
    ring
}

#[test]
fn bounded_routing_respects_the_per_decision_cap() {
    // AC1: a hot key would pin all load to one node under plain hashing; the
    // bounded variant caps each node and walks the ring, so no decision selects
    // a node already at/over the cap unless every node is full.
    let ring = ring5();
    let mut loads: HashMap<String, u64> = HashMap::new();
    let cfg = BoundedLoadConfig::STRICT;

    for i in 0..100u64 {
        let total: u64 = loads.values().sum();
        let decision = ring
            .bounded_node_for_key(&"hot-key", total, cfg, |node| {
                *loads.get(node).unwrap_or(&0)
            })
            .expect("non-empty ring yields a decision");
        if decision.fallback != BoundedLoadFallback::LeastLoaded {
            assert!(
                decision.selected_load < decision.load_limit,
                "decision {i} selected a node at/over the cap without the least-loaded fallback \
                 (load={}, limit={})",
                decision.selected_load,
                decision.load_limit
            );
        }
        *loads.entry(decision.selected_node.to_string()).or_insert(0) += 1;
    }
}

#[test]
fn bounded_load_flattens_hot_key_skew() {
    // AC4: the same hot key, 100 times. Unbounded hashing pins all 100 to one
    // node; bounded load spreads them across the 5-node ring.
    let ring = ring5();
    let assignments = 100u64;

    // Unbounded: every lookup of the same key returns the same node.
    let unbounded_node = ring.node_for_key(&"hot-key").expect("a node").to_string();
    let mut unbounded_loads: HashMap<String, u64> = HashMap::new();
    *unbounded_loads.entry(unbounded_node).or_insert(0) += assignments;
    let unbounded_max = *unbounded_loads.values().max().unwrap();
    assert_eq!(unbounded_max, assignments);

    // Bounded: spreads across the ring.
    let mut loads: HashMap<String, u64> = HashMap::new();
    let cfg = BoundedLoadConfig::STRICT;
    for _ in 0..assignments {
        let total: u64 = loads.values().sum();
        let selected = ring
            .node_for_key_bounded_load(&"hot-key", total, cfg, |node| {
                *loads.get(node).unwrap_or(&0)
            })
            .expect("a node")
            .to_string();
        *loads.entry(selected).or_insert(0) += 1;
    }
    let bounded_max = *loads.values().max().unwrap();
    assert!(
        bounded_max * 3 < unbounded_max,
        "bounded peak {bounded_max} is not under a third of the unbounded peak {unbounded_max}"
    );
}

#[test]
fn bounded_assignment_is_deterministic() {
    // AC3: identical assignment sequence across same-seed runs.
    let run = || {
        let ring = ring5();
        let mut loads: HashMap<String, u64> = HashMap::new();
        let cfg = BoundedLoadConfig::STRICT;
        let mut sequence = Vec::new();
        for i in 0..50u64 {
            let total: u64 = loads.values().sum();
            let key = format!("key-{i}");
            let selected = ring
                .node_for_key_bounded_load(&key, total, cfg, |node| *loads.get(node).unwrap_or(&0))
                .expect("a node")
                .to_string();
            *loads.entry(selected.clone()).or_insert(0) += 1;
            sequence.push(selected);
        }
        sequence
    };
    assert_eq!(run(), run());
}
