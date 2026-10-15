//! Runnable Lifeguard proof: a locally-degraded node does not falsely accuse
//! healthy peers (bead `asupersync-dist-otp-completeness-8y37kz.4.2`, AC4).
//!
//! One node is given large extra latency on every message to/from it (induced
//! local slowness via chaos). Without Lifeguard, its probe acks would arrive
//! after the protocol period and it would wrongly accuse healthy peers. The
//! local-health multiplier stretches the degraded node's own timeouts, so it
//! must never *confirm a healthy peer dead*, and healthy peers must not collapse
//! either.
//!
//! Run with: `cargo test --test swim_lifeguard_chaos_proof --features test-internals`.

use asupersync::distributed::membership::{ClusterConfig, MemberState, SwimConfig, VirtualCluster};
use asupersync::remote::NodeId;

fn ids(n: usize) -> Vec<NodeId> {
    (0..n).map(|i| NodeId::new(format!("n{i}"))).collect()
}

#[test]
fn degraded_local_node_does_not_falsely_accuse_peers() {
    let nodes = ids(4);
    let mut cluster =
        VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 7);
    cluster.advance(2_000); // settle while everyone is healthy

    // Induce local slowness on n0: every message to/from it takes base + 1500ms,
    // which exceeds the 1000ms protocol period — a false-accusation trap that
    // Lifeguard's local-health timeout stretching must defuse.
    cluster.set_slow_node(&nodes[0], 1_500);
    cluster.advance(60_000);

    // The degraded node must not have confirmed any healthy peer dead.
    for peer in &nodes[1..] {
        let view = cluster.view(&nodes[0], peer);
        assert_ne!(
            view,
            Some(MemberState::Dead),
            "degraded node falsely confirmed {peer} dead"
        );
        assert_ne!(view, Some(MemberState::Left));
    }

    // Healthy peers must not falsely confirm one another dead either.
    for a in &nodes[1..] {
        for b in &nodes[1..] {
            if a != b {
                assert_ne!(
                    cluster.view(a, b),
                    Some(MemberState::Dead),
                    "healthy node {a} falsely confirmed healthy {b} dead"
                );
            }
        }
    }
}
