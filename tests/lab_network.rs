//! Deterministic network simulation integration tests.

use asupersync::bytes::Bytes;
use asupersync::lab::{NetworkConditions, NetworkConfig, SimulatedNetwork};
use std::time::Duration;

#[test]
fn network_respects_latency_bounds() {
    let mut net = SimulatedNetwork::new(NetworkConfig {
        default_conditions: NetworkConditions::lan(),
        ..Default::default()
    });

    let a = net.add_host("a");
    let b = net.add_host("b");

    net.send(a, b, Bytes::copy_from_slice(b"ping"));
    net.run_for(Duration::from_millis(10));

    let inbox = net.inbox(b).expect("host inbox");
    assert_eq!(inbox.len(), 1);
    let packet = &inbox[0];
    let latency_ms = packet.received_at.duration_since(packet.sent_at) / 1_000_000;
    assert!((1..=5).contains(&latency_ms));
}

#[test]
fn network_is_deterministic_with_same_seed() {
    let config = NetworkConfig::default();
    let mut net1 = SimulatedNetwork::new(config.clone());
    let mut net2 = SimulatedNetwork::new(config);

    let a1 = net1.add_host("a");
    let b1 = net1.add_host("b");
    let a2 = net2.add_host("a");
    let b2 = net2.add_host("b");

    for _ in 0..20 {
        net1.send(a1, b1, Bytes::copy_from_slice(b"data"));
        net2.send(a2, b2, Bytes::copy_from_slice(b"data"));
    }

    net1.run_until_idle();
    net2.run_until_idle();

    let inbox1 = net1.inbox(b1).expect("inbox");
    let inbox2 = net2.inbox(b2).expect("inbox");
    assert_eq!(inbox1.len(), inbox2.len());
    for (p1, p2) in inbox1.iter().zip(inbox2.iter()) {
        assert_eq!(p1.received_at, p2.received_at);
    }
}
