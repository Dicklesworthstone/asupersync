//! Runnable proofs for the Lifeguard timing policy and the gossip dissemination
//! buffer of the SWIM membership subsystem (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.1`; parent `.4` AC4 mechanism).
//!
//! - Lifeguard: the local-health multiplier stretches a degraded node's
//!   timeouts (so it waits longer before accusing peers — the AC4 anti-false-
//!   accusation mechanism), and the suspicion window shrinks toward its floor as
//!   independent confirmations accumulate.
//! - Gossip: rumors are evicted after the per-rumor retransmit limit, and a
//!   fresher rumor supersedes a stale one for the same node.
//!
//! Run with: `cargo test --test membership_lifeguard_gossip_proof --features test-internals`.

use asupersync::distributed::membership::{
    Awareness, GossipBuffer, Rumor, max_suspicion_ms, min_suspicion_ms, node_scale,
    suspicion_timeout_ms,
};
use asupersync::remote::NodeId;

fn node(s: &str) -> NodeId {
    NodeId::new(s)
}

#[test]
fn awareness_stretches_timeouts_when_locally_degraded() {
    // AC4 mechanism: a healthy node multiplies timeouts by 1; a degraded node
    // multiplies them up, so it waits proportionally longer before accusing.
    let mut awareness = Awareness::new(8);
    assert_eq!(awareness.multiplier(), 1);
    assert_eq!(awareness.scale(500), 500);

    awareness.apply_delta(3);
    assert_eq!(awareness.score(), 3);
    assert_eq!(awareness.multiplier(), 4);
    assert_eq!(awareness.scale(500), 2000);

    // Recovery clamps back to perfect health.
    awareness.apply_delta(-10);
    assert_eq!(awareness.score(), 0);
    assert_eq!(awareness.scale(500), 500);
}

#[test]
fn suspicion_window_shrinks_with_independent_confirmations() {
    let n = 7;
    let min = min_suspicion_ms(4, n, 1000);
    let max = max_suspicion_ms(min, 6);
    assert!(min < max);

    // A lone accuser waits the full window; confirmations collapse it to the floor.
    assert_eq!(suspicion_timeout_ms(min, max, 0, 3), max);
    let one = suspicion_timeout_ms(min, max, 1, 3);
    let three = suspicion_timeout_ms(min, max, 3, 3);
    assert!(one < max);
    assert!(three <= one);
    assert_eq!(suspicion_timeout_ms(min, max, 3, 3), min);
    assert_eq!(suspicion_timeout_ms(min, max, 10, 3), min);
}

#[test]
fn node_scale_has_unit_floor() {
    assert!((node_scale(1) - 1.0).abs() < 1e-9);
    assert!((node_scale(10) - 1.0).abs() < 1e-9);
    assert!((node_scale(100) - 2.0).abs() < 1e-9);
}

#[test]
fn gossip_evicts_rumor_after_retransmit_limit() {
    let mut buffer = GossipBuffer::new(2);
    buffer.queue(Rumor::alive(node("a"), 1));
    assert_eq!(buffer.select(8).len(), 1); // transmit 1
    assert_eq!(buffer.select(8).len(), 1); // transmit 2 -> hits limit, evicted
    assert!(buffer.is_empty());
    assert!(buffer.select(8).is_empty());
}

#[test]
fn gossip_fresher_rumor_supersedes_and_resets() {
    let mut buffer = GossipBuffer::new(3);
    buffer.queue(Rumor::alive(node("a"), 1));
    let _ = buffer.select(8); // transmit the alive rumor once
    // A suspicion at the same incarnation supersedes the alive rumor.
    buffer.queue(Rumor::suspect(node("a"), 1, node("b")));
    assert_eq!(buffer.len(), 1);
    let out = buffer.select(8);
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0], Rumor::Suspect { .. }));
}

#[test]
fn gossip_drops_stale_rumor() {
    let mut buffer = GossipBuffer::new(3);
    buffer.queue(Rumor::suspect(node("a"), 5, node("b")));
    // An older alive (lower incarnation) must not overwrite the suspicion.
    buffer.queue(Rumor::alive(node("a"), 4));
    let out = buffer.select(8);
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0], Rumor::Suspect { .. }));
}
