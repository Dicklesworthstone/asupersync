//! Runnable proof: the watchable MembershipView aggregates real SWIM events into
//! a cursor-based event stream + peer process-group (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.2`, AC3) — the seam the .4.3 lease
//! manager subscribes to.
//!
//! Run with: `cargo test --test swim_membership_view_proof --features test-internals`.

use asupersync::distributed::membership::{
    MembershipKind, MembershipView, Packet, Payload, Rumor, Swim, SwimConfig,
};
use asupersync::remote::NodeId;

fn node(s: &str) -> NodeId {
    NodeId::new(s)
}

#[test]
fn view_reflects_swim_membership_transitions() {
    let mut swim = Swim::new(node("self"), SwimConfig::default(), 1);
    swim.add_peer(0, node("a"));
    swim.add_peer(0, node("b"));

    let mut view = MembershipView::new();
    view.apply_all(swim.drain_events()); // bootstrap joins
    assert_eq!(view.alive_peers(), vec![node("a"), node("b")]);

    let cursor = view.event_count();

    // Suspect "a" via gossip; the pure Swim emits a Suspect membership event.
    let _ = swim.handle(
        0,
        node("acc"),
        Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![Rumor::suspect(node("a"), 0, node("acc"))],
        },
    );
    view.apply_all(swim.drain_events());

    // The watchable stream delivers the new transition exactly once...
    let fresh = view.events_since(cursor);
    assert!(
        fresh
            .iter()
            .any(|e| e.node == node("a") && e.kind == MembershipKind::Suspect),
        "suspect transition not observed on the event stream"
    );
    // ...and the process-group reflects it: "a" is no longer an alive peer.
    assert_eq!(view.kind_of(&node("a")), Some(MembershipKind::Suspect));
    assert!(!view.alive_peers().contains(&node("a")));

    // A consumer that advances its cursor sees no duplicates.
    let advanced = view.event_count();
    assert!(view.events_since(advanced).is_empty());
}
