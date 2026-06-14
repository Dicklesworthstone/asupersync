//! Runnable proof of the suspicion → obligation-revocation mapping (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.3`, AC1 + the design note).
//!
//! Drives a real SWIM through a node's `Alive -> Suspect -> Dead` lifecycle,
//! feeds its events into the watchable `MembershipView`, and asserts the
//! `MembershipLeaseReactor` produces the documented lease actions: suspicion
//! pauses new grants, confirmed death revokes (the action the lease manager
//! enacts through the obligation protocol). The remote.rs enactment + saga
//! compensation showcase (AC2) layers on top of these decisions.
//!
//! Run with: `cargo test --test swim_lease_reactor_proof --features test-internals`.

use asupersync::distributed::membership::{
    LeaseAction, MembershipLeaseReactor, MembershipView, Packet, Payload, Rumor, Swim, SwimConfig,
};
use asupersync::remote::NodeId;

fn node(s: &str) -> NodeId {
    NodeId::new(s)
}

#[test]
fn suspicion_pauses_grants_then_death_revokes() {
    let mut swim = Swim::new(node("self"), SwimConfig::default(), 5);
    swim.add_peer(0, node("a"));

    let mut view = MembershipView::new();
    let mut reactor = MembershipLeaseReactor::new();
    view.apply_all(swim.drain_events()); // bootstrap: a Alive
    assert!(reactor.poll(&view).is_empty());
    assert!(!reactor.is_paused(&node("a")));

    // Suspect "a" via gossip -> the reactor pauses new grants to it.
    let _ = swim.handle(
        0,
        node("acc"),
        Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![Rumor::suspect(node("a"), 0, node("acc"))],
        },
    );
    view.apply_all(swim.drain_events());
    let actions = reactor.poll(&view);
    assert!(
        actions
            .iter()
            .any(|(n, a)| *n == node("a") && *a == LeaseAction::PauseGrants),
        "suspicion did not pause grants: {actions:?}"
    );
    assert!(reactor.is_paused(&node("a")));
    assert!(!reactor.is_revoked(&node("a")));

    // Let the suspicion time out to Dead -> the reactor revokes (the obligation
    // path the lease manager enacts).
    let _ = swim.tick(30_000);
    view.apply_all(swim.drain_events());
    let actions = reactor.poll(&view);
    assert!(
        actions
            .iter()
            .any(|(n, a)| *n == node("a") && *a == LeaseAction::Revoke),
        "death did not revoke: {actions:?}"
    );
    assert!(reactor.is_revoked(&node("a")));
    assert!(!reactor.is_paused(&node("a")));
}
