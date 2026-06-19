//! Runnable proof of membership-driven lease revocation in remote.rs (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.3`, AC2 integration).
//!
//! Drives a real SWIM through a node's `Alive -> Suspect -> Dead` lifecycle and
//! asserts the remote `MembershipLeaseManager`: grants leases while the node is
//! alive, pauses new grants once it is suspected (a refutation could still
//! rescue existing leases), and on confirmed death revokes the node's leases —
//! marking each expired and surfacing its obligation id as a `RevokedLease` for
//! the caller to abort through the obligation protocol (triggering saga
//! compensation).
//!
//! Run with: `cargo test --test swim_remote_lease_revocation_proof --features test-internals`.

use asupersync::distributed::membership::{
    MembershipView, Packet, Payload, Rumor, Swim, SwimConfig,
};
use asupersync::remote::{Lease, MembershipLeaseManager, NodeId};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use std::time::Duration;

fn node(s: &str) -> NodeId {
    NodeId::new(s)
}

fn lease(obligation: u32) -> Lease {
    Lease::new(
        ObligationId::new_for_test(obligation, 0),
        RegionId::new_for_test(1, 0),
        TaskId::new_for_test(1, 0),
        Duration::from_secs(30),
        Time::from_secs(0),
    )
}

#[test]
fn dead_node_leases_are_revoked_for_obligation_abort() {
    let mut swim = Swim::new(node("self"), SwimConfig::default(), 5);
    swim.add_peer(0, node("a"));

    let mut view = MembershipView::new();
    let mut manager = MembershipLeaseManager::new();
    view.apply_all(swim.drain_events());
    let _ = manager.sync(&view);

    // Grant two leases for node "a" while it is alive.
    assert!(manager.try_grant(&node("a"), lease(1)).is_ok());
    assert!(manager.try_grant(&node("a"), lease(2)).is_ok());
    assert_eq!(manager.active_leases(&node("a")), 2);

    // Suspect "a": new grants are paused (existing leases retained).
    let _ = swim.handle(
        0,
        node("acc"),
        Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![Rumor::suspect(node("a"), 0, node("acc"))],
        },
    );
    view.apply_all(swim.drain_events());
    let _ = manager.sync(&view);
    assert!(manager.is_paused(&node("a")));
    assert!(
        manager.try_grant(&node("a"), lease(3)).is_err(),
        "a new grant must be rejected while the node is suspected"
    );
    assert_eq!(manager.active_leases(&node("a")), 2);

    // Death: the node's leases are revoked for obligation abort.
    let _ = swim.tick(30_000);
    view.apply_all(swim.drain_events());
    let revoked = manager.sync(&view);
    assert_eq!(revoked.len(), 2, "both leases revoked on death");
    assert!(revoked.iter().all(|r| r.node == node("a")));
    let obligations: Vec<ObligationId> = revoked.iter().map(|r| r.obligation_id).collect();
    assert!(obligations.contains(&ObligationId::new_for_test(1, 0)));
    assert!(obligations.contains(&ObligationId::new_for_test(2, 0)));
    assert!(manager.is_revoked(&node("a")));
    assert_eq!(manager.active_leases(&node("a")), 0);
}
