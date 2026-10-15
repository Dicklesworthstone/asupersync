//! Runnable death → revoke → compensate showcase for membership-driven lease
//! revocation (bead `asupersync-dist-otp-completeness-8y37kz.4.3`, AC2 showcase).
//!
//! A node holds several leases, each backed by an obligation and a `Saga` whose
//! compensation undoes the remote work. When SWIM confirms the node dead, the
//! `MembershipLeaseManager` revokes its leases (surfacing the obligation ids to
//! abort), and the caller runs each revoked lease's saga compensation. This
//! demonstrates the full flow end to end: failure detection → lease revocation
//! → saga compensation, deterministically.
//!
//! Run with: `cargo test --test swim_lease_saga_compensation_proof --features test-internals`.

use asupersync::distributed::membership::{
    MembershipView, Packet, Payload, Rumor, Swim, SwimConfig,
};
use asupersync::remote::{Lease, MembershipLeaseManager, NodeId, Saga, SagaState};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn node(s: &str) -> NodeId {
    NodeId::new(s)
}

#[test]
fn death_revokes_leases_and_runs_saga_compensation() {
    let compensated = Arc::new(AtomicUsize::new(0));

    let mut swim = Swim::new(node("self"), SwimConfig::default(), 5);
    swim.add_peer(0, node("a"));
    let mut view = MembershipView::new();
    let mut manager = MembershipLeaseManager::new();
    view.apply_all(swim.drain_events());
    let _ = manager.sync(&view);

    // Grant three leases for "a", each backed by an obligation id and a saga
    // whose compensation increments the shared counter when run.
    let lease_count = 3u32;
    let mut sagas: Vec<(ObligationId, Saga)> = Vec::new();
    for i in 0..lease_count {
        let obligation = ObligationId::new_for_test(i, 0);
        let lease = Lease::new(
            obligation,
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            Duration::from_secs(30),
            Time::from_secs(0),
        );
        assert!(manager.try_grant(&node("a"), lease).is_ok());

        let mut saga = Saga::new();
        let counter = compensated.clone();
        saga.step(
            "acquire remote resource",
            || Ok(()),
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                "remote resource released".to_string()
            },
        )
        .expect("forward step succeeds");
        sagas.push((obligation, saga));
    }
    assert_eq!(manager.active_leases(&node("a")), lease_count as usize);

    // "a" is suspected, then dies.
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
    let _ = swim.tick(30_000);
    view.apply_all(swim.drain_events());
    let revoked = manager.sync(&view);
    assert_eq!(
        revoked.len(),
        lease_count as usize,
        "all leases revoked on death"
    );

    // death → revoke → compensate: each revoked lease's saga compensates.
    for r in &revoked {
        let idx = sagas
            .iter()
            .position(|(obligation, _)| *obligation == r.obligation_id)
            .expect("a saga exists for each revoked lease");
        sagas[idx].1.abort();
        assert_eq!(sagas[idx].1.state(), SagaState::Aborted);
        assert!(
            !sagas[idx].1.compensation_results().is_empty(),
            "compensation must have run"
        );
    }

    assert_eq!(
        compensated.load(Ordering::SeqCst),
        lease_count as usize,
        "every revoked lease's saga compensation ran exactly once"
    );
    assert!(manager.is_revoked(&node("a")));
}
