//! Actual runtime-owned SWIM loops; no virtual transport or forged liveness.
//! Related: asupersync-gap-snapshot-transport-swim-pbft-e6drlx.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::distributed::membership::driver::{
    SwimDriverConfig, SwimDriverStatus, SwimObservation, SwimObserver, UdpSwimDriver,
};
use asupersync::distributed::membership::{MembershipKind, SwimConfig, UdpMembershipTransport};
use asupersync::net::UdpSocket;
use asupersync::remote::NodeId;
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::Notify;
use asupersync::types::CancelReason;
use asupersync::types::CancelKind;
use asupersync::{Cx, Outcome};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn socket() -> (UdpMembershipTransport, SocketAddr) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket.set_nonblocking(true).unwrap();
    (UdpMembershipTransport::new(UdpSocket::from_std(socket).unwrap()), address)
}
fn driver(local: &str, peer: &str, address: SocketAddr, transport: UdpMembershipTransport) -> UdpSwimDriver {
    UdpSwimDriver::new_trusted_network(
        NodeId::new(local),
        SwimConfig {
            probe_interval_ms: 500, probe_timeout_ms: 200, awareness_max: 1,
            suspicion_mult: 2, suspicion_max_timeout_mult: 1,
            max_members: 4, ..SwimConfig::default()
        },
        0x5357_494d,
        BTreeMap::from([(NodeId::new(peer), address)]),
        transport,
        SwimDriverConfig {
            max_peers: 4, max_queued_datagrams: 16, retained_events: 16,
            io_batch: 8, tick_ms: 10, max_datagram_age_ms: 200, leave_timeout_ms: 300,
        },
    ).unwrap()
}
async fn observed(cx: &Cx, observer: &SwimObserver, predicate: impl Fn(&SwimObservation) -> bool) -> SwimObservation {
    asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
        loop {
            let snapshot = observer.snapshot();
            if predicate(&snapshot) { return snapshot; }
            assert!(!snapshot.status.is_terminal(), "driver stopped before observation: {snapshot:?}");
            observer.changed(snapshot.revision).await;
        }
    }).await.expect("bounded real SWIM progress")
}
fn exercise(workers: usize, abrupt: bool) {
    let (a_socket, a_address) = socket();
    let (b_socket, b_address) = socket();
    let a = driver("a", "b", b_address, a_socket);
    let b = driver("b", "a", a_address, b_socket);
    let a_view = a.observer();
    let b_view = b.observer();
    let stop_a = Arc::new(Notify::new());
    let stop_b = Arc::new(Notify::new());
    let pending_b = Arc::new(AtomicUsize::new(0));
    let parked_b = Arc::new(Notify::new());
    let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
    runtime.block_on(async {
        let cx = Cx::current().expect("native owner context");
        let stop = Arc::clone(&stop_a);
        let mut a_task = cx.spawn(move |child| async move {
            a.run_until(&child, stop.notified()).await
        }).unwrap();
        let stop = Arc::clone(&stop_b);
        let pending = Arc::clone(&pending_b);
        let parked = Arc::clone(&parked_b);
        let mut b_task = cx.spawn(move |child| async move {
            let mut running = Box::pin(b.run_until(&child, stop.notified()));
            poll_fn(|task| {
                let result = running.as_mut().poll(task);
                if result.is_pending() {
                    pending.fetch_add(1, Ordering::Release);
                    parked.notify_waiters();
                }
                result
            }).await
        }).unwrap();
        // Seeding alone already says Alive: require actual received ACKs and
        // successful sends before claiming native protocol exchange happened.
        observed(&cx, &a_view, |s| s.stats.received_acks >= 2 && s.stats.sent_datagrams >= 2).await;
        observed(&cx, &b_view, |s| s.stats.received_acks >= 2 && s.stats.sent_datagrams >= 2).await;
        assert_eq!(a_view.snapshot().membership.kind_of(&NodeId::new("b")), Some(MembershipKind::Alive));
        if abrupt {
            let before = pending_b.load(Ordering::Acquire);
            asupersync::time::timeout(cx.now(), Duration::from_secs(3),
                parked_b.wait_until(|| pending_b.load(Ordering::Acquire) > before),
            ).await.expect("actual driver Pending before abort");
            b_task.abort_with_reason(CancelReason::user("native SWIM parked cancellation"));
            let report = asupersync::time::timeout(cx.now(), Duration::from_secs(3), b_task.join(&cx)).await
                .expect("parked driver wakes on cancellation")
                .expect("acknowledged cancellation preserves the typed driver result");
            assert!(matches!(&report.outcome, Outcome::Cancelled(reason) if reason.is_kind(CancelKind::User)));
            assert_eq!(report.observation.status, SwimDriverStatus::Cancelled);
            let dead = observed(&cx, &a_view, |s| s.membership.kind_of(&NodeId::new("b")) == Some(MembershipKind::Dead)).await;
            let events = dead.membership.events_since(0);
            let suspect = events.iter().position(|e| e.node == NodeId::new("b") && e.kind == MembershipKind::Suspect).unwrap();
            let dead = events.iter().position(|e| e.node == NodeId::new("b") && e.kind == MembershipKind::Dead).unwrap();
            assert!(suspect < dead, "actual timeout sequence, not an injected Dead rumor");
            assert!(!events.iter().any(|e| e.node == NodeId::new("b") && e.kind == MembershipKind::Left));
        } else {
            stop_b.notify_one();
            let report = asupersync::time::timeout(cx.now(), Duration::from_secs(3), b_task.join(&cx)).await.unwrap().unwrap();
            assert!(matches!(&report.outcome, Outcome::Ok(())), "{report:?}");
            assert_eq!(report.observation.status, SwimDriverStatus::Left);
            observed(&cx, &a_view, |s| s.membership.kind_of(&NodeId::new("b")) == Some(MembershipKind::Left)).await;
        }
        stop_a.notify_one();
        let report = asupersync::time::timeout(cx.now(), Duration::from_secs(3), a_task.join(&cx)).await.unwrap().unwrap();
        assert!(matches!(&report.outcome, Outcome::Ok(())), "{report:?}");
        assert_eq!(report.observation.stats.queued_datagrams, 0);
        assert!(report.observation.stats.queue_high_water <= 16);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    // Observer clones survive but must not retain either native socket.
    assert!(std::net::UdpSocket::bind(a_address).is_ok());
    assert!(std::net::UdpSocket::bind(b_address).is_ok());
}

#[test]
fn current_thread_real_probe_ack_and_graceful_leave() { exercise(1, false); }

#[test]
fn two_workers_real_probe_ack_and_graceful_leave() { exercise(2, false); }

#[test]
fn two_workers_parked_cancel_then_suspicion_and_failure_detection() { exercise(2, true); }
