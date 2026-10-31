use super::*;
use asupersync::distributed::membership::driver::{
    SwimDriverConfig, SwimDriverReport, SwimDriverStatus, SwimObservation, SwimObserver, UdpSwimDriver,
};
use asupersync::distributed::membership::{SwimConfig, UdpMembershipTransport};
use asupersync::runtime::TaskHandle;
use std::net::SocketAddr;

pub struct Detectors {
    pub(super) observer: SwimObserver,
    stop_local: Arc<Notify>,
    stop_peer: Arc<Notify>,
    local: Option<TaskHandle<SwimDriverReport>>,
    peer: Option<TaskHandle<SwimDriverReport>>,
}

impl Drop for Detectors {
    fn drop(&mut self) {
        self.stop_local.notify_one();
        self.stop_peer.notify_one();
    }
}

fn socket() -> (UdpMembershipTransport, SocketAddr) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket.set_nonblocking(true).unwrap();
    (UdpMembershipTransport::new(asupersync::net::UdpSocket::from_std(socket).unwrap()), address)
}

fn detector(local: &str, peer: &str, address: SocketAddr, transport: UdpMembershipTransport) -> UdpSwimDriver {
    UdpSwimDriver::new_trusted_network(
        NodeId::new(local),
        SwimConfig {
            probe_interval_ms: 500, probe_timeout_ms: 200, awareness_max: 1,
            suspicion_mult: 2, suspicion_max_timeout_mult: 1, max_members: 4,
            ..SwimConfig::default()
        },
        0x5357_494d,
        std::collections::BTreeMap::from([(NodeId::new(peer), address)]),
        transport,
        SwimDriverConfig {
            max_peers: 4, max_queued_datagrams: 16, retained_events: 1,
            io_batch: 8, tick_ms: 10, max_datagram_age_ms: 200, leave_timeout_ms: 300,
        },
    ).unwrap()
}

async fn observed(cx: &Cx, observer: &SwimObserver, predicate: impl Fn(&SwimObservation) -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
        loop {
            let snapshot = observer.snapshot();
            if predicate(&snapshot) { return; }
            assert!(!snapshot.status.is_terminal(), "{snapshot:?}");
            observer.changed(snapshot.revision).await;
        }
    }).await.expect("actual bounded UDP observation");
}

impl Detectors {
    pub(super) async fn start(cx: &Cx) -> Self {
        let (local_socket, local_address) = socket();
        let (peer_socket, peer_address) = socket();
        let local_driver = detector("origin", "worker", peer_address, local_socket);
        let peer_driver = detector("worker", "origin", local_address, peer_socket);
        let observer = local_driver.observer();
        let peer_observer = peer_driver.observer();
        assert!(observer.live_contact(&NodeId::new("worker")).is_none(), "seed is not contact");
        let stop_local = Arc::new(Notify::new());
        let stop_peer = Arc::new(Notify::new());
        let stop = Arc::clone(&stop_local);
        let local = cx.spawn(move |cx| async move {
            local_driver.run_until(&cx, stop.notified()).await
        }).unwrap();
        let stop = Arc::clone(&stop_peer);
        let peer = cx.spawn(move |cx| async move {
            peer_driver.run_until(&cx, stop.notified()).await
        }).unwrap();
        let fixture = Self { observer, stop_local, stop_peer, local: Some(local), peer: Some(peer) };
        observed(cx, &fixture.observer, |s| s.stats.received_acks >= 2).await;
        observed(cx, &peer_observer, |s| s.stats.received_acks >= 2).await;
        assert!(fixture.observer.live_contact(&NodeId::new("worker")).is_some());
        fixture
    }

    pub(super) async fn withdraw(&mut self, cx: &Cx, stop_observer: bool) {
        let mut task = if stop_observer {
            self.stop_local.notify_one();
            self.local.take().unwrap()
        } else {
            self.stop_peer.notify_one();
            self.peer.take().unwrap()
        };
        let report = asupersync::time::timeout(cx.now(), Duration::from_secs(3), task.join(cx))
            .await.expect("UDP detector stopped").unwrap();
        assert!(matches!(report.outcome, Outcome::Ok(())));
        if stop_observer {
            assert_eq!(self.observer.snapshot().status, SwimDriverStatus::Left);
        } else {
            observed(cx, &self.observer, |s| {
                s.membership.kind_of(&NodeId::new("worker")) == Some(MembershipKind::Left)
            }).await;
            assert!(self.observer.snapshot().membership.compact_base() > 0);
        }
        assert!(self.observer.live_contact(&NodeId::new("worker")).is_none());
    }

    pub(super) async fn close(&mut self, cx: &Cx) {
        self.stop_local.notify_one();
        self.stop_peer.notify_one();
        for mut task in [self.local.take(), self.peer.take()].into_iter().flatten() {
            let report = asupersync::time::timeout(cx.now(), Duration::from_secs(3), task.join(cx))
                .await.expect("remaining UDP detector stopped").unwrap();
            assert!(matches!(report.outcome, Outcome::Ok(())));
        }
    }
}
