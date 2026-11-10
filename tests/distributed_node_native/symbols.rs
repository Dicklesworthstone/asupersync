//! Real TCP symbol work under the node's checked membership and region lifetime.

use super::*;
use asupersync::distributed::{
    NativeDistributedSymbolConfig, NativeDistributedSymbolError, NativeDistributedSymbolRoute,
};
use asupersync::distributed::symbol_service::{RemoteSymbolError, SymbolBatchKey};
use asupersync::io::AsyncReadExt;
use asupersync::net::TcpListener;
use asupersync::runtime::TaskHandle;
use asupersync::security::AuthenticatedSymbol;
use std::pin::Pin;

fn config() -> NativeDistributedSymbolConfig {
    NativeDistributedSymbolConfig {
        max_routes: 1, max_in_flight: 1,
        work: RemoteRunConfig { timeout: WINDOW, child: ChildRegionSpec::inherit() },
        max_chunk_bytes: None,
    }
}

fn route(client: RemoteComputationClient) -> NativeDistributedSymbolRoute {
    NativeDistributedSymbolRoute {
        replica_id: "replica-a".into(), node: NodeId::new("worker"), incarnation: 1, client,
    }
}

fn symbols() -> Vec<AuthenticatedSymbol> {
    let security = SecurityContext::new(AuthKey::from_seed(42));
    (0..3).map(|esi| {
        security.sign_symbol(&Symbol::new_for_test(71, 0, esi, b"node-owned snapshot symbols"))
    }).collect()
}

fn batch_key() -> SymbolBatchKey { encode_symbol_batch(&symbols(), batch_limits()).unwrap().key() }

#[test]
fn node_symbol_store_and_verified_fetch_use_real_v1_tls_and_release_owners() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, store, .. } = fixture(&cx).await;
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let node = NativeDistributedNode::start(
                &cx, service, membership.clone(), None, ChildRegionSpec::inherit(),
            ).await.unwrap();
            let transport = node.symbol_transport(
                hello, [route(client)], Arc::new(AuthKey::from_seed(42)), batch_limits(), config(),
            ).unwrap();
            let sent = symbols();
            let receipt = assert_send(transport.store_symbols("replica-a", sent.clone())).await.unwrap();
            assert!(receipt.is_success(), "{receipt:?}");
            let work = receipt.work.unwrap().unwrap();
            assert_eq!(work.task.unwrap().unwrap().symbols_received, 3);
            assert!(matches!(work.lease, Ok(OwnedLeaseStatus::Released)));
            assert_ne!(work.close.unwrap().region_id, node.region_id());
            assert_eq!(transport.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);

            // The existing distributor trait composes with this adapter and an
            // identical V1 write remains idempotent at the store's peer limit.
            let ack = transport.clone().send_symbols("replica-a", sent.clone()).await.unwrap();
            assert_eq!(ack.symbols_received, u32::try_from(sent.len()).unwrap());
            let fetched = assert_send(transport.fetch_symbols("replica-a", batch_key())).await.unwrap();
            assert!(fetched.is_success(), "{fetched:?}");
            let fetched = fetched.work.unwrap().unwrap().task.unwrap().unwrap();
            for (actual, expected) in fetched.iter().zip(&sent) {
                assert!(actual.is_verified());
                assert_eq!(actual.symbol(), expected.symbol());
                assert_eq!(actual.tag(), expected.tag());
            }
            assert_eq!(fetched.len(), sent.len());
            assert_eq!(store.stats().batches, 1);
            assert_eq!(transport.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);
            let report = node.close().await;
            assert!(matches!(report.region_close, Some(Ok(()))), "{report:?}");
            assert!(transport.is_closed());
            assert!(matches!(transport.fetch_symbols("replica-a", batch_key()).await,
                Err(NativeDistributedSymbolError::Closed)));
            assert!(!cx.is_cancel_requested());
        });
        finish(runtime);
    }
}

#[test]
fn node_symbol_routes_fail_closed_for_protocol_membership_bounds_and_peer_identity() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, membership, client, hello, store, .. } = fixture(&cx).await;
        membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
        let node = NativeDistributedNode::start(
            &cx, service, membership.clone(), None, ChildRegionSpec::inherit(),
        ).await.unwrap();
        let key = Arc::new(AuthKey::from_seed(42));
        let v3 = RemotePeerHello::new(hello.peer_node().clone(), RemoteProtocolVersion::V3, hello.registry_fingerprint());
        assert!(matches!(node.symbol_transport(v3, [route(client.clone())], key.clone(), batch_limits(), config()),
            Err(NativeDistributedSymbolError::Symbol(RemoteSymbolError::Configuration))));
        let mut stale = route(client.clone());
        stale.incarnation = 2;
        assert!(matches!(node.symbol_transport(hello.clone(), [stale], key.clone(), batch_limits(), config()),
            Err(NativeDistributedSymbolError::Membership)));
        let mut wrong = route(client.clone());
        wrong.node = NodeId::new("unprovisioned");
        assert!(matches!(node.symbol_transport(hello.clone(), [wrong], key.clone(), batch_limits(), config()),
            Err(NativeDistributedSymbolError::Membership)));
        assert!(matches!(node.symbol_transport(hello.clone(), [route(client.clone()), route(client.clone())],
            key.clone(), batch_limits(), config()), Err(NativeDistributedSymbolError::Configuration)));

        let mut denied = config();
        denied.max_in_flight = 0;
        let denied = node.symbol_transport(hello.clone(), [route(client.clone())], key.clone(), batch_limits(), denied).unwrap();
        assert!(matches!(denied.store_symbols("replica-a", symbols()).await, Err(NativeDistributedSymbolError::Capacity)));
        assert_eq!(denied.retained_operations(), 0);
        let transport = node.symbol_transport(hello.clone(), [route(client.clone())], key.clone(), batch_limits(), config()).unwrap();
        let too_many = (0..33).map(|_| symbols().pop().unwrap()).collect();
        assert!(matches!(transport.store_symbols("replica-a", too_many).await,
            Err(NativeDistributedSymbolError::Configuration)));
        assert_eq!(transport.retained_operations(), 0);
        assert_eq!(membership.live_leases(), 0);

        // A real mTLS connection with an ungranted asserted origin cannot write
        // through a correctly pinned route or manufacture a storage receipt.
        let impostor = RemotePeerHello::new(NodeId::new("impostor"), RemoteProtocolVersion::V1, hello.registry_fingerprint());
        let impostor = node.symbol_transport(impostor, [route(client)], key, batch_limits(), config()).unwrap();
        let refused = impostor.store_symbols("replica-a", symbols()).await.unwrap();
        assert!(!refused.is_success(), "{refused:?}");
        assert!(matches!(refused.work, Some(Ok(work)) if matches!(work.task, Ok(Err(_)))));
        assert_eq!(store.stats().batches, 0);
        assert_eq!(membership.live_leases(), 0);
        assert!(matches!(node.close().await.region_close, Some(Ok(()))));
    });
    finish(runtime);
}

struct StalledPeer {
    client: RemoteComputationClient,
    entered: Arc<AtomicBool>,
    changed: Arc<Notify>,
    task: TaskHandle<()>,
}

impl StalledPeer {
    async fn new(cx: &Cx, client: &RemoteComputationClient) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = client.with_bootstrap_endpoints([listener.local_addr().unwrap()]).unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let changed = Arc::new(Notify::new());
        let witnessed = Arc::clone(&entered);
        let notify = Arc::clone(&changed);
        let task = cx.spawn(move |body| async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = [0_u8; 6];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x16, "TLS handshake record");
            assert_eq!(header[5], 0x01, "ClientHello handshake");
            // This witnesses a real TLS ClientHello at the actual TCP peer.
            // Withhold the server response so the client must await native I/O.
            witnessed.store(true, Ordering::Release);
            notify.notify_waiters();
            body.cancelled().await;
            let _ = body.checkpoint();
            drop(socket);
        }).unwrap();
        Self { client, entered, changed, task }
    }

    async fn wait<F: Future>(&self, cx: &Cx, operation: &mut Pin<Box<F>>) {
        let mut witness = std::pin::pin!(self.changed.wait_until(|| self.entered.load(Ordering::Acquire)));
        asupersync::time::timeout(cx.now(), WINDOW, poll_fn(|task| {
            assert!(operation.as_mut().poll(task).is_pending(), "symbol call must await native TLS response");
            witness.as_mut().poll(task)
        })).await.expect("real TLS ingress witness");
    }

    async fn close(mut self, cx: &Cx) {
        self.task.abort();
        assert_retired(asupersync::time::timeout(cx.now(), WINDOW, self.task.join(cx)).await.unwrap());
    }
}

#[test]
fn node_symbol_native_waits_share_capacity_and_drain_on_revocation_drop_and_close() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, .. } = fixture(&cx).await;
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let node = NativeDistributedNode::start(
                &cx, service, membership.clone(), None, ChildRegionSpec::inherit(),
            ).await.unwrap();
            let stalled = StalledPeer::new(&cx, &client).await;
            let transport = node.symbol_transport(hello.clone(), [route(stalled.client.clone())],
                Arc::new(AuthKey::from_seed(42)), batch_limits(), config()).unwrap();
            let clone = transport.clone();
            let mut operation = Box::pin(transport.fetch_symbols("replica-a", batch_key()));
            stalled.wait(&cx, &mut operation).await;
            assert_eq!(transport.retained_operations(), 1);
            assert_eq!(membership.live_leases(), 1);
            assert!(matches!(clone.fetch_symbols("replica-a", batch_key()).await,
                Err(NativeDistributedSymbolError::Capacity)));
            membership.apply_authenticated(&NodeId::new("authority"),
                &member_statement(1, 2, MembershipKind::Dead)).unwrap();
            let revoked = asupersync::time::timeout(cx.now(), WINDOW, operation).await.unwrap().unwrap();
            assert!(!revoked.is_success(), "{revoked:?}");
            assert!(matches!(revoked.work, Some(Ok(work)) if matches!(work.trigger,
                MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Revoked))));
            assert_eq!(membership.live_leases(), 0);
            assert_eq!(clone.retained_operations(), 0);
            stalled.close(&cx).await;

            // A newer Alive incarnation requires explicit rebinding; the old
            // transport cannot silently resume after revocation or rejoin.
            membership.apply_authenticated(&NodeId::new("authority"),
                &member_statement(2, 3, MembershipKind::Alive)).unwrap();
            assert!(matches!(clone.fetch_symbols("replica-a", batch_key()).await,
                Err(NativeDistributedSymbolError::Membership)));
            let stalled = StalledPeer::new(&cx, &client).await;
            let mut rebound = route(stalled.client.clone());
            rebound.incarnation = 2;
            let transport = node.symbol_transport(hello.clone(), [rebound], Arc::new(AuthKey::from_seed(42)),
                batch_limits(), config()).unwrap();
            let mut operation = Box::pin(transport.fetch_symbols("replica-a", batch_key()));
            stalled.wait(&cx, &mut operation).await;
            assert_eq!(transport.retained_operations(), 1);
            drop(operation);
            eventually(&cx, || transport.retained_operations() == 0 && membership.live_leases() == 0).await;
            stalled.close(&cx).await;

            // A fresh explicit binding can do healthy work after revocation
            // and caller drop, with no cancellation of the surrounding owner.
            let mut rebound = route(client.clone());
            rebound.incarnation = 2;
            let healthy = node.symbol_transport(hello.clone(), [rebound],
                Arc::new(AuthKey::from_seed(42)), batch_limits(), config()).unwrap();
            let stored = healthy.store_symbols("replica-a", symbols()).await.unwrap();
            assert!(stored.is_success(), "{stored:?}");
            let fetched = healthy.fetch_symbols("replica-a", batch_key()).await.unwrap();
            assert!(fetched.is_success(), "{fetched:?}");
            let fetched = fetched.work.unwrap().unwrap().task.unwrap().unwrap();
            assert_eq!(fetched.len(), 3);
            assert_eq!(fetched[0].symbol().data(), b"node-owned snapshot symbols");
            assert!(fetched.iter().all(AuthenticatedSymbol::is_verified));
            assert_eq!(healthy.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);

            let stalled = StalledPeer::new(&cx, &client).await;
            let mut rebound = route(stalled.client.clone());
            rebound.incarnation = 2;
            let transport = node.symbol_transport(hello, [rebound], Arc::new(AuthKey::from_seed(42)),
                batch_limits(), config()).unwrap();
            let mut operation = Box::pin(transport.fetch_symbols("replica-a", batch_key()));
            stalled.wait(&cx, &mut operation).await;
            let report = asupersync::time::timeout(cx.now(), WINDOW, assert_send(node.close())).await.unwrap();
            assert!(matches!(report.region_close, Some(Ok(()))), "{report:?}");
            assert!(transport.is_closed());
            assert_eq!(membership.live_leases(), 0);
            // Actual node close retired the task, but its unread report still
            // occupies the bounded public slot until the caller observes it.
            assert_eq!(transport.retained_operations(), 1);
            let closed = operation.await.unwrap();
            assert!(!closed.is_success(), "{closed:?}");
            assert_eq!(transport.retained_operations(), 0);
            assert!(matches!(transport.fetch_symbols("replica-a", batch_key()).await,
                Err(NativeDistributedSymbolError::Closed)));
            stalled.close(&cx).await;
            assert!(!cx.is_cancel_requested());
        });
        finish(runtime);
    }
}
