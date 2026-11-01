//! Real native listener, membership and UDP ownership through the node API.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::cx::ChildRegionSpec;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::distributed::distribution::DistributorTransport;
use asupersync::distributed::membership::authority::{
    MembershipControllerLimits, MembershipFloor, MembershipUpdate,
};
use asupersync::distributed::membership::driver::{
    SwimDriverConfig, SwimDriverStatus, UdpSwimDriver,
};
use asupersync::distributed::membership::owned::{
    OwnedLeaseStatus, OwnedMembershipController, OwnedMembershipError,
};
use asupersync::distributed::membership::service::{
    MEMBERSHIP_SERVICE_COMPUTATION, register_owned_membership_service,
    submit_membership_update,
};
use asupersync::distributed::membership::{
    MembershipEvent, MembershipKind, SwimConfig, UdpMembershipTransport,
};
use asupersync::distributed::symbol_service::{
    RemoteSymbolTransport, SYMBOL_SERVICE_COMPUTATION, SymbolBatchLimits,
    SymbolReplicaStore, SymbolStoreLimits, encode_symbol_batch, register_symbol_service,
};
use asupersync::distributed::{
    HasSchema, NativeDistributedComponent, NativeDistributedNode,
    NativeDistributedNodeStartFailure, NativeDistributedNodeStopCause, SchemaDescriptor,
};
use asupersync::net::{TcpStream, UdpSocket};
use asupersync::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteComputationServiceHandle, RemoteInput,
    RemoteOutcome, RemotePeerAdmissionPolicy, RemotePeerHello, RemoteProtocolVersion,
    RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse,
    RemoteTaskId, SpawnRequest,
};
use asupersync::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder};
use asupersync::security::{AuthKey, SecurityContext};
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::types::symbol::Symbol;
use asupersync::{Cx, Outcome};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const WINDOW: Duration = Duration::from_secs(10);

struct EchoRequest;
struct EchoResponse;
impl HasSchema for EchoRequest {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("node-test-echo-input") }
}
impl HasSchema for EchoResponse {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("node-test-echo-output") }
}

fn batch_limits() -> SymbolBatchLimits {
    SymbolBatchLimits {
        max_encoded_bytes: 8192,
        max_symbols: 32,
        max_payload_bytes: 4096,
        max_decoded_bytes: 16384,
    }
}

fn statement(sequence: u64) -> Vec<u8> {
    MembershipUpdate {
        event: MembershipEvent {
            node: NodeId::new("worker"),
            incarnation: 1,
            kind: MembershipKind::Alive,
        },
        sequence,
    }
    .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42))
    .unwrap()
}

struct Fixture {
    service: RemoteComputationService,
    operator: RemoteComputationServiceHandle,
    membership: OwnedMembershipController,
    client: RemoteComputationClient,
    hello: RemotePeerHello,
    store: Arc<SymbolReplicaStore>,
}

async fn fixture(cx: &Cx) -> Fixture {
    let membership = OwnedMembershipController::new(
        NodeId::new("authority"),
        7,
        AuthKey::from_seed(42),
        vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 16 },
        cx.timer_driver().unwrap(),
    ).unwrap();
    let store = Arc::new(SymbolReplicaStore::new(
        "replica-a",
        AuthKey::from_seed(42),
        batch_limits(),
        SymbolStoreLimits {
            max_batches: 2,
            max_bytes: 16384,
            max_batches_per_peer: 1,
            max_bytes_per_peer: 8192,
        },
    ).unwrap());
    let mut registry = RemoteComputationRegistry::new();
    registry.register::<EchoRequest, EchoResponse, _, _>("echo", |_, invocation| async move {
        Ok(RemoteOutcome::Success(invocation.request().input.data().to_vec()))
    }).unwrap();
    register_owned_membership_service(&mut registry, membership.clone()).unwrap();
    register_symbol_service(&mut registry, Arc::clone(&store)).unwrap();

    let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(&cert).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
        .client_auth(ClientAuth::Required(roots)).build().unwrap();
    let pins = CertificatePinSet::new()
        .with_pin(CertificatePin::compute_spki_sha256(&cert).unwrap());
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&cert).identity(chain, key)
        .with_certificate_pins(pins.clone()).build().unwrap();
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V1, registry.schema_registry().clone(),
    );
    policy.grant_tls_peer(
        NodeId::new("authority"), pins,
        ["echo", MEMBERSHIP_SERVICE_COMPUTATION, SYMBOL_SERVICE_COMPUTATION],
    ).unwrap();
    let hello = policy.hello_for(NodeId::new("authority"));
    let service = RemoteComputationService::bind(
        "127.0.0.1:0", acceptor, policy, registry,
        RemoteComputationServiceConfig::new()
            .with_max_connections(Some(4)).with_drain_timeout(Duration::from_secs(3)),
    ).await.unwrap();
    let operator = service.handle();
    let client = RemoteComputationClient::new(
        service.local_addr().unwrap(), "localhost", connector,
        RemoteComputationClientConfig::new().with_max_attempts(1)
            .with_connect_timeout(Duration::from_secs(2))
            .with_attempt_timeout(Duration::from_secs(3)),
    ).unwrap();
    Fixture { service, operator, membership, client, hello, store }
}

fn singleton_swim(address: SocketAddr) -> UdpSwimDriver {
    // Distinct protocols legitimately share one numeric port.
    let socket = std::net::UdpSocket::bind(address).unwrap();
    socket.set_nonblocking(true).unwrap();
    UdpSwimDriver::new_trusted_network(
        NodeId::new("replica-a"), SwimConfig::default(), 42, BTreeMap::new(),
        UdpMembershipTransport::new(UdpSocket::from_std(socket).unwrap()),
        SwimDriverConfig {
            max_peers: 1,
            max_queued_datagrams: 4,
            retained_events: 4,
            io_batch: 2,
            tick_ms: 10,
            max_datagram_age_ms: 100,
            leave_timeout_ms: 100,
        },
    ).unwrap()
}

fn assert_send<T: Send>(value: T) -> T { value }

fn assert_retired(result: Result<(), JoinError>) {
    assert!(matches!(result, Ok(()) | Err(JoinError::Cancelled(_))), "{result:?}");
}

async fn eventually(cx: &Cx, predicate: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), WINDOW, async {
        while !predicate() {
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }).await.expect("native component progress");
}

fn finish(runtime: Runtime) {
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    let report = runtime.shutdown_drained(WINDOW);
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.live_regions, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
    assert_eq!(report.queued_finalizers, 0);
    assert!(!report.has_pending_obligation_posts);
}

#[test]
fn node_serves_named_symbols_and_membership_then_drains_after_caller_cancel() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, operator, membership, client, hello, store } = fixture(&cx).await;
            let address = service.local_addr().unwrap();
            let swim = singleton_swim(address);
            let node = assert_send(NativeDistributedNode::start(
                &cx, service, membership.clone(), Some(swim), ChildRegionSpec::inherit(),
            )).await.unwrap();
            assert_eq!(node.local_addr(), address);
            let region_id = node.region_id();
            let observer = node.swim_observer().unwrap();

            submit_membership_update(&cx, &client, &hello, &statement(1)).await.unwrap();
            let stamp = node.membership_stamp(&NodeId::new("worker")).unwrap();
            assert_eq!((stamp.incarnation, stamp.sequence, stamp.kind), (1, 1, MembershipKind::Alive));
            let task = RemoteTaskId::next();
            let request = SpawnRequest {
                remote_task_id: task,
                computation: ComputationName::new("echo"),
                input: RemoteInput::new(b"real node-owned computation".to_vec()),
                lease: Duration::from_secs(3),
                idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())),
                budget: None,
                origin_node: hello.peer_node().clone(),
                origin_region: cx.region_id(),
                origin_task: cx.task_id(),
            };
            let wire = RemoteServiceWireRequest::from_spawn_request(hello.clone(), &request).unwrap();
            assert!(matches!(client.call(&cx, &wire).await.unwrap(),
                RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Success(bytes), .. }
                    if bytes == b"real node-owned computation"));

            let transport = RemoteSymbolTransport::new_bounded(
                cx.clone(), hello, [("replica-a".to_owned(), client)],
                Arc::new(AuthKey::from_seed(42)), batch_limits(), 2,
            ).unwrap();
            let security = SecurityContext::new(AuthKey::from_seed(42));
            let symbols: Vec<_> = (0..3).map(|esi| {
                security.sign_symbol(&Symbol::new_for_test(17, 0, esi, b"owned replica bytes"))
            }).collect();
            let key = encode_symbol_batch(&symbols, batch_limits()).unwrap().key();
            let receipt = transport.send_symbols("replica-a", symbols.clone()).await.unwrap();
            assert_eq!(receipt.symbols_received, 3);
            let fetched = transport.fetch_symbols("replica-a", key).await.unwrap();
            assert_eq!(fetched.len(), symbols.len());
            for (actual, expected) in fetched.iter().zip(&symbols) {
                assert!(actual.is_verified());
                assert_eq!(actual.symbol(), expected.symbol());
                assert_eq!(actual.tag(), expected.tag());
            }
            assert_eq!(store.stats().batches, 1);
            drop(transport);

            // Expiry is driven by the node's actual membership task, not a
            // test-side call to expire() or an untracked compatibility lease.
            let owned = membership.clone();
            let mut expiry = cx.spawn(move |holder| async move {
                let lease = owned.try_grant(
                    &holder, &NodeId::new("worker"), 1, Duration::from_millis(50),
                ).unwrap();
                lease.ended().await
            }).unwrap();
            assert_eq!(asupersync::time::timeout(cx.now(), WINDOW, expiry.join(&cx)).await
                .expect("node expiry driver progress").unwrap(), OwnedLeaseStatus::Expired);

            let parked = Arc::new(AtomicBool::new(false));
            let witness = Arc::clone(&parked);
            let owned = membership.clone();
            let mut holder = cx.spawn(move |holder| async move {
                let lease = owned.try_grant(
                    &holder, &NodeId::new("worker"), 1, Duration::from_secs(30),
                ).unwrap();
                let status = {
                    let mut ended = std::pin::pin!(lease.ended());
                    poll_fn(|task| {
                        let next = ended.as_mut().poll(task);
                        if next.is_pending() { witness.store(true, Ordering::Release); }
                        next
                    }).await
                };
                let _ = holder.checkpoint();
                status
            }).unwrap();
            eventually(&cx, || parked.load(Ordering::Acquire)).await;
            assert_eq!(node.live_leases(), 1);
            eventually(&cx, || operator.active_connections() == 0).await;
            // An accepted client stuck before TLS must also retire through the
            // listener's own connection region when the node closes.
            let idle = TcpStream::connect(address).await.unwrap();
            eventually(&cx, || operator.active_connections() == 1).await;
            node.begin_close();
            cx.set_cancel_requested(true);
            assert!(cx.checkpoint().is_err());
            let report = assert_send(node.close()).await;
            assert_eq!(report.stop_cause, NativeDistributedNodeStopCause::Close);
            assert_eq!(report.region_id, Some(region_id));
            assert!(matches!(report.region_close, Some(Ok(()))));
            let listener = report.listener.unwrap();
            assert_retired(listener.retirement);
            let listener = listener.outcome.expect("listener returned its actual outcome")
                .expect("listener drains its connection region");
            assert!(listener.accepted_connections() >= 5);
            assert_eq!(listener.completed_connections(), 4);
            assert_eq!(listener.failed_connections(), 0);
            assert_eq!(listener.panicked_connections(), 0);
            let membership_result = report.membership.unwrap();
            assert_retired(membership_result.retirement);
            assert!(matches!(membership_result.outcome, Some(Ok(()) | Err(OwnedMembershipError::Cancelled))));
            let swim = report.swim.unwrap();
            assert_retired(swim.retirement);
            let swim = swim.outcome.expect("SWIM returned its actual outcome");
            assert!(matches!(swim.outcome, Outcome::Ok(()) | Outcome::Cancelled(_)));
            assert!(matches!(observer.snapshot().status, SwimDriverStatus::Left | SwimDriverStatus::Cancelled));
            assert_eq!(holder.join(&cx).await.unwrap(), OwnedLeaseStatus::Closed);
            assert_eq!(membership.live_leases(), 0);
            assert_eq!(operator.active_connections(), 0);
            drop(idle);
        });
        finish(runtime);
    }
}

#[test]
fn component_startup_error_rolls_back_an_already_entered_listener() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, operator, membership, .. } = fixture(&cx).await;
        membership.close();
        let error = NativeDistributedNode::start(
            &cx, service, membership, None, ChildRegionSpec::inherit(),
        ).await.unwrap_err();
        assert!(matches!(error.cause, NativeDistributedNodeStartFailure::Stopped(
            NativeDistributedNodeStopCause::Component(NativeDistributedComponent::Membership)
        )));
        assert!(error.rollback.region_id.is_some());
        assert!(matches!(error.rollback.region_close, Some(Ok(()))));
        let listener = error.rollback.listener.unwrap();
        assert_retired(listener.retirement);
        assert!(listener.outcome.is_some(), "listener really entered before rollback");
        let membership = error.rollback.membership.unwrap();
        assert_eq!(membership.retirement, Ok(()));
        assert!(matches!(membership.outcome, Some(Err(OwnedMembershipError::Closed))));
        assert!(error.rollback.swim.is_none());
        assert!(operator.shutdown_signal().is_shutting_down());
        assert_eq!(operator.active_connections(), 0);
    });
    finish(runtime);
}

#[test]
fn never_polled_start_seals_both_admissions_and_releases_tcp_and_udp() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, operator, membership, .. } = fixture(&cx).await;
        let address = service.local_addr().unwrap();
        let swim = singleton_swim(address);
        let observer = swim.observer();
        let starting = assert_send(NativeDistributedNode::start(
            &cx, service, membership.clone(), Some(swim), ChildRegionSpec::inherit(),
        ));
        drop(starting);
        assert!(operator.shutdown_signal().is_shutting_down());
        assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &statement(1)),
            Err(OwnedMembershipError::Closed)));
        assert_eq!(observer.snapshot().status, SwimDriverStatus::Dropped);
        let tcp = std::net::TcpListener::bind(address).expect("unpolled start released TCP");
        let udp = std::net::UdpSocket::bind(address).expect("unpolled start released UDP");
        drop((tcp, udp));
    });
    finish(runtime);
}

#[test]
fn restricted_io_fails_before_child_admission_and_still_seals_components() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, operator, membership, .. } = fixture(&cx).await;
        type NoIo = CapSet<true, true, true, false, true>;
        let restricted = {
            let _guard = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            Cx::current().unwrap()
        };
        assert!(restricted.capabilities().spawn && restricted.capabilities().time);
        assert!(!restricted.capabilities().io);
        let error = NativeDistributedNode::start(
            &restricted, service, membership.clone(), None, ChildRegionSpec::inherit(),
        ).await.unwrap_err();
        assert!(matches!(error.cause, NativeDistributedNodeStartFailure::MissingIoDriver));
        assert!(error.rollback.region_id.is_none());
        assert!(error.rollback.region_close.is_none());
        assert!(error.rollback.listener.is_none());
        assert!(error.rollback.membership.is_none());
        assert!(operator.shutdown_signal().is_shutting_down());
        assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &statement(1)),
            Err(OwnedMembershipError::Closed)));
    });
    finish(runtime);
}

#[test]
fn owner_drop_requests_existing_region_cleanup_for_every_component() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, operator, membership, .. } = fixture(&cx).await;
        let swim = singleton_swim(service.local_addr().unwrap());
        let observer = swim.observer();
        let node = NativeDistributedNode::start(
            &cx, service, membership.clone(), Some(swim), ChildRegionSpec::inherit(),
        ).await.unwrap();
        drop(node);
        assert!(operator.shutdown_signal().is_shutting_down());
        assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &statement(1)),
            Err(OwnedMembershipError::Closed)));
        eventually(&cx, || observer.snapshot().status.is_terminal()).await;
    });
    finish(runtime);
}
