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
use asupersync::distributed::membership::owned::work::MembershipWorkTrigger;
use asupersync::distributed::remote_owned::{RemoteRunConfig, RemoteRunError};
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
    NativeDistributedOutboundConfig, NativeDistributedOutboundError,
    NativeDistributedRemoteResult,
};
use asupersync::net::{TcpStream, UdpSocket};
use asupersync::remote::{
    ComputationName, IdempotencyKey, NativeRemoteRoute, NativeRemoteRuntimeConfig, NodeId, RemoteCap, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteComputationServiceHandle, RemoteInput,
    RemoteOutcome, RemotePeerAdmissionPolicy, RemotePeerHello, RemoteProtocolVersion,
    RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse,
    RemoteTaskId, SpawnRequest,
};
use asupersync::runtime::{JoinError, RootDrainOutcome, Runtime, RuntimeBuilder, RuntimeHandle};
use asupersync::runtime::reactor::{Events, Interest, Reactor, Source, Token, create_reactor};
use asupersync::security::{AuthKey, SecurityContext};
use asupersync::sync::Notify;
use asupersync::time::{TimeSource, TimerDriver, TimerDriverHandle, WallClock};
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::types::symbol::Symbol;
use asupersync::{Cx, Outcome, Time};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
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
    member_statement(1, sequence, MembershipKind::Alive)
}

fn member_statement(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate {
        event: MembershipEvent {
            node: NodeId::new("worker"),
            incarnation,
            kind,
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
    parked: Arc<ParkedInvocation>,
}

async fn fixture(cx: &Cx) -> Fixture {
    fixture_protocol(cx, RemoteProtocolVersion::V1).await
}

#[derive(Default)]
struct ParkedInvocation {
    entered: AtomicBool,
    cancelled: AtomicBool,
    release: AtomicBool,
    changed: Notify,
}

struct ReleaseParked(Arc<ParkedInvocation>);
impl Drop for ReleaseParked {
    fn drop(&mut self) {
        self.0.release.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}

async fn fixture_protocol(cx: &Cx, protocol: RemoteProtocolVersion) -> Fixture {
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
    let parked = Arc::new(ParkedInvocation::default());
    let observed = Arc::clone(&parked);
    registry.register::<EchoRequest, EchoResponse, _, _>("echo", move |body, invocation| {
        let observed = Arc::clone(&observed);
        async move {
            if invocation.request().input.data() == b"park" {
                let mut cancelled = std::pin::pin!(body.cancelled());
                poll_fn(|task| {
                    let next = cancelled.as_mut().poll(task);
                    if next.is_pending() {
                        observed.entered.store(true, Ordering::Release);
                        observed.changed.notify_waiters();
                    }
                    next
                }).await;
                assert!(body.checkpoint().is_err());
                observed.cancelled.store(true, Ordering::Release);
                observed.changed.notify_waiters();
                // Deliberately withhold cleanup after acknowledged cancellation.
                observed.changed.wait_until(|| observed.release.load(Ordering::Acquire)).await;
                Ok(RemoteOutcome::Cancelled(body.cancel_reason().unwrap()))
            } else {
                Ok(RemoteOutcome::Success(invocation.request().input.data().to_vec()))
            }
        }
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
        protocol, registry.schema_registry().clone(),
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
    Fixture { service, operator, membership, client, hello, store, parked }
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
            let Fixture { service, operator, membership, client, hello, store, .. } = fixture(&cx).await;
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

fn outbound_config(runtime: RuntimeHandle) -> NativeDistributedOutboundConfig {
    NativeDistributedOutboundConfig::new(
        runtime,
        RemoteCap::new().with_local_node(NodeId::new("authority")),
        NativeRemoteRuntimeConfig::new().with_max_in_flight(1)
            .with_drain_timeout(Duration::from_secs(3)),
        1,
    ).unwrap()
}

fn remote_run_config() -> RemoteRunConfig {
    RemoteRunConfig { timeout: WINDOW, child: ChildRegionSpec::inherit() }
}

fn assert_node_remote_success(result: NativeDistributedRemoteResult, expected: &[u8]) {
    assert_eq!(result.retirement, Ok(()));
    let membership = result.outcome.expect("actual owner outcome").unwrap();
    assert!(membership.is_success(), "{membership:?}");
    let remote = membership.work.task.unwrap().unwrap();
    assert!(remote.is_success(), "{remote:?}");
    assert!(matches!(remote.task.unwrap().outcome,
        Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == expected));
}

struct SubmissionPanicReactor {
    inner: Arc<dyn Reactor>,
    armed: AtomicBool,
}

impl Reactor for SubmissionPanicReactor {
    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> std::io::Result<()> {
        self.inner.register(source, token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> std::io::Result<()> {
        self.inner.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> std::io::Result<()> { self.inner.deregister(token) }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> std::io::Result<usize> {
        self.inner.poll(events, timeout)
    }

    fn wake(&self) -> std::io::Result<()> {
        if self.armed.swap(false, Ordering::AcqRel) { panic!("submission notifier panic"); }
        self.inner.wake()
    }

    fn registration_count(&self) -> usize { self.inner.registration_count() }
}

#[derive(Debug, Default)]
struct SubmissionPanicClock {
    inner: WallClock,
    remaining: AtomicUsize,
}

impl TimeSource for SubmissionPanicClock {
    fn now(&self) -> Time {
        if self.remaining.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |remaining| remaining.checked_sub(1)) == Ok(1)
        { panic!("submission clock panic"); }
        self.inner.now()
    }
}

#[test]
fn node_outbound_submission_unwind_seals_admission_and_drains_unpublished_owner() {
    for before_enqueue in [true, false] {
        // Use real native I/O and wall time. A current-thread driver keeps the
        // armed callback on this synchronous submission, without a timing race.
        let reactor = Arc::new(SubmissionPanicReactor {
            inner: create_reactor().unwrap(), armed: AtomicBool::new(false),
        });
        let clock = Arc::new(SubmissionPanicClock::default());
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor.clone())
            .with_timer_driver(TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&clock)))))
            .build().unwrap();
        let runtime_handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, operator, membership, client, hello, parked, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let _release = ReleaseParked(Arc::clone(&parked));
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let route = NativeRemoteRoute::new(NodeId::new("worker"), hello, client);
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership.clone(), None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            outbound.publish_peer(route.clone(), 1).unwrap();
            if before_enqueue {
                // The submission deadline samples first; gateway enqueue
                // samples next, after the outbound credit was reserved.
                clock.remaining.store(2, Ordering::Release);
            } else {
                reactor.armed.store(true, Ordering::Release);
            }
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                outbound.spawn_remote(NodeId::new("worker"), 1, ComputationName::new("echo"),
                    RemoteInput::new(b"park".to_vec()), remote_run_config())
            })).expect_err("injected submission callback must unwind");
            let expected = if before_enqueue { "submission clock panic" } else { "submission notifier panic" };
            assert_eq!(panic.downcast_ref::<&str>().copied(), Some(expected));
            assert!(outbound.is_closed());
            assert!(node.is_closed());
            assert!(operator.shutdown_signal().is_shutting_down());
            assert_eq!(outbound.retained_operations(), 1, "unknown publication keeps its credit until region close");
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(), remote_run_config(),
            ), Err(NativeDistributedOutboundError::Closed)));
            assert!(matches!(outbound.publish_peer(route, 1), Err(NativeDistributedOutboundError::Closed)));
            assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &statement(2)),
                Err(OwnedMembershipError::Closed)));
            assert!(cx.checkpoint().is_ok(), "submission unwind must not cancel the caller's parent region");

            let report = assert_send(node.close()).await;
            assert_eq!(report.stop_cause, NativeDistributedNodeStopCause::OwnerDropped);
            assert!(matches!(report.region_close, Some(Ok(()))));
            let remote = report.outbound.unwrap();
            assert!(remote.graceful);
            assert_eq!(remote.active_sessions, 0);
            assert_eq!(remote.retained_operations, 0);
            assert_eq!(outbound.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);
            assert!(!parked.entered.load(Ordering::Acquire), "cancelled unpublished work must not reach the remote handler");
        });
        finish(runtime);
    }
}

#[test]
fn node_outbound_authenticates_work_rejoins_and_retains_completed_results() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let runtime_handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, parked, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let _release = ReleaseParked(Arc::clone(&parked));
            let route = NativeRemoteRoute::new(NodeId::new("worker"), hello.clone(), client.clone());
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership.clone(), None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            assert_eq!(outbound.route_generation(), 0);
            assert!(matches!(outbound.publish_peer(route.clone(), 1), Err(NativeDistributedOutboundError::Membership)));
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(), remote_run_config(),
            ), Err(NativeDistributedOutboundError::Membership)));
            assert_eq!(outbound.retained_operations(), 0);

            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let wrong_origin = RemotePeerHello::new(
                NodeId::new("wrong-origin"), RemoteProtocolVersion::V3, hello.registry_fingerprint(),
            );
            assert!(matches!(outbound.publish_peer(
                NativeRemoteRoute::new(NodeId::new("worker"), wrong_origin, client.clone()), 1,
            ), Err(NativeDistributedOutboundError::Routes(
                asupersync::remote::NativeRemoteRuntimeBuildError::OriginIdentityMismatch { .. }
            ))));
            assert_eq!(outbound.route_generation(), 0, "invalid candidate never publishes");
            assert_eq!(outbound.publish_peer(route.clone(), 1).unwrap(), 1);
            assert!(matches!(outbound.publish_peer(
                NativeRemoteRoute::new(NodeId::new("other"), hello, client.clone()), 1,
            ), Err(NativeDistributedOutboundError::PeerCapacity)));
            assert_eq!(outbound.route_generation(), 1);

            let oversized = Vec::with_capacity(client.config().wire_limits().max_frame_bytes() + 1);
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::new(oversized), remote_run_config(),
            ), Err(NativeDistributedOutboundError::RequestTooLarge)));
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(),
                RemoteRunConfig { timeout: Duration::ZERO, child: ChildRegionSpec::inherit() },
            ), Err(NativeDistributedOutboundError::Timing(RemoteRunError::Timeout))));
            assert_eq!(outbound.retained_operations(), 0);

            let mut first = outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"first generation".to_vec()), remote_run_config(),
            ).unwrap();
            eventually(&cx, || first.is_finished()).await;
            assert_eq!(outbound.active_sessions(), 0);
            assert_eq!(outbound.retained_operations(), 1, "unread reports retain the bounded slot");
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(), remote_run_config(),
            ), Err(NativeDistributedOutboundError::OperationCapacity)));
            assert_node_remote_success(assert_send(first.join()).await, b"first generation");
            assert_eq!(outbound.retained_operations(), 0);
            let repeated = first.join().await;
            assert!(repeated.outcome.is_none());
            assert_eq!(repeated.retirement, Err(JoinError::PolledAfterCompletion));

            let mut revoked = outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"park".to_vec()), remote_run_config(),
            ).unwrap();
            eventually(&cx, || parked.entered.load(Ordering::Acquire)).await;
            assert_eq!(membership.live_leases(), 1);
            membership.apply_authenticated(&NodeId::new("authority"),
                &member_statement(1, 2, MembershipKind::Dead)).unwrap();
            eventually(&cx, || parked.cancelled.load(Ordering::Acquire)).await;
            assert_eq!(outbound.retained_operations(), 1, "revocation still owns the draining invocation");
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(), remote_run_config(),
            ), Err(NativeDistributedOutboundError::Membership)));
            parked.release.store(true, Ordering::Release);
            parked.changed.notify_waiters();
            let retired = revoked.join().await;
            assert_retired(retired.retirement);
            let retired = retired.outcome.expect("revoked owner retained its report").unwrap();
            assert!(!retired.is_success());
            assert!(matches!(retired.work.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Revoked)));
            assert!(retired.work.close.is_ok());
            assert!(matches!(retired.work.lease, Ok(OwnedLeaseStatus::Revoked)));
            assert_eq!(membership.live_leases(), 0);
            assert_eq!(outbound.retained_operations(), 0);
            membership.apply_authenticated(&NodeId::new("authority"),
                &member_statement(2, 3, MembershipKind::Alive)).unwrap();
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 2, ComputationName::new("echo"), RemoteInput::empty(), remote_run_config(),
            ), Err(NativeDistributedOutboundError::Membership)), "new authority alone cannot rebind an old route");
            assert!(matches!(outbound.publish_peer(route.clone(), 1), Err(NativeDistributedOutboundError::Membership)));
            assert_eq!(outbound.route_generation(), 1);
            assert_eq!(outbound.publish_peer(route.clone(), 2).unwrap(), 2);
            let mut rejoined = outbound.spawn_remote(
                NodeId::new("worker"), 2, ComputationName::new("echo"),
                RemoteInput::new(b"fresh generation".to_vec()), remote_run_config(),
            ).unwrap();
            assert_node_remote_success(assert_send(rejoined.join()).await, b"fresh generation");
            assert_eq!(outbound.remove_peer(&NodeId::new("worker")).unwrap(), 3);
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 2, ComputationName::new("echo"), RemoteInput::empty(), remote_run_config(),
            ), Err(NativeDistributedOutboundError::Membership)));

            let report = assert_send(node.close()).await;
            assert!(matches!(report.region_close, Some(Ok(()))));
            let remote = report.outbound.unwrap();
            assert!(remote.graceful);
            assert_eq!(remote.active_sessions, 0);
            assert_eq!(remote.retained_operations, 0);
            assert_eq!(remote.route_generation, 3);
            assert!(outbound.is_closed());
            assert!(matches!(outbound.publish_peer(route, 2), Err(NativeDistributedOutboundError::Closed)));
        });
        finish(runtime);
    }
}

#[test]
fn node_outbound_drop_retains_capacity_until_real_drain_and_close_collects_owners() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let runtime_handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, parked, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let _release = ReleaseParked(Arc::clone(&parked));
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let route = NativeRemoteRoute::new(NodeId::new("worker"), hello, client);
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership.clone(), None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            outbound.publish_peer(route, 1).unwrap();
            let first = outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"park".to_vec()), remote_run_config(),
            ).unwrap();
            eventually(&cx, || parked.entered.load(Ordering::Acquire)).await;
            assert_eq!(membership.live_leases(), 1);
            assert_eq!(outbound.active_sessions(), 1);
            drop(first);
            eventually(&cx, || parked.cancelled.load(Ordering::Acquire)).await;
            assert_eq!(outbound.retained_operations(), 1, "handle drop cannot free an owner still draining");
            assert!(matches!(outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(), remote_run_config(),
            ), Err(NativeDistributedOutboundError::OperationCapacity)));
            parked.release.store(true, Ordering::Release);
            parked.changed.notify_waiters();
            eventually(&cx, || outbound.retained_operations() == 0).await;
            assert_eq!(membership.live_leases(), 0);
            assert_eq!(outbound.active_sessions(), 0);
            let mut healthy = outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"after cancelled work".to_vec()), remote_run_config(),
            ).unwrap();
            assert_node_remote_success(healthy.join().await, b"after cancelled work");

            parked.entered.store(false, Ordering::Release);
            parked.cancelled.store(false, Ordering::Release);
            parked.release.store(false, Ordering::Release);
            let mut last = outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"park".to_vec()), remote_run_config(),
            ).unwrap();
            eventually(&cx, || parked.entered.load(Ordering::Acquire)).await;
            node.begin_close();
            assert!(outbound.is_closed());
            eventually(&cx, || parked.cancelled.load(Ordering::Acquire)).await;
            let mut closing = std::pin::pin!(assert_send(node.close()));
            poll_fn(|task| {
                assert!(closing.as_mut().poll(task).is_pending(), "close must await the observed remote cleanup");
                Poll::Ready(())
            }).await;
            parked.release.store(true, Ordering::Release);
            parked.changed.notify_waiters();
            let report = closing.await;
            assert!(matches!(report.region_close, Some(Ok(()))));
            let remote = report.outbound.unwrap();
            assert_eq!(remote.active_sessions, 0);
            assert_eq!(remote.retained_operations, 1, "retired unread handle remains charged");
            let terminal = last.join().await;
            assert_retired(terminal.retirement);
            let actual = terminal.outcome.expect("entered owner retained its actual report");
            assert!(!actual.is_ok_and(|report| report.is_success()));
            assert_eq!(outbound.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);
        });
        finish(runtime);
    }
}

#[test]
fn node_outbound_startup_rollback_and_unpolled_start_preserve_quiescence() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(matches!(NativeDistributedOutboundConfig::new(
            handle.clone(), RemoteCap::new(), NativeRemoteRuntimeConfig::new(), 0,
        ), Err(NativeDistributedOutboundError::Configuration)));
        assert!(matches!(NativeDistributedOutboundConfig::new(
            handle.clone(), RemoteCap::new(), NativeRemoteRuntimeConfig::new().with_max_in_flight(0), 1,
        ), Err(NativeDistributedOutboundError::Routes(
            asupersync::remote::NativeRemoteRuntimeBuildError::ZeroMaxInFlight
        ))));
        let Fixture { service, membership, operator, .. } = fixture(&cx).await;
        type NoIo = CapSet<true, true, true, false, true>;
        let restricted = {
            let _guard = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            Cx::current().unwrap()
        };
        let error = NativeDistributedNode::start_with_outbound(
            &restricted, service, membership.clone(), None,
            outbound_config(handle.clone()), ChildRegionSpec::inherit(),
        ).await.unwrap_err();
        assert!(matches!(error.cause, NativeDistributedNodeStartFailure::MissingIoDriver));
        assert!(error.rollback.region_id.is_none());
        let outbound = error.rollback.outbound.unwrap();
        assert!(outbound.graceful);
        assert_eq!(outbound.active_sessions, 0);
        assert_eq!(outbound.retained_operations, 0);
        assert_eq!(outbound.route_generation, 0);
        assert!(operator.shutdown_signal().is_shutting_down());
        assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &statement(1)),
            Err(OwnedMembershipError::Closed)));

        let Fixture { service, membership, .. } = fixture(&cx).await;
        type NoRemote = CapSet<true, true, true, true, false>;
        let restricted = {
            let _guard = Cx::push_restriction(<NoRemote as CapSetRuntimeMask>::MASK);
            Cx::current().unwrap()
        };
        assert!(!restricted.capabilities().remote);
        let error = NativeDistributedNode::start_with_outbound(
            &restricted, service, membership, None,
            outbound_config(handle.clone()), ChildRegionSpec::inherit(),
        ).await.unwrap_err();
        assert!(matches!(error.cause, NativeDistributedNodeStartFailure::MissingRemote));
        assert!(error.rollback.region_id.is_none());
        assert_eq!(error.rollback.outbound.unwrap().active_sessions, 0);

        let Fixture { service, membership, operator, .. } = fixture(&cx).await;
        let address = service.local_addr().unwrap();
        drop(assert_send(NativeDistributedNode::start_with_outbound(
            &cx, service, membership.clone(), None, outbound_config(handle), ChildRegionSpec::inherit(),
        )));
        assert!(operator.shutdown_signal().is_shutting_down());
        assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &statement(1)),
            Err(OwnedMembershipError::Closed)));
        let rebound = std::net::TcpListener::bind(address).expect("never-polled node released its listener");
        drop(rebound);
    });
    finish(runtime);
}
