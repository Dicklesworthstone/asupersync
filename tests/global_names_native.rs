//! Real mTLS propagation, owner lookups, admission and owned shutdown.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::bytes::BytesMut;
use asupersync::channel::oneshot;
use asupersync::codec::{Framed, LengthDelimitedCodec};
use asupersync::distributed::global_names::{
    GlobalNameConfig, GlobalNameRegistry,
};
use asupersync::distributed::global_names::native::{
    GlobalNamePropagationStop, NativeGlobalNameConfig, NativeGlobalNameError,
    NativeGlobalNameTransport,
};
use asupersync::distributed::global_names::service::{
    GLOBAL_NAME_SERVICE_COMPUTATION, register_global_name_service,
};
use asupersync::distributed::membership::authority::{
    MembershipControllerLimits, MembershipFloor, MembershipUpdate,
};
use asupersync::distributed::membership::owned::OwnedMembershipController;
use asupersync::distributed::membership::{MembershipEvent, MembershipKind};
use asupersync::net::TcpListener;
use asupersync::remote::{
    NodeId, RemoteComputationClient, RemoteComputationClientConfig, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemoteComputationServiceReport, RemotePeerAdmissionPolicy, RemotePeerHello,
    RemoteProtocolVersion, RemoteServiceWireOutcome, RemoteServiceWireRequest,
    RemoteServiceWireResponse,
};
use asupersync::runtime::{RuntimeBuilder, RuntimeHandle, TaskHandle};
use asupersync::security::AuthKey;
use asupersync::stream::StreamExt as _;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptor, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder,
};
use asupersync::types::{Budget, CancelKind, Time};
use asupersync::Cx;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(12);

async fn within<T>(cx: &Cx, future: impl Future<Output = T>) -> T {
    asupersync::time::timeout(cx.now(), WATCHDOG, future)
        .await
        .expect("global-name native watchdog")
}

fn run_native<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx, RuntimeHandle) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    }
    .build()
    .unwrap();
    let handle = runtime.handle();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        within(&cx, test(cx.clone(), handle)).await;
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

fn node(name: &str) -> NodeId {
    NodeId::new(name)
}

struct World {
    membership: OwnedMembershipController,
    a: GlobalNameRegistry,
    b: GlobalNameRegistry,
    membership_driver: TaskHandle<()>,
    drivers: Vec<TaskHandle<()>>,
}

impl World {
    async fn new(cx: &Cx) -> Self {
        let membership = OwnedMembershipController::new(
            node("authority"),
            7,
            AuthKey::from_seed(42),
            ["a", "b"].into_iter().map(|name| MembershipFloor {
                node: node(name),
                incarnation: 0,
                sequence: 0,
            }).collect(),
            MembershipControllerLimits {
                max_members: 2,
                max_lease_ids: 64,
            },
            cx.timer_driver().unwrap(),
        )
        .unwrap();
        for name in ["a", "b"] {
            let statement = MembershipUpdate {
                event: MembershipEvent {
                    node: node(name),
                    incarnation: 1,
                    kind: MembershipKind::Alive,
                },
                sequence: 1,
            }
            .authenticated_bytes(&node("authority"), 7, &AuthKey::from_seed(42))
            .unwrap();
            membership
                .apply_authenticated(&node("authority"), &statement)
                .unwrap();
        }
        let config = || GlobalNameConfig::new(8, 8, Duration::from_millis(20)).unwrap();
        let a = GlobalNameRegistry::new(
            node("a"), 1, [node("b")], membership.clone(), config(),
        )
        .unwrap();
        let b = GlobalNameRegistry::new(
            node("b"), 1, [node("a")], membership.clone(), config(),
        )
        .unwrap();
        let running = membership.clone();
        let membership_driver = cx
            .spawn(move |child| async move {
                running.run(&child).await.expect("membership driver");
            })
            .unwrap();
        let mut drivers = Vec::new();
        for registry in [a.clone(), b.clone()] {
            drivers.push(
                cx.spawn(move |child| async move {
                    registry.run(&child).await.expect("global-name driver");
                })
                .unwrap(),
            );
        }
        within(cx, a.wait_running(cx)).await.unwrap();
        within(cx, b.wait_running(cx)).await.unwrap();
        Self { membership, a, b, membership_driver, drivers }
    }

    async fn finish(mut self, cx: &Cx) {
        self.a.request_shutdown();
        self.b.request_shutdown();
        for driver in &mut self.drivers {
            within(cx, driver.join(cx)).await.unwrap();
        }
        self.membership.close();
        within(cx, self.membership_driver.join(cx)).await.unwrap();
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.a.request_shutdown();
        self.b.request_shutdown();
        self.membership.close();
    }
}

fn tls() -> (TlsAcceptor, TlsConnector, CertificatePinSet) {
    let certificate = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt"))
        .unwrap()
        .remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(&certificate).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
        .client_auth(ClientAuth::Required(roots))
        .build()
        .unwrap();
    let mut pins = CertificatePinSet::new();
    pins.add(CertificatePin::compute_spki_sha256(&certificate).unwrap());
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&certificate)
        .identity(chain, key)
        .with_certificate_pins(pins.clone())
        .build()
        .unwrap();
    (acceptor, connector, pins)
}

fn client(address: std::net::SocketAddr, connector: TlsConnector) -> RemoteComputationClient {
    RemoteComputationClient::new(
        address,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_connect_timeout(Duration::from_secs(2))
            .with_attempt_timeout(Duration::from_secs(8)),
    )
    .unwrap()
}

struct Service {
    client: RemoteComputationClient,
    hello: RemotePeerHello,
    operator: RemoteComputationServiceHandle,
    serving: TaskHandle<RemoteComputationServiceReport>,
}

impl Service {
    async fn start(
        cx: &Cx,
        owner: GlobalNameRegistry,
        grant: bool,
        protocol: RemoteProtocolVersion,
    ) -> Self {
        let mut registry = RemoteComputationRegistry::new();
        register_global_name_service(&mut registry, owner).unwrap();
        let (acceptor, connector, pins) = tls();
        let hello = RemotePeerAdmissionPolicy::new(
            RemoteProtocolVersion::V1,
            registry.schema_registry().clone(),
        )
        .hello_for(node("a"));
        let mut policy =
            RemotePeerAdmissionPolicy::new(protocol, registry.schema_registry().clone());
        if grant {
            policy
                .grant_tls_peer(node("a"), pins, [GLOBAL_NAME_SERVICE_COMPUTATION])
                .unwrap();
        }
        let service = RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            registry,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(4))
                .with_drain_timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let address = service.local_addr().unwrap();
        let operator = service.handle();
        let serving = cx
            .spawn(move |child| async move {
                service.run(&child).await.expect("remote computation service")
            })
            .unwrap();
        Self { client: client(address, connector), hello, operator, serving }
    }

    fn transport(&self, registry: GlobalNameRegistry) -> NativeGlobalNameTransport {
        NativeGlobalNameTransport::new(
            registry,
            self.hello.clone(),
            [(node("b"), self.client.clone())],
            NativeGlobalNameConfig::new(1, Duration::from_secs(30)).unwrap(),
        )
        .unwrap()
    }

    async fn finish(mut self, cx: &Cx) -> RemoteComputationServiceReport {
        let _ = self.operator.begin_drain();
        let report = within(cx, self.serving.join(cx)).await.unwrap();
        assert_eq!(self.operator.active_connections(), 0);
        report
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.operator.begin_drain();
    }
}

#[test]
fn mtls_propagates_full_owner_catalog_and_answers_exact_owner_lookups() {
    for workers in [1, 2] {
        run_native(workers, |cx, _| async move {
            let world = World::new(&cx).await;
            let local = world.a.register_global(&cx, "frontend", "frontend.run").await.unwrap();
            let remote = world.b.register_global(&cx, "backend", "backend.run").await.unwrap();
            let service = Service::start(&cx, world.b.clone(), true, RemoteProtocolVersion::V1).await;
            let transport = service.transport(world.a.clone());
            assert!(world.b.whereis_global(&cx, "frontend").unwrap().is_none());
            let round = within(&cx, transport.propagate_once(&cx)).await.unwrap();
            assert_eq!(round.peers.len(), 1);
            assert_eq!(round.acknowledged(), 1);
            assert!(round.all_acknowledged());
            assert!(world.b.whereis_global(&cx, "frontend").unwrap().is_some());

            let found = within(&cx, transport.lookup_owner(&cx, &node("b"), 1, "backend"))
                .await
                .unwrap();
            assert_eq!(found.owner, node("b"));
            assert_eq!(found.incarnation, 1);
            assert!(found.target.is_some());
            let absent = within(&cx, transport.lookup_owner(&cx, &node("b"), 1, "absent"))
                .await
                .unwrap();
            assert!(absent.target.is_none(), "owner absence is an actual network answer");
            assert!(world.a.whereis_global(&cx, "backend").unwrap().is_none(),
                "a direct lookup does not mutate replicated catalogs");
            assert_eq!(transport.in_flight(), 0);
            let report = service.finish(&cx).await;
            assert_eq!(report.accepted_connections(), 3);
            drop((local, remote));
            world.finish(&cx).await;
        });
    }
}

#[test]
fn mtls_allowlist_and_protocol_refusals_do_not_mutate_replica_catalogs() {
    for workers in [1, 2] {
        for (grant, protocol) in [
            (false, RemoteProtocolVersion::V1),
            (true, RemoteProtocolVersion::V2),
        ] {
            run_native(workers, move |cx, _| async move {
                let world = World::new(&cx).await;
                let lease = world.a.register_global(&cx, "private", "private.run").await.unwrap();
                let service = Service::start(&cx, world.b.clone(), grant, protocol).await;
                let transport = service.transport(world.a.clone());
                let report = within(&cx, transport.propagate_once(&cx)).await.unwrap();
                assert_eq!(report.acknowledged(), 0);
                assert_eq!(report.peers.len(), 1);
                assert!(matches!(report.peers[0].result, Err(NativeGlobalNameError::Refused)));
                assert!(world.b.whereis_global(&cx, "private").unwrap().is_none());
                assert_eq!(transport.in_flight(), 0);
                assert_eq!(service.finish(&cx).await.accepted_connections(), 1);
                drop(lease);
                world.finish(&cx).await;
            });
        }
    }
}

struct ParkWitness<F> {
    operation: Pin<Box<F>>,
    owner: Cx,
    parked: Option<oneshot::Sender<Cx>>,
}

impl<F: Future> Future for ParkWitness<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = this.operation.as_mut().poll(task);
        if result.is_pending()
            && let Some(parked) = this.parked.take()
        {
            parked.send_blocking(this.owner.clone()).unwrap();
        }
        result
    }
}

#[test]
fn native_propagation_clones_share_admission_and_cancel_parked_mtls_sockets() {
    for workers in [1, 2] {
        for (kind, expected) in [
            (CancelKind::User, GlobalNamePropagationStop::Cancelled),
            (CancelKind::Deadline, GlobalNamePropagationStop::Deadline),
            (CancelKind::Timeout, GlobalNamePropagationStop::Deadline),
        ] {
            run_native(workers, move |cx, _| async move {
                let world = World::new(&cx).await;
                let (acceptor, connector, _) = tls();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let (reading, mut read_parked) = oneshot::channel();
                let (closed, mut closed_socket) = oneshot::channel();
                let mut peer = cx.spawn(move |child| async move {
                    let mut reading = Some(reading);
                    let mut closed = Some(closed);
                    for index in 0..2 {
                        let (tcp, _) = within(&child, listener.accept()).await.unwrap();
                        let tls = within(&child, acceptor.accept(tcp)).await.unwrap();
                        let codec = LengthDelimitedCodec::builder()
                            .max_frame_length(128 * 1024)
                            .big_endian()
                            .new_codec();
                        let mut framed = Framed::new(tls, codec)
                            .with_max_buffer_len(128 * 1024 + 4);
                        let bytes = within(&child, framed.next()).await.unwrap().unwrap();
                        let request: RemoteServiceWireRequest = serde_json::from_slice(&bytes).unwrap();
                        assert_eq!(request.hello().peer_node(), &node("a"));
                        assert_eq!(request.hello().protocol_version(), RemoteProtocolVersion::V1);
                        if index == 0 {
                            // A complete authenticated application request has
                            // arrived. Park on the very same socket; only local
                            // transport retirement can produce EOF/reset here.
                            let ended = {
                                let mut next = pin!(framed.next());
                                within(&child, poll_fn(|task| {
                                    let result = next.as_mut().poll(task);
                                    if result.is_pending()
                                        && let Some(reading) = reading.take()
                                    {
                                        reading.send_blocking(()).unwrap();
                                    }
                                    result
                                })).await
                            };
                            assert!(!matches!(ended, Some(Ok(_))),
                                "cancellation does not dispatch a second application frame");
                            drop(framed);
                            closed.take().unwrap().send_blocking(()).unwrap();
                        } else {
                            // An explicit refusal is enough to prove the next
                            // request crossed TLS after both guards recovered.
                            let response = RemoteServiceWireResponse::Outcome {
                                remote_task_id: request.remote_task_id().raw(),
                                outcome: RemoteServiceWireOutcome::Failed("fixture refusal".into()),
                            };
                            let bytes = serde_json::to_vec(&response).unwrap();
                            framed.send(BytesMut::from(bytes.as_slice())).unwrap();
                            within(&child, poll_fn(|task| framed.poll_flush(task))).await.unwrap();
                        }
                    }
                    2_usize
                }).unwrap();

                let mut schema = RemoteComputationRegistry::new();
                register_global_name_service(&mut schema, world.b.clone()).unwrap();
                let hello = RemotePeerAdmissionPolicy::new(
                    RemoteProtocolVersion::V1, schema.schema_registry().clone(),
                ).hello_for(node("a"));
                // Longer than every watchdog: an old detached attempt cannot
                // pass the EOF witness merely by reaching its own timeout.
                let client = RemoteComputationClient::new(
                    address, "localhost", connector,
                    RemoteComputationClientConfig::new()
                        .with_max_attempts(1)
                        .with_connect_timeout(Duration::from_secs(2))
                        .with_attempt_timeout(Duration::from_secs(60)),
                ).unwrap();
                let transport = NativeGlobalNameTransport::new(
                    world.a.clone(), hello, [(node("b"), client)],
                    NativeGlobalNameConfig::new(1, Duration::from_secs(30)).unwrap(),
                ).unwrap();
                let running = transport.clone();
                let (parked, mut observed) = oneshot::channel();
                let mut driver = cx.spawn(move |owner| {
                    let run_owner = owner.clone();
                    ParkWitness {
                        operation: Box::pin(async move { running.run(&run_owner).await }),
                        owner,
                        parked: Some(parked),
                    }
                }).unwrap();
                let owner = within(&cx, observed.recv(&cx)).await.unwrap();
                within(&cx, read_parked.recv(&cx)).await.unwrap();
                assert_eq!(transport.in_flight(), 1);
                let clone = transport.clone();
                assert!(matches!(
                    clone.lookup_owner(&cx, &node("b"), 1, "blocked").await,
                    Err(NativeGlobalNameError::Admission)
                ));
                assert!(matches!(
                    clone.propagate_once(&cx).await,
                    Err(NativeGlobalNameError::RoundRunning)
                ));
                assert!(matches!(
                    clone.run(&cx).await,
                    Err(NativeGlobalNameError::DriverRunning)
                ));
                assert_eq!(clone.in_flight(), 1);
                owner.cancel_with(kind, Some("stop a parked global-name exchange"));
                let report = within(&cx, driver.join(&cx)).await.unwrap().unwrap();
                assert_eq!(report.stop, expected);
                assert_eq!(report.completed_rounds, 0);
                assert_eq!(transport.in_flight(), 0);
                // The peer observes actual socket retirement before drain,
                // remote release, or the 60-second client timeout.
                within(&cx, closed_socket.recv(&cx)).await.unwrap();

                let recovered = within(&cx, transport.propagate_once(&cx)).await.unwrap();
                assert_eq!(recovered.peers.len(), 1);
                assert!(matches!(recovered.peers[0].result, Err(NativeGlobalNameError::Refused)));
                assert_eq!(transport.in_flight(), 0);
                assert_eq!(within(&cx, peer.join(&cx)).await.unwrap(), 2,
                    "no admission refusal opened an extra TCP connection");

                let retry = transport.clone();
                let mut stopped = cx.spawn(move |child| async move {
                    child.cancel_with(CancelKind::User, Some("driver guard recovery"));
                    retry.run(&child).await
                }).unwrap();
                let report = within(&cx, stopped.join(&cx)).await.unwrap().unwrap();
                assert_eq!(report.stop, GlobalNamePropagationStop::Cancelled);
                world.finish(&cx).await;
            });
        }
    }
}

#[test]
fn expired_native_owner_budget_is_a_deadline_before_any_network_effect() {
    for workers in [1, 2] {
        run_native(workers, |cx, handle| async move {
            let world = World::new(&cx).await;
            let service = Service::start(&cx, world.b.clone(), true, RemoteProtocolVersion::V1).await;
            let transport = service.transport(world.a.clone());
            let expired = handle.request_cx_with_budget(
                Budget::INFINITE.with_deadline(Time::ZERO),
            );
            assert!(matches!(
                transport.lookup_owner(&expired, &node("b"), 1, "backend").await,
                Err(NativeGlobalNameError::Deadline)
            ));
            assert_eq!(transport.in_flight(), 0);
            assert!(!cx.is_cancel_requested());
            assert_eq!(service.finish(&cx).await.accepted_connections(), 0);
            world.finish(&cx).await;
        });
    }
}

/// Replay a genuine authenticated service reply under fresh transport task
/// IDs. This exercises semantic owner/name/version validation after ordinary
/// request correlation has already succeeded.
async fn replaying_peer(
    cx: &Cx,
    backend: &Service,
    calls: usize,
) -> (RemoteComputationClient, TaskHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (acceptor, connector, _) = tls();
    let forwarding = backend.client.clone();
    let serving = cx.spawn(move |child| async move {
        let mut captured = None;
        for index in 0..calls {
            let (tcp, _) = within(&child, listener.accept()).await.unwrap();
            let tls = within(&child, acceptor.accept(tcp)).await.unwrap();
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(128 * 1024)
                .big_endian()
                .new_codec();
            let mut framed = Framed::new(tls, codec)
                .with_max_buffer_len(128 * 1024 + 4);
            let frame = within(&child, framed.next()).await.unwrap().unwrap();
            let request: RemoteServiceWireRequest = serde_json::from_slice(&frame).unwrap();
            if index == 0 {
                let response = within(&child, forwarding.call(&child, &request)).await.unwrap();
                let RemoteServiceWireResponse::Outcome {
                    outcome: RemoteServiceWireOutcome::Success(bytes),
                    ..
                } = response else {
                    panic!("the original authenticated service reply must be successful");
                };
                captured = Some(bytes);
            }
            let response = RemoteServiceWireResponse::Outcome {
                remote_task_id: request.remote_task_id().raw(),
                outcome: RemoteServiceWireOutcome::Success(captured.as_ref().unwrap().clone()),
            };
            let bytes = serde_json::to_vec(&response).unwrap();
            framed.send(BytesMut::from(bytes.as_slice())).unwrap();
            within(&child, poll_fn(|task| framed.poll_flush(task))).await.unwrap();
        }
        calls
    }).unwrap();
    (client(address, connector), serving)
}

#[test]
fn native_owner_lookup_rejects_wrong_name_and_stale_incarnation_replies() {
    for workers in [1, 2] {
        run_native(workers, |cx, _| async move {
            let world = World::new(&cx).await;
            let lease = world.b.register_global(&cx, "backend", "backend.run").await.unwrap();
            let service = Service::start(&cx, world.b.clone(), true, RemoteProtocolVersion::V1).await;
            let (client, mut proxy) = replaying_peer(&cx, &service, 4).await;
            let transport = NativeGlobalNameTransport::new(
                world.a.clone(),
                service.hello.clone(),
                [(node("b"), client)],
                NativeGlobalNameConfig::new(1, Duration::from_secs(30)).unwrap(),
            ).unwrap();

            let valid = within(&cx, transport.lookup_owner(&cx, &node("b"), 1, "backend"))
                .await.unwrap();
            assert!(valid.target.is_some());
            assert!(matches!(
                within(&cx, transport.lookup_owner(&cx, &node("b"), 1, "another-name")).await,
                Err(NativeGlobalNameError::Registry(_))
            ));
            assert!(matches!(
                within(&cx, transport.lookup_owner(&cx, &node("b"), 2, "backend")).await,
                Err(NativeGlobalNameError::Registry(_))
            ));
            let recovered = within(&cx, transport.lookup_owner(&cx, &node("b"), 1, "backend"))
                .await.unwrap();
            assert!(recovered.target.is_some());
            assert_eq!(transport.in_flight(), 0);
            assert!(world.a.whereis_global(&cx, "backend").unwrap().is_none());
            assert_eq!(within(&cx, proxy.join(&cx)).await.unwrap(), 4);
            assert_eq!(service.finish(&cx).await.accepted_connections(), 1,
                "all forged answers replay the single genuine application payload");
            drop(lease);
            world.finish(&cx).await;
        });
    }
}

#[test]
fn native_propagation_receipt_must_acknowledge_the_exact_sent_snapshot() {
    for workers in [1, 2] {
        run_native(workers, |cx, _| async move {
            let world = World::new(&cx).await;
            let first = world.a.register_global(&cx, "first", "first.run").await.unwrap();
            let service = Service::start(&cx, world.b.clone(), true, RemoteProtocolVersion::V1).await;
            let (client, mut proxy) = replaying_peer(&cx, &service, 2).await;
            let transport = NativeGlobalNameTransport::new(
                world.a.clone(),
                service.hello.clone(),
                [(node("b"), client)],
                NativeGlobalNameConfig::new(1, Duration::from_secs(30)).unwrap(),
            ).unwrap();
            let first_round = within(&cx, transport.propagate_once(&cx)).await.unwrap();
            assert_eq!(first_round.acknowledged(), 1);
            assert!(world.b.whereis_global(&cx, "first").unwrap().is_some());

            let later = world.a.register_global(&cx, "later", "later.run").await.unwrap();
            let stale = within(&cx, transport.propagate_once(&cx)).await.unwrap();
            assert_eq!(stale.acknowledged(), 0);
            assert!(matches!(stale.peers[0].result, Err(NativeGlobalNameError::Registry(_))));
            assert!(world.b.whereis_global(&cx, "later").unwrap().is_none());
            assert!(world.a.whereis_global(&cx, "later").unwrap().is_some());
            assert_eq!(transport.in_flight(), 0);
            assert_eq!(within(&cx, proxy.join(&cx)).await.unwrap(), 2);
            assert_eq!(service.finish(&cx).await.accepted_connections(), 1);
            drop((first, later));
            world.finish(&cx).await;
        });
    }
}

#[test]
fn native_transport_does_not_borrow_io_authority_from_a_stronger_ambient_task() {
    for workers in [1, 2] {
        run_native(workers, |cx, _| async move {
            let world = World::new(&cx).await;
            let service = Service::start(&cx, world.b.clone(), true, RemoteProtocolVersion::V1).await;
            let transport = service.transport(world.a.clone());
            let restricted = {
                let _guard = cx.restrict::<asupersync::cx::NoCaps>().set_current_restricted();
                Cx::current().unwrap()
            };
            assert!(cx.capabilities().io);
            assert!(!restricted.capabilities().io);
            // restrict shares the live runtime handles; only its authority
            // is attenuated, while the ambient caller remains unrestricted.
            assert!(matches!(
                transport.lookup_owner(&restricted, &node("b"), 1, "backend").await,
                Err(NativeGlobalNameError::Configuration)
            ));
            assert!(matches!(
                transport.propagate_once(&restricted).await,
                Err(NativeGlobalNameError::Configuration)
            ));
            assert_eq!(transport.in_flight(), 0);
            assert_eq!(service.finish(&cx).await.accepted_connections(), 0);
            world.finish(&cx).await;
        });
    }
}
