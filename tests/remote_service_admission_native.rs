//! Inbound quotas through the actual V3 mTLS service, independent of outbound gates.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::remote_owned::{
    RemoteAdmissionLimits, RemoteAdmissionUsage, RemotePeerLimits, RemoteServiceAdmission,
};
use asupersync::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteComputationServiceHandle, RemoteComputationSessionStart,
    RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy, RemotePeerHello, RemoteProtocolVersion,
    RemoteServiceSessionEvent, RemoteServiceWireOutcome, RemoteServiceWireRequest,
    RemoteServiceWireResponse, RemoteTaskId, SpawnRequest,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::{Cx, types::CancelReason};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const NAMES: [&str; 2] = ["echo", "wait"];
struct Bytes;
impl HasSchema for Bytes {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("inbound-native.bytes.v1") }
}
#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cancelled: AtomicBool,
    release: AtomicBool,
    dropped: AtomicBool,
    factories: AtomicUsize,
    changed: Notify,
}
impl Witness {
    fn release(&self) { self.release.store(true, Ordering::Release); self.changed.notify_waiters(); }
}
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) { self.0.dropped.store(true, Ordering::Release); self.0.changed.notify_waiters(); }
}
struct Stop { service: RemoteComputationServiceHandle, witness: Arc<Witness> }
impl Drop for Stop {
    fn drop(&mut self) { self.witness.release(); let _ = self.service.begin_drain(); }
}

fn wire(cx: &Cx, hello: &RemotePeerHello, name: &str, bytes: &[u8], key: u128) -> RemoteServiceWireRequest {
    RemoteServiceWireRequest::from_spawn_request(hello.clone(), &SpawnRequest {
        remote_task_id: RemoteTaskId::next(), computation: ComputationName::new(name),
        input: RemoteInput::new(bytes.to_vec()), lease: Duration::from_secs(20),
        idempotency_key: IdempotencyKey::from_raw(key), budget: None,
        origin_node: hello.peer_node().clone(), origin_region: cx.region_id(), origin_task: cx.task_id(),
    }).unwrap()
}
async fn call(cx: &Cx, client: &RemoteComputationClient, hello: &RemotePeerHello, bytes: &[u8], key: u128)
    -> RemoteServiceWireResponse
{
    client.call(cx, &wire(cx, hello, "echo", bytes, key)).await.unwrap()
}
fn success(response: RemoteServiceWireResponse, expected: &[u8]) {
    assert!(matches!(response,
        RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Success(bytes), .. }
        if bytes == expected));
}
fn refused(response: RemoteServiceWireResponse, diagnostic: &str) {
    assert!(matches!(response,
        RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Failed(message), .. }
        if message == diagnostic));
}

#[derive(Clone, Copy)]
enum Case { Cancel, Disconnect, Limits, Cached }

fn exercise(workers: usize, case: Case) {
    let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
    let witness = Arc::new(Witness::default());
    let admission = RemoteServiceAdmission::new(
        RemoteAdmissionLimits { max_peers: 2, max_in_flight: 2, max_input_bytes: 64 },
        ["a", "b"].map(|peer| (NodeId::new(peer), RemotePeerLimits {
            max_in_flight: 1, max_input_bytes: 32, max_request_bytes: 32,
        })),
    ).unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let mut registry = RemoteComputationRegistry::new();
        let seen = Arc::clone(&witness);
        admission.register::<Bytes, Bytes, _, _>(&mut registry, "echo", ChildRegionSpec::inherit(), move |_, invocation| {
            seen.factories.fetch_add(1, Ordering::SeqCst);
            async move { Ok(RemoteOutcome::Success(invocation.into_request().input.into_data())) }
        }).unwrap();
        let seen = Arc::clone(&witness);
        admission.register::<Bytes, Bytes, _, _>(&mut registry, "wait", ChildRegionSpec::inherit(), move |body, _| {
            let seen = Arc::clone(&seen);
            seen.factories.fetch_add(1, Ordering::SeqCst);
            async move {
                let _retire = Retire(Arc::clone(&seen));
                let mut cancel = std::pin::pin!(body.cancelled());
                poll_fn(|task| {
                    let state = cancel.as_mut().poll(task);
                    if state.is_pending() && !seen.parked.swap(true, Ordering::AcqRel) { seen.changed.notify_waiters(); }
                    state
                }).await;
                assert!(body.checkpoint().is_err());
                seen.cancelled.store(true, Ordering::Release); seen.changed.notify_waiters();
                seen.changed.wait_until(|| seen.release.load(Ordering::Acquire)).await;
                // A late value is deliberately returned. The adapter must not
                // mistake this for uncancelled execution success.
                Ok(RemoteOutcome::Success(b"too late".to_vec()))
            }
        }).unwrap();

        let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
        let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
        let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(&cert).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone()).client_auth(ClientAuth::Required(roots)).build().unwrap();
        let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&cert).unwrap());
        let connector = TlsConnectorBuilder::new().add_root_certificate(&cert).identity(chain, key)
            .with_certificate_pins(pins.clone()).build().unwrap();
        let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, registry.schema_registry().clone());
        // Logical identities deliberately share the fixture certificate. This
        // tests separately provisioned quotas, not independent production PKI.
        for peer in ["a", "b", "unbudgeted"] { policy.grant_tls_peer(NodeId::new(peer), pins.clone(), NAMES).unwrap(); }
        let mut legacy = RemoteComputationRegistry::new();
        for name in NAMES {
            legacy.register::<Bytes, Bytes, _, _>(name, |_, _| async { Ok(RemoteOutcome::Success(Vec::new())) }).unwrap();
        }
        let legacy_policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, legacy.schema_registry().clone());
        let a = legacy_policy.hello_for(NodeId::new("a"));
        let b = legacy_policy.hello_for(NodeId::new("b"));
        assert_eq!(registry.schema_registry().fingerprint(), legacy.schema_registry().fingerprint());
        let service = RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new().with_max_connections(Some(8))
                .with_drain_timeout(Duration::from_secs(3))).await.unwrap();
        let address = service.local_addr().unwrap(); let operator = service.handle();
        let _stop = Stop { service: operator.clone(), witness: Arc::clone(&witness) };
        let mut serving = cx.spawn(move |server| async move { service.run(&server).await }).unwrap();
        let client = RemoteComputationClient::new(address, "localhost", connector,
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(8))).unwrap();

        match case {
            Case::Limits => {
                refused(call(&cx, &client, &a, &[7; 33], 1).await,
                    "remote service admission refused: remote request payload exceeds its admission limit");
                let unknown = legacy_policy.hello_for(NodeId::new("unbudgeted"));
                refused(call(&cx, &client, &unknown, b"x", 2).await,
                    "remote service admission refused: remote admission peer is not configured");
                assert_eq!(witness.factories.load(Ordering::SeqCst), 0, "authenticated refusals precede user factory");
                success(call(&cx, &client, &a, &[8; 32], 3).await, &[8; 32]);
                assert_eq!(witness.factories.load(Ordering::SeqCst), 1);
            }
            Case::Cached => {
                let first = wire(&cx, &a, "echo", b"saved", 17);
                success(client.call(&cx, &first).await.unwrap(), b"saved");
                assert_eq!(witness.factories.load(Ordering::SeqCst), 1);
                assert!(admission.close_admission());
                // A retained V3 terminal is not a new execution. Closing new
                // admission must neither run the factory nor erase that reply.
                let retry = wire(&cx, &a, "echo", b"saved", 17);
                success(client.call(&cx, &retry).await.unwrap(), b"saved");
                assert_eq!(witness.factories.load(Ordering::SeqCst), 1);
                refused(call(&cx, &client, &a, b"new", 18).await,
                    "remote service admission refused: remote executor admission is closed");
            }
            Case::Cancel | Case::Disconnect => {
                let request = wire(&cx, &a, "wait", &[1; 8], 21);
                let mut session = match client.start_session(&cx, &request).await.unwrap() {
                    RemoteComputationSessionStart::Running(session) => session,
                    RemoteComputationSessionStart::Terminal(response) => panic!("expected running V3 session: {response:?}"),
                    _ => panic!("unexpected session start variant"),
                };
                asupersync::time::timeout(cx.now(), Duration::from_secs(3),
                    witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire))).await.expect("actual parked handler");
                assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
                assert!(matches!(session.renew_lease(&cx, Duration::from_secs(20)).await.unwrap(),
                    RemoteServiceSessionEvent::LeaseRenewed { .. }), "renewal needs no execution slot");
                refused(call(&cx, &client, &a, b"x", 22).await,
                    "remote service admission refused: remote peer invocation limit reached");
                success(call(&cx, &client, &b, b"peer b", 23).await, b"peer b");
                assert_eq!(witness.factories.load(Ordering::SeqCst), 2);
                if matches!(case, Case::Cancel) {
                    let mut cancelling = Box::pin(session.cancel(&cx, CancelReason::user("inbound native cancellation")));
                    let mut observed = Box::pin(witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire)));
                    asupersync::time::timeout(cx.now(), Duration::from_secs(3), poll_fn(|task| {
                        assert!(cancelling.as_mut().poll(task).is_pending(), "terminal reply preceded deliberately withheld cleanup");
                        observed.as_mut().poll(task)
                    })).await.expect("V3 Cancel progresses at peer capacity");
                    drop(observed);
                    assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
                    refused(call(&cx, &client, &a, b"x", 24).await,
                        "remote service admission refused: remote peer invocation limit reached");
                    witness.release();
                    let response = cancelling.await.unwrap();
                    assert!(matches!(response, RemoteServiceWireResponse::Outcome {
                        outcome: RemoteServiceWireOutcome::Cancelled(_), ..
                    }), "late handler Success must not escape cancellation");
                } else {
                    drop(session); // Close actual TCP/TLS ownership, not a mock signal.
                    asupersync::time::timeout(cx.now(), Duration::from_secs(3),
                        witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire))).await.expect("disconnect reaches handler cancellation");
                    assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
                    refused(call(&cx, &client, &a, b"x", 24).await,
                        "remote service admission refused: remote peer invocation limit reached");
                    success(call(&cx, &client, &b, b"alive", 25).await, b"alive");
                    witness.release();
                }
                asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
                    while admission.usage().in_flight != 0 {
                        asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                    }
                }).await.expect("server owned cleanup returns admission");
                assert!(witness.dropped.load(Ordering::Acquire));
                success(call(&cx, &client, &a, b"again", 26).await, b"again");
            }
        }
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
        assert!(!cx.is_cancel_requested());
        let _ = operator.begin_drain();
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), serving.join(&cx)).await
            .expect("service drain timeout").expect("service task").expect("service result");
        assert_eq!(operator.active_connections(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn mtls_cancel_and_renewal_progress_at_capacity_until_handler_cleanup_finishes() {
    for workers in [1, 2] { exercise(workers, Case::Cancel); }
}
#[test]
fn mtls_disconnect_does_not_recycle_a_peer_slot_during_owned_cleanup() {
    for workers in [1, 2] { exercise(workers, Case::Disconnect); }
}
#[test]
fn mtls_byte_and_peer_limits_refuse_before_invoking_handlers() {
    for workers in [1, 2] { exercise(workers, Case::Limits); }
}
#[test]
fn v3_retained_terminal_replay_is_not_charged_as_a_new_execution() {
    for workers in [1, 2] { exercise(workers, Case::Cached); }
}

// Linux routes the complete 127/8 range locally, so distinct source addresses
// exercise the IP boundary without host network configuration or external peers.
#[cfg(target_os = "linux")]
mod source_ip_limits {
    use super::*;
    use asupersync::io::AsyncReadExt;
    use asupersync::net::{TcpSocket, TcpStream};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};

    async fn connect_from(cx: &Cx, address: SocketAddr, last_octet: u8) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind((Ipv4Addr::new(127, 0, 0, last_octet), 0).into()).unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), socket.connect(address))
            .await.expect("source-bound TCP connect deadline").unwrap()
    }

    async fn active(cx: &Cx, operator: &RemoteComputationServiceHandle, expected: usize) {
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
            while operator.active_connections() != expected {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        }).await.expect("connection registration/retirement deadline");
    }

    async fn refused_before_tls(cx: &Cx, mut stream: TcpStream) {
        let mut byte = [0; 1];
        let result = asupersync::time::timeout(
            cx.now(), Duration::from_secs(2), stream.read(&mut byte),
        ).await.expect("capacity refusal must precede the 30-second handshake deadline");
        assert!(matches!(result, Ok(0)) || matches!(result,
            Err(ref error) if matches!(error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)),
            "excess unauthenticated socket must be closed: {result:?}");
    }

    struct ForceClose(RemoteComputationServiceHandle);
    impl Drop for ForceClose {
        fn drop(&mut self) { self.0.force_close(); }
    }

    fn exercise_limit(workers: usize, per_ip_limit: Option<u32>) {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let factories = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&factories);
            let mut registry = RemoteComputationRegistry::new();
            registry.register::<Bytes, Bytes, _, _>("echo", move |_, invocation| {
                seen.fetch_add(1, Ordering::SeqCst);
                async move { Ok(RemoteOutcome::Success(invocation.into_request().input.into_data())) }
            }).unwrap();

            let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
            let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
            let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(&cert).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
                .client_auth(ClientAuth::Required(roots)).build().unwrap();
            let mut pins = CertificatePinSet::new();
            pins.add(CertificatePin::compute_spki_sha256(&cert).unwrap());
            let connector = TlsConnectorBuilder::new().add_root_certificate(&cert).identity(chain, key)
                .with_certificate_pins(pins.clone()).build().unwrap();
            let mut policy = RemotePeerAdmissionPolicy::new(
                RemoteProtocolVersion::V3, registry.schema_registry().clone(),
            );
            policy.grant_tls_peer(NodeId::new("source-ip-origin"), pins, ["echo"]).unwrap();
            let hello = policy.hello_for(NodeId::new("source-ip-origin"));
            let defaults = RemoteComputationServiceConfig::new();
            assert_eq!(defaults.max_connections_per_ip(), None);
            let config = defaults.with_max_connections(Some(3))
                .with_max_connections_per_ip(per_ip_limit)
                .with_initial_frame_timeout(Duration::from_secs(30))
                .with_drain_timeout(Duration::from_secs(3));
            assert_eq!(config.max_connections_per_ip(), per_ip_limit);
            let service = RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry, config)
                .await.unwrap();
            let address = service.local_addr().unwrap();
            let operator = service.handle();
            let _stop = ForceClose(operator.clone());
            let mut serving = cx.spawn(move |server| async move { service.run(&server).await }).unwrap();

            let (accepted, rejected, completed) = match per_ip_limit {
                Some(0) => {
                    refused_before_tls(&cx, connect_from(&cx, address, 1).await).await;
                    active(&cx, &operator, 0).await;
                    (1, 1, 0)
                }
                None => {
                    // Existing behavior is preserved: both connections from
                    // one IP can remain in TLS while the global cap has room.
                    let first = connect_from(&cx, address, 1).await;
                    active(&cx, &operator, 1).await;
                    let second = connect_from(&cx, address, 1).await;
                    active(&cx, &operator, 2).await;
                    drop(first);
                    drop(second);
                    active(&cx, &operator, 0).await;
                    (2, 0, 0)
                }
                Some(1) => {
                    let first = connect_from(&cx, address, 1).await;
                    active(&cx, &operator, 1).await;
                    refused_before_tls(&cx, connect_from(&cx, address, 1).await).await;
                    assert_eq!(operator.active_connections(), 1);

                    // A different IP retains access to the listener's other
                    // slots while the first peer never sends a ClientHello.
                    let other_ip = connect_from(&cx, address, 2).await;
                    active(&cx, &operator, 2).await;
                    refused_before_tls(&cx, connect_from(&cx, address, 1).await).await;
                    assert_eq!(operator.active_connections(), 2);
                    assert_eq!(factories.load(Ordering::SeqCst), 0);

                    drop(first);
                    active(&cx, &operator, 1).await;
                    // The retired address can immediately do authenticated
                    // work while the other address still holds its own slot.
                    let client = RemoteComputationClient::new(address, "localhost", connector,
                        RemoteComputationClientConfig::new().with_max_attempts(1)
                            .with_connect_timeout(Duration::from_secs(2))
                            .with_attempt_timeout(Duration::from_secs(5))).unwrap();
                    success(call(&cx, &client, &hello, b"recovered-source-ip", 901).await,
                        b"recovered-source-ip");
                    active(&cx, &operator, 1).await;
                    drop(other_ip);
                    active(&cx, &operator, 0).await;
                    (5, 2, 1)
                }
                _ => unreachable!("test cases use None, zero, or one"),
            };
            assert_eq!(factories.load(Ordering::SeqCst), completed as usize);
            assert!(operator.begin_drain());
            let report = asupersync::time::timeout(cx.now(), Duration::from_secs(3),
                poll_fn(|task| serving.poll_join(task))).await
                .expect("source-IP listener drains").expect("service task").expect("service result");
            assert_eq!(report.accepted_connections(), accepted);
            assert_eq!(report.capacity_rejections(), rejected);
            assert_eq!(report.completed_connections(), completed);
            assert_eq!(report.panicked_connections(), 0);
            assert_eq!(operator.active_connections(), 0);
            assert!(!cx.is_cancel_requested());
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }

    #[test]
    fn pre_tls_source_ip_limit_preserves_other_peers_and_recycles_closed_slots() {
        for workers in [1, 2] { exercise_limit(workers, Some(1)); }
    }

    #[test]
    fn source_ip_limit_is_opt_in_and_zero_refuses_without_running_a_handler() {
        for workers in [1, 2] {
            exercise_limit(workers, None);
            exercise_limit(workers, Some(0));
        }
    }
}
