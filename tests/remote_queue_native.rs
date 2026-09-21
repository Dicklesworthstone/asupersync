//! Actual V3 mTLS queueing, cancellation and cleanup-held admission.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::remote_owned::{RemoteAdmissionLimits, RemoteAdmissionUsage,
    RemotePeerLimits, RemoteQueueLimits, RemoteQueueUsage, RemoteServiceAdmission};
use asupersync::remote::{ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteComputationServiceHandle, RemoteComputationSessionStart,
    RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy, RemotePeerHello, RemoteProtocolVersion,
    RemoteServiceSessionEvent, RemoteServiceWireOutcome,
    RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId, SpawnRequest};
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::Notify;
use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet,
    ClientAuth, PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder};
use asupersync::{Cx, types::CancelReason};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

struct Bytes;
impl HasSchema for Bytes {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("queued-native.bytes.v1") }
}
#[derive(Default)]
struct Witness {
    parked: AtomicBool, cancelled: AtomicBool, release: AtomicBool, dropped: AtomicBool,
    factories: AtomicUsize, changed: Notify,
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
        input: RemoteInput::new(bytes.to_vec()), lease: Duration::from_secs(30),
        idempotency_key: IdempotencyKey::from_raw(key), budget: None,
        origin_node: hello.peer_node().clone(), origin_region: cx.region_id(), origin_task: cx.task_id(),
    }).unwrap()
}
fn success(response: RemoteServiceWireResponse, expected: &[u8]) {
    assert!(matches!(response, RemoteServiceWireResponse::Outcome {
        outcome: RemoteServiceWireOutcome::Success(bytes), ..
    } if bytes == expected));
}
fn refused(response: RemoteServiceWireResponse, expected: &str) {
    assert!(matches!(response, RemoteServiceWireResponse::Outcome {
        outcome: RemoteServiceWireOutcome::Failed(message), ..
    } if message == expected));
}
fn cancelled(response: RemoteServiceWireResponse) {
    assert!(matches!(response, RemoteServiceWireResponse::Outcome {
        outcome: RemoteServiceWireOutcome::Cancelled(_), ..
    }));
}
async fn queue_count(cx: &Cx, admission: &RemoteServiceAdmission, expected: usize) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(4), async {
        while admission.queue_usage().waiters != expected {
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }).await.expect("actual server queue state");
}

#[derive(Clone, Copy)]
enum Case { AfterDrain, CancelQueued, DisconnectQueued, DeadlineQueued }
fn exercise(workers: usize, case: Case) {
    let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
    let witness = Arc::new(Witness::default());
    let admission = RemoteServiceAdmission::new_queued(
        RemoteAdmissionLimits { max_peers: 2, max_in_flight: 2, max_input_bytes: 64 },
        ["a", "b"].map(|peer| (NodeId::new(peer), RemotePeerLimits {
            max_in_flight: 1, max_input_bytes: 32, max_request_bytes: 32,
        })),
        RemoteQueueLimits { max_waiters: 1, max_input_bytes: 16,
            max_waiters_per_peer: 1, max_input_bytes_per_peer: 16 },
    ).unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let mut registry = RemoteComputationRegistry::new();
        let wait_timeout = if matches!(case, Case::DeadlineQueued) { Duration::from_secs(2) }
            else { Duration::from_secs(15) };
        let seen = Arc::clone(&witness);
        admission.register_waiting::<Bytes, Bytes, _, _>(&mut registry, "echo",
            ChildRegionSpec::inherit(), wait_timeout, move |_, invocation| {
                seen.factories.fetch_add(1, Ordering::SeqCst);
                async move { Ok(RemoteOutcome::Success(invocation.into_request().input.into_data())) }
            }).unwrap();
        let seen = Arc::clone(&witness);
        admission.register_waiting::<Bytes, Bytes, _, _>(&mut registry, "wait",
            ChildRegionSpec::inherit(), wait_timeout, move |body, _| {
                let seen = Arc::clone(&seen); seen.factories.fetch_add(1, Ordering::SeqCst);
                async move {
                    let _retire = Retire(Arc::clone(&seen));
                    let mut cancel = std::pin::pin!(body.cancelled());
                    poll_fn(|task| {
                        let state = cancel.as_mut().poll(task);
                        if state.is_pending() && !seen.parked.swap(true, Ordering::AcqRel) {
                            seen.changed.notify_waiters();
                        }
                        state
                    }).await;
                    assert!(body.checkpoint().is_err());
                    seen.cancelled.store(true, Ordering::Release); seen.changed.notify_waiters();
                    seen.changed.wait_until(|| seen.release.load(Ordering::Acquire)).await;
                    Ok(RemoteOutcome::Cancelled(body.cancel_reason().unwrap()))
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
        for peer in ["a", "b"] { policy.grant_tls_peer(NodeId::new(peer), pins.clone(), ["echo", "wait"]).unwrap(); }
        // Independently authenticated logical sessions share one fixture certificate.
        // This tests logical quotas, not independently administered physical hosts.
        let mut ordinary = RemoteComputationRegistry::new();
        for name in ["echo", "wait"] {
            ordinary.register::<Bytes, Bytes, _, _>(name, |_, _| async { Ok(RemoteOutcome::Success(Vec::new())) }).unwrap();
        }
        assert_eq!(ordinary.schema_registry().fingerprint(), registry.schema_registry().fingerprint());
        let hello = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, ordinary.schema_registry().clone());
        let a = hello.hello_for(NodeId::new("a")); let b = hello.hello_for(NodeId::new("b"));
        let service = RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new().with_max_connections(Some(8))
                .with_drain_timeout(Duration::from_secs(3))).await.unwrap();
        let address = service.local_addr().unwrap(); let operator = service.handle();
        let _stop = Stop { service: operator.clone(), witness: Arc::clone(&witness) };
        let mut serving = cx.spawn(move |server| async move { service.run(&server).await }).unwrap();
        let client = RemoteComputationClient::new(address, "localhost", connector,
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(20))).unwrap();
        let mut first = match client.start_session(&cx, &wire(&cx, &a, "wait", &[1; 8], 1)).await.unwrap() {
            RemoteComputationSessionStart::Running(session) => session,
            RemoteComputationSessionStart::Terminal(response) => panic!("first session: {response:?}"),
            _ => panic!("unexpected session start variant"),
        };
        asupersync::time::timeout(cx.now(), Duration::from_secs(3),
            witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire))).await.expect("parked live handler");
        let second = match client.start_session(&cx, &wire(&cx, &a, "echo", b"queued", 2)).await.unwrap() {
            RemoteComputationSessionStart::Running(session) => session,
            RemoteComputationSessionStart::Terminal(response) => panic!("queued session: {response:?}"),
            _ => panic!("unexpected session start variant"),
        };
        let mut second = Some(second);
        queue_count(&cx, &admission, 1).await;
        assert_eq!(admission.queue_usage(), RemoteQueueUsage { waiters: 1, input_bytes: 6 });
        assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
        assert_eq!(witness.factories.load(Ordering::SeqCst), 1, "queue admission is not handler execution");
        refused(client.call(&cx, &wire(&cx, &a, "echo", b"overflow", 3)).await.unwrap(),
            "remote service admission refused: remote wait queue limit reached: waiters");
        success(client.call(&cx, &wire(&cx, &b, "echo", b"other peer", 4)).await.unwrap(), b"other peer");
        assert_eq!(witness.factories.load(Ordering::SeqCst), 2);
        assert_eq!(admission.queue_usage().waiters, 1);
        assert!(matches!(first.renew_lease(&cx, Duration::from_secs(30)).await.unwrap(),
            RemoteServiceSessionEvent::LeaseRenewed { .. }), "full waiting/data quotas do not gate control");

        match case {
            Case::AfterDrain => {
                {
                    let mut cancel = Box::pin(first.cancel(&cx, CancelReason::user("release primary after cleanup")));
                    let mut observed = Box::pin(witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire)));
                    asupersync::time::timeout(cx.now(), Duration::from_secs(3), poll_fn(|task| {
                        assert!(cancel.as_mut().poll(task).is_pending(), "terminal preceded held cleanup");
                        observed.as_mut().poll(task)
                    })).await.expect("first handler observed cancellation");
                    drop(observed);
                    assert_eq!(admission.usage().in_flight, 1);
                    assert_eq!(admission.queue_usage().waiters, 1);
                    assert_eq!(witness.factories.load(Ordering::SeqCst), 2);
                    witness.release(); cancelled(cancel.await.unwrap());
                }
                let response = second.take().unwrap().wait(&cx).await.unwrap();
                success(response, b"queued");
                assert_eq!(witness.factories.load(Ordering::SeqCst), 3);
            }
            Case::CancelQueued => {
                cancelled(second.take().unwrap().cancel(&cx, CancelReason::user("cancel queued only")).await.unwrap());
                queue_count(&cx, &admission, 0).await;
                assert_eq!(witness.factories.load(Ordering::SeqCst), 2);
                assert!(!witness.cancelled.load(Ordering::Acquire));
                witness.release(); cancelled(first.cancel(&cx, CancelReason::user("finish primary")).await.unwrap());
            }
            Case::DisconnectQueued => {
                drop(second.take());
                queue_count(&cx, &admission, 0).await;
                assert_eq!(witness.factories.load(Ordering::SeqCst), 2);
                assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
                witness.release(); cancelled(first.cancel(&cx, CancelReason::user("finish primary")).await.unwrap());
            }
            Case::DeadlineQueued => {
                let response = second.take().unwrap().wait(&cx).await.unwrap();
                refused(response, "remote service admission refused: remote reservation deadline reached");
                assert_eq!(admission.queue_usage(), RemoteQueueUsage::default());
                assert_eq!(witness.factories.load(Ordering::SeqCst), 2);
                assert!(!witness.cancelled.load(Ordering::Acquire));
                witness.release(); cancelled(first.cancel(&cx, CancelReason::user("finish primary")).await.unwrap());
            }
        }
        drop(second);
        queue_count(&cx, &admission, 0).await;
        assert!(witness.dropped.load(Ordering::Acquire));
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
        assert_eq!(admission.queue_usage(), RemoteQueueUsage::default());
        assert!(!cx.is_cancel_requested());
        let _ = operator.begin_drain();
        asupersync::time::timeout(cx.now(), Duration::from_secs(4), serving.join(&cx)).await
            .expect("service drain deadline").expect("service join").expect("service result");
        assert_eq!(operator.active_connections(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn queued_mtls_work_starts_only_after_cancelled_primary_finishes_cleanup() {
    for workers in [1, 2] { exercise(workers, Case::AfterDrain); }
}
#[test]
fn queued_v3_cancel_removes_waiter_without_invoking_user_factory() {
    for workers in [1, 2] { exercise(workers, Case::CancelQueued); }
}
#[test]
fn queued_tls_disconnect_retires_waiting_bytes_without_execution() {
    for workers in [1, 2] { exercise(workers, Case::DisconnectQueued); }
}
#[test]
fn queued_service_deadline_refuses_without_cancelling_active_peer_work() {
    for workers in [1, 2] { exercise(workers, Case::DeadlineQueued); }
}
