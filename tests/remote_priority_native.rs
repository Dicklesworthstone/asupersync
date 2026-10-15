//! Application priority through the actual V3 mTLS registry and bounded queue.
//! Server registrations choose classes; no priority field is added to the wire.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::remote_owned::{RemoteAdmissionLimits, RemoteAdmissionUsage,
    RemotePeerLimits, RemotePriority, RemotePriorityPolicy, RemoteQueueLimits, RemoteQueueUsage,
    RemoteServiceAdmission};
use asupersync::remote::{ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationInvocation, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemoteComputationSessionStart, RemoteError, RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy,
    RemotePeerHello, RemoteProtocolVersion, RemoteServiceSessionEvent,
    RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId, SpawnRequest};
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::Notify;
use asupersync::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder};
use asupersync::{Cx, types::CancelReason};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::task::Poll;
use std::time::Duration;

const NAMES: [&str; 4] = ["background", "normal", "urgent", "immediate"];
struct Bytes;
impl HasSchema for Bytes {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("priority-native.bytes.v1") }
}
struct Witness {
    order: Mutex<Vec<u8>>,
    allowed: [AtomicBool; 8],
    parked: [AtomicBool; 8],
    dropped: AtomicUsize,
    changed: Notify,
}
impl Witness {
    fn new() -> Self {
        Self { order: Mutex::new(Vec::new()), allowed: std::array::from_fn(|_| AtomicBool::new(false)),
            parked: std::array::from_fn(|_| AtomicBool::new(false)), dropped: AtomicUsize::new(0), changed: Notify::new() }
    }
    fn release(&self, id: u8) {
        self.allowed[usize::from(id)].store(true, Ordering::Release); self.changed.notify_waiters();
    }
}
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) { self.0.dropped.fetch_add(1, Ordering::SeqCst); }
}
struct Stop { operator: RemoteComputationServiceHandle, witness: Arc<Witness> }
impl Drop for Stop {
    fn drop(&mut self) {
        for allowed in &self.witness.allowed { allowed.store(true, Ordering::Release); }
        self.witness.changed.notify_waiters(); let _ = self.operator.begin_drain();
    }
}

async fn work(cx: Cx, invocation: RemoteComputationInvocation, witness: Arc<Witness>)
    -> Result<RemoteOutcome, RemoteError>
{
    let bytes = invocation.into_request().input.into_data();
    if bytes.len() != 2 || usize::from(bytes[0]) >= witness.allowed.len() {
        return Ok(RemoteOutcome::Failed("invalid test input".to_owned()));
    }
    let id = bytes[0]; let index = usize::from(id);
    let _retire = Retire(Arc::clone(&witness));
    witness.order.lock().push(id);
    // Byte 1 is deliberately 255 for EVERY class. It cannot choose priority.
    let mut ready = std::pin::pin!(witness.changed.wait_until(|| witness.allowed[index].load(Ordering::Acquire)));
    let mut cancel = std::pin::pin!(cx.cancelled());
    poll_fn(|task| {
        if cancel.as_mut().poll(task).is_ready() || ready.as_mut().poll(task).is_ready() { return Poll::Ready(()); }
        if !witness.parked[index].swap(true, Ordering::AcqRel) { witness.changed.notify_waiters(); }
        Poll::Pending
    }).await;
    if cx.checkpoint().is_err() {
        return Ok(RemoteOutcome::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::parent_cancelled)));
    }
    Ok(RemoteOutcome::Success(bytes))
}
fn wire(cx: &Cx, hello: &RemotePeerHello, name: &str, id: u8, key: u128) -> RemoteServiceWireRequest {
    RemoteServiceWireRequest::from_spawn_request(hello.clone(), &SpawnRequest {
        remote_task_id: RemoteTaskId::next(), computation: ComputationName::new(name),
        input: RemoteInput::new(vec![id, 255]), lease: Duration::from_secs(30),
        idempotency_key: IdempotencyKey::from_raw(key), budget: None,
        origin_node: hello.peer_node().clone(), origin_region: cx.region_id(), origin_task: cx.task_id(),
    }).unwrap()
}
fn success(response: RemoteServiceWireResponse, id: u8) {
    assert!(matches!(response, RemoteServiceWireResponse::Outcome {
        outcome: RemoteServiceWireOutcome::Success(bytes), ..
    } if bytes == [id, 255]));
}
fn refusal(response: RemoteServiceWireResponse, expected: &str) {
    assert!(matches!(response, RemoteServiceWireResponse::Outcome {
        outcome: RemoteServiceWireOutcome::Failed(message), ..
    } if message == expected));
}
async fn parked(cx: &Cx, witness: &Witness, id: u8) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), witness.changed.wait_until(|| {
        witness.parked[usize::from(id)].load(Ordering::Acquire)
    })).await.expect("actual handler Pending before advancing the schedule");
}
async fn queued(cx: &Cx, admission: &RemoteServiceAdmission, count: usize) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while admission.queue_usage().waiters != count {
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }).await.expect("actual server queue ownership");
    assert_eq!(admission.queue_usage(), RemoteQueueUsage { waiters: count, input_bytes: 2 * count });
}

fn exercise(workers: usize, ordering: bool) {
    let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
    let witness = Arc::new(Witness::new());
    let admission = RemoteServiceAdmission::new_prioritized(
        RemoteAdmissionLimits { max_peers: 1, max_in_flight: 1, max_input_bytes: 2 },
        [(NodeId::new("origin"), RemotePeerLimits { max_in_flight: 1, max_input_bytes: 2, max_request_bytes: 2 })],
        RemoteQueueLimits { max_waiters: 4, max_input_bytes: 8, max_waiters_per_peer: 4, max_input_bytes_per_peer: 8 },
        RemotePriorityPolicy { max_bypass: 2 },
    ).unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let mut registry = RemoteComputationRegistry::new();
        for (name, priority) in [("background", RemotePriority::Background), ("normal", RemotePriority::Normal),
            ("urgent", RemotePriority::Urgent)]
        {
            let seen = Arc::clone(&witness);
            let handler = move |body, invocation| work(body, invocation, Arc::clone(&seen));
            if priority == RemotePriority::Normal {
                admission.register_waiting::<Bytes, Bytes, _, _>(&mut registry, name, ChildRegionSpec::inherit(),
                    Duration::from_secs(20), handler).unwrap(); // Existing API shares this same queue.
            } else {
                admission.register_waiting_with_priority::<Bytes, Bytes, _, _>(&mut registry, name, ChildRegionSpec::inherit(),
                    Duration::from_secs(20), priority, handler).unwrap();
            }
        }
        let seen = Arc::clone(&witness);
        admission.register::<Bytes, Bytes, _, _>(&mut registry, "immediate", ChildRegionSpec::inherit(),
            move |body, invocation| work(body, invocation, Arc::clone(&seen))).unwrap();
        let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
        let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
        let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(&cert).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone()).client_auth(ClientAuth::Required(roots)).build().unwrap();
        let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&cert).unwrap());
        let connector = TlsConnectorBuilder::new().add_root_certificate(&cert).identity(chain, key)
            .with_certificate_pins(pins.clone()).build().unwrap();
        let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, registry.schema_registry().clone());
        // Shared fixture certificate: logical authorization tests, not independent PKI.
        for peer in ["origin", "unbudgeted"] { policy.grant_tls_peer(NodeId::new(peer), pins.clone(), NAMES).unwrap(); }
        let mut legacy = RemoteComputationRegistry::new();
        for name in NAMES { legacy.register::<Bytes, Bytes, _, _>(name,
            |_, _| async { Ok(RemoteOutcome::Success(Vec::new())) }).unwrap(); }
        assert_eq!(registry.schema_registry().fingerprint(), legacy.schema_registry().fingerprint());
        let hello_policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, legacy.schema_registry().clone());
        let hello = hello_policy.hello_for(NodeId::new("origin"));
        let service = RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new().with_max_connections(Some(8))
                .with_drain_timeout(Duration::from_secs(3))).await.unwrap();
        let address = service.local_addr().unwrap(); let operator = service.handle();
        let _stop = Stop { operator: operator.clone(), witness: Arc::clone(&witness) };
        let mut serving = cx.spawn(move |server| async move { service.run(&server).await }).unwrap();
        let client = RemoteComputationClient::new(address, "localhost", connector,
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(20))).unwrap();
        let requests: &[(u8, &str)] = if ordering {
            &[(0, "normal"), (1, "background"), (2, "normal"), (3, "urgent"), (4, "urgent")]
        } else { &[(0, "normal"), (1, "background"), (2, "urgent"), (3, "urgent")] };
        let mut sessions = Vec::new();
        for &(id, name) in requests {
            let session = match client.start_session(&cx, &wire(&cx, &hello, name, id, 100 + u128::from(id))).await.unwrap() {
                RemoteComputationSessionStart::Running(session) => session,
                RemoteComputationSessionStart::Terminal(response) => panic!("expected accepted session: {response:?}"),
                _ => panic!("unexpected session start variant"),
            };
            sessions.push(Some(session));
            if id == 0 { parked(&cx, &witness, 0).await; }
            else { queued(&cx, &admission, usize::from(id)).await; }
        }
        assert_eq!(*witness.order.lock(), [0]);
        assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 2 });
        refusal(client.call(&cx, &wire(&cx, &hello, "immediate", 6, 206)).await.unwrap(),
            "remote service admission refused: remote admission is reserved for queued work");
        let unknown = hello_policy.hello_for(NodeId::new("unbudgeted"));
        refusal(client.call(&cx, &wire(&cx, &unknown, "urgent", 7, 207)).await.unwrap(),
            "remote service admission refused: remote admission peer is not configured");

        if ordering {
            refusal(client.call(&cx, &wire(&cx, &hello, "urgent", 6, 306)).await.unwrap(),
                "remote service admission refused: remote wait queue limit reached: waiters");
            let sequence = [0_u8, 3, 4, 1, 2, 5];
            for (position, &id) in sequence.iter().enumerate() {
                parked(&cx, &witness, id).await;
                assert_eq!(*witness.order.lock(), sequence[..=position]);
                if id == 4 {
                    // A fresh Urgent arrives after two bypasses of Background.
                    // It must not reset that older request's promotion history.
                    let extra = match client.start_session(&cx, &wire(&cx, &hello, "urgent", 5, 105)).await.unwrap() {
                        RemoteComputationSessionStart::Running(session) => session,
                        RemoteComputationSessionStart::Terminal(response) => panic!("expected queued urgent: {response:?}"),
                        _ => panic!("unexpected session start variant"),
                    };
                    sessions.push(Some(extra)); queued(&cx, &admission, 3).await;
                }
                witness.release(id);
                let response = sessions[usize::from(id)].take().unwrap().wait(&cx).await.unwrap();
                success(response, id);
            }
            assert_eq!(witness.dropped.load(Ordering::SeqCst), 6);
        } else {
            assert!(matches!(sessions[2].as_mut().unwrap().renew_lease(&cx, Duration::from_secs(30)).await.unwrap(),
                RemoteServiceSessionEvent::LeaseRenewed { .. }));
            let response = sessions[2].take().unwrap().cancel(&cx, CancelReason::user("queued urgent cancelled")).await.unwrap();
            assert!(matches!(response, RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Cancelled(_), .. }));
            drop(sessions[2].take()); queued(&cx, &admission, 2).await;
            drop(sessions[3].take()); queued(&cx, &admission, 1).await; // Actual TLS disconnect.
            assert_eq!(*witness.order.lock(), [0], "cancelled/disconnected queued factories must not run");
            assert_eq!(admission.usage().in_flight, 1);
            for id in [0_u8, 1] {
                parked(&cx, &witness, id).await; witness.release(id);
                let response = sessions[usize::from(id)].take().unwrap().wait(&cx).await.unwrap();
                success(response, id);
            }
            assert_eq!(*witness.order.lock(), [0, 1]); assert_eq!(witness.dropped.load(Ordering::SeqCst), 2);
        }
        queued(&cx, &admission, 0).await;
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
            while admission.usage().in_flight != 0 { asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await; }
        }).await.expect("complete coordinator destruction returns active credit");
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
        assert!(!cx.is_cancel_requested());
        let _ = operator.begin_drain();
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), serving.join(&cx)).await
            .expect("listener drain deadline").expect("service task").expect("service outcome");
        assert_eq!(operator.active_connections(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn native_server_priorities_overtake_then_promote_without_extra_capacity() {
    for workers in [1, 2] { exercise(workers, true); }
}
#[test]
fn native_urgent_waiters_remain_cancellable_without_control_or_identity_privilege() {
    for workers in [1, 2] { exercise(workers, false); }
}
