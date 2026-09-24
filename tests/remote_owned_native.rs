//! Real V3 mTLS remote execution through checked child-region proxy ownership.
//! Service tests use the production listener; silent-peer regressions use actual
//! V3 frames over mTLS and deliberately withhold the peer's terminal response.
#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::remote_owned::{
    RemoteAdmissionError, RemoteAdmissionLimits, RemoteAdmissionUsage, RemoteExecutor,
    RemoteExecutorError, RemoteLeaseSettlement, RemotePeerLimits, RemoteRunConfig, RemoteRunReport,
    RemoteRunTrigger, run_remote,
};
use asupersync::distributed::{ComputationSchemaRegistry, HasSchema, SchemaDescriptor};
use asupersync::observability::diagnostics::Reason;
use asupersync::remote::{
    ComputationName, LeaseRenewal, MessageEnvelope, NativeRemoteRoute, NativeRemoteRuntime,
    NativeRemoteRuntimeConfig, NodeId, RemoteCap, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteComputationServiceHandle, RemoteError, RemoteInput,
    RemoteMessage, RemoteOutcome, RemotePeerAdmissionPolicy, RemotePeerHello,
    RemoteProtocolVersion, RemoteRuntime, RemoteServiceSessionCommand, RemoteServiceSessionEvent,
    RemoteServiceWireRequest, RemoteTaskId, RemoteTaskState, spawn_remote,
};
use asupersync::runtime::{RuntimeBuilder, RuntimeHandle, TaskHandle};
use asupersync::stream::StreamExt;
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::types::{CancelReason, RegionId, TaskId};
use asupersync::{Cx, Outcome};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct Request;
struct Response;
impl HasSchema for Request {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("owned-remote-test-request-v1") }
}
impl HasSchema for Response {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("owned-remote-test-response-v1") }
}
#[derive(Default)]
struct Witness {
    origin: Mutex<Option<(RegionId, TaskId)>>,
    parked: AtomicBool,
    cancelled: AtomicBool,
    release: AtomicBool,
    dropped: AtomicBool,
    changed: Notify,
}
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) { self.0.dropped.store(true, Ordering::Release); self.0.changed.notify_waiters(); }
}
struct Stop {
    service: RemoteComputationServiceHandle,
    remote: Arc<NativeRemoteRuntime>,
    witness: Arc<Witness>,
}
impl Drop for Stop {
    fn drop(&mut self) {
        // A failed assertion must not strand deliberately withheld cleanup.
        self.witness.release.store(true, Ordering::Release);
        self.witness.changed.notify_waiters();
        let _ = self.remote.begin_drain(); let _ = self.service.begin_drain();
    }
}
#[derive(Clone, Copy)]
enum Case { Success, Cancel, Deadline, Drop }
fn config() -> RemoteRunConfig {
    RemoteRunConfig { timeout: Duration::from_secs(5), child: ChildRegionSpec::inherit() }
}

fn exercise(workers: usize, case: Case) {
    exercise_with_admission(workers, case, false);
}

async fn invoke(
    executor: Option<&RemoteExecutor>, cx: &Cx, destination: &str, name: &str,
    input: RemoteInput, config: RemoteRunConfig,
) -> Result<RemoteRunReport, RemoteExecutorError> {
    match executor {
        Some(executor) => executor.run(cx, NodeId::new(destination), ComputationName::new(name), input, config).await,
        None => Ok(run_remote(cx, NodeId::new(destination), ComputationName::new(name), input, config).await?),
    }
}

fn exercise_with_admission(workers: usize, case: Case, bounded: bool) {
    let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
    let runtime_handle = runtime.handle();
    // Keep feature-sensitive Diagnostics on this owner thread, never in a Send task.
    let diagnostics = runtime.diagnostics();
    let witness = Arc::new(Witness::default());
    runtime.block_on(async {
        let base = Cx::current().unwrap();
        let mut registry = RemoteComputationRegistry::new();
        registry.register::<Request, Response, _, _>("echo", |_, request| async move {
            Ok(RemoteOutcome::Success(request.request().input.data().to_vec()))
        }).unwrap();
        let seen = Arc::clone(&witness);
        registry.register::<Request, Response, _, _>("wait", move |cx, request| {
            let seen = Arc::clone(&seen);
            async move {
                let _retire = Retire(Arc::clone(&seen));
                *seen.origin.lock() = Some((request.request().origin_region, request.request().origin_task));
                let mut cancelled = std::pin::pin!(cx.cancelled());
                poll_fn(|task| {
                    let result = cancelled.as_mut().poll(task);
                    if result.is_pending() && !seen.parked.swap(true, Ordering::AcqRel) {
                        seen.changed.notify_waiters();
                    }
                    result
                }).await;
                assert!(cx.checkpoint().is_err());
                seen.cancelled.store(true, Ordering::Release); seen.changed.notify_waiters();
                // Deliberately withhold terminal cleanup. Merely sending Cancel
                // must not allow the origin's checked child to close successfully.
                seen.changed.wait_until(|| seen.release.load(Ordering::Acquire)).await;
                Ok(RemoteOutcome::Cancelled(cx.cancel_reason().expect("attributed cancellation")))
            }
        }).unwrap();
        let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap().remove(0);
        let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
        let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(&cert).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
            .client_auth(ClientAuth::Required(roots)).build().unwrap();
        let mut pins = CertificatePinSet::new(); pins.add(CertificatePin::compute_spki_sha256(&cert).unwrap());
        let connector = TlsConnectorBuilder::new().add_root_certificate(&cert).identity(chain, key)
            .with_certificate_pins(pins.clone()).build().unwrap();
        let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V3, registry.schema_registry().clone());
        policy.grant_tls_peer(NodeId::new("origin"), pins, ["echo", "wait"]).unwrap();
        let hello = policy.hello_for(NodeId::new("origin"));
        let service = RemoteComputationService::bind("127.0.0.1:0", acceptor, policy, registry,
            RemoteComputationServiceConfig::new().with_max_connections(Some(4))
                .with_drain_timeout(Duration::from_secs(3))).await.unwrap();
        let address = service.local_addr().unwrap(); let operator = service.handle();
        let mut serving = base.spawn(move |cx| async move { service.run(&cx).await }).unwrap();
        let client = RemoteComputationClient::new(address, "localhost", connector,
            RemoteComputationClientConfig::new().with_max_attempts(1)
                .with_connect_timeout(Duration::from_secs(2)).with_attempt_timeout(Duration::from_secs(5))).unwrap();
        let remote = Arc::new(NativeRemoteRuntime::with_config(runtime_handle,
            NodeId::new("origin"), [
                NativeRemoteRoute::new(NodeId::new("worker"), hello.clone(), client.clone()),
                // Independent LOGICAL peer quota using the same test listener.
                // This does not claim independent physical hosts or PKI identities.
                NativeRemoteRoute::new(NodeId::new("other"), hello, client),
            ],
            NativeRemoteRuntimeConfig::new().with_max_in_flight(4).with_drain_timeout(Duration::from_secs(3))).unwrap());
        let _stop = Stop { service: operator.clone(), remote: Arc::clone(&remote), witness: Arc::clone(&witness) };
        let cx = base.with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin"))
            .with_default_lease(Duration::from_secs(20)).with_runtime(Arc::clone(&remote) as Arc<dyn RemoteRuntime>));
        let executor = bounded.then(|| RemoteExecutor::new(
            RemoteAdmissionLimits { max_peers: 2, max_in_flight: 2, max_input_bytes: 64 },
            ["worker", "other"].map(|name| (NodeId::new(name), RemotePeerLimits {
                max_in_flight: 1, max_input_bytes: 32, max_request_bytes: 32,
            })),
        ).unwrap());
        let work_input = if bounded { vec![1; 8] } else { Vec::new() };

        if matches!(case, Case::Success) {
            let report = invoke(executor.as_ref(), &cx, "worker", "echo",
                RemoteInput::new(b"native-secret".to_vec()), config()).await.unwrap();
            assert!(
                report.is_success(),
                "{report:?}; proxy error: {:?}",
                report.task.as_ref().err()
            );
            assert!(!format!("{report:?}").contains("native-secret"));
            assert!(matches!(report.task.unwrap().outcome, Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"native-secret"));
            assert_eq!(remote.active_operations(), 0);
        } else if matches!(case, Case::Drop) {
            let mut running = Box::pin(invoke(executor.as_ref(), &cx, "worker", "wait", RemoteInput::new(work_input), config()));
            let mut started = std::pin::pin!(witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)));
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|task| {
                assert!(running.as_mut().poll(task).is_pending()); started.as_mut().poll(task)
            })).await.expect("parked remote handler");
            let (region, holder) = witness.origin.lock().expect("actual origin IDs");
            wait_for_lease(&cx, &diagnostics, region, holder).await;
            drop(running); // No result receipt can escape this path.
            asupersync::time::timeout(cx.now(), Duration::from_secs(3),
                witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire))).await.expect("drop forwarded Cancel");
            assert_eq!(remote.active_operations(), 1, "global remote runtime was not force-closed");
            assert!(holds_lease(&diagnostics, region, holder), "child must still own its checked lease during remote drain");
            if let Some(executor) = &executor {
                assert_peer_still_charged(executor, &cx).await;
                assert_eq!(remote.active_operations(), 1);
            }
            witness.release.store(true, Ordering::Release); witness.changed.notify_waiters();
            asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
                loop {
                    if remote.active_operations() == 0 && !holds_lease(&diagnostics, region, holder)
                        && executor.as_ref().is_none_or(|executor| executor.usage().in_flight == 0)
                    { break; }
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            }).await.expect("dropped runner's region retained and drained proxy");
            assert!(witness.dropped.load(Ordering::Acquire)); assert!(!cx.is_cancel_requested());
        } else {
            let mut bounds = config();
            if matches!(case, Case::Deadline) { bounds.timeout = Duration::from_secs(2); }
            let owned_admission = executor.clone();
            let mut invocation = cx.spawn(move |owner| async move {
                let result = invoke(owned_admission.as_ref(), &owner, "worker", "wait", RemoteInput::new(work_input), bounds).await;
                let _ = owner.checkpoint(); // Preserve the explicit cancellation report.
                result
            }).unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(5),
                witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire))).await.expect("real handler reached Pending");
            let (region, holder) = witness.origin.lock().expect("actual origin IDs");
            wait_for_lease(&cx, &diagnostics, region, holder).await;
            assert!(!witness.cancelled.load(Ordering::Acquire), "the parked lease witness must precede cancellation");
            if matches!(case, Case::Cancel) { invocation.abort(); }
            asupersync::time::timeout(cx.now(), Duration::from_secs(3),
                witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire))).await.expect("remote observed cancellation");
            let early = invocation.try_join().unwrap();
            assert!(early.is_none(), "sending Cancel is not terminal collection: {early:?}");
            assert!(holds_lease(&diagnostics, region, holder));
            assert_eq!(remote.active_operations(), 1);
            // A different invocation on the same remote runtime still works;
            // cancelling one scope never calls global begin_drain/close.
            if let Some(executor) = &executor { assert_peer_still_charged(executor, &cx).await; }
            let destination = if bounded { "other" } else { "worker" };
            let other = invoke(executor.as_ref(), &cx, destination, "echo",
                RemoteInput::new(b"unrelated".to_vec()), config()).await.unwrap();
            assert!(
                other.is_success(),
                "{other:?}; proxy error: {:?}; reply: {:?}; close: {:?}",
                other.task.as_ref().err(), other.task.as_ref().ok(), other.close
            );
            assert_eq!(remote.active_operations(), 1);
            witness.release.store(true, Ordering::Release); witness.changed.notify_waiters();
            let report = asupersync::time::timeout(cx.now(), Duration::from_secs(3), invocation.join(&cx)).await
                .expect("invocation drain deadline").expect("typed owner result").expect("scope admission");
            assert!(!report.is_success()); assert!(report.close.is_ok()); assert!(report.cancel_error.is_none());
            let reply = report.task.unwrap(); assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
            match case {
                Case::Cancel => {
                    assert!(matches!(report.trigger, RemoteRunTrigger::Cancelled(_)));
                    assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Cancelled(_))));
                }
                Case::Deadline => {
                    assert!(matches!(report.trigger, RemoteRunTrigger::Deadline));
                    assert!(matches!(reply.outcome, Outcome::Err(RemoteError::LeaseExpired)));
                }
                _ => unreachable!(),
            }
            assert!(witness.dropped.load(Ordering::Acquire)); assert!(!cx.is_cancel_requested());
            assert_eq!(remote.active_operations(), 0);
        }
        if let Some(executor) = &executor { assert_eq!(executor.usage(), RemoteAdmissionUsage::default()); }
        // Global teardown happens only AFTER per-invocation cleanup assertions.
        assert!(remote.close(&cx).await);
        let _ = operator.begin_drain();
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), serving.join(&cx)).await
            .expect("service drain deadline").expect("service task").expect("service drain");
        assert_eq!(operator.active_connections(), 0);
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

async fn assert_peer_still_charged(executor: &RemoteExecutor, cx: &Cx) {
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
    assert_eq!(executor.peer_usage(&NodeId::new("worker")).unwrap().in_flight, 1);
    let refused = executor.clone().run(cx, NodeId::new("worker"), ComputationName::new("echo"), RemoteInput::empty(), config()).await;
    assert!(matches!(refused, Err(RemoteExecutorError::Admission(RemoteAdmissionError::PeerInFlight))));
    let oversized = executor.run(cx, NodeId::new("other"), ComputationName::new("echo"), RemoteInput::new(vec![0; 33]), config()).await;
    assert!(matches!(oversized, Err(RemoteExecutorError::Admission(RemoteAdmissionError::RequestBytes))));
    let other = executor.run(cx, NodeId::new("other"), ComputationName::new("echo"), RemoteInput::new(vec![7; 32]), config()).await.unwrap();
    assert!(
        other.is_success(),
        "{other:?}; proxy error: {:?}; reply: {:?}; close: {:?}",
        other.task.as_ref().err(), other.task.as_ref().ok(), other.close
    );
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
}

fn holds_lease(diagnostics: &asupersync::observability::diagnostics::Diagnostics, region: RegionId, holder: TaskId) -> bool {
    diagnostics.explain_region_open(region).reasons.iter().any(|reason| {
        matches!(reason, Reason::ObligationHeld { holder_task, obligation_type, .. }
            if *holder_task == holder && obligation_type == "Lease")
    })
}
async fn wait_for_lease(cx: &Cx, diagnostics: &asupersync::observability::diagnostics::Diagnostics, region: RegionId, holder: TaskId) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
        while !holds_lease(diagnostics, region, holder) {
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }).await.expect("real checked Lease projection before triggering cancellation");
}

#[derive(Default)]
struct SilentPeerWitness {
    request: Mutex<Option<(RemoteTaskId, RegionId, TaskId)>>,
    accepted: AtomicBool,
    cancel: Mutex<Option<CancelReason>>,
    renewed: AtomicBool,
    release: AtomicBool,
    closed: AtomicBool,
    changed: Notify,
}

#[derive(Clone, Copy, Debug)]
enum SilentPeerControl {
    None,
    Cancel,
    Renewal { acknowledge: bool },
}

struct SilentNativePeer {
    remote: Arc<NativeRemoteRuntime>,
    peer: TaskHandle<()>,
    witness: Arc<SilentPeerWitness>,
    cx: Cx,
}

impl Drop for SilentNativePeer {
    fn drop(&mut self) {
        // Failure cleanup only: normal assertions run before this guard can
        // release the silent peer or force-close the native runtime.
        self.witness.release.store(true, Ordering::Release);
        self.witness.changed.notify_waiters();
        self.remote.force_close();
    }
}

async fn silent_native_peer(
    base: &Cx,
    runtime: RuntimeHandle,
    lease: Duration,
    drain_timeout: Duration,
    control: SilentPeerControl,
) -> SilentNativePeer {
    let cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt"))
        .unwrap()
        .remove(0);
    let chain = CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(&cert).unwrap();
    let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
        .client_auth(ClientAuth::Required(roots))
        .build()
        .unwrap();
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&cert)
        .identity(chain, key)
        .build()
        .unwrap();
    let listener = asupersync::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let endpoint = listener.local_addr().unwrap();
    let witness = Arc::new(SilentPeerWitness::default());
    let seen = Arc::clone(&witness);
    let peer = base
        .spawn(move |cx| async move {
            let started = Instant::now();
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            let codec = asupersync::codec::LengthDelimitedCodec::builder()
                .max_frame_length(64 * 1024)
                .big_endian()
                .new_codec();
            let mut framed =
                asupersync::codec::Framed::new(stream, codec).with_max_buffer_len(64 * 1024 + 4);
            let encoded = framed.next().await.unwrap().unwrap();
            let request: RemoteServiceWireRequest = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(
                request.hello().protocol_version(),
                RemoteProtocolVersion::V3
            );
            // Observe the real proxy's IDs from the unchanged production wire
            // request, so accounting assertions cannot name a made-up task.
            let fields: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            let region = serde_json::from_value(fields["origin_region"].clone()).unwrap();
            let holder = serde_json::from_value(fields["origin_task"].clone()).unwrap();
            let task_id = request.remote_task_id();
            *seen.request.lock() = Some((task_id, region, holder));
            let accepted = serde_json::to_vec(&RemoteServiceSessionEvent::Accepted {
                remote_task_id: task_id.raw(),
            })
            .unwrap();
            framed
                .send(asupersync::bytes::BytesMut::from(accepted.as_slice()))
                .unwrap();
            poll_fn(|task| framed.poll_flush(task)).await.unwrap();
            seen.accepted.store(true, Ordering::Release);
            seen.changed.notify_waiters();
            eprintln!(
                "{}",
                serde_json::json!({
                    "bead": "asupersync-bi2462.122",
                    "event": "silent_peer_accepted",
                    "remote_task_id": task_id.raw(),
                    "elapsed_ms": started.elapsed().as_millis(),
                    "control": format!("{control:?}"),
                })
            );

            if !matches!(control, SilentPeerControl::None) {
                let frame = framed.next().await.unwrap().unwrap();
                let command: RemoteServiceSessionCommand = serde_json::from_slice(&frame).unwrap();
                match (control, command) {
                    (
                        SilentPeerControl::Cancel,
                        RemoteServiceSessionCommand::Cancel {
                            remote_task_id,
                            reason,
                        },
                    ) => {
                        assert_eq!(remote_task_id, task_id.raw());
                        *seen.cancel.lock() = Some(reason);
                    }
                    (
                        SilentPeerControl::Renewal { acknowledge },
                        RemoteServiceSessionCommand::RenewLease {
                            remote_task_id,
                            renewal_id,
                            lease_secs,
                            lease_subsec_nanos,
                        },
                    ) => {
                        assert_eq!(remote_task_id, task_id.raw());
                        assert_eq!(renewal_id, 1);
                        if acknowledge {
                            let event =
                                serde_json::to_vec(&RemoteServiceSessionEvent::LeaseRenewed {
                                    remote_task_id,
                                    renewal_id,
                                    lease_secs,
                                    lease_subsec_nanos,
                                })
                                .unwrap();
                            framed
                                .send(asupersync::bytes::BytesMut::from(event.as_slice()))
                                .unwrap();
                            poll_fn(|task| framed.poll_flush(task)).await.unwrap();
                        }
                        seen.renewed.store(true, Ordering::Release);
                    }
                    (_, other) => panic!("expected {control:?}, received {other:?}"),
                }
                seen.changed.notify_waiters();
            }

            // No read, reply, socket close or self-wake can help the origin
            // terminate. Only the test's post-result cleanup releases this wait.
            seen.changed
                .wait_until(|| seen.release.load(Ordering::Acquire))
                .await;
            if matches!(control, SilentPeerControl::Renewal { acknowledge: true }) {
                // The confirmed-renewal case closes its handle after the old
                // deadline; this Cancel was deliberately left unanswered too.
                let frame =
                    asupersync::time::timeout(cx.now(), Duration::from_secs(2), framed.next())
                        .await
                        .expect("renewed handle's Cancel reached the peer")
                        .unwrap()
                        .unwrap();
                let command: RemoteServiceSessionCommand = serde_json::from_slice(&frame).unwrap();
                assert!(
                    matches!(command, RemoteServiceSessionCommand::Cancel { remote_task_id, .. }
                    if remote_task_id == task_id.raw())
                );
            }
            let received =
                asupersync::time::timeout(cx.now(), Duration::from_secs(2), framed.next())
                    .await
                    .expect("origin must have dropped its authenticated transport");
            assert!(
                received.is_none() || matches!(received, Some(Err(_))),
                "silent-peer termination must not replay a dispatched request"
            );
            seen.closed.store(true, Ordering::Release);
            seen.changed.notify_waiters();
        })
        .unwrap();
    let mut schemas = ComputationSchemaRegistry::new();
    schemas
        .register_typed::<Request, Response>("silent")
        .unwrap();
    let origin = NodeId::new("silent-origin");
    let hello = RemotePeerHello::new(
        origin.clone(),
        RemoteProtocolVersion::V3,
        schemas.fingerprint(),
    );
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_attempt_timeout(Duration::from_secs(3)),
    )
    .unwrap();
    let remote = Arc::new(
        NativeRemoteRuntime::with_config(
            runtime,
            origin.clone(),
            [NativeRemoteRoute::new(
                NodeId::new("silent-worker"),
                hello,
                client,
            )],
            NativeRemoteRuntimeConfig::new()
                .with_max_in_flight(1)
                .with_drain_timeout(drain_timeout),
        )
        .unwrap(),
    );
    let cx = base.clone().with_remote_cap(
        RemoteCap::new()
            .with_local_node(origin)
            .with_default_lease(lease)
            .with_runtime(Arc::clone(&remote) as Arc<dyn RemoteRuntime>),
    );
    SilentNativePeer {
        remote,
        peer,
        witness,
        cx,
    }
}

async fn wait_for_silent_native_running(
    peer: &SilentNativePeer,
) -> (RemoteTaskId, RegionId, TaskId) {
    asupersync::time::timeout(peer.cx.now(), Duration::from_secs(3), async {
        peer.witness
            .changed
            .wait_until(|| peer.witness.accepted.load(Ordering::Acquire))
            .await;
        let ids = peer
            .witness
            .request
            .lock()
            .expect("peer observed the actual request IDs");
        while peer.remote.observe_task_state(ids.0) != Some(RemoteTaskState::Running) {
            asupersync::time::sleep(peer.cx.now(), Duration::from_millis(1)).await;
        }
        ids
    })
    .await
    .expect("the native origin reached Running before the liveness trigger")
}

async fn finish_silent_native_peer(peer: &mut SilentNativePeer) {
    // Terminal publication wakes another worker before complete() removes the
    // active entry. Observe retirement without invoking global close to help it.
    asupersync::time::timeout(peer.cx.now(), Duration::from_secs(2), async {
        while peer.remote.active_operations() != 0 {
            asupersync::time::sleep(peer.cx.now(), Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("local driver retires after terminal publication");
    assert_eq!(peer.remote.active_operations(), 0);
    assert!(
        !peer.witness.release.load(Ordering::Acquire),
        "peer stayed silent until after the result"
    );
    peer.witness.release.store(true, Ordering::Release);
    peer.witness.changed.notify_waiters();
    asupersync::time::timeout(
        peer.cx.now(),
        Duration::from_secs(3),
        peer.peer.join(&peer.cx),
    )
    .await
    .expect("silent peer cleanup bound")
    .expect("silent peer task completed without panic");
    assert!(peer.witness.closed.load(Ordering::Acquire));
    assert!(peer.remote.close(&peer.cx).await);
}

#[test]
fn native_silent_accepted_peer_expires_without_runtime_close() {
    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .unwrap()
        };
        runtime.block_on(async {
            let base = Cx::current().unwrap();
            let lease = Duration::from_secs(1);
            let mut peer = silent_native_peer(
                &base,
                runtime.handle(),
                lease,
                Duration::from_millis(400),
                SilentPeerControl::None,
            )
            .await;
            let mut handle = spawn_remote(
                &peer.cx,
                NodeId::new("silent-worker"),
                ComputationName::new("silent"),
                RemoteInput::empty(),
            )
            .unwrap();
            let (task_id, _, _) = wait_for_silent_native_running(&peer).await;
            assert_eq!(task_id, handle.remote_task_id());
            assert_eq!(peer.remote.active_operations(), 1);
            let trigger = Instant::now();
            let result = asupersync::time::timeout(
                peer.cx.now(),
                Duration::from_secs(3),
                handle.join(&peer.cx),
            )
            .await
            .expect("Accepted without a terminal reply must expire at the origin lease bound");
            assert!(
                matches!(result, Outcome::Err(RemoteError::LeaseExpired)),
                "{result:?}"
            );
            assert_eq!(handle.state(), RemoteTaskState::LeaseExpired);
            assert!(peer.remote.observe_task_state(task_id).is_none());
            assert!(!peer.cx.is_cancel_requested());
            eprintln!(
                "{}",
                serde_json::json!({
                    "bead": "asupersync-bi2462.122",
                    "scenario": "silent_accepted_lease_expiry",
                    "workers": workers,
                    "remote_task_id": task_id.raw(),
                    "witness": "Running",
                    "lease_ms": lease.as_millis(),
                    "elapsed_since_running_ms": trigger.elapsed().as_millis(),
                    "outcome": "LeaseExpired",
                })
            );
            finish_silent_native_peer(&mut peer).await;
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_silent_peer_renewal_extends_deadline_only_after_acknowledgement() {
    for workers in [1, 2] {
        for acknowledge in [false, true] {
            let runtime = if workers == 1 {
                RuntimeBuilder::current_thread().build().unwrap()
            } else {
                RuntimeBuilder::multi_thread()
                    .worker_threads(workers)
                    .build()
                    .unwrap()
            };
            runtime.block_on(async {
                let base = Cx::current().unwrap();
                let lease = Duration::from_secs(1);
                let mut peer = silent_native_peer(
                    &base,
                    runtime.handle(),
                    lease,
                    Duration::from_millis(400),
                    SilentPeerControl::Renewal { acknowledge },
                )
                .await;
                let mut handle = spawn_remote(
                    &peer.cx,
                    NodeId::new("silent-worker"),
                    ComputationName::new("silent"),
                    RemoteInput::empty(),
                )
                .unwrap();
                let (task_id, _, _) = wait_for_silent_native_running(&peer).await;
                let triggered = Instant::now();
                peer.remote
                    .send_message(
                        &NodeId::new("silent-worker"),
                        MessageEnvelope::new(
                            NodeId::new("silent-origin"),
                            peer.cx.logical_tick(),
                            RemoteMessage::LeaseRenewal(LeaseRenewal {
                                remote_task_id: task_id,
                                new_lease: Duration::from_secs(10),
                                current_state: RemoteTaskState::Running,
                                node: NodeId::new("silent-origin"),
                            }),
                        ),
                    )
                    .unwrap();
                asupersync::time::timeout(
                    peer.cx.now(),
                    Duration::from_secs(2),
                    peer.witness
                        .changed
                        .wait_until(|| peer.witness.renewed.load(Ordering::Acquire)),
                )
                .await
                .expect("peer observed the explicit renewal command");
                if acknowledge {
                    asupersync::time::sleep(peer.cx.now(), lease + Duration::from_millis(100))
                        .await;
                    assert!(
                        handle.try_join().unwrap().is_none(),
                        "confirmed renewal survives the original lease"
                    );
                    assert_eq!(handle.state(), RemoteTaskState::Running);
                    let result = asupersync::time::timeout(
                        peer.cx.now(),
                        Duration::from_secs(2),
                        handle.close(&peer.cx),
                    )
                    .await
                    .expect("renewed operation still has a bounded Cancel drain");
                    assert!(
                        matches!(result, Outcome::Err(RemoteError::Cancelled(_))),
                        "{result:?}"
                    );
                } else {
                    let result = asupersync::time::timeout(
                        peer.cx.now(),
                        Duration::from_secs(3),
                        handle.join(&peer.cx),
                    )
                    .await
                    .expect("unacknowledged renewal cannot extend the original lease deadline");
                    assert!(
                        matches!(result, Outcome::Err(RemoteError::LeaseExpired)),
                        "{result:?}"
                    );
                }
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "bead": "asupersync-bi2462.122",
                        "scenario": "manual_renewal_confirmation_bounds_liveness",
                        "workers": workers,
                        "remote_task_id": task_id.raw(),
                        "witness": "Running_then_RenewLease_received",
                        "acknowledged": acknowledge,
                        "original_lease_ms": lease.as_millis(),
                        "elapsed_since_renewal_ms": triggered.elapsed().as_millis(),
                        "terminal_state": format!("{:?}", handle.state()),
                    })
                );
                finish_silent_native_peer(&mut peer).await;
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }
    }
}

#[test]
fn owned_native_silent_cancel_reply_bounds_parent_close() {
    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .unwrap()
        };
        let diagnostics = runtime.diagnostics();
        runtime.block_on(async {
            let base = Cx::current().unwrap();
            let drain_timeout = Duration::from_millis(400);
            let mut peer = silent_native_peer(
                &base,
                runtime.handle(),
                Duration::from_secs(30),
                drain_timeout,
                SilentPeerControl::Cancel,
            )
            .await;
            let parent = peer
                .cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let parent_id = parent.region_id();
            let mut invocation = parent
                .cx()
                .spawn(|owner| async move {
                    let report = run_remote(
                        &owner,
                        NodeId::new("silent-worker"),
                        ComputationName::new("silent"),
                        RemoteInput::empty(),
                        RemoteRunConfig {
                            timeout: Duration::from_secs(10),
                            child: ChildRegionSpec::inherit(),
                        },
                    )
                    .await;
                    let _ = owner.checkpoint();
                    report
                })
                .unwrap();
            let (task_id, region, holder) = wait_for_silent_native_running(&peer).await;
            wait_for_lease(&peer.cx, &diagnostics, region, holder).await;
            assert_eq!(peer.remote.active_operations(), 1);
            assert!(invocation.try_join().unwrap().is_none());
            let reason = CancelReason::user("silent peer parent close");
            let triggered = Instant::now();
            parent.cancel(reason.clone()).unwrap();
            asupersync::time::timeout(
                peer.cx.now(),
                Duration::from_secs(2),
                peer.witness
                    .changed
                    .wait_until(|| peer.witness.cancel.lock().is_some()),
            )
            .await
            .expect("Cancel must reach the peer before its reply is withheld");
            let (closed, joined) = asupersync::time::timeout(
                peer.cx.now(),
                Duration::from_secs(2),
                futures_lite::future::zip(parent.close(), invocation.join(&peer.cx)),
            )
            .await
            .expect("a silent Cancel reply must not strand the invocation or its closing parent");
            closed.expect("parent region close receipt");
            let report = joined
                .expect("typed cancellation report survives owner cancellation")
                .expect("owned remote admission");
            assert!(!report.is_success());
            assert!(matches!(report.trigger, RemoteRunTrigger::Cancelled(_)));
            assert!(
                report.close.is_ok(),
                "local invocation child reached quiescence"
            );
            assert!(report.cancel_error.is_none());
            let reply = report
                .task
                .expect("proxy returned its terminal classification");
            assert_eq!(reply.remote_task_id, task_id);
            assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
            match reply.outcome {
                Outcome::Err(RemoteError::Cancelled(actual)) => {
                    assert_eq!(Some(&actual), peer.witness.cancel.lock().as_ref());
                    assert_eq!(actual.root_cause().kind, reason.kind);
                    assert_eq!(actual.root_cause().message, reason.message);
                }
                other => panic!(
                    "silent Cancel reply must remain an ambiguous local cancellation: {other:?}"
                ),
            }
            assert!(!holds_lease(&diagnostics, region, holder));
            assert!(peer.remote.observe_task_state(task_id).is_none());
            assert!(
                !peer.cx.is_cancel_requested(),
                "one parent must not cancel the surrounding context"
            );
            assert!(
                runtime.trace_snapshot().iter().any(|event| matches!(
                    &event.data,
                    asupersync::trace::event::TraceData::Message(message)
                        if message == "remote::cancel_drain_expired_delivery_ambiguous"
                )),
                "the per-operation drain timeout classified the unanswered Cancel"
            );
            eprintln!(
                "{}",
                serde_json::json!({
                    "bead": "asupersync-bi2462.122",
                    "scenario": "silent_cancel_parent_close",
                    "workers": workers,
                    "remote_task_id": task_id.raw(),
                    "parent_region": format!("{parent_id:?}"),
                    "witness": "Running_with_checked_lease_and_Cancel_received",
                    "drain_ms": drain_timeout.as_millis(),
                    "elapsed_since_cancel_ms": triggered.elapsed().as_millis(),
                    "outcome": "Cancelled_delivery_ambiguous",
                    "settlement": "Aborted",
                })
            );
            finish_silent_native_peer(&mut peer).await;
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn lab_spawn_join_releases_after_task_record_retirement() {
    use asupersync::{Budget, LabConfig, LabRuntime};
    use asupersync::runtime::task_handle::JoinError;

    for panic_child in [false, true] {
        let mut lab = LabRuntime::new(LabConfig::new(0x59_48_55).max_steps(256));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let completed = Arc::new(AtomicBool::new(false));
        let completed_task = Arc::clone(&completed);
        let child_id = Arc::new(Mutex::new(None));
        let child_id_task = Arc::clone(&child_id);
        let (owner, mut owner_join) = lab.state.create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            let mut child = cx.spawn(move |child_cx| async move {
                *child_id_task.lock() = Some(child_cx.task_id());
                assert!(!panic_child, "retirement regression panic");
                42_u8
            }).unwrap();
            let result = child.join(&cx).await;
            if panic_child {
                match result {
                    Err(JoinError::Panicked(payload)) => {
                        assert_eq!(payload.message(), "retirement regression panic");
                    }
                    other => panic!("expected the child's exact panic, got {other:?}"),
                }
            } else {
                assert_eq!(result.unwrap(), 42);
            }
            completed_task.store(true, Ordering::Release);
        }).unwrap();
        lab.scheduler.lock().schedule(owner, 0);

        // A lost retirement wake leaves the owner parked. A bounded Lab run lets
        // the assertion expose that failure without an unbounded native join.
        lab.run_until_idle();
        let child_id = child_id.lock().expect("child was actually polled");
        assert!(lab.state.task(child_id).is_none(), "child record must be retired");
        assert!(completed.load(Ordering::Acquire), "join stayed parked after child retirement");
        assert!(matches!(owner_join.try_join(), Ok(Some(()))));
        assert!(lab.state.task(owner).is_none(), "owner record must be retired");
    }
}

#[test]
fn lab_teardown_releases_unadmitted_spawn_handles() {
    use asupersync::runtime::task_handle::JoinError;
    use asupersync::{Budget, CancelKind, LabConfig, LabRuntime};
    use std::task::{Context, Wake, Waker};

    struct Captured(Arc<AtomicBool>, bool);
    impl Drop for Captured {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            assert!(!self.1, "queued factory destructor panic");
        }
    }
    struct Woken {
        woken: Arc<AtomicBool>,
        pending: Arc<asupersync::record::region::PendingSpawnCounter>,
        credit_held_at_wake: Arc<AtomicBool>,
    }
    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.credit_held_at_wake
                .store(self.pending.count() == 1, Ordering::Release);
            self.woken.store(true, Ordering::Release);
        }
    }

    for panic_drop in [false, true] {
        let mut lab = LabRuntime::new(LabConfig::new(0x91).max_steps(16));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let pending = lab.state.region(root).unwrap().pending_spawn_handle();
        let retired = Arc::new(AtomicBool::new(false));
        let captured = Captured(Arc::clone(&retired), panic_drop);
        let invoked = Arc::new(AtomicBool::new(false));
        let invoked_child = Arc::clone(&invoked);
        let published = Arc::new(Mutex::new(None));
        let publish = Arc::clone(&published);
        let (owner, _owner_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let child = cx
                    .spawn(move |_| {
                        invoked_child.store(true, Ordering::Release);
                        async move {
                            drop(captured);
                        }
                    })
                    .unwrap();
                *publish.lock() = Some((child, cx));
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);
        // One dispatch publishes the child; no second step may admit it.
        lab.step_for_test();
        let (mut child, retained_cx) = published.lock().take().expect("queued child");
        assert!(!invoked.load(Ordering::Acquire));
        assert!(!retired.load(Ordering::Acquire));
        assert_eq!(pending.count(), 1);
        let woken = Arc::new(AtomicBool::new(false));
        let credit_held_at_wake = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(Woken {
            woken: Arc::clone(&woken),
            pending: Arc::clone(&pending),
            credit_held_at_wake: Arc::clone(&credit_held_at_wake),
        }));
        assert!(
            child
                .poll_join(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let started = std::time::Instant::now();
        eprintln!(
            "teardown_join scenario=lab_unadmitted panic_drop={panic_drop} queued=true trigger=drop"
        );
        drop(lab);
        assert!(
            retired.load(Ordering::Acquire),
            "queued factory retained after Lab drop"
        );
        assert!(
            !invoked.load(Ordering::Acquire),
            "teardown ran user factory"
        );
        assert!(woken.load(Ordering::Acquire), "queued join was not woken");
        assert!(credit_held_at_wake.load(Ordering::Acquire));
        assert_eq!(pending.count(), 0);
        assert!(child.is_finished());
        assert!(matches!(child.try_join(), Err(JoinError::Cancelled(reason))
            if reason.kind == CancelKind::Shutdown));
        assert!(matches!(
            retained_cx.spawn(|_| async {}),
            Err(asupersync::runtime::state::SpawnError::RuntimeUnavailable)
        ));
        eprintln!(
            "teardown_join scenario=lab_unadmitted panic_drop={panic_drop} retired=true woken=true elapsed={:?}",
            started.elapsed()
        );
    }
}

#[test]
fn lab_public_state_remains_movable() {
    let mut lab = asupersync::LabRuntime::with_seed(0x91);
    let root = lab.state.create_root_region(asupersync::Budget::INFINITE);
    let state = lab.state;
    assert!(state.region(root).is_some());
}

#[test]
fn join_handles_preserve_auto_traits_for_non_sync_and_pinned_results() {
    use asupersync::runtime::task_handle::{JoinFuture, TaskHandle};
    use std::cell::Cell;
    use std::marker::PhantomPinned;

    fn assert_sync<T: Sync>() {}
    fn assert_unpin<T: Unpin>() {}

    // Result storage was originally behind the oneshot's mutex. Buffering a
    // result until retirement must preserve these public auto-trait bounds.
    assert_sync::<TaskHandle<Cell<u8>>>();
    assert_sync::<JoinFuture<'static, Cell<u8>>>();
    assert_unpin::<TaskHandle<PhantomPinned>>();
    assert_unpin::<JoinFuture<'static, PhantomPinned>>();
}

#[test]
fn native_child_remote_authority_respects_parent_presence_and_runtime_mask() {
    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap()
        };
        runtime.block_on(async {
            let base = Cx::current().unwrap();
            assert!(base.remote().is_none());
            let unprivileged = base.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            assert!(unprivileged.cx().remote().is_none());
            unprivileged.close().await.unwrap();

            let parent = base.with_remote_cap(RemoteCap::new());
            let child = parent.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            assert!(std::ptr::eq(parent.remote().unwrap(), child.cx().remote().unwrap()));
            assert_ne!(parent.region_id(), child.region_id());
            child.close().await.unwrap();

            // Capture the ambient runtime mask without retaining a thread-local
            // guard across await (the multi-thread runtime may migrate the task).
            let restricted = {
                type LocalCaps = asupersync::cx::cap::CapSet<true, true, true, true, false>;
                let _guard = parent.restrict::<LocalCaps>().set_current_restricted();
                Cx::current().unwrap()
            };
            assert!(parent.remote().is_some());
            assert!(restricted.remote().is_none());
            let child = restricted.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            assert!(child.cx().remote().is_none());
            let grandchild = child.cx().open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            assert!(grandchild.cx().remote().is_none());
            grandchild.close().await.unwrap();
            child.close().await.unwrap();
        });
    }
}

#[test]
fn native_v3_success_has_a_checked_commit_and_closed_local_child() {
    for workers in [1, 2] { exercise(workers, Case::Success); }
}
#[test]
fn cancelled_native_invocation_retains_its_lease_until_remote_handler_cleanup() {
    for workers in [1, 2] { exercise(workers, Case::Cancel); }
}
#[test]
fn native_deadline_forwards_cancel_without_stopping_unrelated_invocations() {
    for workers in [1, 2] { exercise(workers, Case::Deadline); }
}
#[test]
fn dropped_native_runner_keeps_region_owned_cleanup_until_terminal_collection() {
    for workers in [1, 2] { exercise(workers, Case::Drop); }
}

#[test]
fn admitted_native_success_releases_both_scope_and_proxy_charges() {
    for workers in [1, 2] { exercise_with_admission(workers, Case::Success, true); }
}
#[test]
fn admitted_native_cancellation_cannot_reuse_peer_capacity_during_remote_cleanup() {
    for workers in [1, 2] { exercise_with_admission(workers, Case::Cancel, true); }
}
#[test]
fn admitted_native_deadline_preserves_control_progress_and_other_peer_capacity() {
    for workers in [1, 2] { exercise_with_admission(workers, Case::Deadline, true); }
}
#[test]
fn admitted_native_caller_drop_keeps_bytes_charged_until_proxy_drain() {
    for workers in [1, 2] { exercise_with_admission(workers, Case::Drop, true); }
}
