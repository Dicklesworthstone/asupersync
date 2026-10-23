//! Typed computation journeys over actual V3 mTLS sessions and native admission.
//! Pending polls witness cancellation and withheld cleanup; no sleeps establish
//! readiness. Every journey runs on current-thread/two-worker, unified/sharded.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::channel::oneshot;
use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::remote_owned::{
    RemoteLeaseSettlement, RemoteRunConfig, RemoteRunHandleError, RemoteRunTrigger,
};
use asupersync::remote::{
    AdmittedNativeRemoteRuntime, ComputationName, IdempotencyKey, NativeRemoteAdmissionLimits,
    NativeRemotePeerAdmissionLimits, NativeRemoteRoute, NativeRemoteRuntime, NativeRemoteRuntimeConfig,
    NodeId, PreparedTypedRemoteCall, RemoteCap, RemoteComputationClient, RemoteComputationClientConfig,
    RemoteComputationListenerError, RemoteComputationRegistry, RemoteComputationService,
    RemoteComputationServiceConfig, RemoteComputationServiceHandle, RemoteComputationServiceReport,
    RemoteError, RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy, RemoteProtocolVersion,
    RemoteServiceWireLimits, RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId,
    SpawnRequest, TypedRemoteComputation, TypedRemoteError, TypedRemoteLimits, TypedRemoteOutcome,
    TypedRemoteStage, spawn_remote, spawn_remote_typed, spawn_remote_typed_owned,
};
use asupersync::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder, RuntimeHandle, TaskHandle};
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::{Cx, Outcome};
use asupersync::types::{CancelKind, CancelReason};
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::Duration;

const FRAME_LIMIT: usize = 4096;
const CHARGE: usize = 16 * (FRAME_LIMIT + 4) + 256 * 1024;
const WAIT: Duration = Duration::from_secs(5);
const LEASE: Duration = Duration::from_secs(30);
const FIXTURE_STACK: usize = 32 * 1024 * 1024;

struct Add;
impl TypedRemoteComputation for Add {
    const NAME: &'static str = "typed.add";
    type Input = (u64, u64);
    type Output = u64;
}
struct Wait;
impl TypedRemoteComputation for Wait {
    const NAME: &'static str = "typed.wait";
    type Input = ();
    type Output = ();
}
struct Large;
impl TypedRemoteComputation for Large {
    const NAME: &'static str = "typed.large";
    type Input = ();
    type Output = String;
}

#[derive(Default)]
struct Gate {
    parked: AtomicBool,
    cancelled: AtomicBool,
    release: AtomicBool,
    retired: AtomicBool,
    changed: Notify,
}
impl Gate {
    fn release(&self) {
        self.release.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    async fn wait(&self, field: &AtomicBool) {
        self.changed.wait_until(|| field.load(Ordering::Acquire)).await;
    }
}
struct Retirement(Arc<Gate>);
impl Drop for Retirement {
    fn drop(&mut self) {
        self.0.retired.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}

struct Fixture {
    route: NativeRemoteRoute,
    service: RemoteComputationServiceHandle,
    serving: TaskHandle<Result<RemoteComputationServiceReport, RemoteComputationListenerError>>,
    admitted: AdmittedNativeRemoteRuntime,
    legacy: Arc<NativeRemoteRuntime>,
    gate: Arc<Gate>,
    calls: Arc<AtomicUsize>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.gate.release();
        self.admitted.begin_drain();
        let _ = self.legacy.begin_drain();
        let _ = self.service.begin_drain();
    }
}
impl Fixture {
    async fn new(cx: &Cx, runtime: RuntimeHandle) -> Self {
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
        let pins = CertificatePinSet::new()
            .with_pin(CertificatePin::compute_spki_sha256(&certificate).unwrap());
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&certificate)
            .identity(chain, key)
            .with_certificate_pins(pins.clone())
            .build()
            .unwrap();
        let gate = Arc::new(Gate::default());
        let observed_gate = Arc::clone(&gate);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let mut registry = RemoteComputationRegistry::new();
        registry
            .register_typed_json::<Add, _, _>(limits(), move |_, (left, right)| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if left == u64::MAX {
                        TypedRemoteOutcome::Failed("declared application failure".to_owned())
                    } else {
                        TypedRemoteOutcome::Success(left + right)
                    }
                }
            })
            .unwrap();
        registry
            .register_typed_json::<Wait, _, _>(limits(), move |cx, ()| {
                let gate = Arc::clone(&observed_gate);
                async move {
                    let _retired = Retirement(Arc::clone(&gate));
                    let mut cancellation = pin!(cx.cancelled());
                    poll_fn(|task| {
                        let result = cancellation.as_mut().poll(task);
                        if result.is_pending() && !gate.parked.swap(true, Ordering::AcqRel) {
                            gate.changed.notify_waiters();
                        }
                        result
                    })
                    .await;
                    let _ = cx.checkpoint();
                    gate.cancelled.store(true, Ordering::Release);
                    gate.changed.notify_waiters();
                    gate.wait(&gate.release).await;
                    TypedRemoteOutcome::Cancelled(cx.cancel_reason().unwrap())
                }
            })
            .unwrap();
        registry
            .register_typed_json::<Large, _, _>(TypedRemoteLimits::new(1024, 256), |_, ()| async {
                TypedRemoteOutcome::Success("x".repeat(2048))
            })
            .unwrap();
        registry
            .register::<Vec<u8>, Vec<u8>, _, _>("raw.echo", |_, invocation| async move {
                Ok(RemoteOutcome::Success(invocation.request().input.data().to_vec()))
            })
            .unwrap();
        let mut policy = RemotePeerAdmissionPolicy::new(
            RemoteProtocolVersion::V3,
            registry.schema_registry().clone(),
        );
        policy
            .grant_tls_peer(NodeId::new("origin"), pins, [Add::NAME, Wait::NAME, Large::NAME, "raw.echo"])
            .unwrap();
        let hello = policy.hello_for(NodeId::new("origin"));
        let service = RemoteComputationService::bind(
            "127.0.0.1:0",
            acceptor,
            policy,
            registry,
            RemoteComputationServiceConfig::new()
                .with_max_connections(Some(8))
                .with_drain_timeout(WAIT),
        )
        .await
        .unwrap();
        let endpoint = service.local_addr().unwrap();
        let operator = service.handle();
        let serving = cx.spawn(move |cx| async move { service.run(&cx).await }).unwrap();
        let client = RemoteComputationClient::new(
            endpoint,
            "localhost",
            connector,
            RemoteComputationClientConfig::new()
                .with_max_attempts(1)
                .with_wire_limits(RemoteServiceWireLimits::new(FRAME_LIMIT))
                .with_connect_timeout(WAIT)
                .with_attempt_timeout(WAIT),
        )
        .unwrap();
        let route = NativeRemoteRoute::new(NodeId::new("worker"), hello, client);
        let native = NativeRemoteRuntimeConfig::new().with_max_in_flight(4).with_drain_timeout(WAIT);
        let legacy = Arc::new(
            NativeRemoteRuntime::with_config(
                runtime.clone(), NodeId::new("origin"), [route.clone()], native,
            )
            .unwrap(),
        );
        let admitted = AdmittedNativeRemoteRuntime::new(
            runtime,
            NodeId::new("origin"),
            [(route.clone(), NativeRemotePeerAdmissionLimits {
                max_in_flight: 1,
                max_buffer_bytes: CHARGE,
                max_input_bytes: 1024,
            })],
            NativeRemoteAdmissionLimits {
                max_routes: 1,
                max_in_flight: 1,
                max_buffer_bytes: CHARGE,
                max_waiters: 1,
                max_waiters_per_peer: 1,
            },
            native,
        )
        .unwrap();
        Self { route, service: operator, serving, admitted, legacy, gate, calls }
    }

    fn remote_cx(&self, cx: &Cx) -> Cx {
        cx.clone().with_remote_cap(
            RemoteCap::new()
                .with_local_node(NodeId::new("origin"))
                .with_default_lease(LEASE)
                .with_runtime(self.legacy.clone()),
        )
    }

    async fn finish(&mut self, cx: &Cx) {
        assert!(self.admitted.close(cx).await.unwrap());
        assert!(self.legacy.close(cx).await);
        let _ = self.service.begin_drain();
        let report = self.serving.join(cx).await.unwrap().unwrap();
        assert_eq!(report.shutdown().force_closed, 0);
        assert_eq!(self.service.active_connections(), 0);
        assert_eq!(self.admitted.usage().in_flight, 0);
        assert_eq!(self.admitted.usage().buffer_bytes, 0);
        assert_eq!(self.admitted.usage().waiters, 0);
        assert_eq!(self.legacy.active_operations(), 0);
    }
}

fn limits() -> TypedRemoteLimits {
    TypedRemoteLimits::new(1024, 1024)
}

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx, RuntimeHandle) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (sent, received) = mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("typed-remote-fixture".to_owned())
        .stack_size(FIXTURE_STACK)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                for workers in [1, 2] {
                    for sharded in [false, true] {
                        let builder = if workers == 1 {
                            RuntimeBuilder::current_thread()
                        } else {
                            RuntimeBuilder::new().worker_threads(workers)
                        };
                        let runtime = builder
                            .thread_stack_size(FIXTURE_STACK)
                            .with_sharded_state(sharded)
                            .build()
                            .unwrap();
                        let handle = runtime.handle();
                        runtime.block_on(async {
                            let root = Cx::current().unwrap();
                            let mut owner = root.spawn(move |cx| scenario(cx, handle)).unwrap();
                            owner.join(&root).await.unwrap();
                        });
                        let report = runtime.shutdown_drained(WAIT);
                        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                        assert_eq!(report.live_tasks, 0);
                        assert_eq!(report.pending_spawns, 0);
                        assert_eq!(report.pending_obligations, 0);
                    }
                }
            }));
            let _ = sent.send(result);
        })
        .unwrap();
    let result = received.recv_timeout(Duration::from_secs(60))
        .expect("typed remote journey must finish and drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

#[test]
fn typed_native_round_trip_failure_output_limit_and_legacy_coexistence() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let remote = fixture.remote_cx(&cx);
        let mut typed = spawn_remote_typed::<Add>(&remote, NodeId::new("worker"), &(19, 23), limits())
            .unwrap();
        assert!(matches!(typed.join(&cx).await, Outcome::Ok(TypedRemoteOutcome::Success(42))));
        assert!(matches!(typed.try_join(),
            Err(TypedRemoteError::Remote(RemoteError::PolledAfterCompletion))));
        let mut failed = spawn_remote_typed::<Add>(
            &remote, NodeId::new("worker"), &(u64::MAX, 0), limits(),
        )
        .unwrap();
        assert!(matches!(failed.join(&cx).await,
            Outcome::Ok(TypedRemoteOutcome::Failed(message)) if message == "declared application failure"));
        let mut large = spawn_remote_typed::<Large>(&remote, NodeId::new("worker"), &(), limits())
            .unwrap();
        assert!(matches!(large.join(&cx).await,
            Outcome::Err(TypedRemoteError::Remote(RemoteError::TransportError(message)))
                if message.contains("ExecutionFailed")
                    && message.contains("typed remote response exceeds its 256-byte envelope limit")),
            "the typed output cap must be the exact remote refusal cause");
        let mut raw = spawn_remote(
            &remote, NodeId::new("worker"), ComputationName::new("raw.echo"), RemoteInput::new(vec![4, 2]),
        )
        .unwrap();
        assert!(matches!(raw.join(&cx).await,
            Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == [4, 2]));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        drop(remote);
        fixture.finish(&cx).await;
    });
}

#[test]
fn typed_v3_idempotency_replays_without_reexecuting_the_handler() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let call = PreparedTypedRemoteCall::<Add>::encode(&(20, 22), limits()).unwrap();
        let request = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(700),
            computation: ComputationName::new(Add::NAME),
            input: RemoteInput::new(call.encoded_input().to_vec()),
            lease: LEASE,
            idempotency_key: IdempotencyKey::from_raw(0x7459_5045),
            budget: None,
            origin_node: NodeId::new("origin"),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        };
        let wire = RemoteServiceWireRequest::from_spawn_request(fixture.route.hello().clone(), &request)
            .unwrap();
        let first = fixture.route.client().call(&cx, &wire).await.unwrap();
        let second = fixture.route.client().call(&cx, &wire).await.unwrap();
        assert!(matches!(first, RemoteServiceWireResponse::Outcome { .. }));
        assert_eq!(first, second);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        fixture.finish(&cx).await;
    });
}

#[test]
fn typed_charged_handle_keeps_cancelled_observation_separate_from_remote_close() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let call = PreparedTypedRemoteCall::<Wait>::encode(&(), limits()).unwrap();
        let reservation = fixture.admitted.reserve(&cx, &NodeId::new("worker"), call.encoded_len(), WAIT)
            .await.unwrap();
        let mut handle = call.commit(&cx, reservation, LEASE).unwrap();
        fixture.gate.wait(&fixture.gate.parked).await;
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);
        let (parked, mut witnessed) = oneshot::channel();
        let mut observer = cx.spawn(move |observer_cx| async move {
            let mut parked = Some(parked);
            let result = {
                let mut joining = pin!(handle.join(&observer_cx));
                poll_fn(|task| {
                    let result = joining.as_mut().poll(task);
                    if result.is_pending() && let Some(parked) = parked.take() {
                        parked.send_blocking(()).unwrap();
                    }
                    result
                }).await
            };
            (handle, result)
        }).unwrap();
        witnessed.recv(&cx).await.unwrap();
        let reason = CancelReason::user("cancel only typed join observation");
        observer.abort_with_reason(reason.clone());
        let (mut handle, result) = observer.join(&cx).await.unwrap();
        assert!(matches!(result,
            Outcome::Err(TypedRemoteError::Remote(RemoteError::Cancelled(actual))) if actual == reason));
        assert!(!fixture.gate.cancelled.load(Ordering::Acquire));
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);
        let mut closing = Box::pin(handle.close(&cx));
        poll_fn(|task| {
            assert!(closing.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        fixture.gate.wait(&fixture.gate.cancelled).await;
        assert!(!fixture.gate.retired.load(Ordering::Acquire));
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE,
            "withheld remote cleanup must retain native buffer admission");
        fixture.gate.release();
        assert!(matches!(closing.await,
            Outcome::Ok(TypedRemoteOutcome::Cancelled(actual))
                if actual == CancelReason::user("remote handle close")));
        assert!(fixture.gate.retired.load(Ordering::Acquire));
        fixture.finish(&cx).await;
    });
}

#[test]
fn dropping_typed_native_work_retains_credit_until_remote_cleanup_finishes() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let call = PreparedTypedRemoteCall::<Wait>::encode(&(), limits()).unwrap();
        let reservation = fixture.admitted.reserve(&cx, &NodeId::new("worker"), call.encoded_len(), WAIT)
            .await.unwrap();
        let handle = call.commit(&cx, reservation, LEASE).unwrap();
        fixture.gate.wait(&fixture.gate.parked).await;
        drop(handle);
        fixture.gate.wait(&fixture.gate.cancelled).await;
        assert!(!fixture.gate.retired.load(Ordering::Acquire));
        assert_eq!(fixture.admitted.usage().in_flight, 1);
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);
        fixture.gate.release();
        let next = PreparedTypedRemoteCall::<Add>::encode(&(6, 7), limits()).unwrap();
        let reservation = fixture.admitted.reserve(&cx, &NodeId::new("worker"), next.encoded_len(), WAIT)
            .await.unwrap();
        assert!(fixture.gate.retired.load(Ordering::Acquire));
        let mut healthy = next.commit(&cx, reservation, LEASE).unwrap();
        assert!(matches!(healthy.join(&cx).await, Outcome::Ok(TypedRemoteOutcome::Success(13))));
        fixture.finish(&cx).await;
    });
}

fn owned_config() -> RemoteRunConfig {
    RemoteRunConfig {
        timeout: WAIT,
        child: ChildRegionSpec::inherit(),
    }
}

#[test]
fn typed_owned_native_success_and_application_failure_retain_actual_close_receipts() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let remote = fixture.remote_cx(&cx);
        let prepared = PreparedTypedRemoteCall::<Add>::encode(&(20, 22), limits()).unwrap();
        let mut call = prepared.spawn_owned(&remote, NodeId::new("worker"), owned_config()).unwrap();
        assert_ne!(call.local_task_id(), cx.task_id());
        let report = call.join(&cx).await.unwrap();
        assert!(call.is_finished());
        assert!(report.is_success(), "{report:?}");
        assert_ne!(report.close.as_ref().unwrap().region_id, cx.region_id());
        assert!(matches!(report.close.as_ref().unwrap().outcome, Outcome::Ok(())));
        let reply = report.task.unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed);
        assert!(reply.cancellation.is_none());
        assert!(matches!(reply.outcome, Outcome::Ok(TypedRemoteOutcome::Success(42))));
        assert!(matches!(call.try_join(),
            Err(RemoteRunHandleError::Join(JoinError::PolledAfterCompletion))));

        let mut failed = spawn_remote_typed_owned::<Add>(
            &remote, NodeId::new("worker"), &(u64::MAX, 0), limits(), owned_config(),
        ).unwrap();
        let report = failed.join(&cx).await.unwrap();
        assert!(failed.is_finished());
        assert!(!report.is_success());
        assert!(report.close.is_ok());
        let reply = report.task.unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
        assert!(matches!(reply.outcome,
            Outcome::Ok(TypedRemoteOutcome::Failed(message)) if message == "declared application failure"));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        fixture.finish(&cx).await;
    });
}

#[test]
fn typed_owned_response_limit_refuses_decoding_after_retirement_and_preserves_protocol_commit() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let remote = fixture.remote_cx(&cx);
        let mut call = spawn_remote_typed_owned::<Add>(
            &remote,
            NodeId::new("worker"),
            &(21, 21),
            TypedRemoteLimits::new(1024, 1),
            owned_config(),
        ).unwrap();
        let report = call.join(&cx).await.unwrap();
        assert!(call.is_finished(), "codec failure cannot discard the owner retirement barrier");
        assert!(!report.is_success());
        assert!(matches!(report.trigger, RemoteRunTrigger::Finished));
        assert!(report.cancel_error.is_none());
        let close = report.close.unwrap();
        assert_ne!(close.region_id, cx.region_id());
        assert!(matches!(close.outcome, Outcome::Ok(())));
        assert!(close.cleanup_outcome.as_ref().is_none_or(|value| matches!(value, Outcome::Ok(()))));
        let reply = report.task.unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed,
            "application decoding must not rewrite acknowledged remote execution");
        assert!(reply.cancellation.is_none());
        assert!(matches!(reply.outcome, Outcome::Err(TypedRemoteError::LimitExceeded {
            stage: TypedRemoteStage::Response, limit: 1,
        })));
        assert!(matches!(call.try_join(),
            Err(RemoteRunHandleError::Join(JoinError::PolledAfterCompletion))));
        let mut healthy = spawn_remote_typed_owned::<Add>(
            &remote, NodeId::new("worker"), &(6, 7), limits(), owned_config(),
        ).unwrap();
        assert!(healthy.join(&cx).await.unwrap().is_success());
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        fixture.finish(&cx).await;
    });
}

#[test]
fn typed_owned_parent_close_and_handle_drop_wait_for_inflight_remote_cleanup() {
    native(|cx, runtime| async move {
        for drop_handle in [false, true] {
            let mut fixture = Fixture::new(&cx, runtime.clone()).await;
            let remote = fixture.remote_cx(&cx);
            let boundary = remote.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            let mut call = Some(spawn_remote_typed_owned::<Wait>(
                boundary.cx(), NodeId::new("worker"), &(), limits(), owned_config(),
            ).unwrap());
            // The typed result handle has never been polled. The production
            // remote handler's actual Pending poll proves the work is live.
            fixture.gate.wait(&fixture.gate.parked).await;
            assert!(!call.as_ref().unwrap().is_finished());
            if drop_handle {
                drop(call.take());
            }
            let mut closing = Box::pin(boundary.close());
            {
                let mut cancelled = pin!(fixture.gate.wait(&fixture.gate.cancelled));
                poll_fn(|task| {
                    assert!(closing.as_mut().poll(task).is_pending(),
                        "the region cannot close before the peer retires its handler");
                    cancelled.as_mut().poll(task)
                }).await;
            }
            assert!(!fixture.gate.retired.load(Ordering::Acquire));
            assert_eq!(fixture.legacy.active_operations(), 1);
            if let Some(call) = call.as_mut() {
                assert!(call.try_join().unwrap().is_none());
            }
            fixture.gate.release();
            if let Some(call) = call.as_mut() {
                let report = call.join(&cx).await.unwrap();
                assert!(call.is_finished());
                assert!(!report.is_success());
                assert!(matches!(report.trigger, RemoteRunTrigger::Cancelled(_)));
                assert!(report.close.is_ok());
                let reply = report.task.unwrap();
                assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
                assert!(reply.cancellation.is_some());
                assert!(matches!(reply.outcome, Outcome::Ok(TypedRemoteOutcome::Cancelled(_))));
            }
            closing.await.unwrap();
            assert!(fixture.gate.retired.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested(), "the enclosing test owner remains live");
            fixture.finish(&cx).await;
        }
    });
}

#[test]
fn typed_owned_cancelled_and_dropped_observations_preserve_the_later_cleanup_report() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let remote = fixture.remote_cx(&cx);
        let mut call = spawn_remote_typed_owned::<Wait>(
            &remote, NodeId::new("worker"), &(), limits(), owned_config(),
        ).unwrap();
        fixture.gate.wait(&fixture.gate.parked).await;
        let observer = Cx::for_testing();
        observer.cancel_with(CancelKind::User, Some("cancel only owned typed observation"));
        {
            let mut observation = pin!(call.join(&observer));
            poll_fn(|task| {
                assert!(observation.as_mut().poll(task).is_pending(),
                    "owned join is an uninterruptible observation of retained cleanup");
                Poll::Ready(())
            }).await;
        }
        assert!(!fixture.gate.cancelled.load(Ordering::Acquire));
        assert!(!call.is_finished());
        {
            let mut closing = pin!(call.close(&cx));
            poll_fn(|task| {
                assert!(closing.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
        }
        // Dropping the close observation keeps its requested cancellation and
        // the actual owner; it cannot turn unfinished remote cleanup terminal.
        fixture.gate.wait(&fixture.gate.cancelled).await;
        assert!(!fixture.gate.retired.load(Ordering::Acquire));
        assert!(call.try_join().unwrap().is_none());
        assert_eq!(fixture.legacy.active_operations(), 1);
        fixture.gate.release();
        let report = call.join(&cx).await.unwrap();
        assert!(call.is_finished());
        assert!(report.close.is_ok());
        assert!(!report.is_success());
        let reply = report.task.unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
        assert!(matches!(reply.outcome, Outcome::Ok(TypedRemoteOutcome::Cancelled(_))));
        assert!(fixture.gate.retired.load(Ordering::Acquire));
        fixture.finish(&cx).await;
    });
}

#[path = "remote_typed_native/admitted_owned.rs"]
mod admitted_owned;
