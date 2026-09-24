//! Native mTLS admission: authenticated alias isolation, parked cancellation,
//! protected control, unread terminal ownership, and independent legacy traffic.
#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::remote::{
    AdmittedNativeRemoteRuntime, ComputationName, NativeRemoteAdmissionError,
    NativeRemoteAdmissionLimits, NativeRemotePeerAdmissionLimits, NativeRemoteRoute,
    NativeRemoteRuntime, NativeRemoteRuntimeConfig, NodeId, RemoteCap, RemoteComputationClient,
    RemoteComputationClientConfig, RemoteComputationListenerError, RemoteComputationRegistry,
    RemoteComputationService, RemoteComputationServiceConfig, RemoteComputationServiceHandle,
    RemoteComputationServiceReport, RemoteInput, RemoteOutcome, RemotePeerAdmissionPolicy,
    RemoteProtocolVersion, RemoteServiceWireLimits, RemoteTaskState, spawn_remote,
};
use asupersync::runtime::{RuntimeBuilder, TaskHandle};
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
    RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::types::CancelReason;
use asupersync::{Cx, Outcome};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

struct Request;
struct Response;
impl HasSchema for Request {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("native-admission-request")
    }
}
impl HasSchema for Response {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("native-admission-response")
    }
}

#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cancelled: AtomicBool,
    released: AtomicBool,
    retired: AtomicBool,
    changed: Notify,
}
impl Witness {
    fn reset(&self) {
        self.parked.store(false, Ordering::Release);
        self.cancelled.store(false, Ordering::Release);
        self.released.store(false, Ordering::Release);
        self.retired.store(false, Ordering::Release);
    }
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) {
        self.0.retired.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}
struct Serving {
    route: NativeRemoteRoute,
    operator: RemoteComputationServiceHandle,
    task: TaskHandle<Result<RemoteComputationServiceReport, RemoteComputationListenerError>>,
}
struct Cleanup {
    services: Vec<RemoteComputationServiceHandle>,
    admitted: AdmittedNativeRemoteRuntime,
    legacy: Arc<NativeRemoteRuntime>,
    witness: Arc<Witness>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        self.witness.release();
        self.admitted.begin_drain();
        let _ = self.legacy.begin_drain();
        for service in &self.services {
            let _ = service.begin_drain();
        }
    }
}

async fn start_service(
    cx: &Cx,
    node: &str,
    certificate: &[u8],
    private_key: &[u8],
    witness: Arc<Witness>,
) -> Serving {
    let origin_cert = Certificate::from_pem(include_bytes!("fixtures/tls/server.crt"))
        .unwrap()
        .remove(0);
    let origin_chain =
        CertificateChain::from_pem(include_bytes!("fixtures/tls/server.crt")).unwrap();
    let origin_key = PrivateKey::from_pem(include_bytes!("fixtures/tls/server.key")).unwrap();
    let server_cert = Certificate::from_pem(certificate).unwrap().remove(0);
    let mut client_roots = RootCertStore::empty();
    client_roots.add(&origin_cert).unwrap();
    let acceptor = TlsAcceptorBuilder::new(
        CertificateChain::from_pem(certificate).unwrap(),
        PrivateKey::from_pem(private_key).unwrap(),
    )
    .client_auth(ClientAuth::Required(client_roots))
    .build()
    .unwrap();
    let server_pins = CertificatePinSet::new()
        .with_pin(CertificatePin::compute_spki_sha256(&server_cert).unwrap());
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&server_cert)
        .identity(origin_chain, origin_key)
        .with_certificate_pins(server_pins)
        .build()
        .unwrap();
    let mut registry = RemoteComputationRegistry::new();
    registry
        .register::<Request, Response, _, _>("echo", |_, invocation| async move {
            Ok(RemoteOutcome::Success(
                invocation.request().input.data().to_vec(),
            ))
        })
        .unwrap();
    registry
        .register::<Request, Response, _, _>("wait", move |cx, _| {
            let witness = Arc::clone(&witness);
            async move {
                let _retire = Retire(Arc::clone(&witness));
                let mut cancel = std::pin::pin!(cx.cancelled());
                poll_fn(|task| {
                    let next = cancel.as_mut().poll(task);
                    if next.is_pending() && !witness.parked.swap(true, Ordering::AcqRel) {
                        witness.changed.notify_waiters();
                    }
                    next
                })
                .await;
                assert!(cx.checkpoint().is_err());
                witness.cancelled.store(true, Ordering::Release);
                witness.changed.notify_waiters();
                witness
                    .changed
                    .wait_until(|| witness.released.load(Ordering::Acquire))
                    .await;
                Ok(RemoteOutcome::Cancelled(cx.cancel_reason().unwrap()))
            }
        })
        .unwrap();
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        registry.schema_registry().clone(),
    );
    policy
        .grant_tls_peer(
            NodeId::new("origin"),
            CertificatePinSet::new()
                .with_pin(CertificatePin::compute_spki_sha256(&origin_cert).unwrap()),
            ["echo", "wait"],
        )
        .unwrap();
    let hello = policy.hello_for(NodeId::new("origin"));
    let service = RemoteComputationService::bind(
        "127.0.0.1:0",
        acceptor,
        policy,
        registry,
        RemoteComputationServiceConfig::new()
            .with_max_connections(Some(8))
            .with_drain_timeout(Duration::from_secs(3)),
    )
    .await
    .unwrap();
    let endpoint = service.local_addr().unwrap();
    let operator = service.handle();
    let task = cx
        .spawn(move |cx| async move { service.run(&cx).await })
        .unwrap();
    let client = RemoteComputationClient::new(
        endpoint,
        "localhost",
        connector,
        RemoteComputationClientConfig::new()
            .with_max_attempts(1)
            .with_wire_limits(RemoteServiceWireLimits::new(4096))
            .with_connect_timeout(Duration::from_secs(2))
            .with_attempt_timeout(Duration::from_secs(3)),
    )
    .unwrap();
    Serving {
        route: NativeRemoteRoute::new(NodeId::new(node), hello, client),
        operator,
        task,
    }
}

async fn eventually(cx: &Cx, predicate: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !predicate() {
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("observable native state deadline");
}

fn exercise(workers: usize) {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .build()
            .unwrap()
    };
    let runtime_handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let witness = Arc::new(Witness::default());
        let mut a = start_service(&cx, "a", include_bytes!("fixtures/tls/server.crt"),
            include_bytes!("fixtures/tls/server.key"), Arc::clone(&witness)).await;
        let mut b = start_service(&cx, "b", include_bytes!("fixtures/tls/admission_peer.crt"),
            include_bytes!("fixtures/tls/admission_peer.key"), Arc::new(Witness::default())).await;
        let alias = NativeRemoteRoute::new(NodeId::new("a-alias"), a.route.hello().clone(), a.route.client().clone());
        let legacy = Arc::new(NativeRemoteRuntime::with_config(runtime_handle.clone(), NodeId::new("origin"),
            [a.route.clone(), b.route.clone()], NativeRemoteRuntimeConfig::new().with_max_in_flight(2)
                .with_drain_timeout(Duration::from_secs(3))).unwrap());
        let charge = 16 * (4096 + 4) + 256 * 1024;
        let peer = NativeRemotePeerAdmissionLimits { max_in_flight: 1, max_buffer_bytes: charge, max_input_bytes: 1024 };
        let admitted = AdmittedNativeRemoteRuntime::new(runtime_handle, NodeId::new("origin"),
            [(a.route.clone(), peer), (alias, peer), (b.route.clone(), peer)],
            NativeRemoteAdmissionLimits { max_routes: 3, max_in_flight: 2, max_buffer_bytes: 2 * charge,
                max_waiters: 2, max_waiters_per_peer: 1 },
            NativeRemoteRuntimeConfig::new().with_max_in_flight(2).with_drain_timeout(Duration::from_secs(3))).unwrap();
        let _cleanup = Cleanup { services: vec![a.operator.clone(), b.operator.clone()], admitted: admitted.clone(),
            legacy: Arc::clone(&legacy), witness: Arc::clone(&witness) };
        let wait = Duration::from_secs(5);
        let lease = Duration::from_millis(600);
        let node_a = NodeId::new("a"); let node_b = NodeId::new("b"); let node_alias = NodeId::new("a-alias");
        assert_eq!(admitted.reservation_bytes(&node_a), Some(charge));
        assert!(matches!(admitted.reserve(&cx, &node_a, 1025, wait).await,
            Err(NativeRemoteAdmissionError::RequestTooLarge)));
        let unused = admitted.reserve(&cx, &node_a, 1, wait).await.unwrap();
        assert_eq!(admitted.usage().in_flight, 1); drop(unused); assert_eq!(admitted.usage().in_flight, 0);
        let mismatch = admitted.reserve(&cx, &node_a, 2, wait).await.unwrap();
        assert!(matches!(mismatch.commit(&cx, &ComputationName::new("echo"), &[1], lease),
            Err(NativeRemoteAdmissionError::InputLength)));
        assert_eq!(admitted.usage().in_flight, 0);
        let expanded = admitted.reserve(&cx, &node_a, 1024, wait).await.unwrap();
        assert!(matches!(expanded.commit(&cx, &ComputationName::new("echo"), &[255; 1024], lease),
            Err(NativeRemoteAdmissionError::RequestTooLarge)), "JSON expansion must refuse before native publication");
        assert_eq!(admitted.usage().buffer_bytes, 0);

        let mut parked = admitted.reserve(&cx, &node_a, 1, wait).await.unwrap()
            .commit(&cx, &ComputationName::new("wait"), &[7], lease).unwrap();
        eventually(&cx, || witness.parked.load(Ordering::Acquire) && parked.state() == RemoteTaskState::Running).await;
        let mut healthy = admitted.reserve(&cx, &node_b, 3, wait).await.unwrap()
            .commit(&cx, &ComputationName::new("echo"), &[3, 2, 1], lease).unwrap();
        eventually(&cx, || healthy.state() == RemoteTaskState::Completed).await;
        assert_eq!(admitted.usage().in_flight, 2, "unread terminal results retain buffer credit");
        assert_eq!(admitted.usage().buffer_bytes, 2 * charge);
        assert_eq!(admitted.peer_usage(&node_a), admitted.peer_usage(&node_alias));

        // Legacy work uses a genuinely distinct adapter/driver domain. Its real
        // traffic cannot consume or bypass the admitted domain's full counters.
        let legacy_cx = cx.clone().with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin")).with_runtime(legacy.clone()));
        let mut old = spawn_remote(&legacy_cx, node_b.clone(), ComputationName::new("echo"), RemoteInput::new(vec![9])).unwrap();
        assert!(matches!(old.join(&legacy_cx).await, Outcome::Ok(RemoteOutcome::Success(value)) if value == [9]));
        assert_eq!(admitted.usage().buffer_bytes, 2 * charge);

        let queued_cx = Arc::new(Mutex::new(None));
        let queued_seen = Arc::clone(&queued_cx); let queued_domain = admitted.clone();
        let mut queued = cx.spawn(move |task_cx| async move {
            *queued_seen.lock() = Some(task_cx.clone());
            queued_domain.reserve(&task_cx, &NodeId::new("a-alias"), 1, wait).await
        }).unwrap();
        eventually(&cx, || admitted.usage().waiters == 1).await;
        assert_eq!(admitted.peer_usage(&node_a).unwrap().waiters, 1);
        assert!(matches!(admitted.reserve(&cx, &node_alias, 1, wait).await,
            Err(NativeRemoteAdmissionError::Queue(asupersync::distributed::remote_owned::RemoteReserveError::QueueLimit(_)))));
        queued_cx.lock().as_ref().unwrap().set_cancel_reason(CancelReason::user("cancel actual parked admission"));
        assert!(matches!(queued.join(&cx).await.unwrap(), Err(NativeRemoteAdmissionError::Queue(
            asupersync::distributed::remote_owned::RemoteReserveError::Cancelled))));
        assert_eq!(admitted.usage().waiters, 0);
        assert_eq!(admitted.usage().in_flight, 2);

        // Cancellation must use its protected control slot under full data quota,
        // and withheld service cleanup must continue holding the active charge.
        let reason = CancelReason::user("admission full-data cancellation");
        let mut closing = Box::pin(parked.close(&cx, &reason));
        poll_fn(|task| { assert!(closing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        eventually(&cx, || witness.cancelled.load(Ordering::Acquire)).await;
        assert_eq!(admitted.usage().buffer_bytes, 2 * charge);
        assert!(!witness.retired.load(Ordering::Acquire));
        witness.release();
        let result = closing.await.unwrap();
        assert!(matches!(result, Outcome::Ok(RemoteOutcome::Cancelled(value)) if value == reason));
        eventually(&cx, || admitted.usage().in_flight == 1).await;
        assert!(matches!(healthy.try_join().unwrap(), Some(RemoteOutcome::Success(value)) if value == [3, 2, 1]));
        eventually(&cx, || admitted.usage().in_flight == 0).await;

        // Drop of a live handle cannot return credit while its native driver
        // still owns the request and waits for the server's cancellation drain.
        witness.reset();
        let dropped = admitted.reserve(&cx, &node_a, 0, wait).await.unwrap()
            .commit(&cx, &ComputationName::new("wait"), &[], lease).unwrap();
        eventually(&cx, || witness.parked.load(Ordering::Acquire)).await;
        drop(dropped);
        eventually(&cx, || witness.cancelled.load(Ordering::Acquire)).await;
        assert_eq!(admitted.usage().in_flight, 1);
        witness.release(); eventually(&cx, || admitted.usage().in_flight == 0).await;

        // Native-domain close uses one protected, removable registration. A
        // second close cannot append unbounded legacy drain-waiter metadata.
        witness.reset();
        let mut final_handle = admitted.reserve(&cx, &node_a, 0, wait).await.unwrap()
            .commit(&cx, &ComputationName::new("wait"), &[], lease).unwrap();
        eventually(&cx, || witness.parked.load(Ordering::Acquire)).await;
        let issued = admitted.reserve(&cx, &node_b, 0, wait).await.unwrap();
        let mut first_close = Box::pin(admitted.close(&cx));
        poll_fn(|task| { assert!(first_close.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        assert!(matches!(admitted.close(&cx).await, Err(NativeRemoteAdmissionError::CloseInProgress)));
        assert!(matches!(issued.commit(&cx, &ComputationName::new("echo"), &[], lease), Err(NativeRemoteAdmissionError::Closed)));
        drop(first_close);
        eventually(&cx, || witness.cancelled.load(Ordering::Acquire)).await;
        witness.release();
        assert!(admitted.close(&cx).await.unwrap());
        assert_eq!(admitted.usage().in_flight, 1, "terminal handle remains charged after driver close");
        assert!(matches!(final_handle.try_join().unwrap(), Some(RemoteOutcome::Cancelled(_))));
        eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
        assert_eq!(admitted.usage().waiters, 0);
        assert!(legacy.close(&cx).await);
        let _ = a.operator.begin_drain(); let _ = b.operator.begin_drain();
        assert!(a.task.join(&cx).await.unwrap().is_ok()); assert!(b.task.join(&cx).await.unwrap().is_ok());
        eprintln!("{}", serde_json::json!({"bead":"asupersync-bi2462.77", "workers":workers,
            "authenticated_peers":2, "aliases":1, "high_water_bytes":2*charge,
            "parked_waiter_cancelled":true, "control_under_full_data":"terminal_cancelled",
            "legacy_domain":"independent", "remaining_bytes":admitted.usage().buffer_bytes,
            "remaining_waiters":admitted.usage().waiters}));
    });
}

#[test]
fn native_admission_pins_peers_and_retains_every_buffer_owner() {
    for workers in [1, 2] {
        let (done, result) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            exercise(workers);
            done.send(()).unwrap();
        });
        result
            .recv_timeout(Duration::from_secs(45))
            .expect("native admission scenario must finish without a wall-clock hang");
        thread.join().unwrap();
    }
}

#[derive(Clone, Default)]
struct ReentrantMetrics {
    close: Arc<Mutex<Option<AdmittedNativeRemoteRuntime>>>,
    observed: Arc<AtomicBool>,
}

impl asupersync::observability::metrics::MetricsProvider for ReentrantMetrics {
    fn task_spawned(&self, _: asupersync::types::RegionId, _: asupersync::types::TaskId) {
        let target = self.close.lock().take();
        if let Some(target) = target {
            target.begin_drain();
            self.observed.store(true, Ordering::Release);
        }
    }
    fn task_completed(
        &self,
        _: asupersync::types::TaskId,
        _: asupersync::observability::OutcomeKind,
        _: Duration,
    ) {
    }
    fn region_created(
        &self,
        _: asupersync::types::RegionId,
        _: Option<asupersync::types::RegionId>,
    ) {
    }
    fn region_closed(&self, _: asupersync::types::RegionId, _: Duration) {}
    fn cancellation_requested(
        &self,
        _: asupersync::types::RegionId,
        _: asupersync::types::CancelKind,
    ) {
    }
    fn drain_completed(&self, _: asupersync::types::RegionId, _: Duration) {}
    fn deadline_set(&self, _: asupersync::types::RegionId, _: Duration) {}
    fn deadline_exceeded(&self, _: asupersync::types::RegionId) {}
    fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}
    fn deadline_violation(&self, _: &str, _: Duration) {}
    fn deadline_remaining(&self, _: &str, _: Duration) {}
    fn checkpoint_interval(&self, _: &str, _: Duration) {}
    fn task_stuck_detected(&self, _: &str) {}
    fn obligation_created(&self, _: asupersync::types::RegionId) {}
    fn obligation_discharged(&self, _: asupersync::types::RegionId) {}
    fn obligation_leaked(&self, _: asupersync::types::RegionId) {}
    fn scheduler_tick(&self, _: usize, _: Duration) {}
}

#[test]
fn native_admission_close_can_reenter_synchronous_spawn_metrics() {
    let (done, result) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let metrics = ReentrantMetrics::default();
        let runtime = RuntimeBuilder::current_thread()
            .metrics(metrics.clone())
            .build()
            .unwrap();
        let handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let witness = Arc::new(Witness::default());
            let mut serving = start_service(&cx, "peer", include_bytes!("fixtures/tls/server.crt"),
                include_bytes!("fixtures/tls/server.key"), Arc::clone(&witness)).await;
            let charge = 16 * (4096 + 4) + 256 * 1024;
            let admitted = AdmittedNativeRemoteRuntime::new(handle, NodeId::new("origin"),
                [(serving.route.clone(), NativeRemotePeerAdmissionLimits { max_in_flight: 1,
                    max_buffer_bytes: charge, max_input_bytes: 1 })],
                NativeRemoteAdmissionLimits { max_routes: 1, max_in_flight: 1, max_buffer_bytes: charge,
                    max_waiters: 0, max_waiters_per_peer: 0 }, NativeRemoteRuntimeConfig::new()).unwrap();
            let permit = admitted.reserve(&cx, &NodeId::new("peer"), 0, Duration::from_secs(1)).await.unwrap();
            *metrics.close.lock() = Some(admitted.clone());
            let mut invocation = permit.commit(&cx, &ComputationName::new("wait"), &[], Duration::from_secs(1)).unwrap();
            assert!(metrics.observed.load(Ordering::Acquire), "close ran inside synchronous spawn effects");
            assert!(matches!(invocation.join(&cx).await, Outcome::Err(asupersync::remote::RemoteError::Cancelled(reason))
                if reason.is_shutdown()));
            assert!(!witness.parked.load(Ordering::Acquire), "closed admission never dispatches application work");
            assert!(admitted.close(&cx).await.unwrap());
            assert_eq!(admitted.usage().buffer_bytes, 0);
            let _ = serving.operator.begin_drain();
            assert!(serving.task.join(&cx).await.unwrap().is_ok());
            eprintln!("{}", serde_json::json!({"bead":"asupersync-bi2462.77", "case":"reentrant_spawn_metrics_close",
                "callback_observed":true, "dispatched":false, "remaining_bytes":admitted.usage().buffer_bytes}));
        });
        done.send(()).unwrap();
    });
    result
        .recv_timeout(Duration::from_secs(15))
        .expect("reentrant close must not deadlock commit");
    thread.join().unwrap();
}
