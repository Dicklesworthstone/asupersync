//! Real V3 mTLS remote execution through checked child-region proxy ownership.
//! These are native service tests, not a custom wire or a transport mock.
#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::distributed::remote_owned::{
    RemoteLeaseSettlement, RemoteRunConfig, RemoteRunTrigger, run_remote,
};
use asupersync::observability::diagnostics::Reason;
use asupersync::remote::{
    ComputationName, NativeRemoteRoute, NativeRemoteRuntime, NativeRemoteRuntimeConfig,
    NodeId, RemoteCap, RemoteComputationClient, RemoteComputationClientConfig,
    RemoteComputationRegistry, RemoteComputationService, RemoteComputationServiceConfig,
    RemoteComputationServiceHandle, RemoteError, RemoteInput, RemoteOutcome,
    RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteRuntime,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::Notify;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
    PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
};
use asupersync::types::{RegionId, TaskId};
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
}
impl Drop for Stop {
    fn drop(&mut self) { let _ = self.remote.begin_drain(); let _ = self.service.begin_drain(); }
}
#[derive(Clone, Copy)]
enum Case { Success, Cancel, Deadline, Drop }
fn config() -> RemoteRunConfig {
    RemoteRunConfig { timeout: Duration::from_secs(5), child: ChildRegionSpec::inherit() }
}

fn exercise(workers: usize, case: Case) {
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
            NodeId::new("origin"), [NativeRemoteRoute::new(NodeId::new("worker"), hello, client)],
            NativeRemoteRuntimeConfig::new().with_max_in_flight(4).with_drain_timeout(Duration::from_secs(3))).unwrap());
        let _stop = Stop { service: operator.clone(), remote: Arc::clone(&remote) };
        let cx = base.with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin"))
            .with_default_lease(Duration::from_secs(20)).with_runtime(Arc::clone(&remote) as Arc<dyn RemoteRuntime>));

        if matches!(case, Case::Success) {
            let report = run_remote(&cx, NodeId::new("worker"), ComputationName::new("echo"),
                RemoteInput::new(b"native-secret".to_vec()), config()).await.unwrap();
            assert!(report.is_success(), "{report:?}");
            assert!(!format!("{report:?}").contains("native-secret"));
            assert!(matches!(report.task.unwrap().outcome, Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"native-secret"));
            assert_eq!(remote.active_operations(), 0);
        } else if matches!(case, Case::Drop) {
            let mut running = Box::pin(run_remote(&cx, NodeId::new("worker"), ComputationName::new("wait"), RemoteInput::empty(), config()));
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
            witness.release.store(true, Ordering::Release); witness.changed.notify_waiters();
            asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
                loop {
                    if remote.active_operations() == 0 && !holds_lease(&diagnostics, region, holder) { break; }
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            }).await.expect("dropped runner's region retained and drained proxy");
            assert!(witness.dropped.load(Ordering::Acquire)); assert!(!cx.is_cancel_requested());
        } else {
            let mut bounds = config();
            if matches!(case, Case::Deadline) { bounds.timeout = Duration::from_secs(2); }
            let mut invocation = cx.spawn(move |owner| async move {
                let result = run_remote(&owner, NodeId::new("worker"), ComputationName::new("wait"), RemoteInput::empty(), bounds).await;
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
            assert!(invocation.try_join().unwrap().is_none(), "sending Cancel is not terminal collection");
            assert!(holds_lease(&diagnostics, region, holder));
            assert_eq!(remote.active_operations(), 1);
            // A different invocation on the same remote runtime still works;
            // cancelling one scope never calls global begin_drain/close.
            let other = run_remote(&cx, NodeId::new("worker"), ComputationName::new("echo"),
                RemoteInput::new(b"unrelated".to_vec()), config()).await.unwrap();
            assert!(other.is_success()); assert_eq!(remote.active_operations(), 1);
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
