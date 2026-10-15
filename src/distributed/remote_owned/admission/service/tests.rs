use super::*;
use crate::distributed::SchemaDescriptor;
use crate::remote::{
    ComputationName, IdempotencyKey, RemoteComputationDispatchError, RemoteInput,
    RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteTaskId, SpawnRequest,
};
use crate::runtime::RuntimeBuilder;
use crate::sync::Notify;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Context;
use std::time::Duration;

struct Bytes;
impl HasSchema for Bytes {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("admitted-service-test.bytes.v1") }
}
fn budget() -> RemoteServiceAdmission {
    RemoteServiceAdmission::new(
        RemoteAdmissionLimits { max_peers: 2, max_in_flight: 2, max_input_bytes: 8 },
        ["a", "b"].map(|peer| (NodeId::new(peer), RemotePeerLimits {
            max_in_flight: 1, max_input_bytes: 4, max_request_bytes: 4,
        })),
    ).unwrap()
}
fn registry<F, Fut>(admission: &RemoteServiceAdmission, f: F) -> RemoteComputationRegistry
where
    F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
{
    let mut registry = RemoteComputationRegistry::new();
    admission.register::<Bytes, Bytes, _, _>(&mut registry, "work", ChildRegionSpec::inherit(), f).unwrap();
    registry
}

// Local policy admission tests the registry/adapter seam, not certificate binding.
async fn dispatch_named(
    cx: &Cx, registry: &RemoteComputationRegistry, name: &str,
    peer: &str, origin: &str, bytes: &[u8],
) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    let peer = NodeId::new(peer);
    policy.grant_peer(peer.clone(), [name]).unwrap();
    let session = policy.admit(&policy.hello_for(peer)).unwrap();
    let task = RemoteTaskId::next();
    registry.dispatch(cx, &session, SpawnRequest {
        remote_task_id: task, computation: ComputationName::new(name), input: RemoteInput::new(bytes.to_vec()),
        lease: Duration::from_secs(10), idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())),
        budget: None, origin_node: NodeId::new(origin), origin_region: cx.region_id(), origin_task: cx.task_id(),
    }).await
}
async fn dispatch(cx: &Cx, registry: &RemoteComputationRegistry, peer: &str, bytes: &[u8])
    -> Result<RemoteOutcome, RemoteComputationDispatchError>
{
    dispatch_named(cx, registry, "work", peer, peer, bytes).await
}
fn native<F, Fut>(f: F)
where F: FnOnce(Cx) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let mut task = cx.spawn(f).unwrap();
        crate::time::timeout(cx.now(), Duration::from_secs(10), task.join(&cx)).await
            .expect("inbound admission test watchdog").expect("inbound test task");
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[derive(Default)]
struct Gates {
    started: AtomicBool,
    cancelling: AtomicBool,
    release: AtomicBool,
    dropped: AtomicBool,
    changed: Notify,
}
impl Gates {
    fn release(&self) { self.release.store(true, Ordering::Release); self.changed.notify_waiters(); }
}
struct Release(Arc<Gates>);
impl Drop for Release { fn drop(&mut self) { self.0.release(); } }
struct Dropped(Arc<Gates>);
impl Drop for Dropped {
    fn drop(&mut self) { self.0.dropped.store(true, Ordering::Release); self.0.changed.notify_waiters(); }
}
async fn delayed(cx: Cx, gates: Arc<Gates>) -> Result<RemoteOutcome, RemoteError> {
    let _drop = Dropped(Arc::clone(&gates));
    let mut cancel = std::pin::pin!(cx.cancelled());
    poll_fn(|task| {
        let result = cancel.as_mut().poll(task);
        if result.is_pending() && !gates.started.swap(true, Ordering::AcqRel) { gates.changed.notify_waiters(); }
        result
    }).await;
    let _ = cx.checkpoint();
    gates.cancelling.store(true, Ordering::Release); gates.changed.notify_waiters();
    gates.changed.wait_until(|| gates.release.load(Ordering::Acquire)).await;
    Ok(RemoteOutcome::Success(b"late".to_vec()))
}

#[test]
fn original_schemas_and_clean_child_result_are_preserved() {
    native(|cx| async move {
        let admission = budget(); let seen = admission.clone(); let region = cx.region_id();
        let registry = registry(&admission, move |child, invocation| {
            assert_ne!(child.region_id(), region);
            assert_eq!(seen.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
            assert_eq!(invocation.peer_node().as_str(), "a");
            async move { Ok(RemoteOutcome::Success(invocation.into_request().input.into_data())) }
        });
        let mut ordinary = RemoteComputationRegistry::new();
        ordinary.register::<Bytes, Bytes, _, _>("work", |_, _| async { Ok(RemoteOutcome::Success(Vec::new())) }).unwrap();
        assert_eq!(registry.schema_registry().fingerprint(), ordinary.schema_registry().fingerprint());
        assert!(matches!(dispatch(&cx, &registry, "a", b"data").await, Ok(RemoteOutcome::Success(value)) if value == b"data"));
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
        assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn quota_uses_admitted_peer_not_the_asserted_request_origin() {
    native(|cx| async move {
        let admission = budget(); let seen = admission.clone();
        let registry = registry(&admission, move |_, invocation| {
            assert_eq!(invocation.request().origin_node.as_str(), "b");
            assert_eq!(seen.peer_usage(&NodeId::new("a")).unwrap().in_flight, 1);
            assert_eq!(seen.peer_usage(&NodeId::new("b")).unwrap().in_flight, 0);
            async { Ok(RemoteOutcome::Success(Vec::new())) }
        });
        assert!(matches!(dispatch_named(&cx, &registry, "work", "a", "b", b"x").await, Ok(RemoteOutcome::Success(_))));
        let refusal = dispatch_named(&cx, &registry, "work", "unknown", "a", b"x").await.unwrap();
        assert!(matches!(refusal, RemoteOutcome::Failed(message) if message == "remote service admission refused: remote admission peer is not configured"));
        assert_eq!(admission.usage().in_flight, 0);
    });
}

#[test]
fn oversized_input_refuses_before_factory_invocation() {
    native(|cx| async move {
        let admission = budget(); let calls = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&calls);
        let registry = registry(&admission, move |_, _| {
            seen.fetch_add(1, Ordering::SeqCst); async { Ok(RemoteOutcome::Success(Vec::new())) }
        });
        assert!(matches!(dispatch(&cx, &registry, "a", b"large").await, Ok(RemoteOutcome::Failed(message))
            if message == "remote service admission refused: remote request payload exceeds its admission limit"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
    });
}

#[test]
fn closed_admission_is_shared_by_existing_registry_clones() {
    native(|cx| async move {
        let admission = budget();
        let registry = registry(&admission, |_, _| async { panic!("closed factory must not run") });
        let copied = registry.clone();
        assert!(admission.clone().close_admission()); assert!(!admission.close_admission());
        for registry in [&registry, &copied] {
            assert!(matches!(dispatch(&cx, registry, "a", b"").await, Ok(RemoteOutcome::Failed(message))
                if message == "remote service admission refused: remote executor admission is closed"));
        }
        assert_eq!(admission.usage().in_flight, 0);
    });
}

#[test]
fn empty_payload_can_run_with_zero_byte_limits() {
    native(|cx| async move {
        let admission = RemoteServiceAdmission::new(
            RemoteAdmissionLimits { max_peers: 1, max_in_flight: 1, max_input_bytes: 0 },
            [(NodeId::new("a"), RemotePeerLimits { max_in_flight: 1, max_input_bytes: 0, max_request_bytes: 0 })],
        ).unwrap();
        let registry = registry(&admission, |_, _| async { Ok(RemoteOutcome::Success(Vec::new())) });
        assert!(matches!(dispatch(&cx, &registry, "a", b"").await, Ok(RemoteOutcome::Success(_))));
        assert!(matches!(dispatch(&cx, &registry, "a", b"x").await, Ok(RemoteOutcome::Failed(_))));
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
    });
}

#[test]
fn missing_runtime_does_not_fall_back_to_inline_user_code() {
    let admission = budget();
    let registry = registry(&admission, |_, _| async { panic!("detached factory must not run") });
    let cx = Cx::for_testing();
    let result = futures_lite::future::block_on(dispatch(&cx, &registry, "a", b"x"));
    assert!(matches!(result, Err(RemoteComputationDispatchError::Execution(RemoteError::TransportError(_)))));
    assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
}

fn cancelled_dispatch(drop_waiter: bool) {
    native(move |cx| async move {
        let admission = budget(); let gates = Arc::new(Gates::default()); let _release = Release(Arc::clone(&gates));
        let work = Arc::clone(&gates);
        let mut registry = registry(&admission, move |child, _| delayed(child, Arc::clone(&work)));
        admission.register::<Bytes, Bytes, _, _>(&mut registry, "other", ChildRegionSpec::inherit(),
            |_, _| async { Ok(RemoteOutcome::Success(b"other".to_vec())) }).unwrap();
        let copied = registry.clone();
        let mut pending = Box::pin(dispatch(&cx, &copied, "a", b"data"));
        let mut started = Box::pin(gates.changed.wait_until(|| gates.started.load(Ordering::Acquire)));
        poll_fn(|task| {
            assert!(pending.as_mut().poll(task).is_pending()); started.as_mut().poll(task)
        }).await;
        drop(started);
        assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
        if drop_waiter {
            drop(pending);
        } else {
            // The admitted work sees this genuine context cancellation. A separate
            // live context below is used for additional requests and cleanup checks.
            cx.cancel_with(crate::types::CancelKind::User, Some("inbound cancellation test"));
            let mut cancelling = Box::pin(gates.changed.wait_until(|| gates.cancelling.load(Ordering::Acquire)));
            poll_fn(|task| {
                assert!(pending.as_mut().poll(task).is_pending()); cancelling.as_mut().poll(task)
            }).await;
            drop(cancelling);
            gates.release();
            assert!(matches!(pending.await, Ok(RemoteOutcome::Cancelled(_))));
            assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
            let _ = cx.checkpoint();
            return;
        }
        gates.changed.wait_until(|| gates.cancelling.load(Ordering::Acquire)).await;
        assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
        assert!(matches!(dispatch_named(&cx, &registry, "other", "a", "a", b"").await, Ok(RemoteOutcome::Failed(message))
            if message == "remote service admission refused: remote peer invocation limit reached"));
        assert!(matches!(dispatch_named(&cx, &registry, "other", "b", "b", b"xx").await,
            Ok(RemoteOutcome::Success(value)) if value == b"other"));
        gates.release();
        gates.changed.wait_until(|| gates.dropped.load(Ordering::Acquire)).await;
        // The destructor precedes coordinator close; wait for that actual task
        // to finish rather than treating the first destructor as a drain receipt.
        while admission.usage().in_flight != 0 { crate::time::sleep(cx.now(), Duration::from_millis(1)).await; }
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
        assert!(!cx.is_cancel_requested());
    });
}
#[test]
fn cancellation_retains_charge_through_withheld_handler_cleanup() { cancelled_dispatch(false); }
#[test]
fn dropped_dispatch_keeps_capacity_and_other_peers_can_progress() { cancelled_dispatch(true); }

#[test]
fn returned_body_does_not_release_capacity_while_descendants_drain() {
    native(|cx| async move {
        let admission = budget(); let gates = Arc::new(Gates::default()); let _release = Release(Arc::clone(&gates));
        let seen = Arc::clone(&gates);
        let registry = registry(&admission, move |child, _| {
            let seen = Arc::clone(&seen);
            async move {
                let inner = Arc::clone(&seen);
                let _child = child.spawn(move |cx| delayed(cx, inner)).unwrap();
                seen.changed.wait_until(|| seen.started.load(Ordering::Acquire)).await;
                Ok(RemoteOutcome::Success(b"body".to_vec()))
            }
        });
        let mut pending = Box::pin(dispatch(&cx, &registry, "a", b"data"));
        let mut draining = Box::pin(gates.changed.wait_until(|| gates.cancelling.load(Ordering::Acquire)));
        poll_fn(|task| { assert!(pending.as_mut().poll(task).is_pending()); draining.as_mut().poll(task) }).await;
        drop(draining);
        assert_eq!(admission.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
        gates.release();
        let result = pending.await;
        assert!(result.is_ok(), "{result:?}");
        assert!(gates.dropped.load(Ordering::Acquire));
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
    });
}

#[test]
fn handler_errors_keep_the_original_typed_remote_error() {
    native(|cx| async move {
        let admission = budget();
        let registry = registry(&admission, |_, _| async { Err(RemoteError::SerializationError("bad application bytes".to_owned())) });
        assert!(matches!(dispatch(&cx, &registry, "a", b"data").await,
            Err(RemoteComputationDispatchError::Execution(RemoteError::SerializationError(message))) if message == "bad application bytes"));
        assert_eq!(admission.usage().in_flight, 0);
    });
}

#[test]
fn factory_panic_is_isolated_and_releases_admission_after_close() {
    native(|cx| async move {
        let admission = budget();
        let registry = registry(&admission, |_, _| -> std::future::Ready<Result<RemoteOutcome, RemoteError>> {
            panic!("factory secret must not appear in adapter diagnostics")
        });
        assert!(matches!(dispatch(&cx, &registry, "a", b"x").await, Ok(RemoteOutcome::Panicked(message))
            if !message.contains("factory secret")));
        assert_eq!(admission.usage().in_flight, 0);
        assert!(!cx.is_cancel_requested());
    });
}

struct ReadyWithDrop { admission: RemoteServiceAdmission, observed: Arc<AtomicBool>, panic: bool }
impl Future for ReadyWithDrop {
    type Output = Result<RemoteOutcome, RemoteError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(self.admission.usage().in_flight, 1);
        Poll::Ready(Ok(RemoteOutcome::Success(Vec::new())))
    }
}
impl Drop for ReadyWithDrop {
    fn drop(&mut self) {
        assert_eq!(self.admission.usage().in_flight, 1, "destructor runs before admission retirement");
        self.observed.store(true, Ordering::Release);
        assert!(!self.panic, "destructor sentinel");
    }
}
fn destructor_case(panic: bool) {
    native(move |cx| async move {
        let admission = budget(); let seen = admission.clone(); let observed = Arc::new(AtomicBool::new(false)); let flag = Arc::clone(&observed);
        let registry = registry(&admission, move |_, _| ReadyWithDrop { admission: seen.clone(), observed: Arc::clone(&flag), panic });
        let result = dispatch(&cx, &registry, "a", b"x").await.unwrap();
        assert!(if panic { matches!(result, RemoteOutcome::Panicked(_)) } else { matches!(result, RemoteOutcome::Success(_)) });
        assert!(observed.load(Ordering::Acquire)); assert_eq!(admission.usage().in_flight, 0);
    });
}
#[test]
fn future_destructor_can_reenter_usage_before_capacity_release() { destructor_case(false); }
#[test]
fn destructor_panic_cannot_publish_success() { destructor_case(true); }

#[test]
fn cancelled_before_first_dispatch_poll_runs_no_factory_and_charges_nothing() {
    native(|cx| async move {
        let admission = budget();
        let registry = registry(&admission, |_, _| async { panic!("pre-cancel factory") });
        cx.cancel_with(crate::types::CancelKind::User, Some("before dispatch"));
        assert!(matches!(dispatch(&cx, &registry, "a", b"x").await, Ok(RemoteOutcome::Cancelled(_))));
        assert_eq!(admission.usage(), RemoteAdmissionUsage::default());
        let _ = cx.checkpoint();
    });
}
