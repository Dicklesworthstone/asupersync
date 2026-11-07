//! Typed payloads retain the real node/membership/native lifecycle boundaries.

use super::*;
use asupersync::distributed::{
    NativeDistributedTypedRemoteError, NativeDistributedTypedRemoteResult,
};
use asupersync::distributed::remote_owned::RemoteLeaseSettlement;
use asupersync::remote::{
    PreparedTypedRemoteCall, TypedRemoteComputation, TypedRemoteError, TypedRemoteLimits,
    TypedRemoteOutcome, TypedRemoteStage,
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

struct Add;
impl TypedRemoteComputation for Add {
    const NAME: &'static str = "node.typed.add";
    type Input = (u64, u64);
    type Output = u64;
}

struct Wait;
impl TypedRemoteComputation for Wait {
    const NAME: &'static str = "node.typed.wait";
    type Input = ();
    type Output = ();
}

struct Text;
impl TypedRemoteComputation for Text {
    const NAME: &'static str = "node.typed.text";
    type Input = String;
    type Output = String;
}

pub(super) const NAMES: [&str; 3] = [Add::NAME, Wait::NAME, Text::NAME];

pub(super) fn register(registry: &mut RemoteComputationRegistry, parked: Arc<ParkedInvocation>) {
    registry.register_typed_json::<Add, _, _>(TypedRemoteLimits::default(), |_, (left, right)| async move {
        TypedRemoteOutcome::Success(left + right)
    }).unwrap();
    registry.register_typed_json::<Text, _, _>(TypedRemoteLimits::default(), |_, text| async move {
        TypedRemoteOutcome::Success(text)
    }).unwrap();
    registry.register_typed_json::<Wait, _, _>(TypedRemoteLimits::default(), move |body, ()| {
        let parked = Arc::clone(&parked);
        async move {
            let mut cancelled = std::pin::pin!(body.cancelled());
            poll_fn(|task| {
                let next = cancelled.as_mut().poll(task);
                if next.is_pending() {
                    parked.entered.store(true, Ordering::Release);
                    parked.changed.notify_waiters();
                }
                next
            }).await;
            assert!(body.checkpoint().is_err());
            parked.cancelled.store(true, Ordering::Release);
            parked.changed.notify_waiters();
            parked.changed.wait_until(|| parked.release.load(Ordering::Acquire)).await;
            TypedRemoteOutcome::Cancelled(body.cancel_reason().unwrap())
        }
    }).unwrap();
}

#[derive(Deserialize)]
struct EncodingTripwire;
impl Serialize for EncodingTripwire {
    fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        panic!("node admission must refuse before application serialization");
    }
}
impl HasSchema for EncodingTripwire {
    fn schema() -> SchemaDescriptor { <(u64, u64)>::schema() }
}
struct RefusedAdd;
impl TypedRemoteComputation for RefusedAdd {
    const NAME: &'static str = Add::NAME;
    type Input = EncodingTripwire;
    type Output = u64;
}

static DECODE_CALLS: AtomicUsize = AtomicUsize::new(0);
struct ObservedValue(u64);
impl HasSchema for ObservedValue {
    fn schema() -> SchemaDescriptor { u64::schema() }
}
impl Serialize for ObservedValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}
impl<'de> Deserialize<'de> for ObservedValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        DECODE_CALLS.fetch_add(1, Ordering::SeqCst);
        u64::deserialize(deserializer).map(Self)
    }
}
struct ObservedAdd;
impl TypedRemoteComputation for ObservedAdd {
    const NAME: &'static str = Add::NAME;
    type Input = (u64, u64);
    type Output = ObservedValue;
}

// The granted raw echo service returns the request envelope as a Success. Its
// direction is invalid as a typed response, after real transport commitment.
struct WrongDirection;
impl TypedRemoteComputation for WrongDirection {
    const NAME: &'static str = "echo";
    type Input = ();
    type Output = ();
}

fn success<T>(result: NativeDistributedTypedRemoteResult<T>) -> T {
    assert_eq!(result.retirement, Ok(()));
    let membership = result.outcome.expect("actual typed owner result").unwrap();
    assert!(membership.is_success(), "{membership:?}");
    assert!(matches!(membership.work.lease, Ok(OwnedLeaseStatus::Released)));
    let remote = membership.work.task.unwrap().unwrap();
    assert!(remote.is_success(), "{remote:?}");
    let reply = remote.task.unwrap();
    assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed);
    match reply.outcome {
        Outcome::Ok(TypedRemoteOutcome::Success(value)) => value,
        _ => panic!("successful typed report lost its output"),
    }
}

#[test]
fn typed_node_round_trip_retains_capacity_and_preserves_codec_failure_receipts() {
    for workers in [1, 2] {
        DECODE_CALLS.store(0, Ordering::SeqCst);
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let frame_limit = client.config().wire_limits().max_frame_bytes();
            let route = NativeRemoteRoute::new(NodeId::new("worker"), hello, client);
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership.clone(), None, outbound_config(handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 1, &EncodingTripwire, TypedRemoteLimits::default(), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::Membership))));
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            outbound.publish_peer(route, 1).unwrap();
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 1, &EncodingTripwire, TypedRemoteLimits::default(),
                RemoteRunConfig { timeout: Duration::ZERO, child: ChildRegionSpec::inherit() },
            ), Err(NativeDistributedTypedRemoteError::Outbound(
                NativeDistributedOutboundError::Timing(RemoteRunError::Timeout)
            ))));

            let large = "x".repeat(frame_limit + 1);
            assert!(matches!(outbound.spawn_remote_typed::<Text>(
                NodeId::new("worker"), 1, &large, TypedRemoteLimits::new(usize::MAX, 1024), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Codec(TypedRemoteError::LimitExceeded {
                stage: TypedRemoteStage::Request, limit,
            })) if limit == frame_limit));
            let prepared = PreparedTypedRemoteCall::<Text>::encode(
                &large, TypedRemoteLimits::new(frame_limit * 2, 1024),
            ).unwrap();
            assert!(matches!(outbound.spawn_prepared_remote_typed(
                NodeId::new("worker"), 1, prepared, remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::RequestTooLarge))));
            assert_eq!(outbound.retained_operations(), 0);

            let mut first = outbound.spawn_remote_typed::<ObservedAdd>(
                NodeId::new("worker"), 1, &(19, 23), TypedRemoteLimits::default(), remote_run_config(),
            ).unwrap();
            let task_id = first.task_id();
            assert!(first.deadline() > cx.now());
            eventually(&cx, || first.is_finished()).await;
            assert_eq!(DECODE_CALLS.load(Ordering::SeqCst), 0, "unread terminal remains encoded");
            assert_eq!(outbound.retained_operations(), 1);
            assert_eq!(outbound.active_sessions(), 0);
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 1, &EncodingTripwire, TypedRemoteLimits::default(), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::OperationCapacity))));
            assert_eq!(success(assert_send(first.join()).await).0, 42);
            assert_eq!(DECODE_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(outbound.retained_operations(), 0);
            let repeated = first.join().await;
            assert!(repeated.outcome.is_none());
            assert_eq!(repeated.retirement, Err(JoinError::PolledAfterCompletion));
            assert_eq!(DECODE_CALLS.load(Ordering::SeqCst), 1);

            let prepared = PreparedTypedRemoteCall::<Add>::encode(&(7, 8), TypedRemoteLimits::default()).unwrap();
            let mut prepared = outbound.spawn_prepared_remote_typed(
                NodeId::new("worker"), 1, prepared, remote_run_config(),
            ).unwrap();
            assert_eq!(success(prepared.join().await), 15);

            let mut malformed = outbound.spawn_remote_typed::<WrongDirection>(
                NodeId::new("worker"), 1, &(), TypedRemoteLimits::default(), remote_run_config(),
            ).unwrap();
            let result = malformed.join().await;
            assert_eq!(result.retirement, Ok(()));
            let report = result.outcome.expect("actual malformed-codec report").unwrap();
            assert!(!report.is_success());
            assert!(report.work.is_success(), "transport and membership committed before decoding");
            assert!(matches!(report.work.lease, Ok(OwnedLeaseStatus::Released)));
            assert!(matches!(report.work.close.unwrap().outcome, Outcome::Ok(())));
            let remote = report.work.task.unwrap().unwrap();
            assert!(!remote.is_success());
            assert!(matches!(remote.close.unwrap().outcome, Outcome::Ok(())));
            assert!(remote.cancel_error.is_none());
            let reply = remote.task.unwrap();
            assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed);
            assert!(reply.cancellation.is_none());
            assert!(matches!(reply.outcome, Outcome::Err(TypedRemoteError::Direction {
                expected: TypedRemoteStage::Response, actual: TypedRemoteStage::Request,
            })));
            assert_eq!(outbound.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);

            let report = node.close().await;
            assert!(matches!(report.region_close, Some(Ok(()))));
            let remote = report.outbound.unwrap();
            assert!(remote.graceful);
            assert_eq!((remote.active_sessions, remote.retained_operations), (0, 0));
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 1, &EncodingTripwire, TypedRemoteLimits::default(), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::Closed))));
            println!("typed_node workers={workers} task={task_id:?} decoded=1 codec_refusal=retained active=0 owners=0");
        });
        finish(runtime);
    }
}

fn reset_parked(parked: &ParkedInvocation) {
    parked.entered.store(false, Ordering::Release);
    parked.cancelled.store(false, Ordering::Release);
    parked.release.store(false, Ordering::Release);
}

fn release_parked(parked: &ParkedInvocation) {
    parked.release.store(true, Ordering::Release);
    parked.changed.notify_waiters();
}

async fn wait_parked(cx: &Cx, parked: &ParkedInvocation, signal: &AtomicBool) {
    asupersync::time::timeout(cx.now(), WINDOW,
        parked.changed.wait_until(|| signal.load(Ordering::Acquire)),
    ).await.expect("native typed handler progress");
}

#[test]
fn typed_node_drop_revocation_rejoin_and_close_preserve_real_drain() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, parked, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let _release = ReleaseParked(Arc::clone(&parked));
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let route = NativeRemoteRoute::new(NodeId::new("worker"), hello, client);
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership.clone(), None, outbound_config(handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            outbound.publish_peer(route.clone(), 1).unwrap();

            let dropped = outbound.spawn_remote_typed::<Wait>(
                NodeId::new("worker"), 1, &(), TypedRemoteLimits::default(), remote_run_config(),
            ).unwrap();
            wait_parked(&cx, &parked, &parked.entered).await;
            assert_eq!(membership.live_leases(), 1);
            drop(dropped);
            wait_parked(&cx, &parked, &parked.cancelled).await;
            assert_eq!(outbound.retained_operations(), 1, "drop cannot free an owner whose peer still drains");
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 1, &EncodingTripwire, TypedRemoteLimits::default(), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::OperationCapacity))));
            release_parked(&parked);
            eventually(&cx, || outbound.retained_operations() == 0).await;
            assert_eq!(membership.live_leases(), 0);

            reset_parked(&parked);
            let mut revoked = outbound.spawn_remote_typed::<Wait>(
                NodeId::new("worker"), 1, &(), TypedRemoteLimits::default(), remote_run_config(),
            ).unwrap();
            wait_parked(&cx, &parked, &parked.entered).await;
            membership.apply_authenticated(&NodeId::new("authority"),
                &member_statement(1, 2, MembershipKind::Dead)).unwrap();
            wait_parked(&cx, &parked, &parked.cancelled).await;
            poll_fn(|task| {
                assert!(revoked.poll_join(task).is_pending(), "typed observation must await actual retirement");
                Poll::Ready(())
            }).await;
            assert_eq!(outbound.retained_operations(), 1);
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 1, &EncodingTripwire, TypedRemoteLimits::default(), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::Membership))));
            release_parked(&parked);
            let result = revoked.join().await;
            assert_retired(result.retirement);
            let report = result.outcome.expect("revoked typed owner retained its result").unwrap();
            assert!(!report.is_success());
            assert!(matches!(report.work.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Revoked)));
            assert!(matches!(report.work.lease, Ok(OwnedLeaseStatus::Revoked)));
            assert!(report.work.close.is_ok());
            assert_eq!(outbound.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);

            membership.apply_authenticated(&NodeId::new("authority"),
                &member_statement(2, 3, MembershipKind::Alive)).unwrap();
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 2, &EncodingTripwire, TypedRemoteLimits::default(), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::Membership))));
            outbound.publish_peer(route, 2).unwrap();
            assert!(matches!(outbound.spawn_remote_typed::<RefusedAdd>(
                NodeId::new("worker"), 1, &EncodingTripwire, TypedRemoteLimits::default(), remote_run_config(),
            ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::Membership))));
            let mut rejoined = outbound.spawn_remote_typed::<Add>(
                NodeId::new("worker"), 2, &(20, 22), TypedRemoteLimits::default(), remote_run_config(),
            ).unwrap();
            assert_eq!(success(rejoined.join().await), 42);

            reset_parked(&parked);
            let mut last = outbound.spawn_remote_typed::<Wait>(
                NodeId::new("worker"), 2, &(), TypedRemoteLimits::default(), remote_run_config(),
            ).unwrap();
            wait_parked(&cx, &parked, &parked.entered).await;
            node.begin_close();
            wait_parked(&cx, &parked, &parked.cancelled).await;
            let mut closing = std::pin::pin!(assert_send(node.close()));
            poll_fn(|task| {
                assert!(closing.as_mut().poll(task).is_pending(), "node close cannot bypass remote typed cleanup");
                Poll::Ready(())
            }).await;
            release_parked(&parked);
            let report = closing.await;
            assert!(matches!(report.region_close, Some(Ok(()))));
            let remote = report.outbound.unwrap();
            assert_eq!((remote.active_sessions, remote.retained_operations), (0, 1));
            let result = last.join().await;
            assert_retired(result.retirement);
            assert!(!result.outcome.expect("entered typed owner returned a result").is_ok_and(|report| report.is_success()));
            assert_eq!(outbound.retained_operations(), 0);
            assert_eq!(membership.live_leases(), 0);
            println!("typed_node workers={workers} generation=2 drop=drained revoked=drained node_close=drained owners=0");
        });
        finish(runtime);
    }
}

struct ReentrantInput(Arc<dyn Fn() + Send + Sync>);
impl HasSchema for ReentrantInput {
    fn schema() -> SchemaDescriptor { u64::schema() }
}
impl Serialize for ReentrantInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.0)();
        serializer.serialize_u64(1)
    }
}
impl<'de> Deserialize<'de> for ReentrantInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let _ = u64::deserialize(deserializer)?;
        Ok(Self(Arc::new(|| {})))
    }
}
struct Reentrant;
impl TypedRemoteComputation for Reentrant {
    const NAME: &'static str = Add::NAME;
    type Input = ReentrantInput;
    type Output = u64;
}

#[test]
fn typed_node_rechecks_authority_and_capacity_after_reentrant_serialization() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, membership, client, hello, .. } =
            fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
        membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
        let route = NativeRemoteRoute::new(NodeId::new("worker"), hello, client);
        let node = NativeDistributedNode::start_with_outbound(
            &cx, service, membership.clone(), None, outbound_config(handle), ChildRegionSpec::inherit(),
        ).await.unwrap();
        let outbound = node.client().unwrap();
        outbound.publish_peer(route.clone(), 1).unwrap();

        let mutate = outbound.clone();
        let withdraw = ReentrantInput(Arc::new(move || {
            mutate.remove_peer(&NodeId::new("worker")).unwrap();
        }));
        assert!(matches!(outbound.spawn_remote_typed::<Reentrant>(
            NodeId::new("worker"), 1, &withdraw, TypedRemoteLimits::default(), remote_run_config(),
        ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::Membership))));
        assert_eq!(outbound.retained_operations(), 0);
        outbound.publish_peer(route, 1).unwrap();

        let slot = Arc::new(Mutex::new(None));
        let retained = Arc::clone(&slot);
        let mutate = outbound.clone();
        let fill = ReentrantInput(Arc::new(move || {
            let owner = mutate.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"reentrant owner".to_vec()), remote_run_config(),
            ).unwrap();
            *retained.lock().unwrap() = Some(owner);
        }));
        assert!(matches!(outbound.spawn_remote_typed::<Reentrant>(
            NodeId::new("worker"), 1, &fill, TypedRemoteLimits::default(), remote_run_config(),
        ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::OperationCapacity))));
        assert_eq!(outbound.retained_operations(), 1, "only the reentrant raw owner holds credit");
        let mut admitted = slot.lock().unwrap().take().unwrap();
        assert_node_remote_success(admitted.join().await, b"reentrant owner");
        assert_eq!(outbound.retained_operations(), 0);

        let node = Arc::new(Mutex::new(Some(node)));
        let closing = Arc::clone(&node);
        let close = ReentrantInput(Arc::new(move || {
            closing.lock().unwrap().as_ref().unwrap().begin_close();
        }));
        assert!(matches!(outbound.spawn_remote_typed::<Reentrant>(
            NodeId::new("worker"), 1, &close, TypedRemoteLimits::default(), remote_run_config(),
        ), Err(NativeDistributedTypedRemoteError::Outbound(NativeDistributedOutboundError::Closed))));
        assert_eq!(outbound.retained_operations(), 0);
        let node = node.lock().unwrap().take().unwrap();
        let report = node.close().await;
        assert!(matches!(report.region_close, Some(Ok(()))));
        let remote = report.outbound.unwrap();
        assert_eq!((remote.active_sessions, remote.retained_operations), (0, 0));
        assert_eq!(membership.live_leases(), 0);
        println!("typed_node serializer_reentry route=refused capacity=refused close=refused owners=0");
    });
    finish(runtime);
}
