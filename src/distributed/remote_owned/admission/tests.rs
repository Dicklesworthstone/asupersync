use super::*;
use crate::channel::oneshot;
use crate::cx::ChildRegionSpec;
use crate::distributed::remote_owned::{AdmittedProxy, RemoteRunTrigger};
use crate::remote::{MessageEnvelope, RemoteCap, RemoteError, RemoteMessage, RemoteOutcome, RemoteRuntime, RemoteTaskId};
use crate::runtime::RuntimeBuilder;
use crate::sync::Notify;
use crate::types::Outcome;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

fn peer() -> RemotePeerLimits {
    RemotePeerLimits { max_in_flight: 2, max_input_bytes: 8, max_request_bytes: 4 }
}
fn executor(total: usize, bytes: usize, policy: RemotePeerLimits) -> RemoteExecutor {
    RemoteExecutor::new(RemoteAdmissionLimits { max_peers: 2, max_in_flight: total, max_input_bytes: bytes },
        [(NodeId::new("a"), policy), (NodeId::new("b"), policy)]).unwrap()
}
fn refusal(executor: &RemoteExecutor, node: &str, bytes: usize) -> RemoteAdmissionError {
    match executor.acquire(&NodeId::new(node), bytes) {
        Err(error) => error, Ok(_) => panic!("expected admission refusal"),
    }
}
fn empty(executor: &RemoteExecutor) { assert_eq!(executor.usage(), RemoteAdmissionUsage::default()); }

#[test]
fn per_peer_count_is_shared_by_clones_without_starving_another_peer() {
    let policy = RemotePeerLimits { max_in_flight: 1, ..peer() };
    let executor = executor(2, 8, policy);
    let a = executor.acquire(&NodeId::new("a"), 4).unwrap();
    assert_eq!(refusal(&executor.clone(), "a", 0), RemoteAdmissionError::PeerInFlight);
    let b = executor.clone().acquire(&NodeId::new("b"), 4).unwrap();
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 2, input_bytes: 8 });
    drop(a); assert_eq!(executor.peer_usage(&NodeId::new("a")).unwrap().in_flight, 0);
    drop(b); empty(&executor);
}

#[test]
fn all_three_payload_bounds_are_independent_and_exact_limits_are_admitted() {
    let executor = executor(8, 6, RemotePeerLimits { max_input_bytes: 4, ..peer() });
    assert_eq!(refusal(&executor, "a", 5), RemoteAdmissionError::RequestBytes);
    let a = executor.acquire(&NodeId::new("a"), 4).unwrap();
    assert_eq!(refusal(&executor, "a", 1), RemoteAdmissionError::PeerBytes);
    assert_eq!(refusal(&executor, "b", 3), RemoteAdmissionError::TotalBytes);
    let b = executor.acquire(&NodeId::new("b"), 2).unwrap();
    assert_eq!(executor.usage().input_bytes, 6);
    drop((a, b)); empty(&executor);
}

#[test]
fn total_invocation_bound_is_not_the_sum_of_peer_limits() {
    let executor = executor(1, 16, peer());
    let a = executor.acquire(&NodeId::new("a"), 0).unwrap();
    assert_eq!(refusal(&executor, "b", 0), RemoteAdmissionError::TotalInFlight);
    assert_eq!(executor.peer_usage(&NodeId::new("b")).unwrap(), RemoteAdmissionUsage::default());
    drop(a); empty(&executor);
}

#[test]
fn zero_count_denies_empty_requests_but_zero_byte_budget_admits_them() {
    let denied = executor(0, 0, peer());
    assert_eq!(refusal(&denied, "a", 0), RemoteAdmissionError::TotalInFlight);
    let allowed = executor(1, 0, RemotePeerLimits { max_request_bytes: 0, max_input_bytes: 0, ..peer() });
    let a = allowed.acquire(&NodeId::new("a"), 0).unwrap();
    assert_eq!(refusal(&allowed, "b", 1), RemoteAdmissionError::RequestBytes);
    drop(a); empty(&allowed);
}

#[test]
fn peer_configuration_is_fixed_bounded_and_never_silently_overwritten() {
    let limits = RemoteAdmissionLimits { max_peers: 2, max_in_flight: 2, max_input_bytes: 16 };
    for label in [String::new(), "x".repeat(256)] {
        assert!(matches!(RemoteExecutor::new(limits, [(NodeId::new(label), peer())]), Err(RemoteAdmissionError::InvalidPeer)));
    }
    assert!(matches!(RemoteExecutor::new(limits, [(NodeId::new("a"), peer()), (NodeId::new("a"), peer())]), Err(RemoteAdmissionError::DuplicatePeer)));
    assert!(matches!(RemoteExecutor::new(limits, (0..3).map(|n| (NodeId::new(n.to_string()), peer()))), Err(RemoteAdmissionError::PeerLimit)));
    let executor = executor(2, 16, peer());
    assert_eq!(refusal(&executor, "unknown", 0), RemoteAdmissionError::UnknownPeer);
    assert_eq!(executor.peer_usage(&NodeId::new("unknown")), None); empty(&executor);
}

#[test]
fn clones_of_one_permit_retain_exactly_one_charge_until_the_last_owner_drops() {
    let executor = executor(1, 8, peer());
    let root = executor.acquire(&NodeId::new("a"), 4).unwrap();
    let proxy = root.clone();
    drop(root);
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
    drop(proxy); empty(&executor);
}

#[test]
fn scope_retains_admission_after_the_proxy_finishes_until_local_close() {
    let executor = executor(1, 8, peer());
    let root = executor.acquire(&NodeId::new("a"), 4).unwrap();
    let proxy = root.clone(); drop(proxy);
    assert_eq!(refusal(&executor, "b", 0), RemoteAdmissionError::TotalInFlight);
    assert_eq!(executor.usage().input_bytes, 4);
    drop(root); empty(&executor);
}

#[test]
fn permanent_admission_close_preserves_existing_charges_and_shared_state() {
    let executor = executor(2, 8, peer()); let copy = executor.clone();
    let a = executor.acquire(&NodeId::new("a"), 4).unwrap();
    assert!(copy.close_admission()); assert!(!executor.close_admission());
    assert_eq!(refusal(&executor, "b", 1), RemoteAdmissionError::Closed);
    assert_eq!(copy.usage().in_flight, 1); drop(a); empty(&copy);
    assert_eq!(refusal(&copy, "a", 0), RemoteAdmissionError::Closed);
}

#[test]
fn byte_arithmetic_never_wraps_and_refusal_leaves_all_counters_unchanged() {
    let unlimited = RemotePeerLimits { max_in_flight: usize::MAX, max_input_bytes: usize::MAX, max_request_bytes: usize::MAX };
    let executor = executor(usize::MAX, usize::MAX, unlimited);
    // Pure admission arithmetic; no allocation of a usize::MAX payload occurs.
    let a = executor.acquire(&NodeId::new("a"), usize::MAX).unwrap();
    assert_eq!(refusal(&executor, "a", 1), RemoteAdmissionError::PeerBytes);
    assert_eq!(refusal(&executor, "b", 1), RemoteAdmissionError::TotalBytes);
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: usize::MAX });
    drop(a); empty(&executor);
}

#[test]
fn competing_threads_cannot_overbook_the_same_logical_peer() {
    let executor = executor(10, 40, RemotePeerLimits { max_in_flight: 2, ..peer() });
    let held = Arc::new(std::sync::Barrier::new(13));
    let release = Arc::new(std::sync::Barrier::new(13));
    let mut threads = Vec::new();
    for _ in 0..12 {
        let (executor, held, release) = (executor.clone(), Arc::clone(&held), Arc::clone(&release));
        threads.push(std::thread::spawn(move || {
            let admitted = executor.acquire(&NodeId::new("a"), 4);
            held.wait(); release.wait();
            match admitted { Ok(permit) => { drop(permit); true }, Err(error) => { assert_eq!(error, RemoteAdmissionError::PeerInFlight); false } }
        }));
    }
    held.wait(); let observed = executor.usage(); release.wait();
    let count = threads.into_iter().map(|thread| usize::from(thread.join().unwrap())).sum::<usize>();
    assert_eq!(count, 2); assert_eq!(observed, RemoteAdmissionUsage { in_flight: 2, input_bytes: 8 }); empty(&executor);
}

struct ObservedDrop { executor: RemoteExecutor, dropped: Arc<AtomicBool> }
impl Future for ObservedDrop {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { Poll::Ready(()) }
}
impl Drop for ObservedDrop {
    fn drop(&mut self) {
        assert_eq!(self.executor.usage().in_flight, 1, "proxy destructor must still be charged");
        self.dropped.store(true, Ordering::Release);
    }
}
#[test]
fn completed_proxy_destructor_runs_before_its_admission_is_released() {
    let executor = executor(1, 8, peer()); let dropped = Arc::new(AtomicBool::new(false));
    let mut proxy = Box::pin(AdmittedProxy { future: ObservedDrop { executor: executor.clone(), dropped: Arc::clone(&dropped) },
        _admission: Some(executor.acquire(&NodeId::new("a"), 4).unwrap()) });
    assert!(proxy.as_mut().poll(&mut Context::from_waker(std::task::Waker::noop())).is_ready());
    assert_eq!(executor.usage().in_flight, 1); drop(proxy);
    assert!(dropped.load(Ordering::Acquire)); empty(&executor);
}

#[derive(Debug)]
struct HoldingRemote {
    pending: Mutex<BTreeMap<RemoteTaskId, oneshot::Sender<Result<RemoteOutcome, RemoteError>>>>,
    executor: RemoteExecutor,
    sent: AtomicUsize,
    cancels: AtomicUsize,
    clears: AtomicUsize,
    changed: Notify,
}
impl HoldingRemote {
    fn finish(&self) {
        let (_, sender) = self.pending.lock().pop_first().expect("parked remote request");
        let _ = sender.send_blocking(Ok(RemoteOutcome::Cancelled(crate::types::CancelReason::user("drained"))));
    }
}
impl RemoteRuntime for HoldingRemote {
    fn register_task(&self, id: RemoteTaskId, sender: oneshot::Sender<Result<RemoteOutcome, RemoteError>>) {
        assert!(self.executor.usage().in_flight > 0);
        self.pending.lock().insert(id, sender);
    }
    fn send_message(&self, peer: &NodeId, envelope: MessageEnvelope<RemoteMessage>) -> Result<(), RemoteError> {
        // Reentrant quota inspection must not encounter an admission-held mutex.
        assert!(self.executor.usage().in_flight > 0);
        match envelope.payload {
            RemoteMessage::SpawnRequest(request) => {
                self.sent.fetch_add(1, Ordering::Release);
                if peer.as_str() == "b" {
                    let sender = self.pending.lock().remove(&request.remote_task_id).unwrap();
                    let _ = sender.send_blocking(Ok(RemoteOutcome::Success(vec![7])));
                }
            }
            RemoteMessage::CancelRequest(_) => { self.cancels.fetch_add(1, Ordering::Release); }
            _ => {}
        }
        self.changed.notify_waiters(); Ok(())
    }
    fn clear_task_state(&self, id: RemoteTaskId) {
        assert!(self.executor.usage().in_flight > 0, "handle retirement remains charged");
        let pending = self.pending.lock().remove(&id); drop(pending);
        self.clears.fetch_add(1, Ordering::Release);
    }
    fn unregister_task(&self, id: RemoteTaskId) { let pending = self.pending.lock().remove(&id); drop(pending); }
}
fn config() -> RemoteRunConfig {
    RemoteRunConfig { timeout: Duration::from_secs(5), child: ChildRegionSpec::inherit() }
}
fn native<F, Fut>(f: F)
where F: FnOnce(Cx) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap(); let mut task = cx.spawn(f).unwrap();
        crate::time::timeout(cx.now(), Duration::from_secs(10), task.join(&cx)).await.expect("watchdog").expect("test owner");
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}
fn configured(cx: Cx) -> (Cx, RemoteExecutor, Arc<HoldingRemote>) {
    let executor = executor(2, 8, RemotePeerLimits { max_in_flight: 1, ..peer() });
    let remote = Arc::new(HoldingRemote { pending: Mutex::new(BTreeMap::new()), executor: executor.clone(),
        sent: AtomicUsize::new(0), cancels: AtomicUsize::new(0), clears: AtomicUsize::new(0), changed: Notify::new() });
    let cap = RemoteCap::new().with_local_node(NodeId::new("origin")).with_runtime(Arc::clone(&remote) as Arc<dyn RemoteRuntime>);
    (cx.with_remote_cap(cap), executor, remote)
}
async fn call(executor: &RemoteExecutor, cx: &Cx, peer: &str, bytes: usize) -> Result<RemoteRunReport, RemoteExecutorError> {
    executor.run(cx, NodeId::new(peer), ComputationName::new("test"), RemoteInput::new(vec![5; bytes]), config()).await
}

#[test]
fn constructing_or_dropping_an_unpolled_call_acquires_nothing() {
    native(|cx| async move {
        let (cx, executor, remote) = configured(cx);
        let call = call(&executor, &cx, "a", 4); empty(&executor); drop(call); empty(&executor);
        assert_eq!(remote.sent.load(Ordering::Acquire), 0);
    });
}

#[test]
fn setup_failure_and_admission_refusal_do_not_dispatch_or_retain_credits() {
    native(|cx| async move {
        let executor = executor(2, 8, peer());
        assert!(matches!(call(&executor, &cx, "a", 4).await, Err(RemoteExecutorError::Run(RemoteRunError::NoCapability))));
        empty(&executor);
        let (cx, executor, remote) = configured(cx);
        assert!(matches!(call(&executor, &cx, "a", 5).await, Err(RemoteExecutorError::Admission(RemoteAdmissionError::RequestBytes))));
        assert!(matches!(call(&executor, &cx, "unknown", 0).await, Err(RemoteExecutorError::Admission(RemoteAdmissionError::UnknownPeer))));
        assert_eq!(remote.sent.load(Ordering::Acquire), 0); empty(&executor);
    });
}

#[test]
fn successful_public_invocation_preserves_the_report_and_releases_after_close() {
    native(|cx| async move {
        let (cx, executor, remote) = configured(cx);
        let report = call(&executor, &cx, "b", 4).await.unwrap();
        assert!(report.is_success()); assert!(report.close.is_ok());
        assert_eq!(remote.clears.load(Ordering::Acquire), 1); empty(&executor);
        assert!(!format!("{executor:?}").contains("origin"));
    });
}

#[test]
fn caller_drop_cannot_release_peer_capacity_before_the_proxy_collects_terminal() {
    native(|cx| async move {
        let (cx, executor, remote) = configured(cx);
        let mut running = Box::pin(call(&executor, &cx, "a", 4));
        let mut sent = std::pin::pin!(remote.changed.wait_until(|| remote.sent.load(Ordering::Acquire) == 1));
        poll_fn(|task| { assert!(running.as_mut().poll(task).is_pending()); sent.as_mut().poll(task) }).await;
        assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
        drop(running);
        remote.changed.wait_until(|| remote.cancels.load(Ordering::Acquire) == 1).await;
        assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
        assert!(matches!(call(&executor.clone(), &cx, "a", 0).await, Err(RemoteExecutorError::Admission(RemoteAdmissionError::PeerInFlight))));
        assert!(call(&executor, &cx, "b", 4).await.unwrap().is_success());
        assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
        assert!(executor.close_admission()); // Closing never blocks existing cancellation/collection.
        remote.finish();
        while executor.usage().in_flight != 0 { crate::time::sleep(cx.now(), Duration::from_millis(1)).await; }
        assert_eq!(remote.clears.load(Ordering::Acquire), 2); empty(&executor); assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn cancellation_report_and_shared_quota_wait_for_the_same_terminal_collection() {
    native(|cx| async move {
        let (cx, executor, remote) = configured(cx);
        let owned = executor.clone();
        let mut invocation = cx.spawn(move |owner| async move {
            let report = call(&owned, &owner, "a", 4).await;
            let _ = owner.checkpoint(); report
        }).unwrap();
        remote.changed.wait_until(|| remote.sent.load(Ordering::Acquire) == 1).await;
        invocation.abort();
        remote.changed.wait_until(|| remote.cancels.load(Ordering::Acquire) == 1).await;
        assert!(invocation.try_join().unwrap().is_none());
        assert_eq!(executor.usage().in_flight, 1);
        assert!(matches!(call(&executor, &cx, "a", 0).await, Err(RemoteExecutorError::Admission(RemoteAdmissionError::PeerInFlight))));
        remote.finish();
        let report = invocation.join(&cx).await.unwrap().unwrap();
        assert!(matches!(report.trigger, RemoteRunTrigger::Cancelled(_)));
        assert!(!report.is_success()); assert!(report.close.is_ok());
        assert!(matches!(report.task.unwrap().outcome, Outcome::Ok(RemoteOutcome::Cancelled(_))));
        empty(&executor);
    });
}
