use super::*;
use crate::channel::oneshot;
use crate::lab::{LabConfig, LabRuntime};
use crate::remote::{MessageEnvelope, RemoteCap, RemoteMessage, RemoteRuntime, RemoteTaskState};
use crate::runtime::RuntimeBuilder;
use crate::runtime::obligation_mailbox::{ObligationMailbox, apply_obligation_posts};
use crate::sync::Notify;
use crate::time::VirtualClock;
use crate::types::{Budget, CancelKind};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

#[derive(Debug, Clone, Copy)]
enum Mode { Immediate, Deferred, Refuse, Panic, Closed }
#[derive(Debug)]
struct Transport {
    mode: Mode,
    pending: Mutex<BTreeMap<RemoteTaskId, oneshot::Sender<Result<RemoteOutcome, RemoteError>>>>,
    sent: AtomicUsize,
    cancels: AtomicUsize,
    clears: AtomicUsize,
    unregisters: AtomicUsize,
    changed: Notify,
}
impl Transport {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self { mode, pending: Mutex::new(BTreeMap::new()), sent: AtomicUsize::new(0),
            cancels: AtomicUsize::new(0), clears: AtomicUsize::new(0), unregisters: AtomicUsize::new(0),
            changed: Notify::new() })
    }
    fn deliver(&self, value: Result<RemoteOutcome, RemoteError>) {
        let (_, sender) = self.pending.lock().pop_first().expect("admitted remote request");
        let _ = sender.send_blocking(value); // Never publish via a cancelled Cx.
    }
    fn cap(self: &Arc<Self>) -> RemoteCap {
        RemoteCap::new().with_local_node(NodeId::new("origin"))
            .with_runtime(Arc::clone(self) as Arc<dyn RemoteRuntime>)
    }
}
impl RemoteRuntime for Transport {
    fn register_task(&self, id: RemoteTaskId, sender: oneshot::Sender<Result<RemoteOutcome, RemoteError>>) {
        self.pending.lock().insert(id, sender);
    }
    fn send_message(&self, _: &NodeId, message: MessageEnvelope<RemoteMessage>) -> Result<(), RemoteError> {
        match message.payload {
            RemoteMessage::SpawnRequest(_) => {
                self.sent.fetch_add(1, Ordering::Release);
                match self.mode {
                    Mode::Immediate => self.deliver(Ok(RemoteOutcome::Success(b"payload-secret".to_vec()))),
                    Mode::Deferred => {}
                    Mode::Refuse => return Err(RemoteError::NodeDown("test peer".to_owned())),
                    Mode::Panic => panic!("dispatch sentinel"),
                    Mode::Closed => { self.pending.lock().clear(); }
                }
                self.changed.notify_waiters();
            }
            RemoteMessage::CancelRequest(_) => {
                self.cancels.fetch_add(1, Ordering::Release);
                self.changed.notify_waiters();
            }
            _ => {}
        }
        Ok(())
    }
    fn observe_task_state(&self, _: RemoteTaskId) -> Option<RemoteTaskState> { Some(RemoteTaskState::Running) }
    fn clear_task_state(&self, id: RemoteTaskId) {
        self.pending.lock().remove(&id);
        self.clears.fetch_add(1, Ordering::Release);
    }
    fn unregister_task(&self, id: RemoteTaskId) {
        self.pending.lock().remove(&id);
        self.unregisters.fetch_add(1, Ordering::Release);
    }
}
fn fixture(limit: usize, mode: Mode) -> (LabRuntime, Cx, Arc<ObligationMailbox>, Arc<Transport>) {
    let mut lab = LabRuntime::new(LabConfig::new(0xD4_1600).max_steps(4096));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (holder, _task) = lab.state.create_task(root, Budget::INFINITE, std::future::pending::<()>()).unwrap();
    let region = lab.state.region(root).unwrap();
    let mut limits = region.limits(); limits.max_obligations = Some(limit); region.set_limits(limits);
    let transport = Transport::new(mode);
    let cx = lab.state.task(holder).unwrap().cx.clone().unwrap().with_remote_cap(transport.cap());
    let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
    (lab, cx, mailbox, transport)
}
fn clock() -> TimerDriverHandle { TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new())) }
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> { future.poll(&mut Context::from_waker(Waker::noop())) }
fn finish<F: Future>(future: Pin<&mut F>) -> F::Output {
    match poll(future) { Poll::Ready(value) => value, Poll::Pending => panic!("expected ready") }
}
fn operation(cx: Cx) -> impl Future<Output = Result<RemoteRunReply, RemoteRunTaskError>> {
    execute(cx, NodeId::new("worker"), ComputationName::new("test"), RemoteInput::empty(), clock(), Time::from_secs(30))
}
fn config() -> RemoteRunConfig { RemoteRunConfig { timeout: Duration::from_secs(5), child: ChildRegionSpec::inherit() } }
fn native<F, Fut>(f: F)
where F: FnOnce(Cx) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let mut handle = cx.spawn(f).unwrap();
        crate::time::timeout(cx.now(), Duration::from_secs(10), handle.join(&cx)).await
            .expect("failure watchdog").expect("test task");
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn checked_success_commits_exactly_once_and_destroys_the_remote_handle_first() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Immediate);
    let mut run = Box::pin(operation(cx));
    let reply = finish(run.as_mut()).unwrap();
    assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed);
    assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Success(_))));
    assert_eq!(transport.clears.load(Ordering::Acquire), 1);
    drop(run);
    apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().reserved, 1); assert_eq!(mailbox.stats().committed, 1);
    assert_eq!(mailbox.stats().aborted, 0); assert_eq!(mailbox.stats().leaked, 0); assert_eq!(mailbox.open_tickets(), 0);
}

#[test]
fn exhausted_runtime_quota_refuses_before_remote_registration_or_dispatch() {
    let (mut lab, cx, mailbox, transport) = fixture(0, Mode::Immediate);
    let mut run = Box::pin(operation(cx));
    assert!(matches!(finish(run.as_mut()), Err(RemoteRunTaskError::Admission(ObligationAdmissionError::LimitReached { .. }))));
    assert_eq!(transport.sent.load(Ordering::Acquire), 0); assert!(transport.pending.lock().is_empty());
    drop(run); apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().reserved, 0); assert_eq!(mailbox.stats().leaked, 0);
}

#[test]
fn untracked_context_refuses_instead_of_dispatching_without_a_lease() {
    let transport = Transport::new(Mode::Immediate);
    let mut run = Box::pin(operation(Cx::for_testing().with_remote_cap(transport.cap())));
    assert!(matches!(finish(run.as_mut()), Err(RemoteRunTaskError::NoObligationRuntime)));
    assert_eq!(transport.sent.load(Ordering::Acquire), 0);
}

#[test]
fn cancelled_receive_keeps_checked_lease_until_delayed_terminal_collection() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Deferred);
    let mut run = Box::pin(operation(cx.clone()));
    assert!(poll(run.as_mut()).is_pending());
    apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.open_tickets(), 1);
    cx.cancel_with(CancelKind::User, Some("owner cancellation"));
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(transport.cancels.load(Ordering::Acquire), 1);
    assert_eq!(mailbox.open_tickets(), 1); assert_eq!(mailbox.stats().aborted, 0);
    transport.deliver(Ok(RemoteOutcome::Cancelled(CancelReason::user("remote drained"))));
    let reply = finish(run.as_mut()).unwrap();
    assert!(reply.cancellation.is_some()); assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
    assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Cancelled(_))));
    drop(run); apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().aborted, 1); assert_eq!(mailbox.stats().leaked, 0); assert_eq!(mailbox.open_tickets(), 0);
}

#[test]
fn late_success_is_preserved_but_cannot_commit_a_cancelled_proxy() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Deferred);
    let mut run = Box::pin(operation(cx.clone())); assert!(poll(run.as_mut()).is_pending());
    cx.cancel_with(CancelKind::User, Some("cancel before reply"));
    assert!(poll(run.as_mut()).is_pending());
    transport.deliver(Ok(RemoteOutcome::Success(b"late result".to_vec())));
    let reply = finish(run.as_mut()).unwrap();
    assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Success(ref bytes)) if bytes == b"late result"));
    assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
    drop(run); apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().committed, 0); assert_eq!(mailbox.stats().aborted, 1);
}

#[test]
fn dispatch_failure_returns_exact_error_and_rolls_back_the_checked_lease() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Refuse);
    let mut run = Box::pin(operation(cx));
    assert!(matches!(finish(run.as_mut()), Err(RemoteRunTaskError::Dispatch(RemoteError::NodeDown(_)))));
    assert_eq!(transport.unregisters.load(Ordering::Acquire), 1);
    drop(run); apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().aborted, 1); assert_eq!(mailbox.stats().leaked, 0);
}

#[test]
fn dropped_result_sender_aborts_instead_of_manufacturing_remote_success() {
    let (mut lab, cx, mailbox, _) = fixture(1, Mode::Closed);
    let mut run = Box::pin(operation(cx)); let reply = finish(run.as_mut()).unwrap();
    assert!(matches!(reply.outcome, Outcome::Err(RemoteError::Cancelled(_))));
    assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
    drop(run); apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().committed, 0); assert_eq!(mailbox.stats().aborted, 1);
}

#[test]
fn forced_proxy_future_drop_requests_remote_cancel_and_posts_abort_not_leak() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Deferred);
    let mut run = Box::pin(operation(cx)); assert!(poll(run.as_mut()).is_pending()); drop(run);
    assert_eq!(transport.cancels.load(Ordering::Acquire), 1);
    apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().aborted, 1); assert_eq!(mailbox.stats().leaked, 0);
    // The custom transport still owns its work; local abort never certifies remote drain.
    assert_eq!(transport.pending.lock().len(), 1);
    transport.deliver(Err(RemoteError::LeaseExpired));
}

#[test]
fn dispatch_panic_aborts_the_checked_token_during_unwind() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Panic);
    let mut run = Box::pin(operation(cx));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let _ = poll(run.as_mut()); }));
    assert!(panic.is_err()); drop(run);
    apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().aborted, 1); assert_eq!(mailbox.stats().leaked, 0);
    // The legacy registration callback has no panic rollback contract. Clear the
    // explicit mock owner; this test claims checked-token cleanup, not transport rollback.
    transport.pending.lock().clear();
}

#[test]
fn public_runner_uses_a_real_distinct_closed_child_and_redacts_reply_payloads() {
    native(|cx| async move {
        let transport = Transport::new(Mode::Immediate); let cx = cx.with_remote_cap(transport.cap());
        let report = run_remote(&cx, NodeId::new("worker"), ComputationName::new("test"), RemoteInput::empty(), config()).await.unwrap();
        assert!(report.is_success(), "{report:?}");
        assert_ne!(report.close.as_ref().unwrap().region_id, cx.region_id());
        assert!(!format!("{report:?} {:?}", report.task.as_ref().unwrap()).contains("payload-secret"));
        assert_eq!(transport.sent.load(Ordering::Acquire), 1); assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn public_runner_rejects_missing_capability_fallback_and_zero_timeout() {
    native(|cx| async move {
        let result = run_remote(&cx, NodeId::new("worker"), ComputationName::new("test"), RemoteInput::empty(), config()).await;
        assert!(matches!(result, Err(RemoteRunError::NoCapability)));
        let fallback = cx.clone().with_remote_cap(RemoteCap::new());
        assert!(matches!(run_remote(&fallback, NodeId::new("worker"), ComputationName::new("test"), RemoteInput::empty(), config()).await,
            Err(RemoteRunError::NoRemoteRuntime)));
        let transport = Transport::new(Mode::Immediate); let cx = cx.with_remote_cap(transport.cap());
        let mut bounds = config(); bounds.timeout = Duration::ZERO;
        assert!(matches!(run_remote(&cx, NodeId::new("worker"), ComputationName::new("test"), RemoteInput::empty(), bounds).await, Err(RemoteRunError::Timeout)));
        assert_eq!(transport.sent.load(Ordering::Acquire), 0);
    });
}

#[test]
fn deadline_cancels_only_the_child_and_waits_for_the_remote_terminal() {
    native(|cx| async move {
        let transport = Transport::new(Mode::Deferred); let seen = Arc::clone(&transport);
        let mut deliver = cx.spawn(move |_| async move {
            seen.changed.wait_until(|| seen.cancels.load(Ordering::Acquire) == 1).await;
            seen.deliver(Err(RemoteError::LeaseExpired));
        }).unwrap();
        let cx = cx.with_remote_cap(transport.cap()); let mut bounds = config(); bounds.timeout = Duration::from_millis(100);
        let report = run_remote(&cx, NodeId::new("worker"), ComputationName::new("test"), RemoteInput::empty(), bounds).await.unwrap();
        deliver.join(&cx).await.unwrap();
        assert!(matches!(report.trigger, RemoteRunTrigger::Deadline)); assert!(!report.is_success());
        assert!(report.close.is_ok()); assert!(!cx.is_cancel_requested());
        let reply = report.task.unwrap(); assert!(matches!(reply.outcome, Outcome::Err(RemoteError::LeaseExpired)));
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted); assert!(transport.pending.lock().is_empty());
    });
}

#[test]
fn cancellation_with_an_already_buffered_terminal_preserves_that_exact_result() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Deferred);
    let mut run = Box::pin(operation(cx.clone())); assert!(poll(run.as_mut()).is_pending());
    cx.cancel_with(CancelKind::User, Some("cancel before buffered result poll"));
    transport.deliver(Ok(RemoteOutcome::Failed("exact remote business refusal".to_owned())));
    let reply = finish(run.as_mut()).unwrap();
    assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Failed(ref reason)) if reason == "exact remote business refusal"));
    assert!(reply.cancellation.is_some()); assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
    assert_eq!(transport.clears.load(Ordering::Acquire), 1);
    drop(run); apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().aborted, 1); assert_eq!(mailbox.stats().leaked, 0);
}

#[test]
fn consumed_remote_cancelled_error_is_not_replaced_by_polled_after_completion() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Deferred);
    let mut run = Box::pin(operation(cx)); assert!(poll(run.as_mut()).is_pending());
    let reason = CancelReason::user("actual remote cancellation");
    transport.deliver(Err(RemoteError::Cancelled(reason.clone())));
    let reply = finish(run.as_mut()).unwrap();
    assert!(matches!(reply.outcome, Outcome::Err(RemoteError::Cancelled(actual)) if actual == reason));
    assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
    drop(run); apply_obligation_posts(&mut lab.state, &mailbox, 16);
    assert_eq!(mailbox.stats().aborted, 1);
}
