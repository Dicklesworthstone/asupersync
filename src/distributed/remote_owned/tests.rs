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

#[test]
fn owned_spawn_refuses_missing_authority_or_runtime_before_dispatch() {
    native(|cx| async move {
        let spawn = |cx: &Cx, bounds| {
            spawn_remote_owned(
                cx, NodeId::new("worker"), ComputationName::new("test"),
                RemoteInput::empty(), bounds,
            )
        };
        assert!(matches!(spawn(&cx, config()),
            Err(RemoteRunHandleError::Run(RemoteRunError::NoCapability))));
        let fallback = cx.clone().with_remote_cap(RemoteCap::new());
        assert!(matches!(spawn(&fallback, config()),
            Err(RemoteRunHandleError::Run(RemoteRunError::NoRemoteRuntime))));
        let transport = Transport::new(Mode::Immediate);
        let no_timer = Cx::for_testing().with_remote_cap(transport.cap());
        assert!(matches!(spawn(&no_timer, config()),
            Err(RemoteRunHandleError::Run(RemoteRunError::NoTimer))));
        let no_gateway = Cx::new_with_drivers(
            cx.region_id(), cx.task_id(), Budget::INFINITE,
            None, None, None, Some(clock()), None,
        ).with_remote_cap(transport.cap());
        assert!(matches!(spawn(&no_gateway, config()),
            Err(RemoteRunHandleError::Spawn(SpawnError::RuntimeUnavailable))));
        let cx = cx.with_remote_cap(transport.cap());
        let mut zero = config();
        zero.timeout = Duration::ZERO;
        assert!(matches!(spawn(&cx, zero),
            Err(RemoteRunHandleError::Run(RemoteRunError::Timeout))));
        let cancelled = Cx::for_testing().with_remote_cap(transport.cap());
        cancelled.cancel_with(CancelKind::User, Some("before owned spawn"));
        assert!(matches!(spawn(&cancelled, config()),
            Err(RemoteRunHandleError::Run(RemoteRunError::Cancelled))));
        assert_eq!(transport.sent.load(Ordering::Acquire), 0);
        assert!(transport.pending.lock().is_empty());
    });
}

#[test]
fn owned_spawn_deadline_includes_time_before_local_task_admission() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Immediate);
    let mut handle = spawn_remote_owned(
        &cx, NodeId::new("worker"), ComputationName::new("test"),
        RemoteInput::empty(), config(),
    ).unwrap();
    let deadline = handle.deadline();
    assert_eq!(deadline, cx.timer_driver().unwrap().now() + config().timeout);
    assert!(handle.try_join().unwrap().is_none());
    // No scheduler turn has admitted the owner. Its original cancellation
    // interval must not restart when the queued factory finally runs.
    lab.advance_time_to(deadline);
    lab.run_until_idle();
    assert!(matches!(handle.try_join(),
        Err(RemoteRunHandleError::Run(RemoteRunError::Timeout))));
    assert!(handle.is_finished());
    assert!(matches!(handle.try_join(),
        Err(RemoteRunHandleError::Join(JoinError::PolledAfterCompletion))));
    assert_eq!(transport.sent.load(Ordering::Acquire), 0);
    assert!(transport.pending.lock().is_empty());
    assert_eq!(mailbox.stats().reserved, 0);
    assert_eq!(mailbox.stats().leaked, 0);
}

#[test]
fn owned_spawn_cancelled_before_first_poll_never_dispatches_remote_work() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Immediate);
    let mut handle = spawn_remote_owned(
        &cx, NodeId::new("worker"), ComputationName::new("test"),
        RemoteInput::empty(), config(),
    ).unwrap();
    let reason = CancelReason::user("owned remote cancelled before admission");
    handle.abort_with_reason(reason.clone());
    lab.run_until_idle();
    assert!(matches!(handle.try_join(),
        Err(RemoteRunHandleError::Join(JoinError::Cancelled(actual))) if actual == reason));
    assert!(handle.is_finished());
    assert_eq!(transport.sent.load(Ordering::Acquire), 0);
    assert!(transport.pending.lock().is_empty());
    assert_eq!(mailbox.stats().reserved, 0);
    assert_eq!(mailbox.stats().leaked, 0);
}

#[test]
fn owned_spawn_task_quota_refusal_is_terminal_without_remote_registration() {
    let (mut lab, cx, mailbox, transport) = fixture(1, Mode::Immediate);
    let region = lab.state.region(cx.region_id()).unwrap();
    let mut limits = region.limits();
    limits.max_tasks = Some(1); // The fixture's original holder occupies it.
    region.set_limits(limits);
    let mut handle = spawn_remote_owned(
        &cx, NodeId::new("worker"), ComputationName::new("test"),
        RemoteInput::empty(), config(),
    ).unwrap();
    lab.run_until_idle();
    assert!(matches!(handle.try_join(),
        Err(RemoteRunHandleError::Join(JoinError::Cancelled(reason)))
            if reason.kind == CancelKind::User
                && reason.message.as_ref().is_some_and(|message| message.contains("[ASUP-E006]"))));
    assert!(handle.is_finished());
    assert!(matches!(handle.try_join(),
        Err(RemoteRunHandleError::Join(JoinError::PolledAfterCompletion))));
    assert_eq!(transport.sent.load(Ordering::Acquire), 0);
    assert!(transport.pending.lock().is_empty());
    assert_eq!(mailbox.stats().reserved, 0);
    assert_eq!(mailbox.stats().leaked, 0);
}

struct FinishDeferred(Arc<Transport>);
impl Drop for FinishDeferred {
    fn drop(&mut self) {
        let pending = std::mem::take(&mut *self.0.pending.lock());
        for (_, sender) in pending {
            let _ = sender.send_blocking(Err(RemoteError::LeaseExpired));
        }
    }
}

#[test]
fn consumed_owned_remote_report_stays_terminal_without_a_drop_abort() {
    let (mut lab, cx, _, transport) = fixture(1, Mode::Deferred);
    let _finish = FinishDeferred(Arc::clone(&transport));
    let mut handle = spawn_remote_owned(
        &cx, NodeId::new("worker"), ComputationName::new("test"),
        RemoteInput::empty(), config(),
    ).unwrap();
    lab.run_until_idle();
    assert_eq!(transport.sent.load(Ordering::Acquire), 1);
    assert!(handle.try_join().unwrap().is_none());
    // Retain the owner's actual context past record retirement, so a stale
    // implicit abort cannot disappear merely because its weak handle expired.
    let owner = lab.state.task(handle.local_task_id()).unwrap().cx.clone().unwrap();
    transport.deliver(Ok(RemoteOutcome::Success(b"consumed report".to_vec())));
    lab.run_until_idle();
    let report = handle.try_join().unwrap().expect("retired owner report");
    assert!(report.is_success());
    assert!(handle.task.terminal_published(), "consumption must remain terminal");
    assert!(handle.is_finished());
    assert!(!owner.is_cancel_requested());
    let commands = cx.spawn_gateway_ref().unwrap().mailbox();
    assert!(commands.handle_cancels_are_empty());
    drop(handle);
    // No scheduler turn intervenes: check both immediate Cx publication and
    // the callback-free command lane that Drop would otherwise enqueue into.
    assert!(!owner.is_cancel_requested());
    assert!(commands.handle_cancels_are_empty());
    assert_eq!(transport.cancels.load(Ordering::Acquire), 0);
    assert_eq!(transport.clears.load(Ordering::Acquire), 1);
}

#[test]
fn explicit_remote_authority_is_not_timed_out_by_ambient_task_cancellation() {
    native(|cx| async move {
        let transport = Transport::new(Mode::Deferred);
        let _finish = FinishDeferred(Arc::clone(&transport));
        let authority = cx.clone().with_remote_cap(transport.cap());
        let cancelled_polls = Arc::new(AtomicUsize::new(0));
        let repolled = Arc::new(Notify::new());
        let observed_polls = Arc::clone(&cancelled_polls);
        let observed_repoll = Arc::clone(&repolled);
        let mut invocation = cx.spawn(move |running| async move {
            assert_ne!(authority.task_id(), running.task_id());
            let mut run = std::pin::pin!(run_remote(
                &authority, NodeId::new("worker"), ComputationName::new("test"),
                RemoteInput::empty(), config(),
            ));
            let result = poll_fn(|task| {
                let ambient_cancelled = running.is_cancel_requested();
                let progress = run.as_mut().poll(task);
                if ambient_cancelled && progress.is_pending() {
                    assert!(!authority.is_cancel_requested());
                    observed_polls.fetch_add(1, Ordering::Release);
                    observed_repoll.notify_waiters();
                }
                progress
            }).await;
            // Preserve the actual operation report after observing the
            // independent cancellation of this task that polled it.
            let _ = running.checkpoint();
            result
        }).unwrap();
        // The single worker cannot return here until the proxy has actually
        // parked on its remote receive and the owner's deadline is armed.
        transport.changed.wait_until(|| transport.sent.load(Ordering::Acquire) == 1).await;
        invocation.abort_with_reason(CancelReason::user("cancel only the ambient polling task"));
        repolled.wait_until(|| cancelled_polls.load(Ordering::Acquire) > 0).await;
        assert!(!cx.is_cancel_requested());
        assert_eq!(transport.cancels.load(Ordering::Acquire), 0);
        transport.deliver(Ok(RemoteOutcome::Success(b"explicit authority result".to_vec())));
        let report = invocation.join(&cx).await.unwrap().unwrap();
        assert!(matches!(report.trigger, RemoteRunTrigger::Finished));
        assert!(report.is_success());
        let reply = report.task.unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed);
        assert!(reply.cancellation.is_none());
        assert!(matches!(reply.outcome,
            Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"explicit authority result"));
        assert_eq!(transport.cancels.load(Ordering::Acquire), 0);
        assert_eq!(transport.clears.load(Ordering::Acquire), 1);
        assert!(transport.pending.lock().is_empty());
    });
}

#[test]
fn dropping_only_an_owned_remote_join_future_does_not_cancel_the_invocation() {
    native(|cx| async move {
        let transport = Transport::new(Mode::Deferred);
        let _finish = FinishDeferred(Arc::clone(&transport));
        let cx = cx.with_remote_cap(transport.cap());
        let mut handle = spawn_remote_owned(
            &cx, NodeId::new("worker"), ComputationName::new("test"),
            RemoteInput::empty(), config(),
        ).unwrap();
        // On this current-thread runtime, the proxy cannot yield control back
        // here until its result receive has actually returned Pending.
        transport.changed.wait_until(|| transport.sent.load(Ordering::Acquire) == 1).await;
        let mut waiting = Box::pin(handle.join(&cx));
        poll_fn(|task| {
            assert!(waiting.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        drop(waiting);
        // Give any incorrectly enqueued abort a real scheduler turn before
        // publishing the otherwise successful protocol terminal.
        let mut turn = cx.spawn(|_| async {}).unwrap();
        turn.join(&cx).await.unwrap();
        assert_eq!(transport.cancels.load(Ordering::Acquire), 0);
        assert!(handle.try_join().unwrap().is_none());
        transport.deliver(Ok(RemoteOutcome::Success(b"retained result".to_vec())));
        let report = handle.join(&cx).await.unwrap();
        assert!(report.is_success(), "a dropped wait must not abort its owned invocation");
        assert!(matches!(report.task.unwrap().outcome,
            Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"retained result"));
        assert_eq!(transport.cancels.load(Ordering::Acquire), 0);
        assert_eq!(transport.clears.load(Ordering::Acquire), 1);
        assert!(transport.pending.lock().is_empty());
    });
}

#[test]
fn owned_remote_close_keeps_its_report_with_an_already_cancelled_observer() {
    native(|cx| async move {
        let transport = Transport::new(Mode::Deferred);
        let _finish = FinishDeferred(Arc::clone(&transport));
        let cx = cx.with_remote_cap(transport.cap());
        let mut handle = spawn_remote_owned(
            &cx, NodeId::new("worker"), ComputationName::new("test"),
            RemoteInput::empty(), config(),
        ).unwrap();
        transport.changed.wait_until(|| transport.sent.load(Ordering::Acquire) == 1).await;
        let observer = Cx::for_testing();
        observer.cancel_with(CancelKind::User, Some("cancelled remote result observer"));
        let expected = observer.cancel_reason().unwrap();
        let terminal = expected.clone();
        let seen = Arc::clone(&transport);
        let mut delivery = cx.spawn(move |_| async move {
            seen.changed.wait_until(|| seen.cancels.load(Ordering::Acquire) == 1).await;
            seen.deliver(Ok(RemoteOutcome::Cancelled(terminal)));
        }).unwrap();
        let report = handle.close(&observer).await.unwrap();
        delivery.join(&cx).await.unwrap();
        assert!(matches!(report.trigger, RemoteRunTrigger::Cancelled(ref reason) if reason == &expected));
        assert!(!report.is_success());
        assert!(report.close.is_ok());
        assert!(report.cancel_error.is_none());
        let reply = report.task.unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
        assert_eq!(reply.cancellation.as_ref(), Some(&expected));
        assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Cancelled(reason)) if reason == expected));
        assert_eq!(transport.cancels.load(Ordering::Acquire), 1);
        assert_eq!(transport.clears.load(Ordering::Acquire), 1);
        assert!(!cx.is_cancel_requested());
    });
}
