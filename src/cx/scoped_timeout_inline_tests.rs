use super::*;
use crate::cx::{ChildRegionSpec, RaceFactory};
use crate::lab::{LabConfig, LabRuntime};
use crate::record::region::{RegionCloseState, RegionState};
use crate::runtime::spawn_mailbox::{RegionCommand, SpawnGateway, SpawnMailbox};
use crate::runtime::RuntimeBuilder;
use crate::runtime::state::SpawnAdmission;
use crate::types::{Budget, Outcome, TaskId};
use parking_lot::Mutex;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

#[derive(Clone, Default)]
struct Gate(Arc<GateState>);

#[derive(Default)]
struct GateState {
    open: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn release(&self) {
        self.0.open.store(true, Ordering::SeqCst);
        let waker = self.0.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Future for Gate {
    type Output = ();

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        if self.0.open.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        *self.0.waker.lock() = Some(task.waker().clone());
        if self.0.open.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

struct CountWakes(AtomicUsize);

impl Wake for CountWakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

/// A real, still-live owner task whose context can be used by an external
/// controller poller. Its own gate cannot accidentally acknowledge cancel.
fn fixture(seed: u64, start: Time) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
    lab.advance_time_to(start);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let gate = Gate::default();
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, gate.clone())
        .unwrap();
    let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    (lab, cx, root, gate)
}

fn finish_fixture(lab: &mut LabRuntime, root: RegionId, owner_gate: &Gate) {
    owner_gate.release();
    lab.run_until_idle();
    lab.state.close_region_command(root, &CancelReason::user("test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn ready_report<T: std::fmt::Debug, F>(
    future: Pin<&mut F>,
) -> ScopedTimeoutReport<T>
where
    F: Future<Output = Result<ScopedTimeoutReport<T>, ScopedTimeoutError>>,
{
    match poll_once(future) {
        Poll::Ready(Ok(report)) => report,
        other => panic!("expected completed scoped timeout, got {other:?}"),
    }
}

#[test]
fn scoped_timeout_keeps_success_typed_error_and_task_panic_as_task_facts() {
    for case in 0..3 {
        let (mut lab, owner, root, gate) = fixture(0x5C_0100 + case, Time::ZERO);
        let mut timeout = Box::pin(owner.timeout_scoped(
            Duration::from_secs(60),
            move |_body| async move {
                assert!(case != 2, "operation panic");
                if case == 0 { Ok(42_u32) } else { Err("typed failure") }
            },
        ));
        assert!(poll_once(timeout.as_mut()).is_pending());
        lab.run_until_idle();
        let report = ready_report(timeout.as_mut());
        assert!(matches!(report.stop, ScopedTimeoutStop::TaskFinished));
        assert_ne!(report.region_id, Some(root));
        assert!(report.region_id.is_some());
        let close = report.close.unwrap().unwrap();
        match (case, report.task) {
            (0, ScopedTimeoutTask::Joined(Ok(Ok(42)))) => {}
            (1, ScopedTimeoutTask::Joined(Ok(Err("typed failure")))) => {}
            (2, ScopedTimeoutTask::Joined(Err(JoinError::Panicked(payload)))) => {
                assert_eq!(payload.message(), "operation panic");
                assert!(close.descendant_panic.is_some());
            }
            other => panic!("wrong actual task result: {other:?}"),
        }
        assert!(owner.timer_driver().unwrap().is_empty());
        drop(timeout);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_timeout_cancels_whole_region_before_join_and_waits_for_grandchild_cleanup() {
    // One body finishes on cancellation while its descendant is still parked.
    // The other waits through a plain TaskHandle::join on that descendant.
    // Both need whole-subtree cancellation, and neither may outpace its drain.
    for waits_for_child in [false, true] {
        let start = Time::from_secs(5_000);
        let (mut lab, owner, root, owner_gate) =
            fixture(0x5C_0200 + u64::from(waits_for_child), start);
        let cleanup_gate = Gate::default();
        let grandchild_gate = cleanup_gate.clone();
        let cleanup_started = Arc::new(AtomicBool::new(false));
        let grandchild_started = Arc::clone(&cleanup_started);
        let body_finished = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&body_finished);
        let ids = Arc::new(Mutex::new(None));
        let published = Arc::clone(&ids);
        let mut timeout = Box::pin(owner.timeout_scoped(
            Duration::from_millis(50),
            move |body| async move {
                let body_id = body.task_id();
                let body_region = body.region_id();
                let mut child = body.spawn(move |child_cx| async move {
                    let child_region = child_cx
                        .open_child_region(ChildRegionSpec::inherit())
                        .await
                        .unwrap();
                    let region_id = child_region.region_id();
                    let mut grandchild = child_region.cx().spawn(move |grandchild_cx| async move {
                        *published.lock() = Some((
                            body_region, region_id, body_id, grandchild_cx.task_id(),
                        ));
                        grandchild_cx.cancelled().await;
                        assert!(grandchild_cx.checkpoint().is_err());
                        grandchild_started.store(true, Ordering::SeqCst);
                        grandchild_gate.await;
                        "grandchild cleanup complete"
                    }).unwrap();
                    let _ = grandchild.join(&child_cx).await;
                    child_region.close().await.unwrap();
                }).unwrap();
                if waits_for_child {
                    let _ = child.join(&body).await;
                } else {
                    body.cancelled().await;
                }
                assert!(body.checkpoint().is_err());
                finished.store(true, Ordering::SeqCst);
                "acknowledged late value"
            },
        ));
        assert!(poll_once(timeout.as_mut()).is_pending());
        lab.run_until_idle();
        let (body_region, descendant_region, body_id, grandchild_id) =
            ids.lock().expect("the real grandchild started");
        assert_ne!(body_region, root);
        assert_ne!(descendant_region, body_region);
        assert_eq!(lab.state.task(grandchild_id).unwrap().owner, descendant_region);
        assert_eq!(lab.state.region(descendant_region).unwrap().parent, Some(body_region));

        lab.advance_time_to(start + Duration::from_millis(50));
        owner.timer_driver().unwrap().process_timers();
        assert!(poll_once(timeout.as_mut()).is_pending());
        lab.run_until_idle();
        assert!(cleanup_started.load(Ordering::SeqCst));
        assert_eq!(body_finished.load(Ordering::SeqCst), !waits_for_child);
        if !waits_for_child {
            assert!(lab.state.task(body_id).is_none_or(|task| task.state.is_terminal()));
        }
        assert!(poll_once(timeout.as_mut()).is_pending());
        assert!(lab.state.region(body_region).is_some());
        assert!(!owner.is_cancel_requested(), "child timeout does not cancel its owner");

        cleanup_gate.release();
        lab.run_until_idle();
        let report = ready_report(timeout.as_mut());
        assert!(matches!(report.stop, ScopedTimeoutStop::TimedOut));
        assert!(matches!(
            report.task,
            ScopedTimeoutTask::Joined(Ok("acknowledged late value"))
        ));
        assert_eq!(report.region_id, Some(body_region));
        assert!(report.close.unwrap().is_ok());
        assert!(lab.state.region(body_region).is_none());
        assert!(lab.state.region(descendant_region).is_none());
        assert!(owner.timer_driver().unwrap().is_empty());
        drop(timeout);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_timeout_masked_owner_cancel_drains_without_acknowledging_owner() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_0300, Time::ZERO);
    let cleanup_gate = Gate::default();
    let body_gate = cleanup_gate.clone();
    let cleanup = Arc::new(AtomicBool::new(false));
    let body_cleanup = Arc::clone(&cleanup);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(3_600), |body| async move {
        body.cancelled().await;
        assert!(body.checkpoint().is_err());
        body_cleanup.store(true, Ordering::SeqCst);
        body_gate.await;
        7
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let reason = CancelReason::user("masked caller stopped").with_cause(CancelReason::shutdown());
    owner.masked(|| {
        owner.set_cancel_reason(reason.clone());
        assert_eq!(owner.inner.read().mask_depth, 1);
        assert!(!owner.inner.read().cancel_acknowledged);
        assert!(poll_once(timeout.as_mut()).is_pending());
        lab.run_until_idle();
        assert!(cleanup.load(Ordering::SeqCst));
        assert!(poll_once(timeout.as_mut()).is_pending());
        cleanup_gate.release();
        lab.run_until_idle();
        let report = ready_report(timeout.as_mut());
        assert!(matches!(report.stop, ScopedTimeoutStop::Cancelled(ref actual) if *actual == reason));
        assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok(7))));
        assert!(report.close.unwrap().is_ok());
        assert_eq!(owner.inner.read().mask_depth, 1);
        assert!(!owner.inner.read().cancel_acknowledged);
    });
    assert_eq!(owner.inner.read().mask_depth, 0);
    assert!(!owner.inner.read().cancel_acknowledged);
    drop(timeout);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_timeout_never_uses_foreign_ambient_time_and_disarms_after_drain() {
    use crate::time::{TimerDriverHandle, VirtualClock};

    for foreign in [false, true] {
        let start = Time::from_secs(5_000);
        let (mut lab, owner, root, owner_gate) =
            fixture(0x5C_0400 + u64::from(foreign), start);
        let timer = owner.timer_driver().unwrap();
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10_000)));
        let foreign_timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let ambient = Cx::new_with_drivers(
            RegionId::new_for_test(900, 1), TaskId::new_for_test(900, 1),
            Budget::INFINITE, None, None, None, Some(foreign_timer.clone()), None,
        );
        ambient.set_cancel_reason(CancelReason::shutdown());
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut context = Context::from_waker(&waker);
        let mut timeout = Box::pin(owner.timeout_scoped(
            Duration::from_millis(50),
            |body| async move {
                body.cancelled().await;
                assert!(body.checkpoint().is_err());
            },
        ));
        {
            let _ambient = foreign.then(|| Cx::set_current(Some(ambient.clone())));
            assert!(timeout.as_mut().poll(&mut context).is_pending());
        }
        lab.run_until_idle();
        assert_eq!(timer.next_deadline(), Some(start + Duration::from_millis(50)));
        assert!(foreign_timer.is_empty());
        clock.advance_to(Time::from_secs(20_000));
        assert_eq!(foreign_timer.process_timers(), 0);
        {
            let _ambient = foreign.then(|| Cx::set_current(Some(ambient.clone())));
            assert!(timeout.as_mut().poll(&mut context).is_pending());
        }
        let before = wakes.0.load(Ordering::SeqCst);
        lab.advance_time_to(start + Duration::from_millis(50));
        timer.process_timers();
        assert!(wakes.0.load(Ordering::SeqCst) > before, "owner timer wakes an external poller");
        {
            let _ambient = foreign.then(|| Cx::set_current(Some(ambient.clone())));
            assert!(timeout.as_mut().poll(&mut context).is_pending());
        }
        lab.run_until_idle();
        let report = {
            let _ambient = foreign.then(|| Cx::set_current(Some(ambient.clone())));
            ready_report(timeout.as_mut())
        };
        assert!(matches!(report.stop, ScopedTimeoutStop::TimedOut));
        assert!(report.close.unwrap().is_ok());
        assert!(timer.is_empty());
        assert!(foreign_timer.is_empty());
        assert!(!owner.is_cancel_requested());
        drop(timeout);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_timeout_refuses_missing_or_denied_time_before_any_admission() {
    let calls = Arc::new(AtomicUsize::new(0));
    let no_timer = Cx::detached_cancel_context();
    let called = Arc::clone(&calls);
    let mut missing = Box::pin(no_timer.timeout_scoped(Duration::ZERO, move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async {}
    }));
    assert!(matches!(
        poll_once(missing.as_mut()),
        Poll::Ready(Err(ScopedTimeoutError::TimerUnavailable))
    ));
    let (mut lab, mut owner, root, gate) = fixture(0x5C_0500, Time::ZERO);
    let timer = owner.timer_driver().unwrap();
    let pending = owner.pending_spawn_counter_handle().unwrap();
    owner.runtime_mask = cap::CapMask::none();
    let called = Arc::clone(&calls);
    let mut denied = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async {}
    }));
    assert!(matches!(
        poll_once(denied.as_mut()),
        Poll::Ready(Err(ScopedTimeoutError::TimerUnavailable))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(pending.count(), 0);
    assert_eq!(lab.state.live_task_count(), 1);
    assert!(timer.is_empty());
    drop(denied);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_timeout_zero_and_saturated_duration_use_exact_owner_deadlines() {
    let (mut lab, owner, root, gate) = fixture(0x5C_0600, Time::ZERO);
    let mut zero = Box::pin(owner.timeout_scoped(Duration::ZERO, |_| async {
        panic!("zero duration must not invoke its factory");
    }));
    let report = ready_report(zero.as_mut());
    assert!(matches!(report.stop, ScopedTimeoutStop::TimedOut));
    assert!(matches!(report.task, ScopedTimeoutTask::NotStarted));
    assert!(report.region_id.is_none());
    assert!(report.close.is_none());
    assert!(owner.timer_driver().unwrap().is_empty());
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    drop(zero);
    finish_fixture(&mut lab, root, &gate);

    let start = Time::MAX.saturating_sub_nanos(1_000_000);
    let (mut lab, owner, root, gate) = fixture(0x5C_0601, start);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::MAX, |body| async move {
        body.cancelled().await;
        assert!(body.checkpoint().is_err());
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    assert_eq!(owner.timer_driver().unwrap().next_deadline(), Some(Time::MAX));
    lab.advance_time_to(Time::MAX);
    owner.timer_driver().unwrap().process_timers();
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let report = ready_report(timeout.as_mut());
    assert_eq!(report.deadline, Time::MAX);
    assert!(matches!(report.stop, ScopedTimeoutStop::TimedOut));
    assert!(report.close.unwrap().is_ok());
    assert!(owner.timer_driver().unwrap().is_empty());
    drop(timeout);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_timeout_refuses_parent_limit_fallback_without_running_user_factory() {
    use crate::record::RegionLimits;

    let (mut lab, owner, root, gate) = fixture(0x5C_0700, Time::ZERO);
    assert!(lab.state.set_region_limits(root, RegionLimits {
        max_tasks: Some(10),
        ..RegionLimits::default()
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&calls);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async { 42 }
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let report = ready_report(timeout.as_mut());
    assert!(matches!(report.stop, ScopedTimeoutStop::NotAdmitted));
    assert!(matches!(report.task, ScopedTimeoutTask::NotStarted));
    assert!(report.region_id.is_none());
    assert!(report.close.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    assert!(!owner.is_cancel_requested());
    assert_eq!(lab.state.live_task_count(), 1);
    drop(timeout);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_timeout_drop_before_late_admission_closes_the_published_region() {
    let (mut lab, owner, root, gate) = fixture(0x5C_0800, Time::ZERO);
    let calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&calls);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async {}
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    // Freeze the scheduler after dequeue/preflight but before it reserves or
    // publishes a canonical task. Dropping now must not miss the late region.
    let parts = gateway.mailbox().dequeue().unwrap().into_parts();
    let slot = Arc::clone(parts.admitted_slot.as_ref().unwrap().branch_region().unwrap());
    assert!(slot.get().is_none());
    drop(timeout);
    assert!(slot.close_requested());
    assert!(owner.timer_driver().unwrap().is_empty());

    let SpawnAdmission::Admitted {
        task_id, priority, cancel_publication, spawn_effects,
    } = lab.state.admit_spawn_request(parts) else {
        panic!("the already-dequeued request reaches the publication seam");
    };
    let minted = slot.get().expect("late admission minted a private region");
    let region_id = minted.region_id;
    let close = Arc::clone(minted.close_notify());
    assert_ne!(region_id, root);
    let (wakes, observer) = cancel_publication.publish_with_spawn_effects(
        spawn_effects,
        |cancel_priority| {
            if let Some(priority) = cancel_priority {
                lab.scheduler.lock().schedule_cancel(task_id, priority);
            } else {
                lab.scheduler.lock().schedule(task_id, priority);
            }
        },
    );
    if let Some(observer) = observer {
        observer.dispatch();
    }
    wakes.dispatch();
    lab.run_until_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(close.lock().closed);
    assert!(slot.get().unwrap().close_outcome().is_some());
    assert!(lab.state.region(region_id).is_none());
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_timeout_publication_handoff_never_notifies_under_the_admission_lock() {
    for close_first in [false, true] {
        let mailbox = Arc::new(SpawnMailbox::new());
        let life = Arc::new(());
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let gateway = Arc::new(SpawnGateway::new(
            Arc::clone(&mailbox),
            Arc::new(move || { called.fetch_add(1, Ordering::SeqCst); }),
            None,
            Arc::downgrade(&life),
        ));
        let slot = BranchRegionSlot::owned(&gateway);
        let id = RegionId::new_for_test(10, 1);
        let close = Arc::new(Mutex::new(RegionCloseState { closed: false, waiters: Vec::new() }));
        let receipt = Arc::new(Mutex::new(None));
        let reason = CancelReason::user("owner abandoned before publication");
        if close_first {
            slot.request_close(reason.clone()).unwrap();
        }
        slot.publish(id, close, receipt);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "publication invokes no notifier");
        if !close_first {
            slot.request_close(reason.clone()).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        let mut commands = Vec::new();
        assert_eq!(mailbox.dequeue_region_commands_into(4, &mut commands), 1);
        assert!(matches!(
            commands.pop(),
            Some(RegionCommand::Cancel { region_id, reason: actual })
                if region_id == id && actual == reason
        ));
    }
}

#[test]
fn scoped_timeout_submission_notifier_unwind_retains_late_region_cleanup() {
    let (mut lab, owner, root, gate) = fixture(0x5C_0900, Time::ZERO);
    let original = owner.spawn_gateway_handle().unwrap();
    let life = Arc::new(());
    let notified = Arc::new(AtomicUsize::new(0));
    let notified_by_gateway = Arc::clone(&notified);
    let gateway = Arc::new(SpawnGateway::new(
        Arc::clone(original.mailbox()),
        Arc::new(move || {
            notified_by_gateway.fetch_add(1, Ordering::SeqCst);
            panic!("submission notifier panic");
        }),
        owner.timer_driver(),
        Arc::downgrade(&life),
    ));
    lab.state.set_spawn_gateway(Arc::clone(&gateway));
    let owner = owner.with_spawn_gateway(Some(gateway));
    let calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&calls);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async {}
    }));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = poll_once(timeout.as_mut());
    })).is_err());
    drop(timeout);
    assert_eq!(notified.load(Ordering::SeqCst), 1);
    // The request was queued before the hostile notifier ran. Admission must
    // inherit the owner's close without invoking this factory or notifier.
    lab.run_until_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(notified.load(Ordering::SeqCst), 1);
    assert_eq!(lab.state.regions_len(), 1);
    assert_eq!(lab.state.live_task_count(), 1);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_timeout_drop_drains_started_descendants_and_unpolled_drop_starts_nothing() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_0A00, Time::ZERO);
    let unused = owner.timeout_scoped(Duration::from_secs(60), |_| async {
        panic!("an unpolled timeout never starts its factory");
    });
    drop(unused);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    assert!(owner.timer_driver().unwrap().is_empty());

    let gate = Gate::default();
    let descendant_gate = gate.clone();
    let cleanup = Arc::new(AtomicBool::new(false));
    let descendant_cleanup = Arc::clone(&cleanup);
    let context = Arc::new(Mutex::new(None));
    let body_context = Arc::clone(&context);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |body| async move {
        *body_context.lock() = Some(body.clone());
        let _descendant = body.spawn(move |descendant| async move {
            descendant.cancelled().await;
            assert!(descendant.checkpoint().is_err());
            descendant_cleanup.store(true, Ordering::SeqCst);
            descendant_gate.await;
        }).unwrap();
        body.cancelled().await;
        assert!(body.checkpoint().is_err());
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let body = context.lock().clone().unwrap();
    drop(timeout);
    assert!(owner.timer_driver().unwrap().is_empty());
    lab.run_until_idle();
    assert!(cleanup.load(Ordering::SeqCst));
    assert!(lab.state.region(body.region_id()).is_some());
    gate.release();
    lab.run_until_idle();
    assert!(lab.state.region(body.region_id()).is_none());
    assert!(!owner.is_cancel_requested());
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_timeout_nested_race_context_cannot_escape_while_owner_stays_open_or_after_close() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_0B00, Time::ZERO);
    let held_body = Gate::default();
    let body_gate = held_body.clone();
    let contexts = Arc::new(Mutex::new(None));
    let published = Arc::clone(&contexts);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |body| async move {
        let factory: RaceFactory<Cx> = Box::new(|branch| Box::pin(async move { branch }));
        let escaped = body.race_drained_with(vec![factory]).await.unwrap();
        *published.lock() = Some((body.clone(), escaped));
        body_gate.await;
        42
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let (body, escaped) = contexts.lock().clone().expect("nested race completed");
    assert_eq!(lab.state.region(body.region_id()).unwrap().state(), RegionState::Open);
    assert!(lab.state.region(escaped.region_id()).is_none());
    assert_eq!(escaped.spawn_authorization_region_for(escaped.region_id()), Some(root));
    assert_eq!(escaped.spawn_fallback_for(escaped.region_id()), None);

    let calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&calls);
    let mut refused = escaped.spawn(move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async {}
    }).unwrap();
    let mut opening = Box::pin(escaped.open_child_region(ChildRegionSpec::inherit()));
    assert!(poll_once(opening.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(matches!(refused.try_join(), Err(JoinError::Cancelled(_))));
    assert!(matches!(poll_once(opening.as_mut()), Poll::Ready(Err(ChildRegionError::Create(_)))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.region(body.region_id()).unwrap().state(), RegionState::Open);
    drop(opening);

    held_body.release();
    lab.run_until_idle();
    let report = ready_report(timeout.as_mut());
    assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok(42))));
    assert!(report.close.unwrap().is_ok());
    let called = Arc::clone(&calls);
    let mut refused = body.spawn(move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async {}
    }).unwrap();
    lab.run_until_idle();
    assert!(matches!(refused.try_join(), Err(JoinError::Cancelled(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(timeout);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_timeout_queued_spawn_is_refused_when_close_precedes_authoritative_admission() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_0C00, Time::ZERO);
    let context = Arc::new(Mutex::new(None));
    let published = Arc::clone(&context);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |body| async move {
        *published.lock() = Some(body.clone());
        body.cancelled().await;
        assert!(body.checkpoint().is_err());
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let body = context.lock().clone().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&calls);
    let mut queued = body.spawn(move |_| {
        called.fetch_add(1, Ordering::SeqCst);
        async {}
    }).unwrap();
    assert_eq!(body.pending_spawn_counter_handle().unwrap().count(), 1);
    // The real pending admission credit keeps the region from being reclaimed,
    // but close has already revoked admission before this queued work arrives.
    lab.state.close_region_command(body.region_id(), &CancelReason::shutdown());
    assert!(!lab.state.region(body.region_id()).unwrap().state().can_accept_work());
    lab.run_until_idle();
    assert!(matches!(queued.try_join(), Err(JoinError::Cancelled(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let report = ready_report(timeout.as_mut());
    assert!(report.close.unwrap().is_ok());
    assert!(lab.state.region(body.region_id()).is_none());
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(timeout);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_timeout_preserves_real_descendant_finalizer_failure_separately() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_0D00, Time::ZERO);
    let release = Gate::default();
    let body_release = release.clone();
    let context = Arc::new(Mutex::new(None));
    let published = Arc::clone(&context);
    let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |body| async move {
        let child = body.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        *published.lock() = Some(child.region_id());
        body_release.await;
        // Closing the outer owner must observe this child's actual cleanup.
        drop(child);
        "body succeeded"
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let child = context.lock().unwrap();
    assert!(lab.state.register_sync_finalizer(child, || {
        panic!("descendant finalizer failed");
    }));
    release.release();
    lab.run_until_idle();
    let report = match poll_once(timeout.as_mut()) {
        Poll::Ready(Ok(report)) => report,
        Poll::Pending => {
            lab.run_until_idle();
            ready_report(timeout.as_mut())
        }
        other => panic!("unexpected timeout refusal: {other:?}"),
    };
    assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok("body succeeded"))));
    let close = report.close.unwrap().unwrap();
    assert!(matches!(
        close.cleanup_outcome,
        Some(Outcome::Panicked(ref payload)) if payload.message() == "descendant finalizer failed"
    ));
    assert!(close.descendant_panic.is_some());
    assert!(lab.state.region(child).is_none());
    drop(timeout);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_timeout_strict_authority_uses_checked_parent_target_without_placement_escape() {
    use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
    use crate::security::key::AuthKey;
    use crate::time::{TimerDriverHandle, VirtualClock};

    for (current_thread, sharded) in [(true, false), (true, true), (false, false), (false, true)] {
        let key = AuthKey::from_seed(121);
        let builder = if current_thread {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::multi_thread().worker_threads(2)
        };
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(100)));
        let runtime = builder
            .with_sharded_state(sharded)
            .with_timer_driver(TimerDriverHandle::with_virtual_clock(clock))
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let parent = root.region_id();
            let mint = |key: &AuthKey| MacaroonToken::mint(
                key, &format!("spawn:region_{}", parent.as_u64()), "scoped-timeout-test",
            );
            for denied in [
                root.clone(),
                root.clone().with_macaroon(mint(&AuthKey::from_seed(122))),
                root.clone().with_macaroon(mint(&key).add_caveat(CaveatPredicate::TimeBefore(99))),
            ] {
                let result = denied.timeout_scoped(Duration::from_secs(60), |_| async {
                    panic!("denied authority must not invoke the factory");
                }).await;
                assert!(matches!(
                    result,
                    Err(ScopedTimeoutError::Spawn(SpawnError::AuthorizationDenied { .. }))
                ));
            }
            let grant = mint(&key)
                .add_caveat(CaveatPredicate::RegionScope(parent.as_u64()))
                .add_caveat(CaveatPredicate::ResourceScope(format!("regions/{}/spawn", parent.as_u64())));
            let owner = root.clone().with_macaroon(grant);
            let report = owner.timeout_scoped(Duration::from_secs(60), move |body| async move {
                assert_ne!(body.region_id(), parent);
                assert_eq!(body.spawn_fallback_for(body.region_id()), None);
                assert_eq!(body.spawn_authorization_region_for(body.region_id()), Some(parent));
                let mut child = body.spawn(|child| async move {
                    let mut grandchild = child.spawn(|_| async { 42 }).unwrap();
                    grandchild.join(&child).await.unwrap()
                }).unwrap();
                child.join(&body).await.unwrap()
            }).await.unwrap();
            assert!(matches!(report.stop, ScopedTimeoutStop::TaskFinished));
            assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok(42))));
            assert!(report.close.unwrap().is_ok());
        });
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn scoped_timeout_preserves_typed_spawn_and_time_authority() {
    type WorkCaps = cap::CapSet<true, true, false, false, false>;

    let (mut lab, owner, root, gate) = fixture(0x5C_0E00, Time::ZERO);
    let restricted: Cx<WorkCaps> = owner.restrict();
    let mut timeout = Box::pin(restricted.timeout_scoped(Duration::from_secs(60), |body: Cx<WorkCaps>| async move {
        let mut child = body.spawn(|child: Cx<WorkCaps>| async move {
            assert!(!child.capabilities().io);
            7
        }).unwrap();
        poll_fn(|task| child.poll_join(task)).await.unwrap()
    }));
    assert!(poll_once(timeout.as_mut()).is_pending());
    lab.run_until_idle();
    let report = ready_report(timeout.as_mut());
    assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok(7))));
    assert!(report.close.unwrap().is_ok());
    drop(timeout);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_timeout_post_publication_notifier_panics_preserve_normal_drain_and_unwind_drop() {
    for drop_during_unwind in [false, true] {
        let (mut lab, owner, root, owner_gate) =
            fixture(0x5C_0F00 + u64::from(drop_during_unwind), Time::ZERO);
        let original = owner.spawn_gateway_handle().unwrap();
        let life = Arc::new(());
        let hostile = Arc::new(AtomicBool::new(false));
        let hostile_notify = Arc::clone(&hostile);
        let attempts = Arc::new(AtomicUsize::new(0));
        let notify_attempts = Arc::clone(&attempts);
        let gateway = Arc::new(SpawnGateway::new(
            Arc::clone(original.mailbox()),
            Arc::new(move || {
                if hostile_notify.load(Ordering::SeqCst) {
                    notify_attempts.fetch_add(1, Ordering::SeqCst);
                    panic!("post-publication notifier panic");
                }
            }),
            owner.timer_driver(),
            Arc::downgrade(&life),
        ));
        lab.state.set_spawn_gateway(Arc::clone(&gateway));
        let owner = owner.with_spawn_gateway(Some(gateway));
        let cleanup_gate = Gate::default();
        let descendant_gate = cleanup_gate.clone();
        let cleanup_started = Arc::new(AtomicBool::new(false));
        let descendant_started = Arc::clone(&cleanup_started);
        let context = Arc::new(Mutex::new(None));
        let published = Arc::clone(&context);
        let mut timeout = Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |body| async move {
            *published.lock() = Some(body.clone());
            let _descendant = body.spawn(move |descendant| async move {
                descendant.cancelled().await;
                assert!(descendant.checkpoint().is_err());
                descendant_started.store(true, Ordering::SeqCst);
                descendant_gate.await;
            }).unwrap();
            body.cancelled().await;
            assert!(body.checkpoint().is_err());
            "body finished"
        }));
        assert!(poll_once(timeout.as_mut()).is_pending());
        lab.run_until_idle();
        let body = context.lock().clone().expect("body really admitted and polled");
        assert_eq!(lab.state.live_task_count(), 3);
        hostile.store(true, Ordering::SeqCst);
        lab.advance_time_to(Time::from_secs(60));
        owner.timer_driver().unwrap().process_timers();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(poll_once(timeout.as_mut()).is_pending());
        })).is_ok(), "region/handle notifiers contain their own panics");
        assert!(attempts.load(Ordering::SeqCst) > 0);
        lab.run_until_idle();
        assert!(cleanup_started.load(Ordering::SeqCst));
        assert!(lab.state.region(body.region_id()).is_some());

        if drop_during_unwind {
            let unrelated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _drop_on_unwind = timeout;
                panic!("unrelated caller unwind");
            }));
            assert!(unrelated.is_err(), "only the caller's original panic escapes");
            cleanup_gate.release();
            lab.run_until_idle();
        } else {
            assert!(poll_once(timeout.as_mut()).is_pending());
            cleanup_gate.release();
            lab.run_until_idle();
            let report = ready_report(timeout.as_mut());
            assert!(matches!(report.stop, ScopedTimeoutStop::TimedOut));
            assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok("body finished"))));
            assert!(report.close.unwrap().is_ok());
            drop(timeout);
        }
        assert!(lab.state.region(body.region_id()).is_none());
        assert!(!owner.is_cancel_requested());
        assert!(owner.timer_driver().unwrap().is_empty());
        finish_fixture(&mut lab, root, &owner_gate);
    }
}
