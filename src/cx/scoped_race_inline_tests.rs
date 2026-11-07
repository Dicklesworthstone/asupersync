use super::*;
use crate::cx::ChildRegionSpec;
use crate::lab::{LabConfig, LabRuntime};
use crate::record::region::RegionState;
use crate::runtime::state::SpawnAdmission;
use crate::types::{Budget, CancelKind, CancelReason, Outcome, RegionId};
use parking_lot::Mutex;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

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

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

// Keep a real owner task alive while an external controller polls the race.
// Its gate does not acknowledge cancellation on behalf of the scoped API.
fn fixture(seed: u64) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let gate = Gate::default();
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, gate.clone())
        .unwrap();
    let owner = lab.state.task(task).unwrap().cx.clone().unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    (lab, owner, root, gate)
}

fn finish_fixture(lab: &mut LabRuntime, root: RegionId, owner_gate: &Gate) {
    owner_gate.release();
    lab.run_until_idle();
    lab.state
        .close_region_command(root, &CancelReason::user("scoped race test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn ready_report<L: std::fmt::Debug, R: std::fmt::Debug, F>(
    future: Pin<&mut F>,
) -> ScopedRaceReport<L, R>
where
    F: Future<Output = Result<ScopedRaceReport<L, R>, ScopedRaceError>>,
{
    match poll_once(future) {
        Poll::Ready(Ok(report)) => report,
        other => panic!("expected completed scoped race, got {other:?}"),
    }
}

fn assert_closed<T>(branch: &ScopedRaceBranchReport<T>) {
    assert!(branch.region_id.is_some());
    assert!(matches!(&branch.close, Some(Ok(_))), "{:?}", branch.close);
    assert!(branch.submission_error.is_none());
}

// Publish readiness only after the actual cancellation waiter returned Pending.
async fn parked_until_cancelled(cx: &Cx, parked: &AtomicUsize) -> CancelReason {
    let mut witnessed = false;
    let mut cancelled = std::pin::pin!(cx.cancelled());
    poll_fn(|task| match cancelled.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if !witnessed {
                witnessed = true;
                parked.fetch_add(1, Ordering::SeqCst);
            }
            Poll::Pending
        }
    })
    .await;
    assert!(cx.checkpoint().is_err());
    cx.cancel_reason().unwrap()
}

#[test]
fn scoped_race_unpolled_and_already_cancelled_calls_start_neither_factory() {
    let (mut lab, owner, root, gate) = fixture(0x5C_2100);
    let calls = Arc::new(AtomicUsize::new(0));
    for cancelled in [false, true] {
        let reason = CancelReason::user("owner refused useful work");
        if cancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let left_calls = Arc::clone(&calls);
        let right_calls = Arc::clone(&calls);
        let mut race = Box::pin(owner.race_scoped(
            move |_| {
                left_calls.fetch_add(1, Ordering::SeqCst);
                async { 7_u8 }
            },
            move |_| {
                right_calls.fetch_add(1, Ordering::SeqCst);
                async { "right" }
            },
        ));
        if cancelled {
            let report = ready_report(race.as_mut());
            assert!(matches!(
                &report.stop,
                ScopedRaceStop::Cancelled(actual) if actual == &reason
            ));
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
            assert!(matches!(report.left.task, ScopedRaceTask::NotStarted));
            assert!(matches!(report.right.task, ScopedRaceTask::NotStarted));
            assert!(report.left.region_id.is_none());
            assert!(report.right.region_id.is_none());
            assert!(report.left.close.is_none());
            assert!(report.right.close.is_none());
            assert!(!owner.inner.read().cancel_acknowledged);
        }
        drop(race);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
        assert_eq!(lab.state.regions_len(), 1);
    }
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_refuses_parent_limit_fallback_without_running_user_factories() {
    use crate::record::RegionLimits;

    let (mut lab, owner, root, gate) = fixture(0x5C_2200);
    assert!(lab.state.set_region_limits(
        root,
        RegionLimits {
            max_tasks: Some(10),
            ..RegionLimits::default()
        },
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let left_calls = Arc::clone(&calls);
    let right_calls = Arc::clone(&calls);
    let mut race = Box::pin(owner.race_scoped(
        move |_| {
            left_calls.fetch_add(1, Ordering::SeqCst);
            async { 7_u8 }
        },
        move |_| {
            right_calls.fetch_add(1, Ordering::SeqCst);
            async { "right" }
        },
    ));
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    let report = ready_report(race.as_mut());
    assert!(matches!(report.stop, ScopedRaceStop::NotAdmitted(_)));
    assert!(matches!(report.left.task, ScopedRaceTask::NotStarted));
    assert!(matches!(report.right.task, ScopedRaceTask::NotStarted));
    assert!(report.left.region_id.is_none());
    assert!(report.right.region_id.is_none());
    assert!(report.left.close.is_none());
    assert!(report.right.close.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.live_task_count(), 1);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    assert!(!owner.is_cancel_requested());
    drop(race);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_drop_before_late_admission_closes_both_published_regions() {
    let (mut lab, owner, root, gate) = fixture(0x5C_2300);
    let calls = Arc::new(AtomicUsize::new(0));
    let left_calls = Arc::clone(&calls);
    let right_calls = Arc::clone(&calls);
    let mut race = Box::pin(owner.race_scoped(
        move |_| {
            left_calls.fetch_add(1, Ordering::SeqCst);
            async { 7_u8 }
        },
        move |_| {
            right_calls.fetch_add(1, Ordering::SeqCst);
            async { "right" }
        },
    ));
    assert!(poll_once(race.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let mut requests = Vec::new();
    let mut slots = Vec::new();
    for _ in 0..2 {
        let parts = gateway
            .mailbox()
            .dequeue()
            .expect("both branches queued")
            .into_parts();
        let slot = Arc::clone(
            parts
                .admitted_slot
                .as_ref()
                .unwrap()
                .branch_region()
                .unwrap(),
        );
        assert!(slot.get().is_none());
        requests.push(parts);
        slots.push(slot);
    }
    // Both requests passed dequeue but neither has published its region.
    // The drop backstop must survive the absence of both canonical task IDs.
    drop(race);
    for slot in &slots {
        assert!(slot.close_requested());
    }
    for parts in requests {
        let SpawnAdmission::Admitted {
            task_id,
            priority,
            cancel_publication,
            spawn_effects,
        } = lab.state.admit_spawn_request(parts)
        else {
            panic!("the dequeued branch reaches its publication seam");
        };
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
    }
    lab.run_until_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let left_region = slots[0].get().unwrap().region_id;
    let right_region = slots[1].get().unwrap().region_id;
    assert_ne!(left_region, right_region);
    for slot in &slots {
        let region = slot.get().expect("late private region publication");
        assert_ne!(region.region_id, root);
        assert!(region.close_notify().lock().closed);
        assert!(region.close_outcome().is_some());
        assert!(lab.state.region(region.region_id).is_none());
    }
    assert_eq!(lab.state.live_task_count(), 1);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    assert!(!owner.is_cancel_requested());
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_masked_owner_cancel_drains_both_without_acknowledging_owner() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_2400);
    let parked = Arc::new(AtomicUsize::new(0));
    let left_parked = Arc::clone(&parked);
    let right_parked = Arc::clone(&parked);
    let left_release = Gate::default();
    let right_release = Gate::default();
    let left_cleanup = left_release.clone();
    let right_cleanup = right_release.clone();
    let mut race = Box::pin(owner.race_scoped(
        move |body| async move {
            let reason = parked_until_cancelled(&body, &left_parked).await;
            left_cleanup.await;
            (11_u8, reason)
        },
        move |body| async move {
            let reason = parked_until_cancelled(&body, &right_parked).await;
            right_cleanup.await;
            Err::<u16, _>(reason)
        },
    ));
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    assert_eq!(parked.load(Ordering::SeqCst), 2);
    let reason = CancelReason::user("masked owner stopped").with_cause(CancelReason::shutdown());
    owner.masked(|| {
        owner.set_cancel_reason(reason.clone());
        assert!(poll_once(race.as_mut()).is_pending());
        lab.run_until_idle();
        assert!(
            poll_once(race.as_mut()).is_pending(),
            "both cleanup gates are closed"
        );
        assert_eq!(owner.inner.read().mask_depth, 1);
        assert!(!owner.inner.read().cancel_acknowledged);
        left_release.release();
        right_release.release();
        lab.run_until_idle();
        let report = ready_report(race.as_mut());
        assert!(matches!(
            &report.stop,
            ScopedRaceStop::Cancelled(actual) if actual == &reason
        ));
        assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
        assert_closed(&report.left);
        assert_closed(&report.right);
        assert!(matches!(
            report.left.task,
            ScopedRaceTask::Joined(Ok((11, actual))) if actual == reason
        ));
        assert!(matches!(
            report.right.task,
            ScopedRaceTask::Joined(Ok(Err(actual))) if actual == reason
        ));
        assert_eq!(owner.inner.read().mask_depth, 1);
        assert!(!owner.inner.read().cancel_acknowledged);
    });
    assert_eq!(owner.inner.read().mask_depth, 0);
    assert!(!owner.inner.read().cancel_acknowledged);
    drop(race);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_race_owner_cancel_during_drain_strengthens_without_replacing_winner() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_2500);
    let choose_left = Gate::default();
    let left_start = choose_left.clone();
    let release = Gate::default();
    let right_cleanup = release.clone();
    let parked = Arc::new(AtomicUsize::new(0));
    let right_parked = Arc::clone(&parked);
    let cleaning = Arc::new(AtomicBool::new(false));
    let right_cleaning = Arc::clone(&cleaning);
    let context = Arc::new(Mutex::new(None));
    let right_context = Arc::clone(&context);
    let mut race = Box::pin(owner.race_scoped(
        move |_| async move {
            left_start.await;
            13_u8
        },
        move |body| async move {
            *right_context.lock() = Some(body.clone());
            let reason = parked_until_cancelled(&body, &right_parked).await;
            assert_eq!(reason.kind, CancelKind::RaceLost);
            right_cleaning.store(true, Ordering::SeqCst);
            right_cleanup.await;
            "acknowledged cleanup result"
        },
    ));
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    assert_eq!(parked.load(Ordering::SeqCst), 1);
    choose_left.release();
    lab.run_until_idle();
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(cleaning.load(Ordering::SeqCst));

    // Cancellation arrives only after selection, and then strengthens while
    // the same asynchronous cleanup remains pending. Neither event is a new
    // winner and neither may short-circuit the region's close wait.
    owner.set_cancel_reason(CancelReason::user("owner stopped during cleanup"));
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    let shutdown = CancelReason::shutdown().with_message("urgent owner cleanup");
    owner.set_cancel_reason(shutdown.clone());
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    let right = context.lock().clone().unwrap();
    assert_eq!(right.cancel_reason().unwrap(), shutdown);
    assert!(!owner.inner.read().cancel_acknowledged);
    release.release();
    lab.run_until_idle();
    let report = ready_report(race.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRaceStop::Winner(ScopedRaceBranch::Left)
    ));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&shutdown));
    assert_closed(&report.left);
    assert_closed(&report.right);
    assert!(matches!(report.left.task, ScopedRaceTask::Joined(Ok(13))));
    assert!(matches!(
        report.right.task,
        ScopedRaceTask::Joined(Ok("acknowledged cleanup result"))
    ));
    assert!(!owner.inner.read().cancel_acknowledged);
    drop(race);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_race_preserves_spawn_only_capabilities_without_timer_authority() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;

    let (mut lab, owner, root, gate) = fixture(0x5C_2600);
    let restricted: Cx<SpawnOnly> = owner.restrict();
    assert!(!restricted.capabilities().time);
    let mut race = Box::pin(restricted.race_scoped(
        |body: Cx<SpawnOnly>| async move {
            assert!(!body.capabilities().io);
            assert!(!body.capabilities().time);
            let mut child = body
                .spawn(|child: Cx<SpawnOnly>| async move {
                    assert!(!child.capabilities().io);
                    assert!(!child.capabilities().time);
                    17_u8
                })
                .unwrap();
            poll_fn(|task| child.poll_join(task)).await.unwrap()
        },
        |body: Cx<SpawnOnly>| async move {
            assert!(!body.capabilities().io);
            assert!(!body.capabilities().time);
            "independently typed right branch"
        },
    ));
    assert!(poll_once(race.as_mut()).is_pending());
    // Both terminal publications precede the controller's next poll, so the
    // documented left-first observation rule chooses the left result.
    lab.run_until_idle();
    let report = ready_report(race.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRaceStop::Winner(ScopedRaceBranch::Left)
    ));
    assert_closed(&report.left);
    assert_closed(&report.right);
    assert_ne!(report.left.region_id, report.right.region_id);
    assert!(matches!(report.left.task, ScopedRaceTask::Joined(Ok(17))));
    assert!(matches!(
        report.right.task,
        ScopedRaceTask::Joined(Ok("independently typed right branch"))
    ));
    assert!(report.owner_cancellation.is_none());
    assert!(owner.timer_driver().unwrap().is_empty());
    drop(race);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_retains_task_and_descendant_finalizer_panics_as_separate_receipts() {
    async fn panics_on_poll() -> &'static str {
        panic!("scoped race task panic");
    }

    for factory_panics in [false, true] {
        let (mut lab, owner, root, owner_gate) = fixture(0x5C_2700 + u64::from(factory_panics));
        let release = Gate::default();
        let left_release = release.clone();
        let descendant_id = Arc::new(Mutex::new(None));
        let published_id = Arc::clone(&descendant_id);
        let mut race = Box::pin(owner.race_scoped(
            move |body| async move {
                let child = body
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                *published_id.lock() = Some(child.region_id());
                left_release.await;
                drop(child);
                23_u8
            },
            move |_| {
                assert!(!factory_panics, "scoped race factory panic");
                panics_on_poll()
            },
        ));
        assert!(poll_once(race.as_mut()).is_pending());
        lab.run_until_idle();
        let child = descendant_id
            .lock()
            .expect("left descendant region admitted");
        assert!(lab.state.register_sync_finalizer(child, || {
            panic!("scoped race descendant finalizer panic");
        }));
        release.release();
        lab.run_until_idle();
        let report = match poll_once(race.as_mut()) {
            Poll::Ready(Ok(report)) => report,
            Poll::Pending => {
                // Selection may have just queued the last region-close work.
                lab.run_until_idle();
                ready_report(race.as_mut())
            }
            other => panic!("unexpected scoped race refusal: {other:?}"),
        };
        assert_closed(&report.left);
        assert_closed(&report.right);
        assert!(matches!(report.left.task, ScopedRaceTask::Joined(Ok(23))));
        let expected = if factory_panics {
            "scoped race factory panic"
        } else {
            "scoped race task panic"
        };
        assert!(matches!(
            report.right.task,
            ScopedRaceTask::Joined(Err(JoinError::Panicked(ref panic))) if panic.message() == expected
        ));
        let left_close = report.left.close.unwrap().unwrap();
        assert!(matches!(
            left_close.cleanup_outcome,
            Some(Outcome::Panicked(ref panic))
                if panic.message() == "scoped race descendant finalizer panic"
        ));
        assert!(left_close.descendant_panic.is_some());
        assert!(
            report
                .right
                .close
                .unwrap()
                .unwrap()
                .descendant_panic
                .is_some()
        );
        assert!(lab.state.region(child).is_none());
        assert!(!owner.is_cancel_requested());
        drop(race);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_race_future_is_send_with_non_sync_results() {
    fn assert_send<T: Send>(_: &T) {}

    let (mut lab, owner, root, gate) = fixture(0x5C_2800);
    let mut race = Box::pin(owner.race_scoped(
        |_| async { std::cell::Cell::new(29_u32) },
        |_| async { std::cell::Cell::new(31_u32) },
    ));
    // Cell is Send but not Sync. Retaining its result through region close
    // must not add a Sync requirement to the public race future.
    assert_send(&race);
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    let report = ready_report(race.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRaceStop::Winner(ScopedRaceBranch::Left)
    ));
    assert_closed(&report.left);
    assert_closed(&report.right);
    assert!(matches!(
        &report.left.task,
        ScopedRaceTask::Joined(Ok(value)) if value.get() == 29
    ));
    assert!(matches!(
        &report.right.task,
        ScopedRaceTask::Joined(Ok(value)) if value.get() == 31
    ));
    drop(race);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_second_submission_refusal_drains_the_first_late_admission() {
    use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
    use crate::runtime::spawn_mailbox::SpawnGateway;
    use crate::security::key::AuthKey;

    let (mut lab, owner, root, gate) = fixture(0x5C_2900);
    let original = owner.spawn_gateway_handle().unwrap();
    let mailbox = Arc::clone(original.mailbox());
    let frozen = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&frozen);
    let intercepted = Arc::new(AtomicBool::new(false));
    let intercept = Arc::clone(&intercepted);
    let owner_inner = Arc::clone(&owner.inner);
    let original_quota = owner.budget().poll_quota;
    let life = Arc::new(());
    let key = AuthKey::from_seed(133);
    let gateway = Arc::new(SpawnGateway::new(
        Arc::clone(&mailbox),
        Arc::new(move || {
            if !intercept.swap(true, Ordering::SeqCst) {
                // Freeze an already-dequeued left request, like a worker that
                // passed dequeue before the right producer checks authority.
                *capture.lock() = Some(
                    mailbox
                        .dequeue()
                        .expect("first branch was enqueued")
                        .into_parts(),
                );
                // This exact-budget capability still admits the captured
                // left request, but refuses the next producer's changed budget.
                owner_inner.write().budget.poll_quota = original_quota - 1;
            }
        }),
        owner.timer_driver(),
        Arc::downgrade(&life),
    ));
    gateway.require_spawn_authorization(key.clone());
    lab.state.set_spawn_gateway(Arc::clone(&gateway));
    let grant = MacaroonToken::mint(
        &key,
        &format!("spawn:region_{}", root.as_u64()),
        "scoped-race-partial-admission",
    )
    .add_caveat(CaveatPredicate::Custom(
        "poll_quota".to_owned(),
        original_quota.to_string(),
    ));
    let owner = owner.with_spawn_gateway(Some(gateway)).with_macaroon(grant);
    let calls = Arc::new(AtomicUsize::new(0));
    let left_calls = Arc::clone(&calls);
    let right_calls = Arc::clone(&calls);
    let mut race = Box::pin(owner.race_scoped(
        move |_| {
            left_calls.fetch_add(1, Ordering::SeqCst);
            async { 37_u8 }
        },
        move |_| {
            right_calls.fetch_add(1, Ordering::SeqCst);
            async { "never submitted" }
        },
    ));
    assert!(poll_once(race.as_mut()).is_pending(), "the left request still owns admission");
    let parts = frozen.lock().take().expect("left request captured before refusal");
    let slot = Arc::clone(parts.admitted_slot.as_ref().unwrap().branch_region().unwrap());
    assert!(slot.close_requested(), "whole-subtree stop precedes the left join");
    assert!(slot.get().is_none());

    let SpawnAdmission::Admitted {
        task_id,
        priority,
        cancel_publication,
        spawn_effects,
    } = lab.state.admit_spawn_request(parts)
    else {
        panic!("the originally authorized left request still admits");
    };
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
    let report = ready_report(race.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRaceStop::NotAdmitted(ScopedRaceBranch::Right)
    ));
    assert_closed(&report.left);
    assert!(matches!(
        report.left.task,
        ScopedRaceTask::Joined(Err(JoinError::Cancelled(_)))
    ));
    assert!(matches!(
        report.right.submission_error,
        Some(SpawnError::AuthorizationDenied { .. })
    ));
    assert!(matches!(report.right.task, ScopedRaceTask::NotStarted));
    assert!(report.right.region_id.is_none());
    assert!(report.right.close.is_none());
    assert!(report.owner_cancellation.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let left_region = slot.get().expect("left admission published its region");
    assert!(left_region.close_notify().lock().closed);
    assert!(lab.state.region(left_region.region_id).is_none());
    assert_eq!(lab.state.live_task_count(), 1);
    assert!(!owner.is_cancel_requested());
    drop(race);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_missing_gateway_refuses_before_either_factory_runs() {
    let owner = Cx::detached_cancel_context();
    let calls = Arc::new(AtomicUsize::new(0));
    let left_calls = Arc::clone(&calls);
    let right_calls = Arc::clone(&calls);
    let mut race = Box::pin(owner.race_scoped(
        move |_| {
            left_calls.fetch_add(1, Ordering::SeqCst);
            async { 41_u8 }
        },
        move |_| {
            right_calls.fetch_add(1, Ordering::SeqCst);
            async { "right" }
        },
    ));
    assert!(matches!(
        poll_once(race.as_mut()),
        Poll::Ready(Err(ScopedRaceError::Spawn(SpawnError::RuntimeUnavailable)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
