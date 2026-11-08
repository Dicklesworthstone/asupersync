//! Delayed factory and ownership boundaries for the plan's scoped hedge.
//! Fixed LabRuntime seeds expose admission, timer, cancellation, and close seams.

use super::*;
use crate::cx::cap;
use crate::lab::{LabConfig, LabRuntime};
use crate::record::RegionLimits;
use crate::record::region::RegionState;
use crate::runtime::JoinError;
use crate::runtime::state::SpawnAdmission;
use crate::time::TimerDriverHandle;
use crate::types::{Budget, CancelReason, RegionId, Time};
use parking_lot::Mutex;
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[derive(Clone, Default)]
struct Gate(Arc<GateState>);

#[derive(Default)]
struct GateState {
    open: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn release(&self) {
        self.0.open.store(true, Ordering::Release);
        let waker = self.0.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Future for Gate {
    type Output = ();

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        if self.0.open.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        *self.0.waker.lock() = Some(task.waker().clone());
        if self.0.open.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn fixture(seed: u64, start: Time) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
    lab.advance_time_to(start);
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
        .close_region_command(root, &CancelReason::user("scoped hedge test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.regions_len(), 0);
    assert!(lab.state.region(root).is_none());
}

fn drive<P: std::fmt::Debug, B: std::fmt::Debug, F>(
    lab: &mut LabRuntime,
    mut future: Pin<&mut F>,
) -> ScopedHedgeReport<P, B>
where
    F: Future<Output = Result<ScopedHedgeReport<P, B>, ScopedHedgeError>>,
{
    for _ in 0..128 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected hedge refusal: {error}"),
            Poll::Pending => {
                lab.run_until_idle();
            }
        }
    }
    panic!("scoped hedge did not close after its gates were released");
}

fn wait_for_timer<F: Future>(
    lab: &mut LabRuntime,
    mut future: Pin<&mut F>,
    timer: &TimerDriverHandle,
) -> Time {
    for _ in 0..128 {
        assert!(poll_once(future.as_mut()).is_pending());
        lab.run_until_idle();
        if let Some(deadline) = timer.next_deadline() {
            return deadline;
        }
    }
    panic!("the pending hedge never registered its delay");
}

fn assert_closed<T>(branch: &ScopedHedgeBranchReport<T>, root: RegionId) {
    assert_ne!(branch.region_id, Some(root));
    assert!(branch.region_id.is_some());
    let close = branch.close.as_ref().unwrap().as_ref().unwrap();
    assert!(close.descendant_panic.is_none());
    assert!(
        close
            .cleanup_outcome
            .as_ref()
            .is_none_or(|outcome| outcome.is_ok())
    );
    assert!(branch.submission_error.is_none());
}

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
fn scoped_hedge_unpolled_or_already_cancelled_starts_no_factory() {
    for cancelled in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x48_ED00 + u64::from(cancelled), Time::ZERO);
        let timer = owner.timer_driver().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let primary_calls = Arc::clone(&calls);
        let backup_calls = Arc::clone(&calls);
        let reason = CancelReason::shutdown().with_message("hedge owner already stopped");
        if cancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let mut hedge = Box::pin(owner.hedge_scoped(
            Duration::from_secs(60),
            move |_| {
                primary_calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(7_u8)
            },
            move |_| {
                backup_calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready("backup")
            },
        ));
        if cancelled {
            let report = drive(&mut lab, hedge.as_mut());
            assert!(
                matches!(&report.stop, ScopedHedgeStop::Cancelled(actual) if actual == &reason)
            );
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
            assert!(!report.backup_started);
            assert!(matches!(report.primary.task, ScopedHedgeTask::NotStarted));
            assert!(matches!(report.backup.task, ScopedHedgeTask::NotStarted));
            assert!(report.primary.region_id.is_none());
            assert!(report.backup.region_id.is_none());
            assert!(report.primary.close.is_none());
            assert!(report.backup.close.is_none());
            assert!(!owner.inner.read().cancel_acknowledged);
        }
        drop(hedge);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
        assert_eq!(lab.state.regions_len(), 1);
        assert!(timer.is_empty());
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_hedge_fast_primary_never_invokes_backup_user_factory() {
    let (mut lab, owner, root, gate) = fixture(0x48_ED10, Time::from_millis(100));
    let timer = owner.timer_driver().unwrap();
    let backups = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::clone(&backups);
    let mut hedge = Box::pin(owner.hedge_scoped(
        Duration::from_secs(60),
        |_| std::future::ready(Err::<u32, _>("primary typed error")),
        move |_| {
            invoked.fetch_add(1, Ordering::SeqCst);
            std::future::ready(91_u64)
        },
    ));
    let report = drive(&mut lab, hedge.as_mut());
    assert!(matches!(
        report.stop,
        ScopedHedgeStop::Winner(ScopedHedgeBranch::Primary)
    ));
    assert!(matches!(
        report.primary.task,
        ScopedHedgeTask::Joined(Ok(Err("primary typed error")))
    ));
    assert!(!report.backup_started);
    assert_eq!(backups.load(Ordering::SeqCst), 0);
    assert!(!matches!(
        report.backup.task,
        ScopedHedgeTask::Joined(Ok(_))
    ));
    // Both strict wrapper slots are reserved up front. Only user invocation is
    // lazy; an unused backup still has an independent subtree close receipt.
    assert_closed(&report.primary, root);
    assert_closed(&report.backup, root);
    assert_ne!(report.primary.region_id, report.backup.region_id);
    assert!(report.owner_cancellation.is_none());
    assert!(timer.is_empty());
    assert_eq!(timer.now(), Time::from_millis(100));
    drop(hedge);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_hedge_primary_panic_suppresses_backup_before_controller_observes_join() {
    for construction in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x48_ED18 + u64::from(construction), Time::ZERO);
        let timer = owner.timer_driver().unwrap();
        let backups = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&backups);
        let mut hedge = Box::pin(owner.hedge_scoped(
            Duration::from_millis(25),
            move |_| {
                assert!(!construction, "hedge factory panic");
                async {
                    panic!("hedge future panic");
                    #[allow(unreachable_code)]
                    99_u8
                }
            },
            move |_| {
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready("must remain suppressed")
            },
        ));
        assert!(poll_once(hedge.as_mut()).is_pending());
        lab.run_until_idle();
        // The controller has not observed the failed task. The completion
        // guard itself must suppress backup work when the old delay fires.
        lab.advance_time_to(Time::from_millis(100));
        let _ = timer.process_timers();
        lab.run_until_idle();
        assert_eq!(backups.load(Ordering::SeqCst), 0);
        let report = drive(&mut lab, hedge.as_mut());
        assert!(matches!(
            report.stop,
            ScopedHedgeStop::Winner(ScopedHedgeBranch::Primary)
        ));
        let expected = if construction {
            "hedge factory panic"
        } else {
            "hedge future panic"
        };
        assert!(matches!(&report.primary.task,
            ScopedHedgeTask::Joined(Err(JoinError::Panicked(payload)))
                if payload.message() == expected));
        let close = report.primary.close.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(close.descendant_panic.as_ref().unwrap().message(), expected);
        assert!(
            lab.state
                .region(report.primary.region_id.unwrap())
                .is_none()
        );
        assert_closed(&report.backup, root);
        assert!(!report.backup_started);
        assert_eq!(backups.load(Ordering::SeqCst), 0);
        assert!(timer.is_empty());
        drop(hedge);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_hedge_delay_uses_explicit_owner_clock_from_first_outer_poll() {
    let start = Time::from_millis(100);
    let (mut lab, owner, root, gate) = fixture(0x48_ED20, start);
    let timer = owner.timer_driver().unwrap();
    let ambient = Cx::for_testing();
    ambient.set_cancel_reason(CancelReason::shutdown());
    let _foreign_context = Cx::set_current(Some(ambient));
    let parked = Arc::new(AtomicUsize::new(0));
    let primary_parked = Arc::clone(&parked);
    let starts = Arc::new(Mutex::new(Vec::new()));
    let backup_starts = Arc::clone(&starts);
    let mut hedge = Box::pin(owner.hedge_scoped(
        Duration::from_millis(25),
        move |body| async move {
            parked_until_cancelled(&body, &primary_parked).await;
            11_u8
        },
        move |body| {
            backup_starts
                .lock()
                .push(body.timer_driver().unwrap().now());
            std::future::ready("delayed result")
        },
    ));
    assert!(poll_once(hedge.as_mut()).is_pending());
    // Deliberately admit/poll the branch wrappers ten virtual milliseconds
    // later. Their scheduling delay must not move the hedge's deadline.
    lab.advance_time_to(Time::from_millis(110));
    lab.run_until_idle();
    assert_eq!(parked.load(Ordering::SeqCst), 1);
    assert_eq!(timer.next_deadline(), Some(Time::from_millis(125)));
    assert!(starts.lock().is_empty());
    lab.advance_time_to(Time::from_millis(124));
    let _ = timer.process_timers();
    assert!(poll_once(hedge.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(starts.lock().is_empty());
    lab.advance_time_to(Time::from_millis(125));
    let _ = timer.process_timers();
    let report = drive(&mut lab, hedge.as_mut());
    assert_eq!(*starts.lock(), vec![Time::from_millis(125)]);
    assert!(report.backup_started);
    assert!(matches!(
        report.stop,
        ScopedHedgeStop::Winner(ScopedHedgeBranch::Backup)
    ));
    assert!(matches!(
        report.backup.task,
        ScopedHedgeTask::Joined(Ok("delayed result"))
    ));
    assert!(matches!(
        report.primary.task,
        ScopedHedgeTask::Joined(Ok(11))
    ));
    assert_closed(&report.primary, root);
    assert_closed(&report.backup, root);
    assert!(report.owner_cancellation.is_none());
    assert!(!owner.is_cancel_requested());
    assert!(timer.is_empty());
    drop(hedge);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_hedge_zero_delay_supports_send_non_sync_results_without_runtime_time_or_entropy() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    type SpawnTime = cap::CapSet<true, true, false, false, false>;
    fn assert_send<T: Send>(_: &T) {}

    let (mut lab, owner, root, gate) = fixture(0x48_ED30, Time::ZERO);
    let mut owner = owner.restrict::<SpawnTime>();
    owner.runtime_mask = <SpawnOnly as cap::CapSetRuntimeMask>::MASK;
    assert!(owner.timer_driver().is_none());
    let future = owner.hedge_scoped(
        Duration::ZERO,
        |body| {
            assert!(body.timer_driver().is_none());
            assert!(!body.capabilities().entropy);
            std::future::ready(Cell::new(17_u32))
        },
        |body| {
            assert!(body.timer_driver().is_none());
            assert!(!body.capabilities().entropy);
            std::future::ready(Cell::new(23_u64))
        },
    );
    assert_send(&future);
    let mut hedge = Box::pin(future);
    assert!(poll_once(hedge.as_mut()).is_pending());
    lab.run_until_idle();
    let report = drive(&mut lab, hedge.as_mut());
    assert!(matches!(
        report.stop,
        ScopedHedgeStop::Winner(ScopedHedgeBranch::Primary)
    ));
    assert!(
        matches!(&report.primary.task, ScopedHedgeTask::Joined(Ok(value)) if value.get() == 17)
    );
    if report.backup_started {
        assert!(
            matches!(&report.backup.task, ScopedHedgeTask::Joined(Ok(value)) if value.get() == 23)
        );
    } else {
        assert!(!matches!(
            report.backup.task,
            ScopedHedgeTask::Joined(Ok(_))
        ));
    }
    assert_closed(&report.primary, root);
    assert_closed(&report.backup, root);
    drop(hedge);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_hedge_refuses_missing_runtime_authority_before_either_factory() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    for missing_timer in [false, true] {
        let (mut lab, mut owner, root, gate) =
            fixture(0x48_ED40 + u64::from(missing_timer), Time::ZERO);
        if missing_timer {
            owner.runtime_mask = <SpawnOnly as cap::CapSetRuntimeMask>::MASK;
        } else {
            owner = owner.with_spawn_gateway(None);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let primary = Arc::clone(&calls);
        let backup = Arc::clone(&calls);
        let mut hedge = Box::pin(owner.hedge_scoped(
            Duration::from_millis(1),
            move |_| {
                primary.fetch_add(1, Ordering::SeqCst);
                std::future::ready(1_u8)
            },
            move |_| {
                backup.fetch_add(1, Ordering::SeqCst);
                std::future::ready(2_u8)
            },
        ));
        match poll_once(hedge.as_mut()) {
            Poll::Ready(Err(ScopedHedgeError::TimerUnavailable)) if missing_timer => {}
            Poll::Ready(Err(ScopedHedgeError::Spawn(_))) if !missing_timer => {}
            other => panic!("unexpected authority refusal: {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 1);
        assert_eq!(lab.state.regions_len(), 1);
        drop(hedge);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_hedge_private_admission_refusal_never_runs_parent_fallback_factories() {
    for limit in [1, 10] {
        let (mut lab, owner, root, gate) = fixture(0x48_ED50 + limit as u64, Time::ZERO);
        assert!(lab.state.set_region_limits(
            root,
            RegionLimits {
                max_tasks: Some(limit),
                ..RegionLimits::default()
            },
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let primary = Arc::clone(&calls);
        let backup = Arc::clone(&calls);
        let mut hedge = Box::pin(owner.hedge_scoped(
            Duration::from_secs(60),
            move |_| {
                primary.fetch_add(1, Ordering::SeqCst);
                std::future::ready(1_u8)
            },
            move |_| {
                backup.fetch_add(1, Ordering::SeqCst);
                std::future::ready(2_u8)
            },
        ));
        let report = drive(&mut lab, hedge.as_mut());
        assert!(matches!(report.stop, ScopedHedgeStop::NotAdmitted(_)));
        assert!(!report.backup_started);
        assert!(report.primary.region_id.is_none());
        assert!(report.backup.region_id.is_none());
        assert!(report.primary.close.is_none());
        assert!(report.backup.close.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
        assert!(!owner.is_cancel_requested());
        assert!(owner.timer_driver().unwrap().is_empty());
        drop(hedge);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_hedge_cancel_or_drop_during_delay_drains_children_and_retires_timer() {
    for cancel in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x48_ED60 + u64::from(cancel), Time::ZERO);
        let timer = owner.timer_driver().unwrap();
        let parked = Arc::new(AtomicUsize::new(0));
        let child_parked = Arc::clone(&parked);
        let cleaning = Arc::new(AtomicBool::new(false));
        let child_cleaning = Arc::clone(&cleaning);
        let finished = Arc::new(AtomicBool::new(false));
        let child_finished = Arc::clone(&finished);
        let release = Gate::default();
        let cleanup = release.clone();
        let backups = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&backups);
        let mut hedge = Box::pin(owner.hedge_scoped(
            Duration::from_secs(60),
            move |body| async move {
                let mut child = body
                    .spawn(move |child| async move {
                        parked_until_cancelled(&child, &child_parked).await;
                        child_cleaning.store(true, Ordering::Release);
                        cleanup.await;
                        child_finished.store(true, Ordering::Release);
                    })
                    .unwrap();
                child.join(&body).await.unwrap();
                assert!(body.checkpoint().is_err());
                7_u8
            },
            move |_| {
                invoked.fetch_add(1, Ordering::SeqCst);
                std::future::ready("backup must remain unused")
            },
        ));
        assert_eq!(
            wait_for_timer(&mut lab, hedge.as_mut(), &timer),
            Time::from_secs(60)
        );
        lab.run_until_idle();
        assert_eq!(parked.load(Ordering::SeqCst), 1);
        assert!(!finished.load(Ordering::Acquire));
        if cancel {
            let reason = CancelReason::shutdown().with_message("stop before hedge delay");
            owner.masked(|| {
                owner.set_cancel_reason(reason.clone());
                assert!(poll_once(hedge.as_mut()).is_pending());
                lab.run_until_idle();
                assert!(cleaning.load(Ordering::Acquire));
                assert!(poll_once(hedge.as_mut()).is_pending());
                assert!(!finished.load(Ordering::Acquire));
                release.release();
                let report = drive(&mut lab, hedge.as_mut());
                assert!(
                    matches!(&report.stop, ScopedHedgeStop::Cancelled(actual) if actual == &reason)
                );
                assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
                assert!(!report.backup_started);
                assert!(!matches!(
                    report.backup.task,
                    ScopedHedgeTask::Joined(Ok(_))
                ));
                assert_closed(&report.primary, root);
                assert_closed(&report.backup, root);
                assert_eq!(owner.inner.read().mask_depth, 1);
                assert!(!owner.inner.read().cancel_acknowledged);
            });
            drop(hedge);
        } else {
            drop(hedge);
            lab.run_until_idle();
            assert!(cleaning.load(Ordering::Acquire));
            assert!(!finished.load(Ordering::Acquire));
            release.release();
            lab.run_until_idle();
        }
        assert!(finished.load(Ordering::Acquire));
        assert!(timer.is_empty());
        lab.advance_time_to(Time::from_secs(120));
        let _ = timer.process_timers();
        lab.run_until_idle();
        assert_eq!(backups.load(Ordering::SeqCst), 0);
        assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
        assert_eq!(lab.state.live_task_count(), 1);
        assert_eq!(lab.state.regions_len(), 1);
        assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_hedge_drop_before_admission_closes_both_late_private_slots() {
    let (mut lab, owner, root, gate) = fixture(0x48_ED70, Time::ZERO);
    let calls = Arc::new(AtomicUsize::new(0));
    let primary = Arc::clone(&calls);
    let backup = Arc::clone(&calls);
    let mut hedge = Box::pin(owner.hedge_scoped(
        Duration::from_secs(60),
        move |_| {
            primary.fetch_add(1, Ordering::SeqCst);
            std::future::ready(1_u8)
        },
        move |_| {
            backup.fetch_add(1, Ordering::SeqCst);
            std::future::ready(2_u8)
        },
    ));
    assert!(poll_once(hedge.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let mut requests = Vec::new();
    let mut slots = Vec::new();
    for _ in 0..2 {
        let parts = gateway.mailbox().dequeue().unwrap().into_parts();
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
    assert!(gateway.mailbox().dequeue().is_none());
    drop(hedge);
    assert!(slots.iter().all(|slot| slot.close_requested()));
    for parts in requests {
        let SpawnAdmission::Admitted {
            task_id,
            priority,
            cancel_publication,
            spawn_effects,
        } = lab.state.admit_spawn_request(parts)
        else {
            panic!("the dequeued wrapper reaches late publication");
        };
        let (wakes, observer) =
            cancel_publication.publish_with_spawn_effects(spawn_effects, |cancel_priority| {
                if let Some(priority) = cancel_priority {
                    lab.scheduler.lock().schedule_cancel(task_id, priority);
                } else {
                    lab.scheduler.lock().schedule(task_id, priority);
                }
            });
        if let Some(observer) = observer {
            observer.dispatch();
        }
        wakes.dispatch();
    }
    lab.run_until_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    for slot in slots {
        let region = slot.get().unwrap();
        assert_ne!(region.region_id, root);
        assert!(region.close_notify().lock().closed);
        assert!(region.close_outcome().is_some());
        assert!(lab.state.region(region.region_id).is_none());
    }
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    assert_eq!(lab.state.live_task_count(), 1);
    assert_eq!(lab.state.regions_len(), 1);
    assert!(owner.timer_driver().unwrap().is_empty());
    finish_fixture(&mut lab, root, &gate);
}
