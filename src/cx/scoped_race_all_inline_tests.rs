//! Dynamic first-terminal races for asupersync-bi2462 and the descendant-join
//! boundary in asupersync-inleqi. Replay through RCH with `cargo test --lib
//! cx::scoped_race_all::tests -- --nocapture` and an explicit target directory.

use super::*;
use crate::cx::cap;
use crate::cx::{Cx, ScopedRaceBranchReport, ScopedRaceTask};
use crate::lab::{LabConfig, LabRuntime};
use crate::record::region::RegionState;
use crate::runtime::JoinError;
use crate::runtime::state::{SpawnAdmission, SpawnError};
use crate::types::{Budget, CancelKind, CancelReason, RegionId};
use parking_lot::Mutex;
use std::future::{Future, poll_fn, ready};
use std::pin::{Pin, pin};
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

fn fixture(seed: u64) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(20_000));
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

fn finish_fixture(lab: &mut LabRuntime, root: RegionId, gate: &Gate) {
    gate.release();
    lab.run_until_idle();
    lab.state
        .close_region_command(root, &CancelReason::user("dynamic race test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn completed<T: std::fmt::Debug, F>(
    lab: &mut LabRuntime,
    mut future: Pin<&mut F>,
) -> ScopedRaceAllReport<T>
where
    F: Future<Output = Result<ScopedRaceAllReport<T>, ScopedRaceAllError>>,
{
    for _ in 0..32 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected dynamic race refusal: {error:?}"),
            Poll::Pending => {
                lab.run_until_idle();
            }
        }
    }
    panic!("dynamic race did not finish after released deterministic work");
}

fn assert_closed<T>(attempt: &ScopedRaceBranchReport<T>, parent: RegionId) {
    assert!(attempt.region_id.is_some());
    assert_ne!(attempt.region_id, Some(parent));
    assert!(attempt.submission_error.is_none());
    assert!(matches!(&attempt.close, Some(Ok(_))), "{:?}", attempt.close);
}

async fn parked_until_cancelled(cx: &Cx, parked: &AtomicUsize) -> CancelReason {
    let mut witnessed = false;
    let mut cancelled = pin!(cx.cancelled());
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
fn scoped_race_all_invalid_input_and_missing_gateway_start_no_user_work() {
    let (mut lab, owner, root, gate) = fixture(0x5C_4100);
    type Immediate = fn(Cx) -> std::future::Ready<usize>;
    let mut empty = Box::pin(owner.race_all_scoped(Vec::<Immediate>::new()));
    assert!(matches!(
        poll_once(empty.as_mut()),
        Poll::Ready(Err(ScopedRaceAllError::Empty))
    ));
    drop(empty);

    let calls = Arc::new(AtomicUsize::new(0));
    let factories = (0..=MAX_SCOPED_RACE_BRANCHES)
        .map(|index| {
            let calls = Arc::clone(&calls);
            move |_: Cx| {
                calls.fetch_add(1, Ordering::SeqCst);
                ready(index)
            }
        })
        .collect();
    let mut oversized = Box::pin(owner.race_all_scoped(factories));
    assert!(matches!(
        poll_once(oversized.as_mut()),
        Poll::Ready(Err(ScopedRaceAllError::TooManyBranches { total }))
            if total == MAX_SCOPED_RACE_BRANCHES + 1
    ));
    drop(oversized);

    let missing = owner.clone().with_spawn_gateway(None);
    let factories = (0..4)
        .map(|index| {
            let calls = Arc::clone(&calls);
            move |_: Cx| {
                calls.fetch_add(1, Ordering::SeqCst);
                ready(index)
            }
        })
        .collect();
    let mut refused = Box::pin(missing.race_all_scoped(factories));
    assert!(matches!(
        poll_once(refused.as_mut()),
        Poll::Ready(Err(ScopedRaceAllError::Spawn(
            SpawnError::RuntimeUnavailable
        )))
    ));
    drop(refused);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    assert_eq!(lab.state.regions_len(), 1);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_all_unpolled_and_precancelled_calls_retire_without_invocation() {
    let (mut lab, owner, root, gate) = fixture(0x5C_4200);
    let calls = Arc::new(AtomicUsize::new(0));
    for cancelled in [false, true] {
        let reason =
            CancelReason::user("do not start dynamic race").with_cause(CancelReason::shutdown());
        if cancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let factories = (0..4)
            .map(|index| {
                let calls = Arc::clone(&calls);
                move |_: Cx| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    ready(index)
                }
            })
            .collect();
        let mut race = Box::pin(owner.race_all_scoped(factories));
        if cancelled {
            let report = completed(&mut lab, race.as_mut());
            assert!(matches!(
                &report.stop,
                ScopedRaceAllStop::Cancelled(actual) if actual == &reason
            ));
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
            assert_eq!(report.attempts.len(), 4);
            for attempt in report.attempts {
                assert!(matches!(attempt.task, ScopedRaceTask::NotStarted));
                assert!(attempt.region_id.is_none());
                assert!(attempt.close.is_none());
                assert!(attempt.submission_error.is_none());
            }
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
fn scoped_race_all_ready_ties_preserve_input_order_spawn_only_caps_and_non_sync_values() {
    fn assert_send<T: Send>(_: &T) {}
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;

    let (mut lab, owner, root, gate) = fixture(0x5C_4300);
    let restricted: Cx<SpawnOnly> = owner.restrict();
    let factories = (0..MAX_SCOPED_RACE_BRANCHES)
        .map(|index| {
            move |body: Cx<SpawnOnly>| async move {
                assert!(!body.capabilities().io);
                assert!(!body.capabilities().time);
                std::cell::Cell::new(index)
            }
        })
        .collect();
    let mut race = Box::pin(restricted.race_all_scoped(factories));
    assert_send(&race);
    assert!(poll_once(race.as_mut()).is_pending());
    // Complete all bodies before the controller's next observation. A later
    // scheduling order cannot replace the documented input-order tie rule.
    lab.run_until_idle();
    let report = completed(&mut lab, race.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRaceAllStop::Winner { index: 0 }
    ));
    assert_eq!(report.attempts.len(), MAX_SCOPED_RACE_BRANCHES);
    let mut ids = std::collections::HashSet::new();
    for (index, attempt) in report.attempts.iter().enumerate() {
        assert_closed(attempt, root);
        assert!(ids.insert(attempt.region_id.unwrap()));
        assert!(matches!(
            &attempt.task,
            ScopedRaceTask::Joined(Ok(value)) if value.get() == index
        ));
    }
    assert!(report.owner_cancellation.is_none());
    assert!(!owner.is_cancel_requested());
    assert!(owner.timer_driver().unwrap().is_empty());
    drop(race);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_all_selects_first_error_or_panic_instead_of_waiting_for_success() {
    for panic_wins in [false, true] {
        let (mut lab, owner, root, gate) = fixture(0x5C_4400 + u64::from(panic_wins));
        let select = Gate::default();
        let parked = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let factories = (0..4)
            .map(|index| {
                let select = select.clone();
                let parked = Arc::clone(&parked);
                let calls = Arc::clone(&calls);
                move |body: Cx| async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if index == 2 {
                        select.await;
                        assert!(!panic_wins, "first dynamic terminal panic");
                        Err("first terminal error")
                    } else {
                        let reason = parked_until_cancelled(&body, &parked).await;
                        assert_eq!(reason.kind, CancelKind::RaceLost);
                        Ok(index)
                    }
                }
            })
            .collect();
        let mut race = Box::pin(owner.race_all_scoped(factories));
        assert!(poll_once(race.as_mut()).is_pending());
        lab.run_until_idle();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(parked.load(Ordering::SeqCst), 3);
        select.release();
        lab.run_until_idle();
        let report = completed(&mut lab, race.as_mut());
        assert!(matches!(
            report.stop,
            ScopedRaceAllStop::Winner { index: 2 }
        ));
        for (index, attempt) in report.attempts.iter().enumerate() {
            assert_closed(attempt, root);
            if index != 2 {
                assert!(
                    matches!(&attempt.task, ScopedRaceTask::Joined(Ok(Ok(value))) if *value == index)
                );
            } else if panic_wins {
                assert!(matches!(
                    &attempt.task,
                    ScopedRaceTask::Joined(Err(JoinError::Panicked(payload)))
                        if payload.message() == "first dynamic terminal panic"
                ));
                assert!(
                    attempt
                        .close
                        .as_ref()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .descendant_panic
                        .is_some()
                );
            } else {
                assert!(matches!(
                    &attempt.task,
                    ScopedRaceTask::Joined(Ok(Err("first terminal error")))
                ));
            }
        }
        assert!(report.owner_cancellation.is_none());
        assert!(!owner.is_cancel_requested());
        drop(race);
        finish_fixture(&mut lab, root, &gate);
    }
}

#[test]
fn scoped_race_all_private_region_refusal_never_falls_back_to_parent_execution() {
    use crate::record::RegionLimits;

    let (mut lab, owner, root, gate) = fixture(0x5C_4500);
    assert!(lab.state.set_region_limits(
        root,
        RegionLimits {
            max_tasks: Some(10),
            ..RegionLimits::default()
        },
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let factories = (0..4)
        .map(|index| {
            let calls = Arc::clone(&calls);
            move |_: Cx| {
                calls.fetch_add(1, Ordering::SeqCst);
                ready(index)
            }
        })
        .collect();
    let mut race = Box::pin(owner.race_all_scoped(factories));
    assert!(poll_once(race.as_mut()).is_pending());
    let report = completed(&mut lab, race.as_mut());
    assert!(matches!(report.stop, ScopedRaceAllStop::NotAdmitted { .. }));
    assert_eq!(report.attempts.len(), 4);
    for attempt in report.attempts {
        assert!(matches!(attempt.task, ScopedRaceTask::NotStarted));
        assert!(attempt.region_id.is_none());
        assert!(attempt.close.is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    assert!(!owner.is_cancel_requested());
    drop(race);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_all_drop_cancels_every_slot_before_late_region_publication() {
    let (mut lab, owner, root, gate) = fixture(0x5C_4600);
    let calls = Arc::new(AtomicUsize::new(0));
    let factories = (0..4)
        .map(|index| {
            let calls = Arc::clone(&calls);
            move |_: Cx| {
                calls.fetch_add(1, Ordering::SeqCst);
                ready(index)
            }
        })
        .collect();
    let mut race = Box::pin(owner.race_all_scoped(factories));
    assert!(poll_once(race.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let mut requests = Vec::new();
    let mut slots = Vec::new();
    for _ in 0..4 {
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
            panic!("a dequeued request must reach its late publication seam");
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
    let mut ids = std::collections::HashSet::new();
    for slot in &slots {
        let published = slot.get().unwrap();
        assert!(ids.insert(published.region_id));
        assert_ne!(published.region_id, root);
        assert!(published.close_notify().lock().closed);
        assert!(published.close_outcome().is_some());
        assert!(lab.state.region(published.region_id).is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.live_task_count(), 1);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    assert!(!owner.is_cancel_requested());
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_all_partial_submission_refusal_drains_captured_predecessor() {
    use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
    use crate::runtime::spawn_mailbox::SpawnGateway;
    use crate::security::key::AuthKey;

    let (mut lab, owner, root, gate) = fixture(0x5C_4700);
    let original = owner.spawn_gateway_handle().unwrap();
    let mailbox = Arc::clone(original.mailbox());
    let frozen = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&frozen);
    let intercepted = Arc::new(AtomicBool::new(false));
    let intercept = Arc::clone(&intercepted);
    let owner_inner = Arc::clone(&owner.inner);
    let quota = owner.budget().poll_quota;
    let life = Arc::new(());
    let key = AuthKey::from_seed(151);
    let gateway = Arc::new(SpawnGateway::new(
        Arc::clone(&mailbox),
        Arc::new(move || {
            if !intercept.swap(true, Ordering::SeqCst) {
                *capture.lock() = Some(mailbox.dequeue().unwrap().into_parts());
                owner_inner.write().budget.poll_quota = quota - 1;
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
        "dynamic-race-partial-admission",
    )
    .add_caveat(CaveatPredicate::Custom(
        "poll_quota".to_owned(),
        quota.to_string(),
    ));
    let owner = owner.with_spawn_gateway(Some(gateway)).with_macaroon(grant);
    let calls = Arc::new(AtomicUsize::new(0));
    let factories = (0..4)
        .map(|index| {
            let calls = Arc::clone(&calls);
            move |_: Cx| {
                calls.fetch_add(1, Ordering::SeqCst);
                ready(index)
            }
        })
        .collect();
    let mut race = Box::pin(owner.race_all_scoped(factories));
    assert!(poll_once(race.as_mut()).is_pending());
    let parts = frozen
        .lock()
        .take()
        .expect("first request dequeued before refusal");
    let slot = Arc::clone(
        parts
            .admitted_slot
            .as_ref()
            .unwrap()
            .branch_region()
            .unwrap(),
    );
    assert!(slot.close_requested());
    assert!(slot.get().is_none());
    let SpawnAdmission::Admitted {
        task_id,
        priority,
        cancel_publication,
        spawn_effects,
    } = lab.state.admit_spawn_request(parts)
    else {
        panic!("the captured request retains its original valid authority");
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
    let report = completed(&mut lab, race.as_mut());
    assert!(matches!(
        report.stop,
        ScopedRaceAllStop::NotAdmitted { index: 1 }
    ));
    assert_eq!(report.attempts.len(), 4);
    assert_closed(&report.attempts[0], root);
    assert!(matches!(
        &report.attempts[0].task,
        ScopedRaceTask::Joined(Err(JoinError::Cancelled(_)))
    ));
    assert!(matches!(
        &report.attempts[1].submission_error,
        Some(SpawnError::AuthorizationDenied { .. })
    ));
    for attempt in &report.attempts[1..] {
        assert!(matches!(attempt.task, ScopedRaceTask::NotStarted));
        assert!(attempt.region_id.is_none());
        assert!(attempt.close.is_none());
    }
    for attempt in &report.attempts[2..] {
        assert!(attempt.submission_error.is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.live_task_count(), 1);
    assert!(slot.get().unwrap().close_notify().lock().closed);
    assert!(report.owner_cancellation.is_none());
    assert!(!owner.is_cancel_requested());
    drop(race);
    finish_fixture(&mut lab, root, &gate);
}

#[test]
fn scoped_race_all_masked_owner_cancel_drains_every_pending_cleanup_without_ack() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5C_4800);
    let parked = Arc::new(AtomicUsize::new(0));
    let releases: Vec<_> = (0..4).map(|_| Gate::default()).collect();
    let factories = releases
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, cleanup)| {
            let parked = Arc::clone(&parked);
            move |body: Cx| async move {
                let reason = parked_until_cancelled(&body, &parked).await;
                cleanup.await;
                (index, reason)
            }
        })
        .collect();
    let mut race = Box::pin(owner.race_all_scoped(factories));
    assert!(poll_once(race.as_mut()).is_pending());
    lab.run_until_idle();
    assert_eq!(parked.load(Ordering::SeqCst), 4);
    let reason = CancelReason::user("masked dynamic owner").with_cause(CancelReason::shutdown());
    owner.masked(|| {
        owner.set_cancel_reason(reason.clone());
        assert!(poll_once(race.as_mut()).is_pending());
        lab.run_until_idle();
        assert!(poll_once(race.as_mut()).is_pending());
        assert!(!owner.inner.read().cancel_acknowledged);
        assert_eq!(owner.inner.read().mask_depth, 1);
        for release in &releases {
            release.release();
        }
        let report = completed(&mut lab, race.as_mut());
        assert!(matches!(&report.stop, ScopedRaceAllStop::Cancelled(actual) if actual == &reason));
        assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
        for (index, attempt) in report.attempts.iter().enumerate() {
            assert_closed(attempt, root);
            assert!(matches!(
                &attempt.task,
                ScopedRaceTask::Joined(Ok((actual_index, actual_reason)))
                    if *actual_index == index && actual_reason == &reason
            ));
        }
        assert!(!owner.inner.read().cancel_acknowledged);
        assert_eq!(owner.inner.read().mask_depth, 1);
    });
    assert_eq!(owner.inner.read().mask_depth, 0);
    drop(race);
    finish_fixture(&mut lab, root, &owner_gate);
}

mod native {
    use super::*;
    use crate::channel::oneshot;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use crate::sync::Notify;
    use std::time::Duration;

    #[derive(Default)]
    struct Witness {
        parked: AtomicBool,
        cleaning: AtomicBool,
        finished: AtomicBool,
        retired: AtomicBool,
        changed: Notify,
    }

    impl Witness {
        fn note(&self, flag: &AtomicBool) {
            flag.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }

        async fn wait(&self, ready: impl Fn(&Self) -> bool) {
            self.changed.wait_until(|| ready(self)).await;
        }
    }

    struct Retire(Arc<Witness>);

    impl Drop for Retire {
        fn drop(&mut self) {
            self.0.note(&self.0.retired);
        }
    }

    async fn child_cleanup(
        cx: Cx,
        seen: Arc<Witness>,
        mut release: oneshot::Receiver<()>,
        expected: CancelKind,
    ) {
        let _retire = Retire(Arc::clone(&seen));
        {
            let mut cancelled = pin!(cx.cancelled());
            poll_fn(|task| {
                let progress = cancelled.as_mut().poll(task);
                if progress.is_pending() && !seen.parked.load(Ordering::Acquire) {
                    seen.note(&seen.parked);
                }
                progress
            })
            .await;
        }
        assert!(cx.checkpoint().is_err());
        assert_eq!(cx.cancel_reason().unwrap().kind, expected);
        {
            let mut cleanup = pin!(release.recv_uninterruptible());
            poll_fn(|task| {
                let progress = cleanup.as_mut().poll(task);
                if progress.is_pending() && !seen.cleaning.load(Ordering::Acquire) {
                    seen.note(&seen.cleaning);
                }
                progress
            })
            .await
            .expect("controller releases witnessed cleanup");
        }
        seen.note(&seen.finished);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Case {
        Selected,
        AbortAfterSelection,
        AbortBeforeSelection,
    }

    async fn scenario(owner: Cx, case: Case) {
        const BRANCHES: usize = 4;
        const WINNER: usize = 2;
        let witnesses: Arc<Vec<_>> = Arc::new(
            (0..BRANCHES)
                .map(|_| Arc::new(Witness::default()))
                .collect(),
        );
        let (releases, receivers): (Vec<_>, Vec<_>) =
            (0..BRANCHES).map(|_| oneshot::channel()).unzip();
        let observed = Arc::clone(&witnesses);
        let mut racing = owner
            .spawn(move |race_owner| async move {
                let factories = receivers
                    .into_iter()
                    .enumerate()
                    .map(|(index, cleanup)| {
                        let observed = Arc::clone(&observed);
                        move |body: Cx| async move {
                            let seen = Arc::clone(&observed[index]);
                            let expected = if case == Case::AbortBeforeSelection {
                                CancelKind::Shutdown
                            } else if index == WINNER {
                                CancelKind::User
                            } else {
                                CancelKind::RaceLost
                            };
                            let mut child = body
                                .spawn(move |child| child_cleanup(child, seen, cleanup, expected))
                                .unwrap();
                            if index == WINNER && case != Case::AbortBeforeSelection {
                                for seen in observed.iter() {
                                    seen.wait(|state| state.parked.load(Ordering::Acquire))
                                        .await;
                                }
                                // The winning body returns while its descendant stays
                                // parked. Ownership must survive this ordinary handle drop.
                                drop(child);
                            } else {
                                // This join can finish only if the race cancels the
                                // descendant region before joining the direct body.
                                child.join(&body).await.unwrap();
                                assert!(body.checkpoint().is_err());
                            }
                            index
                        }
                    })
                    .collect();
                let report = race_owner.race_all_scoped(factories).await.unwrap();
                if case != Case::Selected {
                    assert!(race_owner.checkpoint().is_err());
                }
                report
            })
            .unwrap();

        let reason = CancelReason::shutdown()
            .with_cause(CancelReason::user("native dynamic race owner abort"));
        if case == Case::AbortBeforeSelection {
            for seen in witnesses.iter() {
                seen.wait(|state| state.parked.load(Ordering::Acquire))
                    .await;
            }
            racing.abort_with_reason(reason.clone());
        }
        for seen in witnesses.iter() {
            seen.wait(|state| state.cleaning.load(Ordering::Acquire))
                .await;
            assert!(!seen.finished.load(Ordering::Acquire));
            assert!(!seen.retired.load(Ordering::Acquire));
        }
        assert!(
            !racing.terminal_published(),
            "all four cleanup operations are parked"
        );
        if case == Case::AbortAfterSelection {
            // All children reached cancellation and then a second Pending, so
            // selection is committed before the native TaskHandle abort.
            racing.abort_with_reason(reason.clone());
        }
        for release in releases {
            release.send_blocking(()).unwrap();
        }
        let report = racing
            .join(&owner)
            .await
            .expect("full acknowledged race receipt");
        if case == Case::AbortBeforeSelection {
            assert!(
                matches!(&report.stop, ScopedRaceAllStop::Cancelled(actual) if actual == &reason)
            );
        } else {
            assert!(matches!(
                report.stop,
                ScopedRaceAllStop::Winner { index: WINNER }
            ));
        }
        if case == Case::Selected {
            assert!(report.owner_cancellation.is_none());
        } else {
            assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
        }
        assert_eq!(report.attempts.len(), BRANCHES);
        let mut regions = std::collections::HashSet::new();
        for (index, attempt) in report.attempts.iter().enumerate() {
            assert_closed(attempt, owner.region_id());
            assert!(regions.insert(attempt.region_id.unwrap()));
            assert!(matches!(&attempt.task, ScopedRaceTask::Joined(Ok(value)) if *value == index));
            let close = attempt.close.as_ref().unwrap().as_ref().unwrap();
            assert!(close.descendant_panic.is_none());
            assert!(
                close
                    .cleanup_outcome
                    .as_ref()
                    .is_none_or(|outcome| outcome.is_ok())
            );
            assert!(witnesses[index].finished.load(Ordering::Acquire));
            assert!(witnesses[index].retired.load(Ordering::Acquire));
        }
        assert!(!owner.is_cancel_requested());
        assert!(owner.timer_driver().unwrap().is_empty());
    }

    fn native(case: Case) {
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("scoped-race-all-native".to_owned())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    for workers in [1, 2] {
                        for sharded in [false, true] {
                            let builder = if workers == 1 {
                                RuntimeBuilder::current_thread()
                            } else {
                                RuntimeBuilder::new().worker_threads(workers)
                            };
                            let runtime = builder.with_sharded_state(sharded).build().unwrap();
                            runtime.block_on(async {
                                let root = Cx::current().unwrap();
                                let mut owner =
                                    root.spawn(move |owner| scenario(owner, case)).unwrap();
                                owner.join(&root).await.unwrap();
                            });
                            let drain = runtime.shutdown_drained(Duration::from_secs(5));
                            assert_eq!(
                                drain.outcome,
                                RootDrainOutcome::Quiescent,
                                "workers={workers}, sharded={sharded}: {drain:?}"
                            );
                            assert_eq!(drain.live_tasks, 0, "{drain:?}");
                            assert_eq!(drain.live_regions, 0, "{drain:?}");
                            assert_eq!(drain.pending_spawns, 0, "{drain:?}");
                            assert_eq!(drain.pending_obligations, 0, "{drain:?}");
                            assert_eq!(drain.queued_finalizers, 0, "{drain:?}");
                            assert!(!drain.has_pending_obligation_posts, "{drain:?}");
                            assert!(runtime.is_quiescent());
                            assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
                        }
                    }
                }));
                let _ = send.send(result);
            })
            .unwrap();
        // A failure watchdog only. The production cancellation and cleanup
        // futures provide the readiness witnesses used by each scenario.
        let result = receive
            .recv_timeout(Duration::from_secs(45))
            .expect("dynamic native race must retire all owned work");
        thread.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn scoped_race_all_native_drains_winner_and_plain_joining_loser_descendants() {
        native(Case::Selected);
    }

    #[test]
    fn scoped_race_all_native_late_abort_preserves_selected_winner_and_all_receipts() {
        native(Case::AbortAfterSelection);
    }

    #[test]
    fn scoped_race_all_native_abort_of_parked_owner_drains_all_four_subtrees() {
        native(Case::AbortBeforeSelection);
    }
}
