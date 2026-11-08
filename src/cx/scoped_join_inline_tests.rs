use super::*;
use crate::cx::{ChildRegionSpec, RaceFactory};
use crate::lab::{LabConfig, LabRuntime};
use crate::record::region::{RegionLimits, RegionState};
use crate::runtime::spawn_mailbox::SpawnRequestParts;
use crate::runtime::state::SpawnAdmission;
use crate::types::{Budget, Outcome};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Waker;

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
        if self.0.open.load(Ordering::SeqCst) { Poll::Ready(()) } else { Poll::Pending }
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn fixture(seed: u64) -> (LabRuntime, Cx, RegionId, Gate) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(10_000));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let gate = Gate::default();
    let (task, _join) = lab.state.create_task(root, Budget::INFINITE, gate.clone()).unwrap();
    let owner = lab.state.task(task).unwrap().cx.clone().unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    (lab, owner, root, gate)
}

fn finish(lab: &mut LabRuntime, root: RegionId, gate: Gate) {
    gate.release();
    lab.run_until_idle();
    lab.state.close_region_command(root, &CancelReason::user("scoped join test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn complete<T, F>(lab: &mut LabRuntime, mut future: Pin<&mut F>) -> T
where
    F: Future<Output = Result<T, ScopedJoinError>>,
{
    for _ in 0..64 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected scoped join refusal: {error}"),
            Poll::Pending => { lab.run_until_idle(); }
        }
    }
    panic!("scoped join did not finish within bounded lab turns");
}

fn assert_closed<T>(lab: &LabRuntime, attempt: &ScopedJoinAttempt<T>) {
    let region = attempt.region_id.expect("private operation region admitted");
    assert!(matches!(&attempt.close, Some(Ok(_))), "region close must have actual evidence");
    assert!(lab.state.region(region).is_none(), "reported private region still exists");
}

fn admit(lab: &mut LabRuntime, parts: SpawnRequestParts) {
    let SpawnAdmission::Admitted {
        task_id, priority, cancel_publication, spawn_effects,
    } = lab.state.admit_spawn_request(parts) else {
        panic!("expected authoritative admission");
    };
    let (wakes, observer) = cancel_publication.publish_with_spawn_effects(spawn_effects, |cancel_priority| {
        if let Some(priority) = cancel_priority {
            lab.scheduler.lock().schedule_cancel(task_id, priority);
        } else {
            lab.scheduler.lock().schedule(task_id, priority);
        }
    });
    if let Some(observer) = observer { observer.dispatch(); }
    wakes.dispatch();
}

#[test]
fn scoped_join_empty_missing_runtime_and_oversized_inputs_never_invoke_factories() {
    let no_runtime = Cx::for_testing();
    let mut empty = Box::pin(no_runtime.join_all_scoped(Vec::<RaceFactory<u8>>::new()));
    let Poll::Ready(Ok(report)) = poll_once(empty.as_mut()) else {
        panic!("empty join needs no runtime");
    };
    assert!(matches!(report.stop, ScopedJoinStop::Completed));
    assert!(report.attempts.is_empty());
    assert!(report.owner_cancellation.is_none());
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let mut missing = Box::pin(no_runtime.join_all_scoped(vec![move |_: Cx| {
        counted.fetch_add(1, Ordering::SeqCst);
        async { 1_u8 }
    }]));
    assert!(matches!(poll_once(missing.as_mut()), Poll::Ready(Err(
        ScopedJoinError::Spawn(SpawnError::RuntimeUnavailable)
    ))));
    let (mut lab, owner, root, gate) = fixture(0x5C_7100);
    let factories: Vec<_> = (0..=MAX_SCOPED_JOIN_BRANCHES).map(|index| {
        let counted = Arc::clone(&calls);
        move |_: Cx| {
            counted.fetch_add(1, Ordering::SeqCst);
            async move { index }
        }
    }).collect();
    let mut oversized = Box::pin(owner.join_all_scoped(factories));
    assert!(matches!(poll_once(oversized.as_mut()), Poll::Ready(Err(
        ScopedJoinError::TooManyBranches { total }
    )) if total == MAX_SCOPED_JOIN_BRANCHES + 1));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    drop(oversized);
    finish(&mut lab, root, gate);
}

#[derive(Debug)]
struct NonCloneValue(usize);

#[test]
fn scoped_join_keeps_input_order_domain_errors_and_both_panic_boundaries_without_fail_fast() {
    let (mut lab, owner, root, gate) = fixture(0x5C_7200);
    let releases: Vec<_> = (0..5).map(|_| Gate::default()).collect();
    let calls = Arc::new(AtomicUsize::new(0));
    let factories: Vec<RaceFactory<Result<NonCloneValue, &'static str>>> = releases.iter()
        .cloned().enumerate().map(|(index, release)| {
            let counted = Arc::clone(&calls);
            Box::new(move |body: Cx| {
                counted.fetch_add(1, Ordering::SeqCst);
                assert_ne!(index, 2, "scoped join factory construction panic");
                Box::pin(async move {
                    release.await;
                    assert!(!body.is_cancel_requested(), "another branch must not cancel this body");
                    assert_ne!(index, 3, "scoped join future polling panic");
                    if index == 1 { Err("typed application failure") } else { Ok(NonCloneValue(index)) }
                }) as Pin<Box<dyn Future<Output = Result<NonCloneValue, &'static str>> + Send>>
            }) as RaceFactory<Result<NonCloneValue, &'static str>>
        }).collect();
    let mut group = Box::pin(owner.join_all_scoped(factories));
    assert!(poll_once(group.as_mut()).is_pending());
    lab.run_until_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    // A constructor panic and later completions must not short-circuit the
    // parked first input, erase errors, or cancel its task before release.
    for index in [4, 1, 3] {
        releases[index].release();
        lab.run_until_idle();
        assert!(poll_once(group.as_mut()).is_pending());
    }
    releases[0].release();
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinStop::Completed));
    assert!(report.owner_cancellation.is_none());
    assert_eq!(report.attempts.iter().map(|attempt| attempt.index).collect::<Vec<_>>(), [0, 1, 2, 3, 4]);
    assert!(matches!(&report.attempts[0].task, ScopedJoinTask::Joined(Ok(Ok(value))) if value.0 == 0));
    assert!(matches!(&report.attempts[1].task, ScopedJoinTask::Joined(Ok(Err("typed application failure")))));
    assert!(matches!(&report.attempts[2].task, ScopedJoinTask::Joined(Err(JoinError::Panicked(payload)))
        if payload.message().contains("factory construction panic")));
    assert!(matches!(&report.attempts[3].task, ScopedJoinTask::Joined(Err(JoinError::Panicked(payload)))
        if payload.message().contains("future polling panic")));
    assert!(matches!(&report.attempts[4].task, ScopedJoinTask::Joined(Ok(Ok(value))) if value.0 == 4));
    for attempt in &report.attempts { assert_closed(&lab, attempt); }
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_unpolled_and_masked_precancelled_calls_start_no_user_work() {
    let (mut lab, owner, root, gate) = fixture(0x5C_7300);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let unpolled = owner.join_all_scoped(vec![move |_: Cx| {
        counted.fetch_add(1, Ordering::SeqCst);
        async { 1_u8 }
    }]);
    drop(unpolled);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    let reason = CancelReason::user("join owner stopped").with_cause(CancelReason::shutdown());
    owner.masked(|| {
        owner.set_cancel_reason(reason.clone());
        let counted = Arc::clone(&calls);
        let mut group = Box::pin(owner.join_all_scoped(vec![move |_: Cx| {
            counted.fetch_add(1, Ordering::SeqCst);
            async { 2_u8 }
        }]));
        let report = complete(&mut lab, group.as_mut());
        assert!(matches!(&report.stop, ScopedJoinStop::Cancelled(actual) if *actual == reason));
        assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
        assert!(matches!(&report.attempts[0].task, ScopedJoinTask::NotStarted));
        assert!(report.attempts[0].region_id.is_none());
        assert!(report.attempts[0].close.is_none());
        assert_eq!(owner.inner.read().mask_depth, 1);
        assert!(!owner.inner.read().cancel_acknowledged);
    });
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    assert!(!owner.inner.read().cancel_acknowledged);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_exact_bound_preserves_spawn_only_capabilities() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    let (mut lab, owner, root, gate) = fixture(0x5C_7400);
    let restricted: Cx<SpawnOnly> = owner.restrict();
    let factories = (0..MAX_SCOPED_JOIN_BRANCHES).map(|index| {
        move |body: Cx<SpawnOnly>| async move {
            assert!(body.capabilities().spawn);
            assert!(!body.capabilities().time);
            assert!(!body.capabilities().io);
            index
        }
    }).collect();
    let mut group = Box::pin(restricted.join_all_scoped(factories));
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinStop::Completed));
    assert_eq!(report.attempts.len(), MAX_SCOPED_JOIN_BRANCHES);
    for (index, attempt) in report.attempts.iter().enumerate() {
        assert!(matches!(&attempt.task, ScopedJoinTask::Joined(Ok(actual)) if *actual == index));
        assert_closed(&lab, attempt);
    }
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_heterogeneous_pair_stays_send_with_non_sync_results() {
    fn assert_send<T: Send>(_: &T) {}

    let (mut lab, owner, root, gate) = fixture(0x5C_7500);
    let mut group = Box::pin(owner.join_scoped(
        |_| async { std::cell::Cell::new(17_u32) },
        |_| async { std::cell::Cell::new(String::from("right typed value")) },
    ));
    assert_send(&group);
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinStop::Completed));
    assert_eq!(report.left.index, 0);
    assert_eq!(report.right.index, 1);
    assert_closed(&lab, &report.left);
    assert_closed(&lab, &report.right);
    assert!(matches!(&report.left.task, ScopedJoinTask::Joined(Ok(value)) if value.get() == 17));
    let ScopedJoinTask::Joined(Ok(value)) = report.right.task else { panic!("right value lost"); };
    assert_eq!(value.into_inner(), "right typed value");
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_partial_admission_refusal_keeps_completed_prefix_and_closes_it() {
    let (mut lab, owner, root, gate) = fixture(0x5C_7600);
    let calls = Arc::new(AtomicUsize::new(0));
    let factories: Vec<_> = (0..2).map(|index| {
        let counted = Arc::clone(&calls);
        move |_: Cx| async move {
            counted.fetch_add(1, Ordering::SeqCst);
            index
        }
    }).collect();
    let mut group = Box::pin(owner.join_all_scoped(factories));
    assert!(poll_once(group.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let first = gateway.mailbox().dequeue().unwrap().into_parts();
    let refused = gateway.mailbox().dequeue().unwrap().into_parts();
    admit(&mut lab, first);
    lab.run_until_idle();
    assert!(poll_once(group.as_mut()).is_pending());
    refused.resolve_failed(SpawnError::RegionAtCapacity { region: root, limit: 1, live: 1 });
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinStop::NotAdmitted { index: 1 }));
    assert!(matches!(&report.attempts[0].task, ScopedJoinTask::Joined(Ok(0))));
    assert_closed(&lab, &report.attempts[0]);
    assert!(matches!(&report.attempts[1].task, ScopedJoinTask::Joined(Err(_))));
    assert!(report.attempts[1].region_id.is_none());
    assert!(report.attempts[1].close.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_strict_region_refusal_never_runs_a_factory_in_the_parent() {
    let (mut lab, owner, root, gate) = fixture(0x5C_7700);
    assert!(lab.state.set_region_limits(root, RegionLimits {
        max_tasks: Some(10), ..RegionLimits::default()
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let mut group = Box::pin(owner.join_all_scoped(vec![move |_: Cx| {
        counted.fetch_add(1, Ordering::SeqCst);
        async { 1_u8 }
    }]));
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinStop::NotAdmitted { index: 0 }));
    assert!(matches!(&report.attempts[0].task, ScopedJoinTask::NotStarted));
    assert!(report.attempts[0].region_id.is_none());
    assert!(report.attempts[0].close.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_drop_before_late_publication_closes_all_pending_regions() {
    let (mut lab, owner, root, gate) = fixture(0x5C_7800);
    let calls = Arc::new(AtomicUsize::new(0));
    let factories: Vec<_> = (0..3).map(|index| {
        let counted = Arc::clone(&calls);
        move |_: Cx| async move {
            counted.fetch_add(1, Ordering::SeqCst);
            index
        }
    }).collect();
    let mut group = Box::pin(owner.join_all_scoped(factories));
    assert!(poll_once(group.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let queued: Vec<_> = (0..3).map(|_| gateway.mailbox().dequeue().unwrap().into_parts()).collect();
    let slots: Vec<_> = queued.iter().map(|parts| {
        Arc::clone(parts.admitted_slot.as_ref().unwrap().branch_region().unwrap())
    }).collect();
    drop(group);
    assert!(slots.iter().all(|slot| slot.close_requested() && slot.get().is_none()));
    for parts in queued { admit(&mut lab, parts); }
    lab.run_until_idle();
    for slot in slots {
        let region = slot.get().expect("late private region publication");
        assert!(region.close_notify().lock().closed);
        assert!(region.close_outcome().is_some());
        assert!(lab.state.region(region.region_id).is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_retains_success_separately_from_descendant_finalizer_failure() {
    let (mut lab, owner, root, gate) = fixture(0x5C_7900);
    let release = Gate::default();
    let body_release = release.clone();
    let child_id = Arc::new(Mutex::new(None));
    let published = Arc::clone(&child_id);
    let mut group = Box::pin(owner.join_scoped(
        move |body| async move {
            let child = body.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
            *published.lock() = Some(child.region_id());
            body_release.await;
            drop(child);
            7_u8
        },
        |_| async { "other success" },
    ));
    assert!(poll_once(group.as_mut()).is_pending());
    lab.run_until_idle();
    let child = child_id.lock().expect("descendant region published");
    assert!(lab.state.register_sync_finalizer(child, || panic!("join descendant finalizer failed")));
    release.release();
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinStop::Completed));
    assert!(matches!(&report.left.task, ScopedJoinTask::Joined(Ok(7))));
    assert!(matches!(&report.right.task, ScopedJoinTask::Joined(Ok("other success"))));
    assert_closed(&lab, &report.left);
    assert_closed(&lab, &report.right);
    let close = report.left.close.as_ref().unwrap().as_ref().unwrap();
    assert!(matches!(&close.cleanup_outcome, Some(Outcome::Panicked(payload))
        if payload.message() == "join descendant finalizer failed"));
    assert!(close.descendant_panic.is_some());
    assert!(lab.state.region(child).is_none());
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_join_completed_bodies_keep_their_results_during_late_owner_cancel_and_close() {
    let (mut lab, owner, root, gate) = fixture(0x5C_7A00);
    let release_body = Gate::default();
    let release_finalizer = Gate::default();
    let body_release = release_body.clone();
    let finalizer_release = release_finalizer.clone();
    let finalizer_started = Arc::new(AtomicBool::new(false));
    let observed_finalizer = Arc::clone(&finalizer_started);
    let child_id = Arc::new(Mutex::new(None));
    let published = Arc::clone(&child_id);
    let mut group = Box::pin(owner.join_all_scoped(vec![move |body: Cx| async move {
        let child = body.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        *published.lock() = Some(child.region_id());
        body_release.await;
        drop(child);
        29_u8
    }]));
    assert!(poll_once(group.as_mut()).is_pending());
    lab.run_until_idle();
    let child = child_id.lock().expect("descendant region published");
    assert!(lab.state.register_async_finalizer(child, async move {
        observed_finalizer.store(true, Ordering::SeqCst);
        finalizer_release.await;
    }));
    release_body.release();
    lab.run_until_idle();
    assert!(poll_once(group.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(finalizer_started.load(Ordering::SeqCst));
    owner.set_cancel_reason(CancelReason::user("owner stopped after join bodies completed"));
    assert!(poll_once(group.as_mut()).is_pending());
    lab.run_until_idle();
    let reason = CancelReason::shutdown().with_message("stronger join cleanup reason");
    owner.set_cancel_reason(reason.clone());
    assert!(poll_once(group.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(!owner.inner.read().cancel_acknowledged);
    release_finalizer.release();
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedJoinStop::Completed));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert!(matches!(&report.attempts[0].task, ScopedJoinTask::Joined(Ok(29))));
    assert_closed(&lab, &report.attempts[0]);
    assert!(!owner.inner.read().cancel_acknowledged);
    drop(group);
    finish(&mut lab, root, gate);
}
