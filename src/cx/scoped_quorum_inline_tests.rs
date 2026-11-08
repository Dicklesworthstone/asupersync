use super::*;
use crate::channel::oneshot;
use crate::cx::{ChildRegionSpec, RaceFactory};
use crate::lab::{LabConfig, LabRuntime};
use crate::record::region::{RegionLimits, RegionState};
use crate::runtime::spawn_mailbox::SpawnRequestParts;
use crate::runtime::state::SpawnAdmission;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::types::{Budget, Outcome};
use parking_lot::Mutex;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Context, Waker};
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
        self.0.open.store(true, Ordering::SeqCst);
        if let Some(waker) = self.0.waker.lock().take() {
            waker.wake();
        }
    }
}

impl Future for Gate {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0.open.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        *self.0.waker.lock() = Some(cx.waker().clone());
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

fn finish(lab: &mut LabRuntime, root: RegionId, gate: Gate) {
    gate.release();
    lab.run_until_idle();
    lab.state
        .close_region_command(root, &CancelReason::user("test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn complete<T, E, F>(lab: &mut LabRuntime, mut future: Pin<&mut F>) -> ScopedQuorumReport<T, E>
where
    F: Future<Output = Result<ScopedQuorumReport<T, E>, ScopedQuorumError>>,
{
    for _ in 0..64 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected quorum refusal: {error}"),
            Poll::Pending => {
                lab.run_until_idle();
            }
        }
    }
    panic!("scoped quorum did not complete within bounded lab turns");
}

fn admit(lab: &mut LabRuntime, parts: SpawnRequestParts) {
    let SpawnAdmission::Admitted {
        task_id,
        priority,
        cancel_publication,
        spawn_effects,
    } = lab.state.admit_spawn_request(parts)
    else {
        panic!("expected authoritative admission");
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

#[test]
fn scoped_quorum_validates_bounds_before_invoking_or_submitting_factories() {
    let (mut lab, owner, root, gate) = fixture(0x5C_5100);
    let calls = Arc::new(AtomicUsize::new(0));
    for (required, total) in [(0, 1), (1, 0), (3, 2), (1, 65)] {
        let factories: Vec<RaceFactory<Result<usize, ()>>> = (0..total)
            .map(|index| {
                let called = Arc::clone(&calls);
                Box::new(move |_| {
                    called.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async move { Ok(index) })
                        as Pin<Box<dyn Future<Output = Result<usize, ()>> + Send>>
                }) as RaceFactory<Result<usize, ()>>
            })
            .collect();
        let mut group = Box::pin(owner.quorum_scoped(required, factories));
        assert!(matches!(poll_once(group.as_mut()), Poll::Ready(Err(
            ScopedQuorumError::InvalidQuorum { required: actual, total: count }
        )) if actual == required && count == total));
        assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_quorum_keeps_input_order_ties_errors_and_unselected_successes() {
    let (mut lab, owner, root, gate) = fixture(0x5C_5200);
    let factories: Vec<RaceFactory<Result<usize, &'static str>>> = (0_usize..4)
        .map(|index| {
            Box::new(move |_| {
                Box::pin(async move {
                    if index == 0 {
                        Err("backend unavailable")
                    } else {
                        Ok(index * 10)
                    }
                })
                    as Pin<Box<dyn Future<Output = Result<usize, &'static str>> + Send>>
            }) as RaceFactory<Result<usize, &'static str>>
        })
        .collect();
    let mut group = Box::pin(owner.quorum_scoped(2, factories));
    assert!(poll_once(group.as_mut()).is_pending());
    // All four real bodies publish before the owner scans any candidate.
    lab.run_until_idle();
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedQuorumStop::Satisfied));
    assert_eq!(report.required, 2);
    assert_eq!(report.selected, [1, 2]);
    assert_eq!(report.attempts.len(), 4);
    assert!(matches!(
        report.attempts[0].task,
        ScopedQuorumTask::Joined(Ok(Err("backend unavailable")))
    ));
    assert!(matches!(
        report.attempts[3].task,
        ScopedQuorumTask::Joined(Ok(Ok(30)))
    ));
    let mut regions = std::collections::BTreeSet::new();
    for attempt in &report.attempts {
        let region = attempt.region_id.expect("private branch region");
        assert_ne!(region, root);
        assert!(regions.insert(region));
        assert!(
            matches!(&attempt.close, Some(Ok(close)) if close.cleanup_outcome.is_none() && close.descendant_panic.is_none())
        );
        assert!(lab.state.region(region).is_none());
    }
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_quorum_preserves_spawn_only_caps_and_accepts_the_exact_branch_bound() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    let (mut lab, owner, root, gate) = fixture(0x5C_5300);
    let restricted: Cx<SpawnOnly> = owner.restrict();
    let factories = (0..MAX_SCOPED_QUORUM_BRANCHES)
        .map(|index| {
            move |body: Cx<SpawnOnly>| async move {
                assert!(!body.capabilities().time);
                assert!(!body.capabilities().io);
                Ok::<_, ()>(index)
            }
        })
        .collect();
    let mut group = Box::pin(restricted.quorum_scoped(MAX_SCOPED_QUORUM_BRANCHES, factories));
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedQuorumStop::Satisfied));
    assert_eq!(report.selected.len(), MAX_SCOPED_QUORUM_BRANCHES);
    assert!(
        report
            .attempts
            .iter()
            .all(|attempt| matches!(&attempt.close, Some(Ok(_))))
    );
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_quorum_masked_precancel_keeps_exact_reason_without_starting_work() {
    let (mut lab, owner, root, gate) = fixture(0x5C_5400);
    let reason = CancelReason::user("request abandoned").with_cause(CancelReason::shutdown());
    owner.masked(|| {
        owner.set_cancel_reason(reason.clone());
        let factories = vec![|_: Cx| async {
            panic!("a pre-cancelled quorum must not invoke its factory");
            #[allow(unreachable_code)]
            Ok::<u8, ()>(7)
        }];
        let mut group = Box::pin(owner.quorum_scoped(1, factories));
        let report = complete(&mut lab, group.as_mut());
        assert!(matches!(&report.stop, ScopedQuorumStop::Cancelled(actual) if *actual == reason));
        assert!(report.selected.is_empty());
        assert!(matches!(
            report.attempts[0].task,
            ScopedQuorumTask::NotStarted
        ));
        assert!(report.attempts[0].region_id.is_none());
        assert!(report.attempts[0].close.is_none());
        assert_eq!(owner.inner.read().mask_depth, 1);
        assert!(!owner.inner.read().cancel_acknowledged);
        assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    });
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_quorum_partial_admission_refusal_retains_the_successful_prefix() {
    let (mut lab, owner, root, gate) = fixture(0x5C_5500);
    let calls = Arc::new(AtomicUsize::new(0));
    let factories: Vec<RaceFactory<Result<u8, ()>>> = (0_u8..2)
        .map(|index| {
            let called = Arc::clone(&calls);
            Box::new(move |_| {
                called.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(index) })
                    as Pin<Box<dyn Future<Output = Result<u8, ()>> + Send>>
            }) as RaceFactory<Result<u8, ()>>
        })
        .collect();
    let mut group = Box::pin(owner.quorum_scoped(2, factories));
    assert!(poll_once(group.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let first = gateway.mailbox().dequeue().unwrap().into_parts();
    let refused = gateway.mailbox().dequeue().unwrap().into_parts();
    admit(&mut lab, first);
    lab.run_until_idle();
    assert!(poll_once(group.as_mut()).is_pending());
    // Exercise the real admission-failure publisher after one body succeeded.
    refused.resolve_failed(SpawnError::RegionAtCapacity {
        region: root,
        limit: 1,
        live: 1,
    });
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(
        report.stop,
        ScopedQuorumStop::NotAdmitted { index: 1 }
    ));
    assert_eq!(report.selected, [0]);
    assert!(matches!(
        report.attempts[0].task,
        ScopedQuorumTask::Joined(Ok(Ok(0)))
    ));
    assert!(matches!(&report.attempts[0].close, Some(Ok(_))));
    assert!(matches!(
        report.attempts[1].task,
        ScopedQuorumTask::Joined(Err(_))
    ));
    assert!(report.attempts[1].region_id.is_none());
    assert!(report.attempts[1].close.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_quorum_refuses_parent_placement_without_invoking_a_factory() {
    let (mut lab, owner, root, gate) = fixture(0x5C_5600);
    assert!(lab.state.set_region_limits(
        root,
        RegionLimits {
            max_tasks: Some(10),
            ..RegionLimits::default()
        }
    ));
    let mut group = Box::pin(owner.quorum_scoped(
        1,
        vec![|_: Cx| async {
            panic!("parent-placement fallback must not invoke user work");
            #[allow(unreachable_code)]
            Ok::<u8, ()>(7)
        }],
    ));
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(
        report.stop,
        ScopedQuorumStop::NotAdmitted { index: 0 }
    ));
    assert!(matches!(
        report.attempts[0].task,
        ScopedQuorumTask::NotStarted
    ));
    assert!(report.attempts[0].region_id.is_none());
    assert!(report.attempts[0].close.is_none());
    drop(group);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_quorum_drop_before_late_publication_closes_every_owned_slot() {
    let (mut lab, owner, root, gate) = fixture(0x5C_5700);
    let factories: Vec<RaceFactory<Result<u8, ()>>> = (0..2)
        .map(|_| {
            Box::new(|_| {
                Box::pin(async {
                    panic!("a dropped quorum cannot run late-admitted user work");
                    #[allow(unreachable_code)]
                    Ok::<u8, ()>(7)
                }) as Pin<Box<dyn Future<Output = Result<u8, ()>> + Send>>
            }) as RaceFactory<Result<u8, ()>>
        })
        .collect();
    let mut group = Box::pin(owner.quorum_scoped(1, factories));
    assert!(poll_once(group.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
    let queued: Vec<_> = (0..2)
        .map(|_| gateway.mailbox().dequeue().unwrap().into_parts())
        .collect();
    let slots: Vec<_> = queued
        .iter()
        .map(|parts| {
            Arc::clone(
                parts
                    .admitted_slot
                    .as_ref()
                    .unwrap()
                    .branch_region()
                    .unwrap(),
            )
        })
        .collect();
    drop(group);
    assert!(
        slots
            .iter()
            .all(|slot| slot.close_requested() && slot.get().is_none())
    );
    for parts in queued {
        admit(&mut lab, parts);
    }
    lab.run_until_idle();
    for slot in slots {
        let region = slot
            .get()
            .expect("late admission publishes a private region");
        assert!(region.close_notify().lock().closed);
        assert!(region.close_outcome().is_some());
        assert!(lab.state.region(region.region_id).is_none());
    }
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    finish(&mut lab, root, gate);
}

#[test]
fn scoped_quorum_keeps_selected_success_and_real_descendant_finalizer_panic() {
    let (mut lab, owner, root, gate) = fixture(0x5C_5800);
    let release = Gate::default();
    let body_release = release.clone();
    let child_id = Arc::new(Mutex::new(None));
    let published = Arc::clone(&child_id);
    let mut group = Box::pin(owner.quorum_scoped(
        1,
        vec![move |body: Cx| async move {
            let child = body
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            *published.lock() = Some(child.region_id());
            body_release.await;
            drop(child);
            Ok::<_, ()>(7)
        }],
    ));
    assert!(poll_once(group.as_mut()).is_pending());
    lab.run_until_idle();
    let child = child_id.lock().unwrap();
    assert!(
        lab.state
            .register_sync_finalizer(child, || panic!("quorum descendant cleanup failed"))
    );
    release.release();
    lab.run_until_idle();
    let report = complete(&mut lab, group.as_mut());
    assert!(matches!(report.stop, ScopedQuorumStop::Satisfied));
    assert_eq!(report.selected, [0]);
    assert!(matches!(
        report.attempts[0].task,
        ScopedQuorumTask::Joined(Ok(Ok(7)))
    ));
    let close = report.attempts[0].close.as_ref().unwrap().as_ref().unwrap();
    assert!(
        matches!(&close.cleanup_outcome, Some(Outcome::Panicked(payload)) if payload.message() == "quorum descendant cleanup failed")
    );
    assert!(close.descendant_panic.is_some());
    assert!(lab.state.region(child).is_none());
    drop(group);
    finish(&mut lab, root, gate);
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("native scoped quorum watchdog");
    worker.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

async fn parked(child: &Cx, ready: oneshot::Sender<()>) {
    let mut ready = Some(ready);
    let mut cancellation = pin!(child.cancelled());
    poll_fn(|task| match cancellation.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                ready.send_blocking(()).unwrap();
            }
            Poll::Pending
        }
    })
    .await;
    assert!(child.checkpoint().is_err());
}

#[test]
fn scoped_quorum_native_closes_winner_and_joining_loser_subtrees_before_return() {
    bounded(|| {
        for workers in [1, 2] {
            for sharded in [false, true] {
                for satisfied in [false, true] {
                    let builder = if workers == 1 {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::multi_thread().worker_threads(workers)
                    };
                    let runtime = builder.with_sharded_state(sharded).build().unwrap();
                    runtime.block_on(runtime.handle().spawn(async move {
                        let cx = Cx::current().unwrap();
                        let cleaned = Arc::new(AtomicUsize::new(0));
                        let release_body = Gate::default();
                        let mut releases = Vec::new();
                        let mut ready = Vec::new();
                        let mut draining = Vec::new();
                        let mut factories: Vec<RaceFactory<Result<u8, &'static str>>> = Vec::new();
                        for index in 0..2 {
                            let release = Gate::default();
                            releases.push(release.clone());
                            let (ready_send, ready_receive) = oneshot::channel();
                            ready.push(ready_receive);
                            let (drain_send, drain_receive) = oneshot::channel();
                            draining.push(drain_receive);
                            let count = Arc::clone(&cleaned);
                            let body_release = release_body.clone();
                            factories.push(Box::new(move |body| {
                                Box::pin(async move {
                                    let mut child = body
                                        .spawn(move |child| async move {
                                            parked(&child, ready_send).await;
                                            drain_send.send_blocking(()).unwrap();
                                            release.await;
                                            count.fetch_add(1, Ordering::SeqCst);
                                            99_u8
                                        })
                                        .unwrap();
                                    if index == 0 {
                                        body_release.await;
                                        if satisfied {
                                            Ok(7)
                                        } else {
                                            Err("backend unavailable")
                                        }
                                    } else {
                                        // This task cannot retire until WHOLE-REGION
                                        // cancellation reaches its parked descendant.
                                        let value = child.join(&body).await.unwrap();
                                        assert!(body.checkpoint().is_err());
                                        Ok(value)
                                    }
                                })
                            }));
                        }
                        let mut owner = cx
                            .spawn(move |owner| async move {
                                let report = owner
                                    .quorum_scoped(if satisfied { 1 } else { 2 }, factories)
                                    .await
                                    .unwrap();
                                if owner.is_cancel_requested() {
                                    assert!(owner.checkpoint().is_err());
                                }
                                report
                            })
                            .unwrap();
                        for witness in &mut ready {
                            witness.recv(&cx).await.unwrap();
                        }
                        release_body.release();
                        for witness in &mut draining {
                            witness.recv(&cx).await.unwrap();
                        }
                        assert_eq!(cleaned.load(Ordering::SeqCst), 0);
                        assert!(matches!(owner.try_join(), Ok(None)));
                        // Selection is already fixed; this abort cannot erase it
                        // or release a report while either child is cleaning up.
                        owner.abort_with_reason(CancelReason::shutdown());
                        assert!(matches!(owner.try_join(), Ok(None)));
                        releases[0].release();
                        assert!(matches!(owner.try_join(), Ok(None)));
                        releases[1].release();
                        let report = owner.join(&cx).await.unwrap();
                        if satisfied {
                            assert!(matches!(report.stop, ScopedQuorumStop::Satisfied));
                            assert_eq!(report.selected, [0]);
                            assert!(matches!(
                                report.attempts[0].task,
                                ScopedQuorumTask::Joined(Ok(Ok(7)))
                            ));
                        } else {
                            assert!(matches!(
                                report.stop,
                                ScopedQuorumStop::InsufficientSuccesses
                            ));
                            assert!(report.selected.is_empty());
                            assert!(matches!(
                                report.attempts[0].task,
                                ScopedQuorumTask::Joined(Ok(Err("backend unavailable")))
                            ));
                        }
                        assert!(matches!(
                            report.attempts[1].task,
                            ScopedQuorumTask::Joined(Ok(Ok(99)))
                        ));
                        assert_eq!(cleaned.load(Ordering::SeqCst), 2);
                        assert_ne!(report.attempts[0].region_id, report.attempts[1].region_id);
                        for attempt in report.attempts {
                            assert!(attempt.region_id.is_some());
                            assert_ne!(attempt.region_id, Some(cx.region_id()));
                            let close = attempt.close.unwrap().unwrap();
                            assert!(close.cleanup_outcome.is_none());
                            assert!(close.descendant_panic.is_none());
                        }
                    }));
                    let report = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                    assert_eq!(report.live_tasks, 0);
                    assert_eq!(report.pending_spawns, 0);
                    assert_eq!(report.pending_obligations, 0);
                }
            }
        }
    });
}
