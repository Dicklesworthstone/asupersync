use super::*;
use crate::cx::{ChildRegionSpec, RaceFactory};
use crate::lab::{LabConfig, LabRuntime};
use crate::record::RegionLimits;
use crate::record::region::RegionState;
use crate::runtime::state::SpawnAdmission;
use crate::types::Budget;
use parking_lot::Mutex;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};

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

async fn parked_until_cancelled(cx: &Cx, parked: Gate) {
    let mut parked = Some(parked);
    let mut cancelled = std::pin::pin!(cx.cancelled());
    poll_fn(|task| match cancelled.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if let Some(parked) = parked.take() {
                parked.release();
            }
            Poll::Pending
        }
    })
    .await;
    assert!(cx.checkpoint().is_err());
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

fn finish_fixture(lab: &mut LabRuntime, root: RegionId, owner_gate: &Gate) {
    owner_gate.release();
    lab.run_until_idle();
    lab.state
        .close_region_command(root, &CancelReason::user("test complete"));
    lab.run_until_idle();
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.state.region(root).is_none());
}

fn drive<T: std::fmt::Debug, E: std::fmt::Debug, F>(
    lab: &mut LabRuntime,
    mut future: Pin<&mut F>,
) -> ScopedFirstOkReport<T, E>
where
    F: Future<Output = Result<ScopedFirstOkReport<T, E>, ScopedFirstOkError>>,
{
    for _ in 0..128 {
        match poll_once(future.as_mut()) {
            Poll::Ready(Ok(report)) => return report,
            Poll::Ready(Err(error)) => panic!("unexpected scoped fallback refusal: {error}"),
            Poll::Pending => {
                lab.run_until_idle();
            }
        }
    }
    panic!("scoped fallback did not complete after its gates were released");
}

fn fake_gateway(lab: &mut LabRuntime, owner: Cx, life: &Arc<()>) -> Cx {
    let original = owner.spawn_gateway_handle().unwrap();
    let gateway = Arc::new(SpawnGateway::new(
        Arc::clone(original.mailbox()),
        Arc::new(|| {}),
        owner.timer_driver(),
        Arc::downgrade(life),
    ));
    lab.state.set_spawn_gateway(Arc::clone(&gateway));
    owner.with_spawn_gateway(Some(gateway))
}

#[test]
fn scoped_first_ok_preserves_ordered_errors_and_short_circuits_after_success() {
    for selected in [None, Some(0), Some(2)] {
        let (mut lab, owner, root, owner_gate) = fixture(0x5F_0100 + selected.unwrap_or(4));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let factories = (0..4).map(|index| {
            let calls = Arc::clone(&calls);
            move |_body| async move {
                calls.lock().push(index);
                if selected == Some(index) {
                    Ok(index + 10)
                } else {
                    Err(index)
                }
            }
        });
        let mut chain = Box::pin(owner.first_ok_scoped(factories));
        let report = drive(&mut lab, chain.as_mut());
        let expected = selected.map_or(4, |index| index + 1) as usize;
        assert_eq!(report.attempts.len(), expected);
        assert_eq!(*calls.lock(), (0..expected as u64).collect::<Vec<_>>());
        match selected {
            Some(index) => assert!(matches!(
                report.stop,
                ScopedFirstOkStop::Succeeded { index: actual } if actual == index as usize
            )),
            None => assert!(matches!(report.stop, ScopedFirstOkStop::AllFailed)),
        }
        for (index, attempt) in report.attempts.iter().enumerate() {
            assert_eq!(attempt.index, index);
            assert!(attempt.region_id.is_some());
            assert_ne!(attempt.region_id, Some(root));
            assert!(lab.state.region(attempt.region_id.unwrap()).is_none());
            let close = attempt.close.as_ref().unwrap().as_ref().unwrap();
            assert!(!cleanup_failed(&attempt.close));
            assert!(close.descendant_panic.is_none());
            if selected == Some(index as u64) {
                assert!(
                    matches!(&attempt.task, ScopedFirstOkTask::Joined(Ok(Ok(value))) if *value == index as u64 + 10)
                );
            } else {
                assert!(
                    matches!(&attempt.task, ScopedFirstOkTask::Joined(Ok(Err(error))) if *error == index as u64)
                );
            }
        }
        assert!(!owner.is_cancel_requested());
        assert_eq!(lab.state.live_task_count(), 1);
        drop(chain);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_first_ok_never_pulls_unused_generator_tail_or_precancelled_input() {
    for precancelled in [false, true] {
        let (mut lab, owner, root, owner_gate) = fixture(0x5F_0200 + u64::from(precancelled));
        let pulled = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&pulled);
        let factories = std::iter::from_fn(move || {
            let index = calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                index, 0,
                "the unbounded generator's tail must remain untouched"
            );
            Some(|_: Cx| std::future::ready(Ok::<_, &'static str>(42)))
        });
        let reason = CancelReason::user("already stopped").with_cause(CancelReason::shutdown());
        if precancelled {
            owner.set_cancel_reason(reason.clone());
        }
        let mut chain = Box::pin(owner.first_ok_scoped(factories));
        let report = drive(&mut lab, chain.as_mut());
        assert_eq!(pulled.load(Ordering::SeqCst), usize::from(!precancelled));
        if precancelled {
            assert!(
                matches!(report.stop, ScopedFirstOkStop::Cancelled(actual) if actual == reason)
            );
            assert!(report.attempts.is_empty());
        } else {
            assert!(matches!(
                report.stop,
                ScopedFirstOkStop::Succeeded { index: 0 }
            ));
            assert_eq!(report.attempts.len(), 1);
        }
        drop(chain);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_first_ok_empty_needs_no_runtime_and_missing_runtime_invokes_nothing() {
    let owner = Cx::for_testing();
    let mut empty = Box::pin(owner.first_ok_scoped(Vec::<RaceFactory<Result<(), ()>>>::new()));
    let Poll::Ready(Ok(report)) = poll_once(empty.as_mut()) else {
        panic!("empty input needs no runtime");
    };
    assert!(matches!(report.stop, ScopedFirstOkStop::Empty));
    assert!(report.attempts.is_empty());

    let called = Arc::new(AtomicBool::new(false));
    let calls = Arc::clone(&called);
    let mut unavailable = Box::pin(owner.first_ok_scoped([move |_| {
        calls.store(true, Ordering::SeqCst);
        std::future::ready(Ok::<_, ()>(()))
    }]));
    assert!(matches!(
        poll_once(unavailable.as_mut()),
        Poll::Ready(Err(ScopedFirstOkError::Spawn(
            SpawnError::RuntimeUnavailable
        )))
    ));
    assert!(!called.load(Ordering::SeqCst));
}

#[test]
fn scoped_first_ok_drains_grandchild_and_finalizer_before_pulling_fallback() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5F_0300);
    let cleanup_gate = Gate::default();
    let grandchild_gate = cleanup_gate.clone();
    let cleanup_started = Arc::new(AtomicBool::new(false));
    let grandchild_started = Arc::clone(&cleanup_started);
    let cleaned = Arc::new(AtomicBool::new(false));
    let grandchild_cleaned = Arc::clone(&cleaned);
    let finalized = Arc::new(AtomicBool::new(false));
    let finalizer_ran = Arc::clone(&finalized);
    let ids = Arc::new(Mutex::new(None));
    let published = Arc::clone(&ids);
    let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
        Box::pin(async move {
            let started = Gate::default();
            let grandchild_parked = started.clone();
            let attempt_region = body.region_id();
            let _child = body
                .spawn(move |child| async move {
                    let region = child
                        .open_child_region(ChildRegionSpec::inherit())
                        .await
                        .unwrap();
                    let child_region = region.region_id();
                    let mut grandchild = region
                        .cx()
                        .spawn(move |leaf| async move {
                            *published.lock() = Some((attempt_region, child_region));
                            parked_until_cancelled(&leaf, grandchild_parked).await;
                            grandchild_started.store(true, Ordering::SeqCst);
                            grandchild_gate.await;
                            grandchild_cleaned.store(true, Ordering::SeqCst);
                        })
                        .unwrap();
                    let _ = grandchild.join(&child).await;
                    region.close().await.unwrap();
                })
                .unwrap();
            started.await;
            Err("primary failed")
        })
    });
    let fallback_called = Arc::new(AtomicBool::new(false));
    let next_called = Arc::clone(&fallback_called);
    let next: RaceFactory<Result<usize, &'static str>> = Box::new(move |_| {
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(finalized.load(Ordering::SeqCst));
        next_called.store(true, Ordering::SeqCst);
        Box::pin(async { Ok(42) })
    });
    let pulled = Arc::new(AtomicUsize::new(0));
    let pull_count = Arc::clone(&pulled);
    let factories = vec![first, next].into_iter().inspect(move |_| {
        pull_count.fetch_add(1, Ordering::SeqCst);
    });
    let mut chain = Box::pin(owner.first_ok_scoped(factories));
    assert!(poll_once(chain.as_mut()).is_pending());
    lab.run_until_idle();
    let (attempt_region, child_region) = ids.lock().expect("real grandchild was polled");
    assert!(lab.state.register_sync_finalizer(attempt_region, move || {
        finalizer_ran.store(true, Ordering::SeqCst);
    }));
    assert!(poll_once(chain.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(cleanup_started.load(Ordering::SeqCst));
    assert!(!fallback_called.load(Ordering::SeqCst));
    assert_eq!(pulled.load(Ordering::SeqCst), 1);
    assert!(poll_once(chain.as_mut()).is_pending());
    assert!(lab.state.region(attempt_region).is_some());
    cleanup_gate.release();
    let report = drive(&mut lab, chain.as_mut());
    assert!(matches!(
        report.stop,
        ScopedFirstOkStop::Succeeded { index: 1 }
    ));
    assert_eq!(report.attempts.len(), 2);
    assert!(fallback_called.load(Ordering::SeqCst));
    assert_eq!(pulled.load(Ordering::SeqCst), 2);
    assert!(lab.state.region(attempt_region).is_none());
    assert!(lab.state.region(child_region).is_none());
    assert!(matches!(
        report.attempts[0].task,
        ScopedFirstOkTask::Joined(Ok(Err("primary failed")))
    ));
    assert_eq!(lab.state.regions_len(), 1);
    drop(chain);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_first_ok_owner_cancel_during_cleanup_preserves_selection_and_blocks_fallback() {
    for succeeded in [false, true] {
        let (mut lab, owner, root, owner_gate) = fixture(0x5F_0400 + u64::from(succeeded));
        let release = Gate::default();
        let child_release = release.clone();
        let cleanup = Arc::new(AtomicBool::new(false));
        let child_cleanup = Arc::clone(&cleanup);
        let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
            Box::pin(async move {
                let started = Gate::default();
                let child_parked = started.clone();
                let _child = body
                    .spawn(move |child| async move {
                        parked_until_cancelled(&child, child_parked).await;
                        child_cleanup.store(true, Ordering::SeqCst);
                        child_release.await;
                    })
                    .unwrap();
                started.await;
                if succeeded {
                    Ok(42)
                } else {
                    Err("failed before owner cancellation")
                }
            })
        });
        let next: RaceFactory<Result<usize, &'static str>> = Box::new(|_| {
            panic!("owner cancellation forbids another factory");
        });
        let mut chain = Box::pin(owner.first_ok_scoped(vec![first, next]));
        assert!(poll_once(chain.as_mut()).is_pending());
        lab.run_until_idle();
        assert!(poll_once(chain.as_mut()).is_pending());
        lab.run_until_idle();
        assert!(cleanup.load(Ordering::SeqCst));
        let reason =
            CancelReason::user("cancel during cleanup").with_cause(CancelReason::shutdown());
        owner.set_cancel_reason(reason.clone());
        assert!(poll_once(chain.as_mut()).is_pending());
        release.release();
        let report = drive(&mut lab, chain.as_mut());
        assert_eq!(report.attempts.len(), 1);
        if succeeded {
            assert!(matches!(
                report.stop,
                ScopedFirstOkStop::Succeeded { index: 0 }
            ));
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::Joined(Ok(Ok(42)))
            ));
        } else {
            assert!(
                matches!(report.stop, ScopedFirstOkStop::Cancelled(actual) if actual == reason)
            );
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::Joined(Ok(Err("failed before owner cancellation")))
            ));
        }
        assert!(!cleanup_failed(&report.attempts[0].close));
        assert!(!owner.inner.read().cancel_acknowledged);
        drop(chain);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_first_ok_masked_owner_cancellation_preserves_acknowledged_late_result() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5F_0500);
    let cleanup_gate = Gate::default();
    let body_gate = cleanup_gate.clone();
    let cleanup = Arc::new(AtomicBool::new(false));
    let body_cleanup = Arc::clone(&cleanup);
    let mut chain = Box::pin(owner.first_ok_scoped([move |body: Cx| async move {
        body.cancelled().await;
        assert!(body.checkpoint().is_err());
        body_cleanup.store(true, Ordering::SeqCst);
        body_gate.await;
        Ok::<_, &'static str>(73)
    }]));
    assert!(poll_once(chain.as_mut()).is_pending());
    lab.run_until_idle();
    let reason = CancelReason::user("masked owner stopped").with_cause(CancelReason::shutdown());
    owner.masked(|| {
        owner.set_cancel_reason(reason.clone());
        assert!(poll_once(chain.as_mut()).is_pending());
        lab.run_until_idle();
        assert!(cleanup.load(Ordering::SeqCst));
        assert!(poll_once(chain.as_mut()).is_pending());
        cleanup_gate.release();
        let report = drive(&mut lab, chain.as_mut());
        assert!(matches!(report.stop, ScopedFirstOkStop::Cancelled(actual) if actual == reason));
        assert!(matches!(
            report.attempts[0].task,
            ScopedFirstOkTask::Joined(Ok(Ok(73)))
        ));
        assert!(!cleanup_failed(&report.attempts[0].close));
        assert_eq!(owner.inner.read().mask_depth, 1);
        assert!(!owner.inner.read().cancel_acknowledged);
    });
    assert_eq!(owner.inner.read().mask_depth, 0);
    drop(chain);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_first_ok_drops_unused_factory_resources_before_joining_or_closing_selected_attempt() {
    struct ReleaseOnDrop(Gate);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    for cancelled in [false, true] {
        let (mut lab, owner, root, owner_gate) = fixture(0x5F_0550 + u64::from(cancelled));
        let release = Gate::default();
        let held_by_unused_factory = ReleaseOnDrop(release.clone());
        let cleaned = Arc::new(AtomicBool::new(false));
        let child_cleaned = Arc::clone(&cleaned);
        let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
            Box::pin(async move {
                let parked = Gate::default();
                let child_parked = parked.clone();
                let mut child = body
                    .spawn(move |child| async move {
                        parked_until_cancelled(&child, child_parked).await;
                        release.await;
                        child_cleaned.store(true, Ordering::SeqCst);
                    })
                    .unwrap();
                parked.await;
                if cancelled {
                    body.cancelled().await;
                    assert!(body.checkpoint().is_err());
                    poll_fn(|task| child.poll_join(task)).await.unwrap();
                }
                Ok(73)
            })
        });
        let unused: RaceFactory<Result<usize, &'static str>> = Box::new(move |_| {
            drop(held_by_unused_factory);
            panic!("the unused factory must be dropped without invocation");
        });
        let mut chain = Box::pin(owner.first_ok_scoped(vec![first, unused]));
        assert!(poll_once(chain.as_mut()).is_pending());
        lab.run_until_idle();
        if cancelled {
            owner.set_cancel_reason(CancelReason::shutdown());
        }
        let report = drive(&mut lab, chain.as_mut());
        if cancelled {
            assert!(matches!(report.stop, ScopedFirstOkStop::Cancelled(_)));
        } else {
            assert!(matches!(
                report.stop,
                ScopedFirstOkStop::Succeeded { index: 0 }
            ));
        }
        assert!(matches!(
            report.attempts[0].task,
            ScopedFirstOkTask::Joined(Ok(Ok(73)))
        ));
        assert!(!cleanup_failed(&report.attempts[0].close));
        assert!(cleaned.load(Ordering::SeqCst));
        drop(chain);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_first_ok_refuses_parent_fallback_and_retains_async_admission_failure() {
    for limit in [1, 10] {
        let (mut lab, owner, root, owner_gate) = fixture(0x5F_0600 + limit as u64);
        assert!(lab.state.set_region_limits(
            root,
            RegionLimits {
                max_tasks: Some(limit),
                ..RegionLimits::default()
            }
        ));
        let called = Arc::new(AtomicBool::new(false));
        let calls = Arc::clone(&called);
        let mut chain = Box::pin(owner.first_ok_scoped([move |_| {
            calls.store(true, Ordering::SeqCst);
            std::future::ready(Ok::<_, ()>(42))
        }]));
        let report = drive(&mut lab, chain.as_mut());
        assert!(matches!(
            report.stop,
            ScopedFirstOkStop::NotAdmitted { index: 0 }
        ));
        assert_eq!(report.attempts.len(), 1);
        assert!(report.attempts[0].region_id.is_none());
        assert!(report.attempts[0].close.is_none());
        if limit == 1 {
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::Joined(Err(JoinError::Cancelled(_)))
            ));
        } else {
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::NotStarted
            ));
        }
        assert!(!called.load(Ordering::SeqCst));
        assert!(!owner.is_cancel_requested());
        assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
        drop(chain);
        finish_fixture(&mut lab, root, &owner_gate);
    }
}

#[test]
fn scoped_first_ok_later_submission_failure_keeps_previous_typed_error() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5F_0700);
    let life = Arc::new(());
    let owner = fake_gateway(&mut lab, owner, &life);
    let release = Gate::default();
    let body_release = release.clone();
    let context = Arc::new(Mutex::new(None));
    let published = Arc::clone(&context);
    let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
        Box::pin(async move {
            *published.lock() = Some(body.region_id());
            body_release.await;
            Err("preserve this error")
        })
    });
    let next: RaceFactory<Result<usize, &'static str>> = Box::new(|_| {
        panic!("dead runtime cannot invoke the next factory");
    });
    let mut chain = Box::pin(owner.first_ok_scoped(vec![first, next]));
    assert!(poll_once(chain.as_mut()).is_pending());
    lab.run_until_idle();
    let region = context.lock().expect("first body started");
    assert!(
        lab.state
            .register_sync_finalizer(region, move || drop(life))
    );
    release.release();
    let report = drive(&mut lab, chain.as_mut());
    assert!(matches!(
        report.stop,
        ScopedFirstOkStop::NotAdmitted { index: 1 }
    ));
    assert_eq!(report.attempts.len(), 2);
    assert!(matches!(
        report.attempts[0].task,
        ScopedFirstOkTask::Joined(Ok(Err("preserve this error")))
    ));
    assert!(!cleanup_failed(&report.attempts[0].close));
    assert!(matches!(
        report.attempts[1].task,
        ScopedFirstOkTask::SubmissionFailed(SpawnError::RuntimeUnavailable)
    ));
    assert!(report.attempts[1].region_id.is_none());
    drop(chain);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_first_ok_close_unavailable_stops_fallback_without_losing_body_error() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5F_0800);
    let life = Arc::new(());
    let owner = fake_gateway(&mut lab, owner, &life);
    let release = Gate::default();
    let child_release = release.clone();
    let cleanup = Arc::new(AtomicBool::new(false));
    let child_cleanup = Arc::clone(&cleanup);
    let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
        Box::pin(async move {
            let started = Gate::default();
            let child_parked = started.clone();
            let _child = body
                .spawn(move |child| async move {
                    parked_until_cancelled(&child, child_parked).await;
                    child_cleanup.store(true, Ordering::SeqCst);
                    child_release.await;
                })
                .unwrap();
            started.await;
            Err("body error before runtime loss")
        })
    });
    let next: RaceFactory<Result<usize, &'static str>> = Box::new(|_| {
        panic!("uncertain cleanup cannot start a fallback");
    });
    let mut chain = Box::pin(owner.first_ok_scoped(vec![first, next]));
    assert!(poll_once(chain.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(poll_once(chain.as_mut()).is_pending());
    lab.run_until_idle();
    assert!(cleanup.load(Ordering::SeqCst));
    drop(life);
    let Poll::Ready(Ok(report)) = poll_once(chain.as_mut()) else {
        panic!("vanished runtime must return a close error");
    };
    assert!(matches!(
        report.stop,
        ScopedFirstOkStop::CleanupFailed { index: 0 }
    ));
    assert_eq!(report.attempts.len(), 1);
    assert!(matches!(
        report.attempts[0].task,
        ScopedFirstOkTask::Joined(Ok(Err("body error before runtime loss")))
    ));
    assert!(matches!(
        report.attempts[0].close,
        Some(Err(ChildRegionError::RuntimeUnavailable))
    ));
    let region = report.attempts[0].region_id.unwrap();
    assert!(
        lab.state.region(region).is_some(),
        "an error does not certify quiescence"
    );
    release.release();
    lab.run_until_idle();
    assert!(
        lab.state.region(region).is_none(),
        "the runtime still owns eventual cleanup"
    );
    drop(chain);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_first_ok_body_panic_and_descendant_finalizer_panic_are_independent_facts() {
    for succeeded in [false, true] {
        let (mut lab, owner, root, owner_gate) = fixture(0x5F_0900 + u64::from(succeeded));
        let release = Gate::default();
        let body_release = release.clone();
        let context = Arc::new(Mutex::new(None));
        let published = Arc::clone(&context);
        let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
            Box::pin(async move {
                let child = body
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                *published.lock() = Some(child.region_id());
                body_release.await;
                drop(child);
                if succeeded {
                    Ok(42)
                } else {
                    Err("body returned an error")
                }
            })
        });
        let next: RaceFactory<Result<usize, &'static str>> = Box::new(|_| {
            panic!("cleanup panic must not start a fallback");
        });
        let mut chain = Box::pin(owner.first_ok_scoped(vec![first, next]));
        assert!(poll_once(chain.as_mut()).is_pending());
        lab.run_until_idle();
        let child = context.lock().expect("descendant region opened");
        assert!(lab.state.register_sync_finalizer(child, || {
            panic!("descendant finalizer failed");
        }));
        release.release();
        let report = drive(&mut lab, chain.as_mut());
        assert_eq!(report.attempts.len(), 1);
        if succeeded {
            assert!(matches!(
                report.stop,
                ScopedFirstOkStop::Succeeded { index: 0 }
            ));
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::Joined(Ok(Ok(42)))
            ));
        } else {
            assert!(matches!(
                report.stop,
                ScopedFirstOkStop::CleanupFailed { index: 0 }
            ));
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::Joined(Ok(Err("body returned an error")))
            ));
        }
        let close = report.attempts[0].close.as_ref().unwrap().as_ref().unwrap();
        assert!(
            matches!(&close.cleanup_outcome, Some(Outcome::Panicked(payload)) if payload.message() == "descendant finalizer failed")
        );
        assert!(close.descendant_panic.is_some());
        assert!(lab.state.region(child).is_none());
        drop(chain);
        finish_fixture(&mut lab, root, &owner_gate);
    }

    let (mut lab, owner, root, owner_gate) = fixture(0x5F_0902);
    let mut chain = Box::pin(owner.first_ok_scoped((0..2).map(|index| {
        move |_| async move {
            assert_eq!(index, 0, "a body panic must stop the chain");
            panic!("attempt body failed");
            #[allow(unreachable_code)]
            Ok::<usize, ()>(0)
        }
    })));
    let report = drive(&mut lab, chain.as_mut());
    assert!(matches!(
        report.stop,
        ScopedFirstOkStop::TaskFailed { index: 0 }
    ));
    assert_eq!(report.attempts.len(), 1);
    assert!(
        matches!(&report.attempts[0].task, ScopedFirstOkTask::Joined(Err(JoinError::Panicked(payload))) if payload.message() == "attempt body failed")
    );
    drop(chain);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_first_ok_drop_before_late_admission_closes_region_and_invokes_no_factory() {
    let (mut lab, owner, root, owner_gate) = fixture(0x5F_0A00);
    let unused = owner.first_ok_scoped([|_: Cx| async {
        panic!("unpolled fallback cannot invoke user code");
        #[allow(unreachable_code)]
        Ok::<usize, ()>(0)
    }]);
    drop(unused);
    assert_eq!(owner.pending_spawn_counter_handle().unwrap().count(), 0);
    let called = Arc::new(AtomicBool::new(false));
    let calls = Arc::clone(&called);
    let mut chain = Box::pin(owner.first_ok_scoped([move |_| {
        calls.store(true, Ordering::SeqCst);
        std::future::ready(Ok::<_, ()>(42))
    }]));
    assert!(poll_once(chain.as_mut()).is_pending());
    let gateway = owner.spawn_gateway_handle().unwrap();
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
    drop(chain);
    assert!(slot.close_requested());
    let SpawnAdmission::Admitted {
        task_id,
        priority,
        cancel_publication,
        spawn_effects,
    } = lab.state.admit_spawn_request(parts)
    else {
        panic!("the dequeued request must reach late publication");
    };
    let region = slot.get().unwrap().region_id;
    let close = Arc::clone(slot.get().unwrap().close_notify());
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
    lab.run_until_idle();
    assert!(!called.load(Ordering::SeqCst));
    assert!(close.lock().closed);
    assert!(slot.get().unwrap().close_outcome().is_some());
    assert!(lab.state.region(region).is_none());
    assert_eq!(lab.state.region(root).unwrap().state(), RegionState::Open);
    finish_fixture(&mut lab, root, &owner_gate);
}

#[test]
fn scoped_first_ok_preserves_spawn_only_capability_and_nonclone_nonunpin_results() {
    type SpawnOnly = cap::CapSet<true, false, false, false, false>;
    #[derive(Debug)]
    struct Value(usize, std::marker::PhantomPinned);

    let (mut lab, owner, root, owner_gate) = fixture(0x5F_0B00);
    let restricted: Cx<SpawnOnly> = owner.restrict();
    let factories = (0..2).map(|index| {
        move |body: Cx<SpawnOnly>| async move {
            assert!(!body.capabilities().time);
            assert!(!body.capabilities().io);
            let mut child = body
                .spawn(move |child: Cx<SpawnOnly>| async move {
                    assert!(!child.capabilities().time);
                    Value(index, std::marker::PhantomPinned)
                })
                .unwrap();
            let value = poll_fn(|task| child.poll_join(task)).await.unwrap();
            if index == 0 { Err(value) } else { Ok(value) }
        }
    });
    let mut chain = Box::pin(restricted.first_ok_scoped(factories));
    let report = drive(&mut lab, chain.as_mut());
    assert!(matches!(
        report.stop,
        ScopedFirstOkStop::Succeeded { index: 1 }
    ));
    assert!(matches!(
        &report.attempts[0].task,
        ScopedFirstOkTask::Joined(Ok(Err(Value(0, _))))
    ));
    assert!(matches!(
        &report.attempts[1].task,
        ScopedFirstOkTask::Joined(Ok(Ok(Value(1, _))))
    ));
    assert!(owner.timer_driver().unwrap().is_empty());
    drop(chain);
    finish_fixture(&mut lab, root, &owner_gate);
}

mod native {
    use super::*;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::sync::mpsc;
    use std::time::Duration;

    fn run<F, Fut>(test: F)
    where
        F: Fn(Cx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let test = Arc::new(test);
                for (current_thread, sharded) in
                    [(true, false), (true, true), (false, false), (false, true)]
                {
                    let builder = if current_thread {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::multi_thread().worker_threads(2)
                    };
                    let runtime = builder.with_sharded_state(sharded).build().unwrap();
                    let test = Arc::clone(&test);
                    runtime.block_on(runtime.handle().spawn(async move {
                        test(Cx::current().expect("runtime task context")).await;
                    }));
                    let report = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                    assert_eq!(report.live_tasks, 0);
                    assert_eq!(report.pending_spawns, 0);
                    assert_eq!(report.pending_obligations, 0);
                }
            }));
            let _ = send.send(result);
        });
        let result = receive
            .recv_timeout(Duration::from_secs(45))
            .expect("scoped fallback must finish its native subtree drain");
        worker.join().unwrap();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn scoped_first_ok_native_fallback_waits_for_genuinely_parked_descendant_cleanup() {
        run(|cx| async move {
            let release = Gate::default();
            let child_release = release.clone();
            let mut cleanup_entered = Gate::default();
            let child_entered = cleanup_entered.clone();
            let cleaned = Arc::new(AtomicBool::new(false));
            let child_cleaned = Arc::clone(&cleaned);
            let called = Arc::new(AtomicBool::new(false));
            let next_called = Arc::clone(&called);
            let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
                Box::pin(async move {
                    let parked = Gate::default();
                    let descendant_parked = parked.clone();
                    let _child = body
                        .spawn(move |child| async move {
                            let region = child
                                .open_child_region(ChildRegionSpec::inherit())
                                .await
                                .unwrap();
                            let mut descendant = region
                                .cx()
                                .spawn(move |descendant| async move {
                                    parked_until_cancelled(&descendant, descendant_parked).await;
                                    child_entered.release();
                                    child_release.await;
                                    child_cleaned.store(true, Ordering::SeqCst);
                                })
                                .unwrap();
                            let _ = descendant.join(&child).await;
                            region.close().await.unwrap();
                        })
                        .unwrap();
                    parked.await;
                    Err("primary failed")
                })
            });
            let next: RaceFactory<Result<usize, &'static str>> = Box::new(move |_| {
                assert!(
                    cleaned.load(Ordering::SeqCst),
                    "fallback waits for descendant cleanup"
                );
                next_called.store(true, Ordering::SeqCst);
                Box::pin(async { Ok(42) })
            });
            let mut chain = Box::pin(cx.first_ok_scoped(vec![first, next]));
            poll_fn(|task| {
                assert!(
                    chain.as_mut().poll(task).is_pending(),
                    "cleanup is still gated"
                );
                Pin::new(&mut cleanup_entered).poll(task)
            })
            .await;
            assert!(!called.load(Ordering::SeqCst));
            assert!(!cx.is_cancel_requested());
            release.release();
            let report = chain.await.unwrap();
            assert!(matches!(
                report.stop,
                ScopedFirstOkStop::Succeeded { index: 1 }
            ));
            assert_eq!(report.attempts.len(), 2);
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::Joined(Ok(Err("primary failed")))
            ));
            assert!(matches!(
                report.attempts[1].task,
                ScopedFirstOkTask::Joined(Ok(Ok(42)))
            ));
            assert!(
                report
                    .attempts
                    .iter()
                    .all(|attempt| !cleanup_failed(&attempt.close))
            );
            assert!(called.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn scoped_first_ok_native_owner_cancel_wakes_body_and_descendant_then_keeps_late_value() {
        run(|cx| async move {
            let mut body_parked = Gate::default();
            let parked_body = body_parked.clone();
            let mut cleanup_entered = Gate::default();
            let child_entered = cleanup_entered.clone();
            let release = Gate::default();
            let child_release = release.clone();
            let cleaned = Arc::new(AtomicBool::new(false));
            let child_cleaned = Arc::clone(&cleaned);
            let first: RaceFactory<Result<usize, &'static str>> = Box::new(move |body| {
                Box::pin(async move {
                    let child_parked = Gate::default();
                    let parked_child = child_parked.clone();
                    let mut child = body
                        .spawn(move |child| async move {
                            parked_until_cancelled(&child, parked_child).await;
                            child_entered.release();
                            child_release.await;
                            child_cleaned.store(true, Ordering::SeqCst);
                        })
                        .unwrap();
                    child_parked.await;
                    parked_until_cancelled(&body, parked_body).await;
                    // A direct-task-only cancel would deadlock here: the child
                    // must also receive cancellation and finish its protocol drain.
                    poll_fn(|task| child.poll_join(task)).await.unwrap();
                    Ok(73)
                })
            });
            let next: RaceFactory<Result<usize, &'static str>> = Box::new(|_| {
                panic!("owner cancellation must not invoke another factory");
            });
            let mut chain = Box::pin(cx.first_ok_scoped(vec![first, next]));
            poll_fn(|task| {
                assert!(chain.as_mut().poll(task).is_pending());
                Pin::new(&mut body_parked).poll(task)
            })
            .await;
            let reason = CancelReason::user("native fallback owner stopped")
                .with_cause(CancelReason::shutdown());
            cx.set_cancel_reason(reason.clone());
            poll_fn(|task| {
                assert!(
                    chain.as_mut().poll(task).is_pending(),
                    "child cleanup is still gated"
                );
                Pin::new(&mut cleanup_entered).poll(task)
            })
            .await;
            assert!(!cleaned.load(Ordering::SeqCst));
            assert!(!cx.inner.read().cancel_acknowledged);
            release.release();
            let report = chain.await.unwrap();
            assert!(
                matches!(report.stop, ScopedFirstOkStop::Cancelled(actual) if actual == reason)
            );
            assert_eq!(report.attempts.len(), 1);
            assert!(matches!(
                report.attempts[0].task,
                ScopedFirstOkTask::Joined(Ok(Ok(73)))
            ));
            assert!(!cleanup_failed(&report.attempts[0].close));
            assert!(cleaned.load(Ordering::SeqCst));
            assert!(!cx.inner.read().cancel_acknowledged);
            // Acknowledgement belongs to the caller, after examining receipts.
            assert!(cx.checkpoint().is_err());
        });
    }
}
