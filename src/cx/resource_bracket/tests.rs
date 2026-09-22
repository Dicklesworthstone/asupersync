#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::oneshot;
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::yield_now;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

fn run_case<F, Fut, T>(factory: F) -> T
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0xb4_ac01).max_steps(16384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("registered bracket test owner")).await
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    let result = join.try_join().unwrap().expect("test completed within lab step bound");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::shutdown(), None).into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
    result
}

async fn wait_count(counter: &AtomicUsize, expected: usize) {
    for _ in 0..512 {
        if counter.load(Ordering::SeqCst) == expected { return; }
        yield_now().await;
    }
    assert_eq!(counter.load(Ordering::SeqCst), expected);
}

// Deliberately neither Clone nor Sync.
#[derive(Debug)]
struct Resource(Cell<u32>);

fn use_resource(_: Cx, resource: &mut Resource) -> BracketUseFuture<'_, u32, &'static str> {
    Box::pin(async move {
        yield_now().await;
        resource.0.set(resource.0.get() + 1);
        Outcome::Ok(resource.0.get())
    })
}

#[test]
fn single_non_clone_send_only_resource_reaches_async_release() {
    run_case(|cx| async move {
        let releases = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&releases);
        let mut handle = cx.spawn_bracket(BracketConfig::new(8),
            |_| async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(41))) },
            use_resource,
            move |_: Cx, resource: Resource| async move {
                yield_now().await;
                assert_eq!(resource.0.get(), 42);
                observed.fetch_add(1, Ordering::SeqCst);
                Outcome::<(), &'static str>::Ok(())
            }).unwrap();
        let report = handle.join().await.unwrap();
        assert!(report.is_success(), "{report:?}");
        assert!(matches!(report.usage.unwrap().outcome, Outcome::Ok(42)));
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn absent_runtime_refuses_before_acquisition() {
    let cx = Cx::for_testing();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let result = cx.spawn_bracket(BracketConfig::new(0), move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(0))) }
    }, use_resource, |_, _| async { Outcome::<(), ()>::Ok(()) });
    assert!(matches!(result, Err(SpawnError::RuntimeUnavailable)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_acquisition_invokes_neither_use_nor_release() {
    run_case(|cx| async move {
        let mut handle = cx.spawn_bracket(BracketConfig::new(0),
            |_| async { Outcome::<Resource, _>::Err("acquire failed") },
            |_, _| -> BracketUseFuture<'_, (), &'static str> { panic!("use must not run") },
            |_, _| -> std::future::Ready<Outcome<(), ()>> { panic!("release must not run") },
        ).unwrap();
        let report = handle.join().await.unwrap();
        assert!(matches!(report.acquisition.as_ref().unwrap().outcome, Outcome::Err("acquire failed")));
        assert!(report.usage.is_none());
        assert!(report.release.is_none());
        assert!(report.close.as_ref().unwrap().is_ok());
        assert!(!report.is_success());
    });
}

#[test]
fn use_error_and_cleanup_error_are_both_retained() {
    run_case(|cx| async move {
        let mut handle = cx.spawn_bracket(BracketConfig::new(4),
            |_| async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(0))) },
            |_, _| -> BracketUseFuture<'_, (), &'static str> {
                Box::pin(async { Outcome::Err("original operation failure") })
            },
            |_, _| async { Outcome::<(), _>::Err(String::from("cleanup failure")) },
        ).unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.is_success());
        assert!(matches!(&report.usage.unwrap().outcome, Outcome::Err("original operation failure")));
        assert!(matches!(&report.release.unwrap().outcome, Outcome::Err(error) if error == "cleanup failure"));
    });
}

#[test]
fn use_factory_and_poll_panics_still_release_once() {
    for factory_panic in [true, false] {
        run_case(move |cx| async move {
            let releases = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&releases);
            let mut handle = cx.spawn_bracket(BracketConfig::new(4),
                |_| async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(0))) },
                move |_, _| -> BracketUseFuture<'_, (), &'static str> {
                    assert!(!factory_panic, "use factory panic");
                    Box::pin(async { panic!("use poll panic") })
                },
                move |_, _| async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Outcome::<(), ()>::Ok(())
                },
            ).unwrap();
            let report = handle.join().await.unwrap();
            assert!(report.usage.as_ref().unwrap().outcome.is_panicked());
            assert!(report.release.as_ref().unwrap().is_success());
            assert_eq!(releases.load(Ordering::SeqCst), 1);
            assert!(!report.is_success());
        });
    }
}

struct AcquireRetirementPanic(Option<Resource>);
impl Future for AcquireRetirementPanic {
    type Output = Outcome<Resource, &'static str>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Outcome::Ok(self.0.take().unwrap()))
    }
}
impl Drop for AcquireRetirementPanic {
    fn drop(&mut self) { panic!("acquire future retirement panic"); }
}

#[test]
fn acquired_value_survives_acquire_future_destructor_panic() {
    run_case(|cx| async move {
        let released = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&released);
        let mut handle = cx.spawn_bracket(BracketConfig::new(4),
            |_| AcquireRetirementPanic(Some(Resource(Cell::new(19)))),
            |_, _| -> BracketUseFuture<'_, (), &'static str> { panic!("unsafe use after acquire panic") },
            move |_, resource: Resource| async move {
                observed.store(resource.0.get() as usize, Ordering::SeqCst);
                Outcome::<(), ()>::Ok(())
            },
        ).unwrap();
        let report = handle.join().await.unwrap();
        assert!(report.acquisition.as_ref().unwrap().outcome.is_ok());
        assert!(report.acquisition.as_ref().unwrap().retirement_panic.is_some());
        assert!(report.usage.is_none());
        assert!(report.release.as_ref().unwrap().is_success());
        assert_eq!(released.load(Ordering::SeqCst), 19);
        assert!(!report.is_success());
    });
}

#[test]
fn acquisition_returning_after_cancel_skips_use_but_releases_its_resource() {
    run_case(|cx| async move {
        let (started, mut started_rx) = oneshot::channel();
        let mut handle = cx.spawn_bracket(BracketConfig::new(8),
            move |acquire_cx| async move {
                started.send_blocking(()).unwrap();
                acquire_cx.cancelled().await;
                Outcome::<_, &'static str>::Ok(Resource(Cell::new(7)))
            },
            |_, _| -> BracketUseFuture<'_, (), &'static str> { panic!("cancelled use must not start") },
            |release_cx, resource: Resource| async move {
                assert!(release_cx.checkpoint().is_ok(), "release has an explicit mask");
                assert_eq!(resource.0.get(), 7);
                yield_now().await;
                Outcome::<(), ()>::Ok(())
            },
        ).unwrap();
        started_rx.recv(&cx).await.unwrap();
        handle.abort();
        let report = handle.join().await.unwrap();
        assert!(report.acquisition.as_ref().unwrap().is_success());
        assert!(report.usage.as_ref().unwrap().outcome.is_cancelled());
        assert!(report.release.as_ref().unwrap().is_success());
        assert!(report.cancellation.is_some());
        assert!(!report.is_success());
    });
}

#[test]
fn dropped_join_waits_resume_the_same_parked_cleanup() {
    run_case(|cx| async move {
        let (release, mut gate) = oneshot::channel();
        let parked = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&parked);
        let mut handle = cx.spawn_bracket(BracketConfig::new(4),
            |_| async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(0))) }, use_resource,
            move |_, _| async move {
                poll_fn(|task_cx| match gate.poll_recv_uninterruptible(task_cx) {
                    Poll::Pending => { observed.store(1, Ordering::SeqCst); Poll::Pending }
                    Poll::Ready(result) => Poll::Ready(result.unwrap()),
                }).await;
                observed.store(2, Ordering::SeqCst);
                Outcome::<(), ()>::Ok(())
            },
        ).unwrap();
        wait_count(&parked, 1).await;
        for _ in 0..4 {
            let mut join = std::pin::pin!(handle.join());
            assert!(join.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert_eq!(parked.load(Ordering::SeqCst), 1);
        release.send_blocking(()).unwrap();
        let report = handle.join().await.unwrap();
        assert!(report.is_success());
        assert_eq!(parked.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn release_mask_exhaustion_unmasks_without_dropping_cleanup() {
    let cx = Cx::for_testing();
    cx.cancel_with(crate::types::CancelKind::User, Some("mask budget test"));
    let history = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&history);
    let release_cx = cx.clone();
    let result = futures_lite::future::block_on(evaluate(|| poll_fn(move |task_cx| {
        let active = release_cx.checkpoint().is_ok();
        observed.lock().push(active);
        if active {
            task_cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Outcome::<(), ()>::Cancelled(cancel_reason(&release_cx)))
        }
    }), Some((&cx, 2))));
    assert_eq!(*history.lock(), [true, true, false]);
    assert!(result.outcome.is_cancelled());
    assert!(result.retirement_panic.is_none());
    assert!(cx.checkpoint().is_err(), "mask never escapes a poll");
}

#[test]
fn cancellation_before_first_poll_never_acquires_a_resource() {
    run_case(|cx| async move {
        let acquisitions = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&acquisitions);
        let mut handle = cx.spawn_bracket(BracketConfig::new(4), move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(0))) }
        }, use_resource, |_, _| async { Outcome::<(), ()>::Ok(()) }).unwrap();
        handle.abort(); // No yield: the lab has not admitted/polled the controller.
        // The controller can publish its cleanup report even when its task
        // terminal is cancellation. Joining retains that report, rather than
        // discarding it behind an outer JoinError.
        let report = handle.join().await.expect("cancelled controller retained its report");
        assert!(matches!(report.controller_task, Err(JoinError::Cancelled(_))));
        assert!(report.cancellation.is_some());
        assert!(!report.is_success());
        assert!(report.acquisition.is_none());
        assert!(report.usage.is_none());
        assert!(report.release.is_none());
        assert!(report.unreleased.is_none());
        assert!(matches!(report.close, Some(Ok(_))));
        assert_eq!(acquisitions.load(Ordering::SeqCst), 0);
    });
}

struct UseRetirementPanic;
impl Future for UseRetirementPanic {
    type Output = Outcome<u32, &'static str>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Outcome::Ok(73))
    }
}
impl Drop for UseRetirementPanic {
    fn drop(&mut self) { panic!("use retirement panic"); }
}

#[test]
fn use_return_value_and_retirement_panic_both_survive_cleanup() {
    run_case(|cx| async move {
        let mut handle = cx.spawn_bracket(BracketConfig::new(4),
            |_| async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(0))) },
            |_, _| -> BracketUseFuture<'_, u32, &'static str> { Box::pin(UseRetirementPanic) },
            |_, _| async { Outcome::<(), ()>::Ok(()) },
        ).unwrap();
        let report = handle.join().await.unwrap();
        assert!(matches!(report.usage.as_ref().unwrap().outcome, Outcome::Ok(73)));
        assert!(report.usage.as_ref().unwrap().retirement_panic.is_some());
        assert!(report.release.as_ref().unwrap().is_success());
        assert!(!report.is_success());
    });
}

struct ReleasePanic { poll_panic: bool, drop_panic: bool }
impl Future for ReleasePanic {
    type Output = Outcome<(), &'static str>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(!self.poll_panic, "release poll panic");
        Poll::Ready(Outcome::Ok(()))
    }
}
impl Drop for ReleasePanic {
    fn drop(&mut self) { assert!(!self.drop_panic, "release retirement panic"); }
}

#[test]
fn release_factory_poll_and_retirement_failures_never_erase_work() {
    for stage in 0..3 {
        run_case(move |cx| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let mut handle = cx.spawn_bracket(BracketConfig::new(4),
                |_| async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(41))) },
                use_resource,
                move |_, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    assert_ne!(stage, 0, "release factory panic");
                    ReleasePanic { poll_panic: stage == 1, drop_panic: stage == 2 }
                },
            ).unwrap();
            let report = handle.join().await.unwrap();
            assert!(matches!(report.usage.as_ref().unwrap().outcome, Outcome::Ok(42)));
            let release = report.release.as_ref().unwrap();
            assert_eq!(release.outcome.is_panicked(), stage != 2);
            assert_eq!(release.retirement_panic.is_some(), stage == 2);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!report.is_success());
        });
    }
}

#[test]
fn release_waits_for_nested_region_finalizers_even_when_they_fail() {
    for fail_cleanup in [false, true] {
        let mut lab = LabRuntime::new(LabConfig::new(0xb4_ac02).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let handle_slot = Arc::new(Mutex::new(None));
        let publication = Arc::clone(&handle_slot);
        let nested_slot = Arc::new(Mutex::new(None));
        let nested_publication = Arc::clone(&nested_slot);
        let (finish_use, mut use_gate) = oneshot::channel();
        let (finish_finalizer, mut finalizer_gate) = oneshot::channel();
        let finalizer_state = Arc::new(AtomicUsize::new(0));
        let state = Arc::clone(&finalizer_state);
        let released = Arc::new(AtomicUsize::new(0));
        let released_value = Arc::clone(&released);
        let finalizer_observed = Arc::clone(&finalizer_state);
        let (parent, mut parent_join) = lab.state.create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            let handle = cx.spawn_bracket(BracketConfig::new(8),
                |_| async { Outcome::<_, &'static str>::Ok(Resource(Cell::new(9))) },
                move |use_cx, resource: &mut Resource| -> BracketUseFuture<'_, (), &'static str> {
                    Box::pin(async move {
                        let nested = use_cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                        *nested_publication.lock() = Some(nested.region_id());
                        use_gate.recv_uninterruptible().await.unwrap();
                        resource.0.set(10);
                        // Drop requests close; it cannot skip the registered finalizer.
                        drop(nested);
                        Outcome::Ok(())
                    })
                },
                move |_, resource: Resource| async move {
                    assert_eq!(finalizer_observed.load(Ordering::SeqCst), 2,
                        "release must follow the nested finalizer, not just the use task");
                    released_value.store(resource.0.get() as usize, Ordering::SeqCst);
                    Outcome::<(), ()>::Ok(())
                },
            ).unwrap();
            *publication.lock() = Some(handle);
        }).unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(parent_join.try_join().unwrap().is_some());
        let nested = nested_slot.lock().expect("use reached the nested region before the gate");
        assert!(lab.state.register_async_finalizer(nested, async move {
            poll_fn(|cx| match finalizer_gate.poll_recv_uninterruptible(cx) {
                Poll::Pending => { state.store(1, Ordering::SeqCst); Poll::Pending }
                Poll::Ready(result) => Poll::Ready(result.unwrap()),
            }).await;
            state.store(2, Ordering::SeqCst);
            assert!(!fail_cleanup, "nested finalizer failure sentinel");
        }));
        let mut handle = handle_slot.lock().take().unwrap();
        finish_use.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_eq!(finalizer_state.load(Ordering::SeqCst), 1);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        {
            let mut joining = std::pin::pin!(handle.join());
            assert!(joining.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        finish_finalizer.send_blocking(()).unwrap();
        lab.run_until_idle();
        let report = {
            let mut joining = std::pin::pin!(handle.join());
            match joining.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(result) => result.unwrap(),
                Poll::Pending => panic!("released bracket must have an actual terminal report"),
            }
        };
        assert_eq!(released.load(Ordering::SeqCst), 10);
        assert!(lab.state.region(nested).is_none());
        assert!(report.release.as_ref().unwrap().is_success());
        assert_eq!(report.is_success(), !fail_cleanup);
        if fail_cleanup {
            let close = report.close.as_ref().unwrap().as_ref().unwrap();
            assert!(close.outcome.is_panicked()
                || close.cleanup_outcome.as_ref().is_some_and(|outcome| outcome.is_panicked()));
        }
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::shutdown(), None).into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
        assert!(lab.state.region(root).is_none());
    }
}

#[test]
fn aggregate_descendant_panic_cannot_be_reported_as_bracket_success() {
    let mut report = BracketReport::<(), (), (), ()>::empty();
    report.acquisition = Some(BracketPhase { outcome: Outcome::Ok(()), retirement_panic: None });
    report.usage = Some(BracketPhase { outcome: Outcome::Ok(()), retirement_panic: None });
    report.release = Some(BracketPhase { outcome: Outcome::Ok(()), retirement_panic: None });
    report.body_task = Some(Ok(()));
    report.close = Some(Ok(BracketRegionOutcome {
        outcome: Outcome::Panicked(PanicPayload::new("descendant failed")), cleanup_outcome: None,
    }));
    assert!(!report.is_success());
}

#[test]
fn legacy_inline_drop_is_a_negative_control_for_externally_woken_release() {
    let (send, mut gate) = oneshot::channel::<()>();
    let completed = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&completed);
    let mut bracket = Box::pin(crate::combinator::bracket::bracket(
        async { Ok::<(), ()>(()) },
        |()| std::future::pending::<Result<(), ()>>(),
        move |()| async move {
            gate.recv_uninterruptible().await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
        },
    ));
    assert!(bracket.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    let failure = catch_unwind(AssertUnwindSafe(|| drop(bracket))).unwrap_err();
    assert_eq!(failure.downcast_ref::<&str>(),
        Some(&"bracket release future did not complete within drop-time cleanup poll budget"));
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    assert!(send.is_closed(), "legacy Drop retired the uncompleted release future");
}
