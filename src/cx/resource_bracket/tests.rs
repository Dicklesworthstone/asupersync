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
                let _reason = acquire_cx.cancelled().await;
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
