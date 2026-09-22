use super::*;
use crate::types::CancelKind;
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Wake, Waker};

async fn success(_: Cx, _: u8) -> Outcome<(), &'static str> {
    Outcome::Ok(())
}

#[test]
fn reservation_precedes_acquisition_and_abandoning_it_spends_no_slot() {
    let mut stack = ResourceStack::<&'static str>::new(1);
    drop(stack.reserve().unwrap());
    assert_eq!(stack.entries.len(), 0);
    let key = stack.reserve().unwrap().insert(9, success);
    assert_eq!(stack.get(&key), Some(&9));
    assert!(matches!(stack.reserve(), Err(ResourceStackError::Capacity { limit: 1 })));
    assert!(stack.report.entries.capacity() >= 1);
    let mut empty = ResourceStack::<()>::new(0);
    assert!(matches!(empty.reserve(), Err(ResourceStackError::Capacity { limit: 0 })));
    assert!(futures_lite::future::block_on(empty.close(&Cx::for_testing())).is_success());
}

#[test]
fn refused_insertion_returns_the_exact_resource_and_factory() {
    let mut stack = ResourceStack::<()>::new(0);
    let resource = Box::new(31_u8);
    let address = std::ptr::from_ref(&*resource);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let failure = stack.try_insert(resource, move |_: Cx, value: Box<u8>| async move {
        assert_eq!(*value, 31);
        observed.fetch_add(1, Ordering::SeqCst);
        Outcome::Ok(())
    }).unwrap_err();
    assert_eq!(std::ptr::from_ref(&*failure.resource), address);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(futures_lite::future::block_on((failure.release)(Cx::for_testing(), failure.resource)).is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn heterogeneous_nonclone_resources_are_borrowed_then_released_in_reverse_order() {
    struct OnlySend(Cell<u8>);
    let mut stack = ResourceStack::<&'static str>::new(2);
    let log = Arc::new(Mutex::new(Vec::new()));
    let first_log = Arc::clone(&log);
    let first = stack.try_insert(OnlySend(Cell::new(4)), move |_: Cx, value: OnlySend| async move {
        first_log.lock().unwrap().push(format!("cell:{}", value.0.get()));
        Outcome::Ok(())
    }).unwrap();
    let second_log = Arc::clone(&log);
    let second = stack.try_insert(String::from("hello"), move |_: Cx, value: String| async move {
        second_log.lock().unwrap().push(value);
        Outcome::Ok(())
    }).unwrap();
    stack.get(&first).unwrap().0.set(7);
    stack.get_mut(&second.clone()).unwrap().push_str(" world");
    let report = futures_lite::future::block_on(stack.close(&Cx::for_testing()));
    assert!(report.is_success());
    assert_eq!(report.entries.iter().map(|entry| entry.index).collect::<Vec<_>>(), [1, 0]);
    assert_eq!(*log.lock().unwrap(), ["hello world", "cell:7"]);
    assert!(stack.get(&first).is_none());
    assert!(stack.get_mut(&second).is_none());
}

#[test]
fn keys_never_alias_another_stack_or_reopen_after_close() {
    let mut a = ResourceStack::new(1);
    let mut b = ResourceStack::new(1);
    let ka = a.try_insert(1, success).unwrap();
    let kb = b.try_insert(2, success).unwrap();
    assert_eq!(ka.index(), kb.index());
    assert!(a.get(&kb).is_none());
    assert!(b.get_mut(&ka).is_none());
    let cx = Cx::for_testing();
    assert!(futures_lite::future::block_on(a.close(&cx)).is_success());
    assert!(a.get(&ka).is_none());
    assert_eq!(a.try_insert(3, success).unwrap_err().error, ResourceStackError::Closed);
    assert!(futures_lite::future::block_on(b.close(&cx)).is_success());
}

struct FailsAndPanicsOnDrop;
impl Future for FailsAndPanicsOnDrop {
    type Output = Outcome<(), &'static str>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Outcome::Err("release error"))
    }
}
impl Drop for FailsAndPanicsOnDrop {
    fn drop(&mut self) { panic!("release retirement panic"); }
}

#[test]
fn factory_poll_and_retirement_panics_do_not_skip_older_resources() {
    let mut stack = ResourceStack::new(4);
    stack.try_insert(0, success).unwrap();
    stack.try_insert(1, |_: Cx, _: u8| FailsAndPanicsOnDrop).unwrap();
    stack.try_insert(2, |_: Cx, _: u8| async {
        panic!("release poll panic");
        #[allow(unreachable_code)]
        Outcome::<(), &'static str>::Ok(())
    }).unwrap();
    stack.try_insert(3, |_: Cx, _: u8| -> std::future::Ready<Outcome<(), &'static str>> {
        panic!("release factory panic")
    }).unwrap();
    let report = futures_lite::future::block_on(stack.close(&Cx::for_testing()));
    assert!(report.complete);
    assert!(!report.is_success());
    assert_eq!(report.entries.iter().map(|entry| entry.index).collect::<Vec<_>>(), [3, 2, 1, 0]);
    assert!(matches!(&report.entries[0].phase.outcome, Outcome::Panicked(p) if p.message() == "release factory panic"));
    assert!(matches!(&report.entries[1].phase.outcome, Outcome::Panicked(p) if p.message() == "release poll panic"));
    assert!(matches!(&report.entries[2].phase.outcome, Outcome::Err("release error")));
    assert_eq!(report.entries[2].phase.retirement_panic.as_ref().unwrap().message(), "release retirement panic");
    assert!(report.entries[3].phase.is_success());
}

struct Gated {
    open: Arc<AtomicBool>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl Future for Gated {
    type Output = Outcome<(), &'static str>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.open.load(Ordering::Acquire) { Poll::Ready(Outcome::Ok(())) }
        else { Poll::Pending }
    }
}
impl Drop for Gated {
    fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn dropped_close_wait_retains_the_exact_pending_release_and_lifo_barrier() {
    let mut stack = ResourceStack::<&'static str>::new(2);
    let older = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&older);
    stack.try_insert(1, move |_: Cx, _: u8| async move {
        count.fetch_add(1, Ordering::SeqCst);
        Outcome::Ok(())
    }).unwrap();
    let open = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let gate = Gated { open: Arc::clone(&open), polls: Arc::clone(&polls), drops: Arc::clone(&drops) };
    stack.try_insert(2, move |_: Cx, _: u8| gate).unwrap();
    let cx = Cx::for_testing();
    for attempt in 1..=4 {
        let mut close = Box::pin(stack.close(&cx));
        assert!(close.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        drop(close);
        assert_eq!(polls.load(Ordering::SeqCst), attempt);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(older.load(Ordering::SeqCst), 0);
        assert!(!stack.report().complete);
        assert!(stack.report().entries.is_empty());
        assert!(matches!(stack.reserve(), Err(ResourceStackError::Closed)));
    }
    open.store(true, Ordering::Release);
    assert!(futures_lite::future::block_on(stack.close(&cx)).is_success());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(older.load(Ordering::SeqCst), 1);
    let before = polls.load(Ordering::SeqCst);
    assert!(futures_lite::future::block_on(stack.close(&cx)).is_success());
    assert_eq!(polls.load(Ordering::SeqCst), before);
}

struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn immediately_ready_cleanup_is_bounded_and_requests_a_continuation() {
    let mut stack = ResourceStack::new(33);
    for i in 0..33 { stack.try_insert(i, success).unwrap(); }
    let cx = Cx::for_testing();
    let wake = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake));
    let mut context = Context::from_waker(&waker);
    assert!(stack.poll_close(&cx, &mut context).is_pending());
    assert_eq!(stack.report.entries.len(), 16);
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert!(stack.poll_close(&cx, &mut context).is_pending());
    assert_eq!(stack.report.entries.len(), 32);
    assert_eq!(wake.0.load(Ordering::SeqCst), 2);
    assert!(stack.poll_close(&cx, &mut context).is_ready());
    assert!(stack.report().is_success());
}

#[test]
fn cancellation_is_a_release_outcome_not_permission_to_skip_cleanup() {
    let mut stack = ResourceStack::new(2);
    stack.try_insert(1, success).unwrap();
    stack.try_insert(2, |cx: Cx, _: u8| async move {
        assert!(cx.checkpoint().is_err());
        Outcome::Cancelled(cx.cancel_reason().unwrap())
    }).unwrap();
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let report = futures_lite::future::block_on(stack.close(&cx));
    assert_eq!(report.entries.len(), 2);
    assert!(matches!(report.entries[0].phase.outcome, Outcome::Cancelled(_)));
    assert!(report.entries[1].phase.is_success());
    assert!(report.complete);
    assert!(!report.is_success());
}

#[test]
fn stack_and_keys_support_send_only_resource_and_error_types() {
    fn assert_send<T: Send>() {}
    assert_send::<ResourceStack<Cell<u8>>>();
    assert_send::<ResourceKey<Cell<u8>>>();
    let mut stack = ResourceStack::<Cell<u8>>::new(1);
    let key = stack.try_insert(Cell::new(17), |_: Cx, value: Cell<u8>| async move {
        Outcome::Err(value)
    }).unwrap();
    assert_eq!(stack.get(&key).unwrap().get(), 17);
    let report = futures_lite::future::block_on(stack.close(&Cx::for_testing()));
    assert!(matches!(&report.entries[0].phase.outcome, Outcome::Err(value) if value.get() == 17));
}

#[test]
fn dropping_the_whole_standalone_stack_does_not_claim_async_release() {
    struct Resource(Arc<AtomicUsize>);
    impl Drop for Resource {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut stack = ResourceStack::<()>::new(1);
    stack.try_insert(Resource(Arc::clone(&drops)), move |_: Cx, resource: Resource| async move {
        observed.fetch_add(1, Ordering::SeqCst);
        drop(resource);
        Outcome::Ok(())
    }).unwrap();
    drop(stack);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn acquire_after_cancellation_still_commits_the_reserved_release_owner() {
    let mut stack = ResourceStack::new(1);
    let cx = Cx::for_testing();
    let phase = futures_lite::future::block_on(stack.reserve().unwrap().acquire(
        &cx,
        |cx| async move {
            cx.cancel_fast(CancelKind::User);
            Outcome::<_, &'static str>::Ok(41_u8)
        },
        success,
    ));
    assert!(phase.is_success());
    let Outcome::Ok(key) = phase.outcome else { panic!("returned resource must be owned"); };
    assert_eq!(stack.get(&key), Some(&41));
    assert!(cx.checkpoint().is_err());
    assert!(futures_lite::future::block_on(stack.close(&cx)).is_success());
}

struct AcquireDropPanic(Option<u8>);
impl Future for AcquireDropPanic {
    type Output = Outcome<u8, &'static str>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Outcome::Ok(self.0.take().unwrap()))
    }
}
impl Drop for AcquireDropPanic {
    fn drop(&mut self) { panic!("acquisition retirement failed after returning resource"); }
}

#[test]
fn acquire_retirement_panic_preserves_both_the_key_and_cleanup_owner() {
    let mut stack = ResourceStack::new(1);
    let cx = Cx::for_testing();
    let phase = futures_lite::future::block_on(stack.reserve().unwrap().acquire(
        &cx, |_| AcquireDropPanic(Some(29)), success,
    ));
    assert!(!phase.is_success());
    assert_eq!(phase.retirement_panic.as_ref().unwrap().message(),
        "acquisition retirement failed after returning resource");
    let Outcome::Ok(key) = phase.outcome else { panic!("resource returned despite retirement panic"); };
    assert_eq!(stack.get(&key), Some(&29));
    assert!(futures_lite::future::block_on(stack.close(&cx)).is_success());
    assert_eq!(stack.report().entries.len(), 1);
}

#[test]
fn acquisition_failures_preserve_older_resources_without_installing_phantom_entries() {
    let mut stack = ResourceStack::new(2);
    stack.try_insert(11, success).unwrap();
    let cx = Cx::for_testing();
    let phase = futures_lite::future::block_on(stack.reserve().unwrap().acquire(
        &cx, |_| async { Outcome::<u8, _>::Err("second acquisition failed") }, success,
    ));
    assert!(matches!(phase.outcome, Outcome::Err("second acquisition failed")));
    let phase = futures_lite::future::block_on(stack.reserve().unwrap().acquire(
        &cx, |_| -> std::future::Ready<Outcome<u8, &'static str>> { panic!("acquire factory panic") }, success,
    ));
    assert!(matches!(phase.outcome, Outcome::Panicked(ref p) if p.message() == "acquire factory panic"));
    assert_eq!(stack.entries.len(), 1);
    assert!(futures_lite::future::block_on(stack.close(&cx)).is_success());
    assert_eq!(stack.report().entries.len(), 1);
}

#[test]
fn already_cancelled_acquisition_never_invokes_the_resource_factory() {
    let mut stack = ResourceStack::new(1);
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let phase = futures_lite::future::block_on(stack.reserve().unwrap().acquire(
        &cx,
        |_| -> std::future::Ready<Outcome<u8, &'static str>> { panic!("cancelled factory ran"); },
        success,
    ));
    assert!(matches!(phase.outcome, Outcome::Cancelled(_)));
    assert!(stack.entries.is_empty());
    assert!(futures_lite::future::block_on(stack.close(&cx)).is_success());
}

#[test]
fn dropping_pending_acquisition_does_not_drop_prior_registered_resources() {
    let mut stack = ResourceStack::new(2);
    let key = stack.try_insert(23, success).unwrap();
    let cx = Cx::for_testing();
    let mut acquisition = Box::pin(stack.reserve().unwrap().acquire(
        &cx, |_| std::future::pending::<Outcome<u8, &'static str>>(), success,
    ));
    assert!(acquisition.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(acquisition);
    assert_eq!(stack.get(&key), Some(&23));
    assert_eq!(stack.entries.len(), 1);
    drop(stack.reserve().unwrap());
    assert!(futures_lite::future::block_on(stack.close(&cx)).is_success());
}

#[test]
fn finite_mask_allowance_is_shared_across_the_whole_lifo_release() {
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let history = Arc::new(Mutex::new(Vec::new()));
    let mut stack = ResourceStack::<()>::new(2);
    let old_history = Arc::clone(&history);
    stack.try_insert(0, move |cx: Cx, value| async move {
        old_history.lock().unwrap().push((value, cx.checkpoint().is_ok()));
        Outcome::Ok(())
    }).unwrap();
    let new_history = Arc::clone(&history);
    stack.try_insert(1, move |cx: Cx, value| {
        let mut first = true;
        poll_fn(move |task| {
            new_history.lock().unwrap().push((value, cx.checkpoint().is_ok()));
            if std::mem::take(&mut first) { task.waker().wake_by_ref(); Poll::Pending }
            else { Poll::Ready(Outcome::Ok(())) }
        })
    }).unwrap();
    let phase = futures_lite::future::block_on(evaluate(|| async {
        stack.close(&cx).await;
        Outcome::<(), ()>::Ok(())
    }, Some((&cx, 1))));
    assert!(phase.is_success());
    assert_eq!(*history.lock().unwrap(), [(1, true), (1, false), (0, false)]);
    assert!(stack.report().is_success());
    assert!(cx.checkpoint().is_err());
}

fn run_scope_case<F, Fut>(factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    use crate::lab::{LabConfig, LabRuntime};
    use crate::types::{Budget, CancelReason};
    let mut lab = LabRuntime::new(LabConfig::new(0x5c0f_2026).max_steps(16_384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("admitted scope owner")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    join.try_join().unwrap().expect("scope completed within the lab step bound");
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
}

#[test]
fn resource_scope_refuses_missing_runtime_before_invoking_work() {
    let result = Cx::for_testing().spawn_resource_scope::<(), (), (), _>(
        BracketConfig::new(0), 1, |_, _| { panic!("work must not run without runtime authority"); },
    );
    assert!(matches!(result, Err(SpawnError::RuntimeUnavailable)));
}

#[test]
fn resource_scope_preserves_failed_startup_and_independent_typed_cleanup_errors() {
    run_scope_case(|cx| async move {
        let mut handle = cx.spawn_resource_scope::<(), &'static str, &'static str, _>(
            BracketConfig::new(4), 2,
            |cx, mut scope| Box::pin(async move {
                let first = scope.reserve().unwrap().acquire(
                    &cx, |_| async { Outcome::<_, &'static str>::Ok(Cell::new(6_u8)) },
                    |_, resource| async move {
                        assert_eq!(resource.get(), 7);
                        Outcome::Err("first resource release failed")
                    },
                ).await;
                assert!(first.is_success());
                let Outcome::Ok(key) = first.outcome else { panic!("first acquisition"); };
                scope.get(&key).unwrap().set(7);
                let second = scope.reserve().unwrap().acquire(
                    &cx, |_| async { Outcome::<u8, _>::Err("second acquisition failed") },
                    |_, _| -> std::future::Ready<Outcome<(), &'static str>> { panic!("unacquired resource release"); },
                ).await;
                match second.outcome {
                    Outcome::Err(error) => Outcome::Err(error),
                    _ => panic!("expected original setup failure"),
                }
            }),
        ).unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.is_success());
        assert!(report.lifecycle.close.as_ref().unwrap().is_ok());
        assert!(matches!(&report.lifecycle.usage.as_ref().unwrap().outcome, Outcome::Err("second acquisition failed")));
        assert!(matches!(&report.lifecycle.release.as_ref().unwrap().outcome, Outcome::Err(())));
        let cleanup = report.cleanup.unwrap();
        assert!(cleanup.complete);
        assert_eq!(cleanup.entries.len(), 1);
        assert_eq!(cleanup.entries[0].index, 0);
        assert!(matches!(cleanup.entries[0].phase.outcome, Outcome::Err("first resource release failed")));
        assert!(report.lifecycle.unreleased.is_none());
    });
}

#[test]
fn work_panic_still_drains_and_reports_every_resource_release() {
    run_scope_case(|cx| async move {
        let log = Arc::new(Mutex::new(Vec::new()));
        let work_log = Arc::clone(&log);
        let mut handle = cx.spawn_resource_scope::<(), &'static str, &'static str, _>(
            BracketConfig::new(4), 2,
            move |_, mut scope| Box::pin(async move {
                let first = Arc::clone(&work_log);
                scope.try_insert(13_u8, move |_, value| async move {
                    first.lock().unwrap().push(value);
                    Outcome::Ok(())
                }).unwrap();
                scope.try_insert(String::from("newer resource"), move |_, value| async move {
                    assert_eq!(value, "newer resource");
                    work_log.lock().unwrap().push(21);
                    Outcome::Ok(())
                }).unwrap();
                crate::runtime::yield_now().await;
                panic!("work failed after two registrations");
            }),
        ).unwrap();
        let report = handle.join().await.unwrap();
        assert!(!report.is_success());
        assert!(matches!(&report.lifecycle.usage.as_ref().unwrap().outcome,
            Outcome::Panicked(p) if p.message() == "work failed after two registrations"));
        assert!(report.cleanup.as_ref().unwrap().is_success());
        assert_eq!(report.cleanup.as_ref().unwrap().entries.len(), 2);
        assert_eq!(*log.lock().unwrap(), [21, 13]);
    });
}

#[test]
fn resource_scope_success_retains_successful_cleanup_entries_including_empty_scope() {
    run_scope_case(|cx| async move {
        for capacity in [0, 2] {
            let mut handle = cx.spawn_resource_scope::<usize, (), Cell<u8>, _>(
                BracketConfig::new(2), capacity,
                move |_, mut resources| Box::pin(async move {
                    for _ in 0..capacity {
                        let key = resources.try_insert(Cell::new(3_u8), |_, value| async move {
                            assert_eq!(value.get(), 5);
                            Outcome::Ok(())
                        }).unwrap();
                        resources.get_mut(&key).unwrap().set(5);
                    }
                    Outcome::Ok(capacity)
                }),
            ).unwrap();
            let report = handle.join().await.unwrap();
            assert!(report.is_success());
            assert_eq!(report.cleanup.as_ref().unwrap().entries.len(), capacity);
            assert!(matches!(report.lifecycle.usage.unwrap().outcome, Outcome::Ok(n) if n == capacity));
            assert!(report.lifecycle.release.unwrap().is_success());
        }
    });
}
