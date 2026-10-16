    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;
    use super::super::tests::{finish, fixture, flush};
    use crate::runtime::obligation_mailbox::ObligationGateway;
    use crate::types::{Budget, CancelKind};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    fn counter() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        (count, waker)
    }

    fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(waker))
    }

    fn ready<T>(result: Poll<Result<T, TrackedNameError>>) -> T {
        match result {
            Poll::Ready(Ok(value)) => value,
            Poll::Ready(Err(error)) => panic!("unexpected name refusal: {error}"),
            Poll::Pending => panic!("name should be ready"),
        }
    }

    #[test]
    fn immediate_wait_returns_an_invisible_accounted_permit() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        let permit = ready(poll(wait.as_mut(), Waker::noop()));
        assert_eq!(names.whereis("worker"), None);
        assert!(names.waiters.lock().is_empty());
        let ticket = permit.obligation_ticket();
        let lease = permit.commit().unwrap();
        assert_eq!(lease.obligation_ticket(), ticket);
        lease.release().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn sleeping_contender_does_not_hold_the_owners_only_quota_credit() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let before = lab.state.obligation_gateway().unwrap().mailbox().stats().posted;
        let mut wait = Box::pin(names.register_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.obligation_gateway().unwrap().mailbox().stats().posted, before);
        owner.release().unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        let lease = ready(poll(wait.as_mut(), &waker));
        assert_eq!(names.whereis("worker"), Some(cx.task_id()));
        lease.release().unwrap();
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn aborting_or_dropping_unpublished_ownership_wakes_contenders() {
        for explicit in [false, true] {
            let (lab, cx, handle) = fixture(1);
            let names = TrackedNameRegistry::new();
            let owner = names.reserve(&cx, "worker").unwrap();
            let (count, waker) = counter();
            let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
            assert!(poll(wait.as_mut(), &waker).is_pending());
            if explicit { owner.abort().unwrap(); } else { drop(owner); }
            assert!(count.0.load(Ordering::SeqCst) > 0);
            let next = ready(poll(wait.as_mut(), &waker));
            assert_eq!(names.whereis("worker"), None);
            next.abort().unwrap();
            drop(wait);
            finish(lab, &cx, handle, 2);
        }
    }

    #[test]
    fn cancellation_alone_wakes_wait_and_preserves_the_current_owner() {
        let (mut lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        cx.cancel_fast(CancelKind::User);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(poll(wait.as_mut(), &waker), Poll::Ready(Err(TrackedNameError::Cancelled))));
        assert_eq!(names.whereis("worker"), Some(owner.holder()));
        assert!(names.waiters.lock().is_empty());
        assert_eq!(Arc::strong_count(&count), 2);
        drop(wait);
        owner.release().unwrap();
        flush(&mut lab);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        drop(handle);
    }

    #[test]
    fn dropping_wait_removes_both_subscriptions_and_name_metadata() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(Arc::strong_count(&count), 2);
        owner.release().unwrap();
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn unrelated_name_release_does_not_wake_the_waiter() {
        let (lab, cx, handle) = fixture(2);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let unrelated = names.register(&cx, "unrelated").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        unrelated.release().unwrap();
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        owner.release().unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        ready(poll(wait.as_mut(), &waker)).abort().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 3);
    }

    #[test]
    fn same_waker_waiters_have_independent_subscription_ownership() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut first = Box::pin(names.reserve_wait(&cx, "worker"));
        let mut second = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(first.as_mut(), &waker).is_pending());
        assert!(poll(second.as_mut(), &waker).is_pending());
        drop(first);
        assert_eq!(names.waiters.lock().get("worker").unwrap().users, 1);
        owner.release().unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        ready(poll(second.as_mut(), &waker)).abort().unwrap();
        drop(second);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(Arc::strong_count(&count), 2);
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn migrated_wait_retires_the_old_executor_waker() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (old_count, old_waker) = counter();
        let (new_count, new_waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &old_waker).is_pending());
        assert!(poll(wait.as_mut(), &new_waker).is_pending());
        assert_eq!(Arc::strong_count(&old_count), 2);
        owner.release().unwrap();
        assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
        assert!(new_count.0.load(Ordering::SeqCst) > 0);
        ready(poll(wait.as_mut(), &new_waker)).abort().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn release_between_condition_check_and_first_poll_is_not_lost() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let interest = names.subscribe("worker");
        let epoch = interest.signal.epoch.load(Ordering::Acquire);
        assert!(matches!(names.inner.lock().reserve("worker", cx.task_id(), cx.region_id(), cx.now()),
            Err(NameLeaseError::NameTaken { .. })));
        assert_eq!(interest.signal.notify.waiter_count(), 0);
        owner.release().unwrap();
        // This is the same armed wait used by reserve_wait, first polled AFTER
        // the owner released with no Notify waker registered.
        let mut changed = Box::pin(interest.changed(epoch));
        assert!(poll(changed.as_mut(), Waker::noop()).is_ready());
        drop(changed);
        drop(interest);
        assert!(names.waiters.lock().is_empty());
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn quota_refusal_after_claim_returns_the_invisible_name() {
        let (mut lab, cx, handle) = fixture(0);
        let names = TrackedNameRegistry::new();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(matches!(poll(wait.as_mut(), Waker::noop()),
            Poll::Ready(Err(TrackedNameError::Admission(ObligationAdmissionError::LimitReached { limit: 0, live: 0 })))));
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(names.whereis("worker"), None);
        assert!(lab.state.set_region_limits(cx.region_id(), crate::record::region::RegionLimits {
            max_obligations: Some(1), ..crate::record::region::RegionLimits::UNLIMITED
        }));
        names.register(&cx, "worker").unwrap().release().unwrap();
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn elapsed_deadline_refuses_even_an_available_name() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let mut wait = Box::pin(names.reserve_wait_until(&cx, "worker", Time::ZERO));
        assert!(matches!(poll(wait.as_mut(), Waker::noop()),
            Poll::Ready(Err(TrackedNameError::Registry(NameLeaseError::WaitBudgetExceeded { .. })))));
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(names.whereis("worker"), None);
        finish(lab, &cx, handle, 0);
    }

    #[test]
    fn virtual_deadline_wakes_without_name_or_cancellation_activity() {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::time::{TimerDriverHandle, VirtualClock};
        crate::test_utils::init_test_logging();
        let mut lab = LabRuntime::new(LabConfig::new(0x100_71ae).max_steps(512));
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        lab.state.set_timer_driver(timer.clone());
        let root = lab.state.create_root_region(Budget::INFINITE);
        let region = lab.state.create_child_region(root, Budget::INFINITE).unwrap();
        let (task, handle) = lab.state.create_task(region, Budget::INFINITE, async {}).unwrap();
        let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let deadline = Time::from_secs(1);
        let mut wait = Box::pin(names.reserve_wait_until(&cx, "worker", deadline));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        clock.advance_to(deadline);
        let _ = timer.process_timers();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(poll(wait.as_mut(), &waker),
            Poll::Ready(Err(TrackedNameError::Registry(NameLeaseError::WaitBudgetExceeded { .. })))));
        drop(wait);
        assert_eq!(names.whereis("worker"), Some(owner.holder()));
        assert!(names.waiters.lock().is_empty());
        owner.release().unwrap();
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn settlement_notifier_panic_still_wakes_after_returning_quota() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(move || {
                if observed.fetch_add(1, Ordering::SeqCst) == 1 {
                    panic!("planted name settlement failure");
                }
            }),
            Arc::downgrade(&liveness),
        ));
        let owner_cx = cx.clone().with_obligation_gateway(Some(gateway), None);
        let owner = names.register(&owner_cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.release()));
        assert!(result.is_err());
        assert!(count.0.load(Ordering::SeqCst) > 0);
        ready(poll(wait.as_mut(), &waker)).abort().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 2);
    }
