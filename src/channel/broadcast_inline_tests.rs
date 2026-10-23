    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now;
    use crate::types::Budget;
    use serde_json::Value;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Debug)]
    struct CountingWaker {
        wakes: AtomicUsize,
    }

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                wakes: AtomicUsize::new(0),
            })
        }

        fn wake_count(&self) -> usize {
            self.wakes.load(AtomicOrdering::Acquire)
        }
    }

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, AtomicOrdering::AcqRel);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, AtomicOrdering::AcqRel);
        }
    }

    /// An unchecked send whose evicted message panics in `Drop` still wakes
    /// the receivers parked for the new message.
    #[test]
    fn unchecked_send_wakes_parked_receivers_when_the_evicted_message_drop_panics() {
        thread_local! {
            static ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }
        #[derive(Clone, Debug, PartialEq)]
        struct Bomb(u32);
        impl Drop for Bomb {
            fn drop(&mut self) {
                if ARMED.with(|armed| armed.replace(false)) {
                    panic!("planted evicted-message drop panic");
                }
            }
        }

        let cx = test_cx();
        let (tx, _first) = channel::<Bomb>(1);
        assert_eq!(tx.send(&cx, Bomb(1)), Ok(1));
        let mut fast = tx.subscribe();
        let wakes = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wakes));
        let mut context = Context::from_waker(&waker);
        let mut receiver = Box::pin(fast.recv(&cx));
        assert!(receiver.as_mut().poll(&mut context).is_pending());

        ARMED.with(|armed| armed.set(true));
        let sent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tx.send(&cx, Bomb(2))));
        ARMED.with(|armed| armed.set(false));
        assert!(sent.is_err(), "the evicted message's destructor panicked");
        assert_eq!(wakes.wake_count(), 1, "the parked receiver is woken anyway");
    }

    /// One panicking waker must not strand the other parked receivers when the
    /// last sender drops.
    #[test]
    fn last_sender_drop_wakes_every_parked_receiver_despite_a_panicking_waker() {
        struct PanickingWaker {
            wakes: Arc<AtomicUsize>,
        }
        impl std::task::Wake for PanickingWaker {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.wakes.fetch_add(1, AtomicOrdering::SeqCst);
                panic!("planted broadcast receiver wake panic");
            }
        }

        let cx = test_cx();
        let (tx, mut first) = channel::<u32>(1);
        let mut second = tx.subscribe();
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(PanickingWaker {
            wakes: Arc::clone(&wakes),
        }));
        let mut context = Context::from_waker(&waker);
        let mut first_recv = Box::pin(first.recv(&cx));
        let mut second_recv = Box::pin(second.recv(&cx));
        assert!(first_recv.as_mut().poll(&mut context).is_pending());
        assert!(second_recv.as_mut().poll(&mut context).is_pending());

        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(tx)));
        assert!(dropped.is_err(), "the first wake panic resumes afterwards");
        assert_eq!(
            wakes.load(AtomicOrdering::SeqCst),
            2,
            "every parked receiver is woken"
        );
    }

    fn checked_admission_fixture(
        limit: usize,
    ) -> (crate::lab::LabRuntime, Cx, crate::runtime::TaskHandle<()>) {
        let mut lab =
            crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x28_c003).max_steps(128));
        let region = lab.state.create_root_region(Budget::INFINITE);
        assert!(lab.state.set_region_limits(
            region,
            crate::record::region::RegionLimits {
                max_obligations: Some(limit),
                ..crate::record::region::RegionLimits::UNLIMITED
            }
        ));
        let (task, handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        (lab, cx, handle)
    }

    fn finish_checked_admission_fixture(
        mut lab: crate::lab::LabRuntime,
        cx: &Cx,
        mut handle: crate::runtime::TaskHandle<()>,
        committed: u64,
        aborted: u64,
    ) {
        let region = lab.state.region(cx.region_id()).unwrap();
        assert_eq!(
            region.pending_obligations(),
            0,
            "quota must settle before draining"
        );
        let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
        lab.scheduler.lock().schedule(cx.task_id(), 0);
        let report = lab.run_until_quiescent_with_report();
        assert!(
            report.oracle_report.all_passed(),
            "{:?}",
            report.oracle_report.failures()
        );
        assert!(report.invariant_violations.is_empty());
        assert!(handle.try_join().unwrap().is_some());
        let stats = mailbox.stats();
        eprintln!(
            "checked broadcast region={:?} holder={:?} expected_committed={committed} expected_aborted={aborted} stats={stats:?} queued={} open_tickets={}",
            cx.region_id(),
            cx.task_id(),
            mailbox.len(),
            mailbox.open_tickets(),
        );
        assert_eq!(stats.posted, stats.applied);
        assert_eq!(stats.reserved, committed + aborted);
        assert_eq!(stats.committed, committed);
        assert_eq!(stats.aborted, aborted);
        assert_eq!(stats.refused, 0);
        assert_eq!(stats.leaked, 0);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        assert_eq!(
            lab.state
                .region(cx.region_id())
                .unwrap()
                .unapplied_obligation_count(),
            0
        );
    }

    fn checked_panic_notifier<T: Send + 'static>(
        lab: &crate::lab::LabRuntime,
        cx: Cx,
        tx: &Sender<T>,
        panic_at: usize,
    ) -> (Cx, Arc<()>, Arc<AtomicUsize>) {
        let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
        let notifications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&notifications);
        let channel = Arc::downgrade(&tx.channel);
        let liveness = Arc::new(());
        let gateway = Arc::new(crate::runtime::obligation_mailbox::ObligationGateway::new(
            mailbox,
            Arc::new(move || {
                assert!(channel.upgrade().unwrap().inner.try_lock().is_some());
                assert_ne!(
                    observed.fetch_add(1, AtomicOrdering::SeqCst),
                    panic_at,
                    "planted broadcast obligation notification panic"
                );
            }),
            Arc::downgrade(&liveness),
        ));
        (
            cx.with_obligation_gateway(Some(gateway), None),
            liveness,
            notifications,
        )
    }

    struct CheckedPanicWaker<T> {
        channel: std::sync::Weak<Channel<T>>,
        calls: Arc<AtomicUsize>,
    }

    impl<T: Send + 'static> std::task::Wake for CheckedPanicWaker<T> {
        fn wake(self: Arc<Self>) {
            assert!(self.channel.upgrade().unwrap().inner.try_lock().is_some());
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            panic!("planted broadcast receiver wake panic");
        }
    }

    struct CheckedPanicRetirementWaker<T> {
        channel: std::sync::Weak<Channel<T>>,
        wakes: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl<T: Send + 'static> std::task::Wake for CheckedPanicRetirementWaker<T> {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            assert!(self.channel.upgrade().unwrap().inner.try_lock().is_some());
            self.wakes.fetch_add(1, AtomicOrdering::SeqCst);
            panic!("planted broadcast final-owner wake panic");
        }
    }

    impl<T> Drop for CheckedPanicRetirementWaker<T> {
        fn drop(&mut self) {
            assert!(self.channel.upgrade().unwrap().inner.try_lock().is_some());
            self.drops.fetch_add(1, AtomicOrdering::SeqCst);
            panic!("planted broadcast final-owner retirement panic");
        }
    }

    #[test]
    fn checked_admission_denial_preserves_ring_and_parked_receivers() {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        for limit in [0, 1, 3] {
            let (lab, cx, handle) = checked_admission_fixture(limit);
            eprintln!("checked broadcast pre-publication quota limit={limit}");
            let (tx, mut slow) = channel::<u32>(1);
            assert_eq!(tx.send(&test_cx(), 11), Ok(1));
            let mut fast = tx.subscribe();
            let wakes = CountingWaker::new();
            let waker = Waker::from(Arc::clone(&wakes));
            let mut context = Context::from_waker(&waker);
            let mut receiver = Box::pin(fast.recv(&cx));
            assert!(receiver.as_mut().poll(&mut context).is_pending());
            let mut permits = Vec::new();
            for _ in 0..limit {
                permits.push(tx.reserve_checked(&cx).unwrap());
            }
            let cancellations = tx.telemetry_snapshot(0).cancellation_count;
            assert_eq!(
                tx.send_checked(&cx, 17),
                Err(CheckedSendError::Admission {
                    error: ObligationAdmissionError::LimitReached { limit, live: limit },
                    value: 17,
                })
            );
            assert_eq!(tx.channel.inner.lock().total_sent, 1);
            assert_eq!(tx.channel.inner.lock().wakers.len(), 1);
            assert_eq!(wakes.wake_count(), 0);
            assert_eq!(tx.telemetry_snapshot(0).cancellation_count, cancellations);
            assert_eq!(
                slow.try_recv(),
                Ok(11),
                "denial must not evict the old value"
            );
            if let Some(permit) = permits.pop() {
                assert_eq!(permit.send(23), 2);
                assert_eq!(wakes.wake_count(), 1);
                assert!(matches!(
                    receiver.as_mut().poll(&mut context),
                    Poll::Ready(Ok(23))
                ));
            }
            drop(receiver);
            drop(permits);
            if limit > 0 {
                // No task poll or mailbox drain: every commit and unsent drop
                // must already have made its quota available to the next send.
                for value in 100..165 {
                    assert_eq!(tx.send_checked(&cx, value), Ok(2));
                    assert_eq!(fast.try_recv(), Ok(value));
                }
            }
            finish_checked_admission_fixture(
                lab,
                &cx,
                handle,
                if limit > 0 { 66 } else { 0 },
                limit.saturating_sub(1) as u64,
            );
        }
    }

    #[test]
    fn checked_admission_notifier_panic_aborts_before_any_publication() {
        let (lab, cx, handle) = checked_admission_fixture(1);
        let (tx, mut rx) = channel::<u32>(1);
        let (cx, _liveness, notifications) = checked_panic_notifier(&lab, cx, &tx, 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = tx.reserve_checked(&cx).unwrap();
        }));
        assert!(
            result.is_err(),
            "the admission callback must actually panic"
        );
        assert_eq!(notifications.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(tx.channel.inner.lock().total_sent, 0);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(tx.send_checked(&cx, 31), Ok(1));
        assert_eq!(rx.try_recv(), Ok(31));
        assert_eq!(notifications.load(AtomicOrdering::SeqCst), 3);
        finish_checked_admission_fixture(lab, &cx, handle, 1, 1);
    }

    #[test]
    fn checked_commit_notifier_panic_preserves_fanout_and_later_wakes() {
        for panic_notifier in [false, true] {
            let (lab, cx, handle) = checked_admission_fixture(1);
            let (tx, mut first) = channel::<u32>(2);
            let mut second = tx.subscribe();
            let (cx, _liveness, notifications) =
                checked_panic_notifier(&lab, cx, &tx, if panic_notifier { 1 } else { usize::MAX });
            let first_calls = Arc::new(AtomicUsize::new(0));
            let first_waker = Waker::from(Arc::new(CheckedPanicWaker {
                channel: Arc::downgrade(&tx.channel),
                calls: Arc::clone(&first_calls),
            }));
            let second_calls = CountingWaker::new();
            let second_waker = Waker::from(Arc::clone(&second_calls));
            let mut first_context = Context::from_waker(&first_waker);
            let mut second_context = Context::from_waker(&second_waker);
            let mut first_recv = Box::pin(first.recv(&cx));
            let mut second_recv = Box::pin(second.recv(&cx));
            assert!(first_recv.as_mut().poll(&mut first_context).is_pending());
            assert!(second_recv.as_mut().poll(&mut second_context).is_pending());
            assert_eq!(tx.channel.inner.lock().wakers.len(), 2);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tx.send_checked(&cx, 41).unwrap();
            }));
            let payload = result.expect_err("the planted callback must execute");
            if panic_notifier {
                assert!(payload.downcast_ref::<String>().is_some_and(|text| {
                    text.contains("planted broadcast obligation notification panic")
                }));
            } else {
                assert_eq!(
                    payload.downcast_ref::<&str>(),
                    Some(&"planted broadcast receiver wake panic")
                );
            }
            assert_eq!(notifications.load(AtomicOrdering::SeqCst), 2);
            assert_eq!(first_calls.load(AtomicOrdering::SeqCst), 1);
            assert_eq!(second_calls.wake_count(), 1);
            assert_eq!(tx.channel.inner.lock().wakers.len(), 0);
            assert!(matches!(
                first_recv.as_mut().poll(&mut first_context),
                Poll::Ready(Ok(41))
            ));
            assert!(matches!(
                second_recv.as_mut().poll(&mut second_context),
                Poll::Ready(Ok(41))
            ));
            drop(first_recv);
            drop(second_recv);
            assert_eq!(tx.send_checked(&cx, 43), Ok(2));
            assert_eq!(first.try_recv(), Ok(43));
            assert_eq!(second.try_recv(), Ok(43));
            finish_checked_admission_fixture(lab, &cx, handle, 2, 0);
        }
    }

    #[test]
    fn checked_permit_drop_notifier_panic_releases_quota() {
        let (lab, cx, handle) = checked_admission_fixture(1);
        let (tx, mut rx) = channel::<u32>(1);
        let (cx, _liveness, notifications) = checked_panic_notifier(&lab, cx, &tx, 1);
        let permit = tx.reserve_checked(&cx).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(permit)));
        assert!(result.is_err(), "the abort notifier must execute");
        assert_eq!(notifications.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(tx.channel.inner.lock().total_sent, 0);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(tx.send_checked(&cx, 47), Ok(1));
        assert_eq!(rx.try_recv(), Ok(47));
        finish_checked_admission_fixture(lab, &cx, handle, 1, 1);
    }

    #[derive(Debug, Clone)]
    struct CheckedPanicPayload {
        value: u32,
        armed: Arc<AtomicBool>,
        channel: std::sync::Weak<Channel<Self>>,
    }

    impl Drop for CheckedPanicPayload {
        fn drop(&mut self) {
            if self.armed.swap(false, AtomicOrdering::SeqCst) {
                assert!(self.channel.upgrade().unwrap().inner.try_lock().is_some());
                panic!("planted broadcast eviction drop panic");
            }
        }
    }

    #[test]
    fn checked_eviction_panic_keeps_primary_panic_and_wakes_all_receivers() {
        let (lab, cx, handle) = checked_admission_fixture(1);
        let (tx, mut slow) = channel::<CheckedPanicPayload>(1);
        assert_eq!(
            tx.send(
                &test_cx(),
                CheckedPanicPayload {
                    value: 51,
                    armed: Arc::new(AtomicBool::new(true)),
                    channel: Arc::downgrade(&tx.channel),
                }
            )
            .unwrap(),
            1
        );
        let mut first = tx.subscribe();
        let mut second = tx.subscribe();
        let (cx, _liveness, notifications) = checked_panic_notifier(&lab, cx, &tx, 1);
        let first_calls = Arc::new(AtomicUsize::new(0));
        let first_waker = Waker::from(Arc::new(CheckedPanicWaker {
            channel: Arc::downgrade(&tx.channel),
            calls: Arc::clone(&first_calls),
        }));
        let second_calls = CountingWaker::new();
        let second_waker = Waker::from(Arc::clone(&second_calls));
        let mut first_context = Context::from_waker(&first_waker);
        let mut second_context = Context::from_waker(&second_waker);
        let mut first_recv = Box::pin(first.recv(&cx));
        let mut second_recv = Box::pin(second.recv(&cx));
        assert!(first_recv.as_mut().poll(&mut first_context).is_pending());
        assert!(second_recv.as_mut().poll(&mut second_context).is_pending());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tx.send_checked(
                &cx,
                CheckedPanicPayload {
                    value: 53,
                    armed: Arc::new(AtomicBool::new(false)),
                    channel: Arc::downgrade(&tx.channel),
                },
            )
            .unwrap();
        }));
        let payload = result.expect_err("the evicted payload destructor must execute");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"planted broadcast eviction drop panic")
        );
        assert_eq!(notifications.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(first_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(second_calls.wake_count(), 1);
        assert!(
            matches!(first_recv.as_mut().poll(&mut first_context), Poll::Ready(Ok(value)) if value.value == 53)
        );
        assert!(
            matches!(second_recv.as_mut().poll(&mut second_context), Poll::Ready(Ok(value)) if value.value == 53)
        );
        assert!(matches!(slow.try_recv(), Err(TryRecvError::Lagged(1))));
        assert_eq!(slow.try_recv().unwrap().value, 53);
        finish_checked_admission_fixture(lab, &cx, handle, 1, 0);
    }

    #[test]
    fn checked_final_waker_owner_panics_do_not_abort_or_strand_fanout() {
        for first_failure in ["wake", "notifier", "eviction"] {
            let (lab, cx, handle) = checked_admission_fixture(1);
            let (tx, mut slow) = channel::<CheckedPanicPayload>(1);
            assert_eq!(
                tx.send(
                    &test_cx(),
                    CheckedPanicPayload {
                        value: 81,
                        armed: Arc::new(AtomicBool::new(first_failure == "eviction")),
                        channel: Arc::downgrade(&tx.channel),
                    }
                )
                .unwrap(),
                1
            );
            let mut first = tx.subscribe();
            let mut second = tx.subscribe();
            let (cx, _liveness, notifications) = checked_panic_notifier(
                &lab,
                cx,
                &tx,
                if first_failure == "wake" {
                    usize::MAX
                } else {
                    1
                },
            );
            let wakes = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let final_owner = Arc::new(CheckedPanicRetirementWaker {
                channel: Arc::downgrade(&tx.channel),
                wakes: Arc::clone(&wakes),
                drops: Arc::clone(&drops),
            });
            let observer = Arc::downgrade(&final_owner);
            let mut first_recv = Box::pin(first.recv(&cx));
            {
                let waker = Waker::from(final_owner);
                let mut context = Context::from_waker(&waker);
                assert!(first_recv.as_mut().poll(&mut context).is_pending());
            }
            assert_eq!(
                observer.strong_count(),
                1,
                "only the stored waiter owns the payload"
            );
            let second_calls = CountingWaker::new();
            let second_waker = Waker::from(Arc::clone(&second_calls));
            let mut second_context = Context::from_waker(&second_waker);
            let mut second_recv = Box::pin(second.recv(&cx));
            assert!(second_recv.as_mut().poll(&mut second_context).is_pending());
            assert_eq!(tx.channel.inner.lock().wakers.len(), 2);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tx.send_checked(
                    &cx,
                    CheckedPanicPayload {
                        value: 83,
                        armed: Arc::new(AtomicBool::new(false)),
                        channel: Arc::downgrade(&tx.channel),
                    },
                )
                .unwrap();
            }));
            let payload = result.expect_err("the planted first callback must execute");
            match first_failure {
                "notifier" => assert!(payload.downcast_ref::<String>().is_some_and(|text| {
                    text.contains("planted broadcast obligation notification panic")
                })),
                "eviction" => assert_eq!(
                    payload.downcast_ref::<&str>(),
                    Some(&"planted broadcast eviction drop panic")
                ),
                _ => assert_eq!(
                    payload.downcast_ref::<&str>(),
                    Some(&"planted broadcast final-owner wake panic")
                ),
            }
            assert_eq!(notifications.load(AtomicOrdering::SeqCst), 2);
            assert_eq!(wakes.load(AtomicOrdering::SeqCst), 1);
            assert_eq!(drops.load(AtomicOrdering::SeqCst), 1);
            assert_eq!(observer.strong_count(), 0);
            assert_eq!(second_calls.wake_count(), 1);
            assert_eq!(tx.channel.inner.lock().wakers.len(), 0);
            let mut first_context = Context::from_waker(Waker::noop());
            assert!(
                matches!(first_recv.as_mut().poll(&mut first_context), Poll::Ready(Ok(value)) if value.value == 83)
            );
            assert!(
                matches!(second_recv.as_mut().poll(&mut second_context), Poll::Ready(Ok(value)) if value.value == 83)
            );
            assert!(matches!(slow.try_recv(), Err(TryRecvError::Lagged(1))));
            assert_eq!(slow.try_recv().unwrap().value, 83);
            eprintln!(
                "checked broadcast final-owner retirement first_failure={first_failure} wakes=1 drops=1 healthy_wakes=1"
            );
            finish_checked_admission_fixture(lab, &cx, handle, 1, 0);
        }
    }

    #[test]
    fn checked_send_preserves_stateless_channel_errors_and_zero_receiver_commit() {
        let cx = test_cx();
        let (tx, mut rx) = channel::<u32>(1);
        assert_eq!(tx.send_checked(&cx, 61), Ok(1));
        assert_eq!(rx.try_recv(), Ok(61));
        cx.set_cancel_requested(true);
        assert_eq!(
            tx.send_checked(&cx, 67),
            Err(CheckedSendError::Channel(SendError::Cancelled(67)))
        );
        cx.set_cancel_requested(false);
        drop(rx);
        assert_eq!(
            tx.send_checked(&cx, 71),
            Err(CheckedSendError::Channel(SendError::Closed(71)))
        );

        let (lab, cx, handle) = checked_admission_fixture(1);
        let (tx, rx) = channel::<u32>(1);
        let permit = tx.reserve_checked(&cx).unwrap();
        drop(rx);
        assert_eq!(permit.send(73), 0);
        assert_eq!(tx.channel.inner.lock().total_sent, 0);
        assert!(tx.is_empty());
        let mut next = tx.subscribe();
        assert_eq!(tx.send_checked(&cx, 79), Ok(1));
        assert_eq!(next.try_recv(), Ok(79));
        finish_checked_admission_fixture(lab, &cx, handle, 2, 0);
    }

    #[derive(Debug)]
    struct WakerDropLockProbe {
        channel: std::sync::Weak<Channel<i32>>,
        drop_count: Arc<AtomicUsize>,
        lock_was_free: Arc<AtomicBool>,
    }

    #[allow(clippy::manual_noop_waker)]
    impl std::task::Wake for WakerDropLockProbe {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for WakerDropLockProbe {
        fn drop(&mut self) {
            let lock_was_free = self
                .channel
                .upgrade()
                .is_none_or(|channel| channel.inner.try_lock().is_some());
            self.lock_was_free
                .store(lock_was_free, AtomicOrdering::Release);
            self.drop_count.fetch_add(1, AtomicOrdering::AcqRel);
        }
    }

    fn waker_drop_lock_probe(tx: &Sender<i32>) -> (Waker, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let drop_count = Arc::new(AtomicUsize::new(0));
        let lock_was_free = Arc::new(AtomicBool::new(false));
        let probe = Arc::new(WakerDropLockProbe {
            channel: Arc::downgrade(&tx.channel),
            drop_count: Arc::clone(&drop_count),
            lock_was_free: Arc::clone(&lock_was_free),
        });
        (Waker::from(probe), drop_count, lock_was_free)
    }

    fn assert_waker_dropped_outside_lock(drop_count: &AtomicUsize, lock_was_free: &AtomicBool) {
        assert_eq!(drop_count.load(AtomicOrdering::Acquire), 1);
        assert!(lock_was_free.load(AtomicOrdering::Acquire));
    }

    #[derive(Debug)]
    struct DropBlocker {
        entered_tx: std::sync::mpsc::SyncSender<()>,
        release_rx: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        armed: AtomicUsize,
    }

    impl DropBlocker {
        fn new() -> (
            Arc<Self>,
            std::sync::mpsc::Receiver<()>,
            std::sync::mpsc::SyncSender<()>,
        ) {
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
            (
                Arc::new(Self {
                    entered_tx,
                    release_rx: std::sync::Mutex::new(Some(release_rx)),
                    armed: AtomicUsize::new(1),
                }),
                entered_rx,
                release_tx,
            )
        }
    }

    #[derive(Debug)]
    enum GateMsg {
        Blocking(Arc<DropBlocker>),
        Plain(i32),
    }

    impl Clone for GateMsg {
        fn clone(&self) -> Self {
            match self {
                Self::Blocking(blocker) => Self::Blocking(Arc::clone(blocker)),
                Self::Plain(value) => Self::Plain(*value),
            }
        }
    }

    impl Drop for GateMsg {
        fn drop(&mut self) {
            let Self::Blocking(blocker) = self else {
                return;
            };

            if blocker.armed.fetch_sub(1, AtomicOrdering::AcqRel) != 1 {
                return;
            }

            let _ = blocker.entered_tx.send(());
            let release_rx = if let Ok(mut guard) = blocker.release_rx.lock() {
                guard.take()
            } else {
                None
            };

            if let Some(rx) = release_rx {
                let _ = rx.recv();
            }
        }
    }

    #[derive(Debug)]
    struct CloneReentryMsg {
        value: i32,
        request_tx: std::sync::mpsc::SyncSender<()>,
        response_rx: Arc<StdMutex<std::sync::mpsc::Receiver<usize>>>,
    }

    impl Clone for CloneReentryMsg {
        fn clone(&self) -> Self {
            self.request_tx
                .send(())
                .expect("request Sender::len re-entry");
            let observed_len = self
                .response_rx
                .lock()
                .expect("response receiver mutex poisoned")
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("Sender::len re-entry blocked on the broadcast mutex");
            assert_eq!(observed_len, 1);
            Self {
                value: self.value,
                request_tx: self.request_tx.clone(),
                response_rx: Arc::clone(&self.response_rx),
            }
        }
    }

    #[derive(Debug)]
    struct PanicOnceCloneMsg {
        value: i32,
        clone_attempts: Arc<AtomicUsize>,
    }

    impl Clone for PanicOnceCloneMsg {
        fn clone(&self) -> Self {
            if self.clone_attempts.fetch_add(1, AtomicOrdering::AcqRel) == 0 {
                panic!("intentional first clone panic");
            }
            Self {
                value: self.value,
                clone_attempts: Arc::clone(&self.clone_attempts),
            }
        }
    }

    #[derive(Debug)]
    struct CloneBlocker {
        entered_tx: std::sync::mpsc::SyncSender<()>,
        release_rx: StdMutex<Option<std::sync::mpsc::Receiver<()>>>,
        armed: AtomicUsize,
    }

    impl CloneBlocker {
        fn new() -> (
            Arc<Self>,
            std::sync::mpsc::Receiver<()>,
            std::sync::mpsc::SyncSender<()>,
        ) {
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
            (
                Arc::new(Self {
                    entered_tx,
                    release_rx: StdMutex::new(Some(release_rx)),
                    armed: AtomicUsize::new(1),
                }),
                entered_rx,
                release_tx,
            )
        }

        fn block_once(&self) {
            if self
                .armed
                .compare_exchange(1, 0, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
                .is_err()
            {
                return;
            }
            self.entered_tx.send(()).expect("clone entered signal");
            let release_rx = self
                .release_rx
                .lock()
                .expect("clone release mutex poisoned")
                .take();
            if let Some(rx) = release_rx {
                rx.recv().expect("clone release signal");
            }
        }
    }

    #[derive(Debug)]
    struct CloneGateMsg {
        value: i32,
        blocker: Option<Arc<CloneBlocker>>,
    }

    impl Clone for CloneGateMsg {
        fn clone(&self) -> Self {
            if let Some(blocker) = &self.blocker {
                blocker.block_once();
            }
            Self {
                value: self.value,
                blocker: self.blocker.as_ref().map(Arc::clone),
            }
        }
    }

    #[derive(Debug)]
    struct DropReentryMsg {
        request_tx: Option<std::sync::mpsc::SyncSender<()>>,
        response_rx: Arc<StdMutex<std::sync::mpsc::Receiver<usize>>>,
    }

    impl Clone for DropReentryMsg {
        fn clone(&self) -> Self {
            Self {
                request_tx: None,
                response_rx: Arc::clone(&self.response_rx),
            }
        }
    }

    impl Drop for DropReentryMsg {
        fn drop(&mut self) {
            let Some(request_tx) = self.request_tx.take() else {
                return;
            };
            request_tx.send(()).expect("request Sender::len from Drop");
            let observed_len = self
                .response_rx
                .lock()
                .expect("drop response receiver mutex poisoned")
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("Sender::len from Drop blocked on the broadcast mutex");
            assert_eq!(observed_len, 0);
        }
    }

    #[test]
    fn recv_accepts_detached_no_cap_context() {
        init_test("recv_accepts_detached_no_cap_context");
        let send_cx = test_cx();
        let recv_cx = Cx::<crate::cx::cap::None>::detached_cancel_context();
        let (tx, mut rx) = channel::<i32>(4);

        tx.send(&send_cx, 47).expect("send should succeed");
        let value = block_on(rx.recv(&recv_cx)).expect("recv should accept cap::None Cx");

        crate::assert_with_log!(value == 47, "recv value", 47, value);
        crate::test_complete!("recv_accepts_detached_no_cap_context");
    }

    #[test]
    fn basic_send_recv() {
        init_test("basic_send_recv");
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);
        let mut rx2 = tx.subscribe();

        tx.send(&cx, 10).expect("send failed");
        tx.send(&cx, 20).expect("send failed");

        let rx1_first = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_first == 10, "rx1 first", 10, rx1_first);
        let rx1_second = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_second == 20, "rx1 second", 20, rx1_second);

        let rx2_first = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_first == 10, "rx2 first", 10, rx2_first);
        let rx2_second = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_second == 20, "rx2 second", 20, rx2_second);
        crate::test_complete!("basic_send_recv");
    }

    #[test]
    fn lag_detection() {
        init_test("lag_detection");
        let cx = test_cx();
        let (tx, mut rx) = channel(2);

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap();
        tx.send(&cx, 3).unwrap(); // overwrites 1

        // rx expected 1 (index 0), but earliest is 2 (index 1)
        let result = block_on(rx.recv(&cx));
        match result {
            Err(RecvError::Lagged(n)) => {
                crate::assert_with_log!(n == 1, "lagged count", 1, n);
            }
            other => unreachable!("expected lagged, got {other:?}"),
        }

        // next should be 2
        let second = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(second == 2, "second", 2, second);
        let third = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(third == 3, "third", 3, third);
        crate::test_complete!("lag_detection");
    }

    #[test]
    fn closed_send() {
        init_test("closed_send");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(10);
        drop(rx);
        let result = tx.send(&cx, 1);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Closed(1))),
            "send after close",
            "Err(Closed(1))",
            format!("{:?}", result)
        );
        crate::test_complete!("closed_send");
    }

    #[test]
    fn closed_recv() {
        init_test("closed_recv");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);
        drop(tx);
        let result = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(result, Err(RecvError::Closed)),
            "recv after close",
            "Err(Closed)",
            format!("{:?}", result)
        );
        crate::test_complete!("closed_recv");
    }

    #[test]
    fn subscribe_sees_future() {
        init_test("subscribe_sees_future");
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);

        tx.send(&cx, 1).unwrap();

        let mut rx2 = tx.subscribe();

        tx.send(&cx, 2).unwrap();

        let rx1_first = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_first == 1, "rx1 first", 1, rx1_first);
        let rx1_second = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_second == 2, "rx1 second", 2, rx1_second);

        // rx2 should skip 1
        let rx2_first = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_first == 2, "rx2 first", 2, rx2_first);
        crate::test_complete!("subscribe_sees_future");
    }

    #[test]
    fn send_returns_live_receiver_count() {
        init_test("send_returns_live_receiver_count");
        let cx = test_cx();
        let (tx, rx1) = channel::<i32>(10);
        let rx2 = tx.subscribe();
        let rx3 = rx2.clone();

        let count = tx.send(&cx, 1).expect("send failed");
        crate::assert_with_log!(count == 3, "receiver count", 3, count);

        drop(rx1);
        let count2 = tx.send(&cx, 2).expect("send failed");
        crate::assert_with_log!(count2 == 2, "receiver count after drop", 2, count2);

        drop(rx2);
        drop(rx3);
        let closed = tx.send(&cx, 3);
        crate::assert_with_log!(
            matches!(closed, Err(SendError::Closed(3))),
            "send closed when no receivers",
            "Err(Closed(3))",
            format!("{:?}", closed)
        );

        crate::test_complete!("send_returns_live_receiver_count");
    }

    #[test]
    fn send_count_excludes_receivers_that_subscribe_after_commit() {
        init_test("send_count_excludes_receivers_that_subscribe_after_commit");
        let cx = test_cx();
        let (tx, mut rx1) = channel::<GateMsg>(1);
        let (blocker, entered_rx, release_tx) = DropBlocker::new();

        tx.send(&cx, GateMsg::Blocking(blocker)).unwrap();

        let tx_thread = tx.clone();
        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            tx_thread.send(&cx, GateMsg::Plain(2)).expect("send failed")
        });

        entered_rx.recv().expect("drop blocker entered");

        let mut rx2 = tx.subscribe();
        release_tx.send(()).expect("drop blocker release send");

        let count = handle.join().expect("sender thread panicked");
        crate::assert_with_log!(
            count == 1,
            "send count excludes late subscriber",
            1usize,
            count
        );

        let lag = block_on(rx1.recv(&cx));
        crate::assert_with_log!(
            matches!(lag, Err(RecvError::Lagged(1))),
            "existing receiver first observes eviction lag",
            true,
            matches!(lag, Err(RecvError::Lagged(1)))
        );

        let got1 = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(
            matches!(got1, GateMsg::Plain(2)),
            "existing receiver sees committed message",
            true,
            matches!(got1, GateMsg::Plain(2))
        );

        tx.send(&cx, GateMsg::Plain(3)).unwrap();
        let got2 = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(
            matches!(got2, GateMsg::Plain(3)),
            "late subscriber sees only future message",
            true,
            matches!(got2, GateMsg::Plain(3))
        );

        crate::test_complete!("send_count_excludes_receivers_that_subscribe_after_commit");
    }

    #[test]
    fn recv_waiter_dedup_and_wake_on_send() {
        init_test("recv_waiter_dedup_and_wake_on_send");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));

        // No message yet: should pend and register exactly one waiter.
        let first_pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);
        let second_pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(second_pending, "second poll pending", true, second_pending);

        tx.send(&cx, 123).expect("send failed");

        // Waiter list should not contain duplicates: a single send wakes once.
        let wake_count = wake_state.wake_count();
        crate::assert_with_log!(wake_count == 1, "wake count", 1, wake_count);

        let got = match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(v)) => v,
            other => {
                unreachable!("expected Ready(Ok), got {other:?}");
            }
        };
        crate::assert_with_log!(got == 123, "received", 123, got);

        crate::test_complete!("recv_waiter_dedup_and_wake_on_send");
    }

    #[test]
    fn pending_recv_woken_on_sender_drop_returns_closed() {
        init_test("pending_recv_woken_on_sender_drop_returns_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));
        let pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(pending, "poll pending", true, pending);

        drop(tx);

        let wake_count = wake_state.wake_count();
        crate::assert_with_log!(wake_count == 1, "wake count", 1, wake_count);

        let got = match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Err(e)) => e,
            other => {
                unreachable!("expected Ready(Err), got {other:?}");
            }
        };
        crate::assert_with_log!(
            got == RecvError::Closed,
            "recv closed after sender drop",
            RecvError::Closed,
            got
        );

        crate::test_complete!("pending_recv_woken_on_sender_drop_returns_closed");
    }

    #[test]
    fn recv_cancelled_does_not_advance_cursor() {
        init_test("recv_cancelled_does_not_advance_cursor");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        cx.set_cancel_requested(true);
        let cancelled = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(cancelled, Err(RecvError::Cancelled)),
            "recv cancelled",
            "Err(Cancelled)",
            format!("{:?}", cancelled)
        );

        // Clear cancellation and ensure the cursor didn't advance past the first message.
        cx.set_cancel_requested(false);
        tx.send(&cx, 7).expect("send failed");
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 7, "received after cancel", 7, got);

        crate::test_complete!("recv_cancelled_does_not_advance_cursor");
    }

    /// br-asupersync-bed5oh: Sender::reserve must surface cancellation as
    /// SendError::Cancelled — the previous implementation only traced the
    /// cancel and granted the permit anyway, violating the documented
    /// "reserve is cancel-safe" contract.
    #[test]
    fn reserve_cancelled_returns_err_not_permit() {
        init_test("reserve_cancelled_returns_err_not_permit");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(10);
        // Drain initial state.
        let _ = rx;

        cx.set_cancel_requested(true);
        let result = tx.reserve(&cx);
        crate::assert_with_log!(
            matches!(result.as_ref(), Err(SendError::Cancelled(_))),
            "reserve under cancel must return Cancelled",
            "Err(Cancelled)",
            format!("{:?}", result.as_ref().map(|_| "Ok(permit)"))
        );

        // Sanity: clearing the cancel restores normal behavior.
        cx.set_cancel_requested(false);
        let permit = tx.reserve(&cx).expect("reserve should succeed after clear");
        drop(permit);

        crate::test_complete!("reserve_cancelled_returns_err_not_permit");
    }

    /// br-asupersync-bed5oh: Sender::send is the public hot path; verify
    /// it propagates Cancelled (and that no message is observed by any
    /// receiver in that case — the cancel signal cannot be smuggled
    /// across as data).
    #[test]
    fn send_cancelled_propagates_and_drops_message() {
        init_test("send_cancelled_propagates_and_drops_message");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        cx.set_cancel_requested(true);
        let result = tx.send(&cx, 99);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Cancelled(_))),
            "send under cancel must return Cancelled",
            "Err(Cancelled)",
            format!("{:?}", result)
        );

        // Receiver sees nothing — cancel did not silently push a message.
        cx.set_cancel_requested(false);
        let try_recv = rx.try_recv();
        crate::assert_with_log!(
            matches!(try_recv, Err(_)),
            "no message should have been buffered",
            "Err(_)",
            format!("{:?}", try_recv)
        );

        crate::test_complete!("send_cancelled_propagates_and_drops_message");
    }

    #[test]
    fn recv_cancelled_clears_waiter_registration() {
        init_test("recv_cancelled_clears_waiter_registration");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));

        // No message yet: should pend and register exactly one waiter.
        crate::assert_with_log!(
            matches!(fut.as_mut().poll(&mut ctx), Poll::Pending),
            "poll pending",
            true,
            true
        );
        let wakers_len = {
            let inner = tx.channel.inner.lock();
            inner.wakers.len()
        };
        crate::assert_with_log!(wakers_len == 1, "one waiter registered", 1usize, wakers_len);

        // Cancel: poll should return Cancelled and clear the waiter entry.
        cx.set_cancel_requested(true);
        let res = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(res, Poll::Ready(Err(RecvError::Cancelled))),
            "cancelled",
            "Ready(Err(Cancelled))",
            format!("{res:?}")
        );
        let cleared = {
            let inner = tx.channel.inner.lock();
            inner.wakers.is_empty()
        };
        crate::assert_with_log!(cleared, "waiter cleared", true, cleared);

        drop(fut);

        // Cursor must not have advanced.
        cx.set_cancel_requested(false);
        tx.send(&cx, 7).expect("send failed");
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 7, "received after cancel", 7, got);

        crate::test_complete!("recv_cancelled_clears_waiter_registration");
    }

    #[test]
    fn recv_drop_clears_waiter_registration() {
        init_test("recv_drop_clears_waiter_registration");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        {
            let mut fut = Box::pin(rx.recv(&cx));

            // No message yet: should pend and register exactly one waiter.
            crate::assert_with_log!(
                matches!(fut.as_mut().poll(&mut ctx), Poll::Pending),
                "poll pending",
                true,
                true
            );

            let wakers_len = {
                let inner = tx.channel.inner.lock();
                inner.wakers.len()
            };
            crate::assert_with_log!(wakers_len == 1, "one waiter registered", 1usize, wakers_len);
        } // drop fut

        let cleared = {
            let inner = tx.channel.inner.lock();
            inner.wakers.is_empty()
        };
        crate::assert_with_log!(cleared, "waiter cleared on drop", true, cleared);

        // Cursor must not have advanced.
        tx.send(&cx, 7).expect("send failed");
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 7, "received after drop", 7, got);

        crate::test_complete!("recv_drop_clears_waiter_registration");
    }

    #[test]
    fn recv_future_drop_retires_waker_outside_channel_lock() {
        init_test("recv_future_drop_retires_waker_outside_channel_lock");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);
        let (waker, drop_count, lock_was_free) = waker_drop_lock_probe(&tx);
        let mut fut = Box::pin(rx.recv(&cx));

        {
            let mut task_cx = Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut task_cx).is_pending());
        }
        drop(waker);
        drop(fut);

        assert_waker_dropped_outside_lock(&drop_count, &lock_was_free);
        crate::test_complete!("recv_future_drop_retires_waker_outside_channel_lock");
    }

    #[test]
    fn recv_cancellation_retires_waker_outside_channel_lock() {
        init_test("recv_cancellation_retires_waker_outside_channel_lock");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);
        let (waker, drop_count, lock_was_free) = waker_drop_lock_probe(&tx);
        let mut fut = Box::pin(rx.recv(&cx));

        {
            let mut task_cx = Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut task_cx).is_pending());
        }
        drop(waker);

        cx.set_cancel_requested(true);
        let noop = Waker::noop();
        let mut task_cx = Context::from_waker(noop);
        assert!(matches!(
            fut.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(RecvError::Cancelled))
        ));

        assert_waker_dropped_outside_lock(&drop_count, &lock_was_free);
        crate::test_complete!("recv_cancellation_retires_waker_outside_channel_lock");
    }

    #[test]
    fn recv_changed_waker_retires_previous_waker_outside_channel_lock() {
        init_test("recv_changed_waker_retires_previous_waker_outside_channel_lock");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);
        let (old_waker, drop_count, lock_was_free) = waker_drop_lock_probe(&tx);
        let mut fut = Box::pin(rx.recv(&cx));

        {
            let mut task_cx = Context::from_waker(&old_waker);
            assert!(fut.as_mut().poll(&mut task_cx).is_pending());
        }
        drop(old_waker);

        let new_wake_state = CountingWaker::new();
        let new_waker = Waker::from(new_wake_state);
        let mut task_cx = Context::from_waker(&new_waker);
        assert!(fut.as_mut().poll(&mut task_cx).is_pending());

        assert_waker_dropped_outside_lock(&drop_count, &lock_was_free);
        assert_eq!(tx.channel.inner.lock().wakers.len(), 1);
        crate::test_complete!("recv_changed_waker_retires_previous_waker_outside_channel_lock");
    }

    #[test]
    fn recv_value_cleanup_retires_waker_outside_channel_lock() {
        init_test("recv_value_cleanup_retires_waker_outside_channel_lock");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);
        let (waker, drop_count, lock_was_free) = waker_drop_lock_probe(&tx);
        let mut fut = Box::pin(rx.recv(&cx));

        {
            let mut task_cx = Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut task_cx).is_pending());
        }
        drop(waker);

        {
            let mut inner = tx.channel.inner.lock();
            inner.buffer.push_back(Slot {
                msg: Arc::new(Mutex::new(17)),
                index: 0,
            });
            inner.total_sent = 1;
        }

        let noop = Waker::noop();
        let mut task_cx = Context::from_waker(noop);
        assert!(matches!(
            fut.as_mut().poll(&mut task_cx),
            Poll::Ready(Ok(17))
        ));

        assert_waker_dropped_outside_lock(&drop_count, &lock_was_free);
        crate::test_complete!("recv_value_cleanup_retires_waker_outside_channel_lock");
    }

    #[test]
    fn recv_lag_cleanup_retires_waker_outside_channel_lock() {
        init_test("recv_lag_cleanup_retires_waker_outside_channel_lock");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(1);
        let (waker, drop_count, lock_was_free) = waker_drop_lock_probe(&tx);
        let mut fut = Box::pin(rx.recv(&cx));

        {
            let mut task_cx = Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut task_cx).is_pending());
        }
        drop(waker);

        {
            let mut inner = tx.channel.inner.lock();
            inner.buffer.push_back(Slot {
                msg: Arc::new(Mutex::new(29)),
                index: 1,
            });
            inner.total_sent = 2;
        }

        let noop = Waker::noop();
        let mut task_cx = Context::from_waker(noop);
        assert!(matches!(
            fut.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(RecvError::Lagged(1)))
        ));

        assert_waker_dropped_outside_lock(&drop_count, &lock_was_free);
        crate::test_complete!("recv_lag_cleanup_retires_waker_outside_channel_lock");
    }

    #[test]
    fn recv_closed_cleanup_retires_waker_outside_channel_lock() {
        init_test("recv_closed_cleanup_retires_waker_outside_channel_lock");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);
        let (waker, drop_count, lock_was_free) = waker_drop_lock_probe(&tx);
        let mut fut = Box::pin(rx.recv(&cx));

        {
            let mut task_cx = Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut task_cx).is_pending());
        }
        drop(waker);

        tx.channel.sender_count.store(0, Ordering::Release);
        let noop = Waker::noop();
        let mut task_cx = Context::from_waker(noop);
        assert!(matches!(
            fut.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(RecvError::Closed))
        ));
        tx.channel.sender_count.store(1, Ordering::Release);

        assert_waker_dropped_outside_lock(&drop_count, &lock_was_free);
        crate::test_complete!("recv_closed_cleanup_retires_waker_outside_channel_lock");
    }

    #[test]
    fn broadcast_cloned_sender_both_deliver() {
        init_test("broadcast_cloned_sender_both_deliver");
        let cx = test_cx();
        let (tx1, mut rx) = channel(10);
        let tx2 = tx1.clone();

        tx1.send(&cx, 1).unwrap();
        tx2.send(&cx, 2).unwrap();

        let first = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(first == 1, "first", 1, first);
        let second = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(second == 2, "second", 2, second);
        crate::test_complete!("broadcast_cloned_sender_both_deliver");
    }

    #[test]
    fn broadcast_heavy_lag_overwrite() {
        init_test("broadcast_heavy_lag_overwrite");
        let cx = test_cx();
        let (tx, mut rx) = channel(4);

        // Send 10 messages into capacity-4 buffer, overwriting 6.
        for i in 0..10 {
            tx.send(&cx, i).unwrap();
        }

        // First recv should detect lag.
        let result = block_on(rx.recv(&cx));
        match result {
            Err(RecvError::Lagged(n)) => {
                crate::assert_with_log!(n == 6, "lagged 6", 6u64, n);
            }
            other => unreachable!("expected lagged, got {other:?}"),
        }

        // Now should receive 6, 7, 8, 9.
        for expected in 6..10 {
            let got = block_on(rx.recv(&cx)).unwrap();
            crate::assert_with_log!(got == expected, "post-lag msg", expected, got);
        }

        crate::test_complete!("broadcast_heavy_lag_overwrite");
    }

    #[test]
    fn broadcast_clone_receiver_shares_position() {
        init_test("broadcast_clone_receiver_shares_position");
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);

        tx.send(&cx, 10).unwrap();
        tx.send(&cx, 20).unwrap();

        // Advance rx1 past the first message.
        let first = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(first == 10, "rx1 first", 10, first);

        // Clone after advancing — rx2 should start at the same cursor.
        let mut rx2 = rx1.clone();

        let rx1_second = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_second == 20, "rx1 second", 20, rx1_second);

        let rx2_second = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_second == 20, "rx2 second", 20, rx2_second);

        crate::test_complete!("broadcast_clone_receiver_shares_position");
    }

    #[test]
    fn broadcast_reserve_then_send() {
        init_test("broadcast_reserve_then_send");
        let cx = test_cx();
        let (tx, mut rx) = channel(10);

        let permit = tx.reserve(&cx).expect("reserve failed");
        let count = permit.send(42);
        crate::assert_with_log!(count == 1, "receiver count", 1usize, count);

        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 42, "received", 42, got);
        crate::test_complete!("broadcast_reserve_then_send");
    }

    #[test]
    fn broadcast_drop_all_senders_closes() {
        init_test("broadcast_drop_all_senders_closes");
        let cx = test_cx();
        let (tx1, mut rx) = channel::<i32>(10);
        let tx2 = tx1.clone();

        // Drop first sender — channel still open (tx2 alive).
        drop(tx1);

        tx2.send(&cx, 5).unwrap();
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 5, "still open", 5, got);

        // Drop last sender — channel closed.
        drop(tx2);
        let result = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(result, Err(RecvError::Closed)),
            "closed after all senders drop",
            true,
            true
        );
        crate::test_complete!("broadcast_drop_all_senders_closes");
    }

    #[test]
    fn broadcast_fan_out_under_lab_runtime() {
        init_test("broadcast_fan_out_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0xBADC_A571)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let checkpoints = Arc::new(StdMutex::new(Vec::<Value>::new()));

        let ((rx1_first, rx1_second), (rx2_first, rx2_second), checkpoints) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let sender_spawn_cx = cx.clone();
                let rx1_spawn_cx = cx.clone();
                let rx2_spawn_cx = cx.clone();

                let (tx, mut rx1) = channel(8);
                let mut rx2 = tx.subscribe();

                let sender_checkpoints = Arc::clone(&checkpoints);
                let sender = LabRuntimeTarget::spawn(&sender_spawn_cx, Budget::INFINITE, {
                    let tx = tx.clone();
                    let sender_task_cx = sender_spawn_cx.clone();
                    async move {
                        yield_now().await;

                        let permit = tx.reserve(&sender_task_cx).expect("reserve should succeed");
                        let first_receivers = permit.send(11);
                        let first = serde_json::json!({
                            "phase": "sent_first",
                            "value": 11,
                            "receivers": first_receivers,
                        });
                        tracing::info!(event = %first, "broadcast_lab_checkpoint");
                        sender_checkpoints.lock().unwrap().push(first);

                        let second_receivers =
                            tx.send(&sender_task_cx, 22).expect("send should succeed");
                        let second = serde_json::json!({
                            "phase": "sent_second",
                            "value": 22,
                            "receivers": second_receivers,
                        });
                        tracing::info!(event = %second, "broadcast_lab_checkpoint");
                        sender_checkpoints.lock().unwrap().push(second);
                    }
                });

                let rx1_checkpoints = Arc::clone(&checkpoints);
                let rx1_task = LabRuntimeTarget::spawn(&rx1_spawn_cx, Budget::INFINITE, {
                    let rx1_task_cx = rx1_spawn_cx.clone();
                    async move {
                        let first = rx1.recv(&rx1_task_cx).await.expect("rx1 first receive");
                        let first_event = serde_json::json!({
                            "phase": "rx1_first",
                            "value": first,
                        });
                        tracing::info!(event = %first_event, "broadcast_lab_checkpoint");
                        rx1_checkpoints.lock().unwrap().push(first_event);

                        let second = rx1.recv(&rx1_task_cx).await.expect("rx1 second receive");
                        let second_event = serde_json::json!({
                            "phase": "rx1_second",
                            "value": second,
                        });
                        tracing::info!(event = %second_event, "broadcast_lab_checkpoint");
                        rx1_checkpoints.lock().unwrap().push(second_event);

                        (first, second)
                    }
                });

                let rx2_checkpoints = Arc::clone(&checkpoints);
                let rx2_task = LabRuntimeTarget::spawn(&rx2_spawn_cx, Budget::INFINITE, {
                    let rx2_task_cx = rx2_spawn_cx.clone();
                    async move {
                        let first = rx2.recv(&rx2_task_cx).await.expect("rx2 first receive");
                        let first_event = serde_json::json!({
                            "phase": "rx2_first",
                            "value": first,
                        });
                        tracing::info!(event = %first_event, "broadcast_lab_checkpoint");
                        rx2_checkpoints.lock().unwrap().push(first_event);

                        let second = rx2.recv(&rx2_task_cx).await.expect("rx2 second receive");
                        let second_event = serde_json::json!({
                            "phase": "rx2_second",
                            "value": second,
                        });
                        tracing::info!(event = %second_event, "broadcast_lab_checkpoint");
                        rx2_checkpoints.lock().unwrap().push(second_event);

                        (first, second)
                    }
                });

                let sender_outcome = sender.await;
                crate::assert_with_log!(
                    matches!(sender_outcome, crate::types::Outcome::Ok(())),
                    "sender task completes successfully",
                    true,
                    matches!(sender_outcome, crate::types::Outcome::Ok(()))
                );

                let rx1_outcome = rx1_task.await;
                crate::assert_with_log!(
                    matches!(rx1_outcome, crate::types::Outcome::Ok(_)),
                    "rx1 task completes successfully",
                    true,
                    matches!(rx1_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(rx1_values) = rx1_outcome else {
                    panic!("rx1 task should finish successfully");
                };

                let rx2_outcome = rx2_task.await;
                crate::assert_with_log!(
                    matches!(rx2_outcome, crate::types::Outcome::Ok(_)),
                    "rx2 task completes successfully",
                    true,
                    matches!(rx2_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(rx2_values) = rx2_outcome else {
                    panic!("rx2 task should finish successfully");
                };

                (rx1_values, rx2_values, checkpoints.lock().unwrap().clone())
            });

        assert_eq!((rx1_first, rx1_second), (11, 22));
        assert_eq!((rx2_first, rx2_second), (11, 22));
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "sent_first"),
            "first send checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "rx1_second"),
            "rx1 second receive checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "rx2_second"),
            "rx2 second receive checkpoint should be recorded"
        );
        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "broadcast lab-runtime fan-out test should leave runtime invariants clean: {violations:?}"
        );
    }

    #[test]
    fn recv_closed_clears_waiter_registration() {
        init_test("recv_closed_clears_waiter_registration");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        // Poll to register a waiter (no messages available).
        let mut fut = Box::pin(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(fut.as_mut().poll(&mut ctx), Poll::Pending),
            "poll pending",
            true,
            true
        );
        let wakers_len = {
            let inner = tx.channel.inner.lock();
            inner.wakers.len()
        };
        crate::assert_with_log!(wakers_len == 1, "one waiter registered", 1usize, wakers_len);

        // Drop sender — channel closes, retain() wakes and removes all waiters.
        drop(tx);

        // Re-poll: should return Closed and clear the stale waiter token.
        let res = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(res, Poll::Ready(Err(RecvError::Closed))),
            "closed",
            "Ready(Err(Closed))",
            format!("{res:?}")
        );

        // Drop the future — Drop handler should not panic even though
        // the waiter was already removed by retain() + cleared by poll.
        drop(fut);

        crate::test_complete!("recv_closed_clears_waiter_registration");
    }

    #[test]
    fn recv_second_poll_after_ok_fails_closed() {
        init_test("recv_second_poll_after_ok_fails_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);
        tx.send(&cx, 42).expect("send failed");

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(42))),
            "first poll receives value",
            "Poll::Ready(Ok(42))",
            format!("{first:?}")
        );

        let second = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "second poll fails closed",
            "Poll::Ready(Err(PolledAfterCompletion))",
            format!("{second:?}")
        );

        crate::test_complete!("recv_second_poll_after_ok_fails_closed");
    }

    #[test]
    fn recv_second_poll_after_lagged_fails_closed() {
        init_test("recv_second_poll_after_lagged_fails_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(2);
        tx.send(&cx, 1).expect("send failed");
        tx.send(&cx, 2).expect("send failed");
        tx.send(&cx, 3).expect("send failed");

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        {
            let mut fut = std::pin::pin!(rx.recv(&cx));

            let first = fut.as_mut().poll(&mut ctx);
            crate::assert_with_log!(
                matches!(first, Poll::Ready(Err(RecvError::Lagged(1)))),
                "first poll reports lag",
                "Poll::Ready(Err(Lagged(1)))",
                format!("{first:?}")
            );

            let second = fut.as_mut().poll(&mut ctx);
            crate::assert_with_log!(
                matches!(second, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
                "second poll fails closed after lag",
                "Poll::Ready(Err(PolledAfterCompletion))",
                format!("{second:?}")
            );
        }

        let next = block_on(rx.recv(&cx))
            .expect("new recv future should continue from lag-adjusted cursor");
        crate::assert_with_log!(
            next == 2,
            "next recv continues at earliest retained item",
            2,
            next
        );

        crate::test_complete!("recv_second_poll_after_lagged_fails_closed");
    }

    #[test]
    fn recv_second_poll_after_closed_fails_closed() {
        init_test("recv_second_poll_after_closed_fails_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);
        drop(tx);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(RecvError::Closed))),
            "first poll reports closed",
            "Poll::Ready(Err(Closed))",
            format!("{first:?}")
        );

        let second = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "second poll fails closed after close",
            "Poll::Ready(Err(PolledAfterCompletion))",
            format!("{second:?}")
        );

        crate::test_complete!("recv_second_poll_after_closed_fails_closed");
    }

    #[test]
    fn recv_second_poll_after_cancelled_fails_closed() {
        init_test("recv_second_poll_after_cancelled_fails_closed");
        let cx = test_cx();
        let (_tx, mut rx) = channel::<i32>(4);
        cx.set_cancel_requested(true);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(RecvError::Cancelled))),
            "first poll reports cancelled",
            "Poll::Ready(Err(Cancelled))",
            format!("{first:?}")
        );

        let second = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "second poll fails closed after cancellation",
            "Poll::Ready(Err(PolledAfterCompletion))",
            format!("{second:?}")
        );

        crate::test_complete!("recv_second_poll_after_cancelled_fails_closed");
    }

    #[test]
    fn permit_send_after_last_receiver_drop_is_noop() {
        init_test("permit_send_after_last_receiver_drop_is_noop");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(4);

        let permit = tx.reserve(&cx).expect("reserve should succeed");
        drop(rx);

        let delivered = permit.send(42);
        crate::assert_with_log!(delivered == 0, "delivered count", 0usize, delivered);

        let inner = tx.channel.inner.lock();
        crate::assert_with_log!(
            inner.total_sent == 0,
            "total_sent unchanged",
            0u64,
            inner.total_sent
        );
        crate::assert_with_log!(
            inner.buffer.is_empty(),
            "buffer remains empty",
            true,
            inner.buffer.is_empty()
        );
        drop(inner);

        let closed = tx.send(&cx, 7);
        crate::assert_with_log!(
            matches!(closed, Err(SendError::Closed(7))),
            "send sees closed after receiver drop",
            "Err(Closed(7))",
            format!("{closed:?}")
        );

        crate::test_complete!("permit_send_after_last_receiver_drop_is_noop");
    }

    #[test]
    fn try_recv_clones_message_outside_lock_and_allows_sender_reentry() {
        init_test("try_recv_clones_message_outside_lock_and_allows_sender_reentry");
        let cx = test_cx();
        let (tx, mut rx) = channel::<CloneReentryMsg>(1);
        let (request_tx, request_rx) = std::sync::mpsc::sync_channel(1);
        let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
        let response_rx = Arc::new(StdMutex::new(response_rx));

        let reentrant_tx = tx.clone();
        let reentry = std::thread::spawn(move || {
            request_rx.recv().expect("clone re-entry request");
            let len = reentrant_tx.len();
            response_tx.send(len).expect("clone re-entry response");
        });

        tx.send(
            &cx,
            CloneReentryMsg {
                value: 17,
                request_tx,
                response_rx,
            },
        )
        .expect("send failed");

        let received = rx.try_recv().expect("try_recv failed");
        reentry.join().expect("Sender::len re-entry panicked");
        crate::assert_with_log!(
            received.value == 17,
            "try_recv returns message after clone re-entry",
            17,
            received.value
        );

        crate::test_complete!("try_recv_clones_message_outside_lock_and_allows_sender_reentry");
    }

    #[test]
    fn retained_payload_preserves_send_only_type_contract() {
        init_test("retained_payload_preserves_send_only_type_contract");

        #[derive(Clone)]
        struct SendButNotSync(std::cell::Cell<u8>);

        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}

        assert_send_sync::<Sender<SendButNotSync>>();
        assert_send::<Receiver<SendButNotSync>>();

        let value = SendButNotSync(std::cell::Cell::new(7));
        crate::assert_with_log!(
            value.0.get() == 7,
            "send-only fixture remains usable",
            7,
            value.0.get()
        );
        crate::test_complete!("retained_payload_preserves_send_only_type_contract");
    }

    #[test]
    fn recv_clone_panic_preserves_receiver_cursor() {
        init_test("recv_clone_panic_preserves_receiver_cursor");
        let cx = test_cx();
        let (tx, mut rx) = channel::<PanicOnceCloneMsg>(1);
        let clone_attempts = Arc::new(AtomicUsize::new(0));
        tx.send(
            &cx,
            PanicOnceCloneMsg {
                value: 23,
                clone_attempts: Arc::clone(&clone_attempts),
            },
        )
        .expect("send failed");

        let first =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| block_on(rx.recv(&cx))));
        crate::assert_with_log!(first.is_err(), "first clone panics", true, first.is_err());

        let recorded_cursor = {
            let inner = tx.channel.inner.lock();
            inner.receiver_cursors.get(rx.receiver_token).copied()
        };
        crate::assert_with_log!(
            rx.next_index == 0 && recorded_cursor == Some(0),
            "clone panic leaves receiver cursor unchanged",
            "next_index=0, recorded=Some(0)",
            format!("next_index={}, recorded={recorded_cursor:?}", rx.next_index)
        );

        let received = block_on(rx.recv(&cx)).expect("retry after clone panic failed");
        crate::assert_with_log!(
            received.value == 23 && rx.next_index == 1,
            "retry delivers the same retained message",
            "value=23, next_index=1",
            format!("value={}, next_index={}", received.value, rx.next_index)
        );

        crate::test_complete!("recv_clone_panic_preserves_receiver_cursor");
    }

    #[test]
    fn recv_retains_message_across_eviction_during_out_of_lock_clone() {
        init_test("recv_retains_message_across_eviction_during_out_of_lock_clone");
        let cx = test_cx();
        let (tx, rx) = channel::<CloneGateMsg>(1);
        let (blocker, clone_entered_rx, clone_release_tx) = CloneBlocker::new();
        tx.send(
            &cx,
            CloneGateMsg {
                value: 1,
                blocker: Some(blocker),
            },
        )
        .expect("initial send failed");

        let (recv_done_tx, recv_done_rx) = std::sync::mpsc::sync_channel(1);
        let recv_handle = std::thread::spawn(move || {
            let cx = test_cx();
            let mut rx = rx;
            let result = block_on(rx.recv(&cx)).map(|msg| msg.value);
            recv_done_tx
                .send((rx, result))
                .expect("receive completion send");
        });

        clone_entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("message clone did not reach blocking point");

        let tx_thread = tx.clone();
        let (send_done_tx, send_done_rx) = std::sync::mpsc::sync_channel(1);
        let send_handle = std::thread::spawn(move || {
            let cx = test_cx();
            let result = tx_thread.send(
                &cx,
                CloneGateMsg {
                    value: 2,
                    blocker: None,
                },
            );
            send_done_tx.send(result).expect("send completion signal");
        });

        let send_before_clone_release = send_done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .ok();
        let send_completed_before_clone_release = send_before_clone_release.is_some();
        clone_release_tx.send(()).expect("release blocked clone");
        let send_result = match send_before_clone_release {
            Some(result) => result,
            None => send_done_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("send remained blocked after clone release"),
        };

        send_handle.join().expect("sender thread panicked");
        let (mut rx, first_result) = recv_done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("receive remained blocked after clone release");
        recv_handle.join().expect("receiver thread panicked");

        crate::assert_with_log!(
            send_completed_before_clone_release,
            "concurrent eviction completes while Clone is blocked",
            true,
            send_completed_before_clone_release
        );
        crate::assert_with_log!(
            matches!(&send_result, Ok(1)) && first_result == Ok(1),
            "evicted retained message is delivered",
            "send=Ok(1), recv=Ok(1)",
            format!("send={send_result:?}, recv={first_result:?}")
        );

        let second = rx.try_recv().map(|msg| msg.value);
        crate::assert_with_log!(
            second == Ok(2),
            "receiver continues with concurrently committed message",
            "Ok(2)",
            format!("{second:?}")
        );

        crate::test_complete!("recv_retains_message_across_eviction_during_out_of_lock_clone");
    }

    #[test]
    fn send_rollback_drops_uncommitted_message_outside_lock() {
        init_test("send_rollback_drops_uncommitted_message_outside_lock");
        let cx = test_cx();
        let (tx, rx) = channel::<DropReentryMsg>(1);
        let permit = tx.reserve(&cx).expect("reserve failed");
        let (request_tx, request_rx) = std::sync::mpsc::sync_channel(1);
        let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);

        let reentrant_tx = tx.clone();
        let reentry = std::thread::spawn(move || {
            request_rx.recv().expect("drop re-entry request");
            let len = reentrant_tx.len();
            response_tx.send(len).expect("drop re-entry response");
        });

        let delivered = permit.send_forcing_zero_at_final_liveness(DropReentryMsg {
            request_tx: Some(request_tx),
            response_rx: Arc::new(StdMutex::new(response_rx)),
        });
        reentry.join().expect("Sender::len from Drop panicked");

        crate::assert_with_log!(
            delivered == 0,
            "send rolls back after final receiver snapshot reaches zero",
            0usize,
            delivered
        );
        let inner = tx.channel.inner.lock();
        crate::assert_with_log!(
            inner.total_sent == 0 && inner.buffer.is_empty(),
            "rollback restores channel state",
            "total_sent=0, buffer empty",
            format!(
                "total_sent={}, buffer_len={}",
                inner.total_sent,
                inner.buffer.len()
            )
        );
        drop(inner);

        drop(rx);

        crate::test_complete!("send_rollback_drops_uncommitted_message_outside_lock");
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn total_sent_advances_even_when_buffer_evicts() {
        // Verify total_sent is a monotonic sequence number independent of buffer size.
        init_test("total_sent_advances_even_when_buffer_evicts");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(2);

        for i in 0..10 {
            tx.send(&cx, i).unwrap();
        }

        let (total_sent, buffer_len, first_idx) = {
            let inner = tx.channel.inner.lock();
            (
                inner.total_sent,
                inner.buffer.len(),
                inner.buffer.front().unwrap().index,
            )
        };
        crate::assert_with_log!(total_sent == 10, "total_sent", 10u64, total_sent);
        crate::assert_with_log!(buffer_len == 2, "buffer len", 2usize, buffer_len);
        // Buffer should hold the last 2 messages (indices 8, 9).
        crate::assert_with_log!(first_idx == 8, "first buffer index", 8u64, first_idx);
        crate::test_complete!("total_sent_advances_even_when_buffer_evicts");
    }

    #[test]
    fn subscribe_from_lagged_position_gets_only_future() {
        // New subscribers should only see messages sent after subscription.
        init_test("subscribe_from_lagged_position_gets_only_future");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(4);

        // Send some messages before subscribing.
        for i in 0..5 {
            tx.send(&cx, i).unwrap();
        }

        let mut rx2 = tx.subscribe();

        // rx2 shouldn't see any existing messages (it starts at total_sent=5).
        tx.send(&cx, 99).unwrap();
        let got = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 99, "subscriber sees only future", 99, got);
        crate::test_complete!("subscribe_from_lagged_position_gets_only_future");
    }

    #[test]
    fn multiple_receivers_independent_lag() {
        // Each receiver tracks its own lag independently.
        init_test("multiple_receivers_independent_lag");
        let cx = test_cx();
        let (tx, mut rx1) = channel::<i32>(2);
        let mut rx2 = tx.subscribe();

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap();

        // Advance rx1 but not rx2.
        let v = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(v == 1, "rx1 reads 1", 1, v);

        // Overwrite buffer.
        tx.send(&cx, 3).unwrap(); // evicts 1

        // rx1 should get 2 (still in buffer).
        let v = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(v == 2, "rx1 reads 2", 2, v);

        // rx2 has next_index=0, but earliest is now 1 → lagged by 1.
        let result = block_on(rx2.recv(&cx));
        let lagged_ok = matches!(result, Err(RecvError::Lagged(1)));
        crate::assert_with_log!(lagged_ok, "rx2 lagged by 1", true, lagged_ok);
        crate::test_complete!("multiple_receivers_independent_lag");
    }

    #[test]
    fn permit_send_returns_zero_after_all_receivers_drop() {
        // Verify that SendPermit::send does not mutate state when no receivers.
        init_test("permit_send_returns_zero_after_all_receivers_drop");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(4);
        let permit = tx.reserve(&cx).expect("reserve");

        drop(rx);
        let count = permit.send(42);
        crate::assert_with_log!(count == 0, "no receivers", 0usize, count);

        // total_sent and buffer should be untouched.
        let (total_sent, buffer_empty) = {
            let inner = tx.channel.inner.lock();
            (inner.total_sent, inner.buffer.is_empty())
        };
        crate::assert_with_log!(total_sent == 0, "total_sent", 0u64, total_sent);
        crate::assert_with_log!(buffer_empty, "buffer empty", true, buffer_empty);
        crate::test_complete!("permit_send_returns_zero_after_all_receivers_drop");
    }

    #[test]
    fn permit_send_does_not_commit_if_last_receiver_drops_while_waiting_for_lock() {
        // Regression: if `SendPermit::send` checks receiver_count before taking
        // the channel lock, it can commit after the last receiver has dropped.
        init_test("permit_send_does_not_commit_if_last_receiver_drops_while_waiting_for_lock");
        let (tx, rx) = channel::<i32>(4);

        // Hold the channel lock so the sender thread blocks in `send`.
        let lock_guard = tx.channel.inner.lock();

        let tx_thread = tx.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (go_tx, go_rx) = std::sync::mpsc::sync_channel(1);
        let (send_entered_tx, send_entered_rx) = std::sync::mpsc::sync_channel(1);

        let handle = std::thread::spawn(move || {
            let cx = test_cx();
            let permit = tx_thread
                .reserve(&cx)
                .expect("reserve should succeed before receiver drop");
            ready_tx.send(()).expect("ready send");
            go_rx.recv().expect("go recv");
            // Synchronize with the main thread so we avoid timing-based sleeps.
            send_entered_tx.send(()).expect("send_entered send");
            permit.send(99)
        });

        ready_rx.recv().expect("ready recv");
        go_tx.send(()).expect("go send");
        send_entered_rx.recv().expect("send_entered recv");

        let drop_handle = std::thread::spawn(move || {
            drop(rx);
        });

        // Wait for receiver count to drop to 0 before releasing the lock.
        // This ensures the sender thread (waiting on the lock) will see count == 0.
        while tx
            .channel
            .receiver_count
            .load(std::sync::atomic::Ordering::Acquire)
            > 0
        {
            std::thread::yield_now();
        }

        drop(lock_guard);
        drop_handle.join().expect("drop thread panicked");

        let delivered = handle.join().expect("sender thread panicked");
        crate::assert_with_log!(
            delivered == 0,
            "delivered count after last receiver drop",
            0usize,
            delivered
        );

        let (total_sent, buffer_empty) = {
            let inner = tx.channel.inner.lock();
            (inner.total_sent, inner.buffer.is_empty())
        };
        crate::assert_with_log!(
            total_sent == 0,
            "total_sent unchanged after lock-contention drop race",
            0u64,
            total_sent
        );
        crate::assert_with_log!(
            buffer_empty,
            "buffer remains empty after lock-contention drop race",
            true,
            buffer_empty
        );

        crate::test_complete!(
            "permit_send_does_not_commit_if_last_receiver_drops_while_waiting_for_lock"
        );
    }

    #[test]
    fn subscribe_reactivating_zero_receivers_drops_stale_buffer_outside_lock() {
        init_test("subscribe_reactivating_zero_receivers_drops_stale_buffer_outside_lock");
        let cx = test_cx();
        let (tx, rx) = channel::<GateMsg>(1);
        let (blocker, entered_rx, release_tx) = DropBlocker::new();

        tx.send(&cx, GateMsg::Blocking(blocker))
            .expect("send failed");

        // Model the race window where the last receiver has already decremented
        // the count to zero, but its buffer-clear path has not acquired `inner`
        // yet. We intentionally forget the old receiver so this state remains
        // stable for the deterministic regression test.
        std::mem::forget(rx); // ubs:ignore - intentional memory leak for testing
        tx.channel.receiver_count.store(0, Ordering::Release);

        let tx_thread = tx.clone();
        let handle = std::thread::spawn(move || tx_thread.subscribe());

        let drop_started = entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();

        let lock_free_during_drop = drop_started && tx.channel.inner.try_lock().is_some();
        let _ = release_tx.send(());
        let mut rx2 = handle.join().expect("subscribe thread panicked");

        crate::assert_with_log!(
            drop_started,
            "subscribe drops stale buffer",
            true,
            drop_started
        );
        crate::assert_with_log!(
            lock_free_during_drop,
            "subscribe drops stale buffer outside lock",
            true,
            lock_free_during_drop
        );

        tx.send(&cx, GateMsg::Plain(7)).expect("send failed");
        let got = block_on(rx2.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(
            matches!(got, GateMsg::Plain(7)),
            "reactivated subscriber sees future message",
            true,
            matches!(got, GateMsg::Plain(7))
        );

        crate::test_complete!(
            "subscribe_reactivating_zero_receivers_drops_stale_buffer_outside_lock"
        );
    }

    #[test]
    fn capacity_one_overwrites_correctly() {
        // Edge case: capacity=1 means every send overwrites the previous.
        init_test("capacity_one_overwrites_correctly");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(1);

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap(); // evicts 1
        tx.send(&cx, 3).unwrap(); // evicts 2

        // rx should detect lag (missed 1 and 2).
        let result = block_on(rx.recv(&cx));
        let lagged_ok = matches!(result, Err(RecvError::Lagged(2)));
        crate::assert_with_log!(lagged_ok, "lagged by 2", true, lagged_ok);

        // Then receive 3.
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 3, "last message", 3, got);
        crate::test_complete!("capacity_one_overwrites_correctly");
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn recv_large_delta_does_not_truncate_offset() {
        // Regression: on 32-bit, casting `u64` delta to `usize` truncated and
        // could incorrectly return a buffered message at offset 0.
        init_test("recv_large_delta_does_not_truncate_offset");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(2);
        tx.send(&cx, 7).unwrap();

        // Simulate a receiver cursor far beyond the current window.
        rx.next_index = u64::from(u32::MAX) + 1;

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));
        let pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(pending, "poll pending", true, pending);

        crate::test_complete!("recv_large_delta_does_not_truncate_offset");
    }

    // =========================================================================
    // Wave 48 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn send_error_debug_clone_eq_display() {
        let e = SendError::Closed(42);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Closed"), "{dbg}");
        assert!(dbg.contains("42"), "{dbg}");
        let display = format!("{e}");
        assert!(display.contains("closed broadcast channel"), "{display}");
        let cloned = e.clone();
        assert_eq!(cloned, e);
        let err: &dyn std::error::Error = &e;
        assert!(err.source().is_none());
    }

    #[test]
    fn recv_error_debug_clone_copy_eq_display() {
        let errors = [
            RecvError::Lagged(5),
            RecvError::Closed,
            RecvError::Cancelled,
            RecvError::PolledAfterCompletion,
        ];
        let expected_display = [
            "receiver lagged by 5 messages",
            "broadcast channel closed",
            "[ASUP-E203] receive operation cancelled",
            "broadcast receive future polled after completion",
        ];
        for (e, expected) in errors.iter().zip(expected_display.iter()) {
            let copied = *e;
            let cloned = *e;
            assert_eq!(copied, cloned);
            assert!(!format!("{e:?}").is_empty());
            assert_eq!(format!("{e}"), *expected);
        }
        assert_ne!(errors[0], errors[1]);
        assert_ne!(errors[1], errors[2]);
    }

    // ---- Tests for new public APIs: try_recv, receiver_count, len, is_empty ----

    #[test]
    fn try_recv_empty_returns_empty() {
        init_test("broadcast_try_recv_empty");
        let (_tx, mut rx) = channel::<i32>(16);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn try_recv_returns_message() {
        init_test("broadcast_try_recv_message");
        let cx = test_cx();
        let (tx, mut rx) = channel(16);
        tx.send(&cx, 42).expect("send");
        assert_eq!(rx.try_recv(), Ok(42));
        // Second try_recv should be empty
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn try_recv_fifo_ordering() {
        init_test("broadcast_try_recv_fifo");
        let cx = test_cx();
        let (tx, mut rx) = channel(16);
        tx.send(&cx, 1).expect("send 1");
        tx.send(&cx, 2).expect("send 2");
        tx.send(&cx, 3).expect("send 3");
        assert_eq!(rx.try_recv(), Ok(1));
        assert_eq!(rx.try_recv(), Ok(2));
        assert_eq!(rx.try_recv(), Ok(3));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn try_recv_closed_after_drain() {
        init_test("broadcast_try_recv_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel(16);
        tx.send(&cx, 99).expect("send");
        drop(tx);
        // First try_recv drains the buffered message.
        assert_eq!(rx.try_recv(), Ok(99));
        // Now closed.
        assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));
    }

    #[test]
    fn try_recv_lagged_receiver() {
        init_test("broadcast_try_recv_lagged");
        let cx = test_cx();
        let (tx, mut rx) = channel(2);
        // Send 3 messages into a capacity-2 channel; first is evicted.
        tx.send(&cx, 10).expect("send 1");
        tx.send(&cx, 20).expect("send 2");
        tx.send(&cx, 30).expect("send 3");
        // Receiver was at index 0, earliest now at 1 → lagged by 1.
        let err = rx.try_recv();
        assert_eq!(err, Err(TryRecvError::Lagged(1)));
        // After lag, cursor is advanced; next try_recv should succeed.
        assert_eq!(rx.try_recv(), Ok(20));
        assert_eq!(rx.try_recv(), Ok(30));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn receiver_count_tracks_active_receivers() {
        init_test("broadcast_receiver_count");
        let (tx, rx1) = channel::<i32>(16);
        assert_eq!(tx.receiver_count(), 1);

        let rx2 = tx.subscribe();
        assert_eq!(tx.receiver_count(), 2);

        let rx3 = rx1.clone();
        assert_eq!(tx.receiver_count(), 3);

        drop(rx2);
        assert_eq!(tx.receiver_count(), 2);

        drop(rx1);
        drop(rx3);
        assert_eq!(tx.receiver_count(), 0);
    }

    #[test]
    fn telemetry_receiver_count_tracks_active_receivers() {
        init_test("broadcast_telemetry_receiver_count");
        let (tx, rx1) = channel::<i32>(16);

        let initial = tx.telemetry_snapshot(7);
        assert_eq!(initial.receiver_count, 1);
        assert!(!initial.closed);

        let rx2 = tx.subscribe();
        let rx3 = rx1.clone();

        let with_subscribers = tx.telemetry_snapshot(7);
        assert_eq!(with_subscribers.receiver_count, 3);
        assert!(!with_subscribers.closed);

        drop(rx2);
        let after_drop = tx.telemetry_snapshot(7);
        assert_eq!(after_drop.receiver_count, 2);
        assert!(!after_drop.closed);

        drop(rx1);
        drop(rx3);
        let closed = tx.telemetry_snapshot(7);
        assert_eq!(closed.receiver_count, 0);
        assert!(closed.closed);
        crate::test_complete!("broadcast_telemetry_receiver_count");
    }

    #[test]
    fn telemetry_unread_value_stays_ready_after_last_sender_drops() {
        init_test("broadcast_telemetry_unread_after_sender_close");
        let cx = test_cx();
        let (tx, mut rx) = channel(2);
        tx.send(&cx, 11).expect("send");

        let open = rx.telemetry_snapshot(11);
        assert_eq!(open.queued_messages, 1);
        assert_eq!(open.receiver_health, "value_ready");
        assert!(!open.closed);

        drop(tx);

        let closed = rx.telemetry_snapshot(11);
        assert_eq!(closed.queued_messages, 1);
        assert_eq!(closed.receiver_health, "value_ready");
        assert!(closed.closed);
        assert_eq!(rx.try_recv(), Ok(11));
        crate::test_complete!("broadcast_telemetry_unread_after_sender_close");
    }

    #[test]
    fn telemetry_reports_sender_closed_after_receiver_drains_retained_value() {
        init_test("broadcast_telemetry_drained_after_sender_close");
        let cx = test_cx();
        let (tx, mut rx) = channel(2);
        tx.send(&cx, 11).expect("send");
        assert_eq!(rx.try_recv(), Ok(11));

        let retained = rx.telemetry_snapshot(12);
        assert_eq!(retained.queued_messages, 1);
        assert_eq!(retained.receiver_health, "caught_up");
        assert!(!retained.closed);

        drop(tx);

        let closed = rx.telemetry_snapshot(12);
        assert_eq!(closed.queued_messages, 1);
        assert_eq!(closed.receiver_health, "sender_closed");
        assert!(closed.closed);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));
        crate::test_complete!("broadcast_telemetry_drained_after_sender_close");
    }

    #[test]
    fn telemetry_preserves_lag_and_value_ready_transitions_after_sender_close() {
        init_test("broadcast_telemetry_lagged_sender_close");
        let cx = test_cx();
        let (tx, mut rx) = channel(2);
        tx.send(&cx, 10).expect("send 1");
        tx.send(&cx, 20).expect("send 2");
        tx.send(&cx, 30).expect("send 3");
        drop(tx);

        let lagged = rx.telemetry_snapshot(13);
        assert_eq!(lagged.queued_messages, 2);
        assert_eq!(lagged.lagged_receiver_count, Some(1));
        assert_eq!(lagged.receiver_health, "lagged");
        assert!(lagged.closed);

        assert_eq!(rx.try_recv(), Err(TryRecvError::Lagged(1)));
        let ready = rx.telemetry_snapshot(13);
        assert_eq!(ready.receiver_health, "value_ready");
        assert!(ready.closed);

        assert_eq!(rx.try_recv(), Ok(20));
        assert_eq!(rx.try_recv(), Ok(30));
        let drained = rx.telemetry_snapshot(13);
        assert_eq!(drained.queued_messages, 2);
        assert_eq!(drained.receiver_health, "sender_closed");
        assert!(drained.closed);
        crate::test_complete!("broadcast_telemetry_lagged_sender_close");
    }

    #[test]
    fn telemetry_receiver_drop_reports_closed_endpoint() {
        init_test("broadcast_telemetry_receiver_drop_closed_endpoint");
        let cx = test_cx();
        let (tx, rx) = channel(2);
        tx.send(&cx, 11).expect("send");
        drop(rx);

        let closed = tx.telemetry_snapshot(14);
        assert_eq!(closed.queued_messages, 0);
        assert_eq!(closed.receiver_count, 0);
        assert_eq!(closed.receiver_health, "receiver_dropped");
        assert!(closed.closed);
        crate::test_complete!("broadcast_telemetry_receiver_drop_closed_endpoint");
    }

    #[test]
    fn len_tracks_buffered_messages() {
        init_test("broadcast_len");
        let cx = test_cx();
        let (tx, mut rx) = channel(16);
        assert_eq!(tx.len(), 0);
        assert!(tx.is_empty());

        tx.send(&cx, 1).expect("send 1");
        assert_eq!(tx.len(), 1);
        assert!(!tx.is_empty());

        tx.send(&cx, 2).expect("send 2");
        assert_eq!(tx.len(), 2);

        // Consuming from rx doesn't shrink the buffer (broadcast semantics).
        let _ = rx.try_recv();
        // len counts buffer slots, which are only reclaimed on eviction.
        assert!(tx.len() >= 1);
    }

    #[test]
    fn len_caps_at_capacity_on_eviction() {
        init_test("broadcast_len_cap");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(3);
        tx.send(&cx, 1).expect("send 1");
        tx.send(&cx, 2).expect("send 2");
        tx.send(&cx, 3).expect("send 3");
        assert_eq!(tx.len(), 3);

        // Fourth send evicts the oldest.
        tx.send(&cx, 4).expect("send 4");
        assert_eq!(tx.len(), 3);
    }

    /// br-asupersync-lh4z78 L1: a capacity larger than any backlog, even
    /// `usize::MAX`, allocates as messages arrive. It used to panic with
    /// "capacity overflow" (or abort when a huge allocation failed).
    #[test]
    fn huge_capacity_allocates_lazily() {
        init_test("broadcast_huge_capacity");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(usize::MAX);
        for value in 0..3 {
            tx.send(&cx, value).expect("send");
        }
        assert_eq!(tx.len(), 3);
        for value in 0..3 {
            assert_eq!(rx.try_recv(), Ok(value));
        }
    }

    #[test]
    fn try_recv_error_traits() {
        init_test("broadcast_try_recv_error_traits");
        let errors = [
            TryRecvError::Empty,
            TryRecvError::Lagged(5),
            TryRecvError::Closed,
        ];
        let expected = [
            "broadcast channel empty",
            "receiver lagged by 5 messages",
            "broadcast channel closed",
        ];
        for (e, exp) in errors.iter().zip(expected.iter()) {
            let copied = *e;
            let cloned = *e;
            assert_eq!(copied, cloned);
            assert!(!format!("{e:?}").is_empty());
            assert_eq!(format!("{e}"), *exp);
        }
        assert_ne!(errors[0], errors[1]);
        assert_ne!(errors[1], errors[2]);
        // TryRecvError implements Error
        let _ = <TryRecvError as std::error::Error>::source(&errors[0]);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct BurstWraparoundSnapshot {
        lagged_by: u64,
        retained_values: Vec<i32>,
        retained_indices: Vec<u64>,
        total_sent: u64,
        earliest_index: u64,
    }

    fn capture_burst_wraparound_snapshot(
        capacity: usize,
        burst_chunks: &[usize],
        alternate_senders: bool,
        drain_fast_receiver_each_chunk: bool,
    ) -> (BurstWraparoundSnapshot, Vec<i32>) {
        let cx = test_cx();
        let (tx_primary, mut slow_rx) = channel::<i32>(capacity);
        let tx_secondary = tx_primary.clone();
        let mut fast_rx = drain_fast_receiver_each_chunk.then(|| tx_primary.subscribe());
        let mut fast_sequence = Vec::new();
        let mut next_value = 0i32;

        for &chunk_len in burst_chunks {
            for _ in 0..chunk_len {
                let sender = if alternate_senders && next_value % 2 != 0 {
                    &tx_secondary
                } else {
                    &tx_primary
                };
                sender.send(&cx, next_value).expect("send burst value");
                next_value += 1;
                // Interleave drain with send so the fast receiver never
                // falls behind the ring buffer's capacity window when a
                // single chunk exceeds `capacity`.
                if let Some(rx) = fast_rx.as_mut() {
                    fast_sequence.push(block_on(rx.recv(&cx)).expect("fast receiver keeps up"));
                }
            }
        }

        let (total_sent, earliest_index, retained_indices) = {
            let inner = tx_primary.channel.inner.lock();
            (
                inner.total_sent,
                inner
                    .buffer
                    .front()
                    .map_or(inner.total_sent, |slot| slot.index),
                inner
                    .buffer
                    .iter()
                    .map(|slot| slot.index)
                    .collect::<Vec<_>>(),
            )
        };

        let lagged_by = match slow_rx.try_recv() {
            Err(TryRecvError::Lagged(n)) => n,
            other => panic!("expected lagged receiver after burst wraparound, got {other:?}"),
        };

        let mut retained_values = Vec::new();
        loop {
            match slow_rx.try_recv() {
                Ok(value) => retained_values.push(value),
                Err(TryRecvError::Empty) => break,
                Err(other) => panic!("expected retained suffix or empty after lag, got {other:?}"),
            }
        }

        (
            BurstWraparoundSnapshot {
                lagged_by,
                retained_values,
                retained_indices,
                total_sent,
                earliest_index,
            },
            fast_sequence,
        )
    }

    // =========================================================================
    // METAMORPHIC TESTING SUITE (asupersync-xpzv2k)
    // =========================================================================

    /// MR1: Order Preservation (Equivalence Relation)
    /// All subscribers observe events in broadcast order under no-drop conditions.
    /// Transformation: Vary number of receivers, timing of subscription
    /// Relation: All receivers see messages in same FIFO order
    #[test]
    fn metamorphic_order_preservation_across_receivers() {
        init_test("metamorphic_order_preservation_across_receivers");
        let cx = test_cx();

        // Test various receiver counts and message sequences
        for num_receivers in 1..=5 {
            for num_messages in 2..=10 {
                let (tx, mut receivers) = {
                    let (tx, rx1) = channel::<i32>(num_messages + 2); // +2 to avoid lag
                    let mut receivers = vec![rx1];
                    for _ in 1..num_receivers {
                        receivers.push(tx.subscribe());
                    }
                    (tx, receivers)
                };

                // Send messages
                let messages: Vec<i32> = (0..num_messages)
                    .map(|x| i32::try_from(x).unwrap())
                    .collect();
                for &msg in &messages {
                    tx.send(&cx, msg).expect("send");
                }

                // Collect sequences from all receivers
                let mut sequences = Vec::new();
                for rx in &mut receivers {
                    let mut sequence = Vec::new();
                    for _ in 0..num_messages {
                        match block_on(rx.recv(&cx)) {
                            Ok(msg) => sequence.push(msg),
                            Err(e) => panic!("Unexpected recv error: {:?}", e),
                        }
                    }
                    sequences.push(sequence);
                }

                // METAMORPHIC RELATION: All sequences must be identical
                let first_sequence = &sequences[0];
                for (i, sequence) in sequences.iter().enumerate() {
                    crate::assert_with_log!(
                        sequence == first_sequence,
                        format!(
                            "order preservation rx{} vs rx0 ({}rx, {}msg)",
                            i, num_receivers, num_messages
                        ),
                        first_sequence.clone(),
                        sequence.clone()
                    );
                }

                // Verify order matches send order
                crate::assert_with_log!(
                    first_sequence == &messages,
                    format!(
                        "order matches send order ({}rx, {}msg)",
                        num_receivers, num_messages
                    ),
                    messages,
                    first_sequence.clone()
                );
            }
        }

        crate::test_complete!("metamorphic_order_preservation_across_receivers");
    }

    /// MR2: Lag Behavior Correctness (Domain-Specific Relation)
    /// Lagged subscribers see Lagged(n) error then resume with correct skip count.
    /// Transformation: Vary lag amounts and buffer capacities
    /// Relation: RecvError::Lagged(n) followed by correct post-lag message sequence
    #[test]
    fn metamorphic_lag_behavior_correctness() {
        init_test("metamorphic_lag_behavior_correctness");
        let cx = test_cx();

        // Test various capacity and overrun scenarios
        for capacity in 2..=6 {
            for overrun in 1..=8 {
                let (tx, mut rx_slow) = channel::<i32>(capacity);
                let mut rx_fast = tx.subscribe();

                // Send messages up to capacity
                for i in 0..capacity {
                    tx.send(&cx, i32::try_from(i).unwrap()).expect("send");
                }

                // Fast receiver consumes all
                for _ in 0..capacity {
                    block_on(rx_fast.recv(&cx)).expect("fast recv");
                }

                // Send overrun messages, causing lag for slow receiver
                for i in 0..overrun {
                    tx.send(&cx, i32::try_from(capacity + i).unwrap())
                        .expect("send overrun");
                }

                // METAMORPHIC RELATION: Slow receiver gets Lagged(overrun) then correct sequence
                let lag_result = block_on(rx_slow.recv(&cx));
                match lag_result {
                    Err(RecvError::Lagged(n)) => {
                        crate::assert_with_log!(
                            n == overrun as u64,
                            format!("lag count (cap={}, overrun={})", capacity, overrun),
                            overrun as u64,
                            n
                        );
                    }
                    other => panic!("Expected Lagged({}) but got: {:?}", overrun, other),
                }

                // After lag, the slow receiver resumes at the oldest
                // message still retained in the ring buffer. The buffer
                // holds the last `capacity` messages out of
                // `capacity + overrun` total sends, so the first visible
                // message is `overrun` (0-indexed).
                let remaining_count = capacity;
                let start_msg = overrun;
                for i in 0..remaining_count {
                    let received = block_on(rx_slow.recv(&cx)).expect("post-lag recv");
                    let expected = i32::try_from(start_msg + i).unwrap();
                    crate::assert_with_log!(
                        received == expected,
                        format!(
                            "post-lag message {} (cap={}, overrun={})",
                            i, capacity, overrun
                        ),
                        expected,
                        received
                    );
                }
            }
        }

        crate::test_complete!("metamorphic_lag_behavior_correctness");
    }

    /// MR2b: Slot Wraparound Under Burst (Equivalence Relation)
    /// Different burst chunking and sender/receiver perturbations preserve the
    /// same lag count and retained suffix once the ring buffer wraps.
    #[test]
    fn metamorphic_slot_wraparound_under_burst_preserves_suffix() {
        init_test("metamorphic_slot_wraparound_under_burst_preserves_suffix");

        for capacity in 2..=6usize {
            for wraps in 1..=4usize {
                let total_messages = capacity * (wraps + 1) + 1;
                let expected_lag = (total_messages - capacity) as u64;
                let expected_suffix: Vec<i32> = (i32::try_from(total_messages - capacity).unwrap()
                    ..i32::try_from(total_messages).unwrap())
                    .collect();
                let expected_indices: Vec<u64> =
                    ((total_messages - capacity) as u64..total_messages as u64).collect();

                let mut remaining = total_messages;
                let mut chunk_seed = wraps + 1;
                let mut irregular_chunks = Vec::new();
                while remaining > 0 {
                    let next = ((chunk_seed * 3) % (capacity + 2)).max(1);
                    let chunk_len = next.min(remaining);
                    irregular_chunks.push(chunk_len);
                    remaining -= chunk_len;
                    chunk_seed += 1;
                }

                let (base, _) =
                    capture_burst_wraparound_snapshot(capacity, &[total_messages], false, false);
                let (chunked, _) =
                    capture_burst_wraparound_snapshot(capacity, &irregular_chunks, false, false);
                let (perturbed, fast_sequence) =
                    capture_burst_wraparound_snapshot(capacity, &irregular_chunks, true, true);

                crate::assert_with_log!(
                    base.lagged_by == expected_lag,
                    format!("base lag count (cap={}, wraps={})", capacity, wraps),
                    expected_lag,
                    base.lagged_by
                );
                crate::assert_with_log!(
                    base.retained_values == expected_suffix,
                    format!("base suffix (cap={}, wraps={})", capacity, wraps),
                    expected_suffix.clone(),
                    base.retained_values.clone()
                );
                crate::assert_with_log!(
                    base.retained_indices == expected_indices,
                    format!("base indices (cap={}, wraps={})", capacity, wraps),
                    expected_indices.clone(),
                    base.retained_indices.clone()
                );
                crate::assert_with_log!(
                    base.total_sent == total_messages as u64,
                    format!("base total_sent (cap={}, wraps={})", capacity, wraps),
                    total_messages as u64,
                    base.total_sent
                );
                crate::assert_with_log!(
                    base.earliest_index == (total_messages - capacity) as u64,
                    format!("base earliest index (cap={}, wraps={})", capacity, wraps),
                    (total_messages - capacity) as u64,
                    base.earliest_index
                );

                crate::assert_with_log!(
                    chunked == base,
                    format!(
                        "chunked burst matches base (cap={}, wraps={})",
                        capacity, wraps
                    ),
                    format!("{base:?}"),
                    format!("{chunked:?}")
                );
                crate::assert_with_log!(
                    perturbed == base,
                    format!(
                        "sender/receiver perturbation matches base (cap={}, wraps={})",
                        capacity, wraps
                    ),
                    format!("{base:?}"),
                    format!("{perturbed:?}")
                );
                crate::assert_with_log!(
                    fast_sequence
                        == (0..i32::try_from(total_messages).unwrap()).collect::<Vec<_>>(),
                    format!(
                        "fast receiver keeps full order (cap={}, wraps={})",
                        capacity, wraps
                    ),
                    (0..i32::try_from(total_messages).unwrap()).collect::<Vec<_>>(),
                    fast_sequence
                );
            }
        }

        crate::test_complete!("metamorphic_slot_wraparound_under_burst_preserves_suffix");
    }

    /// MR3: Mid-Stream Subscription Isolation (Inclusive Relation)
    /// Receivers created mid-stream only see messages sent after subscription.
    /// Transformation: Vary timing of new receiver creation
    /// Relation: Early receivers see all messages, late receivers see subset
    #[test]
    fn metamorphic_midstream_subscription_isolation() {
        init_test("metamorphic_midstream_subscription_isolation");
        let cx = test_cx();

        for total_messages in 5..=15 {
            for split_point in 1..total_messages {
                let (tx, mut rx_early) = channel::<i32>(total_messages + 2);

                // Send first batch of messages
                for i in 0..split_point {
                    tx.send(&cx, i32::try_from(i).unwrap()).expect("send pre");
                }

                // Create mid-stream receiver
                let mut rx_late = tx.subscribe();

                // Send second batch of messages
                for i in split_point..total_messages {
                    tx.send(&cx, i32::try_from(i).unwrap()).expect("send post");
                }

                // Collect sequences
                let mut early_sequence = Vec::new();
                let mut late_sequence = Vec::new();

                for _ in 0..total_messages {
                    early_sequence.push(block_on(rx_early.recv(&cx)).expect("early recv"));
                }

                for _ in split_point..total_messages {
                    late_sequence.push(block_on(rx_late.recv(&cx)).expect("late recv"));
                }

                // METAMORPHIC RELATION: Late receiver sees subset of early receiver
                let expected_late: Vec<i32> = (i32::try_from(split_point).unwrap()
                    ..i32::try_from(total_messages).unwrap())
                    .collect();
                let expected_early: Vec<i32> =
                    (0..i32::try_from(total_messages).unwrap()).collect();

                crate::assert_with_log!(
                    early_sequence == expected_early,
                    format!(
                        "early receiver sees all (split={}/{})",
                        split_point, total_messages
                    ),
                    expected_early,
                    early_sequence
                );

                crate::assert_with_log!(
                    late_sequence == expected_late,
                    format!(
                        "late receiver sees subset (split={}/{})",
                        split_point, total_messages
                    ),
                    expected_late,
                    late_sequence
                );

                // Inclusion property: late sequence is suffix of early sequence
                let early_suffix = &early_sequence[split_point..];
                crate::assert_with_log!(
                    late_sequence == early_suffix,
                    format!(
                        "late sequence is suffix of early (split={}/{})",
                        split_point, total_messages
                    ),
                    early_suffix.to_vec(),
                    late_sequence
                );
            }
        }

        crate::test_complete!("metamorphic_midstream_subscription_isolation");
    }

    /// MR3b: Cancelled Receive Cursor Invariance (Equivalence Relation)
    /// Cancelling one receiver's queued recv must not perturb peer delivery,
    /// and the cancelled receiver must resume at the same cursor afterward.
    #[test]
    fn metamorphic_cancelled_recv_preserves_peer_delivery_counts() {
        init_test("metamorphic_cancelled_recv_preserves_peer_delivery_counts");

        for total_messages in 1..=8usize {
            let messages: Vec<i32> = (0..i32::try_from(total_messages).unwrap()).collect();

            for prefix_len in 0..total_messages {
                let baseline = {
                    let cx = test_cx();
                    let (tx, mut rx_cancelled) = channel::<i32>(total_messages + 2);
                    let mut rx_peer = tx.subscribe();

                    for &msg in &messages {
                        tx.send(&cx, msg).expect("baseline send");
                    }

                    let mut cancelled_sequence = Vec::new();
                    let mut peer_sequence = Vec::new();

                    for _ in 0..total_messages {
                        cancelled_sequence
                            .push(block_on(rx_cancelled.recv(&cx)).expect("baseline cancelled"));
                    }
                    for _ in 0..total_messages {
                        peer_sequence.push(block_on(rx_peer.recv(&cx)).expect("baseline peer"));
                    }

                    (cancelled_sequence, peer_sequence)
                };

                let transformed = {
                    let cx = test_cx();
                    let (tx, mut rx_cancelled) = channel::<i32>(total_messages + 2);
                    let mut rx_peer = tx.subscribe();

                    for &msg in &messages {
                        tx.send(&cx, msg).expect("transformed send");
                    }

                    let mut cancelled_prefix = Vec::new();
                    for _ in 0..prefix_len {
                        cancelled_prefix.push(
                            block_on(rx_cancelled.recv(&cx)).expect("transformed prefix recv"),
                        );
                    }

                    cx.set_cancel_requested(true);
                    let cancelled = block_on(rx_cancelled.recv(&cx));
                    crate::assert_with_log!(
                        matches!(cancelled, Err(RecvError::Cancelled)),
                        format!(
                            "queued recv cancelled (prefix={}/{})",
                            prefix_len, total_messages
                        ),
                        "Err(Cancelled)",
                        format!("{cancelled:?}")
                    );
                    cx.set_cancel_requested(false);

                    let mut peer_sequence = Vec::new();
                    for _ in 0..total_messages {
                        peer_sequence.push(block_on(rx_peer.recv(&cx)).expect("transformed peer"));
                    }

                    let mut cancelled_suffix = Vec::new();
                    for _ in prefix_len..total_messages {
                        cancelled_suffix.push(
                            block_on(rx_cancelled.recv(&cx)).expect("transformed suffix recv"),
                        );
                    }

                    cancelled_prefix.extend(cancelled_suffix);
                    (cancelled_prefix, peer_sequence)
                };

                crate::assert_with_log!(
                    transformed.0 == baseline.0,
                    format!(
                        "cancelled receiver transcript matches baseline (prefix={}/{})",
                        prefix_len, total_messages
                    ),
                    baseline.0.clone(),
                    transformed.0.clone()
                );
                crate::assert_with_log!(
                    transformed.1 == baseline.1,
                    format!(
                        "peer transcript matches baseline (prefix={}/{})",
                        prefix_len, total_messages
                    ),
                    baseline.1.clone(),
                    transformed.1.clone()
                );
                crate::assert_with_log!(
                    transformed.0 == messages,
                    format!(
                        "cancelled receiver delivery count preserved (prefix={}/{})",
                        prefix_len, total_messages
                    ),
                    messages.clone(),
                    transformed.0.clone()
                );
                crate::assert_with_log!(
                    transformed.1 == messages,
                    format!(
                        "peer delivery count preserved (prefix={}/{})",
                        prefix_len, total_messages
                    ),
                    messages.clone(),
                    transformed.1.clone()
                );
            }
        }

        crate::test_complete!("metamorphic_cancelled_recv_preserves_peer_delivery_counts");
    }

    /// MR4: Close Propagation (Equivalence Relation)
    /// Sender drop propagates Closed error to all active receivers.
    /// Transformation: Vary number of senders, timing of drops
    /// Relation: All receivers get Closed when last sender drops
    #[test]
    fn metamorphic_close_propagation() {
        init_test("metamorphic_close_propagation");
        let cx = test_cx();

        for num_senders in 1..=4 {
            for num_receivers in 1..=4 {
                let (tx1, mut receivers) = {
                    let (tx, rx1) = channel::<i32>(10);
                    let mut receivers = vec![rx1];
                    for _ in 1..num_receivers {
                        receivers.push(tx.subscribe());
                    }
                    (tx, receivers)
                };

                // Create additional senders
                let mut senders = vec![tx1];
                for _ in 1..num_senders {
                    senders.push(senders[0].clone());
                }

                // Send some messages
                for i in 0..3 {
                    senders[i % num_senders]
                        .send(&cx, i32::try_from(i).unwrap())
                        .expect("send");
                }

                // Drop all senders except last
                for _ in 0..num_senders - 1 {
                    senders.pop();
                }

                // Receivers should still work
                for rx in &mut receivers {
                    for _ in 0..3 {
                        block_on(rx.recv(&cx)).expect("recv before close");
                    }
                }

                // Drop last sender
                senders.pop();
                assert!(senders.is_empty());

                // METAMORPHIC RELATION: All receivers get Closed
                for (i, rx) in receivers.iter_mut().enumerate() {
                    let result = block_on(rx.recv(&cx));
                    crate::assert_with_log!(
                        matches!(result, Err(RecvError::Closed)),
                        format!(
                            "receiver {} closed ({} senders, {} receivers)",
                            i, num_senders, num_receivers
                        ),
                        true,
                        matches!(result, Err(RecvError::Closed))
                    );
                }
            }
        }

        crate::test_complete!("metamorphic_close_propagation");
    }

    /// MR5: Waker Deduplication (Performance Relation)
    /// Single receiver case should not register duplicate wakers.
    /// Transformation: Vary polling patterns on single receiver
    /// Relation: Waker arena size stays minimal (≤ 1) for single receiver
    #[test]
    fn metamorphic_waker_deduplication() {
        init_test("metamorphic_waker_deduplication");
        let cx = test_cx();

        let (tx, mut rx) = channel::<i32>(10);
        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        // Test multiple polling scenarios
        for scenario in 0..5 {
            // Clear any existing state
            if scenario > 0 {
                drop(rx);
                rx = tx.subscribe();
            }

            // You cannot have multiple active futures borrowing the same receiver mutably.
            // Instead, we just poll one future multiple times to simulate the scenario.
            let mut fut = Box::pin(rx.recv(&cx));
            let _ = fut.as_mut().poll(&mut ctx);
            let _ = fut.as_mut().poll(&mut ctx);
            let _ = fut.as_mut().poll(&mut ctx);

            // METAMORPHIC RELATION: Waker arena should have ≤ 1 entry for single receiver
            let waker_count = {
                let inner = tx.channel.inner.lock();
                inner.wakers.len()
            };

            crate::assert_with_log!(
                waker_count <= 1,
                format!("waker dedup scenario {} (single receiver)", scenario),
                "≤ 1".to_string(),
                format!("{}", waker_count)
            );

            // Send message and verify exactly one wake
            let wake_count_before = wake_state.wake_count();
            tx.send(&cx, scenario).expect("send");
            let wake_count_after = wake_state.wake_count();

            // Should wake exactly once for single receiver
            let wake_delta = wake_count_after - wake_count_before;
            crate::assert_with_log!(
                wake_delta <= 1,
                format!("wake count scenario {} (single receiver)", scenario),
                "≤ 1".to_string(),
                format!("{}", wake_delta)
            );

            // Cleanup: consume the message
            drop(fut);
            block_on(rx.recv(&cx)).expect("cleanup recv");
        }

        crate::test_complete!("metamorphic_waker_deduplication");
    }

    /// Composite MR: Order + Lag + Close (MR1 ∘ MR2 ∘ MR4)
    /// Combined stress test ensuring multiple relations hold simultaneously.
    #[test]
    fn metamorphic_composite_stress_test() {
        init_test("metamorphic_composite_stress_test");
        let cx = test_cx();

        let (tx, mut rx_fast) = channel::<i32>(4);
        let mut rx_slow = tx.subscribe();
        let mut rx_mid = tx.subscribe();

        // Phase 1: Send initial messages (order preservation)
        let initial_messages = vec![10, 20, 30, 40];
        for &msg in &initial_messages {
            tx.send(&cx, msg).expect("send initial");
        }

        // Fast receiver consumes all
        let mut fast_sequence = Vec::new();
        for _ in 0..4 {
            fast_sequence.push(block_on(rx_fast.recv(&cx)).expect("fast recv"));
        }

        // Phase 2: Create lag condition
        for i in 0..6 {
            tx.send(&cx, 100 + i).expect("send overrun");
        }

        // Phase 3: Drop all senders (close propagation)
        drop(tx);

        // COMPOSITE METAMORPHIC RELATIONS:

        // 1. Order preservation: Fast receiver saw messages in order
        crate::assert_with_log!(
            fast_sequence == initial_messages,
            "composite: initial order preserved",
            initial_messages,
            fast_sequence
        );

        // 2. Lag behavior: Slow receiver gets lag error
        let slow_lag_result = block_on(rx_slow.recv(&cx));
        let got_lag = matches!(slow_lag_result, Err(RecvError::Lagged(_)));
        crate::assert_with_log!(got_lag, "composite: slow receiver lagged", true, got_lag);

        // 3. Close propagation: All receivers eventually get closed.
        // Mid receiver may surface `Lagged(_)` before `Closed` because
        // it was behind when the sender was dropped; we keep recv'ing
        // until the terminal `Closed` signal is observed.
        let mid_close_result = loop {
            match block_on(rx_mid.recv(&cx)) {
                Ok(_) => (),                     // Consume any buffered messages
                Err(RecvError::Lagged(_)) => (), // Acknowledge lag and retry
                Err(e) => break e,
            }
        };

        crate::assert_with_log!(
            matches!(mid_close_result, RecvError::Closed),
            "composite: mid receiver closed",
            true,
            matches!(mid_close_result, RecvError::Closed)
        );

        crate::test_complete!("metamorphic_composite_stress_test");
    }

    #[test]
    fn recv_cancellation_alone_wakes_and_clears_before_future_drop() {
        init_test("recv_cancellation_alone_wakes_and_clears_before_future_drop");
        let cx = test_cx();
        let (tx, mut rx) = channel::<u8>(2);
        let count = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&count));
        let mut task = Context::from_waker(&waker);
        let mut recv = Box::pin(rx.recv(&cx));
        assert!(recv.as_mut().poll(&mut task).is_pending());
        assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 1);
        assert_eq!(count.wake_count(), 0);
        cx.cancel_fast(crate::types::CancelKind::User);
        assert!(count.wake_count() > 0);
        assert_eq!(
            recv.as_mut().poll(&mut task),
            Poll::Ready(Err(RecvError::Cancelled))
        );
        assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
        assert_eq!(Arc::strong_count(&count), 2);
        assert_eq!(
            recv.as_mut().poll(&mut task),
            Poll::Ready(Err(RecvError::PolledAfterCompletion))
        );
        let fresh = test_cx();
        assert_eq!(tx.send(&fresh, 7), Ok(1));
        drop(recv);
        let mut retry = Box::pin(rx.recv(&fresh));
        assert_eq!(retry.as_mut().poll(&mut task), Poll::Ready(Ok(7)));
    }

    #[test]
    fn recv_success_close_and_lag_clear_cancellation_before_future_drop() {
        init_test("recv_success_close_and_lag_clear_cancellation_before_future_drop");
        for terminal in 0..3 {
            let cx = test_cx();
            let (tx, mut rx) = channel::<u8>(1);
            let count = CountingWaker::new();
            let waker = Waker::from(Arc::clone(&count));
            let mut task = Context::from_waker(&waker);
            let mut recv = Box::pin(rx.recv(&cx));
            assert!(recv.as_mut().poll(&mut task).is_pending());
            let expected = match terminal {
                0 => {
                    tx.send(&cx, 3).unwrap();
                    Ok(3)
                }
                1 => {
                    drop(tx);
                    Err(RecvError::Closed)
                }
                _ => {
                    tx.send(&cx, 3).unwrap();
                    tx.send(&cx, 4).unwrap();
                    Err(RecvError::Lagged(1))
                }
            };
            assert_eq!(recv.as_mut().poll(&mut task), Poll::Ready(expected));
            assert_eq!(Arc::strong_count(&count), 2);
            count.wakes.store(0, AtomicOrdering::SeqCst);
            cx.cancel_fast(crate::types::CancelKind::User);
            assert_eq!(count.wake_count(), 0);
            drop(recv);
        }
    }

    #[test]
    fn recv_drop_removes_only_its_owned_cancellation_registration() {
        init_test("recv_drop_removes_only_its_owned_cancellation_registration");
        for sibling in [false, true] {
            let cx = test_cx();
            let (tx, mut rx) = channel::<u8>(1);
            let count = CountingWaker::new();
            let waker = Waker::from(Arc::clone(&count));
            let mut task = Context::from_waker(&waker);
            let mut observer = sibling.then(|| Box::pin(cx.cancelled()));
            if let Some(observer) = observer.as_mut() {
                assert!(observer.as_mut().poll(&mut task).is_pending());
            }
            let mut recv = Box::pin(rx.recv(&cx));
            assert!(recv.as_mut().poll(&mut task).is_pending());
            drop(recv);
            assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
            cx.cancel_fast(crate::types::CancelKind::User);
            assert_eq!(count.wake_count() > 0, sibling);
            if let Some(observer) = observer.as_mut() {
                assert!(observer.as_mut().poll(&mut task).is_ready());
            }
            assert_eq!(Arc::strong_count(&count), 2);
            let wakes = count.wake_count();
            let fresh = test_cx();
            tx.send(&fresh, 9).unwrap();
            assert_eq!(count.wake_count(), wakes);
            assert_eq!(rx.try_recv(), Ok(9));
        }
    }

    #[test]
    fn recv_migration_retargets_the_cancellation_waker() {
        init_test("recv_migration_retargets_the_cancellation_waker");
        let cx = test_cx();
        let (_tx, mut rx) = channel::<u8>(1);
        let old_count = CountingWaker::new();
        let new_count = CountingWaker::new();
        let old_waker = Waker::from(Arc::clone(&old_count));
        let new_waker = Waker::from(Arc::clone(&new_count));
        let mut old_task = Context::from_waker(&old_waker);
        let mut new_task = Context::from_waker(&new_waker);
        let mut recv = Box::pin(rx.recv(&cx));
        assert!(recv.as_mut().poll(&mut old_task).is_pending());
        assert!(recv.as_mut().poll(&mut new_task).is_pending());
        assert_eq!(Arc::strong_count(&old_count), 2);
        cx.cancel_fast(crate::types::CancelKind::User);
        assert_eq!(old_count.wake_count(), 0);
        assert!(new_count.wake_count() > 0);
        assert_eq!(
            recv.as_mut().poll(&mut new_task),
            Poll::Ready(Err(RecvError::Cancelled))
        );
        assert_eq!(Arc::strong_count(&new_count), 2);
    }

    struct RetiredCancellationWake {
        cx: Cx,
        channel: std::sync::Weak<Channel<u8>>,
        retired: Arc<AtomicBool>,
    }

    #[allow(clippy::manual_noop_waker)]
    impl std::task::Wake for RetiredCancellationWake {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for RetiredCancellationWake {
        fn drop(&mut self) {
            let channel = self.channel.upgrade().expect("sender remains alive");
            assert!(channel.inner.try_lock().is_some());
            assert!(self.cx.inner.try_write().is_some());
            self.retired.store(true, AtomicOrdering::SeqCst);
            self.cx.cancel_fast(crate::types::CancelKind::User);
        }
    }

    #[test]
    fn recv_retiring_wakers_cancel_outside_locks() {
        init_test("recv_retiring_wakers_cancel_outside_locks");
        for abandon in [false, true] {
            let cx = test_cx();
            let (tx, mut rx) = channel::<u8>(1);
            let retired = Arc::new(AtomicBool::new(false));
            let mut recv = Box::pin(rx.recv(&cx));
            {
                let waker = Waker::from(Arc::new(RetiredCancellationWake {
                    cx: cx.clone(),
                    channel: Arc::downgrade(&tx.channel),
                    retired: Arc::clone(&retired),
                }));
                let mut task = Context::from_waker(&waker);
                assert!(recv.as_mut().poll(&mut task).is_pending());
            }
            assert!(!cx.is_cancel_requested());
            assert!(!retired.load(AtomicOrdering::SeqCst));
            if abandon {
                drop(recv);
            } else {
                let count = CountingWaker::new();
                let waker = Waker::from(Arc::clone(&count));
                let mut task = Context::from_waker(&waker);
                assert_eq!(
                    recv.as_mut().poll(&mut task),
                    Poll::Ready(Err(RecvError::Cancelled)),
                    "cancellation from the retired Waker must finish this poll"
                );
                assert_eq!(Arc::strong_count(&count), 2);
            }
            assert!(retired.load(AtomicOrdering::SeqCst));
            assert!(cx.is_cancel_requested());
            assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
        }
    }


    fn broadcast_causal_test_cx(node: &str) -> Cx {
        Cx::for_testing()
            .with_logical_clock(
                crate::trace::distributed::LogicalClockMode::Vector {
                    node: crate::remote::NodeId::new(node),
                }
                .build_handle(None),
            )
            .with_task_causality_runtime(Some(97))
    }

    #[test]
    fn broadcast_causality_sidecar_is_lazy_and_released_with_receivers() {
        init_test("broadcast_causality_sidecar_is_lazy_and_released_with_receivers");
        let _host = Cx::set_current(None);
        let sender = broadcast_causal_test_cx("sender");
        let (tx, rx) = channel(2);
        assert_eq!(tx.send(&sender, 1), Ok(1));
        assert!(tx.channel.inner.lock().message_causality.is_none());
        {
            let _current = Cx::set_current(Some(sender.clone()));
            assert_eq!(tx.send(&sender, 2), Ok(1));
        }
        {
            let inner = tx.channel.inner.lock();
            let messages = inner.message_causality.as_ref().unwrap();
            assert_eq!(messages.len(), inner.buffer.len());
            assert!(messages[0].is_none());
            assert!(messages[1].is_some());
        }
        drop(rx);
        {
            let inner = tx.channel.inner.lock();
            assert!(inner.buffer.is_empty());
            assert!(inner.message_causality.is_none());
        }
        let mut rx = tx.subscribe();
        assert_eq!(tx.send(&sender, 3), Ok(1));
        assert!(tx.channel.inner.lock().message_causality.is_none());
        assert_eq!(rx.try_recv(), Ok(3));
    }

    #[test]
    fn broadcast_final_liveness_rollback_preserves_publication_evidence() {
        use crate::trace::distributed::CausalOrder;

        init_test("broadcast_final_liveness_rollback_preserves_publication_evidence");
        let _host = Cx::set_current(None);
        for attributed in [false, true] {
            let published = broadcast_causal_test_cx("published");
            let refused = broadcast_causal_test_cx("refused");
            let receiver = broadcast_causal_test_cx("receiver");
            let published_before = published.logical_tick();
            let (tx, mut rx) = channel(1);
            {
                let _current = Cx::set_current(attributed.then(|| published.clone()));
                assert_eq!(tx.send(&published, 1), Ok(1));
            }
            let original = tx
                .channel
                .inner
                .lock()
                .message_causality_at(0)
                .map(|evidence| (evidence.runtime, evidence.time));
            let refused_before = refused.logical_tick();
            {
                let _current = Cx::set_current(Some(refused.clone()));
                let permit = tx.reserve(&refused).unwrap();
                assert_eq!(permit.send_forcing_zero_at_final_liveness(2), 0);
            }
            assert_eq!(refused.logical_now(), refused_before);
            {
                let inner = tx.channel.inner.lock();
                assert_eq!(inner.total_sent, 1);
                assert_eq!(inner.message_causality.is_some(), attributed);
                assert_eq!(
                    inner.message_causality_at(0).map(|evidence| (evidence.runtime, evidence.time)),
                    original
                );
            }
            let observed = {
                let _current = Cx::set_current(Some(receiver.clone()));
                assert_eq!(rx.try_recv(), Ok(1));
                receiver.logical_tick()
            };
            assert_eq!(
                published_before.causal_order(&observed),
                if attributed { CausalOrder::Before } else { CausalOrder::Concurrent }
            );
            assert_eq!(refused_before.causal_order(&observed), CausalOrder::Concurrent);
        }
    }

    #[test]
    fn broadcast_cancelled_ready_receive_does_not_observe_the_value() {
        use crate::trace::distributed::CausalOrder;

        init_test("broadcast_cancelled_ready_receive_does_not_observe_the_value");
        let _host = Cx::set_current(None);
        let published = broadcast_causal_test_cx("published");
        let receiver = broadcast_causal_test_cx("receiver");
        let before = published.logical_tick();
        let (tx, mut rx) = channel(1);
        {
            let _current = Cx::set_current(Some(published.clone()));
            assert_eq!(tx.send(&published, 1), Ok(1));
        }
        receiver.set_cancel_requested(true);
        let _current = Cx::set_current(Some(receiver.clone()));
        assert_eq!(block_on(rx.recv(&receiver)), Err(RecvError::Cancelled));
        assert_eq!(
            before.causal_order(&receiver.logical_tick()),
            CausalOrder::Concurrent
        );
        assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
        receiver.set_cancel_requested(false);
        assert_eq!(block_on(rx.recv(&receiver)), Ok(1));
        assert_eq!(before.causal_order(&receiver.logical_now()), CausalOrder::Before);
    }
