    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Waker};

    static TEST_NOW_NANOS: AtomicU64 = AtomicU64::new(0);
    static TEST_TIME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_test_time() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_TIME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_test_time(0);
        guard
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<std::sync::atomic::AtomicBool>);

    use std::task::Wake;
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW_NANOS.store(nanos, Ordering::SeqCst);
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW_NANOS.load(Ordering::SeqCst))
    }

    fn collect_throttled(input: &[i32], period: Duration, now_nanos: u64) -> Vec<i32> {
        set_test_time(now_nanos);
        let mut stream = Throttle::with_time_getter(iter(input.to_vec()), period, test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = Vec::new();

        for _ in 0..=input.len() + 2 {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => out.push(item),
                Poll::Ready(None) => return out,
                Poll::Pending => {}
            }
        }

        panic!("throttle did not finish draining finite input");
    }

    #[test]
    fn throttle_zero_duration_passes_all() {
        init_test("throttle_zero_duration_passes_all");
        let mut stream = Throttle::new(iter(vec![1, 2, 3]), Duration::ZERO);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(2))
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_zero_duration_passes_all");
    }

    #[test]
    fn mr_throttle_zero_duration_split_matches_unsplit_identity() {
        init_test("mr_throttle_zero_duration_split_matches_unsplit_identity");
        let _time_guard = lock_test_time();
        let input = vec![4, 1, 4, 2, 1, 3];
        let expected = collect_throttled(&input, Duration::ZERO, 10);

        for split in 0..=input.len() {
            let mut split_input = input[..split].to_vec();
            split_input.extend_from_slice(&input[split..]);
            let actual = collect_throttled(&split_input, Duration::ZERO, 10);

            crate::assert_with_log!(
                actual == expected,
                format!("zero-duration split at {split}"),
                expected.clone(),
                actual
            );
        }

        crate::test_complete!("mr_throttle_zero_duration_split_matches_unsplit_identity");
    }

    #[test]
    fn mr_throttle_constant_time_nonzero_period_is_suffix_invariant() {
        init_test("mr_throttle_constant_time_nonzero_period_is_suffix_invariant");
        let _time_guard = lock_test_time();
        let prefix = vec![9];
        let suffixes = [Vec::new(), vec![1], vec![1, 2, 3], vec![1, 2, 3, 5, 8, 13]];
        let expected = collect_throttled(&prefix, Duration::from_secs(1), 20);

        for suffix in suffixes {
            let mut input = prefix.clone();
            input.extend_from_slice(&suffix);
            let actual = collect_throttled(&input, Duration::from_secs(1), 20);

            crate::assert_with_log!(
                actual == expected,
                format!("constant-time suffix length {}", suffix.len()),
                expected.clone(),
                actual
            );
        }

        crate::test_complete!("mr_throttle_constant_time_nonzero_period_is_suffix_invariant");
    }

    #[test]
    fn throttle_first_item_passes_immediately() {
        init_test("throttle_first_item_passes_immediately");
        let mut stream = Throttle::new(iter(vec![42]), Duration::from_secs(999));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item always passes regardless of period.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(42))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_first_item_passes_immediately");
    }

    #[test]
    fn throttle_suppresses_rapid_items() {
        init_test("throttle_suppresses_rapid_items");
        // With a large period, all items after the first should be dropped
        // since iter produces them synchronously (zero time between items).
        let mut stream = Throttle::new(iter(vec![1, 2, 3, 4, 5]), Duration::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item passes.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(Some(1)));

        // Remaining items are all within 10s window → dropped; stream ends.
        let poll = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(poll, Poll::Ready(None));
        crate::test_complete!("throttle_suppresses_rapid_items");
    }

    #[test]
    fn throttle_empty_stream() {
        init_test("throttle_empty_stream");
        let mut stream = Throttle::new(iter(Vec::<i32>::new()), Duration::from_millis(100));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_empty_stream");
    }

    #[test]
    fn throttle_with_delay() {
        init_test("throttle_with_delay");
        let _time_guard = lock_test_time();
        set_test_time(0);
        let mut stream =
            Throttle::with_time_getter(iter(vec![1, 2, 3]), Duration::from_millis(1), test_time);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item passes immediately.
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );

        set_test_time(
            Duration::from_millis(5)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(2))
        );
        set_test_time(
            Duration::from_millis(10)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(3))
        );
        crate::test_complete!("throttle_with_delay");
    }

    #[test]
    fn throttle_accessors() {
        init_test("throttle_accessors");
        let _time_guard = lock_test_time();
        set_test_time(17);
        let mut stream =
            Throttle::with_time_getter(iter(vec![1, 2]), Duration::from_millis(100), test_time);
        let _ref = stream.get_ref();
        let _mut = stream.get_mut();
        assert_eq!((stream.time_getter())().as_nanos(), 17);
        let inner = stream.into_inner();
        let mut inner = inner;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            Pin::new(&mut inner).poll_next(&mut cx),
            Poll::Ready(Some(1))
        );
        crate::test_complete!("throttle_accessors");
    }

    #[test]
    fn throttle_debug() {
        let stream = Throttle::new(iter(vec![1, 2, 3]), Duration::from_millis(100));
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("Throttle"));
    }

    struct AlwaysReadyStream {
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Stream for AlwaysReadyStream {
        type Item = usize;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let call = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(
                call <= MAX_SUPPRESSED_DRAIN_PER_POLL + 1,
                "throttle kept draining suppressed items without yielding"
            );
            Poll::Ready(Some(call))
        }
    }

    #[test]
    fn throttle_yields_after_suppression_budget_on_always_ready_stream() {
        init_test("throttle_yields_after_suppression_budget_on_always_ready_stream");
        let _time_guard = lock_test_time();
        set_test_time(0);
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker: Waker = Arc::new(TrackWaker(Arc::clone(&wake_flag))).into();
        let mut cx = Context::from_waker(&waker);
        let inner = AlwaysReadyStream {
            polls: Arc::clone(&polls),
        };
        let mut stream = Throttle::with_time_getter(inner, Duration::from_secs(1), test_time);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(first, Poll::Ready(Some(1)));
        assert_eq!(polls.load(Ordering::SeqCst), 1);

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        assert_eq!(second, Poll::Pending);
        assert!(wake_flag.load(Ordering::SeqCst));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            MAX_SUPPRESSED_DRAIN_PER_POLL + 1
        );
        crate::test_complete!("throttle_yields_after_suppression_budget_on_always_ready_stream");
    }

    #[derive(Debug, Default)]
    struct OneThenDoneThenPanicStream {
        yielded_once: bool,
        completed: bool,
    }

    impl Stream for OneThenDoneThenPanicStream {
        type Item = i32;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.yielded_once {
                self.yielded_once = true;
                return Poll::Ready(Some(7));
            }

            assert!(
                !self.completed,
                "throttle inner stream repolled after completion"
            );
            self.completed = true;
            Poll::Ready(None)
        }
    }

    #[test]
    fn throttle_does_not_repoll_exhausted_upstream() {
        init_test("throttle_does_not_repoll_exhausted_upstream");
        let _time_guard = lock_test_time();
        set_test_time(0);
        let mut stream = Throttle::with_time_getter(
            OneThenDoneThenPanicStream::default(),
            Duration::from_secs(1),
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(7))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
        crate::test_complete!("throttle_does_not_repoll_exhausted_upstream");
    }
