    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<AtomicBool>);

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn poll_once<S: Stream + Unpin>(stream: &mut S) -> Poll<Option<S::Item>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(stream).poll_next(&mut cx)
    }

    /// Drains one half, tolerating the `Pending` returned while the shared
    /// source is being pumped. Bounded so a stall fails loudly.
    fn drain_half<S: Stream + Unpin>(stream: &mut S) -> Vec<S::Item> {
        let mut out = Vec::new();
        let mut idle = 0usize;
        loop {
            match poll_once(stream) {
                Poll::Ready(Some(item)) => {
                    out.push(item);
                    idle = 0;
                }
                Poll::Ready(None) => return out,
                Poll::Pending => {
                    idle += 1;
                    assert!(idle <= 64, "partition half stalled for {idle} polls");
                }
            }
        }
    }

    #[test]
    fn partition_routes_every_item_to_exactly_one_half() {
        init_test("partition_routes_every_item_to_exactly_one_half");
        let (mut evens, mut odds) =
            partition(iter(vec![0, 1, 2, 3, 4, 5]), |x: &i32| x % 2 == 0, 8);

        let even_items = drain_half(&mut evens);
        crate::assert_with_log!(
            even_items == vec![0, 2, 4],
            "matched half receives predicate-true items in order",
            vec![0, 2, 4],
            even_items
        );

        // The odd items were buffered while the even half pumped the source.
        let odd_items = drain_half(&mut odds);
        crate::assert_with_log!(
            odd_items == vec![1, 3, 5],
            "unmatched half receives the rest, in order",
            vec![1, 3, 5],
            odd_items
        );
        crate::test_complete!("partition_routes_every_item_to_exactly_one_half");
    }

    #[test]
    fn partition_stalls_at_peer_capacity() {
        init_test("partition_stalls_at_peer_capacity");
        // Every item belongs to the ODD half, so polling the EVEN half can only
        // fill the peer buffer. With capacity 2 it must stall after 2 items
        // rather than buffering the whole source.
        let (mut evens, _odds) = partition(iter(vec![1, 3, 5, 7, 9]), |x: &i32| x % 2 == 0, 2);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);
        let polled = Pin::new(&mut evens).poll_next(&mut cx);

        crate::assert_with_log!(
            matches!(polled, Poll::Pending),
            "matched half yields once the peer buffer is full",
            "Poll::Pending",
            polled
        );
        crate::assert_with_log!(
            evens.peer_buffered_len() == 2,
            "peer buffer bounded by lane_capacity, not by source length",
            2,
            evens.peer_buffered_len()
        );
        crate::test_complete!("partition_stalls_at_peer_capacity");
    }

    #[test]
    fn partition_peer_consumption_releases_the_stall() {
        init_test("partition_peer_consumption_releases_the_stall");
        let (mut evens, mut odds) = partition(iter(vec![1, 3, 2, 5, 7]), |x: &i32| x % 2 == 0, 2);

        // Even half fills the odd buffer to capacity and stalls.
        crate::assert_with_log!(
            matches!(poll_once(&mut evens), Poll::Pending),
            "even half stalls at capacity",
            "Poll::Pending",
            "Poll::Pending"
        );

        // Draining one odd item frees a slot, so the even half can proceed and
        // reach the `2` that is waiting behind the odd items.
        let first_odd = poll_once(&mut odds);
        crate::assert_with_log!(
            matches!(first_odd, Poll::Ready(Some(1))),
            "odd half drains its buffer",
            "Poll::Ready(Some(1))",
            first_odd
        );

        let resumed = poll_once(&mut evens);
        crate::assert_with_log!(
            matches!(resumed, Poll::Ready(Some(2))),
            "even half resumes once the peer made room",
            "Poll::Ready(Some(2))",
            resumed
        );

        // And then stalls AGAIN: routing 5 and 7 refills the odd buffer to
        // capacity. This is the head-of-line contract, not a bug - the even
        // half cannot outrun a peer that is not being consumed.
        let stalled_again = poll_once(&mut evens);
        crate::assert_with_log!(
            matches!(stalled_again, Poll::Pending),
            "even half re-stalls once the peer buffer refills",
            "Poll::Pending",
            stalled_again
        );
        crate::assert_with_log!(
            evens.peer_buffered_len() == 2,
            "peer buffer back at capacity",
            2,
            evens.peer_buffered_len()
        );
        crate::test_complete!("partition_peer_consumption_releases_the_stall");
    }

    #[test]
    fn partition_delivers_every_item_when_both_halves_are_consumed() {
        init_test("partition_delivers_every_item_when_both_halves_are_consumed");
        // The contract's happy path: with a capacity far below the source
        // length, alternating consumption still delivers every item exactly
        // once and in per-lane order.
        let (mut evens, mut odds) =
            partition(iter(vec![1, 3, 2, 5, 7, 4, 9, 6]), |x: &i32| x % 2 == 0, 2);

        let mut even_items = Vec::new();
        let mut odd_items = Vec::new();
        let mut even_done = false;
        let mut odd_done = false;
        let mut idle = 0usize;

        while !(even_done && odd_done) {
            let mut progressed = false;
            if !even_done {
                match poll_once(&mut evens) {
                    Poll::Ready(Some(item)) => {
                        even_items.push(item);
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        even_done = true;
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
            }
            if !odd_done {
                match poll_once(&mut odds) {
                    Poll::Ready(Some(item)) => {
                        odd_items.push(item);
                        progressed = true;
                    }
                    Poll::Ready(None) => {
                        odd_done = true;
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
            }
            if progressed {
                idle = 0;
            } else {
                idle += 1;
                assert!(idle <= 16, "both halves stalled together for {idle} rounds");
            }
        }

        crate::assert_with_log!(
            even_items == vec![2, 4, 6],
            "matched items delivered in order",
            vec![2, 4, 6],
            even_items
        );
        crate::assert_with_log!(
            odd_items == vec![1, 3, 5, 7, 9],
            "unmatched items delivered in order",
            vec![1, 3, 5, 7, 9],
            odd_items
        );
        crate::test_complete!("partition_delivers_every_item_when_both_halves_are_consumed");
    }

    #[test]
    fn partition_dropped_peer_lifts_backpressure() {
        init_test("partition_dropped_peer_lifts_backpressure");
        let (mut evens, odds) =
            partition(iter(vec![1, 3, 2, 5, 7, 9, 11]), |x: &i32| x % 2 == 0, 1);

        // Without this drop the even half would stall permanently at capacity 1.
        drop(odds);

        let even_items = drain_half(&mut evens);
        crate::assert_with_log!(
            even_items == vec![2],
            "surviving half runs to completion, peer items discarded",
            vec![2],
            even_items
        );
        crate::test_complete!("partition_dropped_peer_lifts_backpressure");
    }

    #[test]
    fn partition_end_of_source_terminates_both_halves() {
        init_test("partition_end_of_source_terminates_both_halves");
        let (mut evens, mut odds) = partition(iter(vec![2, 4]), |x: &i32| x % 2 == 0, 4);

        let even_items = drain_half(&mut evens);
        crate::assert_with_log!(
            even_items == vec![2, 4],
            "matched half drains the source",
            vec![2, 4],
            even_items
        );
        crate::assert_with_log!(
            matches!(poll_once(&mut odds), Poll::Ready(None)),
            "unmatched half observes end-of-source with an empty buffer",
            "Poll::Ready(None)",
            "Poll::Ready(None)"
        );
        crate::test_complete!("partition_end_of_source_terminates_both_halves");
    }

    #[test]
    #[should_panic(expected = "partition lane_capacity must be non-zero")]
    fn partition_rejects_zero_capacity() {
        let _ = partition(iter(Vec::<i32>::new()), |_: &i32| true, 0);
    }

    /// Spec: the backpressure, head-of-line and wakeup contract documented on
    /// [`partition`], plus `PARTITION_COOPERATIVE_BUDGET`.
    mod partition_conformance {
        use super::*;

        #[test]
        fn peer_buffer_never_exceeds_capacity() {
            init_test("partition_conformance::peer_buffer_never_exceeds_capacity");
            let source: Vec<i32> = (0..64).map(|i| i * 2 + 1).collect(); // all odd
            let (mut evens, _odds) = partition(iter(source), |x: &i32| x % 2 == 0, 3);
            for _ in 0..32 {
                let _ = poll_once(&mut evens);
                crate::assert_with_log!(
                    evens.peer_buffered_len() <= 3,
                    "peer buffer stays within lane_capacity across repeated polls",
                    "<= 3",
                    evens.peer_buffered_len()
                );
            }
            crate::test_complete!("partition_conformance::peer_buffer_never_exceeds_capacity");
        }

        #[test]
        fn routing_yields_after_cooperative_budget() {
            init_test("partition_conformance::routing_yields_after_cooperative_budget");
            // All items are peer-bound and the capacity is deliberately larger
            // than the budget, so only the cooperative budget can stop the
            // routing loop. Without it, one poll would route the whole source.
            let source: Vec<i32> = (0..PARTITION_COOPERATIVE_BUDGET + 16)
                .map(|i| (i as i32) * 2 + 1)
                .collect();
            let (mut evens, _odds) = partition(
                iter(source),
                |x: &i32| x % 2 == 0,
                PARTITION_COOPERATIVE_BUDGET * 4,
            );

            let woke = Arc::new(AtomicBool::new(false));
            let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
            let mut cx = Context::from_waker(&waker);
            let polled = Pin::new(&mut evens).poll_next(&mut cx);

            crate::assert_with_log!(
                matches!(polled, Poll::Pending),
                "routing yields at the cooperative budget",
                "Poll::Pending",
                polled
            );
            crate::assert_with_log!(
                evens.peer_buffered_len() == PARTITION_COOPERATIVE_BUDGET,
                "routed exactly the cooperative budget in one poll",
                PARTITION_COOPERATIVE_BUDGET,
                evens.peer_buffered_len()
            );
            crate::assert_with_log!(
                woke.load(Ordering::SeqCst),
                "self-wake requested so the yield is not a stall",
                true,
                woke.load(Ordering::SeqCst)
            );
            crate::test_complete!("partition_conformance::routing_yields_after_cooperative_budget");
        }
    }
