    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct CountWaker(Arc<AtomicUsize>);

    use std::task::Wake;
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountWaker(counter)))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn collect_closed_stream(
        mut stream: BroadcastStream<i32>,
    ) -> Vec<Result<i32, BroadcastStreamRecvError>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(item)) => out.push(item),
                Poll::Ready(None) => return out,
                Poll::Pending => panic!("closed broadcast stream unexpectedly returned Pending"),
            }
        }
    }

    fn collect_sent_sequence(input: &[i32]) -> Vec<Result<i32, BroadcastStreamRecvError>> {
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();
        let (tx, rx) = broadcast::channel(input.len().max(1) + 1);
        for &item in input {
            tx.send(&cx_send, item).expect("send input item");
        }
        drop(tx);
        collect_closed_stream(BroadcastStream::new(cx_recv, rx))
    }

    #[test]
    fn broadcast_stream_none_is_terminal_after_cancel() {
        init_test("broadcast_stream_none_is_terminal_after_cancel");
        let cx_recv: Cx = Cx::for_testing();
        cx_recv.set_cancel_requested(true);
        let cx_send: Cx = Cx::for_testing();

        let (tx, rx) = broadcast::channel(4);
        let mut stream = BroadcastStream::new(cx_recv.clone(), rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let first_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(first_none, "first poll none", true, first_none);

        cx_recv.set_cancel_requested(false);
        tx.send(&cx_send, 11).expect("send after cancel clear");

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let still_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(still_none, "stream remains terminated", true, still_none);
        crate::test_complete!("broadcast_stream_none_is_terminal_after_cancel");
    }

    /// Invariant: broadcast stream delivers pre-sent messages via poll_next.
    #[test]
    fn broadcast_stream_receives_prefilled_messages() {
        init_test("broadcast_stream_receives_prefilled_messages");
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();

        let (tx, rx) = broadcast::channel(8);
        tx.send(&cx_send, 10).expect("send 10");
        tx.send(&cx_send, 20).expect("send 20");

        let mut stream = BroadcastStream::new(cx_recv, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_10 = matches!(poll, Poll::Ready(Some(Ok(10))));
        crate::assert_with_log!(got_10, "received 10", true, got_10);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_20 = matches!(poll, Poll::Ready(Some(Ok(20))));
        crate::assert_with_log!(got_20, "received 20", true, got_20);

        crate::test_complete!("broadcast_stream_receives_prefilled_messages");
    }

    /// Invariant: stream yields None after all senders are dropped.
    #[test]
    fn broadcast_stream_terminated_after_sender_drop() {
        init_test("broadcast_stream_terminated_after_sender_drop");
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();

        let (tx, rx) = broadcast::channel(4);
        tx.send(&cx_send, 42).expect("send");
        drop(tx);

        let mut stream = BroadcastStream::new(cx_recv, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // First poll: should get the message.
        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_42 = matches!(poll, Poll::Ready(Some(Ok(42))));
        crate::assert_with_log!(got_42, "received 42", true, got_42);

        // Second poll: sender dropped, should terminate.
        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "terminated after sender drop", true, is_none);

        crate::test_complete!("broadcast_stream_terminated_after_sender_drop");
    }

    #[test]
    fn broadcast_stream_pending_poll_keeps_waker_registration() {
        init_test("broadcast_stream_pending_poll_keeps_waker_registration");
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();
        let (tx, rx) = broadcast::channel::<i32>(4);
        let mut stream = BroadcastStream::new(cx_recv, rx);

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut task_cx);
        let first_pending = matches!(first, Poll::Pending);
        crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);

        tx.send(&cx_send, 33).expect("send");
        let wake_total = wake_count.load(Ordering::SeqCst);
        crate::assert_with_log!(wake_total == 1, "single wake after send", 1, wake_total);

        let second = Pin::new(&mut stream).poll_next(&mut task_cx);
        let second_ready = matches!(second, Poll::Ready(Some(Ok(33))));
        crate::assert_with_log!(second_ready, "second poll has item", true, second_ready);

        crate::test_complete!("broadcast_stream_pending_poll_keeps_waker_registration");
    }

    #[test]
    fn broadcast_stream_accepts_non_send_items() {
        init_test("broadcast_stream_accepts_non_send_items");
        let cx_send: Cx = Cx::for_testing();
        let cx_recv: Cx = Cx::for_testing();
        let (tx, rx) = broadcast::channel::<Rc<String>>(4);
        let payload = Rc::new(String::from("local-only"));
        tx.send(&cx_send, Rc::clone(&payload))
            .expect("send local payload");

        let mut stream = BroadcastStream::new(cx_recv, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_local = matches!(
            poll,
            Poll::Ready(Some(Ok(value))) if Rc::ptr_eq(&value, &payload)
        );
        crate::assert_with_log!(got_local, "non-Send Rc payload is yielded", true, got_local);

        crate::test_complete!("broadcast_stream_accepts_non_send_items");
    }

    /// Invariant: BroadcastStreamRecvError::Lagged preserves the count and implements Display/Error.
    #[test]
    fn broadcast_stream_recv_error_lagged_preserves_count() {
        init_test("broadcast_stream_recv_error_lagged_preserves_count");

        let err = BroadcastStreamRecvError::Lagged(42);
        let is_lagged = matches!(err, BroadcastStreamRecvError::Lagged(42));
        crate::assert_with_log!(is_lagged, "lagged(42)", true, is_lagged);

        // Clone and Eq
        let cloned = err.clone();
        let eq = err == cloned;
        crate::assert_with_log!(eq, "clone eq", true, eq);

        // Debug
        let dbg = format!("{err:?}");
        let has_42 = dbg.contains("42");
        crate::assert_with_log!(has_42, "debug contains count", true, has_42);

        // Display
        let disp = format!("{err}");
        let disp_has_42 = disp.contains("lagged by 42 messages");
        crate::assert_with_log!(disp_has_42, "display contains message", true, disp_has_42);

        // Error trait
        let e: &dyn std::error::Error = &err;
        crate::assert_with_log!(
            e.source().is_none(),
            "no source",
            true,
            e.source().is_none()
        );

        crate::test_complete!("broadcast_stream_recv_error_lagged_preserves_count");
    }

    #[test]
    fn mr_broadcast_stream_split_sends_match_unsplit_fifo_order() {
        init_test("mr_broadcast_stream_split_sends_match_unsplit_fifo_order");
        let input = vec![2, 7, 1, 8, 2, 8];
        let expected = collect_sent_sequence(&input);

        for split in 0..=input.len() {
            let cx_send: Cx = Cx::for_testing();
            let cx_recv: Cx = Cx::for_testing();
            let (tx, rx) = broadcast::channel(input.len() + 1);
            for &item in &input[..split] {
                tx.send(&cx_send, item).expect("left split send");
            }
            for &item in &input[split..] {
                tx.send(&cx_send, item).expect("right split send");
            }
            drop(tx);

            let actual = collect_closed_stream(BroadcastStream::new(cx_recv, rx));
            crate::assert_with_log!(
                actual == expected,
                format!("split at {split}"),
                expected.clone(),
                actual
            );
        }

        crate::test_complete!("mr_broadcast_stream_split_sends_match_unsplit_fifo_order");
    }

    #[test]
    fn mr_broadcast_stream_pre_send_subscribers_receive_same_sequence() {
        init_test("mr_broadcast_stream_pre_send_subscribers_receive_same_sequence");
        let input = vec![1, 1, 2, 3, 5, 8, 13];
        let expected = collect_sent_sequence(&input);

        let cx_send: Cx = Cx::for_testing();
        let (tx, rx_a) = broadcast::channel(input.len() + 1);
        let rx_b = tx.subscribe();
        for &item in &input {
            tx.send(&cx_send, item).expect("send shared input");
        }
        drop(tx);

        let actual_a = collect_closed_stream(BroadcastStream::new(Cx::for_testing(), rx_a));
        let actual_b = collect_closed_stream(BroadcastStream::new(Cx::for_testing(), rx_b));

        crate::assert_with_log!(
            actual_a == expected,
            "first receiver matches baseline",
            expected.clone(),
            actual_a
        );
        crate::assert_with_log!(
            actual_b == expected,
            "second receiver matches baseline",
            expected,
            actual_b
        );

        crate::test_complete!("mr_broadcast_stream_pre_send_subscribers_receive_same_sequence");
    }

    /// A stream parked on channel A whose receiver is replaced through
    /// `get_mut` with one of channel B must not use its old waiter token
    /// against B, where it evicted the waker of a receiver parked on B.
    #[test]
    fn replacing_the_receiver_keeps_another_receivers_waker() {
        use std::future::Future as _;

        init_test("replacing_the_receiver_keeps_another_receivers_waker");
        let cx: Cx = Cx::for_testing();
        let (_tx_a, rx_a) = broadcast::channel::<i32>(4);
        let mut stream = BroadcastStream::new(Cx::for_testing(), rx_a);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_next(&mut task_cx).is_pending());

        let (tx_b, mut rx_b) = broadcast::channel::<i32>(4);
        let wakes = Arc::new(AtomicUsize::new(0));
        let counting = counting_waker(Arc::clone(&wakes));
        let mut recv = Box::pin(rx_b.recv(&cx));
        assert!(
            recv.as_mut()
                .poll(&mut Context::from_waker(&counting))
                .is_pending()
        );

        *stream.get_mut() = tx_b.subscribe();
        drop(stream);
        tx_b.send(&cx, 7).expect("send on channel B");
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "the receiver parked on channel B is still woken"
        );
        drop(recv);
    }
