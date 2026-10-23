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

    struct CountingWaker {
        wake_count: AtomicUsize,
    }

    use std::task::Wake;
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Arc<CountingWaker>, Waker) {
        let state = Arc::new(CountingWaker {
            wake_count: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&state));
        (state, waker)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn collect_closed_stream(mut stream: WatchStream<i32>) -> Vec<i32> {
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut out = Vec::new();

        loop {
            match Pin::new(&mut stream).poll_next(&mut task_cx) {
                Poll::Ready(Some(item)) => out.push(item),
                Poll::Ready(None) => return out,
                Poll::Pending => panic!("closed watch stream unexpectedly returned Pending"),
            }
        }
    }

    fn collect_new_after_sends(initial: i32, sends: &[i32]) -> Vec<i32> {
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(initial);
        for &value in sends {
            tx.send(value)
                .expect("watch send before stream construction");
        }
        drop(tx);
        collect_closed_stream(WatchStream::new(cx, rx))
    }

    #[test]
    fn watch_stream_none_is_terminal_after_cancel() {
        init_test("watch_stream_none_is_terminal_after_cancel");
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let (tx, rx) = watch::channel(0);
        let mut stream = WatchStream::from_changes(cx.clone(), rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let first_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(first_none, "first poll none", true, first_none);

        cx.set_cancel_requested(false);
        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "send after cancel clear succeeds",
            true,
            send_result.is_ok()
        );

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let still_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(still_none, "stream remains terminated", true, still_none);
        crate::test_complete!("watch_stream_none_is_terminal_after_cancel");
    }

    #[test]
    fn watch_stream_new_none_is_terminal_after_cancel_before_initial_snapshot() {
        init_test("watch_stream_new_none_is_terminal_after_cancel_before_initial_snapshot");
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let (tx, rx) = watch::channel(0);
        let mut stream = WatchStream::new(cx.clone(), rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let first_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(first_none, "first poll none", true, first_none);

        cx.set_cancel_requested(false);
        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "send after cancel clear succeeds",
            true,
            send_result.is_ok()
        );

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let still_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(still_none, "stream remains terminated", true, still_none);
        crate::test_complete!(
            "watch_stream_new_none_is_terminal_after_cancel_before_initial_snapshot"
        );
    }

    #[test]
    fn mr_watch_stream_preconstruction_split_sends_coalesce_to_latest() {
        init_test("mr_watch_stream_preconstruction_split_sends_coalesce_to_latest");
        let sends = vec![1, 2, 3, 5, 8];
        let expected = collect_new_after_sends(0, &sends);

        for split in 0..=sends.len() {
            let mut split_sends = sends[..split].to_vec();
            split_sends.extend_from_slice(&sends[split..]);
            let actual = collect_new_after_sends(0, &split_sends);

            crate::assert_with_log!(
                actual == expected,
                format!("preconstruction split at {split}"),
                expected.clone(),
                actual
            );
        }

        crate::test_complete!("mr_watch_stream_preconstruction_split_sends_coalesce_to_latest");
    }

    #[test]
    fn mr_watch_stream_from_changes_output_is_prehistory_invariant() {
        init_test("mr_watch_stream_from_changes_output_is_prehistory_invariant");
        let future_change = 99;
        let prehistories: &[&[i32]] = &[&[], &[1], &[1, 2, 3], &[5, 8, 13, 21]];

        for &prehistory in prehistories {
            let cx: Cx = Cx::for_testing();
            let (tx, rx) = watch::channel(0);
            for &value in prehistory {
                tx.send(value).expect("watch prehistory send");
            }

            let mut stream = WatchStream::from_changes(cx, rx);
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let first = Pin::new(&mut stream).poll_next(&mut task_cx);
            crate::assert_with_log!(
                first.is_pending(),
                format!("prehistory length {} is skipped", prehistory.len()),
                true,
                first.is_pending()
            );

            tx.send(future_change).expect("watch future send");
            drop(tx);
            let actual = collect_closed_stream(stream);

            crate::assert_with_log!(
                actual == vec![future_change],
                format!(
                    "prehistory length {} yields only future change",
                    prehistory.len()
                ),
                vec![future_change],
                actual
            );
        }

        crate::test_complete!("mr_watch_stream_from_changes_output_is_prehistory_invariant");
    }

    #[test]
    fn watch_stream_initial_snapshot_does_not_duplicate_pending_update() {
        init_test("watch_stream_initial_snapshot_does_not_duplicate_pending_update");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0);
        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "pre-send should succeed",
            true,
            send_result.is_ok()
        );

        let mut stream = WatchStream::new(cx, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(1))),
            "first poll returns latest snapshot once",
            "Ready(Some(1))",
            format!("{first:?}")
        );

        let second = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            second.is_pending(),
            "second poll waits for a new change",
            true,
            second.is_pending()
        );
        crate::test_complete!("watch_stream_initial_snapshot_does_not_duplicate_pending_update");
    }

    #[test]
    fn watch_stream_from_changes_skips_current_value() {
        init_test("watch_stream_from_changes_skips_current_value");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0);
        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "pre-send should succeed",
            true,
            send_result.is_ok()
        );

        let mut stream = WatchStream::from_changes(cx, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            first.is_pending(),
            "from_changes skips current value",
            true,
            first.is_pending()
        );

        let send_result = tx.send(2);
        crate::assert_with_log!(
            send_result.is_ok(),
            "second send should succeed",
            true,
            send_result.is_ok()
        );
        let second = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(2))),
            "next change is yielded",
            "Ready(Some(2))",
            format!("{second:?}")
        );
        crate::test_complete!("watch_stream_from_changes_skips_current_value");
    }

    /// Invariant: stream terminates after sender is dropped.
    #[test]
    fn watch_stream_terminates_after_sender_drop() {
        init_test("watch_stream_terminates_after_sender_drop");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(42);
        let mut stream = WatchStream::new(cx, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // First poll: returns initial snapshot.
        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_42 = matches!(poll, Poll::Ready(Some(42)));
        crate::assert_with_log!(got_42, "initial snapshot", true, got_42);

        // Drop sender, then poll — should terminate.
        drop(tx);
        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let is_none = matches!(poll, Poll::Ready(None));
        crate::assert_with_log!(is_none, "terminated after sender drop", true, is_none);

        crate::test_complete!("watch_stream_terminates_after_sender_drop");
    }

    #[test]
    fn watch_stream_pending_poll_retains_waiter_registration() {
        init_test("watch_stream_pending_poll_retains_waiter_registration");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0);
        let mut stream = WatchStream::from_changes(cx, rx);
        let (wake_state, waker) = counting_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            first.is_pending(),
            "initial poll waits for a change",
            true,
            first.is_pending()
        );
        let wake_count = wake_state.wake_count.load(Ordering::SeqCst);
        crate::assert_with_log!(wake_count == 0, "no wake before send", 0, wake_count);

        let send_result = tx.send(1);
        crate::assert_with_log!(
            send_result.is_ok(),
            "send after pending poll succeeds",
            true,
            send_result.is_ok()
        );
        let wake_count = wake_state.wake_count.load(Ordering::SeqCst);
        crate::assert_with_log!(
            wake_count > 0,
            "pending waiter is woken by send",
            "> 0",
            wake_count
        );

        let second = Pin::new(&mut stream).poll_next(&mut task_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(1))),
            "woken poll yields new value",
            "Ready(Some(1))",
            format!("{second:?}")
        );
        crate::test_complete!("watch_stream_pending_poll_retains_waiter_registration");
    }

    #[test]
    fn watch_stream_accepts_non_send_non_sync_items() {
        init_test("watch_stream_accepts_non_send_non_sync_items");
        let cx: Cx = Cx::for_testing();
        let payload = Rc::new(String::from("local-only"));
        let (_tx, rx) = watch::channel(Rc::clone(&payload));
        let mut stream = WatchStream::new(cx, rx);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut stream).poll_next(&mut task_cx);
        let got_initial = matches!(
            poll,
            Poll::Ready(Some(value)) if Rc::ptr_eq(&value, &payload)
        );
        crate::assert_with_log!(
            got_initial,
            "non-Send/non-Sync Rc payload is yielded",
            true,
            got_initial
        );

        crate::test_complete!("watch_stream_accepts_non_send_non_sync_items");
    }

    #[test]
    fn watch_stream_cancellation_alone_wakes_latest_poller() {
        init_test("watch_stream_cancellation_alone_wakes_latest_poller");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0_u8);
        let mut stream = WatchStream::from_changes(cx.clone(), rx);
        let (old_count, old_waker) = counting_waker();
        let (count, waker) = counting_waker();
        let mut old_task = Context::from_waker(&old_waker);
        let mut task = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_next(&mut old_task).is_pending());
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert_eq!(Arc::strong_count(&old_count), 2);
        cx.cancel_fast(crate::types::CancelKind::User);
        assert_eq!(old_count.wake_count.load(Ordering::SeqCst), 0);
        assert!(count.wake_count.load(Ordering::SeqCst) > 0);
        assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
        assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
        assert_eq!(Arc::strong_count(&count), 2);
        tx.send(7).unwrap();
        assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
        let rx = stream.into_inner();
        assert!(rx.has_changed());
        assert_eq!(*rx.borrow(), 7);
    }

    #[test]
    fn watch_stream_rearms_after_value_and_preserves_cancellation_mask() {
        init_test("watch_stream_rearms_after_value_and_preserves_cancellation_mask");
        let cx: Cx = Cx::for_testing();
        let (tx, rx) = watch::channel(0_u8);
        let mut stream = WatchStream::from_changes(cx.clone(), rx);
        let (count, waker) = counting_waker();
        let mut task = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        tx.send(3).unwrap();
        assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(Some(3)));
        assert_eq!(Arc::strong_count(&count), 2);
        count.wake_count.store(0, Ordering::SeqCst);
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        cx.masked(|| {
            cx.cancel_fast(crate::types::CancelKind::User);
            assert!(count.wake_count.load(Ordering::SeqCst) > 0);
            assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
            assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 1);
        });
        assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn watch_stream_transfer_and_drop_retire_only_owned_registrations() {
        use std::future::Future as _;

        init_test("watch_stream_transfer_and_drop_retire_only_owned_registrations");
        for action in 0..3 {
            let cx: Cx = Cx::for_testing();
            let (tx, rx) = watch::channel(0_u8);
            let mut stream = Some(WatchStream::from_changes(cx.clone(), rx));
            let (count, waker) = counting_waker();
            let mut task = Context::from_waker(&waker);
            let mut observer = Box::pin(cx.cancelled());
            assert!(observer.as_mut().poll(&mut task).is_pending());
            assert!(Pin::new(stream.as_mut().unwrap()).poll_next(&mut task).is_pending());
            let mut extracted = None;
            match action {
                0 => { let _ = stream.as_mut().unwrap().get_mut(); }
                1 => { extracted = Some(stream.take().unwrap().into_inner()); }
                _ => { drop(stream.take()); }
            }
            assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
            cx.cancel_fast(crate::types::CancelKind::User);
            assert!(count.wake_count.load(Ordering::SeqCst) > 0);
            assert!(observer.as_mut().poll(&mut task).is_ready());
            assert_eq!(Arc::strong_count(&count), 2);
            drop(extracted);
            drop(stream);
        }
    }
