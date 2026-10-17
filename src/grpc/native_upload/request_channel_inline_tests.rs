    use super::*;
    use crate::types::CancelKind;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    fn counter() -> (Arc<Wakes>, Waker) {
        let wakes = Arc::new(Wakes::default());
        (Arc::clone(&wakes), Waker::from(wakes))
    }
    fn next<T: Send>(stream: &mut NativeRequestStream<T>) -> Poll<Option<Result<T, Status>>> {
        Pin::new(stream).poll_next(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn capacity_is_checked_before_allocation() {
        let cx = Cx::for_testing();
        for capacity in [0, MAX_STREAM_BUFFERED + 1, usize::MAX] {
            assert_eq!(native_request_channel::<()>(&cx, capacity).unwrap_err().code(), Code::InvalidArgument);
        }
    }

    #[test]
    fn full_queue_returns_input_and_explicit_close_drains_in_order() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 2).unwrap();
        sender.try_send(1).unwrap();
        sender.try_send(2).unwrap();
        let error = sender.try_send(3).unwrap_err();
        assert_eq!(error.status().code(), Code::ResourceExhausted);
        assert_eq!(error.into_inner(), 3);
        sender.close().unwrap();
        sender.close().unwrap();
        drop(sender);
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(2)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn send_waits_for_capacity_and_receiving_wakes_it() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(1).unwrap();
        let (wakes, waker) = counter();
        let mut sending = Box::pin(sender.send(2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        assert!(wakes.0.load(Ordering::SeqCst) > 0, "capacity must wake the producer");
        assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Ok(()))));
        drop(sending);
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(2)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn dropped_send_does_not_enqueue_and_sender_remains_usable() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(1).unwrap();
        let mut sending = Box::pin(sender.send(2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        drop(sending);
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        sender.try_send(3).unwrap();
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(3)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn open_sender_drop_is_failure_even_with_queued_messages() {
        let cx = Cx::for_testing();
        for queued in [false, true] {
            let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
            if queued { sender.try_send(7).unwrap(); }
            drop(sender);
            assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status))) if status.code() == Code::Cancelled));
            assert!(matches!(next(&mut stream), Poll::Ready(None)));
        }
    }

    #[test]
    fn producer_failure_bypasses_full_queue_and_preserves_first_status() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(7).unwrap();
        sender.fail(Status::resource_exhausted("producer limit")).unwrap();
        sender.cancel();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status)))
            if status.code() == Code::ResourceExhausted && status.message() == "producer limit"));
        assert!(!cx.is_cancel_requested());
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn failure_wakes_a_parked_source_and_ok_cannot_fake_failure() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel::<u8>(&cx, 1).unwrap();
        assert_eq!(sender.fail(Status::new(Code::Ok, "not a failure")).unwrap_err().code(), Code::InvalidArgument);
        let (wakes, waker) = counter();
        assert!(Pin::new(&mut stream).poll_next(&mut Context::from_waker(&waker)).is_pending());
        sender.fail(Status::internal("source error")).unwrap();
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status))) if status.message() == "source error"));
    }

    #[test]
    fn receiver_drop_wakes_a_capacity_blocked_send() {
        let cx = Cx::for_testing();
        let (mut sender, stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(1).unwrap();
        let (wakes, waker) = counter();
        let mut sending = Box::pin(sender.send(2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(stream);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(status)) if status.code() == Code::FailedPrecondition));
        drop(sending);
        assert!(sender.is_closed());
    }

    #[test]
    fn owner_cancellation_wakes_sender_and_receiver_without_network_progress() {
        for full in [false, true] {
            let cx = Cx::for_testing();
            let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
            let (wakes, waker) = counter();
            if full {
                sender.try_send(1).unwrap();
                let mut sending = Box::pin(sender.send(2));
                assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                cx.cancel_with(CancelKind::User, Some("stop upload"));
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)),
                    Poll::Ready(Err(status)) if status.code() == Code::Cancelled));
            } else {
                assert!(Pin::new(&mut stream).poll_next(&mut Context::from_waker(&waker)).is_pending());
                cx.cancel_with(CancelKind::User, Some("stop upload"));
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
            }
            assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status))) if status.code() == Code::Cancelled));
            assert!(matches!(next(&mut stream), Poll::Ready(None)));
        }
    }

    #[test]
    fn producer_cancellation_is_separate_from_rpc_owner_cancellation() {
        let owner = Cx::for_testing();
        let caller = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&owner, 1).unwrap();
        sender.try_send(1).unwrap();
        let (wakes, waker) = counter();
        let mut sending = Box::pin(sender.send_with_cx(&caller, 2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        caller.cancel_with(CancelKind::User, Some("producer only"));
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(status)) if status.code() == Code::Cancelled));
        drop(sending);
        assert!(!owner.is_cancel_requested());
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        sender.try_send(3).unwrap();
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(3)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn nonunpin_messages_need_no_clone_or_debug_and_drop_under_owner_context() {
        struct Message {
            owner: crate::types::TaskId,
            drops: Arc<AtomicUsize>,
            _pin: std::marker::PhantomPinned,
        }
        impl Drop for Message {
            fn drop(&mut self) {
                assert_eq!(Cx::current().unwrap().task_id(), self.owner);
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        let cx = Cx::for_testing();
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut sender, stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(Message { owner: cx.task_id(), drops: Arc::clone(&drops), _pin: std::marker::PhantomPinned }).unwrap();
        drop(stream);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(sender.is_closed());
    }

    /// br-asupersync-244ump L3: a failure before the source publishes the end
    /// of its input still overrides a requested half-close. Once that end is
    /// published, fail() is refused, as close() is, instead of returning Ok
    /// for an abort that cannot take effect.
    #[test]
    fn fail_after_the_end_of_input_is_published_is_refused() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel::<u8>(&cx, 1).unwrap();
        sender.close().unwrap();
        sender
            .fail(Status::data_loss("abort before the end"))
            .unwrap();
        assert!(matches!(
            next(&mut stream),
            Poll::Ready(Some(Err(status))) if status.code() == Code::DataLoss
        ));

        let (mut sender, mut stream) = native_request_channel::<u8>(&cx, 1).unwrap();
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
        let refused = sender
            .fail(Status::data_loss("abort after the end"))
            .unwrap_err();
        assert_eq!(refused.code(), Code::FailedPrecondition);
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }
