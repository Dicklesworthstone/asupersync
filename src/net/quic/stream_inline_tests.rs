    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::task::Context;

    fn noop_waker() -> std::task::Waker {
        std::task::Waker::noop().clone()
    }

    struct PendingOnce {
        polled: bool,
    }

    impl Future for PendingOnce {
        type Output = Result<(), QuicError>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.polled {
                Poll::Ready(Ok(()))
            } else {
                self.polled = true;
                Poll::Pending
            }
        }
    }

    #[test]
    fn tracker_initially_not_closing() {
        let tracker = StreamTracker::new();
        assert!(!tracker.is_closing());
    }

    #[test]
    fn tracker_mark_closing() {
        let tracker = StreamTracker::new();
        tracker.mark_closing();
        assert!(tracker.is_closing());
    }

    #[test]
    fn tracker_mark_closing_idempotent() {
        let tracker = StreamTracker::new();
        tracker.mark_closing();
        tracker.mark_closing();
        assert!(tracker.is_closing());
    }

    #[test]
    fn tracker_shared_across_arcs() {
        let tracker = StreamTracker::new();
        let tracker2 = Arc::clone(&tracker);

        assert!(!tracker2.is_closing());
        tracker.mark_closing();
        assert!(tracker2.is_closing());
    }

    #[test]
    fn tracker_default() {
        let tracker = StreamTracker::default();
        assert!(!tracker.closing.load(Ordering::Acquire));
    }

    #[test]
    fn tracker_debug() {
        let tracker = StreamTracker::new();
        let debug = format!("{tracker:?}");
        assert!(debug.contains("StreamTracker"));
    }

    #[test]
    fn wait_result_with_cx_returns_cancelled_when_context_is_cancelled_between_polls() {
        let cx = Cx::for_testing();
        let mut future = std::pin::pin!(wait_result_with_cx(&cx, PendingOnce { polled: false }));
        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        assert!(matches!(future.as_mut().poll(&mut poll_cx), Poll::Pending));

        cx.set_cancel_requested(true);

        let cancelled = matches!(
            future.as_mut().poll(&mut poll_cx),
            Poll::Ready(Err(QuicError::Cancelled))
        );
        assert!(
            cancelled,
            "future should return cancelled after Cx cancellation"
        );
    }

    #[test]
    fn stream_operation_guard_observes_cancellation_before_quinn_call() {
        let cx = Cx::for_testing();
        let tracker = StreamTracker::new();
        cx.set_cancel_requested(true);

        let err = check_stream_operation(&cx, &tracker).expect_err("cancelled Cx must fail");
        assert!(matches!(err, QuicError::Cancelled));
    }

    #[test]
    fn stream_operation_guard_rejects_closing_tracker() {
        let cx = Cx::for_testing();
        let tracker = StreamTracker::new();
        tracker.mark_closing();

        let err = check_stream_operation(&cx, &tracker).expect_err("closing tracker must fail");
        assert!(matches!(err, QuicError::StreamClosed));
    }
