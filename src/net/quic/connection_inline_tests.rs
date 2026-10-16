    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]

    use super::*;
    use std::pin::Pin;
    use std::task::Context;

    fn noop_waker() -> std::task::Waker {
        std::task::Waker::noop().clone()
    }

    struct PendingOnce {
        polled: bool,
    }

    impl Future for PendingOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.polled {
                Poll::Ready(())
            } else {
                self.polled = true;
                Poll::Pending
            }
        }
    }

    #[test]
    fn wait_with_cx_returns_cancelled_when_context_is_cancelled_between_polls() {
        let cx = Cx::for_testing();
        let mut future = std::pin::pin!(wait_with_cx(&cx, PendingOnce { polled: false }));
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
