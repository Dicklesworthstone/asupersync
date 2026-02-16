//! Regression test ensuring bracket releases on cancellation.

#[macro_use]
mod common;

#[cfg(test)]
mod tests {
    use crate::common::*;
    use asupersync::combinator::bracket::bracket;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::task::{Context, Poll};

    struct PendingOnce {
        polled: bool,
    }

    impl Future for PendingOnce {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.polled {
                Poll::Ready(())
            } else {
                self.polled = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[test]
    fn bracket_leak_on_cancel() {
        init_test_logging();
        test_phase!("bracket_leak_on_cancel");
        test_section!("setup");
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        // A future that we will cancel
        let bracket_fut = bracket(
            async { Ok::<_, ()>(()) }, // Acquire
            |()| async {
                // Use: suspend once to allow cancellation
                PendingOnce { polled: false }.await;
                Ok::<_, ()>(())
            },
            move |()| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        );

        // Poll it once to enter the "use" phase
        let mut boxed = Box::pin(bracket_fut);
        let waker = std::task::Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);

        test_section!("poll_once");
        let pending = boxed.as_mut().poll(&mut cx).is_pending();
        assert_with_log!(pending, "bracket future should be pending", true, pending);

        // Now drop the future (simulate cancellation)
        test_section!("cancel");
        drop(boxed);

        // Verify if release was called
        test_section!("verify");
        let released_value = released.load(Ordering::SeqCst);
        assert_with_log!(
            released_value,
            "release should have been called on cancellation",
            true,
            released_value
        );
        test_complete!("bracket_leak_on_cancel");
    }

    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
}
