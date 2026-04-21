//! Cooperative yielding primitive for the asupersync runtime.
//!
//! This module provides the `yield_now()` function that allows tasks to voluntarily
//! yield execution back to the runtime scheduler, enabling fair cooperative multitasking.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Future that yields execution back to the runtime.
pub struct YieldNow {
    yielded: bool,
    completed: bool,
}

impl Future for YieldNow {
    type Output = ();

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(!self.completed, "yield_now future polled after completion");
        if self.yielded {
            self.completed = true;
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Yields execution back to the runtime, allowing other tasks to run.
#[inline]
#[must_use]
pub fn yield_now() -> YieldNow {
    YieldNow {
        yielded: false,
        completed: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct WakeCounter {
        wakes: AtomicUsize,
    }

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn yield_now_pending_then_ready_with_single_wake() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("yield_now_pending_then_ready_with_single_wake");

        let wake_counter = Arc::new(WakeCounter::default());
        let waker = std::task::Waker::from(Arc::clone(&wake_counter));
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(yield_now());

        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(wake_counter.wakes.load(Ordering::Relaxed), 1);

        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(())));
        assert_eq!(wake_counter.wakes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn yield_now_repoll_after_completion_panics() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("yield_now_repoll_after_completion_panics");

        let wake_counter = Arc::new(WakeCounter::default());
        let waker = std::task::Waker::from(Arc::clone(&wake_counter));
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(yield_now());

        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(())));

        let repoll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        let payload = repoll.expect_err("post-completion repoll must fail closed");
        let message = payload.downcast_ref::<&'static str>().map_or_else(
            || {
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .unwrap_or_else(|| "<non-string panic payload>".to_string())
            },
            |msg| (*msg).to_string(),
        );
        assert!(
            message.contains("yield_now future polled after completion"),
            "unexpected panic message: {message}"
        );
    }

    #[test]
    fn metamorphic_waker_substitution_preserves_yield_protocol() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("metamorphic_waker_substitution_preserves_yield_protocol");

        let baseline_counter = Arc::new(WakeCounter::default());
        let baseline_waker = std::task::Waker::from(Arc::clone(&baseline_counter));
        let mut baseline_cx = Context::from_waker(&baseline_waker);
        let mut baseline = std::pin::pin!(yield_now());

        assert!(matches!(
            baseline.as_mut().poll(&mut baseline_cx),
            Poll::Pending
        ));
        assert!(matches!(
            baseline.as_mut().poll(&mut baseline_cx),
            Poll::Ready(())
        ));
        assert_eq!(baseline_counter.wakes.load(Ordering::Relaxed), 1);

        let first_counter = Arc::new(WakeCounter::default());
        let second_counter = Arc::new(WakeCounter::default());
        let first_waker = std::task::Waker::from(Arc::clone(&first_counter));
        let second_waker = std::task::Waker::from(Arc::clone(&second_counter));
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);
        let mut transformed = std::pin::pin!(yield_now());

        assert!(matches!(
            transformed.as_mut().poll(&mut first_cx),
            Poll::Pending
        ));
        assert!(matches!(
            transformed.as_mut().poll(&mut second_cx),
            Poll::Ready(())
        ));

        assert_eq!(
            first_counter.wakes.load(Ordering::Relaxed),
            baseline_counter.wakes.load(Ordering::Relaxed),
            "changing the second-poll waker must not perturb the initial self-wake"
        );
        assert_eq!(
            second_counter.wakes.load(Ordering::Relaxed),
            0,
            "completion after substitution must not spuriously wake the replacement waker"
        );
    }
}
