use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Future that yields execution back to the runtime.
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Yields execution back to the runtime, allowing other tasks to run.
#[must_use]
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
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
        let mut fut = Box::pin(yield_now());

        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(wake_counter.wakes.load(Ordering::Relaxed), 1);

        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(())));
        assert_eq!(wake_counter.wakes.load(Ordering::Relaxed), 1);
    }
}
