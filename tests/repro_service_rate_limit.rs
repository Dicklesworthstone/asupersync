//! Reproduction test for rate-limit readiness wake behavior under fixed time.

use asupersync::service::Service;
use asupersync::service::rate_limit::RateLimit;
use asupersync::types::Time;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake};
use std::time::Duration;

struct NoopWaker(Arc<AtomicUsize>);
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct DummySvc;
impl Service<()> for DummySvc {
    type Response = ();
    type Error = ();
    type Future = std::future::Ready<Result<(), ()>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), ()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, (): ()) -> Self::Future {
        std::future::ready(Ok(()))
    }
}

fn fixed_time() -> Time {
    Time::from_millis(1000)
}

#[test]
fn test_rate_limit_does_not_spin_when_time_is_frozen() {
    let wake_count = Arc::new(AtomicUsize::new(0));
    let test_waker = Arc::new(NoopWaker(wake_count.clone())).into();
    let mut cx = Context::from_waker(&test_waker);

    // Rate limit: 1 token per 100ms.
    let mut svc = RateLimit::with_time_getter(
        DummySvc,
        1,
        Duration::from_millis(100),
        fixed_time, // Always return the same time
    );

    // Consume first token
    assert!(svc.poll_ready(&mut cx).is_ready());
    let _ = svc.call(()); // Actually consume the reserved token

    // Try second token - should return Pending without eager wake/spin.
    assert!(svc.poll_ready(&mut cx).is_pending());

    assert_eq!(wake_count.load(Ordering::SeqCst), 0);

    // Re-poll at identical time still stays pending and still avoids spin wake.
    assert!(svc.poll_ready(&mut cx).is_pending());
    assert_eq!(wake_count.load(Ordering::SeqCst), 0);
}
