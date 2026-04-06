//! Integration test: multiple poll_ready calls do not leak tokens.
use asupersync::service::{RateLimit, Service};
use asupersync::types::Time;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[derive(Clone, Debug)]
struct EchoService;
impl Service<i32> for EchoService {
    type Response = i32;
    type Error = ();
    type Future = std::future::Ready<Result<i32, ()>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: i32) -> Self::Future {
        std::future::ready(Ok(req))
    }
}

fn noop_waker() -> Waker {
    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }
    Waker::from(std::sync::Arc::new(NoopWaker))
}

#[test]
fn test_multiple_poll_ready_does_not_leak_tokens() {
    let mut svc = RateLimit::new(EchoService, 2, Duration::from_secs(1));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First poll_ready
    let ready = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
    assert!(ready.is_ready());
    assert_eq!(svc.available_tokens(), 1);

    // Second poll_ready BEFORE call
    let ready2 = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
    assert!(ready2.is_ready());
    assert_eq!(
        svc.available_tokens(),
        1,
        "second poll_ready should not consume another token"
    );
}
// touched
