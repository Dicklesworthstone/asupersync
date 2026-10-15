//! Integration test: multiple poll_ready calls do not leak tokens.

use asupersync::service::{RateLimit, Service};
use asupersync::types::Time;
use std::future::Future;
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

#[test]
fn repeated_poll_ready_reuses_one_reserved_token_until_call() {
    let mut svc = RateLimit::new(EchoService, 2, Duration::from_secs(1));
    let mut cx = Context::from_waker(Waker::noop());

    let ready = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
    assert!(ready.is_ready());
    assert_eq!(svc.available_tokens(), 1);

    let ready2 = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
    assert!(ready2.is_ready());
    assert_eq!(
        svc.available_tokens(),
        1,
        "second poll_ready should not consume another token"
    );

    let mut call = std::pin::pin!(svc.call(7));
    let result = call.as_mut().poll(&mut cx);
    assert!(
        matches!(result, Poll::Ready(Ok(7))),
        "reserved call should complete successfully, got {result:?}"
    );
    assert_eq!(
        svc.available_tokens(),
        1,
        "call should consume the reserved token without touching the bucket again"
    );

    let ready3 = svc.poll_ready_with_time::<i32>(Time::ZERO, &mut cx);
    assert!(ready3.is_ready());
    assert_eq!(
        svc.available_tokens(),
        0,
        "a new poll_ready after call should consume the second token"
    );
}
