#![allow(warnings)]
#![allow(clippy::all)]
//! Regression test for join-handle readiness after runtime shutdown.

use asupersync::runtime::RuntimeBuilder;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct HangFuture;
impl Future for HangFuture {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

#[test]
fn test_join_handle_does_not_hang_if_runtime_dropped() {
    let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
    let handle = runtime.handle().spawn(HangFuture);

    // Drop the runtime, which should cancel/drop all tasks.
    drop(runtime);

    // If we block on the handle now, it shouldn't hang forever!
    // It should panic because the task was dropped before completion.
    let waker = std::task::Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let mut handle = Box::pin(handle);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle.as_mut().poll(&mut cx)
    }));

    assert!(
        result.is_err(),
        "JoinHandle should panic when polled after the task was forcefully dropped"
    );
}
