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
fn join_handle_after_runtime_drop_is_finished_and_fails_closed() {
    let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
    let handle = runtime.handle().spawn(HangFuture);

    // Drop the runtime, which should cancel/drop all tasks.
    drop(runtime);
    assert!(
        handle.is_finished(),
        "JoinHandle should be terminal after runtime shutdown drops the executor side"
    );

    // If we block on the handle now, it shouldn't hang forever!
    // It should panic because the task was dropped before completion.
    let waker = std::task::Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let mut handle = Box::pin(handle);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle.as_mut().poll(&mut cx)
    }));
    let panic_payload = result.expect_err("JoinHandle should fail closed after task drop");
    let message = panic_payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| panic_payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>");

    assert!(
        message.contains("task was dropped or cancelled before completion"),
        "JoinHandle should preserve the dropped-task panic message, got {message}"
    );
    assert!(handle.is_finished());
}
