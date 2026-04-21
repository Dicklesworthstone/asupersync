#![allow(clippy::all)]
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn test_join_early_return_on_cancel() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let task_running = Arc::new(AtomicBool::new(true));
    let task_running_clone = Arc::clone(&task_running);

    let cx = Cx::for_testing();

    // Spawn a task that just loops
    let (mut handle, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            std::future::pending::<()>().await;
            task_running_clone.store(false, Ordering::SeqCst);
        })
        .unwrap();

    // Cancel the parent cx
    cx.set_cancel_requested(true);

    // Try to join
    let join_fut = handle.join(&cx);

    // We expect join to NOT return early just because the parent is cancelled!
    // But if it does, this will print "Returned early".
    let mut cx_task = std::task::Context::from_waker(std::task::Waker::noop());
    let mut pinned = Box::pin(join_fut);
    if let std::task::Poll::Ready(res) = pinned.as_mut().poll(&mut cx_task) {
        panic!(
            "BUG: JoinFuture returned early on cancel! result: {:?}",
            res
        );
    }
}
