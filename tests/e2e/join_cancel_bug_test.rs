use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use std::future::Future;

#[test]
fn join_does_not_resolve_immediately_when_parent_cx_is_cancelled() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let cx = Cx::for_testing();

    let (_, mut handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            std::future::pending::<()>().await;
        })
        .expect("pending child task should be created");

    cx.set_cancel_requested(true);

    let join_fut = handle.join(&cx);

    let mut cx_task = std::task::Context::from_waker(std::task::Waker::noop());
    let mut pinned = Box::pin(join_fut);
    if let std::task::Poll::Ready(res) = pinned.as_mut().poll(&mut cx_task) {
        panic!("JoinFuture returned early on parent cancellation: {res:?}");
    }
}
