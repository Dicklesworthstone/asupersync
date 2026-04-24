#![allow(clippy::all)]
use asupersync::cx::Cx;
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::time::timeout;
use asupersync::types::{CancelKind, Time};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[test]
fn test_race_empty_wakes_on_cancel() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::for_testing();
        
        let cx_clone = cx.clone();
        let fut = Box::pin(async move {
            let empty: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];
            cx_clone.race(empty).await
        });
        
        // spawn the future in background so it gets polled and goes to Pending
        let handle = asupersync::proc_macros::scope!(cx, {
            scope.spawn(&cx, asupersync::record::TaskKind::Worker, fut)
        });

        // wait a bit to let the task poll
        asupersync::time::sleep(&cx, std::time::Duration::from_millis(10)).await.unwrap();

        // Cancel the context
        cx.cancel_fast(CancelKind::User);

        // Await the task. It should complete with an Err(JoinError::Cancelled(_))
        let res = timeout(Time::ZERO, Duration::from_millis(50), handle).await;
        
        assert!(res.is_ok(), "The task hung and did not wake up on cancellation");
    });
}
