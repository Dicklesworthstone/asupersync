#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::Mutex;
use asupersync::types::Budget;
use common::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// Helper to force a yield
struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn yield_now() {
    YieldNow { yielded: false }.await;
}

#[test]
fn test_mutex_contention_async() {
    init_test("test_mutex_contention_async");
    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(1000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mutex = Arc::new(Mutex::new(0));

    let finished_1 = Arc::new(AtomicBool::new(false));
    let finished_2 = Arc::new(AtomicBool::new(false));

    let m1 = mutex.clone();
    let f1 = finished_1.clone();

    // Task 1: Acquire lock, yield, release
    let (t1, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Now using await!
            let cx: asupersync::Cx = asupersync::Cx::for_testing();
            let _guard = m1.lock(&cx).await.unwrap();
            // Hold lock and yield
            yield_now().await;
            // _guard dropped here
            f1.store(true, Ordering::SeqCst);
        })
        .unwrap();

    let m2 = mutex;
    let f2 = finished_2.clone();

    // Task 2: Try to acquire lock
    let (t2, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // This should await (yield) if locked, not block the thread
            let cx: asupersync::Cx = asupersync::Cx::for_testing();
            let _guard = m2.lock(&cx).await.unwrap();
            f2.store(true, Ordering::SeqCst);
        })
        .unwrap();

    test_section!("schedule");
    runtime.scheduler.lock().schedule(t1, 0);
    runtime.scheduler.lock().schedule(t2, 0);

    test_section!("run");
    runtime.run_until_quiescent();

    test_section!("verify");
    let finished_1_value = finished_1.load(Ordering::SeqCst);
    assert_with_log!(
        finished_1_value,
        "task 1 should finish",
        true,
        finished_1_value
    );
    let finished_2_value = finished_2.load(Ordering::SeqCst);
    assert_with_log!(
        finished_2_value,
        "task 2 should finish",
        true,
        finished_2_value
    );
    test_complete!("test_mutex_contention_async");
}
