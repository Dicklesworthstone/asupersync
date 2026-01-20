use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::Mutex;
use asupersync::types::Budget;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

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
    YieldNow { yielded: false }.await
}

#[test]
fn test_mutex_contention_async() {
    let mut runtime = LabRuntime::new(LabConfig::default().max_steps(1000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mutex = Arc::new(Mutex::new(0));
    
    let finished_1 = Arc::new(AtomicBool::new(false));
    let finished_2 = Arc::new(AtomicBool::new(false));
    
    let m1 = mutex.clone();
    let f1 = finished_1.clone();
    
    // Task 1: Acquire lock, yield, release
    let (t1, _) = runtime.state.create_task(region, Budget::INFINITE, async move {
        // Now using await!
        let cx = asupersync::Cx::for_testing();
        let _guard = m1.lock(&cx).await.unwrap();
        // Hold lock and yield
        yield_now().await;
        // _guard dropped here
        f1.store(true, Ordering::SeqCst);
    }).unwrap();
    
    let m2 = mutex.clone();
    let f2 = finished_2.clone();
    
    // Task 2: Try to acquire lock
    let (t2, _) = runtime.state.create_task(region, Budget::INFINITE, async move {
        // This should await (yield) if locked, not block the thread
        let cx = asupersync::Cx::for_testing();
        let _guard = m2.lock(&cx).await.unwrap();
        f2.store(true, Ordering::SeqCst);
    }).unwrap();
    
    runtime.scheduler.lock().unwrap().schedule(t1, 0);
    runtime.scheduler.lock().unwrap().schedule(t2, 0);
    
    runtime.run_until_quiescent();
    
    assert!(finished_1.load(Ordering::SeqCst), "Task 1 should finish");
    assert!(finished_2.load(Ordering::SeqCst), "Task 2 should finish");
}