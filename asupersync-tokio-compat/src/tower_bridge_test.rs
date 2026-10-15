//! Tests for the tower bridge adapter.
//!
//! Verifies that Cx is correctly captured and that services run smoothly.

use super::*;
use asupersync_tokio_compat::tower_bridge::{IntoTower, BridgeError};
use tower::Service;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::convert::Infallible;
use std::task::{Context, Poll, Wake, Waker};
use std::future::Future;

fn noop_waker() -> Waker { std::task::Waker::noop().clone() }

#[derive(Clone)]
struct CounterService { counter: Arc<AtomicU64> }
impl asupersync::service::AsupersyncService<u64> for CounterService {
    type Response = u64;
    type Error = Infallible;
    async fn call(&self, cx: &asupersync::Cx, request: u64) -> Result<u64, Infallible> {
        Ok(self.counter.fetch_add(request, Ordering::SeqCst) + request)
    }
}

#[test]
fn test_cx_captured_at_call() {
    let svc = CounterService { counter: Arc::new(AtomicU64::new(0)) };
    let mut tower_svc = IntoTower::new(svc);
    
    // Set Cx
    let cx = asupersync::Cx::for_testing();
    let guard = asupersync::Cx::set_current(Some(cx));
    
    // Call while Cx is active
    let mut fut = tower_svc.call(10);
    
    // Drop the guard, clearing Cx::current()
    drop(guard);
    
    assert!(asupersync::Cx::current().is_none());
    
    // Now poll the future. If it captured Cx eagerly, it will succeed.
    // If it captures Cx lazily during poll, it will fail with NoCxAvailable.
    let waker = noop_waker();
    let mut task_cx = Context::from_waker(&waker);
    let poll = std::pin::Pin::new(&mut fut).poll(&mut task_cx);
    
    match poll {
        Poll::Ready(Ok(val)) => assert_eq!(val, 10),
        Poll::Ready(Err(e)) => panic!("Failed: {}", e),
        Poll::Pending => panic!("Pending"),
    }
}
