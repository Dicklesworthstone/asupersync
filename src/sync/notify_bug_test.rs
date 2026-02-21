use std::sync::Arc;
use std::task::{Context, Poll, Waker, Wake};
use std::pin::Pin;

use asupersync::sync::Notify;

struct NoopWaker;
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn noop_waker() -> Waker { Arc::new(NoopWaker).into() }

fn main() {
    let notify = Notify::new();
    let mut fut1 = notify.notified();
    let mut fut2 = notify.notified();
    
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    
    let _ = Pin::new(&mut fut1).poll(&mut cx);
    let _ = Pin::new(&mut fut2).poll(&mut cx);
    
    assert_eq!(notify.waiter_count(), 2);
    
    notify.notify_one();
    assert_eq!(notify.waiter_count(), 1);
    
    drop(fut1);
    
    println!("after drop(fut1): waiter_count = {}", notify.waiter_count());
    
    let _ = Pin::new(&mut fut2).poll(&mut cx);
    
    println!("after poll fut2: waiter_count = {}", notify.waiter_count());
}
