use super::*;
use crate::stream::{StreamExt, iter};
use crate::types::CancelKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counter() -> (Arc<WakeCount>, Waker) {
    crate::test_utils::init_test_logging();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

struct Idle(Arc<AtomicUsize>);

impl Stream for Idle {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<u8>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

#[test]
fn with_cx_pre_cancelled_wait_does_not_poll_source() {
    let cx = Cx::for_testing();
    let polls = Arc::new(AtomicUsize::new(0));
    let mut source = Idle(Arc::clone(&polls));
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    cx.cancel_fast(CancelKind::User);
    let mut wait = Box::pin(source.next().with_cx(&cx));

    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn with_cx_idle_stream_wakes_on_cancellation_only() {
    let cx = Cx::for_testing();
    let mut source = Idle(Arc::new(AtomicUsize::new(0)));
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(source.next().with_cx(&cx));

    assert!(wait.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn with_cx_drop_removes_own_registration() {
    let cx = Cx::for_testing();
    let mut source = Idle(Arc::new(AtomicUsize::new(0)));
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(source.next().with_cx(&cx));

    assert!(wait.as_mut().poll(&mut task).is_pending());
    drop(wait);
    assert_eq!(Arc::strong_count(&count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[test]
fn with_cx_waker_migration_releases_old_task() {
    let cx = Cx::for_testing();
    let mut source = Idle(Arc::new(AtomicUsize::new(0)));
    let (old_count, old_waker) = counter();
    let (new_count, new_waker) = counter();
    let mut old_task = Context::from_waker(&old_waker);
    let mut new_task = Context::from_waker(&new_waker);
    let mut wait = Box::pin(source.next().with_cx(&cx));

    assert!(wait.as_mut().poll(&mut old_task).is_pending());
    assert!(wait.as_mut().poll(&mut new_task).is_pending());
    assert_eq!(Arc::strong_count(&old_count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
    assert!(new_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(wait.as_mut().poll(&mut new_task), Poll::Ready(Err(_))));
}

#[test]
fn with_cx_same_waker_waits_have_independent_ownership() {
    let cx = Cx::for_testing();
    let mut first_source = Idle(Arc::new(AtomicUsize::new(0)));
    let mut second_source = Idle(Arc::new(AtomicUsize::new(0)));
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut first = Box::pin(first_source.next().with_cx(&cx));
    let mut second = Box::pin(second_source.next().with_cx(&cx));

    assert!(first.as_mut().poll(&mut task).is_pending());
    assert!(second.as_mut().poll(&mut task).is_pending());
    drop(first);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(second.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    assert_eq!(Arc::strong_count(&count), 2);
}

struct CancelFromPoll {
    cx: Cx,
    ready: bool,
}

impl Stream for CancelFromPoll {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<u8>> {
        self.cx.cancel_fast(CancelKind::User);
        if self.ready {
            Poll::Ready(Some(7))
        } else {
            Poll::Pending
        }
    }
}

#[test]
fn with_cx_keeps_item_when_source_cancels_during_ready_poll() {
    let cx = Cx::for_testing();
    let mut source = CancelFromPoll {
        cx: cx.clone(),
        ready: true,
    };
    let (_count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(source.next().with_cx(&cx));

    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Ok(Some(7)))));
    assert!(cx.is_cancel_requested());
}

#[test]
fn with_cx_catches_cancellation_during_pending_source_poll() {
    let cx = Cx::for_testing();
    let mut source = CancelFromPoll {
        cx: cx.clone(),
        ready: false,
    };
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(source.next().with_cx(&cx));

    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn with_cx_honors_checkpoint_masking() {
    let cx = Cx::for_testing();
    let mut source = Idle(Arc::new(AtomicUsize::new(0)));
    let (_count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(source.next().with_cx(&cx));
    cx.cancel_fast(CancelKind::User);

    let masked = cx.masked(|| wait.as_mut().poll(&mut task));
    assert!(masked.is_pending());
    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(_))));
}

#[test]
fn with_cx_ready_and_eof_do_not_leave_cancel_wakers() {
    let cx = Cx::for_testing();
    let mut source = iter([11]);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut first = Box::pin(source.next().with_cx(&cx));
    assert!(matches!(first.as_mut().poll(&mut task), Poll::Ready(Ok(Some(11)))));
    drop(first);
    let mut eof = Box::pin(source.next().with_cx(&cx));
    assert!(matches!(eof.as_mut().poll(&mut task), Poll::Ready(Ok(None))));
    assert_eq!(Arc::strong_count(&count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[test]
fn with_cx_accepts_borrowed_non_send_items() {
    let cx = Cx::for_testing();
    let value = std::rc::Rc::new(String::from("local"));
    let mut source = iter([&value]);
    let (_count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(source.next().with_cx(&cx));
    match wait.as_mut().poll(&mut task) {
        Poll::Ready(Ok(Some(item))) => assert!(std::rc::Rc::ptr_eq(item, &value)),
        other => panic!("expected the borrowed local item, got {other:?}"),
    }
}

struct CancelOnDrop(Cx);

impl Wake for CancelOnDrop {
    fn wake(self: Arc<Self>) {}
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel_fast(CancelKind::User);
    }
}

#[test]
fn with_cx_cancellation_during_waker_retirement_does_not_park() {
    let cx = Cx::for_testing();
    let mut source = Idle(Arc::new(AtomicUsize::new(0)));
    let mut wait = Box::pin(source.next().with_cx(&cx));
    {
        let waker = Waker::from(Arc::new(CancelOnDrop(cx.clone())));
        let mut task = Context::from_waker(&waker);
        assert!(wait.as_mut().poll(&mut task).is_pending());
    }
    assert!(!cx.is_cancel_requested());
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    assert!(cx.is_cancel_requested());
    assert_eq!(Arc::strong_count(&count), 2);
}
