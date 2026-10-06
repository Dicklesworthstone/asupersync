//! Regression tests for cancellation as the only event waking an MPSC wait.

use super::*;
use crate::types::CancelKind;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Wake, Waker};

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

fn assert_no_send_waiters<T>(sender: &Sender<T>) {
    let snapshot = sender.telemetry_snapshot(1);
    assert_eq!(snapshot.send_waiter_count, 0);
    assert_eq!(snapshot.reserved_uncommitted_obligations, 0);
}

#[test]
fn reserve_cancellation_wakes_without_receiver_progress() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut reserve = Box::pin(sender.reserve(&cx));

    assert!(reserve.as_mut().poll(&mut task).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        reserve.as_mut().poll(&mut task),
        Poll::Ready(Err(SendError::Cancelled(())))
    ));
    assert_no_send_waiters(&sender);
    // Neither cancellation nor cleanup consumed the already committed item.
    assert_eq!(receiver.try_recv(), Ok(1));
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn checked_reserve_cancellation_wakes_without_receiver_progress() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut reserve = Box::pin(sender.reserve_checked(&cx));

    assert!(reserve.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        reserve.as_mut().poll(&mut task),
        Poll::Ready(Err(CheckedSendError::Channel(SendError::Cancelled(()))))
    ));
    assert_no_send_waiters(&sender);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn convenience_send_cancellation_wakes_and_returns_original_value() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(1);
    sender.try_send(String::from("committed")).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut send = Box::pin(sender.send(&cx, String::from("pending")));

    assert!(send.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    match send.as_mut().poll(&mut task) {
        Poll::Ready(Err(SendError::Cancelled(value))) => assert_eq!(value, "pending"),
        other => panic!("expected cancellation with the unsent value, got {other:?}"),
    }
    assert_no_send_waiters(&sender);
    assert_eq!(receiver.try_recv().unwrap(), "committed");
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn checked_send_cancellation_wakes_and_retains_value() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut send = Box::pin(sender.send_checked(&cx, 2));

    assert!(send.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        send.as_mut().poll(&mut task),
        Poll::Ready(Err(CheckedSendError::Channel(SendError::Cancelled(2))))
    ));
    assert_no_send_waiters(&sender);
}

#[test]
fn dropping_reservation_removes_both_wake_registrations() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut reserve = Box::pin(sender.reserve(&cx));

    assert!(reserve.as_mut().poll(&mut task).is_pending());
    drop(reserve);
    assert_no_send_waiters(&sender);
    assert_eq!(Arc::strong_count(&count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[test]
fn moving_reservation_between_tasks_replaces_cancellation_waker() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (first_count, first_waker) = counter();
    let (second_count, second_waker) = counter();
    let mut first_task = Context::from_waker(&first_waker);
    let mut second_task = Context::from_waker(&second_waker);
    let mut reserve = Box::pin(sender.reserve(&cx));

    assert!(reserve.as_mut().poll(&mut first_task).is_pending());
    assert!(reserve.as_mut().poll(&mut second_task).is_pending());
    assert_eq!(Arc::strong_count(&first_count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(first_count.0.load(Ordering::SeqCst), 0);
    assert!(second_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        reserve.as_mut().poll(&mut second_task),
        Poll::Ready(Err(SendError::Cancelled(())))
    ));
}

#[test]
fn dropping_one_same_waker_reservation_does_not_unsubscribe_another() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut first = Box::pin(sender.reserve(&cx));
    let mut second = Box::pin(sender.reserve(&cx));

    assert!(first.as_mut().poll(&mut task).is_pending());
    assert!(second.as_mut().poll(&mut task).is_pending());
    drop(first);
    assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 1);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        second.as_mut().poll(&mut task),
        Poll::Ready(Err(SendError::Cancelled(())))
    ));
    assert_no_send_waiters(&sender);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn capacity_completion_unregisters_cancellation_before_future_drop() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut reserve = Box::pin(sender.reserve(&cx));

    assert!(reserve.as_mut().poll(&mut task).is_pending());
    assert_eq!(receiver.try_recv(), Ok(1));
    let permit = match reserve.as_mut().poll(&mut task) {
        Poll::Ready(Ok(permit)) => permit,
        other => panic!("expected a ready permit, got {other:?}"),
    };
    permit.try_send(2).unwrap();
    assert_eq!(Arc::strong_count(&count), 2);
    count.0.store(0, Ordering::SeqCst);
    // Keep the completed future alive: cleanup cannot depend on its Drop.
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    drop(reserve);
    assert_eq!(receiver.try_recv(), Ok(2));
}

#[test]
fn disconnection_completion_unregisters_cancellation_before_future_drop() {
    let cx = Cx::for_testing();
    let (sender, receiver) = channel(1);
    sender.try_send(1).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut reserve = Box::pin(sender.reserve(&cx));

    assert!(reserve.as_mut().poll(&mut task).is_pending());
    drop(receiver);
    assert!(matches!(
        reserve.as_mut().poll(&mut task),
        Poll::Ready(Err(SendError::Disconnected(())))
    ));
    assert_eq!(Arc::strong_count(&count), 2);
    count.0.store(0, Ordering::SeqCst);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[test]
fn pre_cancelled_reservation_has_no_wake_or_capacity_ownership() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    cx.cancel_fast(CancelKind::User);
    let mut reserve = Box::pin(sender.reserve(&cx));
    assert!(matches!(
        reserve.as_mut().poll(&mut task),
        Poll::Ready(Err(SendError::Cancelled(())))
    ));
    assert_no_send_waiters(&sender);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn ready_reservation_does_not_install_cancellation_registration() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut reserve = Box::pin(sender.reserve(&cx));
    let permit = match reserve.as_mut().poll(&mut task) {
        Poll::Ready(Ok(permit)) => permit,
        other => panic!("expected a ready permit, got {other:?}"),
    };
    assert_eq!(Arc::strong_count(&count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    drop(permit);
    assert_no_send_waiters(&sender);
}

struct CancelOnDrop(Cx);

// Waking does nothing; dropping the waker cancels, which is the point.
#[allow(clippy::manual_noop_waker)]
impl Wake for CancelOnDrop {
    fn wake(self: Arc<Self>) {}
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel_fast(CancelKind::User);
    }
}

#[test]
fn cancellation_during_waker_retirement_is_not_lost() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = channel(1);
    sender.try_send(1).unwrap();
    let mut reserve = Box::pin(sender.reserve(&cx));
    {
        let old_waker = Waker::from(Arc::new(CancelOnDrop(cx.clone())));
        let mut old_task = Context::from_waker(&old_waker);
        assert!(reserve.as_mut().poll(&mut old_task).is_pending());
    }
    assert!(!cx.is_cancel_requested());
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    // Retiring the last owner of the old executor waker cancels Cx during
    // refresh. The post-registration checkpoint must not return Pending.
    assert!(matches!(
        reserve.as_mut().poll(&mut task),
        Poll::Ready(Err(SendError::Cancelled(())))
    ));
    assert!(cx.is_cancel_requested());
    assert_no_send_waiters(&sender);
    assert_eq!(Arc::strong_count(&count), 2);
}
