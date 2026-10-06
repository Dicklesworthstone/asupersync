//! Receive cancellation must wake without requiring a producer or timer event.

use super::*;
use crate::types::CancelKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[test]
fn idle_recv_cancellation_wakes_without_a_producer_event() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        recv.as_mut().poll(&mut task),
        Poll::Ready(Err(RecvError::Cancelled))
    ));
    assert_eq!(sender.telemetry_snapshot(1).recv_waiter_count, 0);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn idle_recv_many_cancellation_wakes_and_preserves_existing_buffer() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut buffer = vec![99];
    let mut recv = Box::pin(receiver.recv_many(&cx, &mut buffer, 4));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        recv.as_mut().poll(&mut task),
        Poll::Ready(Err(RecvError::Cancelled))
    ));
    assert_eq!(sender.telemetry_snapshot(1).recv_waiter_count, 0);
    assert_eq!(Arc::strong_count(&count), 2);
    drop(recv);
    assert_eq!(buffer, [99]);
}

#[test]
fn unbounded_recv_also_wakes_on_cancellation_only() {
    let cx = Cx::for_testing();
    let (_sender, mut receiver) = unbounded_channel::<u8>();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        recv.as_mut().poll(&mut task),
        Poll::Ready(Err(RecvError::Cancelled))
    ));
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn dropping_recv_unregisters_cancellation_and_data_wakers() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    drop(recv);
    assert_eq!(sender.telemetry_snapshot(1).recv_waiter_count, 0);
    assert_eq!(Arc::strong_count(&count), 2);
    cx.cancel_fast(CancelKind::User);
    sender.try_send(7).unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(receiver.try_recv(), Ok(7));
}

#[test]
fn dropping_recv_many_unregisters_cancellation_and_keeps_buffer() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut buffer = vec![4, 5];
    let mut recv = Box::pin(receiver.recv_many(&cx, &mut buffer, 10));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    drop(recv);
    assert_eq!(buffer, [4, 5]);
    assert_eq!(sender.telemetry_snapshot(1).recv_waiter_count, 0);
    assert_eq!(Arc::strong_count(&count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[test]
fn recv_task_migration_updates_cancellation_waker() {
    let cx = Cx::for_testing();
    let (_sender, mut receiver) = channel::<u8>(1);
    let (old_count, old_waker) = counter();
    let (new_count, new_waker) = counter();
    let mut old_task = Context::from_waker(&old_waker);
    let mut new_task = Context::from_waker(&new_waker);
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(recv.as_mut().poll(&mut old_task).is_pending());
    assert!(recv.as_mut().poll(&mut new_task).is_pending());
    assert_eq!(Arc::strong_count(&old_count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
    assert!(new_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        recv.as_mut().poll(&mut new_task),
        Poll::Ready(Err(RecvError::Cancelled))
    ));
}

#[test]
fn recv_many_task_migration_updates_cancellation_waker() {
    let cx = Cx::for_testing();
    let (_sender, mut receiver) = channel::<u8>(1);
    let (old_count, old_waker) = counter();
    let (new_count, new_waker) = counter();
    let mut old_task = Context::from_waker(&old_waker);
    let mut new_task = Context::from_waker(&new_waker);
    let mut buffer = Vec::new();
    let mut recv = Box::pin(receiver.recv_many(&cx, &mut buffer, 4));

    assert!(recv.as_mut().poll(&mut old_task).is_pending());
    assert!(recv.as_mut().poll(&mut new_task).is_pending());
    assert_eq!(Arc::strong_count(&old_count), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
    assert!(new_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        recv.as_mut().poll(&mut new_task),
        Poll::Ready(Err(RecvError::Cancelled))
    ));
}

#[test]
fn successful_recv_clears_subscription_before_future_drop() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    sender.try_send(7).unwrap();
    assert!(matches!(recv.as_mut().poll(&mut task), Poll::Ready(Ok(7))));
    assert_eq!(Arc::strong_count(&count), 2);
    count.0.store(0, Ordering::SeqCst);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    drop(recv);
}

#[test]
fn successful_batch_clears_subscription_before_future_drop() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(2);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut buffer = vec![1];
    let mut recv = Box::pin(receiver.recv_many(&cx, &mut buffer, 2));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    sender.try_send(2).unwrap();
    sender.try_send(3).unwrap();
    assert!(matches!(recv.as_mut().poll(&mut task), Poll::Ready(Ok(2))));
    assert_eq!(Arc::strong_count(&count), 2);
    count.0.store(0, Ordering::SeqCst);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    drop(recv);
    assert_eq!(buffer, [1, 2, 3]);
}

#[test]
fn disconnected_recv_unregisters_cancellation() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    drop(sender);
    assert!(matches!(
        recv.as_mut().poll(&mut task),
        Poll::Ready(Err(RecvError::Disconnected))
    ));
    assert_eq!(Arc::strong_count(&count), 2);
    count.0.store(0, Ordering::SeqCst);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[test]
fn zero_limit_batch_stays_ready_even_for_cancelled_context() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(1);
    sender.try_send(8).unwrap();
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut buffer = vec![1];
    cx.cancel_fast(CancelKind::User);
    let mut recv = Box::pin(receiver.recv_many(&cx, &mut buffer, 0));

    assert!(matches!(recv.as_mut().poll(&mut task), Poll::Ready(Ok(0))));
    assert_eq!(Arc::strong_count(&count), 2);
    drop(recv);
    assert_eq!(buffer, [1]);
    assert_eq!(receiver.try_recv(), Ok(8));
}

#[test]
fn unpolled_recv_drop_keeps_existing_direct_poll_registration() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);

    assert!(receiver.poll_recv(&cx, &mut task).is_pending());
    drop(receiver.recv(&cx));
    assert_eq!(sender.telemetry_snapshot(1).recv_waiter_count, 1);
    sender.try_send(3).unwrap();
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(receiver.try_recv(), Ok(3));
}

#[test]
fn dropping_recv_does_not_remove_same_waker_cancellation_observer() {
    let cx = Cx::for_testing();
    let (_sender, mut receiver) = channel::<u8>(1);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut observer = Box::pin(cx.cancelled());
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(observer.as_mut().poll(&mut task).is_pending());
    assert!(recv.as_mut().poll(&mut task).is_pending());
    drop(recv);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(observer.as_mut().poll(&mut task).is_ready());
    assert_eq!(Arc::strong_count(&count), 2);
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
fn recv_cancellation_during_waker_retirement_finishes_in_same_poll() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let mut recv = Box::pin(receiver.recv(&cx));
    {
        let waker = Waker::from(Arc::new(CancelOnDrop(cx.clone())));
        let mut task = Context::from_waker(&waker);
        assert!(recv.as_mut().poll(&mut task).is_pending());
    }
    assert!(!cx.is_cancel_requested());
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(matches!(
        recv.as_mut().poll(&mut task),
        Poll::Ready(Err(RecvError::Cancelled))
    ));
    assert!(cx.is_cancel_requested());
    assert_eq!(sender.telemetry_snapshot(1).recv_waiter_count, 0);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn cancelled_receive_leaves_newly_arrived_value_for_fresh_context() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel(1);
    let (_count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut recv = Box::pin(receiver.recv(&cx));

    assert!(recv.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    sender.try_send(42).unwrap();
    assert!(matches!(
        recv.as_mut().poll(&mut task),
        Poll::Ready(Err(RecvError::Cancelled))
    ));
    drop(recv);
    let fresh = Cx::for_testing();
    let mut retry = Box::pin(receiver.recv(&fresh));
    assert!(matches!(retry.as_mut().poll(&mut task), Poll::Ready(Ok(42))));
}
