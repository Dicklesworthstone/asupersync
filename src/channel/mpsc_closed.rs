//! Receiver-closure observation without reserving channel capacity.

use super::{ChannelShared, Sender, UnboundedSender};
use crate::sync::Notify;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;

/// A channel that never observes closure pays no Notify allocation.
#[derive(Debug, Default)]
pub(super) struct ClosedSignal {
    notify: OnceLock<Box<Notify>>,
}

impl<T> Sender<T> {
    /// Waits until the receiver closes the channel or is dropped.
    ///
    /// This observes the same monotone state as [`Self::is_closed`]. It does
    /// not reserve capacity, publish a value, consume queued messages, or wait
    /// for the queue to drain. It can interrupt an upstream producer even when
    /// that producer has no message ready to send. Existing permits can still
    /// be outstanding when this resolves; their sends will be refused.
    ///
    /// Each pending call owns its notification registration. Dropping the
    /// future removes that registration without changing the channel or other
    /// observers, including observers polled with the same task waker. No
    /// runtime, timer, background task, or periodic poll is required. This wait
    /// observes channel closure, not context cancellation; race it with
    /// `cx.cancelled()` when both events matter.
    ///
    /// ```
    /// # futures_lite::future::block_on(async {
    /// use asupersync::channel::mpsc;
    /// let (sender, mut receiver) = mpsc::channel(1);
    /// sender.try_send(7).unwrap();
    /// receiver.close();
    /// sender.closed().await;
    /// assert_eq!(receiver.try_recv(), Ok(7));
    /// # });
    /// ```
    pub async fn closed(&self) {
        if self.is_closed() {
            return;
        }
        let notify = self
            .shared
            .closed
            .notify
            .get_or_init(|| Box::new(Notify::new()));
        // Synchronize with any racing closer on weak-memory architectures:
        // Taking the channel mutex and issuing SeqCst fences guarantees that
        // notify initialization is visible to the closer and receiver_dropped
        // is visible to this waiter, preventing store-buffering missed wakeups.
        drop(self.shared.inner.lock());
        std::sync::atomic::fence(Ordering::SeqCst);
        // Notify::wait_until samples its broadcast generation BEFORE checking
        // the persistent flag. Closure before initialization is seen by the
        // predicate; closure between check and registration is a replayed edge.
        notify.wait_until(|| self.is_closed()).await;
    }
}

impl<T> UnboundedSender<T> {
    /// Waits for receiver closure without sending or allocating queue capacity.
    ///
    /// See [`Sender::closed`] for cancellation and queue-draining semantics.
    pub async fn closed(&self) {
        self.inner.closed().await;
    }
}

/// Construct only after publishing receiver_dropped and releasing the channel
/// mutex. Declaring this after extracted queue values makes it run before their
/// destruction, even if an existing detached sender wake unwinds. Closure does
/// not claim that queued values have been destroyed or permits have settled.
pub(super) struct WakeClosed<'a, T>(pub(super) &'a ChannelShared<T>);

impl<T> Drop for WakeClosed<'_, T> {
    fn drop(&mut self) {
        std::sync::atomic::fence(Ordering::SeqCst);
        let Some(notify) = self.0.closed.notify.get() else {
            return;
        };
        let unwinding = std::thread::panicking();
        // Notify fanout isolates individual wakes. Do not turn an already
        // propagating sender-wake panic into a process-aborting double unwind.
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            notify.notify_waiters();
        })) {
            if unwinding {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{RecvError, SendError, channel, unbounded_channel};
    use super::*;
    use crate::cx::Cx;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    #[derive(Default)]
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counter() -> (Arc<Count>, Waker) {
        crate::test_utils::init_test_logging();
        let count = Arc::new(Count::default());
        let waker = Waker::from(Arc::clone(&count));
        (count, waker)
    }
    fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(waker))
    }
    fn waiters<T>(sender: &Sender<T>) -> usize {
        sender
            .shared
            .closed
            .notify
            .get()
            .map_or(0, |notify| notify.waiter_count())
    }

    #[test]
    fn all_receiver_close_paths_wake_idle_producers() {
        for mode in 0..3 {
            let (sender, receiver) = channel::<u8>(1);
            let mut receiver = Some(receiver);
            let (count, waker) = counter();
            let mut closed = Box::pin(sender.closed());
            assert!(poll(closed.as_mut(), &waker).is_pending());
            assert_eq!(count.0.load(Ordering::SeqCst), 0);
            match mode {
                0 => receiver.as_mut().unwrap().close(),
                1 => drop(receiver.take()),
                _ => sender.close_receiver(),
            }
            assert!(count.0.load(Ordering::SeqCst) > 0);
            assert!(poll(closed.as_mut(), &waker).is_ready());
            assert_eq!(waiters(&sender), 0);
            assert_eq!(Arc::strong_count(&count), 2);
        }
    }

    #[test]
    fn already_closed_wait_is_ready_without_allocating_notification_state() {
        let (sender, mut receiver) = channel::<u8>(1);
        let mut unpolled = Box::pin(sender.closed());
        receiver.close();
        assert!(poll(unpolled.as_mut(), Waker::noop()).is_ready());
        assert!(sender.shared.closed.notify.get().is_none());
    }

    #[test]
    fn observing_closure_neither_reserves_capacity_nor_consumes_messages() {
        let (sender, mut receiver) = channel(2);
        let (count, waker) = counter();
        let mut closed = Box::pin(sender.closed());
        assert!(poll(closed.as_mut(), &waker).is_pending());
        sender.try_send(7).unwrap();
        let permit = sender.try_reserve().unwrap();
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
        receiver.close();
        assert!(poll(closed.as_mut(), &waker).is_ready());
        assert_eq!(permit.try_send(8), Err(SendError::Disconnected(8)));
        assert_eq!(receiver.try_recv(), Ok(7));
        assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));
    }

    #[test]
    fn dropped_same_waker_observer_does_not_remove_its_peer() {
        let (sender, mut receiver) = channel::<u8>(1);
        let (count, waker) = counter();
        let mut first = Box::pin(sender.closed());
        let mut second = Box::pin(sender.closed());
        assert!(poll(first.as_mut(), &waker).is_pending());
        assert!(poll(second.as_mut(), &waker).is_pending());
        assert_eq!(waiters(&sender), 2);
        drop(first);
        assert_eq!(waiters(&sender), 1);
        receiver.close();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(poll(second.as_mut(), &waker).is_ready());
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn migrated_and_dropped_observers_release_executor_wakers() {
        let (sender, mut receiver) = channel::<u8>(1);
        let (old, old_waker) = counter();
        let (new, new_waker) = counter();
        let mut closed = Box::pin(sender.closed());
        assert!(poll(closed.as_mut(), &old_waker).is_pending());
        assert!(poll(closed.as_mut(), &new_waker).is_pending());
        assert_eq!(Arc::strong_count(&old), 2);
        drop(closed);
        assert_eq!(waiters(&sender), 0);
        assert_eq!(Arc::strong_count(&new), 2);
        receiver.close();
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(new.0.load(Ordering::SeqCst), 0);
    }

    struct CloseOnDrop(Sender<u8>);
    // The waker's Drop is the point: it closes the receiver.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for CloseOnDrop {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for CloseOnDrop {
        fn drop(&mut self) {
            self.0.close_receiver();
        }
    }

    #[test]
    fn closure_during_waker_retirement_cannot_lose_the_notification() {
        let (sender, _receiver) = channel::<u8>(1);
        let mut closed = Box::pin(sender.closed());
        {
            let old = Waker::from(Arc::new(CloseOnDrop(sender.clone())));
            assert!(poll(closed.as_mut(), &old).is_pending());
        }
        assert!(!sender.is_closed());
        let (count, waker) = counter();
        if poll(closed.as_mut(), &waker).is_pending() {
            assert!(
                count.0.load(Ordering::SeqCst) > 0,
                "pending requires a wake"
            );
            assert!(poll(closed.as_mut(), &waker).is_ready());
        }
        assert!(sender.is_closed());
        assert_eq!(waiters(&sender), 0);
    }

    struct PanicWake;
    impl Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            panic!("planted wake failure");
        }
        fn wake_by_ref(self: &Arc<Self>) {
            panic!("planted wake failure");
        }
    }

    #[test]
    fn panicking_sender_wake_does_not_strand_closure_observers() {
        let cx = Cx::for_testing();
        let (sender, mut receiver) = channel(1);
        sender.try_send(1).unwrap();
        let panic_waker = Waker::from(Arc::new(PanicWake));
        let mut reservation = Box::pin(sender.reserve(&cx));
        assert!(poll(reservation.as_mut(), &panic_waker).is_pending());
        let (count, waker) = counter();
        let mut closed = Box::pin(sender.closed());
        assert!(poll(closed.as_mut(), &waker).is_pending());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receiver.close())).is_err()
        );
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(poll(closed.as_mut(), &waker).is_ready());
        assert!(matches!(
            poll(reservation.as_mut(), Waker::noop()),
            Poll::Ready(Err(SendError::Disconnected(())))
        ));
    }

    struct Reenter(Sender<u8>, Arc<Count>);
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            assert!(
                self.0.shared.inner.try_lock().is_some(),
                "closure wake under channel lock"
            );
            assert_eq!(self.0.try_send(9), Err(SendError::Disconnected(9)));
            self.1.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn closure_wakes_can_reenter_the_channel() {
        let (sender, mut receiver) = channel::<u8>(1);
        let count = Arc::new(Count::default());
        let waker = Waker::from(Arc::new(Reenter(sender.clone(), Arc::clone(&count))));
        let mut closed = Box::pin(sender.closed());
        assert!(poll(closed.as_mut(), &waker).is_pending());
        receiver.close();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(poll(closed.as_mut(), &waker).is_ready());
    }

    #[test]
    fn unbounded_sender_observes_closure_and_keeps_queued_values() {
        let (sender, mut receiver) = unbounded_channel();
        let (count, waker) = counter();
        let mut closed = Box::pin(sender.closed());
        assert!(poll(closed.as_mut(), &waker).is_pending());
        sender.send(3).unwrap();
        receiver.close();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(poll(closed.as_mut(), &waker).is_ready());
        assert_eq!(receiver.try_recv(), Ok(3));
    }
}
