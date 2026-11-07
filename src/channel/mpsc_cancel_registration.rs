//! Owned auxiliary cancellation wakeups for channel waiters.
//!
//! Channel capacity/data registrations cannot wake a waiter when cancellation
//! is the only event. Keep this registration separate from both those queues
//! and the runtime's cancellation-lane waker. A registration is installed only
//! on the slow path; ready operations do not acquire a cancellation slot.

use crate::cx::{CancelWakerToken, Cx};
use std::task::Waker;

struct Registration {
    // Keep a strong owner outside the Cx registry. Replacing or removing the
    // registry entry must not run the final executor-Waker destructor under
    // its lock. This is the same ownership rule as Cx::cancelled().
    waker: Waker,
    // Clearing the slot must not drop the final owner inside a completing
    // poll: an executor's destructor can panic after the value was consumed.
    token: Option<CancelWakerToken>,
}

struct RegistrationState {
    registration: Option<Registration>,
}

impl RegistrationState {
    const fn new() -> Self {
        Self { registration: None }
    }

    // Callers recheck cancellation after arbitrary Waker callbacks return.
    fn refresh<Caps>(&mut self, cx: &Cx<Caps>, waker: &Waker) {
        let unchanged = self
            .registration
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));
        let incoming = if unchanged { None } else { Some(waker.clone()) };
        let previous = self.registration.as_ref().and_then(|entry| entry.token);
        let token = cx.refresh_cancel_waker(previous, waker);
        let retired = if let Some(waker) = incoming {
            self.registration.replace(Registration {
                waker,
                token: Some(token),
            })
        } else {
            self.registration
                .as_mut()
                .expect("unchanged waker has an owned cancellation registration")
                .token = Some(token);
            None
        };
        // Refresh only runs after a pending channel poll. A stream may retire
        // the previous owner here without losing an already-consumed item,
        // and retains at most one owner across arbitrarily many ready items.
        drop(retired);
    }

    fn clear<Caps>(&mut self, cx: &Cx<Caps>) {
        if let Some(token) = self
            .registration
            .as_mut()
            .and_then(|registered| registered.token.take())
        {
            cx.clear_cancel_waker(token);
        }
        // Keep the owner until this future/stream is dropped or a later
        // pending poll replaces it. No cancellation slot remains active, but
        // a final-Waker Drop panic cannot unwind the result out of this poll.
    }
}

pub(super) struct CancelRegistration<'a, Caps = crate::cx::cap::All> {
    cx: &'a Cx<Caps>,
    state: RegistrationState,
}

impl<'a, Caps> CancelRegistration<'a, Caps> {
    pub(super) const fn new(cx: &'a Cx<Caps>) -> Self {
        Self {
            cx,
            state: RegistrationState::new(),
        }
    }

    /// Refresh the wake target without replacing any other waiter's slot.
    ///
    /// Callers must check cancellation after this returns: an executor's
    /// arbitrary Waker clone/retirement callbacks may themselves cancel Cx.
    pub(super) fn refresh(&mut self, waker: &Waker) {
        self.state.refresh(self.cx, waker);
    }

    pub(super) fn clear(&mut self) {
        self.state.clear(self.cx);
    }
}

impl<Caps> Drop for CancelRegistration<'_, Caps> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A stream owns its Cx, so its cancellation slot must own that same context
/// rather than borrow another field of the stream.
pub struct OwnedCancelRegistration {
    cx: Cx,
    state: RegistrationState,
}

impl OwnedCancelRegistration {
    pub(crate) fn new(cx: Cx) -> Self {
        Self {
            cx,
            state: RegistrationState::new(),
        }
    }

    pub(crate) fn cx(&self) -> &Cx {
        &self.cx
    }

    pub(crate) fn refresh(&mut self, waker: &Waker) {
        self.state.refresh(&self.cx, waker);
    }

    pub(crate) fn clear(&mut self) {
        self.state.clear(&self.cx);
    }
}

impl std::fmt::Debug for OwnedCancelRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedCancelRegistration")
            .field("cx", &self.cx)
            .field(
                "registered",
                &self
                    .state
                    .registration
                    .as_ref()
                    .is_some_and(|entry| entry.token.is_some()),
            )
            .finish()
    }
}

impl Drop for OwnedCancelRegistration {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::Cx;
    use crate::channel::{broadcast, mpsc, watch};
    use crate::stream::{BroadcastStream, ReceiverStream, Stream, WatchStream};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct RetirementWaker {
        drops: Arc<AtomicUsize>,
        panic_on_drop: bool,
    }

    // Only final-owner retirement matters for these deterministic schedules.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for RetirementWaker {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for RetirementWaker {
        fn drop(&mut self) {
            // Do not turn a failed assertion into a double-panic process abort.
            if self.panic_on_drop && std::thread::panicking() {
                return;
            }
            self.drops.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.panic_on_drop,
                "planted final cancellation Waker retirement panic"
            );
        }
    }

    fn park_with_panicking_waker<T>(
        drops: &Arc<AtomicUsize>,
        poll: impl FnOnce(&mut Context<'_>) -> Poll<T>,
    ) {
        crate::test_utils::init_test_logging();
        let waker = Waker::from(Arc::new(RetirementWaker {
            drops: Arc::clone(drops),
            panic_on_drop: true,
        }));
        let mut task = Context::from_waker(&waker);
        assert!(poll(&mut task).is_pending());
    }

    fn assert_retirement_panics(value: impl Sized, drops: &AtomicUsize) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(value)));
        let payload = result.expect_err("the final owner must retire at Drop");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"planted final cancellation Waker retirement panic")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn completed_mpsc_receive_survives_final_waker_retirement() {
        let cx = Cx::for_testing();
        let (tx, mut rx) = mpsc::channel(1);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut recv = Box::pin(rx.recv(&cx));
        park_with_panicking_waker(&drops, |task| recv.as_mut().poll(task));
        tx.try_send(7).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        let completion = recv.as_mut().poll(&mut task);
        assert_eq!(completion, Poll::Ready(Ok(7)));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
        assert_retirement_panics(recv, &drops);
        assert_eq!(completion, Poll::Ready(Ok(7)));
        assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
    }

    #[test]
    fn completed_mpsc_batch_survives_final_waker_retirement() {
        let cx = Cx::for_testing();
        let (tx, mut rx) = mpsc::channel(2);
        let mut buffer = vec![5];
        let drops = Arc::new(AtomicUsize::new(0));
        let mut recv = Box::pin(rx.recv_many(&cx, &mut buffer, 2));
        park_with_panicking_waker(&drops, |task| recv.as_mut().poll(task));
        tx.try_send(7).unwrap();
        tx.try_send(8).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        let completion = recv.as_mut().poll(&mut task);
        assert_eq!(completion, Poll::Ready(Ok(2)));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_retirement_panics(recv, &drops);
        assert_eq!(completion, Poll::Ready(Ok(2)));
        assert_eq!(buffer, [5, 7, 8]);
        assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
    }

    fn check_completed_reservation<'a, E: std::fmt::Debug>(
        tx: &'a mpsc::Sender<u8>,
        rx: &mut mpsc::Receiver<u8>,
        reserve: impl Future<Output = Result<mpsc::SendPermit<'a, u8>, E>>,
    ) {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut reserve = Box::pin(reserve);
        park_with_panicking_waker(&drops, |task| reserve.as_mut().poll(task));
        assert_eq!(rx.try_recv(), Ok(1));
        let mut task = Context::from_waker(Waker::noop());
        let permit = match reserve.as_mut().poll(&mut task) {
            Poll::Ready(Ok(permit)) => permit,
            other => panic!("expected the reserved permit, got {other:?}"),
        };
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_retirement_panics(reserve, &drops);
        // The caller still owns a usable permit after catching future Drop.
        permit.try_send(2).unwrap();
        assert_eq!(rx.try_recv(), Ok(2));
        let snapshot = tx.telemetry_snapshot(1);
        assert_eq!(snapshot.send_waiter_count, 0);
        assert_eq!(snapshot.reserved_uncommitted_obligations, 0);
    }

    #[test]
    fn completed_mpsc_reservations_survive_final_waker_retirement() {
        let cx = Cx::for_testing();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(1).unwrap();
        check_completed_reservation(&tx, &mut rx, tx.reserve(&cx));
        tx.try_send(1).unwrap();
        check_completed_reservation(&tx, &mut rx, tx.reserve_checked(&cx));
    }

    #[test]
    fn completed_watch_change_survives_final_waker_retirement() {
        let cx = Cx::for_testing();
        let (tx, mut rx) = watch::channel(0_u8);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut changed = Box::pin(rx.changed(&cx));
        park_with_panicking_waker(&drops, |task| changed.as_mut().poll(task));
        tx.send(7).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(changed.as_mut().poll(&mut task), Poll::Ready(Ok(())));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(tx.telemetry_snapshot(1).recv_waiter_count, 0);
        assert_retirement_panics(changed, &drops);
        assert!(!rx.has_changed());
        assert_eq!(*rx.borrow(), 7);
    }

    fn check_stream_items<S>(
        mut stream: S,
        mut publish: impl FnMut(u8),
        expected: [S::Item; 2],
    ) where
        S: Stream + Unpin,
        S::Item: PartialEq + std::fmt::Debug,
    {
        let drops = Arc::new(AtomicUsize::new(0));
        park_with_panicking_waker(&drops, |task| Pin::new(&mut stream).poll_next(task));
        let mut task = Context::from_waker(Waker::noop());
        let mut delivered = Vec::new();
        for (value, expected) in [7, 8].into_iter().zip(expected) {
            publish(value);
            let Poll::Ready(Some(actual)) = Pin::new(&mut stream).poll_next(&mut task) else {
                panic!("a published item must be ready");
            };
            assert_eq!(actual, expected);
            delivered.push(actual);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
        }
        assert_retirement_panics(stream, &drops);
        assert_eq!(delivered.len(), 2);
    }

    #[test]
    fn channel_streams_preserve_ready_items_until_final_waker_retirement() {
        let cx = Cx::for_testing();
        let (tx, rx) = mpsc::channel(2);
        check_stream_items(
            ReceiverStream::new(cx.clone(), rx),
            |value| tx.try_send(value).unwrap(),
            [7, 8],
        );

        let (tx, rx) = broadcast::channel(2);
        check_stream_items(
            BroadcastStream::new(cx.clone(), rx),
            |value| {
                tx.send(&cx, value).unwrap();
            },
            [Ok(7), Ok(8)],
        );

        let (tx, rx) = watch::channel(0_u8);
        check_stream_items(
            WatchStream::from_changes(cx, rx),
            |value| tx.send(value).unwrap(),
            [7, 8],
        );
    }

    #[test]
    fn stream_retains_only_one_owner_across_rearmed_pending_polls() {
        crate::test_utils::init_test_logging();
        let cx = Cx::for_testing();
        let (tx, rx) = mpsc::channel(1);
        let mut stream = ReceiverStream::new(cx, rx);
        let drops = Arc::new(AtomicUsize::new(0));
        for value in 0..4 {
            let owner = Arc::new(RetirementWaker {
                drops: Arc::clone(&drops),
                panic_on_drop: false,
            });
            let observer = Arc::downgrade(&owner);
            {
                let waker = Waker::from(owner);
                let mut task = Context::from_waker(&waker);
                assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
            }
            assert_eq!(drops.load(Ordering::SeqCst), value);
            tx.try_send(value).unwrap();
            let mut task = Context::from_waker(Waker::noop());
            assert_eq!(
                Pin::new(&mut stream).poll_next(&mut task),
                Poll::Ready(Some(value))
            );
            assert_eq!(observer.strong_count(), 1);
        }
        drop(stream);
        assert_eq!(drops.load(Ordering::SeqCst), 4);
    }
}
