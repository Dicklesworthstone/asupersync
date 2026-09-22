//! Keep borrowing consumers Send for caller-owned native tasks.
use super::{GroupSessionRunError, ReplayGroupSession};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// Borrowing consumer future suitable for a caller-owned Send task.
pub type GroupSendConsumerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl ReplayGroupSession {
    /// Execute without erasing the consumer's Send property. This does not spawn
    /// or detach tasks: callers retain their runtime/region ownership. All poll
    /// budget, panic, destructor, completion and external-deadline requirements
    /// match [`Self::run`]. A zero budget refuses before invoking the factory.
    pub async fn run_send<T: Send, F>(self, max_polls: usize, consumer: F) -> Result<T, GroupSessionRunError>
    where
        F: Send + for<'a> FnOnce(&'a ReplayGroupSession) -> GroupSendConsumerFuture<'a, T>,
    {
        if max_polls == 0 { return Err(GroupSessionRunError::PollLimit { limit: 0 }); }
        let result = {
            let mut future = consumer(&self);
            let mut polls = 0;
            poll_fn(|cx| {
                if polls == max_polls { return Poll::Ready(Err(GroupSessionRunError::PollLimit { limit: max_polls })); }
                polls += 1;
                future.as_mut().poll(cx).map(Ok)
            }).await
        };
        let output = result?;
        self.verify_complete()?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::replay::IoCaptureLimits;
    use crate::io::replay_group_session::{GroupReplayClock, GroupSessionCaptureLimits, RecordingGroupSession};
    use crate::time::{TimeSource, VirtualClock};
    use crate::util::DetEntropy;
    use crate::util::entropy_replay::EntropyCaptureLimits;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use std::task::{Context, Waker};

    fn replay() -> ReplayGroupSession {
        let recording = RecordingGroupSession::new(Arc::new(DetEntropy::new(13)), Arc::new(VirtualClock::new()), GroupSessionCaptureLimits {
            max_streams: 0, max_effects: 1, per_stream: IoCaptureLimits::new(0, 0, 0, 0),
            entropy: EntropyCaptureLimits::new(0, 0, 1), clock_observations: 1,
        }).unwrap();
        recording.clock().now(); recording.finish().unwrap().replay()
    }
    fn require_send<T: Send>(value: T) -> T { value }

    #[test]
    fn send_driver_refuses_unconsumed_output_and_zero_budget_factory() {
        let mut future = Box::pin(require_send(replay().run_send(1, |_| Box::pin(async { 42 }))));
        assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(GroupSessionRunError::Replay(_)))));
        let mut zero = Box::pin(require_send(replay().run_send::<(), _>(0, |_| panic!("zero factory sentinel"))));
        assert!(matches!(zero.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(GroupSessionRunError::PollLimit { limit: 0 }))));
    }

    struct DropObservation<'a> { clock: &'a GroupReplayClock, extra: bool }
    impl Future for DropObservation<'_> {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { Poll::Ready(()) }
    }
    impl Drop for DropObservation<'_> {
        fn drop(&mut self) {
            self.clock.try_now().unwrap();
            if self.extra { let _ = self.clock.try_now(); } // intentionally ignored divergence
        }
    }
    #[test]
    fn destructor_observations_and_ignored_errors_precede_verification() {
        for extra in [false, true] {
            let mut future = Box::pin(require_send(replay().run_send(1, move |session| Box::pin(DropObservation { clock: session.clock(), extra }))));
            let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) else { panic!("ready consumer"); };
            assert_eq!(result.is_ok(), !extra);
        }
    }

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
    #[test]
    fn poll_budget_drops_parked_send_consumer_exactly_once() {
        let drops = Arc::new(AtomicUsize::new(0)); let count = Arc::clone(&drops);
        let mut future = Box::pin(require_send(replay().run_send(2, move |_| Box::pin(async move {
            let _guard = DropCount(count); std::future::pending::<()>().await;
        }))));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(GroupSessionRunError::PollLimit { limit: 2 }))));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
