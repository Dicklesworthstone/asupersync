//! Bounded, single-producer requests for the native streaming transport.

use crate::channel::mpsc;
use crate::cx::Cx;
use crate::grpc::status::{Code, Status};
use crate::grpc::streaming::{MAX_STREAM_BUFFERED, Streaming};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

mod native;

#[derive(Default)]
enum State {
    #[default]
    Open,
    HalfClosed,
    Failed(Status),
    Retired,
}

#[derive(Default)]
struct ControlState {
    state: State,
    waiter: Option<Waker>,
}

#[derive(Default)]
pub(super) struct RequestControl(parking_lot::Mutex<ControlState>);

impl RequestControl {
    fn send_error(&self) -> Option<Status> {
        match &self.0.lock().state {
            State::Open => None,
            State::Failed(status) => Some(status.clone()),
            State::HalfClosed | State::Retired => {
                Some(Status::failed_precondition("native request sender is closed"))
            }
        }
    }

    // One consumer owns this registration. Native channel constructors also
    // consult it before driving the network, independently of upload credit.
    pub(super) fn poll_failure(&self, task: &Context<'_>) -> Option<Status> {
        let mut incoming = Some(task.waker().clone());
        let (status, previous) = {
            let mut state = self.0.lock();
            match &state.state {
                State::Failed(status) => (Some(status.clone()), None),
                State::Retired => (None, None),
                State::Open | State::HalfClosed => {
                    let previous = state.waiter.replace(incoming.take().expect("incoming waker"));
                    (None, previous)
                }
            }
        };
        drop(previous);
        drop(incoming);
        status
    }

    // False once the source has retired: the end of the request was already
    // published, so a failure can no longer abort it.
    fn fail(&self, status: Status) -> bool {
        let waiter = {
            let mut state = self.0.lock();
            match &state.state {
                State::Retired => return false,
                State::Failed(_) => return true,
                State::Open | State::HalfClosed => {}
            }
            state.state = State::Failed(status);
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        true
    }

    // Every sender is gone. One locked transition decides the source's end: a
    // recorded failure is its result, otherwise input ended and the source
    // retires, so a racing fail() cannot be accepted after the end of input
    // is published (br-asupersync-244ump L3).
    fn finish_input(&self) -> Option<Status> {
        let (failure, waiter) = {
            let mut state = self.0.lock();
            let failure = match &state.state {
                State::Failed(status) => Some(status.clone()),
                State::Open | State::HalfClosed | State::Retired => None,
            };
            if failure.is_none() {
                state.state = State::Retired;
            }
            (failure, state.waiter.take())
        };
        drop(waiter);
        failure
    }

    fn retire(&self) {
        let waiter = {
            let mut state = self.0.lock();
            if !matches!(&state.state, State::Failed(_)) {
                state.state = State::Retired;
            }
            state.waiter.take()
        };
        drop(waiter);
    }
}

/// A refused nonblocking request send. Debug never prints application data.
pub struct NativeRequestSendError<T> {
    message: T,
    status: Status,
}

impl<T> NativeRequestSendError<T> {
    /// Why the message was not accepted. Full capacity is `ResourceExhausted`.
    #[must_use]
    pub fn status(&self) -> &Status {
        &self.status
    }

    /// Recover the unpublished message for an application-controlled retry.
    pub fn into_inner(self) -> T {
        self.message
    }

    /// Recover both the refusal and the unpublished message.
    pub fn into_parts(self) -> (Status, T) {
        (self.status, self.message)
    }
}

impl<T> fmt::Debug for NativeRequestSendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRequestSendError")
            .field("code", &self.status.code())
            .finish_non_exhaustive()
    }
}

/// Single producer for a bounded native request source.
///
/// Acceptance means local enqueue, not transmission or remote acknowledgement.
/// Drive the response owner concurrently with a producer that awaits capacity;
/// sending an entire upload before polling the response can deadlock by design.
/// There is no implicit background task. This sender is deliberately not Clone,
/// so at most one borrowed send owns an additional waiting input per channel.
///
/// Call [`Self::close`] for graceful EOF. Dropping an open sender instead fails
/// the source with `Cancelled`, discarding queued requests on its next poll.
/// Explicit producer failure never has to wait for a free queue slot.
pub struct NativeRequestSender<T> {
    cx: Cx,
    sender: Option<mpsc::Sender<T>>,
    control: Arc<RequestControl>,
    capacity: usize,
}

impl<T> fmt::Debug for NativeRequestSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRequestSender")
            .field("capacity", &self.capacity)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl<T> NativeRequestSender<T> {
    /// Maximum number of queued message objects, excluding an in-flight send.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether new requests can no longer be accepted.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.as_ref().is_none_or(mpsc::Sender::is_closed)
            || self.control.send_error().is_some()
    }

    /// Wait for queue capacity and enqueue one request exactly once.
    ///
    /// Dropping a pending wait drops its unpublished input, but leaves the
    /// sender usable and does not replay any accepted request. Use `try_send`
    /// when the application must retain the input on refusal. The channel's
    /// explicit context supplies cancellation and checkpoint budgets, even if
    /// a different task is polling this wait. Owner cancellation interrupts a
    /// full queue without depending on network progress or a timer.
    /// A separately spawned producer should use [`Self::send_with_cx`] so its
    /// own cancellation and checkpoint budget participate as well.
    pub fn send(&mut self, message: T) -> impl Future<Output = Result<(), Status>> + '_ {
        self.send_owned_context(self.cx.clone(), message)
    }

    /// Enqueue while observing both the RPC owner and an explicit producer.
    ///
    /// Use the spawn-supplied context of a producer task. Either cancellation
    /// wakes a capacity-blocked send; acknowledgement is performed on the
    /// context that was cancelled. Only the producer's checkpoint budget is
    /// charged for channel admission. Dropping this borrowing wait does not
    /// abort the source, but dropping an open sender when its task exits does.
    /// The returned future owns a context clone and does not borrow `caller`.
    pub fn send_with_cx<'a>(
        &'a mut self,
        caller: &Cx,
        message: T,
    ) -> impl Future<Output = Result<(), Status>> + 'a + use<'a, T> {
        self.send_owned_context(caller.clone(), message)
    }

    fn send_owned_context(&mut self, caller: Cx, message: T) -> impl Future<Output = Result<(), Status>> + '_ {
        let cx = self.cx.clone();
        let owner = cx.clone();
        let sender = self.sender.as_ref();
        let control = Arc::clone(&self.control);
        cx.with_ambient(async move {
            if let Some(error) = control.send_error() {
                return Err(error);
            }
            let sender = sender.ok_or_else(|| Status::failed_precondition("native request sender is closed"))?;
            let mut sending = pin!(sender.send(&caller, message));
            let mut cancelled = pin!(owner.cancelled());
            let mut caller_cancelled = pin!(caller.cancelled());
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() {
                    let _ = owner.checkpoint();
                    return Poll::Ready(Err(Status::cancelled("native request channel owner cancelled")));
                }
                if caller_cancelled.as_mut().poll(task).is_ready() {
                    let _ = caller.checkpoint();
                    return Poll::Ready(Err(Status::cancelled("native request producer cancelled")));
                }
                match sending.as_mut().poll(task) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) => {
                        let status = match error {
                            mpsc::SendError::Cancelled(_) => Status::cancelled("native request send cancelled"),
                            mpsc::SendError::Full(_) => Status::resource_exhausted("native request buffer is full"),
                            mpsc::SendError::Disconnected(_) => control.send_error().unwrap_or_else(|| {
                                Status::failed_precondition("native request consumer has retired")
                            }),
                        };
                        Poll::Ready(Err(status))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }).await
        })
    }

    /// Enqueue without waiting, returning the unchanged input on refusal.
    pub fn try_send(&mut self, message: T) -> Result<(), NativeRequestSendError<T>> {
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        if let Some(status) = self.control.send_error() {
            return Err(NativeRequestSendError { message, status });
        }
        if self.cx.is_cancel_requested() || self.cx.checkpoint().is_err() {
            return Err(NativeRequestSendError {
                message,
                status: Status::cancelled("native request channel owner cancelled"),
            });
        }
        let Some(sender) = &self.sender else {
            return Err(NativeRequestSendError {
                message,
                status: Status::failed_precondition("native request sender is closed"),
            });
        };
        sender.try_send(message).map_err(|error| {
            let (message, status) = match error {
                mpsc::SendError::Full(message) => (message, Status::resource_exhausted("native request buffer is full")),
                mpsc::SendError::Cancelled(message) => (message, Status::cancelled("native request send cancelled")),
                mpsc::SendError::Disconnected(message) => (message, self.control.send_error().unwrap_or_else(|| {
                    Status::failed_precondition("native request consumer has retired")
                })),
            };
            NativeRequestSendError { message, status }
        })
    }

    /// Stop accepting requests; deliver every queued message before source EOF.
    /// This is local half-close intent, not an RPC completion acknowledgement.
    pub fn close(&mut self) -> Result<(), Status> {
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        {
            let mut state = self.control.0.lock();
            match &state.state {
                State::Failed(status) => return Err(status.clone()),
                State::Retired => return Err(Status::failed_precondition("native request consumer has retired")),
                State::Open => state.state = State::HalfClosed,
                State::HalfClosed => {}
            }
        }
        drop(self.sender.take());
        Ok(())
    }

    /// Fail the source with an exact non-OK status, without queueing a message.
    /// The first failure wins. An OK status is rejected without closing input.
    /// Cancellation can override a requested half-close until the source retires.
    /// Once the source has published the end of its input, the request can no
    /// longer be aborted and this returns `FailedPrecondition`.
    pub fn fail(&mut self, status: Status) -> Result<(), Status> {
        if status.code() == Code::Ok {
            return Err(Status::invalid_argument("request failure status must not be OK"));
        }
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        // Own the channel locally before invoking a possibly panicking waker.
        let sender = self.sender.take();
        let failed = self.control.fail(status);
        drop(sender);
        if failed {
            Ok(())
        } else {
            Err(Status::failed_precondition(
                "native request source already completed",
            ))
        }
    }

    /// Abort only this request source, not its parent context.
    pub fn cancel(&mut self) {
        let _ = self.fail(Status::cancelled("native request sender cancelled"));
    }
}

impl<T> Drop for NativeRequestSender<T> {
    fn drop(&mut self) {
        if self.sender.is_some() {
            self.cancel();
        }
    }
}

/// Streaming half of [`native_request_channel`].
///
/// The native driver pulls only when its encoded upload slot is free. Queued
/// objects are bounded by count, not their heap size: configure the transport's
/// send-message limit and apply an application object-size policy as well.
/// Source cancellation is observed even while its context is masked; checkpoint
/// acknowledgement still respects the mask. Dropping the source closes the
/// queue, releases queued objects and wakes a producer blocked on capacity.
pub struct NativeRequestStream<T> {
    cx: Cx,
    receiver: Option<mpsc::Receiver<T>>,
    control: Arc<RequestControl>,
    cancelled: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl<T> fmt::Debug for NativeRequestStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRequestStream")
            .field("finished", &self.receiver.is_none())
            .finish_non_exhaustive()
    }
}

impl<T> NativeRequestStream<T> {
    fn retire(&mut self) {
        let receiver = self.receiver.take();
        let cancelled = self.cancelled.take();
        self.control.retire();
        drop(receiver);
        drop(cancelled);
    }
}

impl<T: Send> Streaming for NativeRequestStream<T> {
    type Message = T;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<T, Status>>> {
        let this = self.get_mut();
        let _ambient = Cx::set_current(Some(this.cx.clone()));
        if this.receiver.is_none() {
            return Poll::Ready(None);
        }
        let failed = this.control.poll_failure(task);
        let cancelled = this.cancelled.as_mut().expect("live cancellation observer")
            .as_mut().poll(task).is_ready();
        if let Some(status) = failed.or_else(|| cancelled.then(|| {
            let _ = this.cx.checkpoint();
            Status::cancelled("native request channel owner cancelled")
        })) {
            this.retire();
            return Poll::Ready(Some(Err(status)));
        }
        match this.receiver.as_mut().expect("live request receiver").poll_recv(&this.cx, task) {
            Poll::Ready(Ok(message)) => Poll::Ready(Some(Ok(message))),
            // `Empty` is only produced by `try_recv`; it is unreachable from
            // `poll_recv` and is handled as cancellation for exhaustiveness.
            Poll::Ready(Err(mpsc::RecvError::Cancelled | mpsc::RecvError::Empty)) => {
                this.retire();
                Poll::Ready(Some(Err(Status::cancelled("native request receive cancelled"))))
            }
            Poll::Ready(Err(mpsc::RecvError::Disconnected)) => {
                // Sender drop publishes failure before disconnecting. Recheck
                // after recv so a racing drop cannot be mistaken for EOF.
                let failure = this.control.finish_input();
                this.retire();
                Poll::Ready(failure.map(Err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Drop for NativeRequestStream<T> {
    fn drop(&mut self) {
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        self.retire();
    }
}

/// Create bounded typed input without spawning a producer or network driver.
///
/// `capacity` must be in `1..=MAX_STREAM_BUFFERED`. The channel stores at most
/// that many message objects, plus one input owned by a pending `send`. A native
/// call can separately retain one encoded outbound message and its transport
/// buffers. These limits are not an allocator/RSS bound. No runtime effect or
/// I/O capability is minted by constructing this channel.
///
/// Pass the stream to a native streaming call and drive responses concurrently
/// with sends. Direct use as an arbitrary `Streaming` source observes failure
/// on its next source poll; this source alone cannot interrupt an unpolled or
/// flow-control-blocked transport.
pub fn native_request_channel<T: Send>(
    cx: &Cx,
    capacity: usize,
) -> Result<(NativeRequestSender<T>, NativeRequestStream<T>), Status> {
    if capacity == 0 || capacity > MAX_STREAM_BUFFERED {
        return Err(Status::invalid_argument("native request capacity is outside 1..=MAX_STREAM_BUFFERED"));
    }
    let (sender, receiver) = mpsc::channel(capacity);
    let control = Arc::new(RequestControl::default());
    let owner = cx.clone();
    Ok((
        NativeRequestSender {
            cx: cx.clone(), sender: Some(sender), control: Arc::clone(&control), capacity,
        },
        NativeRequestStream {
            cx: cx.clone(), receiver: Some(receiver), control,
            cancelled: Some(Box::pin(async move { owner.cancelled().await })),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CancelKind;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    fn counter() -> (Arc<Wakes>, Waker) {
        let wakes = Arc::new(Wakes::default());
        (Arc::clone(&wakes), Waker::from(wakes))
    }
    fn next<T: Send>(stream: &mut NativeRequestStream<T>) -> Poll<Option<Result<T, Status>>> {
        Pin::new(stream).poll_next(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn capacity_is_checked_before_allocation() {
        let cx = Cx::for_testing();
        for capacity in [0, MAX_STREAM_BUFFERED + 1, usize::MAX] {
            assert_eq!(native_request_channel::<()>(&cx, capacity).unwrap_err().code(), Code::InvalidArgument);
        }
    }

    #[test]
    fn full_queue_returns_input_and_explicit_close_drains_in_order() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 2).unwrap();
        sender.try_send(1).unwrap();
        sender.try_send(2).unwrap();
        let error = sender.try_send(3).unwrap_err();
        assert_eq!(error.status().code(), Code::ResourceExhausted);
        assert_eq!(error.into_inner(), 3);
        sender.close().unwrap();
        sender.close().unwrap();
        drop(sender);
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(2)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn send_waits_for_capacity_and_receiving_wakes_it() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(1).unwrap();
        let (wakes, waker) = counter();
        let mut sending = Box::pin(sender.send(2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        assert!(wakes.0.load(Ordering::SeqCst) > 0, "capacity must wake the producer");
        assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Ok(()))));
        drop(sending);
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(2)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn dropped_send_does_not_enqueue_and_sender_remains_usable() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(1).unwrap();
        let mut sending = Box::pin(sender.send(2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        drop(sending);
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        sender.try_send(3).unwrap();
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(3)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn open_sender_drop_is_failure_even_with_queued_messages() {
        let cx = Cx::for_testing();
        for queued in [false, true] {
            let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
            if queued { sender.try_send(7).unwrap(); }
            drop(sender);
            assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status))) if status.code() == Code::Cancelled));
            assert!(matches!(next(&mut stream), Poll::Ready(None)));
        }
    }

    #[test]
    fn producer_failure_bypasses_full_queue_and_preserves_first_status() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(7).unwrap();
        sender.fail(Status::resource_exhausted("producer limit")).unwrap();
        sender.cancel();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status)))
            if status.code() == Code::ResourceExhausted && status.message() == "producer limit"));
        assert!(!cx.is_cancel_requested());
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn failure_wakes_a_parked_source_and_ok_cannot_fake_failure() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel::<u8>(&cx, 1).unwrap();
        assert_eq!(sender.fail(Status::new(Code::Ok, "not a failure")).unwrap_err().code(), Code::InvalidArgument);
        let (wakes, waker) = counter();
        assert!(Pin::new(&mut stream).poll_next(&mut Context::from_waker(&waker)).is_pending());
        sender.fail(Status::internal("source error")).unwrap();
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status))) if status.message() == "source error"));
    }

    #[test]
    fn receiver_drop_wakes_a_capacity_blocked_send() {
        let cx = Cx::for_testing();
        let (mut sender, stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(1).unwrap();
        let (wakes, waker) = counter();
        let mut sending = Box::pin(sender.send(2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(stream);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(status)) if status.code() == Code::FailedPrecondition));
        drop(sending);
        assert!(sender.is_closed());
    }

    #[test]
    fn owner_cancellation_wakes_sender_and_receiver_without_network_progress() {
        for full in [false, true] {
            let cx = Cx::for_testing();
            let (mut sender, mut stream) = native_request_channel(&cx, 1).unwrap();
            let (wakes, waker) = counter();
            if full {
                sender.try_send(1).unwrap();
                let mut sending = Box::pin(sender.send(2));
                assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                cx.cancel_with(CancelKind::User, Some("stop upload"));
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)),
                    Poll::Ready(Err(status)) if status.code() == Code::Cancelled));
            } else {
                assert!(Pin::new(&mut stream).poll_next(&mut Context::from_waker(&waker)).is_pending());
                cx.cancel_with(CancelKind::User, Some("stop upload"));
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
            }
            assert!(matches!(next(&mut stream), Poll::Ready(Some(Err(status))) if status.code() == Code::Cancelled));
            assert!(matches!(next(&mut stream), Poll::Ready(None)));
        }
    }

    #[test]
    fn producer_cancellation_is_separate_from_rpc_owner_cancellation() {
        let owner = Cx::for_testing();
        let caller = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel(&owner, 1).unwrap();
        sender.try_send(1).unwrap();
        let (wakes, waker) = counter();
        let mut sending = Box::pin(sender.send_with_cx(&caller, 2));
        assert!(sending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        caller.cancel_with(CancelKind::User, Some("producer only"));
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(sending.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(status)) if status.code() == Code::Cancelled));
        drop(sending);
        assert!(!owner.is_cancel_requested());
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(1)))));
        sender.try_send(3).unwrap();
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(Some(Ok(3)))));
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }

    #[test]
    fn nonunpin_messages_need_no_clone_or_debug_and_drop_under_owner_context() {
        struct Message {
            owner: crate::types::TaskId,
            drops: Arc<AtomicUsize>,
            _pin: std::marker::PhantomPinned,
        }
        impl Drop for Message {
            fn drop(&mut self) {
                assert_eq!(Cx::current().unwrap().task_id(), self.owner);
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        let cx = Cx::for_testing();
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut sender, stream) = native_request_channel(&cx, 1).unwrap();
        sender.try_send(Message { owner: cx.task_id(), drops: Arc::clone(&drops), _pin: std::marker::PhantomPinned }).unwrap();
        drop(stream);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(sender.is_closed());
    }

    /// br-asupersync-244ump L3: a failure before the source publishes the end
    /// of its input still overrides a requested half-close. Once that end is
    /// published, fail() is refused, as close() is, instead of returning Ok
    /// for an abort that cannot take effect.
    #[test]
    fn fail_after_the_end_of_input_is_published_is_refused() {
        let cx = Cx::for_testing();
        let (mut sender, mut stream) = native_request_channel::<u8>(&cx, 1).unwrap();
        sender.close().unwrap();
        sender
            .fail(Status::data_loss("abort before the end"))
            .unwrap();
        assert!(matches!(
            next(&mut stream),
            Poll::Ready(Some(Err(status))) if status.code() == Code::DataLoss
        ));

        let (mut sender, mut stream) = native_request_channel::<u8>(&cx, 1).unwrap();
        sender.close().unwrap();
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
        let refused = sender
            .fail(Status::data_loss("abort after the end"))
            .unwrap_err();
        assert_eq!(refused.code(), Code::FailedPrecondition);
        assert!(matches!(next(&mut stream), Poll::Ready(None)));
    }
}
