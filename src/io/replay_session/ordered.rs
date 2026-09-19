//! Cross-provider ordering for an explicitly owned consumer replay window.
//!
//! Unlike the independent component windows in [`super::ReplaySession`], this
//! opt-in adapter records the order of completed I/O, clock, and per-source
//! entropy effects. Replay enforces that order before returning recorded values.
//! Early asynchronous I/O waits for its prerequisite and is woken on progress;
//! synchronous clock/entropy reordering fails immediately, not by blocking a
//! thread. A failure in any component invalidates all subsequent effects.
//!
//! Live provider results remain unchanged. Overlapping/reentrant provider calls
//! invalidate capture rather than guessing a cross-thread linearization. Pending
//! I/O polls consume no order entries in the default mode. Opt in with
//! [`OrderedRecordingSession::new_with_pending_io`] to retain pending attempts
//! and enforce every I/O poll's order/shape. Replaying a recorded pending poll
//! returns `Pending` and requests one immediate re-poll, not its original host
//! wake timing. Neither mode captures a task schedule, wake counts, elapsed
//! readiness delays, cancellation, or arbitrary concurrent-program execution.
//! Owners must drain their users before finishing and use their runtime's own
//! deadline/cancellation to bound a parked consumer. No live fallback is used.
//!
//! Providers, payloads, timestamps and entropy are omitted from Debug. Captures
//! contain sensitive data and activity patterns; protect any explicit exports.

use super::{
    RecordedSession, RecordingSession, ReplayConsumerFuture, ReplaySession,
    SessionCaptureError, SessionCaptureLimits, SessionReplayError,
};
use crate::io::replay::{RecordingIo, ReplayIo};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::replay::{RecordingTimeSource, ReplayTimeSource};
use crate::time::TimeSource;
use crate::types::{TaskId, Time};
use crate::util::entropy::EntropySource;
use crate::util::entropy_replay::{EntropyCaptureError, RecordingEntropy, ReplayEntropy};
use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

mod pending;
use pending::PendingInput;
pub use pending::PendingIoCaptureLimits;

mod gate;
use gate::{OrderTape, RecordOrder, ReplayOrder};
pub use gate::{
    OrderCaptureError, OrderCompletionError, OrderReplayError, OrderReplayMismatch, OrderedEffect,
};

/// All capture refusals; no partial ordered session is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ordered session capture refused (order: {order:?}, components: {components:?})")]
pub struct OrderedCaptureError {
    /// Ordering capture/coverage refusal.
    pub order: Option<OrderCaptureError>,
    /// Original component capture refusals.
    pub components: Option<SessionCaptureError>,
}

/// All order and component completion diagnostics, without recorded values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ordered session replay refused (order: {order:?}, components: {components:?})")]
pub struct OrderedReplayError {
    /// Ordering divergence or unused effects.
    pub order: Option<OrderCompletionError>,
    /// Underlying component divergence or unused observations.
    pub components: Option<SessionReplayError>,
}

/// A consumer's output was not accepted as complete ordered replay.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OrderedRunError {
    /// At least one order/component window failed final verification.
    #[error(transparent)]
    Replay(#[from] OrderedReplayError),
    /// The explicit consumer-poll budget was exceeded.
    #[error("ordered replay exceeded its {limit}-poll budget")]
    PollLimit {
        /// Maximum number of consumer polls, including zero.
        limit: usize,
    },
}

/// Live providers with one shared, bounded completed-effect ordering window.
///
/// Finish only after draining all provider users. Retained provider clones keep
/// forwarding after finish, outside the captured window. No task is detached,
/// cancelled, or silently declared quiescent by this adapter.
pub struct OrderedRecordingSession<T, S: ?Sized> {
    io: OrderedRecordingIo<T>,
    entropy: Arc<OrderedRecordingEntropy>,
    clock: Arc<OrderedRecordingClock<S>>,
    recorder: Arc<RecordingEntropy>,
    order: Arc<RecordOrder>,
}

impl<T, S: ?Sized> fmt::Debug for OrderedRecordingSession<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedRecordingSession").finish_non_exhaustive()
    }
}

impl<T: AsyncWrite, S: TimeSource + ?Sized> OrderedRecordingSession<T, S> {
    /// Wrap authorized providers. `max_effects` independently bounds the order.
    /// No source is sampled; the I/O vectored-write capability is queried once.
    pub fn new(
        io: T, entropy: Arc<dyn EntropySource>, clock: Arc<S>,
        limits: SessionCaptureLimits, max_effects: usize,
    ) -> Result<Self, EntropyCaptureError> {
        Self::with_order(io, entropy, clock, limits, RecordOrder::new(max_effects))
    }

    /// Record every pending I/O attempt as well as completed effects.
    ///
    /// `max_effects` bounds ALL order entries; `pending` independently bounds
    /// extra poll storage and write hashing. Live results and wakeups are never
    /// changed. Replay requires exact I/O poll order, capacities, scalar bytes,
    /// and vector shapes, including attempts that were subsequently dropped.
    /// A recorded pending poll yields and requests one immediate continuation;
    /// original wake timing/counts and time inside a poll are not reproduced.
    pub fn new_with_pending_io(
        io: T, entropy: Arc<dyn EntropySource>, clock: Arc<S>,
        limits: SessionCaptureLimits, max_effects: usize, pending: PendingIoCaptureLimits,
    ) -> Result<Self, EntropyCaptureError> {
        Self::with_order(io, entropy, clock, limits, RecordOrder::with_pending(max_effects, Some(pending)))
    }

    fn with_order(
        io: T, entropy: Arc<dyn EntropySource>, clock: Arc<S>,
        limits: SessionCaptureLimits, order: RecordOrder,
    ) -> Result<Self, EntropyCaptureError> {
        let RecordingSession { io, entropy: recorder, clock } =
            RecordingSession::new(io, entropy, clock, limits)?;
        let order = Arc::new(order);
        let source: Arc<dyn EntropySource> = recorder.clone();
        Ok(Self {
            io: OrderedRecordingIo { inner: io, order: Arc::clone(&order) },
            entropy: Arc::new(OrderedRecordingEntropy { inner: source, order: Arc::clone(&order), source: 0 }),
            clock: Arc::new(OrderedRecordingClock { inner: clock, order: Arc::clone(&order) }),
            recorder, order,
        })
    }
}

impl<T, S: TimeSource + ?Sized> OrderedRecordingSession<T, S> {
    /// Borrow the live I/O adapter.
    pub fn io(&mut self) -> &mut OrderedRecordingIo<T> { &mut self.io }

    /// Share the ordered root entropy provider; forks remain ordered.
    #[must_use]
    pub fn entropy(&self) -> Arc<OrderedRecordingEntropy> { Arc::clone(&self.entropy) }

    /// Share the ordered serial clock provider.
    #[must_use]
    pub fn clock(&self) -> Arc<OrderedRecordingClock<S>> { Arc::clone(&self.clock) }

    /// End capture and return the original I/O owner on success AND refusal.
    ///
    /// Close order admission first, finish every component, then cross-check
    /// effect counts and source creation order. A call racing the boundary may
    /// cause refusal but cannot publish unsequenced component observations.
    /// Successful component tapes are dropped if any other window fails.
    pub fn into_parts(self) -> (T, Result<OrderedRecordedSession, OrderedCaptureError>) {
        let order = self.order.finish();
        let base = RecordingSession {
            io: self.io.inner, entropy: self.recorder, clock: Arc::clone(&self.clock.inner),
        };
        let (inner, components) = base.into_parts();
        let errors = OrderedCaptureError {
            order: order.as_ref().err().copied(),
            components: components.as_ref().err().copied(),
        };
        let result = match (order, components) {
            (Ok(order), Ok(components)) if order.covers(&components) => {
                Ok(OrderedRecordedSession { order, components })
            }
            (Ok(_), Ok(_)) => Err(OrderedCaptureError {
                order: Some(OrderCaptureError::InconsistentWindow), components: None,
            }),
            _ => Err(errors),
        };
        (inner, result)
    }
}

/// Complete component tapes plus their completed-effect order; no source owners.
pub struct OrderedRecordedSession {
    components: RecordedSession,
    order: OrderTape,
}

impl fmt::Debug for OrderedRecordedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedRecordedSession")
            .field("effects", &self.order.entries.len()).finish_non_exhaustive()
    }
}

impl OrderedRecordedSession {
    /// Number of order entries, including pending attempts in poll-aware mode.
    #[must_use]
    pub fn effects(&self) -> usize { self.order.entries.len() }

    /// Whether every I/O poll must be reproduced, not just completed results.
    #[must_use]
    pub fn is_poll_aware(&self) -> bool { self.order.poll_aware }

    /// Number of recorded pending I/O attempts, without revealing requests.
    #[must_use]
    pub fn pending_io_polls(&self) -> usize {
        self.order.entries.iter().filter(|entry| entry.pending.is_some()).count()
    }

    /// Reconstruct exclusively offline providers with shared ordering authority.
    #[must_use]
    pub fn replay(self) -> OrderedReplaySession {
        let ReplaySession { io, entropy, clock } = self.components.replay();
        let order = Arc::new(ReplayOrder::new(self.order));
        OrderedReplaySession {
            io: OrderedReplayIo { inner: io, order: Arc::clone(&order) },
            entropy: OrderedReplayEntropy { inner: entropy, order: Arc::clone(&order), source: 0 },
            clock: OrderedReplayClock { inner: clock, order: Arc::clone(&order) },
            order,
        }
    }
}

/// Borrowing inputs for the real consumer being replayed.
#[derive(Debug)]
pub struct OrderedReplayInputs<'a> {
    /// Ordered duplex byte I/O.
    pub io: &'a mut OrderedReplayIo,
    /// Ordered entropy, with exact task identities at forks.
    pub entropy: &'a OrderedReplayEntropy,
    /// Ordered serial clock observations.
    pub clock: &'a OrderedReplayClock,
}

/// Offline ordered providers and joint verification, not a task executor.
pub struct OrderedReplaySession {
    io: OrderedReplayIo,
    entropy: OrderedReplayEntropy,
    clock: OrderedReplayClock,
    order: Arc<ReplayOrder>,
}

impl fmt::Debug for OrderedReplaySession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedReplaySession").finish_non_exhaustive()
    }
}

impl OrderedReplaySession {
    /// Borrow all providers for manual driving under an existing runtime owner.
    pub fn inputs(&mut self) -> OrderedReplayInputs<'_> {
        OrderedReplayInputs { io: &mut self.io, entropy: &self.entropy, clock: &self.clock }
    }

    /// Verify all component tapes AND the order; does not consume observations.
    pub fn verify_complete(&self) -> Result<(), OrderedReplayError> {
        let components = SessionReplayError {
            io: self.io.inner.verify_complete().err(),
            entropy: self.entropy.inner.verify_complete().err(),
            clock: self.clock.inner.verify_complete().err(),
        };
        let components = (components.io.is_some() || components.entropy.is_some() || components.clock.is_some())
            .then_some(components);
        let order = self.order.verify().err();
        if order.is_none() && components.is_none() { Ok(()) }
        else { Err(OrderedReplayError { order, components }) }
    }

    /// Execute a caller-owned consumer, drop its future, then validate every tape.
    ///
    /// Panics propagate. Application errors remain ordinary output, but swallowed
    /// order/component divergence refuses that output. The poll bound does not
    /// bound time inside `poll` or replace an owner deadline
    /// for parked work. Zero refuses before invoking the factory. The consumer
    /// must drain any tasks it creates; this driver owns only its returned future.
    pub async fn run<T, F>(mut self, max_polls: usize, consumer: F) -> Result<T, OrderedRunError>
    where F: for<'a> FnOnce(OrderedReplayInputs<'a>) -> ReplayConsumerFuture<'a, T>,
    {
        if max_polls == 0 { return Err(OrderedRunError::PollLimit { limit: 0 }); }
        let result = {
            let mut future = consumer(self.inputs());
            let mut polls = 0;
            poll_fn(|cx| {
                if polls == max_polls {
                    return Poll::Ready(Err(OrderedRunError::PollLimit { limit: max_polls }));
                }
                polls += 1;
                future.as_mut().poll(cx).map(Ok)
            }).await
        };
        let output = result?;
        self.verify_complete()?;
        Ok(output)
    }
}

/// Live I/O capture with completed-effect ordering, transparent on capture errors.
pub struct OrderedRecordingIo<T> { inner: RecordingIo<T>, order: Arc<RecordOrder> }
impl<T> fmt::Debug for OrderedRecordingIo<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedRecordingIo").finish_non_exhaustive()
    }
}
impl<T> OrderedRecordingIo<T> {
    fn poll_with<R>(
        &mut self, cx: &mut Context<'_>, input: PendingInput<'_, '_>,
        poll: impl FnOnce(&mut RecordingIo<T>, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        let guard = self.order.begin();
        let result = poll(&mut self.inner, cx);
        if let Some(guard) = guard { guard.finish_io(input, result.is_ready()); }
        result
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for OrderedRecordingIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, PendingInput::Read(buf.remaining()), |io, cx| Pin::new(io).poll_read(cx, buf))
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for OrderedRecordingIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, PendingInput::Write(buf), |io, cx| Pin::new(io).poll_write(cx, buf))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, PendingInput::Vectored(bufs), |io, cx| Pin::new(io).poll_write_vectored(cx, bufs))
    }
    fn is_write_vectored(&self) -> bool { self.inner.is_write_vectored() }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, PendingInput::Flush, |io, cx| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, PendingInput::Shutdown, |io, cx| Pin::new(io).poll_shutdown(cx))
    }
}

/// Root or forked live entropy with a shared ordering window.
pub struct OrderedRecordingEntropy { inner: Arc<dyn EntropySource>, order: Arc<RecordOrder>, source: usize }
impl fmt::Debug for OrderedRecordingEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedRecordingEntropy").field("source", &self.source).finish_non_exhaustive()
    }
}
impl EntropySource for OrderedRecordingEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let guard = self.order.begin();
        self.inner.fill_bytes(dest);
        if let Some(guard) = guard { guard.finish(OrderedEffect::Entropy(self.source), true); }
    }
    fn next_u64(&self) -> u64 {
        let guard = self.order.begin();
        let result = self.inner.next_u64();
        if let Some(guard) = guard { guard.finish(OrderedEffect::Entropy(self.source), true); }
        result
    }
    fn fork(&self, task: TaskId) -> Arc<dyn EntropySource> {
        let guard = self.order.begin();
        let inner = self.inner.fork(task);
        let source = guard.map_or(0, |guard| guard.finish(OrderedEffect::Fork(self.source), true));
        Arc::new(Self { inner, order: Arc::clone(&self.order), source })
    }
    fn source_id(&self) -> &'static str { "ordered-recording" }
}

/// Live clock that participates in the shared completed-effect order.
pub struct OrderedRecordingClock<S: ?Sized> { inner: Arc<RecordingTimeSource<S>>, order: Arc<RecordOrder> }
impl<S: ?Sized> fmt::Debug for OrderedRecordingClock<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedRecordingClock").finish_non_exhaustive()
    }
}
impl<S: TimeSource + ?Sized> TimeSource for OrderedRecordingClock<S> {
    fn now(&self) -> Time {
        let guard = self.order.begin();
        let result = self.inner.now();
        if let Some(guard) = guard { guard.finish(OrderedEffect::Clock, true); }
        result
    }
}

/// Offline I/O: early reads/writes wait; same-direction mismatches fail closed.
pub struct OrderedReplayIo { inner: ReplayIo, order: Arc<ReplayOrder> }
impl fmt::Debug for OrderedReplayIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedReplayIo").finish_non_exhaustive()
    }
}
impl OrderedReplayIo {
    fn poll_with<R>(
        &mut self, cx: &mut Context<'_>, input: PendingInput<'_, '_>,
        poll: impl FnOnce(&mut ReplayIo, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        let guard = match ready!(self.order.enter_io(cx, input.operation())) {
            Ok(guard) => guard,
            Err(error) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error))),
        };
        if let Some(expected) = guard.pending_request() {
            let matches = expected.matches(input);
            if let Err(error) = guard.finish(matches) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
            }
            // The transcript, not a live provider, requests the next poll. This
            // preserves the Pending boundary, not original wake timing. No lock
            // or active admission is held across this arbitrary callback.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cx.waker().wake_by_ref()));
            return Poll::Pending;
        }
        let result = poll(&mut self.inner, cx);
        // An admitted I/O turn must be satisfiable by its component immediately.
        // A malformed cross-projection cannot become a permanently parked replay.
        if let Err(error) = guard.finish(result.is_ready() && self.inner.failure().is_none()) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        result
    }
}
impl Drop for OrderedReplayIo {
    fn drop(&mut self) { self.order.clear_waiters(); }
}
impl AsyncRead for OrderedReplayIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, PendingInput::Read(buf.remaining()), |io, cx| Pin::new(io).poll_read(cx, buf))
    }
}
impl AsyncWrite for OrderedReplayIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, PendingInput::Write(buf), |io, cx| Pin::new(io).poll_write(cx, buf))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_with(cx, PendingInput::Vectored(bufs), |io, cx| Pin::new(io).poll_write_vectored(cx, bufs))
    }
    fn is_write_vectored(&self) -> bool { self.inner.is_write_vectored() }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, PendingInput::Flush, |io, cx| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_with(cx, PendingInput::Shutdown, |io, cx| Pin::new(io).poll_shutdown(cx))
    }
}

/// Offline entropy with exact source ordinals and session-wide sticky failure.
#[derive(Clone)]
pub struct OrderedReplayEntropy { inner: ReplayEntropy, order: Arc<ReplayOrder>, source: usize }
impl fmt::Debug for OrderedReplayEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedReplayEntropy").field("source", &self.source).finish_non_exhaustive()
    }
}
impl OrderedReplayEntropy {
    /// Fill exactly the recorded request. Pre-admission refusal leaves `dest` unchanged.
    /// Overlap can invalidate an already-started effect; it does not roll it back.
    pub fn try_fill_bytes(&self, dest: &mut [u8]) -> Result<(), OrderReplayError> {
        let guard = self.order.enter(OrderedEffect::Entropy(self.source))?;
        let result = self.inner.try_fill_bytes(dest);
        guard.finish(result.is_ok())
    }
    /// Return the next recorded u64 only at its captured cross-provider turn.
    pub fn try_next_u64(&self) -> Result<u64, OrderReplayError> {
        let guard = self.order.enter(OrderedEffect::Entropy(self.source))?;
        let result = self.inner.try_next_u64();
        guard.finish(result.is_ok())?;
        Ok(result.expect("component success checked"))
    }
    /// Fork only at the recorded parent turn, retaining exact task identity checks.
    pub fn try_fork(&self, task: TaskId) -> Result<Self, OrderReplayError> {
        let guard = self.order.enter(OrderedEffect::Fork(self.source))?;
        let source = guard.child();
        let result = self.inner.try_fork(task);
        guard.finish(result.is_ok())?;
        Ok(Self { inner: result.expect("component success checked"), order: Arc::clone(&self.order), source })
    }
}
impl EntropySource for OrderedReplayEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap_or_else(|error| std::panic::panic_any(error));
    }
    fn next_u64(&self) -> u64 {
        self.try_next_u64().unwrap_or_else(|error| std::panic::panic_any(error))
    }
    fn fork(&self, task: TaskId) -> Arc<dyn EntropySource> {
        Arc::new(self.try_fork(task).unwrap_or_else(|error| std::panic::panic_any(error)))
    }
    fn source_id(&self) -> &'static str { "ordered-replay" }
}

/// Offline clock that refuses reordered or extra observations without live fallback.
pub struct OrderedReplayClock { inner: ReplayTimeSource, order: Arc<ReplayOrder> }
impl fmt::Debug for OrderedReplayClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedReplayClock").finish_non_exhaustive()
    }
}
impl OrderedReplayClock {
    /// Return the exact next timestamp only at the clock's recorded turn.
    pub fn try_now(&self) -> Result<Time, OrderReplayError> {
        let guard = self.order.enter(OrderedEffect::Clock)?;
        let result = self.inner.try_now();
        guard.finish(result.is_ok())?;
        Ok(result.expect("component success checked"))
    }
}
impl TimeSource for OrderedReplayClock {
    fn now(&self) -> Time {
        self.try_now().unwrap_or_else(|error| std::panic::panic_any(error))
    }
}

#[cfg(test)]
mod tests;

mod codec;
pub use codec::{OrderedSessionBytes, OrderedSessionDecodeLimits, OrderedSessionTapeError};
mod send;
pub use send::OrderedSendConsumerFuture;


#[cfg(test)]
mod pending_tests;
