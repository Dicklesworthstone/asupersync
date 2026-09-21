//! Bounded work delivery with explicit acknowledgement and drop-time redelivery.
//!
//! Unlike an ordinary MPSC receive, taking a [`Delivery`] does not release queue
//! capacity or remove the item from the unfinished-work count. [`Delivery::ack`]
//! commits consumption; [`Delivery::nack`] and Drop return the same owned value
//! to the ready queue. Workers can be cloned and replaced without cloning `T`.
//!
//! Capacity includes ready items, send reservations AND outstanding deliveries.
//! Redelivery therefore needs no new capacity and never waits for a producer.
//! Send and acknowledgement obligations use checked runtime admission. A context
//! deliberately constructed without a runtime retains its untracked semantics.
//!
//! # Boundaries
//!
//! This is in-memory at-least-once delivery, not durable or exactly-once execution.
//! A live delivery is never stolen or expired. Dropping its owning future returns
//! it; forgetting the delivery can hold capacity forever. Nack preserves any
//! mutations to the value, and cannot undo external side effects. Ready items are
//! selected FIFO; retries join the tail. Waiting tasks have no FIFO admission
//! guarantee. Capacity bounds items, not their payload bytes or waiting futures.
//!
//! Keep a receiver outside restartable workers. Dropping the LAST receiver is
//! explicit abandonment: queued items are destroyed outside the lock, pending
//! sends fail, and outstanding deliveries are destroyed rather than redelivered.
//! Closing admission is different: existing reservations can still publish, and
//! receivers continue until every reservation and delivery has settled.

use crate::cx::{CancelWakerToken, Cx};
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken, ObligationTransferError};
use crate::sync::Notify;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fmt;
use std::future::{Future, poll_fn};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

/// A queue refusal; no variant asserts that an item was processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QueueError {
    /// All item credits are queued, reserved or awaiting acknowledgement.
    #[error("acknowledged work queue is full")]
    Full,
    /// Nothing is ready, but a producer, reservation or delivery can produce work.
    #[error("acknowledged work queue has no ready item")]
    Empty,
    /// Admission closed, all work drained, or all receivers were abandoned.
    #[error("acknowledged work queue is closed")]
    Closed,
    /// The operation's context acknowledged cancellation before publication.
    #[error("acknowledged work queue operation cancelled")]
    Cancelled,
    /// Runtime obligation admission refused; physical ownership was rolled back.
    #[error("acknowledged work queue obligation refused: {0}")]
    Admission(#[from] ObligationAdmissionError),
    /// Some unacknowledged work was destroyed after every receiver was dropped.
    #[error("acknowledged work was abandoned, not drained successfully")]
    Abandoned,
    /// No wrapped item identity is issued.
    #[error("acknowledged work queue item sequence exhausted")]
    SequenceExhausted,
}

/// A send refused before publication, retaining the original caller-owned value.
#[derive(Debug)]
pub struct SendError<T> {
    /// Reason for refusing the send.
    pub error: QueueError,
    /// Value which was not enqueued.
    pub value: T,
}

impl<T> fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.error, f) }
}
impl<T: fmt::Debug> std::error::Error for SendError<T> {}

/// An atomic snapshot of physical item accounting, not a durable receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueueStats {
    /// Total item-credit limit.
    pub capacity: usize,
    /// Items immediately available to workers.
    pub queued: usize,
    /// Uncommitted producer reservations.
    pub reserved: usize,
    /// Items currently owned by delivery guards.
    pub in_flight: usize,
    /// No new producer reservations can be admitted.
    pub admission_closed: bool,
    /// At least one queued or nacked item was destroyed after receiver abandonment.
    pub abandoned: bool,
}

impl QueueStats {
    /// Total item credits still owned by the queue, producers or workers.
    #[must_use]
    pub const fn unfinished(&self) -> usize { self.queued + self.reserved + self.in_flight }
}

struct Item<T> { value: T, sequence: u64, attempts: u64 }
struct State<T> {
    ready: VecDeque<Item<T>>,
    reserved: usize,
    in_flight: usize,
    senders: usize,
    receivers: usize,
    sealed: bool,
    sequence: u64,
    abandoned: bool,
}
struct Shared<T> { state: Mutex<State<T>>, changed: Notify, capacity: usize }

// Never let a notification panic hide a committed queue transition. Notify
// completes its broadcast fanout before resuming the first callback panic.
fn notify(changed: &Notify) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| changed.notify_waiters())) {
        std::mem::forget(payload);
    }
}
struct WakeAfter<'a>(&'a Notify);
impl Drop for WakeAfter<'_> {
    fn drop(&mut self) { notify(self.0); }
}
struct Cancellation<'a> { cx: &'a Cx, token: Option<CancelWakerToken> }
impl Drop for Cancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

impl<T> Shared<T> {
    fn stats(&self) -> QueueStats {
        let state = self.state.lock();
        QueueStats {
            capacity: self.capacity, queued: state.ready.len(), reserved: state.reserved,
            in_flight: state.in_flight,
            admission_closed: state.sealed || state.senders == 0 || state.receivers == 0,
            abandoned: state.abandoned,
        }
    }

    fn close(&self) {
        self.state.lock().sealed = true;
        notify(&self.changed);
    }

    async fn wait_drained(&self, cx: &Cx) -> Result<(), QueueError> {
        self.wait(cx, || {
            let state = self.state.lock();
            if !state.ready.is_empty() || state.reserved != 0 || state.in_flight != 0 {
                Err(QueueError::Empty)
            } else if state.abandoned { Err(QueueError::Abandoned) }
            else { Ok(()) }
        }).await
    }

    async fn wait<R>(&self, cx: &Cx, mut attempt: impl FnMut() -> Result<R, QueueError>) -> Result<R, QueueError> {
        let mut cancellation = Cancellation { cx, token: None };
        let mut notified = self.changed.notified();
        poll_fn(|task| {
            cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token, task.waker()));
            if cx.checkpoint().is_err() { return Poll::Ready(Err(QueueError::Cancelled)); }
            // Register BEFORE inspecting/mutating queue state. A broadcast in
            // the gap either wakes this waiter or makes the condition ready.
            // At most two notification polls per delivered poll, even in a flood.
            if Pin::new(&mut notified).poll(task).is_ready() {
                notified = self.changed.notified();
                if Pin::new(&mut notified).poll(task).is_ready() { task.waker().wake_by_ref(); }
            }
            match attempt() {
                Err(QueueError::Full | QueueError::Empty) => Poll::Pending,
                result => Poll::Ready(result),
            }
        }).await
    }
}

/// Create a bounded, multi-producer/multi-worker acknowledged queue.
///
/// # Panics
/// Panics for zero capacity or an unrepresentable allocation. Queue storage is
/// preallocated so returning a delivery never grows its ready-item buffer.
#[must_use]
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "acknowledged queue capacity must be nonzero");
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            ready: VecDeque::with_capacity(capacity), reserved: 0, in_flight: 0,
            senders: 1, receivers: 1, sealed: false, sequence: 0, abandoned: false,
        }),
        changed: Notify::new(), capacity,
    });
    (Sender { shared: Arc::clone(&shared) }, Receiver { shared })
}

/// Cloneable producer. A permit can outlive the producer which obtained it.
pub struct Sender<T> { shared: Arc<Shared<T>> }
/// Cloneable worker endpoint. Retain one outside restartable worker tasks.
pub struct Receiver<T> { shared: Arc<Shared<T>> }

impl<T> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("AckSender").field("stats", &self.stats()).finish() }
}
impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("AckReceiver").field("stats", &self.stats()).finish() }
}
impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        let shared = Arc::clone(&self.shared);
        let mut state = shared.state.lock();
        state.senders = state.senders.checked_add(1).expect("producer count exhausted");
        drop(state);
        Self { shared }
    }
}
impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        let shared = Arc::clone(&self.shared);
        let mut state = shared.state.lock();
        state.receivers = state.receivers.checked_add(1).expect("worker count exhausted");
        drop(state);
        Self { shared }
    }
}
impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.shared.state.lock().senders -= 1;
        notify(&self.shared.changed);
    }
}
impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let abandoned = {
            let mut state = self.shared.state.lock();
            state.receivers -= 1;
            if state.receivers == 0 {
                state.abandoned |= !state.ready.is_empty();
                Some(std::mem::take(&mut state.ready))
            } else { None }
        };
        let _wake = WakeAfter(&self.shared.changed);
        // Payload destructors can reenter the queue. No queue lock is held.
        drop(abandoned);
    }
}

impl<T> Sender<T> {
    /// Inspect queued, reserved and delivered item credits atomically.
    #[must_use]
    pub fn stats(&self) -> QueueStats { self.shared.stats() }
    /// Seal new reservations. Already issued permits retain their send right.
    pub fn close(&self) { self.shared.close(); }

    /// Wait until ready items, reservations and deliveries have all settled.
    /// An abandoned item makes the result `Abandoned`, never successful drain.
    /// Without `close`, this is only a point-in-time empty observation. This
    /// barrier does not join worker tasks or wait for runtime ledger projection;
    /// the owning region remains the authoritative task/obligation close barrier.
    pub async fn wait_drained(&self, cx: &Cx) -> Result<(), QueueError> {
        self.shared.wait_drained(cx).await
    }

    /// Seal admission and wait for every accepted item to be acknowledged.
    /// Preissued permits still need to send or abort. Dropping/cancelling this
    /// wait does not reopen admission; repeat `wait_drained` to observe progress.
    pub async fn close_and_drain(&self, cx: &Cx) -> Result<(), QueueError> {
        if cx.checkpoint().is_err() { return Err(QueueError::Cancelled); }
        self.close();
        self.wait_drained(cx).await
    }

    /// Reserve without waiting, using checked runtime obligation admission.
    pub fn try_reserve(&self, cx: &Cx) -> Result<SendPermit<T>, QueueError> {
        if cx.checkpoint().is_err() { return Err(QueueError::Cancelled); }
        let sequence = {
            let mut state = self.shared.state.lock();
            if state.sealed || state.receivers == 0 { return Err(QueueError::Closed); }
            if state.ready.len() + state.reserved + state.in_flight == self.shared.capacity {
                return Err(QueueError::Full);
            }
            let sequence = state.sequence.checked_add(1).ok_or(QueueError::SequenceExhausted)?;
            state.sequence = sequence;
            state.reserved += 1;
            sequence
        };
        // Own physical rollback before runtime admission can notify or unwind.
        let mut permit = SendPermit { shared: Arc::clone(&self.shared), sequence, live: true, obligation: None };
        permit.obligation = cx.try_register_obligation_checked(ObligationKind::SendPermit, cx.task_id())?;
        if cx.checkpoint().is_err() { return Err(QueueError::Cancelled); }
        Ok(permit)
    }

    /// Wait for an item credit; cancellation/drop leaves no reserved slot.
    pub async fn reserve(&self, cx: &Cx) -> Result<SendPermit<T>, QueueError> {
        self.shared.wait(cx, || self.try_reserve(cx)).await
    }

    /// Publish immediately or return the unpublished value with its refusal.
    pub fn try_send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        match self.try_reserve(cx) {
            Ok(permit) => permit.send(value),
            Err(error) => Err(SendError { error, value }),
        }
    }

    /// Wait for capacity and publish. A returned error retains the value.
    /// Dropping this owning future before publication drops its caller-owned value;
    /// use reserve with an externally retained value when that is undesirable.
    pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        match self.reserve(cx).await {
            Ok(permit) => permit.send(value),
            Err(error) => Err(SendError { error, value }),
        }
    }
}

impl<T> Receiver<T> {
    /// Inspect queued, reserved and delivered item credits atomically.
    #[must_use]
    pub fn stats(&self) -> QueueStats { self.shared.stats() }
    /// Seal producer admission without abandoning queued or delivered work.
    pub fn close(&self) { self.shared.close(); }

    /// Take one item with a checked Ack obligation, or leave/requeue it on refusal.
    /// An empty queue is not EOF while a delivery or send reservation can return work.
    pub fn try_recv_with_ack(&self, cx: &Cx) -> Result<Delivery<T>, QueueError> {
        if cx.checkpoint().is_err() { return Err(QueueError::Cancelled); }
        let mut item = {
            let mut state = self.shared.state.lock();
            if let Some(item) = state.ready.pop_front() {
                state.in_flight += 1;
                item
            } else if (state.sealed || state.senders == 0) && state.reserved == 0 && state.in_flight == 0 {
                return Err(QueueError::Closed);
            } else { return Err(QueueError::Empty); }
        };
        item.attempts = item.attempts.saturating_add(1);
        let mut delivery = Delivery { shared: Arc::clone(&self.shared), item: Some(item), obligation: None };
        delivery.obligation = cx.try_register_obligation_checked(ObligationKind::Ack, cx.task_id())?;
        if cx.checkpoint().is_err() { return Err(QueueError::Cancelled); }
        Ok(delivery)
    }

    /// Wait for an acknowledged delivery. Dropping the wait consumes no item.
    /// The returned guard, unlike an ordinary received value, nacks on Drop.
    pub async fn recv_with_ack(&self, cx: &Cx) -> Result<Delivery<T>, QueueError> {
        self.shared.wait(cx, || self.try_recv_with_ack(cx)).await
    }
}

/// A refused holder transfer retaining the original resource guard.
/// Dropping this failure drops its guard (abort for a permit, nack for a delivery).
#[derive(Debug)]
#[must_use = "recover the original guard or deliberately abort/nack it"]
pub struct TransferFailure<G> {
    /// Original runtime refusal, with no invented destination ownership.
    pub error: ObligationTransferError,
    /// Guard retaining its original holder, payload/credit and queue identity.
    pub guard: G,
}
impl<G> fmt::Display for TransferFailure<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.error, f) }
}
impl<G: fmt::Debug> std::error::Error for TransferFailure<G> {}

fn transfer<Caps>(slot: &mut Option<ObligationToken>, destination: &Cx<Caps>) -> Result<(), ObligationTransferError> {
    let token = slot.take().ok_or(ObligationTransferError::SourceNotChecked)?;
    match token.try_transfer(destination) {
        Ok(next) => { *slot = Some(next); Ok(()) }
        Err(failure) => {
            let (error, original) = failure.into_parts();
            *slot = Some(original);
            Err(error)
        }
    }
}

/// Owned send credit. Drop/abort releases capacity and aborts its tracked obligation.
#[must_use = "send a value or abort the reservation"]
pub struct SendPermit<T> {
    shared: Arc<Shared<T>>, sequence: u64, live: bool, obligation: Option<ObligationToken>,
}
impl<T> fmt::Debug for SendPermit<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("AckSendPermit").field("sequence", &self.sequence).finish_non_exhaustive() }
}
impl<T> SendPermit<T> {
    /// Transfer runtime liability to an actual live task in the same runtime.
    /// Refusal retains this exact credit; untracked guards refuse explicitly.
    /// A notification panic follows the runtime's transfer contract and Drop
    /// releases the physical reservation. It never fabricates a delivered value.
    pub fn try_transfer<Caps>(mut self, destination: &Cx<Caps>) -> Result<Self, TransferFailure<Self>> {
        match transfer(&mut self.obligation, destination) {
            Ok(()) => Ok(self),
            Err(error) => Err(TransferFailure { error, guard: self }),
        }
    }

    /// Commit without a cancellation checkpoint. Closing admission does not
    /// revoke this credit, but last-receiver abandonment returns the value.
    pub fn send(mut self, value: T) -> Result<(), SendError<T>> {
        let mut item = Some(Item { value, sequence: self.sequence, attempts: 0 });
        {
            let mut state = self.shared.state.lock();
            state.reserved -= 1;
            self.live = false;
            if state.receivers != 0 { state.ready.push_back(item.take().expect("owned unpublished item")); }
        }
        let _wake = WakeAfter(&self.shared.changed);
        if let Some(item) = item {
            if let Some(token) = self.obligation.take() { let _ = token.abort(ObligationAbortReason::Error); }
            Err(SendError { error: QueueError::Closed, value: item.value })
        } else {
            if let Some(token) = self.obligation.take() { let _ = token.commit(); }
            Ok(())
        }
    }
    /// Release an unused credit. No queue payload has been published.
    pub fn abort(self) { drop(self); }
}
impl<T> Drop for SendPermit<T> {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            self.shared.state.lock().reserved -= 1;
            let _wake = WakeAfter(&self.shared.changed);
            if let Some(token) = self.obligation.take() { let _ = token.abort(ObligationAbortReason::Cancel); }
        }
    }
}

/// Exclusive ownership of an unacknowledged item; dereferences to its value.
///
/// A delivery has no Clone or value-extraction method except acknowledgement.
/// Nack/Drop returns the same (possibly mutated) value to the queue tail while
/// another receiver survives. Resolve before the receiving task exits: moving
/// a guard does not automatically transfer its runtime obligation holder.
#[must_use = "acknowledge after processing; dropping redelivers unfinished work"]
pub struct Delivery<T> { shared: Arc<Shared<T>>, item: Option<Item<T>>, obligation: Option<ObligationToken> }
impl<T> fmt::Debug for Delivery<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delivery").field("sequence", &self.sequence()).field("attempts", &self.attempts()).finish_non_exhaustive()
    }
}
impl<T> Delivery<T> {
    /// Transfer the Ack liability before handing this delivery to another task.
    /// Queue item identity, payload, attempt count and capacity remain unchanged.
    /// Refusal returns the original guard. A notification panic aborts any
    /// unreturned destination obligation and this guard's Drop requeues the item.
    pub fn try_transfer<Caps>(mut self, destination: &Cx<Caps>) -> Result<Self, TransferFailure<Self>> {
        match transfer(&mut self.obligation, destination) {
            Ok(()) => Ok(self),
            Err(error) => Err(TransferFailure { error, guard: self }),
        }
    }

    /// Queue-local item identity, preserved through every retry; gaps are allowed.
    #[must_use]
    pub fn sequence(&self) -> u64 { self.item.as_ref().expect("live delivery").sequence }
    /// Physical delivery attempts, including refused Ack admissions; saturates at u64::MAX.
    #[must_use]
    pub fn attempts(&self) -> u64 { self.item.as_ref().expect("live delivery").attempts }
    /// Commit consumption, release capacity, and return the acknowledged value.
    /// No cancellation checkpoint can undo this explicit terminal transition.
    pub fn ack(mut self) -> T {
        let item = self.item.take().expect("live delivery");
        self.shared.state.lock().in_flight -= 1;
        let _wake = WakeAfter(&self.shared.changed);
        if let Some(token) = self.obligation.take() { let _ = token.commit(); }
        item.value
    }
    /// Return the value to the ready tail without releasing its capacity credit.
    pub fn nack(self) { drop(self); }
}
impl<T> Deref for Delivery<T> {
    type Target = T;
    fn deref(&self) -> &T { &self.item.as_ref().expect("live delivery").value }
}
impl<T> DerefMut for Delivery<T> {
    fn deref_mut(&mut self) -> &mut T { &mut self.item.as_mut().expect("live delivery").value }
}
impl<T> Drop for Delivery<T> {
    fn drop(&mut self) {
        if let Some(item) = self.item.take() {
            let mut abandoned = Some(item);
            {
                let mut state = self.shared.state.lock();
                state.in_flight -= 1;
                if state.receivers != 0 { state.ready.push_back(abandoned.take().expect("owned retry")); }
                else { state.abandoned = true; }
            }
            let _wake = WakeAfter(&self.shared.changed);
            if let Some(token) = self.obligation.take() { let _ = token.abort(ObligationAbortReason::Cancel); }
            drop(abandoned);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "ack/lifecycle_tests.rs"]
mod lifecycle_tests;
