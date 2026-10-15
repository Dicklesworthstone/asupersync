//! Single-consumer, payload-preserving terminal receipts for acknowledged work.

use super::{Cx, Item, SendError, SendPermit, Sender};
use crate::channel::oneshot;
use std::fmt;
use std::num::NonZeroU64;

/// Actual disposition of one accepted item, not a claim about external effects.
#[non_exhaustive]
pub enum SettlementOutcome<T> {
    /// A worker called `Delivery::ack`; the worker receives the acknowledged value.
    Acknowledged,
    /// A worker explicitly rejected the item. The producer regains its payload.
    Rejected(T),
    /// Every receiver disappeared before acknowledgement. The payload is returned.
    Abandoned(T),
    /// The opted-in issued-delivery limit was reached without acknowledgement.
    /// The producer regains the possibly mutated payload for explicit recovery.
    RetryExhausted(T),
}

impl<T> fmt::Debug for SettlementOutcome<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Acknowledged => "Acknowledged",
            Self::Rejected(_) => "Rejected(<redacted>)",
            Self::Abandoned(_) => "Abandoned(<redacted>)",
            Self::RetryExhausted(_) => "RetryExhausted(<redacted>)",
        })
    }
}

/// Terminal physical queue disposition, including the exact queue-local identity.
///
/// It does not certify that external effects occurred exactly once, that a
/// runtime ledger projection completed, or that worker tasks have joined.
#[non_exhaustive]
#[must_use = "inspect the disposition; a terminal result is not necessarily an acknowledgement"]
pub struct Settlement<T> {
    /// Queue-local item sequence, identical to the submitted receipt's identity.
    pub sequence: u64,
    /// Physical receive attempts, including refused Ack admissions.
    pub attempts: u64,
    /// Deliveries issued to workers, excluding refused or cancelled admission.
    pub deliveries: u64,
    /// Acknowledgement or the payload's explicit negative disposition.
    pub outcome: SettlementOutcome<T>,
}

impl<T> fmt::Debug for Settlement<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settlement")
            .field("sequence", &self.sequence)
            .field("attempts", &self.attempts)
            .field("deliveries", &self.deliveries)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// An observation failure, never substituted for a queue acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// This borrowing wait observed caller cancellation; the receipt is resumable.
    #[error("acknowledgement receipt wait cancelled")]
    Cancelled,
    /// The receipt was already consumed or its publication path disappeared.
    /// An unknown disposition must be reconciled, never treated as successful work.
    #[error("acknowledgement receipt is closed without another terminal result")]
    Closed,
}

/// A single-owner terminal receipt which does not retain a queue endpoint.
///
/// Dropping this receipt relinquishes its eventual result, NOT the submitted
/// work. Dropping a borrowing wait preserves the receipt. Negative settlements
/// return the original, possibly mutated payload without cloning it. Results
/// retained by callers are outside the queue's item/byte capacity accounting.
#[must_use = "retain the receipt to distinguish acknowledgement from returned work"]
pub struct Receipt<T> {
    sequence: u64,
    receiver: oneshot::Receiver<Settlement<T>>,
    retry: RetryPolicy,
}

impl<T> fmt::Debug for Receipt<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AckReceipt")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl<T> Receipt<T> {
    /// Queue-local identity assigned by the original send reservation.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The immutable policy selected at publication, including the initial delivery.
    #[must_use]
    pub const fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// Take a ready settlement without waiting. `None` means still unresolved.
    pub fn try_take(&mut self) -> Result<Option<Settlement<T>>, ReceiptError> {
        match self.receiver.try_recv() {
            Ok(value) => Ok(Some(value)),
            Err(oneshot::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(ReceiptError::Closed),
        }
    }

    /// Wait with explicit caller cancellation. Cancellation consumes no settlement.
    pub async fn wait(&mut self, cx: &Cx) -> Result<Settlement<T>, ReceiptError> {
        match self.receiver.recv(cx).await {
            Ok(value) => Ok(value),
            Err(oneshot::RecvError::Cancelled) => Err(ReceiptError::Cancelled),
            Err(_) => Err(ReceiptError::Closed),
        }
    }

    /// Observe the same terminal result without a caller-cancellation shortcut.
    /// Dropping this borrowing future still preserves the receipt and its value.
    pub async fn wait_uninterruptible(&mut self) -> Result<Settlement<T>, ReceiptError> {
        self.receiver
            .recv_uninterruptible()
            .await
            .map_err(|_| ReceiptError::Closed)
    }
}

/// Per-item delivery allowance, separate from task restart intensity or timeouts.
///
/// A limit includes the first delivery. Only a guard actually returned to a
/// worker spends an attempt; checked-admission refusal and cancellation before
/// handoff do not. Expiry is checked on nack/Drop, never while a worker owns the
/// item. Ordinary sends preserve their existing unlimited-redelivery behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_deliveries: Option<NonZeroU64>,
}

impl RetryPolicy {
    /// Keep redelivering until a worker acknowledges or explicitly rejects the item.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_deliveries: None,
        }
    }

    /// Return the item after this many issued deliveries end without acknowledgement.
    /// The nonzero type prevents a job from being refused before its first attempt.
    #[must_use]
    pub const fn limited(max_deliveries: NonZeroU64) -> Self {
        Self {
            max_deliveries: Some(max_deliveries),
        }
    }

    /// Maximum issued deliveries, including the initial one; None means unlimited.
    #[must_use]
    pub const fn max_deliveries(self) -> Option<NonZeroU64> {
        self.max_deliveries
    }

    pub(super) fn exhausted(self, deliveries: u64) -> bool {
        self.max_deliveries
            .is_some_and(|limit| deliveries >= limit.get())
    }
}

impl<T> Sender<T> {
    /// Publish without waiting and retain a separate receipt for actual settlement.
    /// A refused send returns the unpublished value, not a fabricated receipt.
    pub fn try_send_tracked(&self, cx: &Cx, value: T) -> Result<Receipt<T>, SendError<T>> {
        self.try_send_tracked_with_policy(cx, value, RetryPolicy::unlimited())
    }

    /// Publish with an explicit delivery allowance and payload-return receipt.
    /// A retry limit is not a deadline, backoff policy, or external-effect rollback.
    pub fn try_send_tracked_with_policy(
        &self,
        cx: &Cx,
        value: T,
        retry: RetryPolicy,
    ) -> Result<Receipt<T>, SendError<T>> {
        match self.try_reserve(cx) {
            Ok(permit) => permit.send_tracked_with_policy(value, retry),
            Err(error) => Err(SendError { error, value }),
        }
    }

    /// Wait for capacity, publish, then return a receipt without waiting for a worker.
    /// Before publication this owning future has the same value-drop semantics as
    /// `Sender::send`; reserve first to keep that value outside the waiting future.
    pub async fn send_tracked(&self, cx: &Cx, value: T) -> Result<Receipt<T>, SendError<T>> {
        self.send_tracked_with_policy(cx, value, RetryPolicy::unlimited())
            .await
    }

    /// Wait for capacity and publish with an explicit issued-delivery allowance.
    /// Dropping before publication drops the caller-owned value, as with `send`.
    pub async fn send_tracked_with_policy(
        &self,
        cx: &Cx,
        value: T,
        retry: RetryPolicy,
    ) -> Result<Receipt<T>, SendError<T>> {
        match self.reserve(cx).await {
            Ok(permit) => permit.send_tracked_with_policy(value, retry),
            Err(error) => Err(SendError { error, value }),
        }
    }
}

impl<T> SendPermit<T> {
    /// Commit this reservation and return a receipt. No cancellation recheck is made.
    /// Pre-close credits remain valid. Each tracked item allocates one oneshot.
    pub fn send_tracked(self, value: T) -> Result<Receipt<T>, SendError<T>> {
        self.send_tracked_with_policy(value, RetryPolicy::unlimited())
    }

    /// Commit a preissued credit with an explicit retry limit and recovery receipt.
    /// Exhaustion is a negative settlement and cannot become successful drain.
    pub fn send_tracked_with_policy(
        self,
        value: T,
        retry: RetryPolicy,
    ) -> Result<Receipt<T>, SendError<T>> {
        let sequence = self.sequence;
        let (sender, receiver) = oneshot::channel();
        self.publish(value, Some(sender), retry)?;
        Ok(Receipt {
            sequence,
            receiver,
            retry,
        })
    }
}

// Terminal publication is retained before arbitrary ledger notifications. A
// cancellation-aware send would erase a completed result, so use the existing
// Cx-independent, immediate in-memory oneshot bridge instead.
pub(super) struct Publication<T> {
    sender: Option<oneshot::Sender<Settlement<T>>>,
    settlement: Option<Settlement<T>>,
}

impl<T> Publication<T> {
    pub(super) fn new(
        sender: Option<oneshot::Sender<Settlement<T>>>,
        settlement: Settlement<T>,
    ) -> Self {
        Self {
            sender,
            settlement: Some(settlement),
        }
    }

    pub(super) fn returned(item: Item<T>, disposition: fn(T) -> SettlementOutcome<T>) -> Self {
        let Item {
            value,
            sequence,
            attempts,
            deliveries,
            receipt,
            ..
        } = item;
        Self::new(
            receipt,
            Settlement {
                sequence,
                attempts,
                deliveries,
                outcome: disposition(value),
            },
        )
    }
}

impl<T> Drop for Publication<T> {
    fn drop(&mut self) {
        let sender = self.sender.take();
        let settlement = self.settlement.take().expect("one terminal publication");
        // A producer who dropped its receipt relinquished its payload. Contain
        // retirement panics so that this cannot skip ledger settlement or the
        // queue's remaining wake fanout, including during worker unwinding.
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(sender) = sender {
                drop(sender.send_blocking(settlement));
            } else {
                drop(settlement);
            }
        })) {
            std::mem::forget(payload);
        }
    }
}

pub(super) struct AbandonedItem<T>(pub(super) Option<Item<T>>);
impl<T> Drop for AbandonedItem<T> {
    fn drop(&mut self) {
        abandon_items(self.0.take());
    }
}

// Last-receiver teardown must notify every tracked item, even when an unrelated
// untracked payload destructor fails. Preserve the first ordinary teardown panic
// only after completing all terminal publications; suppress secondary panics.
pub(super) fn abandon_items<T>(items: impl IntoIterator<Item = Item<T>>) {
    let unwinding = std::thread::panicking();
    let mut first = None;
    for item in items {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if item.receipt.is_some() {
                drop(Publication::returned(item, SettlementOutcome::Abandoned));
            } else {
                drop(item);
            }
        }));
        if let Err(payload) = result {
            if !unwinding && first.is_none() {
                first = Some(payload);
            } else {
                std::mem::forget(payload);
            }
        }
    }
    if let Some(payload) = first {
        std::panic::resume_unwind(payload);
    }
}
