#![allow(clippy::cast_possible_wrap)]
//! Session-typed two-phase channels with obligation tracking.
//!
//! This module wraps the existing [`mpsc`] and [`oneshot`]
//! channels with obligation-tracked senders that enforce the reserve/commit protocol
//! at the type level. Dropping a [`TrackedPermit`] or [`TrackedOneshotPermit`] without
//! calling `send()` or `abort()` triggers a drop-bomb panic via
//! [`ObligationToken<SendPermit>`](crate::obligation::graded::ObligationToken).
//!
//! The receiver side is unchanged — obligation tracking only affects the sender.
//!
//! The additive `*_checked` sender methods obtain runtime admission through the
//! underlying channel before creating a graded permit. They return the channel's
//! checked error on denial and retain the same explicit commit/abort requirement
//! on success. The graded token does not register a second runtime obligation.
//! Deliberately stateless contexts retain the underlying channel's untracked
//! behavior; the existing graded region requirement still applies.
//!
//! # Two-Phase Protocol
//!
//! ```text
//!   TrackedSender
//!       │
//!       ├── reserve(&cx)  ──► TrackedPermit ──┬── send(v) ──► CommittedProof
//!       │                                     └── abort()  ──► AbortedProof
//!       │                                     └── (drop)   ──► PANIC!
//!       │
//!       ├── try_reserve(&cx) ─► TrackedPermit (or immediate error)
//!       │
//!       └── send(&cx, v)  ──► CommittedProof (convenience: reserve + send)
//! ```
//!
//! # Compile-Fail Examples
//!
//! A permit is consumed on `send`, so calling it twice is a move error:
//!
//! ```compile_fail
//! # // E0382: use of moved value
//! use asupersync::channel::session::*;
//! use asupersync::channel::mpsc;
//! use asupersync::cx::Cx;
//!
//! fn double_send(permit: TrackedPermit<'_, i32>) {
//!     permit.send(42);
//!     permit.send(43); // ERROR: use of moved value
//! }
//! ```
//!
//! Proof tokens cannot be forged — the `_kind` field is private:
//!
//! ```compile_fail
//! # // E0451: field `_kind` of struct `CommittedProof` is private
//! use asupersync::obligation::graded::{CommittedProof, SendPermit};
//! use std::marker::PhantomData;
//!
//! let forged: CommittedProof<SendPermit> = CommittedProof { _kind: PhantomData };
//! ```

use crate::channel::{mpsc, oneshot};
use crate::cx::Cx;
use crate::obligation::graded::{AbortedProof, CommittedProof, ObligationToken, SendPermit};
use crate::types::RegionId;

fn reserve_tracked_send_obligation_for_region(
    description: &'static str,
    region: RegionId,
) -> ObligationToken<SendPermit> {
    #[cfg(any(test, feature = "test-internals"))]
    if region.as_u64() == 0 {
        return ObligationToken::<SendPermit>::reserve_test(description);
    }

    ObligationToken::<SendPermit>::reserve(description, region)
}

fn checked_mpsc_error_with_value<T>(
    error: mpsc::CheckedSendError<()>,
    value: T,
) -> mpsc::CheckedSendError<T> {
    match error {
        mpsc::CheckedSendError::Channel(error) => mpsc::CheckedSendError::Channel(match error {
            mpsc::SendError::Disconnected(()) => mpsc::SendError::Disconnected(value),
            mpsc::SendError::Full(()) => mpsc::SendError::Full(value),
            mpsc::SendError::Cancelled(()) => mpsc::SendError::Cancelled(value),
        }),
        mpsc::CheckedSendError::Admission { error, value: () } => {
            mpsc::CheckedSendError::Admission { error, value }
        }
    }
}

/// Redacted telemetry for one underlying channel inside a session wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSubchannelTelemetrySnapshot {
    /// Caller-provided deterministic channel identifier.
    pub channel_id: u64,
    /// Stable underlying channel kind label.
    pub channel_kind: &'static str,
    /// Maximum number of queued or reserved slots for this subchannel.
    pub capacity: usize,
    /// Committed values waiting for this subchannel receiver.
    pub queued_messages: usize,
    /// Reserved-but-uncommitted send obligations on this subchannel.
    pub reserved_uncommitted_obligations: usize,
}

/// Opt-in, redacted telemetry snapshot for a session channel wrapper.
///
/// The caller supplies `channel_id`, which keeps identifiers deterministic and
/// avoids ambient globals or pointer-derived IDs. Payload values are never
/// exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTelemetrySnapshot {
    /// Caller-provided deterministic session channel identifier.
    pub channel_id: u64,
    /// Stable wrapper kind label.
    pub channel_kind: &'static str,
    /// Stable underlying channel kind label.
    pub subchannel_kind: &'static str,
    /// Maximum number of queued or reserved slots.
    pub capacity: usize,
    /// Number of committed values waiting for the receiver.
    pub queued_messages: usize,
    /// Number of reserved-but-uncommitted send obligations.
    pub reserved_uncommitted_obligations: usize,
    /// Sender-side waiters waiting for capacity or closure.
    pub send_waiter_count: usize,
    /// Receiver-side waiters waiting for messages, values, or closure.
    pub recv_waiter_count: usize,
    /// Redacted receiver state.
    pub receiver_health: &'static str,
    /// Underlying lag count when the subchannel supports receiver lag.
    pub lagged_receiver_count: Option<usize>,
    /// Cancel/abort events observed by the underlying subchannel.
    pub cancellation_count: u64,
    /// Whether the underlying subchannel has reached a closed state.
    pub closed: bool,
    /// Deterministically ordered underlying subchannel report.
    pub subchannels: [SessionSubchannelTelemetrySnapshot; 1],
}

impl SessionTelemetrySnapshot {
    fn from_mpsc(snapshot: mpsc::MpscTelemetrySnapshot) -> Self {
        Self {
            channel_id: snapshot.channel_id,
            channel_kind: "session",
            subchannel_kind: snapshot.channel_kind,
            capacity: snapshot.capacity,
            queued_messages: snapshot.queued_messages,
            reserved_uncommitted_obligations: snapshot.reserved_uncommitted_obligations,
            send_waiter_count: snapshot.send_waiter_count,
            recv_waiter_count: snapshot.recv_waiter_count,
            receiver_health: snapshot.receiver_health,
            lagged_receiver_count: snapshot.lagged_receiver_count,
            cancellation_count: snapshot.cancellation_count,
            closed: snapshot.closed,
            subchannels: [SessionSubchannelTelemetrySnapshot {
                channel_id: snapshot.channel_id,
                channel_kind: snapshot.channel_kind,
                capacity: snapshot.capacity,
                queued_messages: snapshot.queued_messages,
                reserved_uncommitted_obligations: snapshot.reserved_uncommitted_obligations,
            }],
        }
    }

    fn from_oneshot(snapshot: oneshot::OneshotTelemetrySnapshot) -> Self {
        Self {
            channel_id: snapshot.channel_id,
            channel_kind: "session",
            subchannel_kind: snapshot.channel_kind,
            capacity: snapshot.capacity,
            queued_messages: snapshot.queued_messages,
            reserved_uncommitted_obligations: snapshot.reserved_uncommitted_obligations,
            send_waiter_count: snapshot.send_waiter_count,
            recv_waiter_count: snapshot.recv_waiter_count,
            receiver_health: snapshot.receiver_health,
            lagged_receiver_count: snapshot.lagged_receiver_count,
            cancellation_count: snapshot.cancellation_count,
            closed: snapshot.closed,
            subchannels: [SessionSubchannelTelemetrySnapshot {
                channel_id: snapshot.channel_id,
                channel_kind: snapshot.channel_kind,
                capacity: snapshot.capacity,
                queued_messages: snapshot.queued_messages,
                reserved_uncommitted_obligations: snapshot.reserved_uncommitted_obligations,
            }],
        }
    }
}

// ============================================================================
// MPSC: TrackedSender<T>
// ============================================================================

/// An obligation-tracked MPSC sender.
///
/// Wraps an [`mpsc::Sender<T>`] and enforces that every reserved permit is
/// consumed via [`TrackedPermit::send`] or [`TrackedPermit::abort`].
#[derive(Debug)]
pub struct TrackedSender<T> {
    inner: mpsc::Sender<T>,
}

impl<T> TrackedSender<T> {
    /// Wraps an existing [`mpsc::Sender`].
    #[must_use]
    pub fn new(inner: mpsc::Sender<T>) -> Self {
        Self { inner }
    }

    /// Reserves a slot, returning a [`TrackedPermit`] that must be consumed.
    ///
    /// The returned permit carries an [`ObligationToken<SendPermit>`] that
    /// panics on drop if not committed or aborted.
    pub async fn reserve<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> Result<TrackedPermit<'a, T>, mpsc::SendError<()>> {
        let permit = self.inner.reserve(cx).await?;
        let obligation =
            reserve_tracked_send_obligation_for_region("TrackedPermit(mpsc)", cx.region_id());
        Ok(TrackedPermit { permit, obligation })
    }

    /// Non-blocking reserve attempt scoped to the supplied context.
    ///
    /// Cancellation is checked before channel capacity is acquired. This
    /// method never consults ambient task context, so synchronous production
    /// code can use it with an explicit, non-root task [`Cx`].
    pub fn try_reserve(&self, cx: &Cx) -> Result<TrackedPermit<'_, T>, mpsc::SendError<()>> {
        if cx.checkpoint().is_err() {
            return Err(mpsc::SendError::Cancelled(()));
        }

        let permit = self.inner.try_reserve()?;
        let obligation =
            reserve_tracked_send_obligation_for_region("TrackedPermit(mpsc)", cx.region_id());
        Ok(TrackedPermit { permit, obligation })
    }

    /// Reserves a slot with runtime admission before creating a graded permit.
    ///
    /// Delegates cancellation, FIFO waiting, and admission to
    /// [`mpsc::Sender::reserve_checked`]. Admission failure releases the channel
    /// slot and returns its checked error without creating a graded token.
    /// The successful permit still requires explicit send or abort.
    ///
    /// # Panics
    ///
    /// Like the legacy session reservation, requires a non-root region for
    /// graded tracking outside test-internal builds.
    pub async fn reserve_checked<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> Result<TrackedPermit<'a, T>, mpsc::CheckedSendError<()>> {
        let permit = self.inner.reserve_checked(cx).await?;
        let obligation =
            reserve_tracked_send_obligation_for_region("TrackedPermit(mpsc)", cx.region_id());
        Ok(TrackedPermit { permit, obligation })
    }

    /// Attempts checked reservation without waiting for channel capacity.
    ///
    /// Uses [`mpsc::Sender::try_reserve_checked`] exactly once and has the same
    /// graded lifecycle and non-root region requirement as
    /// [`Self::reserve_checked`].
    pub fn try_reserve_checked(
        &self,
        cx: &Cx,
    ) -> Result<TrackedPermit<'_, T>, mpsc::CheckedSendError<()>> {
        let permit = self.inner.try_reserve_checked(cx)?;
        let obligation =
            reserve_tracked_send_obligation_for_region("TrackedPermit(mpsc)", cx.region_id());
        Ok(TrackedPermit { permit, obligation })
    }

    /// Convenience: reserve a slot, send a value, and return the proof.
    pub async fn send(
        &self,
        cx: &Cx,
        value: T,
    ) -> Result<CommittedProof<SendPermit>, mpsc::SendError<T>> {
        let result = self.reserve(cx).await;
        let permit = match result {
            Ok(p) => p,
            Err(mpsc::SendError::Disconnected(())) => {
                return Err(mpsc::SendError::Disconnected(value));
            }
            Err(mpsc::SendError::Full(())) => return Err(mpsc::SendError::Full(value)),
            Err(mpsc::SendError::Cancelled(())) => {
                return Err(mpsc::SendError::Cancelled(value));
            }
        };
        permit.try_send(value)
    }

    /// Reserves with checked admission, sends the value, and returns its proof.
    ///
    /// Returns ownership of `value` on channel or admission failure. The region
    /// requirement is the same as [`Self::reserve_checked`].
    pub async fn send_checked(
        &self,
        cx: &Cx,
        value: T,
    ) -> Result<CommittedProof<SendPermit>, mpsc::CheckedSendError<T>> {
        match self.reserve_checked(cx).await {
            Ok(permit) => permit
                .try_send(value)
                .map_err(mpsc::CheckedSendError::Channel),
            Err(error) => Err(checked_mpsc_error_with_value(error, value)),
        }
    }

    /// Attempts checked reserve and send without waiting for channel capacity.
    ///
    /// Returns ownership of `value` on channel or admission failure. The region
    /// requirement is the same as [`Self::reserve_checked`].
    pub fn try_send_checked(
        &self,
        cx: &Cx,
        value: T,
    ) -> Result<CommittedProof<SendPermit>, mpsc::CheckedSendError<T>> {
        match self.try_reserve_checked(cx) {
            Ok(permit) => permit
                .try_send(value)
                .map_err(mpsc::CheckedSendError::Channel),
            Err(error) => Err(checked_mpsc_error_with_value(error, value)),
        }
    }

    /// Returns the underlying [`mpsc::Sender`], discarding obligation tracking.
    #[must_use]
    pub fn into_inner(self) -> mpsc::Sender<T> {
        self.inner
    }

    /// Returns `true` if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Returns an opt-in redacted telemetry snapshot for this session sender.
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> SessionTelemetrySnapshot {
        SessionTelemetrySnapshot::from_mpsc(self.inner.telemetry_snapshot(channel_id))
    }
}

impl<T> Clone for TrackedSender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// ============================================================================
// MPSC: TrackedPermit<'a, T>
// ============================================================================

/// A reserved MPSC slot with obligation tracking.
///
/// **Must** be consumed via [`send`](Self::send) or [`abort`](Self::abort).
/// Dropping without consuming panics with `"OBLIGATION TOKEN LEAKED"`.
///
/// Fields are ordered so that `permit` drops first (releasing the channel slot)
/// and then `obligation` drops (firing the panic). No custom `Drop` impl needed.
#[must_use = "TrackedPermit must be consumed via send() or abort()"]
pub struct TrackedPermit<'a, T> {
    permit: mpsc::SendPermit<'a, T>,
    obligation: ObligationToken<SendPermit>,
}

impl<T> TrackedPermit<'_, T> {
    /// Sends a value, consuming the permit and returning a [`CommittedProof`].
    ///
    /// # Errors
    ///
    /// Returns an error if the receiver was dropped before the value could be sent.
    pub fn send(self, value: T) -> Result<CommittedProof<SendPermit>, mpsc::SendError<T>> {
        let Self { permit, obligation } = self;
        match permit.try_send(value) {
            Ok(()) => Ok(obligation.commit()),
            Err(e) => {
                let _aborted = obligation.abort();
                Err(e)
            }
        }
    }

    /// Sends a value, returning an error if the receiver was dropped.
    pub fn try_send(self, value: T) -> Result<CommittedProof<SendPermit>, mpsc::SendError<T>> {
        let Self { permit, obligation } = self;
        match permit.try_send(value) {
            Ok(()) => Ok(obligation.commit()),
            Err(e) => {
                let _aborted = obligation.abort();
                Err(e)
            }
        }
    }

    /// Aborts the reserved slot, consuming the permit and returning an [`AbortedProof`].
    #[must_use]
    pub fn abort(self) -> AbortedProof<SendPermit> {
        let Self { permit, obligation } = self;
        permit.abort();
        obligation.abort()
    }

    /// Returns an opt-in redacted telemetry snapshot for this tracked permit.
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> SessionTelemetrySnapshot {
        SessionTelemetrySnapshot::from_mpsc(self.permit.telemetry_snapshot(channel_id))
    }
}

impl<T> std::fmt::Debug for TrackedPermit<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedPermit")
            .field("obligation", &self.obligation)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Constructor: tracked_channel
// ============================================================================

/// Creates a bounded MPSC channel with obligation-tracked sender.
///
/// The receiver is the standard [`mpsc::Receiver`] — obligation tracking only
/// applies to the sender side.
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[must_use]
pub fn tracked_channel<T>(capacity: usize) -> (TrackedSender<T>, mpsc::Receiver<T>) {
    let (tx, rx) = mpsc::channel(capacity);
    (TrackedSender::new(tx), rx)
}

// ============================================================================
// Oneshot: TrackedOneshotSender<T>
// ============================================================================

/// An obligation-tracked oneshot sender.
///
/// Wraps a [`oneshot::Sender<T>`] and enforces that the send permit is
/// consumed via [`TrackedOneshotPermit::send`] or [`TrackedOneshotPermit::abort`].
#[derive(Debug)]
pub struct TrackedOneshotSender<T> {
    inner: oneshot::Sender<T>,
}

impl<T> TrackedOneshotSender<T> {
    /// Wraps an existing [`oneshot::Sender`].
    #[must_use]
    pub fn new(inner: oneshot::Sender<T>) -> Self {
        Self { inner }
    }

    /// Reserves the channel, consuming the sender and returning a tracked permit.
    ///
    /// The returned permit carries an [`ObligationToken<SendPermit>`] that
    /// panics on drop if not committed or aborted.
    ///
    /// # Errors
    ///
    /// Returns `Err(oneshot::SendError::Cancelled(()))` if the supplied `Cx`
    /// is already cancelled — propagated from `oneshot::Sender::reserve`
    /// (br-asupersync-4taf1b).
    pub fn reserve(self, cx: &Cx) -> Result<TrackedOneshotPermit<T>, oneshot::SendError<()>> {
        let permit = self.inner.reserve(cx)?;
        let obligation =
            reserve_tracked_send_obligation_for_region("TrackedOneshotPermit", cx.region_id());
        Ok(TrackedOneshotPermit { permit, obligation })
    }

    /// Consumes the sender and admits one runtime obligation before grading it.
    ///
    /// Delegates to [`oneshot::Sender::reserve_checked`] exactly once. Denial
    /// closes the consumed sender without creating a graded token; a successful
    /// permit still requires explicit send or abort.
    ///
    /// # Panics
    ///
    /// Like the legacy session reservation, requires a non-root region for
    /// graded tracking outside test-internal builds.
    pub fn reserve_checked(
        self,
        cx: &Cx,
    ) -> Result<TrackedOneshotPermit<T>, oneshot::CheckedSendError<()>> {
        let permit = self.inner.reserve_checked(cx)?;
        let obligation =
            reserve_tracked_send_obligation_for_region("TrackedOneshotPermit", cx.region_id());
        Ok(TrackedOneshotPermit { permit, obligation })
    }

    /// Convenience: reserve + send in one step, returning a proof on success.
    pub fn send(
        self,
        cx: &Cx,
        value: T,
    ) -> Result<CommittedProof<SendPermit>, oneshot::SendError<T>> {
        match self.reserve(cx) {
            Ok(permit) => permit.send(value),
            Err(oneshot::SendError::Cancelled(())) => Err(oneshot::SendError::Cancelled(value)),
            Err(oneshot::SendError::Disconnected(())) => {
                Err(oneshot::SendError::Disconnected(value))
            }
        }
    }

    /// Reserves with checked admission, sends the value, and returns its proof.
    ///
    /// Returns ownership of `value` on channel or admission failure. The region
    /// requirement is the same as [`Self::reserve_checked`].
    pub fn send_checked(
        self,
        cx: &Cx,
        value: T,
    ) -> Result<CommittedProof<SendPermit>, oneshot::CheckedSendError<T>> {
        match self.reserve_checked(cx) {
            Ok(permit) => permit
                .send(value)
                .map_err(oneshot::CheckedSendError::Channel),
            Err(oneshot::CheckedSendError::Channel(error)) => {
                Err(oneshot::CheckedSendError::Channel(match error {
                    oneshot::SendError::Cancelled(()) => oneshot::SendError::Cancelled(value),
                    oneshot::SendError::Disconnected(()) => oneshot::SendError::Disconnected(value),
                }))
            }
            Err(oneshot::CheckedSendError::Admission { error, value: () }) => {
                Err(oneshot::CheckedSendError::Admission { error, value })
            }
        }
    }

    /// Returns the underlying [`oneshot::Sender`], discarding obligation tracking.
    #[must_use]
    pub fn into_inner(self) -> oneshot::Sender<T> {
        self.inner
    }

    /// Returns `true` if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Returns an opt-in redacted telemetry snapshot for this session oneshot sender.
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> SessionTelemetrySnapshot {
        SessionTelemetrySnapshot::from_oneshot(self.inner.telemetry_snapshot(channel_id))
    }
}

// ============================================================================
// Oneshot: TrackedOneshotPermit<T>
// ============================================================================

/// A reserved oneshot slot with obligation tracking.
///
/// **Must** be consumed via [`send`](Self::send) or [`abort`](Self::abort).
/// Dropping without consuming panics with `"OBLIGATION TOKEN LEAKED"`.
///
/// Fields are ordered so that `permit` drops first (releasing the channel)
/// and then `obligation` drops (firing the panic). No custom `Drop` impl needed.
#[must_use = "TrackedOneshotPermit must be consumed via send() or abort()"]
pub struct TrackedOneshotPermit<T> {
    permit: oneshot::SendPermit<T>,
    obligation: ObligationToken<SendPermit>,
}

impl<T> TrackedOneshotPermit<T> {
    /// Sends a value, consuming the permit and returning a [`CommittedProof`].
    pub fn send(self, value: T) -> Result<CommittedProof<SendPermit>, oneshot::SendError<T>> {
        let Self { permit, obligation } = self;
        match permit.send(value) {
            Ok(()) => Ok(obligation.commit()),
            Err(e) => {
                // Receiver dropped — abort the obligation cleanly.
                let _aborted = obligation.abort();
                Err(e)
            }
        }
    }

    /// Aborts the reserved slot, consuming the permit and returning an [`AbortedProof`].
    #[must_use]
    pub fn abort(self) -> AbortedProof<SendPermit> {
        let Self { permit, obligation } = self;
        permit.abort();
        obligation.abort()
    }

    /// Returns `true` if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.permit.is_closed()
    }

    /// Returns an opt-in redacted telemetry snapshot for this tracked oneshot permit.
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> SessionTelemetrySnapshot {
        SessionTelemetrySnapshot::from_oneshot(self.permit.telemetry_snapshot(channel_id))
    }
}

impl<T> std::fmt::Debug for TrackedOneshotPermit<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedOneshotPermit")
            .field("obligation", &self.obligation)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Constructor: tracked_oneshot
// ============================================================================

/// Creates a oneshot channel with an obligation-tracked sender.
///
/// The receiver is the standard [`oneshot::Receiver`] — obligation tracking only
/// applies to the sender side.
#[must_use]
pub fn tracked_oneshot<T>() -> (TrackedOneshotSender<T>, oneshot::Receiver<T>) {
    let (tx, rx) = oneshot::channel();
    (TrackedOneshotSender::new(tx), rx)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now;
    use crate::types::Budget;
    use std::future::Future;
    use std::task::{Context, Poll};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_request()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    // 1. Reserve + send, verify receiver gets value and CommittedProof returned
    #[test]
    fn tracked_mpsc_send_recv() {
        init_test("tracked_mpsc_send_recv");
        let cx = test_cx();
        let (tx, mut rx) = tracked_channel::<i32>(10);

        let permit = block_on(tx.reserve(&cx)).expect("reserve failed");
        let proof = permit.send(42).unwrap();

        crate::assert_with_log!(
            proof.kind() == crate::record::ObligationKind::SendPermit,
            "proof kind",
            crate::record::ObligationKind::SendPermit,
            proof.kind()
        );

        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);

        crate::test_complete!("tracked_mpsc_send_recv");
    }

    // 2. Reserve + abort, verify AbortedProof and channel slot released
    #[test]
    fn tracked_mpsc_abort_returns_proof() {
        init_test("tracked_mpsc_abort_returns_proof");
        let cx = test_cx();
        let (tx, mut rx) = tracked_channel::<i32>(1);

        let permit = block_on(tx.reserve(&cx)).expect("reserve failed");
        let proof = permit.abort();

        crate::assert_with_log!(
            proof.kind() == crate::record::ObligationKind::SendPermit,
            "aborted proof kind",
            crate::record::ObligationKind::SendPermit,
            proof.kind()
        );

        // Slot was released — we can reserve again.
        let permit2 = block_on(tx.reserve(&cx)).expect("second reserve failed");
        let _ = permit2.send(99).unwrap();

        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 99, "recv value after abort", 99, value);

        crate::test_complete!("tracked_mpsc_abort_returns_proof");
    }

    // 3. Dropping TrackedPermit without send/abort triggers panic
    #[test]
    #[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
    fn tracked_mpsc_drop_permit_panics() {
        init_test("tracked_mpsc_drop_permit_panics");
        let cx = test_cx();
        let (tx, _rx) = tracked_channel::<i32>(10);

        let permit = block_on(tx.reserve(&cx)).expect("reserve failed");
        drop(permit); // should panic
    }

    // 4. Synchronous try_reserve + send
    #[test]
    fn tracked_mpsc_try_reserve_send() {
        init_test("tracked_mpsc_try_reserve_send");
        let cx = test_cx();
        let (tx, mut rx) = tracked_channel::<i32>(10);

        let permit = tx.try_reserve(&cx).expect("try_reserve failed");
        let proof = permit.send(7).unwrap();

        crate::assert_with_log!(
            proof.kind() == crate::record::ObligationKind::SendPermit,
            "try_reserve proof kind",
            crate::record::ObligationKind::SendPermit,
            proof.kind()
        );

        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 7, "recv value", 7, value);

        crate::test_complete!("tracked_mpsc_try_reserve_send");
    }

    #[test]
    fn tracked_mpsc_try_reserve_rejects_pre_cancelled_context() {
        init_test("tracked_mpsc_try_reserve_rejects_pre_cancelled_context");
        let cancelled_cx = test_cx();
        cancelled_cx.cancel_with(
            crate::types::CancelKind::User,
            Some("cancel before tracked try_reserve"),
        );
        let (tx, mut rx) = tracked_channel::<i32>(1);
        let before = tx.telemetry_snapshot(7);

        assert!(matches!(
            tx.try_reserve(&cancelled_cx),
            Err(mpsc::SendError::Cancelled(()))
        ));
        assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
        assert_eq!(tx.telemetry_snapshot(7), before);

        let active_cx = test_cx();
        let permit = tx
            .try_reserve(&active_cx)
            .expect("cancelled attempt must leave capacity intact");
        permit.send(11).expect("active explicit context commits");
        assert_eq!(
            block_on(rx.recv(&active_cx)).expect("committed value is available"),
            11
        );

        crate::test_complete!("tracked_mpsc_try_reserve_rejects_pre_cancelled_context");
    }

    // 5. Full oneshot reserve + send + recv with proof
    #[test]
    fn tracked_oneshot_send_recv() {
        init_test("tracked_oneshot_send_recv");
        let cx = test_cx();
        let (tx, mut rx) = tracked_oneshot::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        let proof = permit.send(100).expect("oneshot send failed");

        crate::assert_with_log!(
            proof.kind() == crate::record::ObligationKind::SendPermit,
            "oneshot proof kind",
            crate::record::ObligationKind::SendPermit,
            proof.kind()
        );

        let value = block_on(rx.recv(&cx)).expect("oneshot recv failed");
        crate::assert_with_log!(value == 100, "oneshot recv value", 100, value);

        crate::test_complete!("tracked_oneshot_send_recv");
    }

    // 6. Oneshot reserve + abort
    #[test]
    fn tracked_oneshot_abort() {
        init_test("tracked_oneshot_abort");
        let cx = test_cx();
        let (tx, mut rx) = tracked_oneshot::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        let proof = permit.abort();

        crate::assert_with_log!(
            proof.kind() == crate::record::ObligationKind::SendPermit,
            "oneshot aborted proof kind",
            crate::record::ObligationKind::SendPermit,
            proof.kind()
        );

        // Receiver should see Closed
        let result = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            result.is_err(),
            "oneshot recv after abort",
            true,
            result.is_err()
        );

        crate::test_complete!("tracked_oneshot_abort");
    }

    // 7. Dropping TrackedOneshotPermit without send/abort triggers panic
    #[test]
    #[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
    fn tracked_oneshot_drop_permit_panics() {
        init_test("tracked_oneshot_drop_permit_panics");
        let cx = test_cx();
        let (tx, _rx) = tracked_oneshot::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        drop(permit); // should panic
    }

    // 8. One-step send() returning CommittedProof
    #[test]
    fn tracked_oneshot_convenience_send() {
        init_test("tracked_oneshot_convenience_send");
        let cx = test_cx();
        let (tx, mut rx) = tracked_oneshot::<i32>();

        let proof = tx.send(&cx, 55).expect("convenience send failed");

        crate::assert_with_log!(
            proof.kind() == crate::record::ObligationKind::SendPermit,
            "convenience proof kind",
            crate::record::ObligationKind::SendPermit,
            proof.kind()
        );

        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 55, "convenience recv value", 55, value);

        crate::test_complete!("tracked_oneshot_convenience_send");
    }

    // 9. into_inner() returns underlying sender, no obligation tracking
    #[test]
    fn tracked_into_inner_escapes() {
        init_test("tracked_into_inner_escapes");
        let cx = test_cx();
        let (tx, mut rx) = tracked_channel::<i32>(10);

        let raw_tx = tx.into_inner();
        // Use the raw sender — no obligation tracking, no panic on permit drop.
        let permit = raw_tx.try_reserve().expect("raw try_reserve failed");
        permit.send(123);

        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 123, "into_inner recv value", 123, value);

        crate::test_complete!("tracked_into_inner_escapes");
    }

    // 10. Dropped MPSC receiver yields disconnected error with original value.
    #[test]
    fn tracked_mpsc_send_returns_disconnected_when_receiver_dropped() {
        init_test("tracked_mpsc_send_returns_disconnected_when_receiver_dropped");
        let cx = test_cx();
        let (tx, rx) = tracked_channel::<i32>(1);
        drop(rx);

        let err =
            block_on(tx.send(&cx, 77)).expect_err("send should fail when receiver is dropped");
        match err {
            mpsc::SendError::Disconnected(value) => {
                crate::assert_with_log!(
                    value == 77,
                    "disconnected error must return original value",
                    77,
                    value
                );
            }
            other => unreachable!("expected Disconnected(77), got {other:?}"),
        }

        crate::test_complete!("tracked_mpsc_send_returns_disconnected_when_receiver_dropped");
    }

    // 11. Dropped oneshot receiver: reserved permit send aborts obligation and returns value.
    #[test]
    fn tracked_oneshot_reserved_send_returns_disconnected_without_obligation_leak() {
        init_test("tracked_oneshot_reserved_send_returns_disconnected_without_obligation_leak");
        let cx = test_cx();
        let (tx, rx) = tracked_oneshot::<i32>();
        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        drop(rx);

        let err = permit
            .send(101)
            .expect_err("reserved oneshot send should fail when receiver is dropped");
        match err {
            oneshot::SendError::Disconnected(value) | oneshot::SendError::Cancelled(value) => {
                crate::assert_with_log!(
                    value == 101,
                    "oneshot error must return original value",
                    101,
                    value
                );
            }
        }

        crate::test_complete!(
            "tracked_oneshot_reserved_send_returns_disconnected_without_obligation_leak"
        );
    }

    // =========================================================================
    // Wave 33: Data-type trait coverage
    // =========================================================================

    #[test]
    fn tracked_sender_debug() {
        let (tx, _rx) = tracked_channel::<i32>(10);
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("TrackedSender"));
    }

    #[test]
    fn tracked_sender_clone_is_closed() {
        let (tx, rx) = tracked_channel::<i32>(10);
        let cloned = tx.clone();
        assert!(!cloned.is_closed());
        drop(rx);
        assert!(tx.is_closed());
    }

    #[test]
    fn tracked_permit_debug() {
        let cx = test_cx();
        let (tx, _rx) = tracked_channel::<i32>(10);
        let permit = tx.try_reserve(&cx).expect("reserve");
        let dbg = format!("{permit:?}");
        assert!(dbg.contains("TrackedPermit"));
        let _ = permit.abort();
    }

    #[test]
    fn tracked_oneshot_sender_debug() {
        let (tx, _rx) = tracked_oneshot::<i32>();
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("TrackedOneshotSender"));
    }

    #[test]
    fn tracked_oneshot_sender_is_closed() {
        let (tx, rx) = tracked_oneshot::<i32>();
        assert!(!tx.is_closed());
        drop(rx);
        assert!(tx.is_closed());
    }

    #[test]
    fn tracked_oneshot_permit_debug() {
        let cx = test_cx();
        let (tx, _rx) = tracked_oneshot::<i32>();
        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        let dbg = format!("{permit:?}");
        assert!(dbg.contains("TrackedOneshotPermit"));
        let _ = permit.abort();
    }

    #[test]
    fn tracked_oneshot_permit_is_closed() {
        let cx = test_cx();
        let (tx, rx) = tracked_oneshot::<i32>();
        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        assert!(!permit.is_closed());
        drop(rx);
        assert!(permit.is_closed());
        let _ = permit.abort();
    }

    // 12. Dropped oneshot receiver: convenience send returns disconnected and original value.
    #[test]
    fn tracked_oneshot_convenience_send_returns_disconnected_when_receiver_dropped() {
        init_test("tracked_oneshot_convenience_send_returns_disconnected_when_receiver_dropped");
        let cx = test_cx();
        let (tx, rx) = tracked_oneshot::<i32>();
        drop(rx);

        let err = tx
            .send(&cx, 202)
            .expect_err("convenience oneshot send should fail when receiver is dropped");
        match err {
            oneshot::SendError::Disconnected(value) => {
                crate::assert_with_log!(
                    value == 202,
                    "oneshot disconnected must return original value",
                    202,
                    value
                );
            }
            oneshot::SendError::Cancelled(_) => {
                panic!("cx not cancelled in this test — Cancelled unexpected");
            }
        }

        crate::test_complete!(
            "tracked_oneshot_convenience_send_returns_disconnected_when_receiver_dropped"
        );
    }

    // =========================================================================
    // Metamorphic Testing: Session Protocol Invariants (META-SESSION)
    // =========================================================================

    /// META-SESSION-001: Reserve-Abort-Reserve Equivalence Property
    /// reserve() + abort() + reserve() should be equivalent to two independent reserves
    /// Metamorphic relation: capacity_after(reserve→abort→reserve) = capacity_after(reserve×2)
    #[test]
    fn meta_reserve_abort_reserve_equivalence() {
        init_test("meta_reserve_abort_reserve_equivalence");
        let cx = test_cx();

        // Setup 1: Reserve, abort, reserve sequence
        let (tx1, mut rx1) = tracked_channel::<i32>(2);
        let permit1a = block_on(tx1.reserve(&cx)).expect("first reserve");
        let _aborted_proof = permit1a.abort();
        let permit1b = block_on(tx1.reserve(&cx)).expect("reserve after abort");
        let _committed_proof1 = permit1b.send(100).expect("send after abort");

        // Setup 2: Two independent reserves (reference behavior)
        let (tx2, mut rx2) = tracked_channel::<i32>(2);
        let permit2a = block_on(tx2.reserve(&cx)).expect("independent first reserve");
        let permit2b = block_on(tx2.reserve(&cx)).expect("independent second reserve");
        let _aborted_proof2 = permit2a.abort();
        let _committed_proof2 = permit2b.send(100).expect("independent send");

        // Metamorphic relation: Both channels should receive the same value
        let value1 = block_on(rx1.recv(&cx)).expect("recv from abort sequence");
        let value2 = block_on(rx2.recv(&cx)).expect("recv from independent sequence");

        crate::assert_with_log!(
            value1 == value2,
            "reserve-abort-reserve equivalence",
            value2,
            value1
        );

        crate::test_complete!("meta_reserve_abort_reserve_equivalence");
    }

    /// META-SESSION-002: Tracking vs Raw Channel Equivalence Property
    /// Tracked channels with perfect obligation discipline should behave identically to raw channels
    /// Metamorphic relation: tracked_behavior_with_perfect_discipline = raw_behavior
    #[test]
    fn meta_tracking_raw_equivalence() {
        init_test("meta_tracking_raw_equivalence");
        let cx = test_cx();

        // Tracked channel with perfect discipline
        let (tracked_tx, mut tracked_rx) = tracked_channel::<i32>(3);
        let tracked_permit1 = block_on(tracked_tx.reserve(&cx)).expect("tracked reserve 1");
        let tracked_permit2 = block_on(tracked_tx.reserve(&cx)).expect("tracked reserve 2");
        let _tracked_proof1 = tracked_permit1.send(42).expect("tracked send 1");
        let _tracked_proof2 = tracked_permit2.send(43).expect("tracked send 2");

        // Raw channel (same operations via into_inner)
        let (raw_tracked_tx, mut raw_rx) = tracked_channel::<i32>(3);
        let raw_tx = raw_tracked_tx.into_inner();
        let raw_permit1 = raw_tx.try_reserve().expect("raw reserve 1");
        let raw_permit2 = raw_tx.try_reserve().expect("raw reserve 2");
        raw_permit1.send(42);
        raw_permit2.send(43);

        // Metamorphic relation: receivers should see identical sequences
        let tracked_seq = vec![
            block_on(tracked_rx.recv(&cx)).expect("tracked recv 1"),
            block_on(tracked_rx.recv(&cx)).expect("tracked recv 2"),
        ];
        let raw_seq = vec![
            block_on(raw_rx.recv(&cx)).expect("raw recv 1"),
            block_on(raw_rx.recv(&cx)).expect("raw recv 2"),
        ];

        crate::assert_with_log!(
            tracked_seq == raw_seq,
            "tracking equivalence with raw",
            raw_seq,
            tracked_seq
        );

        crate::test_complete!("meta_tracking_raw_equivalence");
    }

    /// META-SESSION-003: Commitment Monotonicity Property
    /// The number of successful commits should never exceed permits reserved
    /// Metamorphic relation: committed_count ≤ reserved_count (always)
    #[test]
    fn meta_commitment_monotonicity() {
        init_test("meta_commitment_monotonicity");
        let cx = test_cx();

        let (tx, mut rx) = tracked_channel::<i32>(5);
        let mut reserved_count = 0;
        let mut committed_count = 0;

        // Reserve 3 permits
        let permit1 = block_on(tx.reserve(&cx)).expect("reserve 1");
        reserved_count += 1;
        let permit2 = block_on(tx.reserve(&cx)).expect("reserve 2");
        reserved_count += 1;
        let permit3 = block_on(tx.reserve(&cx)).expect("reserve 3");
        reserved_count += 1;

        // Commit 2, abort 1
        let _proof1 = permit1.send(10).expect("send 1");
        committed_count += 1;
        let _aborted = permit2.abort();
        let _proof2 = permit3.send(20).expect("send 2");
        committed_count += 1;

        // Metamorphic relation: monotonicity invariant
        crate::assert_with_log!(
            committed_count <= reserved_count,
            "commitment monotonicity",
            format!("committed({committed_count}) <= reserved({reserved_count})"),
            format!("committed({committed_count}) <= reserved({reserved_count})")
        );

        // Verify actual receives match committed count
        let mut received_count = 0;
        while let Ok(_) = rx.try_recv() {
            received_count += 1;
        }
        crate::assert_with_log!(
            received_count == committed_count,
            "received equals committed",
            committed_count,
            received_count
        );

        crate::test_complete!("meta_commitment_monotonicity");
    }

    /// META-SESSION-004: Error Value Preservation Property
    /// Failed sends due to disconnection must return the original value unchanged
    /// Metamorphic relation: error_value = original_value (identity under failure)
    #[test]
    fn meta_error_value_preservation() {
        init_test("meta_error_value_preservation");
        let cx = test_cx();

        // Test with various value types
        let test_values = vec![42, -100, 0, i32::MAX, i32::MIN];

        for &original_value in &test_values {
            // MPSC case
            let (tx, rx) = tracked_channel::<i32>(1);
            drop(rx); // Disconnect

            let mpsc_result = block_on(tx.send(&cx, original_value));
            crate::assert_with_log!(
                matches!(mpsc_result, Err(mpsc::SendError::Disconnected(_))),
                "MPSC send returns disconnected error",
                true,
                matches!(mpsc_result, Err(mpsc::SendError::Disconnected(_)))
            );
            let Err(mpsc::SendError::Disconnected(returned_value)) = mpsc_result else {
                unreachable!("validated disconnected MPSC send result");
            };
            crate::assert_with_log!(
                returned_value == original_value,
                "MPSC error value preservation",
                original_value,
                returned_value
            );

            // Oneshot case
            let (tx, rx) = tracked_oneshot::<i32>();
            drop(rx); // Disconnect

            let oneshot_result = tx.send(&cx, original_value);
            crate::assert_with_log!(
                matches!(oneshot_result, Err(oneshot::SendError::Disconnected(_))),
                "oneshot send returns disconnected error",
                true,
                matches!(oneshot_result, Err(oneshot::SendError::Disconnected(_)))
            );
            let Err(oneshot::SendError::Disconnected(returned_value)) = oneshot_result else {
                unreachable!("validated disconnected oneshot send result");
            };
            crate::assert_with_log!(
                returned_value == original_value,
                "Oneshot error value preservation",
                original_value,
                returned_value
            );
        }

        crate::test_complete!("meta_error_value_preservation");
    }

    /// META-SESSION-005: Clone Broadcast Equivalence Property
    /// Messages sent via any clone should be received identically
    /// Metamorphic relation: broadcast(clone_a, msg) = broadcast(clone_b, msg)
    #[test]
    fn meta_clone_broadcast_equivalence() {
        init_test("meta_clone_broadcast_equivalence");
        let cx = test_cx();

        let (tx_original, mut rx) = tracked_channel::<i32>(10);
        let tx_clone1 = tx_original.clone();
        let tx_clone2 = tx_original.clone();

        // Send from original
        let _proof1 = block_on(tx_original.send(&cx, 100)).expect("original send");

        // Send from clone 1
        let _proof2 = block_on(tx_clone1.send(&cx, 200)).expect("clone1 send");

        // Send from clone 2
        let _proof3 = block_on(tx_clone2.send(&cx, 300)).expect("clone2 send");

        // Metamorphic relation: all messages received regardless of sender clone
        let mut received = vec![];
        for _ in 0..3 {
            received.push(block_on(rx.recv(&cx)).expect("recv from clones"));
        }
        received.sort_unstable(); // Order may vary

        let expected = vec![100, 200, 300];
        crate::assert_with_log!(
            received == expected,
            "clone broadcast equivalence",
            expected,
            received
        );

        crate::test_complete!("meta_clone_broadcast_equivalence");
    }

    /// META-SESSION-006: Receiver State Symmetry Property
    /// is_closed() should be consistent across all sender clones
    /// Metamorphic relation: clone_a.is_closed() = clone_b.is_closed() (symmetric)
    #[test]
    fn meta_receiver_state_symmetry() {
        init_test("meta_receiver_state_symmetry");

        // MPSC case
        let (tx1, rx) = tracked_channel::<i32>(5);
        let tx2 = tx1.clone();
        let tx3 = tx1.clone();

        // Before drop: all should be open
        crate::assert_with_log!(
            !tx1.is_closed() && !tx2.is_closed() && !tx3.is_closed(),
            "all clones open before receiver drop",
            "all false",
            format!(
                "tx1: {}, tx2: {}, tx3: {}",
                tx1.is_closed(),
                tx2.is_closed(),
                tx3.is_closed()
            )
        );

        drop(rx);

        // After drop: all should be closed (symmetric)
        crate::assert_with_log!(
            tx1.is_closed() && tx2.is_closed() && tx3.is_closed(),
            "all clones closed after receiver drop",
            "all true",
            format!(
                "tx1: {}, tx2: {}, tx3: {}",
                tx1.is_closed(),
                tx2.is_closed(),
                tx3.is_closed()
            )
        );

        // Oneshot case (no clone, but test sender state)
        let (tx, rx) = tracked_oneshot::<i32>();
        crate::assert_with_log!(
            !tx.is_closed(),
            "oneshot open before drop",
            false,
            tx.is_closed()
        );
        drop(rx);
        crate::assert_with_log!(
            tx.is_closed(),
            "oneshot closed after drop",
            true,
            tx.is_closed()
        );

        crate::test_complete!("meta_receiver_state_symmetry");
    }

    /// META-SESSION-007: Proof Composition Property
    /// Total proofs (committed + aborted) should equal total permits reserved
    /// Metamorphic relation: committed_proofs + aborted_proofs = reserved_permits
    #[test]
    fn meta_proof_composition() {
        init_test("meta_proof_composition");
        let cx = test_cx();

        let (tx, _rx) = tracked_channel::<i32>(10);
        let mut reserved_permits = 0;
        let mut committed_proofs = 0;
        let mut aborted_proofs = 0;

        // Reserve 5 permits
        let permits: Vec<_> = (0..5)
            .map(|i| {
                reserved_permits += 1;
                block_on(tx.reserve(&cx)).unwrap_or_else(|_| panic!("reserve {i}"))
            })
            .collect();

        // Commit 3, abort 2
        for (i, permit) in permits.into_iter().enumerate() {
            if i < 3 {
                let _proof = permit.send(i as i32).unwrap_or_else(|_| panic!("send {i}"));
                committed_proofs += 1;
            } else {
                let _proof = permit.abort();
                aborted_proofs += 1;
            }
        }

        // Metamorphic relation: conservation of proof count
        crate::assert_with_log!(
            committed_proofs + aborted_proofs == reserved_permits,
            "proof composition conservation",
            reserved_permits,
            committed_proofs + aborted_proofs
        );

        crate::assert_with_log!(
            committed_proofs == 3 && aborted_proofs == 2,
            "expected proof distribution",
            "committed: 3, aborted: 2",
            format!("committed: {committed_proofs}, aborted: {aborted_proofs}")
        );

        crate::test_complete!("meta_proof_composition");
    }

    /// META-SESSION-008: Oneshot Consumption Finality Property
    /// Oneshot permits are consumed exactly once - no double-use possible
    /// Metamorphic relation: oneshot_use_count = 1 (always finite)
    #[test]
    fn meta_oneshot_consumption_finality() {
        init_test("meta_oneshot_consumption_finality");
        let cx = test_cx();

        let (tx1, mut rx1) = tracked_oneshot::<i32>();
        let (tx2, mut rx2) = tracked_oneshot::<i32>();

        // Path 1: Reserve then send
        let permit1 = tx1.reserve(&cx).expect("reserve 1");
        let _proof1 = permit1.send(111).expect("oneshot reserve+send");

        // Path 2: Direct send (convenience)
        let _proof2 = tx2.send(&cx, 222).expect("oneshot direct send");

        // Metamorphic relation: both paths result in exactly one message
        let value1 = block_on(rx1.recv(&cx)).expect("oneshot recv 1");
        let value2 = block_on(rx2.recv(&cx)).expect("oneshot recv 2");

        crate::assert_with_log!(value1 == 111, "oneshot value 1", 111, value1);
        crate::assert_with_log!(value2 == 222, "oneshot value 2", 222, value2);

        // Both receivers should now report closed
        crate::assert_with_log!(
            rx1.try_recv().is_err() && rx2.try_recv().is_err(),
            "oneshot finality - no more messages",
            "both receivers closed",
            "both receivers closed"
        );

        crate::test_complete!("meta_oneshot_consumption_finality");
    }

    /// META-SESSION-009: Capacity Pressure Invariant Property
    /// Under capacity pressure, permit allocation should maintain fairness and consistency
    /// Metamorphic relation: high_pressure_allocation_fairness = low_pressure_allocation_fairness
    #[test]
    fn meta_capacity_pressure_invariant() {
        init_test("meta_capacity_pressure_invariant");
        let cx = test_cx();

        const SMALL_CAPACITY: usize = 2;
        let (tx, mut rx) = tracked_channel::<usize>(SMALL_CAPACITY);

        // Fill to capacity with permits
        let permit1 = block_on(tx.reserve(&cx)).expect("permit 1");
        let permit2 = block_on(tx.reserve(&cx)).expect("permit 2");

        // Try to reserve more (should fail)
        let should_fail = tx.try_reserve(&cx);
        crate::assert_with_log!(
            should_fail.is_err(),
            "capacity pressure blocks new reservations",
            "blocked",
            "unblocked"
        );

        // Free one slot via abort, reserve again
        let _aborted = permit1.abort();
        let permit3 = tx.try_reserve(&cx).expect("permit after abort");

        // Free another slot via send, reserve again
        let _committed = permit2.send(100).expect("send");
        let _received = block_on(rx.recv(&cx)).expect("recv");
        let permit4 = tx.try_reserve(&cx).expect("permit after send");

        // Both newly acquired permits should behave identically
        let _committed3 = permit3.send(200).expect("send 3");
        let _committed4 = permit4.send(300).expect("send 4");

        let val3 = block_on(rx.recv(&cx)).expect("recv 3");
        let val4 = block_on(rx.recv(&cx)).expect("recv 4");

        crate::assert_with_log!(
            (val3 == 200 && val4 == 300) || (val3 == 300 && val4 == 200),
            "capacity pressure maintains permit functionality",
            "200,300 or 300,200",
            format!("{},{}", val3, val4)
        );

        crate::test_complete!("meta_capacity_pressure_invariant");
    }

    /// META-SESSION-010: Concurrent Permit Independence Property
    /// Operations on different permits should be independent and commute
    /// Metamorphic relation: concurrent_ops(A,B) = sequential_ops(A,B) ∪ sequential_ops(B,A)
    #[test]
    fn meta_concurrent_permit_independence() {
        init_test("meta_concurrent_permit_independence");
        let cx = test_cx();

        // Test multiple times to catch race conditions
        for iteration in 0..5 {
            let (tx, mut rx) = tracked_channel::<(u8, char)>(4);

            // Create permits in one order
            let permit_a = block_on(tx.reserve(&cx)).expect("permit A");
            let permit_b = block_on(tx.reserve(&cx)).expect("permit B");
            let permit_c = block_on(tx.reserve(&cx)).expect("permit C");

            // Execute operations in specific order
            let _proof_c = permit_c.abort();
            let _proof_a = permit_a.send((iteration, 'A')).expect("send A");
            let _proof_b = permit_b.send((iteration, 'B')).expect("send B");

            // Collect results
            let mut messages = Vec::new();
            while let Ok(msg) = rx.try_recv() {
                messages.push(msg);
            }

            // Should get exactly two messages (C was aborted)
            crate::assert_with_log!(
                messages.len() == 2,
                "concurrent permits: correct message count",
                2,
                messages.len()
            );

            // Messages should contain both A and B values
            let has_a = messages.iter().any(|(i, c)| *i == iteration && *c == 'A');
            let has_b = messages.iter().any(|(i, c)| *i == iteration && *c == 'B');
            crate::assert_with_log!(
                has_a && has_b,
                "concurrent permits: both values received",
                "A and B present",
                format!("A:{} B:{}", has_a, has_b)
            );
        }

        crate::test_complete!("meta_concurrent_permit_independence");
    }

    /// META-SESSION-011: Error Recovery Consistency Property
    /// Error recovery should restore the channel to equivalent states
    /// Metamorphic relation: error_recovery_state = fresh_state_with_same_config
    #[test]
    fn meta_error_recovery_consistency() {
        init_test("meta_error_recovery_consistency");
        let cx = test_cx();

        // Scenario 1: Error during send, then recover
        let (tx1, rx1) = tracked_channel::<String>(3);
        let permit1 = block_on(tx1.reserve(&cx)).expect("reserve before error");
        drop(rx1); // Cause disconnection error

        let send_error = permit1.send("will_fail".to_string());
        crate::assert_with_log!(
            send_error.is_err(),
            "send to dropped receiver fails",
            "error",
            "success"
        );

        // After error, channel should be in closed state
        crate::assert_with_log!(
            tx1.is_closed(),
            "channel closed after receiver drop",
            true,
            tx1.is_closed()
        );

        // Scenario 2: Fresh channel in same configuration
        let (tx2, _rx2) = tracked_channel::<String>(3);
        // Don't drop rx2 yet, so channel starts open

        crate::assert_with_log!(
            !tx2.is_closed(),
            "fresh channel starts open",
            false,
            tx2.is_closed()
        );

        // Both closed channels should behave identically
        let reserve1 = tx1.try_reserve(&cx);
        let reserve2_before_close = tx2.try_reserve(&cx);

        crate::assert_with_log!(
            reserve1.is_err(),
            "closed channel rejects reserves",
            "error",
            "success"
        );
        crate::assert_with_log!(
            reserve2_before_close.is_ok(),
            "open channel accepts reserves",
            "success",
            "error"
        );

        // Explicitly abort the successful reserve so the tracked permit
        // token is consumed rather than leaked at scope exit.
        if let Ok(permit) = reserve2_before_close {
            let _ = permit.abort();
        }

        crate::test_complete!("meta_error_recovery_consistency");
    }

    /// META-SESSION-012: Proof Token Lifecycle Invariant Property
    /// Proof tokens should maintain consistent obligation metadata throughout lifecycle
    /// Metamorphic relation: proof_metadata_consistency across all valid proof-generating paths
    #[test]
    fn meta_proof_token_lifecycle_invariant() {
        init_test("meta_proof_token_lifecycle_invariant");
        let cx = test_cx();

        let mut committed_proofs = Vec::new();
        let mut aborted_proofs = Vec::new();

        // Generate proofs via different paths
        for i in 0..3 {
            // Path A: MPSC direct send
            let (tx_a, _rx_a) = tracked_channel::<i32>(1);
            let proof_a = block_on(tx_a.send(&cx, i)).expect("mpsc direct send");
            committed_proofs.push(proof_a);

            // Path B: MPSC reserve + send
            let (tx_b, _rx_b) = tracked_channel::<i32>(1);
            let permit_b = block_on(tx_b.reserve(&cx)).expect("mpsc reserve");
            let proof_b = permit_b.send(i).expect("mpsc permit send");
            committed_proofs.push(proof_b);

            // Path C: Oneshot direct send
            let (tx_c, _rx_c) = tracked_oneshot::<i32>();
            let proof_c = tx_c.send(&cx, i).expect("oneshot direct send");
            committed_proofs.push(proof_c);

            // Path D: MPSC reserve + abort
            let (tx_d, _rx_d) = tracked_channel::<i32>(1);
            let permit_d = block_on(tx_d.reserve(&cx)).expect("mpsc reserve for abort");
            let proof_d = permit_d.abort();
            aborted_proofs.push(proof_d);

            // Path E: Oneshot reserve + abort
            let (tx_e, _rx_e) = tracked_oneshot::<i32>();
            let permit_e = tx_e.reserve(&cx).expect("reserve e");
            let proof_e = permit_e.abort();
            aborted_proofs.push(proof_e);
        }

        // All committed proofs should have identical obligation kind
        let first_committed_kind = committed_proofs[0].kind();
        for (i, proof) in committed_proofs.iter().enumerate() {
            crate::assert_with_log!(
                proof.kind() == first_committed_kind,
                format!("committed proof {} has consistent kind", i),
                first_committed_kind,
                proof.kind()
            );
        }

        // All aborted proofs should have identical obligation kind
        let first_aborted_kind = aborted_proofs[0].kind();
        for (i, proof) in aborted_proofs.iter().enumerate() {
            crate::assert_with_log!(
                proof.kind() == first_aborted_kind,
                format!("aborted proof {} has consistent kind", i),
                first_aborted_kind,
                proof.kind()
            );
        }

        // Committed and aborted proofs should have the same underlying kind
        crate::assert_with_log!(
            first_committed_kind == first_aborted_kind,
            "committed and aborted proofs share obligation kind",
            first_aborted_kind,
            first_committed_kind
        );

        crate::test_complete!("meta_proof_token_lifecycle_invariant");
    }

    /// META-SESSION-013: Channel State Transition Determinism Property
    /// Given the same sequence of operations, channel state transitions should be deterministic
    /// Metamorphic relation: deterministic_state_transitions across identical operation sequences
    #[test]
    fn meta_channel_state_transition_determinism() {
        init_test("meta_channel_state_transition_determinism");
        let cx = test_cx();

        // Define a deterministic sequence of operations
        let operations = vec![
            ("reserve", 0),
            ("reserve", 1),
            ("send", 0),  // send on permit 0
            ("abort", 1), // abort permit 1
            ("reserve", 2),
            ("send", 2),
        ];

        // Execute sequence twice on identical channels
        for run in 0..2 {
            let (tx, mut rx) = tracked_channel::<(usize, usize)>(3);
            let mut permits = Vec::new();
            let mut received_messages = Vec::new();

            for (op, permit_idx) in &operations {
                match *op {
                    "reserve" => {
                        let permit = block_on(tx.reserve(&cx)).expect("deterministic reserve");
                        permits.push(Some(permit));
                    }
                    "send" => {
                        if let Some(permit_slot) = permits.get_mut(*permit_idx) {
                            let taken_permit =
                                permit_slot.take().expect("permit available for send");
                            let _proof = taken_permit
                                .send((run, *permit_idx))
                                .expect("deterministic send");
                        }
                    }
                    "abort" => {
                        if let Some(permit_slot) = permits.get_mut(*permit_idx) {
                            let taken_permit =
                                permit_slot.take().expect("permit available for abort");
                            let _proof = taken_permit.abort();
                        }
                    }
                    _ => unreachable!(),
                }
            }

            // Collect all messages from this run
            while let Ok(msg) = rx.try_recv() {
                received_messages.push(msg);
            }

            // For deterministic verification, store results from first run
            if run == 0 {
                // First run establishes the expected pattern
                crate::assert_with_log!(
                    received_messages.len() == 2,
                    "deterministic run 0: correct message count",
                    2,
                    received_messages.len()
                );
            } else {
                // Second run should match first run exactly
                crate::assert_with_log!(
                    received_messages.len() == 2,
                    "deterministic run 1: matches run 0 message count",
                    2,
                    received_messages.len()
                );

                // Messages should contain the same structure (run differs, permit_idx same)
                let has_permit_0 = received_messages.iter().any(|(_, idx)| *idx == 0);
                let has_permit_2 = received_messages.iter().any(|(_, idx)| *idx == 2);
                crate::assert_with_log!(
                    has_permit_0 && has_permit_2,
                    "deterministic run 1: same permit indices as run 0",
                    "permits 0,2",
                    format!("permit_0:{} permit_2:{}", has_permit_0, has_permit_2)
                );
            }
        }

        crate::test_complete!("meta_channel_state_transition_determinism");
    }

    #[test]
    fn tracked_mpsc_send_recv_under_lab_runtime() {
        init_test("tracked_mpsc_send_recv_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0x05E5_5104)
            .with_tracing(true)
            .with_max_steps(50_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (received, proof_kind, checkpoints) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let sender_cx = cx.clone();
                let receiver_cx = cx.clone();
                let (tx, mut rx) = tracked_channel::<i32>(1);

                let sender_task_cx = sender_cx.clone();
                let sender = LabRuntimeTarget::spawn(&sender_cx, Budget::INFINITE, async move {
                    let permit = tx.reserve(&sender_task_cx).await.expect("reserve failed");
                    tracing::info!(
                        event = %serde_json::json!({
                            "phase": "reserved",
                            "capacity": 1,
                        }),
                        "session_lab_checkpoint"
                    );
                    permit.send(42).expect("send failed").kind()
                });

                let receiver_task_cx = receiver_cx.clone();
                let receiver =
                    LabRuntimeTarget::spawn(&receiver_cx, Budget::INFINITE, async move {
                        let value = rx.recv(&receiver_task_cx).await.expect("recv failed");
                        tracing::info!(
                            event = %serde_json::json!({
                                "phase": "received",
                                "value": value,
                            }),
                            "session_lab_checkpoint"
                        );
                        value
                    });

                yield_now().await;

                let sender_outcome = sender.await;
                crate::assert_with_log!(
                    matches!(sender_outcome, crate::types::Outcome::Ok(_)),
                    "sender task completes successfully",
                    true,
                    matches!(sender_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(proof_kind) = sender_outcome else {
                    unreachable!("validated successful sender outcome");
                };

                let receiver_outcome = receiver.await;
                crate::assert_with_log!(
                    matches!(receiver_outcome, crate::types::Outcome::Ok(_)),
                    "receiver task completes successfully",
                    true,
                    matches!(receiver_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(received) = receiver_outcome else {
                    unreachable!("validated successful receiver outcome");
                };

                let checkpoints = vec![
                    serde_json::json!({
                        "phase": "sender_completed",
                        "proof_kind": format!("{proof_kind:?}"),
                    }),
                    serde_json::json!({
                        "phase": "receiver_completed",
                        "value": received,
                    }),
                ];

                for checkpoint in &checkpoints {
                    tracing::info!(event = %checkpoint, "session_lab_checkpoint");
                }

                (received, proof_kind, checkpoints)
            });

        crate::assert_with_log!(received == 42, "lab runtime recv value", 42, received);
        crate::assert_with_log!(
            proof_kind == crate::record::ObligationKind::SendPermit,
            "lab runtime proof kind",
            crate::record::ObligationKind::SendPermit,
            proof_kind
        );
        crate::assert_with_log!(
            checkpoints.len() == 2,
            "lab runtime emitted completion checkpoints",
            2,
            checkpoints.len()
        );
        crate::assert_with_log!(
            runtime.is_quiescent(),
            "lab runtime reaches quiescence",
            true,
            runtime.is_quiescent()
        );

        crate::test_complete!("tracked_mpsc_send_recv_under_lab_runtime");
    }

    // These are component tests using a real Lab-owned task Cx and its shared
    // regional admission gate. The task remains live until all wrapper actions
    // finish; no scheduler turn or mailbox drain can manufacture reusable credit.
    fn checked_session_fixture(
        limit: usize,
    ) -> (crate::lab::LabRuntime, Cx, crate::runtime::TaskHandle<()>) {
        let mut lab =
            crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x28_5e55).max_steps(128));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .unwrap();
        assert_ne!(
            region.as_u64(),
            0,
            "exercise the production graded-token path"
        );
        assert!(lab.state.set_region_limits(
            region,
            crate::record::region::RegionLimits {
                max_obligations: Some(limit),
                ..crate::record::region::RegionLimits::UNLIMITED
            }
        ));
        let (task, handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async {})
            .unwrap();
        let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        (lab, cx, handle)
    }

    fn checked_session_ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
            panic!("checked operation with available capacity must finish in one poll");
        };
        result
    }

    fn finish_checked_session_fixture(
        mut lab: crate::lab::LabRuntime,
        cx: &Cx,
        mut handle: crate::runtime::TaskHandle<()>,
        committed: u64,
        aborted: u64,
        expected_terminal: Result<Option<()>, crate::runtime::JoinError>,
    ) {
        let mailbox = lab.state.obligation_gateway().unwrap().mailbox().clone();
        let reservations = committed + aborted;
        assert_eq!(mailbox.stats().posted, 2 * reservations);
        assert_eq!(
            mailbox.stats().applied,
            0,
            "credit reuse precedes the drain"
        );
        lab.scheduler.lock().schedule(cx.task_id(), 0);
        let report = lab.run_until_quiescent_with_report();
        assert!(
            report.oracle_report.all_passed(),
            "{:?}",
            report.oracle_report.failures()
        );
        assert!(report.invariant_violations.is_empty());
        assert_eq!(handle.try_join(), expected_terminal);
        let stats = mailbox.stats();
        tracing::info!(?stats, ?cx, committed, aborted, "checked session settled");
        assert_eq!(stats.posted, stats.applied);
        assert_eq!(
            stats.reserved, reservations,
            "one runtime token per graded permit"
        );
        assert_eq!(stats.committed, committed);
        assert_eq!(stats.aborted, aborted);
        assert_eq!(stats.refused, 0);
        assert_eq!(stats.leaked, 0);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
    }

    #[test]
    fn checked_session_zero_quota_preserves_values_without_graded_permits() {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        init_test("checked_session_zero_quota_preserves_values_without_graded_permits");
        let (lab, cx, handle) = checked_session_fixture(0);
        let error = ObligationAdmissionError::LimitReached { limit: 0, live: 0 };
        let (tx, mut rx) = tracked_channel::<String>(1);
        assert_eq!(
            checked_session_ready(tx.reserve_checked(&cx)).unwrap_err(),
            mpsc::CheckedSendError::Admission { error, value: () }
        );
        assert_eq!(
            tx.try_reserve_checked(&cx).unwrap_err(),
            mpsc::CheckedSendError::Admission { error, value: () }
        );
        assert_eq!(
            checked_session_ready(tx.send_checked(&cx, String::from("async owned"))).unwrap_err(),
            mpsc::CheckedSendError::Admission {
                error,
                value: String::from("async owned")
            }
        );
        assert_eq!(
            tx.try_send_checked(&cx, String::from("sync owned"))
                .unwrap_err(),
            mpsc::CheckedSendError::Admission {
                error,
                value: String::from("sync owned")
            }
        );
        assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
        assert_eq!(tx.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        assert_eq!(tx.telemetry_snapshot(1).send_waiter_count, 0);

        let (once, mut once_rx) = tracked_oneshot::<String>();
        assert_eq!(
            once.reserve_checked(&cx).unwrap_err(),
            oneshot::CheckedSendError::Admission { error, value: () }
        );
        assert_eq!(once_rx.try_recv(), Err(oneshot::TryRecvError::Closed));
        let (once, mut once_rx) = tracked_oneshot::<String>();
        assert_eq!(
            once.send_checked(&cx, String::from("once owned"))
                .unwrap_err(),
            oneshot::CheckedSendError::Admission {
                error,
                value: String::from("once owned")
            }
        );
        assert_eq!(once_rx.try_recv(), Err(oneshot::TryRecvError::Closed));
        // Quota denial must also leave the physical MPSC slot usable by the
        // unchanged legacy API. Explicitly abort its separate graded token.
        let proof = tx.try_reserve(&cx).unwrap().abort();
        assert_eq!(proof.kind(), crate::record::ObligationKind::SendPermit);
        finish_checked_session_fixture(lab, &cx, handle, 0, 0, Ok(Some(())));
    }

    #[test]
    fn checked_session_shared_quota_registers_once_and_reuses_credit_in_one_poll() {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        init_test("checked_session_shared_quota_registers_once_and_reuses_credit_in_one_poll");
        let (lab, cx, handle) = checked_session_fixture(1);
        let (tx, mut rx) = tracked_channel::<String>(2);
        let permit = checked_session_ready(tx.reserve_checked(&cx)).unwrap();
        let error = ObligationAdmissionError::LimitReached { limit: 1, live: 1 };
        // A second physical slot is free: only the shared runtime quota refuses.
        assert_eq!(
            tx.try_send_checked(&cx, String::from("denied"))
                .unwrap_err(),
            mpsc::CheckedSendError::Admission {
                error,
                value: String::from("denied")
            }
        );
        let (once, mut once_rx) = tracked_oneshot::<String>();
        assert_eq!(
            once.send_checked(&cx, String::from("cross-channel denied"))
                .unwrap_err(),
            oneshot::CheckedSendError::Admission {
                error,
                value: String::from("cross-channel denied")
            }
        );
        assert_eq!(once_rx.try_recv(), Err(oneshot::TryRecvError::Closed));
        assert_eq!(tx.telemetry_snapshot(2).reserved_uncommitted_obligations, 1);
        let proof = permit.send(String::from("first")).unwrap();
        assert_eq!(proof.kind(), crate::record::ObligationKind::SendPermit);
        assert_eq!(rx.try_recv(), Ok(String::from("first")));
        let proof = tx.try_reserve_checked(&cx).unwrap().abort();
        assert_eq!(proof.kind(), crate::record::ObligationKind::SendPermit);
        let (once, mut once_rx) = tracked_oneshot::<String>();
        let proof = once.reserve_checked(&cx).unwrap().abort();
        assert_eq!(proof.kind(), crate::record::ObligationKind::SendPermit);
        assert_eq!(once_rx.try_recv(), Err(oneshot::TryRecvError::Closed));
        let (once, mut once_rx) = tracked_oneshot::<String>();
        let proof = once.send_checked(&cx, String::from("once")).unwrap();
        assert_eq!(proof.kind(), crate::record::ObligationKind::SendPermit);
        assert_eq!(once_rx.try_recv(), Ok(String::from("once")));
        let _proof = checked_session_ready(tx.send_checked(&cx, String::from("async"))).unwrap();
        assert_eq!(rx.try_recv(), Ok(String::from("async")));
        let _proof = tx.try_send_checked(&cx, String::from("sync")).unwrap();
        assert_eq!(rx.try_recv(), Ok(String::from("sync")));
        assert_eq!(tx.telemetry_snapshot(2).reserved_uncommitted_obligations, 0);
        finish_checked_session_fixture(lab, &cx, handle, 4, 2, Ok(Some(())));
    }

    #[test]
    fn checked_session_channel_errors_keep_values_and_abort_runtime_tokens() {
        init_test("checked_session_channel_errors_keep_values_and_abort_runtime_tokens");
        let (lab, cx, handle) = checked_session_fixture(1);
        let (tx, rx) = tracked_channel::<String>(1);
        let permit = tx.try_reserve_checked(&cx).unwrap();
        assert_eq!(
            tx.try_send_checked(&cx, String::from("full")).unwrap_err(),
            mpsc::CheckedSendError::Channel(mpsc::SendError::Full(String::from("full")))
        );
        drop(rx);
        assert_eq!(
            permit.try_send(String::from("disconnected")).unwrap_err(),
            mpsc::SendError::Disconnected(String::from("disconnected"))
        );
        assert_eq!(
            checked_session_ready(tx.send_checked(&cx, String::from("closed"))).unwrap_err(),
            mpsc::CheckedSendError::Channel(mpsc::SendError::Disconnected(String::from("closed")))
        );
        let (once, once_rx) = tracked_oneshot::<String>();
        drop(once_rx);
        assert_eq!(
            once.send_checked(&cx, String::from("once closed"))
                .unwrap_err(),
            oneshot::CheckedSendError::Channel(oneshot::SendError::Disconnected(String::from(
                "once closed"
            )))
        );
        cx.set_cancel_requested(true);
        let (tx, mut rx) = tracked_channel::<String>(1);
        assert_eq!(
            checked_session_ready(tx.send_checked(&cx, String::from("async cancelled")))
                .unwrap_err(),
            mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(String::from(
                "async cancelled"
            )))
        );
        assert_eq!(
            tx.try_send_checked(&cx, String::from("sync cancelled"))
                .unwrap_err(),
            mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(String::from(
                "sync cancelled"
            )))
        );
        assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
        let (once, mut once_rx) = tracked_oneshot::<String>();
        assert_eq!(
            once.send_checked(&cx, String::from("once cancelled"))
                .unwrap_err(),
            oneshot::CheckedSendError::Channel(oneshot::SendError::Cancelled(String::from(
                "once cancelled"
            )))
        );
        assert_eq!(once_rx.try_recv(), Err(oneshot::TryRecvError::Closed));
        // The same state-owned holder is cancelled before its first poll.
        // Keep that request live: the cancellation-dominant state-task API
        // retains the exact v0.4.x fallback for a reasonless cancellation.
        finish_checked_session_fixture(
            lab,
            &cx,
            handle,
            0,
            2,
            Err(crate::runtime::JoinError::Cancelled(
                crate::types::CancelReason::user("join channel closed"),
            )),
        );
    }

    fn checked_session_panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
        payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .expect("planted panic must retain a string payload")
    }

    #[test]
    fn checked_session_drop_bombs_and_primary_unwind_return_runtime_credit() {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        init_test("checked_session_drop_bombs_and_primary_unwind_return_runtime_credit");
        for oneshot in [false, true] {
            for primary_unwind in [false, true] {
                let (lab, cx, handle) = checked_session_fixture(1);
                let (tx, mut rx) = tracked_channel::<u32>(1);
                let failure = if oneshot {
                    let (once, mut once_rx) = tracked_oneshot::<u32>();
                    let permit = once.reserve_checked(&cx).unwrap();
                    let failure = catch_unwind(AssertUnwindSafe(move || {
                        let owned_permit = permit;
                        if primary_unwind {
                            panic!("planted session owner panic");
                        }
                        drop(owned_permit);
                    }));
                    assert_eq!(once_rx.try_recv(), Err(oneshot::TryRecvError::Closed));
                    failure
                } else {
                    let permit = tx.try_reserve_checked(&cx).unwrap();
                    catch_unwind(AssertUnwindSafe(move || {
                        let owned_permit = permit;
                        if primary_unwind {
                            panic!("planted session owner panic");
                        }
                        drop(owned_permit);
                    }))
                };
                let failure =
                    failure.expect_err("unresolved graded permits must never silently drop");
                let message = checked_session_panic_message(failure.as_ref());
                if primary_unwind {
                    assert_eq!(message, "planted session owner panic");
                } else {
                    assert!(
                        message.contains("[ASUP-E101] OBLIGATION TOKEN LEAKED"),
                        "{message}"
                    );
                }
                assert_eq!(tx.telemetry_snapshot(3).reserved_uncommitted_obligations, 0);
                assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
                let _proof = tx.try_send_checked(&cx, 37).unwrap();
                assert_eq!(rx.try_recv(), Ok(37));
                finish_checked_session_fixture(lab, &cx, handle, 1, 1, Ok(Some(())));
            }
        }
    }

    #[test]
    fn checked_session_notifier_unwind_preserves_primary_panic_and_settlement() {
        use crate::runtime::obligation_mailbox::ObligationGateway;
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        init_test("checked_session_notifier_unwind_preserves_primary_panic_and_settlement");
        for oneshot in [false, true] {
            for phase in ["admission", "commit", "abort"] {
                let (lab, cx, handle) = checked_session_fixture(1);
                let mailbox = lab.state.obligation_gateway().unwrap().mailbox().clone();
                let notifications = Arc::new(AtomicUsize::new(0));
                let observed = notifications.clone();
                let liveness = Arc::new(());
                let gateway = Arc::new(ObligationGateway::new(
                    mailbox,
                    Arc::new(move || {
                        let index = observed.fetch_add(1, Ordering::SeqCst);
                        if index == usize::from(phase != "admission") {
                            panic!("planted session {phase} notifier panic");
                        }
                    }),
                    Arc::downgrade(&liveness),
                ));
                let cx = cx.with_obligation_gateway(Some(gateway), None);
                let (tx, mut rx) = tracked_channel::<u32>(1);
                let failure = if oneshot {
                    let (once, mut once_rx) = tracked_oneshot::<u32>();
                    let failure = catch_unwind(AssertUnwindSafe(|| {
                        let permit = once.reserve_checked(&cx).unwrap();
                        if phase == "commit" {
                            let _proof = permit.send(41).unwrap();
                        } else {
                            let _proof = permit.abort();
                        }
                    }));
                    if phase == "commit" {
                        assert_eq!(once_rx.try_recv(), Ok(41));
                    } else {
                        assert_eq!(once_rx.try_recv(), Err(oneshot::TryRecvError::Closed));
                    }
                    failure
                } else {
                    let failure = catch_unwind(AssertUnwindSafe(|| {
                        let permit = checked_session_ready(tx.reserve_checked(&cx)).unwrap();
                        if phase == "commit" {
                            let _proof = permit.send(41).unwrap();
                        } else {
                            let _proof = permit.abort();
                        }
                    }));
                    if phase == "commit" {
                        assert_eq!(rx.try_recv(), Ok(41));
                    }
                    failure
                };
                let failure = failure.expect_err("the selected real gateway callback must panic");
                assert_eq!(
                    checked_session_panic_message(failure.as_ref()),
                    format!("planted session {phase} notifier panic")
                );
                assert_eq!(tx.telemetry_snapshot(4).reserved_uncommitted_obligations, 0);
                assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
                assert_eq!(
                    notifications.load(Ordering::SeqCst),
                    if phase == "admission" { 1 } else { 2 }
                );
                let _proof = tx.try_send_checked(&cx, 43).unwrap();
                assert_eq!(rx.try_recv(), Ok(43));
                assert_eq!(
                    notifications.load(Ordering::SeqCst),
                    if phase == "admission" { 3 } else { 4 }
                );
                finish_checked_session_fixture(
                    lab,
                    &cx,
                    handle,
                    1 + u64::from(phase == "commit"),
                    u64::from(phase != "commit"),
                    Ok(Some(())),
                );
            }
        }
    }

    #[test]
    fn checked_session_dropping_pending_reservation_retires_waiter_without_token() {
        init_test("checked_session_dropping_pending_reservation_retires_waiter_without_token");
        let (lab, cx, handle) = checked_session_fixture(1);
        let (tx, mut rx) = tracked_channel::<u32>(1);
        let permit = tx.try_reserve_checked(&cx).unwrap();
        let mut waiting = Box::pin(tx.reserve_checked(&cx));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        assert_eq!(tx.telemetry_snapshot(5).send_waiter_count, 1);
        assert_eq!(
            lab.state
                .obligation_gateway()
                .unwrap()
                .mailbox()
                .stats()
                .posted,
            1
        );
        drop(waiting);
        assert_eq!(tx.telemetry_snapshot(5).send_waiter_count, 0);
        assert_eq!(tx.telemetry_snapshot(5).reserved_uncommitted_obligations, 1);
        let _proof = permit.abort();
        let _proof = checked_session_ready(tx.send_checked(&cx, 47)).unwrap();
        assert_eq!(rx.try_recv(), Ok(47));
        finish_checked_session_fixture(lab, &cx, handle, 1, 1, Ok(Some(())));
    }
}
