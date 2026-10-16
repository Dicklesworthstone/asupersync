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
//! # Callers must run in a non-root region
//!
//! Every tracked reservation mints a graded obligation token scoped to the
//! caller's region, and obligations cannot live in the root region
//! (`[ASUP-E103]`: they would hide leaks and break quiescence). `block_on`'s
//! root task and `RuntimeHandle::spawn` tasks run in the root region, as does
//! a `LabRuntime` task created directly under `create_root_region`; reserving
//! from such a `Cx` panics with `[ASUP-E103]` in every build (the former
//! test-only fallback that masked this is gone, asupersync-a2hoy1). Reserve
//! from a child region (a `Scope` region or a task spawned inside one).
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

/// Mints the graded send obligation for a tracked permit, scoped to the
/// caller's region.
///
/// asupersync-a2hoy1: this used to route the root region (id zero) to the
/// test-only `ObligationToken::reserve_test` under `cfg(test)` and the
/// `test-internals` feature, so every in-tree test of a root-region caller
/// succeeded while production builds panicked with `[ASUP-E103]`. The
/// fallback is gone: tests and production now share one path, and the
/// `[ASUP-E103]` guard in [`ObligationToken::reserve`] is the single source
/// of the non-root requirement (root-region obligations would hide leaks and
/// break quiescence). Callers that must run in the root region, such as
/// `block_on`'s task, need a child region before reserving; the gen_server
/// call path refuses such callers with a typed error instead.
fn reserve_tracked_send_obligation_for_region(
    description: &'static str,
    region: RegionId,
) -> ObligationToken<SendPermit> {
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
    ///
    /// # Panics
    ///
    /// Panics with `[ASUP-E103]` when `cx` belongs to the root region; see
    /// the module docs.
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
    ///
    /// # Panics
    ///
    /// Panics with `[ASUP-E103]` when `cx` belongs to the root region; see
    /// the module docs.
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
    /// Like the legacy session reservation, panics with `[ASUP-E103]` when
    /// `cx` belongs to the root region; see the module docs.
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
    ///
    /// **Cancellation:** this future owns `value` while it waits for a slot;
    /// cancelling it before the reserve completes drops the value. Reserve
    /// first and commit on the permit to keep the value in the caller's hands.
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
    /// requirement is the same as [`Self::reserve_checked`]. Cancelling the
    /// future while it waits for a slot drops `value`, as with [`Self::send`].
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
    ///
    /// # Panics
    ///
    /// Panics with `[ASUP-E103]` when `cx` belongs to the root region; see
    /// the module docs.
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
    /// Like the legacy session reservation, panics with `[ASUP-E103]` when
    /// `cx` belongs to the root region; see the module docs.
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
#[path = "session_inline_tests.rs"]
mod tests;
