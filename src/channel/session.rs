//! Session-typed two-phase channels with obligation tracking.
//!
//! This module wraps the existing [`mpsc`](super::mpsc) and [`oneshot`](super::oneshot)
//! channels with obligation-tracked senders that enforce the reserve/commit protocol
//! at the type level. Dropping a [`TrackedPermit`] or [`TrackedOneshotPermit`] without
//! calling `send()` or `abort()` triggers a drop-bomb panic via
//! [`ObligationToken<SendPermit>`](crate::obligation::graded::ObligationToken).
//!
//! The receiver side is unchanged — obligation tracking only affects the sender.
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
//! let fake: CommittedProof<SendPermit> = CommittedProof { _kind: PhantomData };
//! ```

use crate::channel::{mpsc, oneshot};
use crate::cx::Cx;
use crate::obligation::graded::{AbortedProof, CommittedProof, ObligationToken, SendPermit};

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
        let obligation = ObligationToken::<SendPermit>::reserve("TrackedPermit(mpsc)");
        Ok(TrackedPermit { permit, obligation })
    }

    /// Non-blocking reserve attempt.
    pub fn try_reserve(&self) -> Result<TrackedPermit<'_, T>, mpsc::SendError<()>> {
        let permit = self.inner.try_reserve()?;
        let obligation = ObligationToken::<SendPermit>::reserve("TrackedPermit(mpsc)");
        Ok(TrackedPermit { permit, obligation })
    }

    /// Convenience: reserve a slot, send a value, and return the proof.
    pub async fn send(
        &self,
        cx: &Cx,
        value: T,
    ) -> Result<CommittedProof<SendPermit>, mpsc::SendError<T>> {
        let permit = match self.reserve(cx).await {
            Ok(p) => p,
            Err(mpsc::SendError::Disconnected(())) => {
                return Err(mpsc::SendError::Disconnected(value))
            }
            Err(mpsc::SendError::Full(())) => return Err(mpsc::SendError::Full(value)),
            Err(mpsc::SendError::Cancelled(())) => return Err(mpsc::SendError::Cancelled(value)),
        };
        Ok(permit.send(value))
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
    #[must_use]
    pub fn send(self, value: T) -> CommittedProof<SendPermit> {
        let Self { permit, obligation } = self;
        permit.send(value);
        obligation.commit()
    }

    /// Aborts the reserved slot, consuming the permit and returning an [`AbortedProof`].
    #[must_use]
    pub fn abort(self) -> AbortedProof<SendPermit> {
        let Self { permit, obligation } = self;
        permit.abort();
        obligation.abort()
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
    pub fn reserve(self, cx: &Cx) -> TrackedOneshotPermit<T> {
        let permit = self.inner.reserve(cx);
        let obligation = ObligationToken::<SendPermit>::reserve("TrackedOneshotPermit");
        TrackedOneshotPermit { permit, obligation }
    }

    /// Convenience: reserve + send in one step, returning a proof on success.
    pub fn send(
        self,
        cx: &Cx,
        value: T,
    ) -> Result<CommittedProof<SendPermit>, oneshot::SendError<T>> {
        let permit = self.reserve(cx);
        permit.send(value)
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
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(NoopWaker));
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
        let (tx, rx) = tracked_channel::<i32>(10);

        let permit = block_on(tx.reserve(&cx)).expect("reserve failed");
        let proof = permit.send(42);

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
        let (tx, rx) = tracked_channel::<i32>(1);

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
        let _ = permit2.send(99);

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
        let (tx, rx) = tracked_channel::<i32>(10);

        let permit = tx.try_reserve().expect("try_reserve failed");
        let proof = permit.send(7);

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

    // 5. Full oneshot reserve + send + recv with proof
    #[test]
    fn tracked_oneshot_send_recv() {
        init_test("tracked_oneshot_send_recv");
        let cx = test_cx();
        let (tx, rx) = tracked_oneshot::<i32>();

        let permit = tx.reserve(&cx);
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
        let (tx, rx) = tracked_oneshot::<i32>();

        let permit = tx.reserve(&cx);
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

        let permit = tx.reserve(&cx);
        drop(permit); // should panic
    }

    // 8. One-step send() returning CommittedProof
    #[test]
    fn tracked_oneshot_convenience_send() {
        init_test("tracked_oneshot_convenience_send");
        let cx = test_cx();
        let (tx, rx) = tracked_oneshot::<i32>();

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
        let (tx, rx) = tracked_channel::<i32>(10);

        let raw_tx = tx.into_inner();
        // Use the raw sender — no obligation tracking, no panic on permit drop.
        let permit = raw_tx.try_reserve().expect("raw try_reserve failed");
        permit.send(123);

        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 123, "into_inner recv value", 123, value);

        crate::test_complete!("tracked_into_inner_escapes");
    }
}
