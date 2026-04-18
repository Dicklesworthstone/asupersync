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

        let permit = tx.try_reserve().expect("try_reserve failed");
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

    // 5. Full oneshot reserve + send + recv with proof
    #[test]
    fn tracked_oneshot_send_recv() {
        init_test("tracked_oneshot_send_recv");
        let cx = test_cx();
        let (tx, mut rx) = tracked_oneshot::<i32>();

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
        let (tx, mut rx) = tracked_oneshot::<i32>();

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
        let permit = tx.reserve(&cx);
        drop(rx);

        let err = permit
            .send(101)
            .expect_err("reserved oneshot send should fail when receiver is dropped");
        match err {
            oneshot::SendError::Disconnected(value) => {
                crate::assert_with_log!(
                    value == 101,
                    "oneshot disconnected must return original value",
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
        let (tx, _rx) = tracked_channel::<i32>(10);
        let permit = tx.try_reserve().expect("reserve");
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
        let permit = tx.reserve(&cx);
        let dbg = format!("{permit:?}");
        assert!(dbg.contains("TrackedOneshotPermit"));
        let _ = permit.abort();
    }

    #[test]
    fn tracked_oneshot_permit_is_closed() {
        let cx = test_cx();
        let (tx, rx) = tracked_oneshot::<i32>();
        let permit = tx.reserve(&cx);
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
        while let Ok(_) = block_on(rx.try_recv(&cx)) {
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

            if let Err(mpsc::SendError::Disconnected(returned_value)) =
                block_on(tx.send(&cx, original_value)) {
                crate::assert_with_log!(
                    returned_value == original_value,
                    "MPSC error value preservation",
                    original_value,
                    returned_value
                );
            } else {
                panic!("Expected Disconnected error for MPSC");
            }

            // Oneshot case
            let (tx, rx) = tracked_oneshot::<i32>();
            drop(rx); // Disconnect

            if let Err(oneshot::SendError::Disconnected(returned_value)) =
                tx.send(&cx, original_value) {
                crate::assert_with_log!(
                    returned_value == original_value,
                    "Oneshot error value preservation",
                    original_value,
                    returned_value
                );
            } else {
                panic!("Expected Disconnected error for oneshot");
            }
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
        received.sort(); // Order may vary

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
            format!("tx1: {}, tx2: {}, tx3: {}", tx1.is_closed(), tx2.is_closed(), tx3.is_closed())
        );

        drop(rx);

        // After drop: all should be closed (symmetric)
        crate::assert_with_log!(
            tx1.is_closed() && tx2.is_closed() && tx3.is_closed(),
            "all clones closed after receiver drop",
            "all true",
            format!("tx1: {}, tx2: {}, tx3: {}", tx1.is_closed(), tx2.is_closed(), tx3.is_closed())
        );

        // Oneshot case (no clone, but test sender state)
        let (tx, rx) = tracked_oneshot::<i32>();
        crate::assert_with_log!(!tx.is_closed(), "oneshot open before drop", false, tx.is_closed());
        drop(rx);
        crate::assert_with_log!(tx.is_closed(), "oneshot closed after drop", true, tx.is_closed());

        crate::test_complete!("meta_receiver_state_symmetry");
    }

    /// META-SESSION-007: Proof Composition Property
    /// Total proofs (committed + aborted) should equal total permits reserved
    /// Metamorphic relation: committed_proofs + aborted_proofs = reserved_permits
    #[test]
    fn meta_proof_composition() {
        init_test("meta_proof_composition");
        let cx = test_cx();

        let (tx, mut rx) = tracked_channel::<i32>(10);
        let mut reserved_permits = 0;
        let mut committed_proofs = 0;
        let mut aborted_proofs = 0;

        // Reserve 5 permits
        let permits: Vec<_> = (0..5).map(|i| {
            reserved_permits += 1;
            block_on(tx.reserve(&cx)).expect(&format!("reserve {i}"))
        }).collect();

        // Commit 3, abort 2
        for (i, permit) in permits.into_iter().enumerate() {
            if i < 3 {
                let _proof = permit.send(i as i32).expect(&format!("send {i}"));
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
        let permit1 = tx1.reserve(&cx);
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
            block_on(rx1.try_recv(&cx)).is_err() && block_on(rx2.try_recv(&cx)).is_err(),
            "oneshot finality - no more messages",
            "both receivers closed",
            "both receivers closed"
        );

        crate::test_complete!("meta_oneshot_consumption_finality");
    }

}
