// Module-level clippy allows pending cleanup (pre-existing from bd-3u5d3.1).
#![allow(clippy::must_use_candidate)]
#![allow(clippy::manual_assert)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::type_complexity)]
#![allow(clippy::used_underscore_binding)]

//! Session type encoding for obligation protocols (bd-3u5d3.1).
//!
//! Maps Asupersync's obligation protocols to binary session types, providing
//! compile-time guarantees that protocol participants follow the correct
//! message exchange sequence. Each protocol is defined as a global type,
//! projected to local types, and encoded as Rust typestate.
//!
//! # Background
//!
//! Session types formalize the structure of communication between two parties.
//! A global type describes the protocol from a third-person perspective; local
//! types describe what each participant does. Typestate encoding uses
//! `PhantomData<S>` to track the current protocol state, making invalid
//! transitions a compile error.
//!
//! # Protocols
//!
//! ## SendPermit → Ack (Two-Phase Send)
//!
//! Global type:
//! ```text
//!   G_send = Sender → Receiver: Reserve
//!          . Sender → Receiver: { Send(T).end, Abort.end }
//! ```
//!
//! Local types:
//! ```text
//!   L_sender   = !Reserve . ⊕{ !Send(T).end, !Abort.end }
//!   L_receiver = ?Reserve . &{ ?Send(T).end, ?Abort.end }
//! ```
//!
//! ## Lease → Release (Resource Lifecycle)
//!
//! Global type:
//! ```text
//!   G_lease = Holder → Resource: Acquire
//!           . μX. Holder → Resource: { Renew.X, Release.end }
//! ```
//!
//! Local types:
//! ```text
//!   L_holder   = !Acquire . μX. ⊕{ !Renew.X, !Release.end }
//!   L_resource = ?Acquire . μX. &{ ?Renew.X, ?Release.end }
//! ```
//!
//! ## Reserve → Commit (Two-Phase Effect)
//!
//! Global type:
//! ```text
//!   G_2pc = Initiator → Executor: Reserve(K)
//!         . Initiator → Executor: { Commit.end, Abort(reason).end }
//! ```
//!
//! Local types:
//! ```text
//!   L_initiator = !Reserve(K) . ⊕{ !Commit.end, !Abort(reason).end }
//!   L_executor  = ?Reserve(K) . &{ ?Commit.end, ?Abort(reason).end }
//! ```
//!
//! # Encoding
//!
//! The typestate encoding uses zero-sized types as state markers. A channel
//! endpoint `Chan<Role, S>` is parameterized by the participant role and the
//! current session type. Each transition method consumes `self` and returns
//! the channel in the next state, making out-of-order operations impossible.
//!
//! ```text
//!   Chan<Sender, Send<T, S>>  --send(T)-->  Chan<Sender, S>
//!   Chan<Sender, Offer<A, B>> --select-->   Chan<Sender, A> | Chan<Sender, B>
//!   Chan<R, End>              --close()-->  ()
//! ```
//!
//! # Protocol Composition
//!
//! Protocols compose via **delegation**: a channel can be sent as a message
//! in another protocol. This enables a task to hand off its obligation to
//! another task, critical for work-stealing and structured cancellation.
//!
//! ```text
//!   G_delegate = A → B: Delegate(Chan<S>)
//!              . B continues as S
//! ```
//!
//! # Cx Integration
//!
//! Each `Chan` endpoint carries a reference to the `Cx` capability context.
//! Transitions consume budget from the context, and the trace ID propagates
//! through delegated channels for end-to-end distributed tracing.

use crate::record::ObligationKind;
use std::marker::PhantomData;

// ============================================================================
// Session type primitives
// ============================================================================

/// Marker: end of protocol.
pub struct End;

/// Marker: send a value of type `T`, then continue as `S`.
pub struct Send<T, S> {
    _t: PhantomData<T>,
    _s: PhantomData<S>,
}

/// Marker: receive a value of type `T`, then continue as `S`.
pub struct Recv<T, S> {
    _t: PhantomData<T>,
    _s: PhantomData<S>,
}

/// Marker: offer a choice to the peer — either `A` or `B`.
///
/// The local participant decides which branch to take.
pub struct Select<A, B> {
    _a: PhantomData<A>,
    _b: PhantomData<B>,
}

/// Marker: the peer offers a choice — wait for either `A` or `B`.
///
/// The remote participant decides which branch is taken.
pub struct Offer<A, B> {
    _a: PhantomData<A>,
    _b: PhantomData<B>,
}

/// Marker: recursive protocol unfolding point.
///
/// `Rec<F>` marks a recursion boundary. `F` should be a type alias
/// that unfolds to the recursive body when applied.
pub struct Rec<F> {
    _f: PhantomData<F>,
}

/// Marker: jump back to the nearest enclosing `Rec`.
pub struct Var;

// ============================================================================
// Roles
// ============================================================================

/// Participant role: the initiating side of a protocol.
pub struct Initiator;

/// Participant role: the responding side of a protocol.
pub struct Responder;

// ============================================================================
// Channel endpoint (typestate)
// ============================================================================

/// A session-typed channel endpoint.
///
/// `R` is the participant role, `S` is the current session type.
/// The channel tracks the obligation kind for runtime diagnostics
/// and carries a PhantomData marker encoding the protocol state.
///
/// # Linearity
///
/// `Chan` is `#[must_use]` and implements a drop bomb: dropping a
/// channel in a non-`End` state panics. This approximates the linear
/// usage requirement of session types in Rust's affine type system.
///
/// # Cx Integration
///
/// The `trace_id` field enables distributed tracing across delegated
/// channels. Budget consumption is handled externally by the caller
/// (who holds the `Cx` reference).
#[must_use = "session channel must be driven to End; dropping mid-protocol leaks the obligation"]
pub struct Chan<R, S> {
    /// Channel identifier for diagnostics.
    channel_id: u64,
    /// Obligation kind being tracked.
    obligation_kind: ObligationKind,
    /// Whether the channel has reached the End state.
    closed: bool,
    /// Role and session type markers.
    _marker: PhantomData<(R, S)>,
}

impl<R, S> Chan<R, S> {
    /// Create a new channel endpoint in the initial protocol state.
    ///
    /// This is the "session initiation" — both endpoints must be
    /// created together (one `Initiator`, one `Responder`).
    fn new_raw(channel_id: u64, obligation_kind: ObligationKind) -> Self {
        Self {
            channel_id,
            obligation_kind,
            closed: false,
            _marker: PhantomData,
        }
    }

    /// Channel identifier.
    pub fn channel_id(&self) -> u64 {
        self.channel_id
    }

    /// Obligation kind.
    pub fn obligation_kind(&self) -> ObligationKind {
        self.obligation_kind
    }

    /// Unsafe state transition (used by protocol methods).
    ///
    /// Consumes `self` in state `S`, returns a channel in state `S2`.
    /// The caller must ensure this transition is valid per the protocol.
    fn transition<S2>(self) -> Chan<R, S2> {
        let chan = Chan {
            channel_id: self.channel_id,
            obligation_kind: self.obligation_kind,
            closed: false,
            _marker: PhantomData,
        };
        // Disarm the old channel's drop bomb.
        std::mem::forget(self);
        chan
    }
}

// -- Send transition --

impl<R, T, S> Chan<R, Send<T, S>> {
    /// Send a value, transitioning to the continuation state.
    pub fn send(self, _value: T) -> Chan<R, S> {
        // In a real implementation, this would write to the underlying
        // transport. Here we encode only the typestate transition.
        self.transition()
    }
}

// -- Recv transition --

impl<R, T, S> Chan<R, Recv<T, S>> {
    /// Receive a value, transitioning to the continuation state.
    ///
    /// In a real implementation, this would block/await on the transport.
    /// Here it returns a placeholder and transitions the typestate.
    pub fn recv(self, value: T) -> (T, Chan<R, S>) {
        (value, self.transition())
    }
}

// -- Select transition (choice by local participant) --

/// Result of a selection: the chosen branch.
pub enum Selected<A, B> {
    /// First branch was selected.
    Left(A),
    /// Second branch was selected.
    Right(B),
}

impl<R, A, B> Chan<R, Select<A, B>> {
    /// Select the first (left) branch.
    pub fn select_left(self) -> Chan<R, A> {
        self.transition()
    }

    /// Select the second (right) branch.
    pub fn select_right(self) -> Chan<R, B> {
        self.transition()
    }
}

// -- Offer transition (choice by remote participant) --

impl<R, A, B> Chan<R, Offer<A, B>> {
    /// Wait for the peer's choice and branch accordingly.
    ///
    /// The `choice` parameter simulates receiving the peer's decision.
    /// Returns the channel in the chosen branch's state.
    pub fn offer(self, choice: Branch) -> Selected<Chan<R, A>, Chan<R, B>> {
        match choice {
            Branch::Left => Selected::Left(self.transition()),
            Branch::Right => Selected::Right(self.transition()),
        }
    }
}

/// Which branch the peer selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// First branch.
    Left,
    /// Second branch.
    Right,
}

// -- End transition --

/// Proof that a session completed successfully.
#[derive(Debug)]
pub struct SessionProof {
    /// Channel ID of the completed session.
    pub channel_id: u64,
    /// Obligation kind that was fulfilled.
    pub obligation_kind: ObligationKind,
}

impl<R> Chan<R, End> {
    /// Close the channel, producing a proof of session completion.
    pub fn close(self) -> SessionProof {
        let proof = SessionProof {
            channel_id: self.channel_id,
            obligation_kind: self.obligation_kind,
        };
        std::mem::forget(self); // Disarm drop bomb.
        proof
    }
}

impl<R, S> Drop for Chan<R, S> {
    fn drop(&mut self) {
        if !self.closed {
            // In a production build, this would log + metric rather than panic.
            panic!(
                "SESSION LEAKED: channel {} ({}) dropped without reaching End state",
                self.channel_id, self.obligation_kind,
            );
        }
    }
}

// ============================================================================
// Protocol: SendPermit → Ack
// ============================================================================

// Session types for the SendPermit → Ack protocol, generated via
// `session_protocol!` macro (bd-3u5d3.3).
//
// Global type:
//   Sender → Receiver: Reserve
//   Sender → Receiver: { Send(T).end, Abort.end }
asupersync_macros::session_protocol! {
    send_permit<T> for SendPermit {
        msg ReserveMsg;
        msg AbortMsg;

        send ReserveMsg => select {
            send T => end,
            send AbortMsg => end,
        }
    }
}

/// Backward-compatible aliases mapping legacy names to macro-generated types.
pub mod send_permit_compat {
    pub use super::send_permit::InitiatorSession as SenderSession;
    pub use super::send_permit::ResponderSession as ReceiverSession;
}

// ============================================================================
// Protocol: Lease → Release
// ============================================================================

// Session types for the Lease → Release protocol, generated via
// `session_protocol!` macro (bd-3u5d3.4).
//
// Global type:
//   Holder → Resource: Acquire
//   μX. Holder → Resource: { Renew.X, Release.end }
//
// The `loop`/`continue` DSL generates InitiatorLoop/ResponderLoop
// type aliases and a `renew_loop` constructor for μ-unfolding.
asupersync_macros::session_protocol! {
    lease for Lease {
        msg AcquireMsg;
        msg RenewMsg;
        msg ReleaseMsg;

        send AcquireMsg => loop {
            select {
                send RenewMsg => continue,
                send ReleaseMsg => end,
            }
        }
    }
}

/// Backward-compatible aliases for the lease protocol.
pub mod lease_compat {
    pub use super::lease::InitiatorLoop as HolderLoop;
    pub use super::lease::InitiatorSession as HolderSession;
    pub use super::lease::ResponderLoop as ResourceLoop;
    pub use super::lease::ResponderSession as ResourceSession;
}

// ============================================================================
// Protocol: Reserve → Commit (Two-Phase Effect)
// ============================================================================

// Session types for the Reserve → Commit two-phase effect, generated via
// `session_protocol!` macro (bd-3u5d3.5).
//
// Global type:
//   Initiator → Executor: Reserve(K)
//   Initiator → Executor: { Commit.end, Abort(reason).end }
//
// Uses parameterized obligation: constructor takes `kind: ObligationKind`.
asupersync_macros::session_protocol! {
    two_phase(kind: ObligationKind) {
        msg ReserveMsg { kind: ObligationKind };
        msg CommitMsg;
        msg AbortMsg { reason: String };

        send ReserveMsg => select {
            send CommitMsg => end,
            send AbortMsg => end,
        }
    }
}

/// Backward-compatible alias for the two-phase protocol.
pub mod two_phase_compat {
    pub use super::two_phase::ResponderSession as ExecutorSession;
}

// ============================================================================
// Delegation
// ============================================================================

/// Protocol composition via delegation.
///
/// A channel in state `S` can be sent as a message in another protocol,
/// transferring the obligation to the receiver. This is essential for
/// work-stealing: the original task delegates its obligation channel
/// to the stealing worker.
///
/// ```text
///   G_delegate = A → B: Delegate(Chan<S>)
///              . B continues protocol S
/// ```
///
/// In the typestate encoding, delegation is a `Send<Chan<R, S>, End>`
/// on the delegation channel. The delegatee receives a channel already
/// in state `S` and must drive it to `End`.
pub mod delegation {
    use super::{Chan, End, Initiator, Recv, Responder, Send};
    use crate::record::ObligationKind;

    /// Delegator's session type: send the obligation channel, then end.
    pub type DelegatorSession<R, S> = Send<Chan<R, S>, End>;

    /// Delegatee's session type: receive the obligation channel, then end.
    pub type DelegateeSession<R, S> = Recv<Chan<R, S>, End>;

    /// A paired delegation channel.
    pub type DelegationPair<R, S> = (
        Chan<Initiator, DelegatorSession<R, S>>,
        Chan<Responder, DelegateeSession<R, S>>,
    );

    /// Create a delegation channel pair.
    #[allow(clippy::type_complexity)]
    pub fn new_delegation<R, S>(
        channel_id: u64,
        obligation_kind: ObligationKind,
    ) -> DelegationPair<R, S> {
        (
            Chan::new_raw(channel_id, obligation_kind),
            Chan::new_raw(channel_id, obligation_kind),
        )
    }
}

// ============================================================================
// Tracing contract
// ============================================================================

/// Tracing span and metric contract for session type transitions.
///
/// Implementations of the session type protocols MUST emit:
///
/// - **Span**: `session::transition` with fields:
///   - `channel_id`: u64
///   - `from_state`: &str (type name of the pre-transition state)
///   - `to_state`: &str (type name of the post-transition state)
///   - `trace_id`: TraceId (from the Cx context)
///
/// - **DEBUG log**: `session type state transition: channel_id={id}, {from} -> {to}, transition={op}`
///
/// - **INFO log** (on completion): `session completed: channel_id={id}, protocol={name}, total_transitions={n}, duration_us={us}`
///
/// - **WARN log** (on fallback): `session type fallback to runtime checking: channel_id={id}, reason={reason}`
///
/// - **ERROR log** (on violation): `protocol violation detected: channel_id={id}, expected_state={expected}, actual_state={actual}`
///
/// - **Metrics**:
///   - `session_transition_total` (counter by protocol and transition)
///   - `session_completion_total` (counter by protocol and outcome)
///   - `session_duration_us` (histogram by protocol)
///   - `session_fallback_total` (counter by reason)
pub struct TracingContract;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ObligationKind;

    // -- SendPermit protocol --

    #[test]
    fn send_permit_commit_path() {
        let (sender, receiver) = send_permit::new_session::<String>(1);

        // Sender: Reserve → Send → End.
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left(); // choose Send
        let sender = sender.send("hello".to_string());
        let proof = sender.close();
        assert_eq!(proof.channel_id, 1);
        assert_eq!(proof.obligation_kind, ObligationKind::SendPermit);

        // Receiver: Reserve → offer → recv → End.
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (msg, ch) = ch.recv("hello".to_string());
                assert_eq!(msg, "hello");
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Left branch"),
        }
    }

    #[test]
    fn send_permit_abort_path() {
        let (sender, receiver) = send_permit::new_session::<String>(2);

        // Sender: Reserve → Abort → End.
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_right(); // choose Abort
        let sender = sender.send(send_permit::AbortMsg);
        let proof = sender.close();
        assert_eq!(proof.channel_id, 2);

        // Receiver: Reserve → offer → Abort → End.
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(send_permit::AbortMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Right branch"),
        }
    }

    // -- Two-phase commit protocol --

    #[test]
    fn two_phase_commit_path() {
        let (initiator, executor) = two_phase::new_session(3, ObligationKind::SendPermit);

        // Initiator: Reserve → Commit → End.
        let reserve_msg = two_phase::ReserveMsg {
            kind: ObligationKind::SendPermit,
        };
        let initiator = initiator.send(reserve_msg.clone());
        let initiator = initiator.select_left(); // Commit
        let initiator = initiator.send(two_phase::CommitMsg);
        let proof = initiator.close();
        assert_eq!(proof.obligation_kind, ObligationKind::SendPermit);

        // Executor: Reserve → offer → Commit → End.
        let (msg, executor) = executor.recv(reserve_msg);
        assert_eq!(msg.kind, ObligationKind::SendPermit);
        match executor.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(two_phase::CommitMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Commit"),
        }
    }

    #[test]
    fn two_phase_abort_path() {
        let (initiator, executor) = two_phase::new_session(4, ObligationKind::Lease);

        // Initiator: Reserve → Abort → End.
        let reserve_msg = two_phase::ReserveMsg {
            kind: ObligationKind::Lease,
        };
        let initiator = initiator.send(reserve_msg.clone());
        let initiator = initiator.select_right(); // Abort
        let abort_msg = two_phase::AbortMsg {
            reason: "timeout".to_string(),
        };
        let initiator = initiator.send(abort_msg);
        let proof = initiator.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        // Executor side.
        let (_, executor) = executor.recv(reserve_msg);
        match executor.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (msg, ch) = ch.recv(two_phase::AbortMsg {
                    reason: "timeout".to_string(),
                });
                assert_eq!(msg.reason, "timeout");
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Abort"),
        }
    }

    // -- Lease protocol --

    #[test]
    fn lease_acquire_and_release() {
        let (holder, resource) = lease::new_session(5);

        // Holder: Acquire → Release → End.
        let holder = holder.send(lease::AcquireMsg);
        let holder = holder.select_right(); // Release
        let holder = holder.send(lease::ReleaseMsg);
        let proof = holder.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        // Resource: Acquire → offer → Release → End.
        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Release"),
        }
    }

    #[test]
    fn lease_acquire_renew_release() {
        let (holder, resource) = lease::new_session(6);

        // Holder: Acquire → Renew → (new loop) → Release → End.
        let holder = holder.send(lease::AcquireMsg);
        let holder = holder.select_left(); // Renew
        let holder = holder.send(lease::RenewMsg);
        let _proof_renew = holder.close();

        // After renew, create a new loop iteration.
        let (holder2, resource2) = lease::renew_loop(6);
        let holder2 = holder2.select_right(); // Release
        let holder2 = holder2.send(lease::ReleaseMsg);
        let proof = holder2.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        // Resource side: Acquire → Renew.
        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(lease::RenewMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Renew"),
        }

        // Resource loop 2: Release.
        match resource2.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Release"),
        }
    }

    // -- SessionProof --

    #[test]
    fn session_proof_fields() {
        let (sender, _receiver) = send_permit::new_session::<u32>(42);

        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left();
        let sender = sender.send(100_u32);
        let proof = sender.close();

        assert_eq!(proof.channel_id, 42);
        assert_eq!(proof.obligation_kind, ObligationKind::SendPermit);

        // Prevent receiver drop bomb.
        std::mem::forget(_receiver);
    }

    // -- Drop bomb verification --

    #[test]
    #[should_panic(expected = "SESSION LEAKED")]
    fn drop_mid_protocol_panics() {
        let (sender, receiver) = send_permit::new_session::<u32>(99);

        // Forget receiver first to avoid double-panic during unwinding.
        std::mem::forget(receiver);

        // Sender starts but doesn't finish — drop should panic.
        let sender = sender.send(send_permit::ReserveMsg);
        drop(sender); // PANIC: session leaked
    }

    // -- Chan transition preserves metadata --

    #[test]
    fn transition_preserves_channel_id() {
        let (sender, _receiver) = two_phase::new_session(77, ObligationKind::IoOp);
        assert_eq!(sender.channel_id(), 77);
        assert_eq!(sender.obligation_kind(), ObligationKind::IoOp);

        let reserve_msg = two_phase::ReserveMsg {
            kind: ObligationKind::IoOp,
        };
        let sender = sender.send(reserve_msg);
        let sender = sender.select_left();
        let sender = sender.send(two_phase::CommitMsg);
        let proof = sender.close();
        assert_eq!(proof.channel_id, 77);

        std::mem::forget(_receiver);
    }
}
