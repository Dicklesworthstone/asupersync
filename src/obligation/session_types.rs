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
//! # Transport Modes
//!
//! Session channels operate in two modes:
//!
//! - **Pure typestate** (default): `send(v)` discards the value and only tracks
//!   the state transition. Created with `new_session()`.
//! - **Transport-backed**: `send_async(&cx, v)` actually sends the value over an
//!   in-process `mpsc` channel. Created with `new_transport_pair()`.
//!
//! The async methods (`send_async`, `recv_async`, `select_*_async`, `offer_async`)
//! require transport backing and take `&Cx` for cancellation and budget enforcement.
//! When the peer drops or `Cx` is cancelled, they return `SessionError`.
//!
//! # Supported Scope
//!
//! - **In-process `mpsc` transport** is the only supported bridge.
//! - **Cross-process/network transport** is explicitly deferred.
//! - **Serialization** (Serde bounds) is not required for in-process use.
//!
//! # Cx Integration
//!
//! All transport-backed operations take `&Cx` for cancellation and budget checks.
//! The trace ID propagates through delegated channels for distributed tracing.
//!
//! # Compile-Fail Migration Guards
//!
//! The typed surface stays explicitly opt-in until both compile-fail and
//! typed-vs-dynamic migration checks remain green. These doctests are the
//! compile-fail portion of the AA-05.3 contract.
//!
//! Sending a payload before selecting the `Send` or `Abort` branch is illegal:
//!
//! ```compile_fail
//! use asupersync::obligation::session_types::send_permit;
//!
//! let (sender, _receiver) = send_permit::new_session::<u64>(7);
//! let sender = sender.send(send_permit::ReserveMsg);
//! let _illegal = sender.send(42_u64);
//! ```
//!
//! A lease cannot be closed before the protocol reaches `End`:
//!
//! ```compile_fail
//! use asupersync::obligation::session_types::lease;
//!
//! let (holder, _resource) = lease::new_session(9);
//! let holder = holder.send(lease::AcquireMsg);
//! let _proof = holder.close();
//! ```
//!
//! Choosing the `Commit` branch forbids sending an abort message afterward:
//!
//! ```compile_fail
//! use asupersync::obligation::session_types::two_phase;
//! use asupersync::record::ObligationKind;
//!
//! let (initiator, _executor) = two_phase::new_session(11, ObligationKind::IoOp);
//! let initiator = initiator.send(two_phase::ReserveMsg {
//!     kind: ObligationKind::IoOp,
//! });
//! let initiator = initiator.select_left();
//! let _illegal = initiator.send(two_phase::AbortMsg {
//!     reason: "late abort".to_string(),
//! });
//! ```

use crate::channel::mpsc;
use crate::cx::Cx;
use crate::record::ObligationKind;
use std::future::Future;
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
// Transport backing
// ============================================================================

/// Type-erased bidirectional transport for session channels.
///
/// Each endpoint holds a sender (to push messages to the peer) and a
/// receiver (to pull messages from the peer). Messages are `Box<dyn std::any::Any + std::marker::Send>`
/// to allow different types at different protocol stages.
pub(super) struct SessionTransport {
    /// Send half — push messages to the peer endpoint.
    tx: mpsc::Sender<Box<dyn std::any::Any + std::marker::Send>>,
    /// Receive half — pull messages from the peer endpoint.
    rx: mpsc::Receiver<Box<dyn std::any::Any + std::marker::Send>>,
}

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
/// # Transport Modes
///
/// When `transport` is `None`, the channel operates in pure typestate mode
/// (transitions only, no communication). When `Some`, the async methods
/// actually send and receive values over an mpsc channel.
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
    /// Transport backing (None = pure typestate, Some = transport-backed).
    transport: Option<SessionTransport>,
    /// Role and session type markers.
    _marker: PhantomData<(R, S)>,
}

impl<R, S> Chan<R, S> {
    /// Create a new channel endpoint in pure typestate mode (no transport).
    ///
    /// This is the "session initiation" — both endpoints must be
    /// created together (one `Initiator`, one `Responder`).
    fn new_raw(channel_id: u64, obligation_kind: ObligationKind) -> Self {
        Self {
            channel_id,
            obligation_kind,
            closed: false,
            transport: None,
            _marker: PhantomData,
        }
    }

    /// Create a new channel endpoint with transport backing.
    #[allow(dead_code)] // Used by non-proc-macros session constructors
    fn new_with_transport(
        channel_id: u64,
        obligation_kind: ObligationKind,
        transport: SessionTransport,
    ) -> Self {
        Self {
            channel_id,
            obligation_kind,
            closed: false,
            transport: Some(transport),
            _marker: PhantomData,
        }
    }

    /// Returns true if this channel has transport backing.
    #[must_use]
    pub fn is_transport_backed(&self) -> bool {
        self.transport.is_some()
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
    /// Transport backing is carried forward to the new state.
    fn transition<S2>(mut self) -> Chan<R, S2> {
        let channel_id = self.channel_id;
        let obligation_kind = self.obligation_kind;
        let transport = self.transport.take();
        // Disarm drop bomb for the consumed pre-transition state.
        self.closed = true;
        Chan {
            channel_id,
            obligation_kind,
            closed: false,
            transport,
            _marker: PhantomData,
        }
    }

    /// Disarm the drop bomb for testing without leaking memory or triggering warnings.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn disarm_for_test(mut self) {
        self.closed = true;
    }
}

// -- Send transition --

impl<R, T, S> Chan<R, Send<T, S>> {
    /// Send a value (pure typestate mode, no transport).
    ///
    /// In pure typestate mode, the value is discarded and only the state
    /// transition is tracked. Use [`send_async`] for transport-backed channels.
    pub fn send(self, _value: T) -> Chan<R, S> {
        self.transition()
    }
}

fn map_transport_send_error<T>(error: &mpsc::SendError<T>) -> SessionError {
    match error {
        mpsc::SendError::Disconnected(_) => SessionError::Closed,
        mpsc::SendError::Cancelled(_) => SessionError::Cancelled,
        mpsc::SendError::Full(_) => {
            debug_assert!(
                false,
                "transport-backed session send unexpectedly returned SendError::Full"
            );
            SessionError::Closed
        }
    }
}

impl<R, T: std::marker::Send + 'static, S> Chan<R, Send<T, S>> {
    /// Send a value over the transport, transitioning to the continuation state.
    ///
    /// Returns `SessionError::Cancelled` if the `Cx` is cancelled, or
    /// `SessionError::Closed` if the peer endpoint was dropped.
    ///
    /// # Panics
    ///
    /// Panics if this channel has no transport backing. Use [`is_transport_backed`]
    /// to check, or construct with [`new_transport_pair`].
    pub fn send_async<'a>(
        mut self,
        cx: &'a Cx,
        value: T,
    ) -> impl Future<Output = Result<Chan<R, S>, SessionError>> + 'a
    where
        R: 'a,
        S: 'a,
    {
        let transport = self
            .transport
            .take()
            .expect("send_async called on non-transport-backed session channel");

        // Disarm before the future is returned so dropping an unpolled future
        // is just as safe as dropping one after it has yielded once.
        self.closed = true;

        async move {
            let boxed = Box::new(value) as Box<dyn std::any::Any + std::marker::Send>;
            if let Err(error) = transport.tx.send(cx, boxed).await {
                return Err(map_transport_send_error(&error));
            }

            self.transport = Some(transport);
            self.closed = false;
            Ok(self.transition())
        }
    }
}

// -- Recv transition --

impl<R, T, S> Chan<R, Recv<T, S>> {
    /// Receive a value (pure typestate mode, no transport).
    ///
    /// In pure typestate mode, the caller provides the value. Use
    /// [`recv_async`] for transport-backed channels.
    pub fn recv(self, value: T) -> (T, Chan<R, S>) {
        (value, self.transition())
    }
}

impl<R, T: std::marker::Send + 'static, S> Chan<R, Recv<T, S>> {
    /// Receive a value from the transport, transitioning to the continuation state.
    ///
    /// Returns `SessionError::Cancelled` if the `Cx` is cancelled, or
    /// `SessionError::Closed` if the peer endpoint was dropped.
    ///
    /// # Panics
    ///
    /// Panics if this channel has no transport backing, or if the received
    /// value is not of the expected type (protocol violation).
    pub fn recv_async<'a>(
        mut self,
        cx: &'a Cx,
    ) -> impl Future<Output = Result<(T, Chan<R, S>), SessionError>> + 'a
    where
        R: 'a,
        S: 'a,
        T: 'a,
    {
        let mut transport = self
            .transport
            .take()
            .expect("recv_async called on non-transport-backed session channel");

        // Disarm before the future is returned so dropping an unpolled future
        // is just as safe as dropping one after it has yielded once.
        self.closed = true;

        async move {
            let boxed = match transport.rx.recv(cx).await {
                Ok(boxed) => boxed,
                Err(error) => {
                    return Err(map_transport_recv_error(error));
                }
            };

            let Ok(value) = boxed.downcast::<T>() else {
                return Err(SessionError::ProtocolViolation {
                    expected: std::any::type_name::<T>(),
                    actual: "unknown (downcast failed)",
                });
            };

            self.transport = Some(transport);
            self.closed = false;
            Ok((*value, self.transition()))
        }
    }
}

fn map_transport_recv_error(error: mpsc::RecvError) -> SessionError {
    match error {
        mpsc::RecvError::Disconnected => SessionError::Closed,
        mpsc::RecvError::Cancelled => SessionError::Cancelled,
        mpsc::RecvError::Empty => {
            debug_assert!(
                false,
                "transport-backed session recv unexpectedly returned RecvError::Empty"
            );
            SessionError::Closed
        }
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
    /// Select the first (left) branch (pure typestate mode).
    pub fn select_left(self) -> Chan<R, A> {
        self.transition()
    }

    /// Select the second (right) branch (pure typestate mode).
    pub fn select_right(self) -> Chan<R, B> {
        self.transition()
    }

    /// Select the left branch and notify the peer via transport.
    ///
    /// # Panics
    ///
    /// Panics if this channel has no transport backing. Use [`is_transport_backed`]
    /// to check, or use [`select_left`](Self::select_left) for pure typestate mode.
    pub fn select_left_async<'a>(
        mut self,
        cx: &'a Cx,
    ) -> impl Future<Output = Result<Chan<R, A>, SessionError>> + 'a
    where
        R: 'a,
        A: 'a,
        B: 'a,
    {
        let transport = self
            .transport
            .take()
            .expect("select_left_async called on non-transport-backed session channel");

        // Disarm before the future is returned so dropping an unpolled future
        // is just as safe as dropping one after it has yielded once.
        self.closed = true;

        async move {
            let branch = Box::new(Branch::Left) as Box<dyn std::any::Any + std::marker::Send>;
            if let Err(error) = transport.tx.send(cx, branch).await {
                return Err(map_transport_send_error(&error));
            }

            self.transport = Some(transport);
            self.closed = false;
            Ok(self.transition())
        }
    }

    /// Select the right branch and notify the peer via transport.
    ///
    /// # Panics
    ///
    /// Panics if this channel has no transport backing. Use [`is_transport_backed`]
    /// to check, or use [`select_right`](Self::select_right) for pure typestate mode.
    pub fn select_right_async<'a>(
        mut self,
        cx: &'a Cx,
    ) -> impl Future<Output = Result<Chan<R, B>, SessionError>> + 'a
    where
        R: 'a,
        A: 'a,
        B: 'a,
    {
        let transport = self
            .transport
            .take()
            .expect("select_right_async called on non-transport-backed session channel");

        // Disarm before the future is returned so dropping an unpolled future
        // is just as safe as dropping one after it has yielded once.
        self.closed = true;

        async move {
            let branch = Box::new(Branch::Right) as Box<dyn std::any::Any + std::marker::Send>;
            if let Err(error) = transport.tx.send(cx, branch).await {
                return Err(map_transport_send_error(&error));
            }

            self.transport = Some(transport);
            self.closed = false;
            Ok(self.transition())
        }
    }
}

// -- Offer transition (choice by remote participant) --

impl<R, A, B> Chan<R, Offer<A, B>> {
    /// Wait for the peer's choice (pure typestate mode).
    ///
    /// The `choice` parameter simulates receiving the peer's decision.
    pub fn offer(self, choice: Branch) -> Selected<Chan<R, A>, Chan<R, B>> {
        match choice {
            Branch::Left => Selected::Left(self.transition()),
            Branch::Right => Selected::Right(self.transition()),
        }
    }

    /// Wait for the peer's branch selection via transport.
    ///
    /// Returns the channel in the chosen branch's state.
    pub fn offer_async<'a>(
        mut self,
        cx: &'a Cx,
    ) -> impl Future<Output = Result<Selected<Chan<R, A>, Chan<R, B>>, SessionError>> + 'a
    where
        R: 'a,
        A: 'a,
        B: 'a,
    {
        let mut transport = self
            .transport
            .take()
            .expect("offer_async called on non-transport-backed session channel");

        // Disarm before the future is returned so dropping an unpolled future
        // is just as safe as dropping one after it has yielded once.
        self.closed = true;

        async move {
            let boxed = match transport.rx.recv(cx).await {
                Ok(boxed) => boxed,
                Err(error) => {
                    return Err(map_transport_recv_error(error));
                }
            };

            let Ok(branch) = boxed.downcast::<Branch>() else {
                return Err(SessionError::ProtocolViolation {
                    expected: "Branch (Left/Right)",
                    actual: "unknown (downcast failed)",
                });
            };

            self.transport = Some(transport);
            self.closed = false;
            let branch = *branch;

            match branch {
                Branch::Left => Ok(Selected::Left(self.transition())),
                Branch::Right => Ok(Selected::Right(self.transition())),
            }
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
    pub fn close(mut self) -> SessionProof {
        self.closed = true;
        SessionProof {
            channel_id: self.channel_id,
            obligation_kind: self.obligation_kind,
        }
    }
}

impl<R, S> Drop for Chan<R, S> {
    fn drop(&mut self) {
        if !self.closed {
            // If the thread is already panicking, we don't want to double-panic and abort.
            if std::thread::panicking() {
                return;
            }

            // In a production build, this logs rather than panics.
            #[cfg(debug_assertions)]
            panic!(
                // ubs:ignore - intentional panic on leak in debug build
                "SESSION LEAKED: channel {} ({}) dropped without reaching End state",
                self.channel_id, self.obligation_kind,
            );

            #[cfg(not(debug_assertions))]
            crate::tracing_compat::error!(
                channel_id = %self.channel_id,
                obligation_kind = %self.obligation_kind,
                "SESSION LEAKED: dropped without reaching End state"
            );
        }
    }
}

// ============================================================================
// Transport-backed session creation (works with any protocol)
// ============================================================================

/// Create a transport-backed session pair for any protocol.
///
/// `IS` and `RS` are the session types for the initiator and responder
/// respectively (e.g., `send_permit::InitiatorSession<T>` and
/// `send_permit::ResponderSession<T>`).
///
/// `buffer` controls the mpsc channel capacity for backpressure.
pub fn new_transport_pair<IS, RS>(
    channel_id: u64,
    obligation_kind: ObligationKind,
    buffer: usize,
) -> (Chan<Initiator, IS>, Chan<Responder, RS>) {
    let (tx_i2r, rx_i2r) = mpsc::channel::<Box<dyn std::any::Any + std::marker::Send>>(buffer);
    let (tx_r2i, rx_r2i) = mpsc::channel::<Box<dyn std::any::Any + std::marker::Send>>(buffer);
    (
        Chan::new_with_transport(
            channel_id,
            obligation_kind,
            SessionTransport {
                tx: tx_i2r,
                rx: rx_r2i,
            },
        ),
        Chan::new_with_transport(
            channel_id,
            obligation_kind,
            SessionTransport {
                tx: tx_r2i,
                rx: rx_i2r,
            },
        ),
    )
}

// ============================================================================
// Protocol: SendPermit → Ack
// ============================================================================

// When `proc-macros` is enabled, protocols are generated via `session_protocol!`.
// Otherwise, hand-written typestate definitions are used as fallback.

#[cfg(feature = "proc-macros")]
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

#[cfg(feature = "proc-macros")]
/// Backward-compatible aliases mapping legacy names to macro-generated types.
pub mod send_permit_compat {
    pub use super::send_permit::InitiatorSession as SenderSession;
    pub use super::send_permit::ResponderSession as ReceiverSession;
}

#[cfg(not(feature = "proc-macros"))]
/// Session types for the SendPermit → Ack protocol.
pub mod send_permit {
    use super::{Chan, End, Initiator, Offer, Recv, Responder, Select, Send, SessionTransport};
    use crate::channel::mpsc;
    use crate::record::ObligationKind;

    /// Reserve request marker.
    pub struct ReserveMsg;
    /// Abort notification marker.
    pub struct AbortMsg;

    /// Initiator's session type: send Reserve, then choose Send(T) or Abort.
    pub type SenderSession<T> = Send<ReserveMsg, Select<Send<T, End>, Send<AbortMsg, End>>>;
    /// Alias for macro compatibility.
    pub type InitiatorSession<T> = SenderSession<T>;

    /// Responder's session type: recv Reserve, then offer Send(T) or Abort.
    pub type ReceiverSession<T> = Recv<ReserveMsg, Offer<Recv<T, End>, Recv<AbortMsg, End>>>;
    /// Alias for macro compatibility.
    pub type ResponderSession<T> = ReceiverSession<T>;

    /// Create a paired sender/receiver session for SendPermit (pure typestate).
    pub fn new_session<T>(
        channel_id: u64,
    ) -> (
        Chan<Initiator, SenderSession<T>>,
        Chan<Responder, ReceiverSession<T>>,
    ) {
        (
            Chan::new_raw(channel_id, ObligationKind::SendPermit),
            Chan::new_raw(channel_id, ObligationKind::SendPermit),
        )
    }

    /// Create a transport-backed sender/receiver session for SendPermit.
    ///
    /// Each endpoint gets a bidirectional mpsc channel to the peer.
    /// `buffer` controls the mpsc channel capacity.
    pub fn new_session_with_transport<T>(
        channel_id: u64,
        buffer: usize,
    ) -> (
        Chan<Initiator, SenderSession<T>>,
        Chan<Responder, ReceiverSession<T>>,
    ) {
        let (tx_i2r, rx_i2r) = mpsc::channel::<Box<dyn std::any::Any + std::marker::Send>>(buffer);
        let (tx_r2i, rx_r2i) = mpsc::channel::<Box<dyn std::any::Any + std::marker::Send>>(buffer);
        (
            Chan::new_with_transport(
                channel_id,
                ObligationKind::SendPermit,
                SessionTransport {
                    tx: tx_i2r,
                    rx: rx_r2i,
                },
            ),
            Chan::new_with_transport(
                channel_id,
                ObligationKind::SendPermit,
                SessionTransport {
                    tx: tx_r2i,
                    rx: rx_i2r,
                },
            ),
        )
    }
}

#[cfg(not(feature = "proc-macros"))]
/// Backward-compatible aliases for the send_permit protocol.
pub mod send_permit_compat {
    pub use super::send_permit::ReceiverSession;
    pub use super::send_permit::SenderSession;
}

// ============================================================================
// Protocol: Lease → Release
// ============================================================================

#[cfg(feature = "proc-macros")]
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

#[cfg(feature = "proc-macros")]
/// Backward-compatible aliases for the lease protocol.
pub mod lease_compat {
    pub use super::lease::InitiatorLoop as HolderLoop;
    pub use super::lease::InitiatorSession as HolderSession;
    pub use super::lease::ResponderLoop as ResourceLoop;
    pub use super::lease::ResponderSession as ResourceSession;
}

#[cfg(not(feature = "proc-macros"))]
/// Session types for the Lease → Release protocol.
pub mod lease {
    use super::{Chan, End, Initiator, Offer, Recv, Responder, Select, Send, SessionTransport};
    use crate::record::ObligationKind;

    /// Acquire request marker.
    pub struct AcquireMsg;
    /// Renew request marker.
    pub struct RenewMsg;
    /// Release notification marker.
    pub struct ReleaseMsg;

    /// One iteration of the lease loop.
    pub type HolderLoop = Select<Send<RenewMsg, End>, Send<ReleaseMsg, End>>;
    /// Alias for macro compatibility.
    pub type InitiatorLoop = HolderLoop;

    /// Holder's session type: send Acquire, then enter loop.
    pub type HolderSession = Send<AcquireMsg, HolderLoop>;
    /// Alias for macro compatibility.
    pub type InitiatorSession = HolderSession;

    /// Resource's session type for one loop iteration.
    pub type ResourceLoop = Offer<Recv<RenewMsg, End>, Recv<ReleaseMsg, End>>;
    /// Alias for macro compatibility.
    pub type ResponderLoop = ResourceLoop;

    /// Resource's session type: recv Acquire, then enter loop.
    pub type ResourceSession = Recv<AcquireMsg, ResourceLoop>;
    /// Alias for macro compatibility.
    pub type ResponderSession = ResourceSession;

    /// Create a paired holder/resource session for Lease (pure typestate).
    pub fn new_session(
        channel_id: u64,
    ) -> (
        Chan<Initiator, HolderSession>,
        Chan<Responder, ResourceSession>,
    ) {
        (
            Chan::new_raw(channel_id, ObligationKind::Lease),
            Chan::new_raw(channel_id, ObligationKind::Lease),
        )
    }

    /// Create a transport-backed holder/resource session for Lease.
    pub fn new_session_with_transport(
        channel_id: u64,
        buffer: usize,
    ) -> (
        Chan<Initiator, HolderSession>,
        Chan<Responder, ResourceSession>,
    ) {
        let (tx_i2r, rx_i2r) =
            crate::channel::mpsc::channel::<Box<dyn std::any::Any + std::marker::Send>>(buffer);
        let (tx_r2i, rx_r2i) =
            crate::channel::mpsc::channel::<Box<dyn std::any::Any + std::marker::Send>>(buffer);
        (
            Chan::new_with_transport(
                channel_id,
                ObligationKind::Lease,
                SessionTransport {
                    tx: tx_i2r,
                    rx: rx_r2i,
                },
            ),
            Chan::new_with_transport(
                channel_id,
                ObligationKind::Lease,
                SessionTransport {
                    tx: tx_r2i,
                    rx: rx_i2r,
                },
            ),
        )
    }

    /// After a `Renew`, create a fresh loop iteration (pure typestate).
    pub fn renew_loop(
        channel_id: u64,
    ) -> (Chan<Initiator, HolderLoop>, Chan<Responder, ResourceLoop>) {
        (
            Chan::new_raw(channel_id, ObligationKind::Lease),
            Chan::new_raw(channel_id, ObligationKind::Lease),
        )
    }
}

#[cfg(not(feature = "proc-macros"))]
/// Backward-compatible aliases for the lease protocol.
pub mod lease_compat {
    pub use super::lease::HolderLoop;
    pub use super::lease::HolderSession;
    pub use super::lease::ResourceLoop;
    pub use super::lease::ResourceSession;
}

// ============================================================================
// Protocol: Reserve → Commit (Two-Phase Effect)
// ============================================================================

#[cfg(feature = "proc-macros")]
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

#[cfg(feature = "proc-macros")]
/// Backward-compatible alias for the two-phase protocol.
pub mod two_phase_compat {
    pub use super::two_phase::ResponderSession as ExecutorSession;
}

#[cfg(not(feature = "proc-macros"))]
/// Session types for the Reserve → Commit two-phase effect.
pub mod two_phase {
    use super::{Chan, End, Initiator, Offer, Recv, Responder, Select, Send};
    use crate::record::ObligationKind;

    /// Reserve request carrying the obligation kind.
    #[derive(Debug, Clone)]
    pub struct ReserveMsg {
        /// Which obligation kind is being reserved.
        pub kind: ObligationKind,
    }

    /// Commit notification.
    pub struct CommitMsg;

    /// Abort notification with reason.
    #[derive(Debug, Clone)]
    pub struct AbortMsg {
        /// Why the obligation was aborted.
        pub reason: String,
    }

    /// Initiator's session type: send Reserve, then choose Commit or Abort.
    pub type InitiatorSession = Send<ReserveMsg, Select<Send<CommitMsg, End>, Send<AbortMsg, End>>>;

    /// Executor's session type: recv Reserve, then offer Commit or Abort.
    pub type ExecutorSession = Recv<ReserveMsg, Offer<Recv<CommitMsg, End>, Recv<AbortMsg, End>>>;
    /// Alias for macro compatibility.
    pub type ResponderSession = ExecutorSession;

    /// Create a paired initiator/executor session for two-phase commit.
    pub fn new_session(
        channel_id: u64,
        kind: ObligationKind,
    ) -> (
        Chan<Initiator, InitiatorSession>,
        Chan<Responder, ExecutorSession>,
    ) {
        (
            Chan::new_raw(channel_id, kind),
            Chan::new_raw(channel_id, kind),
        )
    }
}

#[cfg(not(feature = "proc-macros"))]
/// Backward-compatible alias for the two-phase protocol.
pub mod two_phase_compat {
    pub use super::two_phase::ExecutorSession;
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
// Transport bridge contract (G1 decision — bead v2ofj7.7.1)
// ============================================================================

/// Transport bridge contract for session-typed channels.
///
/// # Current contract
///
/// The session-type API now supports both:
///
/// - pure typestate transitions for compile-time protocol checking, and
/// - an in-process transport-backed mode via [`new_transport_pair`] plus the
///   async transition methods (`send_async`, `recv_async`, `select_*_async`,
///   `offer_async`).
///
/// The transport-backed surface is intentionally narrow: it only covers
/// in-process bounded `mpsc` delivery. Cross-process and network bindings
/// remain explicitly deferred.
///
/// ## Chosen Bridge: in-process `mpsc`
///
/// Session channels bind to the existing in-process `mpsc::channel` transport.
/// This keeps the runtime contract honest without pretending the surface is
/// already a general remote/session-runtime abstraction.
///
/// ### Architecture
///
/// ```text
///   Chan<R, Send<T, S>>
///       │
///       ├── Typestate transition (compile-time)
///       │
///       └── SessionTransport (bidirectional)
///               │
///               ├── tx: mpsc::Sender<Box<dyn Any + Send>>
///               │       └── reserve(&cx) → Permit → send(Box::new(v))
///               │
///               └── rx: mpsc::Receiver<Box<dyn Any + Send>>
///                       └── recv(&cx) → downcast::<T>() | SessionError
/// ```
///
/// ### Wire Format
///
/// The transport uses `Box<dyn Any + Send>` with runtime downcasting:
///
/// ```text
///   Send<T, S>  transitions  → Box::new(value: T), downcast::<T>() on recv
///   Select<A,B> transitions  → Box::new(Branch::Left | Branch::Right)
///   End.close()              → no transport message (local disarm only)
/// ```
///
/// ### Capability Requirements
///
/// - **`Cx` reference**: Every transport operation takes `&Cx` for cancellation
///   and budget enforcement. If `cx.is_cancel_requested()`, the operation fails
///   immediately with `SessionError::Cancelled`.
///
/// - **Obligation tracking**: transport-backed sends and receives flow through
///   Asupersync's cancel-aware bounded `mpsc` channel, so cancellation and peer
///   closure preserve the existing obligation semantics of the underlying
///   channel primitives.
///
/// - **Budget consumption**: Each transition decrements the `Cx` poll budget.
///   If budget is exhausted, the operation yields rather than blocking.
///
/// ### Error Semantics
///
/// | Condition | Behavior |
/// |-----------|----------|
/// | Cancelled Cx | `SessionError::Cancelled` — permit aborted |
/// | Receiver dropped | `SessionError::Closed` — send returns error |
/// | Sender dropped | `SessionError::Closed` — recv returns None |
/// | Budget exhausted | Yield (cooperate with scheduler) |
/// | Protocol violation | Panic in debug, log + close in release |
/// | Drop mid-protocol | Drop-bomb panic (existing behavior) |
///
/// ### Scope Constraints
///
/// - **First supported bridge**: In-process `mpsc` only. Cross-process and
///   network transport are explicitly deferred to future work.
/// - **Serialization**: Not required for in-process bridge. The `mpsc` channel
///   moves `T` by value. Serde bounds are NOT added yet.
/// - **Backpressure**: Bounded by `mpsc` channel capacity (set at session
///   creation time).
///
/// ### Validation contract
///
/// The current truthfulness/rollout contract is backed by:
/// - compile-fail doctests in this module,
/// - transport-backed integration coverage in `tests/session_type_obligations.rs`,
/// - focused transport and cancellation regressions in this module's tests.
#[allow(dead_code)] // Contract type — used as documentation anchor
pub struct TransportBridgeContract;

// Note: The transport implementation uses `Box<dyn Any + Send>` with runtime
// downcasting rather than a typed `SessionMessage<T>` enum. This is because
// the payload type changes at each protocol step (e.g., `ReserveMsg` then `u64`
// then `AbortMsg`), so a single typed channel cannot carry all transitions.
// Branch selections (`Select`/`Offer`) send `Branch::Left`/`Branch::Right`
// values. The `close()` method does not send a transport message — it only
// disarms the drop bomb locally.

/// Errors from transport-backed session operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Error type for G2 implementation
pub enum SessionError {
    /// The Cx was cancelled before the operation completed.
    Cancelled,
    /// The peer endpoint was dropped (channel closed).
    Closed,
    /// Protocol violation: unexpected message type received.
    ProtocolViolation {
        /// What the protocol expected.
        expected: &'static str,
        /// What was actually received.
        actual: &'static str,
    },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "session cancelled"),
            Self::Closed => write!(f, "session peer closed"),
            Self::ProtocolViolation { expected, actual } => {
                write!(f, "protocol violation: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

const DOC_COMPILE_FAIL_SURFACE: &str = "compile-fail doctests: src/obligation/session_types.rs";
const MIGRATION_INTEGRATION_SURFACE: &str =
    "typed/dynamic migration surface: tests/session_type_obligations.rs";
const MIGRATION_GUIDE_SURFACE: &str = "migration guide: docs/integration.md";

// ============================================================================
// Adoption contract
// ============================================================================

/// Code-backed rollout contract for an opt-in session-typed protocol family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProtocolAdoptionSpec {
    /// Stable protocol identifier used in docs/tests/migration plans.
    pub protocol_id: &'static str,
    /// Typestate/session entrypoint that users opt into first.
    pub typed_entrypoint: &'static str,
    /// Existing dynamic/runtime-checked surface the typed API must coexist with.
    pub dynamic_surface: &'static str,
    /// Canonical protocol states in user-visible order.
    pub states: &'static [&'static str],
    /// Canonical state transitions that matter for migration review.
    pub transitions: &'static [&'static str],
    /// Compile-time guarantees expected from the typed encoding.
    pub compile_time_constraints: &'static [&'static str],
    /// Runtime oracles that still remain authoritative during rollout.
    pub runtime_oracles: &'static [&'static str],
    /// Existing and planned test surfaces for migration safety.
    pub migration_test_surfaces: &'static [&'static str],
    /// Stable diagnostics/log fields needed for debuggable adoption.
    pub diagnostics_fields: &'static [&'static str],
    /// Narrow surface that should adopt the typed API first.
    pub initial_rollout_scope: &'static str,
    /// Surfaces intentionally deferred until ergonomics and tooling improve.
    pub avoid_for_now: &'static [&'static str],
}

impl SessionProtocolAdoptionSpec {
    /// First adoption target: send-permit style two-phase delivery.
    pub const fn send_permit() -> Self {
        Self {
            protocol_id: "send_permit",
            typed_entrypoint: "asupersync::obligation::session_types::send_permit::new_session",
            dynamic_surface: "channel reserve/send-or-abort flows plus asupersync::obligation::ledger::ObligationLedger::{acquire, commit, abort}",
            states: &["Reserve", "Select<Send,Abort>", "End"],
            transitions: &[
                "send(ReserveMsg)",
                "select_left() + send(T)",
                "select_right() + send(AbortMsg)",
                "close()",
            ],
            compile_time_constraints: &[
                "payload send is impossible before Reserve",
                "exactly one terminal branch (Send or Abort) is consumed",
                "the endpoint is linearly moved on every transition",
                "delegation transfers ownership of the protocol endpoint instead of cloning it",
            ],
            runtime_oracles: &[
                "src/obligation/ledger.rs",
                "src/obligation/marking.rs",
                "src/obligation/no_leak_proof.rs",
                "src/obligation/separation_logic.rs",
            ],
            migration_test_surfaces: &[
                DOC_COMPILE_FAIL_SURFACE,
                MIGRATION_INTEGRATION_SURFACE,
                MIGRATION_GUIDE_SURFACE,
            ],
            diagnostics_fields: &[
                "channel_id",
                "from_state",
                "to_state",
                "trace_id",
                "obligation_kind",
                "protocol",
                "transition",
            ],
            initial_rollout_scope: "two-phase send/reserve paths that already resolve a SendPermit explicitly",
            avoid_for_now: &[
                "ambient channel wrappers that hide reserve/abort boundaries",
                "surfaces that depend on implicit Drop-based cleanup instead of explicit resolution",
            ],
        }
    }

    /// First adoption target for renewable lease-style resources.
    pub const fn lease() -> Self {
        Self {
            protocol_id: "lease",
            typed_entrypoint: "asupersync::obligation::session_types::lease::new_session",
            dynamic_surface: "lease-backed registry/resource flows such as asupersync::cx::NameLease plus ledger-backed Lease obligations",
            states: &["Acquire", "HolderLoop<Renew|Release>", "End"],
            transitions: &[
                "send(AcquireMsg)",
                "select_left() + send(RenewMsg)",
                "select_right() + send(ReleaseMsg)",
                "close()",
            ],
            compile_time_constraints: &[
                "Acquire must happen before Renew or Release",
                "Renew and Release are mutually exclusive per loop iteration",
                "Release is terminal and cannot be followed by another Renew",
                "delegated lease endpoints preserve a single holder at the type level",
            ],
            runtime_oracles: &[
                "src/cx/registry.rs",
                "src/obligation/ledger.rs",
                "src/obligation/marking.rs",
                "src/obligation/separation_logic.rs",
            ],
            migration_test_surfaces: &[
                DOC_COMPILE_FAIL_SURFACE,
                MIGRATION_INTEGRATION_SURFACE,
                MIGRATION_GUIDE_SURFACE,
            ],
            diagnostics_fields: &[
                "channel_id",
                "from_state",
                "to_state",
                "trace_id",
                "obligation_kind",
                "protocol",
                "transition",
            ],
            initial_rollout_scope: "lease-backed naming/resource lifecycles with a single obvious holder and explicit release path",
            avoid_for_now: &[
                "multi-party renewal protocols without a single delegation owner",
                "surfaces that currently encode renewal via ad hoc timers or hidden retries",
            ],
        }
    }

    /// First adoption target for reserve/commit two-phase effects.
    pub const fn two_phase() -> Self {
        Self {
            protocol_id: "two_phase",
            typed_entrypoint: "asupersync::obligation::session_types::two_phase::new_session",
            dynamic_surface: "two-phase reserve/commit-or-abort effects backed by asupersync::obligation::ledger::ObligationLedger::{acquire, commit, abort}",
            states: &["Reserve(K)", "Select<Commit,Abort>", "End"],
            transitions: &[
                "send(ReserveMsg)",
                "select_left() + send(CommitMsg)",
                "select_right() + send(AbortMsg)",
                "close()",
            ],
            compile_time_constraints: &[
                "Commit and Abort are mutually exclusive after Reserve",
                "kind-specific reserve state cannot be skipped",
                "terminal Commit or Abort consumes the endpoint",
                "delegation keeps the reserved effect linear across task handoff",
            ],
            runtime_oracles: &[
                "src/obligation/ledger.rs",
                "src/obligation/dialectica.rs",
                "src/obligation/no_aliasing_proof.rs",
                "src/obligation/separation_logic.rs",
            ],
            migration_test_surfaces: &[
                DOC_COMPILE_FAIL_SURFACE,
                MIGRATION_INTEGRATION_SURFACE,
                MIGRATION_GUIDE_SURFACE,
            ],
            diagnostics_fields: &[
                "channel_id",
                "from_state",
                "to_state",
                "trace_id",
                "obligation_kind",
                "protocol",
                "transition",
            ],
            initial_rollout_scope: "small reserve/commit APIs where the effect boundary is already explicit and the fallback remains the ledger",
            avoid_for_now: &[
                "open-ended effect pipelines that cross opaque adapter boundaries",
                "surfaces that require polymorphic branching beyond Commit or Abort in the first rollout",
            ],
        }
    }
}

/// Canonical adoption order for session-typed obligation protocols.
#[must_use]
pub fn session_protocol_adoption_specs() -> Vec<SessionProtocolAdoptionSpec> {
    vec![
        SessionProtocolAdoptionSpec::send_permit(),
        SessionProtocolAdoptionSpec::lease(),
        SessionProtocolAdoptionSpec::two_phase(),
    ]
}

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

    #[test]
    fn session_protocol_adoption_specs_cover_priority_families() {
        let specs = session_protocol_adoption_specs();
        let ids = specs
            .iter()
            .map(|spec| spec.protocol_id)
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["send_permit", "lease", "two_phase"]);
        assert!(
            specs.iter().all(|spec| !spec.typed_entrypoint.is_empty()),
            "typed entrypoints must be explicit"
        );
        assert!(
            specs.iter().all(|spec| !spec.dynamic_surface.is_empty()),
            "dynamic coexistence surfaces must be explicit"
        );
    }

    #[test]
    fn session_protocol_adoption_specs_document_oracles_and_migration_surfaces() {
        for spec in session_protocol_adoption_specs() {
            assert!(
                !spec.runtime_oracles.is_empty(),
                "runtime oracles must remain explicit for {}",
                spec.protocol_id
            );
            assert!(
                spec.runtime_oracles
                    .iter()
                    .all(|surface| surface.starts_with("src/")),
                "runtime oracles must point at concrete source files for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces.len() >= 2,
                "migration surfaces must include existing and planned coverage for {}",
                spec.protocol_id
            );
            assert!(
                !spec.initial_rollout_scope.is_empty(),
                "initial rollout scope must be documented for {}",
                spec.protocol_id
            );
            assert!(
                !spec.avoid_for_now.is_empty(),
                "deferred surfaces must be documented for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces
                    .iter()
                    .all(|surface| !surface.contains("planned")),
                "migration surfaces must point at concrete live paths for {}",
                spec.protocol_id
            );
        }
    }

    #[test]
    fn session_protocol_adoption_specs_keep_diagnostics_fields_stable() {
        for spec in session_protocol_adoption_specs() {
            assert!(
                spec.diagnostics_fields.contains(&"channel_id"),
                "channel_id must remain stable for {}",
                spec.protocol_id
            );
            assert!(
                spec.diagnostics_fields.contains(&"trace_id"),
                "trace_id must remain stable for {}",
                spec.protocol_id
            );
            assert!(
                spec.diagnostics_fields.contains(&"protocol"),
                "protocol field must remain stable for {}",
                spec.protocol_id
            );
            assert!(
                spec.compile_time_constraints.len() >= 3,
                "compile-time guarantees must stay substantive for {}",
                spec.protocol_id
            );
            assert!(
                spec.transitions.len() >= 3,
                "state transitions must stay explicit for {}",
                spec.protocol_id
            );
        }
    }

    #[test]
    fn session_protocol_adoption_specs_reference_current_validation_surfaces() {
        for spec in session_protocol_adoption_specs() {
            assert!(
                spec.migration_test_surfaces
                    .contains(&DOC_COMPILE_FAIL_SURFACE),
                "compile-fail doctest surface must stay wired for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces
                    .contains(&MIGRATION_INTEGRATION_SURFACE),
                "typed/dynamic migration surface must stay wired for {}",
                spec.protocol_id
            );
            assert!(
                spec.migration_test_surfaces
                    .contains(&MIGRATION_GUIDE_SURFACE),
                "migration guide surface must stay wired for {}",
                spec.protocol_id
            );
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
        _receiver.disarm_for_test();
    }

    // -- Drop bomb verification --

    #[test]
    #[should_panic(expected = "SESSION LEAKED")]
    fn drop_mid_protocol_panics() {
        let (sender, receiver) = send_permit::new_session::<u32>(99);

        // Disarm receiver first to avoid double-panic during unwinding.
        receiver.disarm_for_test();

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

        _receiver.disarm_for_test();
    }

    // -- Duality invariant --

    /// Invariant: `new_session` produces dual endpoints sharing the same
    /// channel_id and obligation_kind.
    #[test]
    fn send_permit_dual_channels_share_identity() {
        let (sender, receiver) = send_permit::new_session::<u32>(100);

        let ids_match = sender.channel_id() == receiver.channel_id();
        assert!(ids_match, "channel_id must match across endpoints");

        let kinds_match = sender.obligation_kind() == receiver.obligation_kind();
        assert!(kinds_match, "obligation_kind must match across endpoints");

        assert_eq!(sender.obligation_kind(), ObligationKind::SendPermit);

        // Drive both to End to avoid drop bombs.
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left();
        let sender = sender.send(42_u32);
        let _proof = sender.close();

        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(42_u32);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Left"),
        }
    }

    // -- Delegation invariant --

    /// Invariant: delegation channel pair preserves metadata and both
    /// endpoints share the same channel_id and obligation_kind.
    #[test]
    fn delegation_pair_preserves_metadata() {
        use delegation::new_delegation;

        let (delegator_ch, delegatee_ch) = new_delegation::<Initiator, two_phase::InitiatorSession>(
            201,
            ObligationKind::SendPermit,
        );

        assert_eq!(delegator_ch.channel_id(), 201);
        assert_eq!(delegator_ch.obligation_kind(), ObligationKind::SendPermit);
        assert_eq!(delegatee_ch.channel_id(), 201);
        assert_eq!(delegatee_ch.obligation_kind(), ObligationKind::SendPermit);

        // Disarm drop bombs — delegation is typestate-only encoding; the
        // actual Chan<R,S> value cannot pass through send() without triggering
        // the inner drop bomb, so we verify metadata and type-level correctness.
        delegator_ch.disarm_for_test();
        delegatee_ch.disarm_for_test();
    }

    // -- Multi-renew lease invariant --

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn branch_debug_copy_eq() {
        let left = Branch::Left;
        let right = Branch::Right;

        let dbg = format!("{left:?}");
        assert!(dbg.contains("Left"));

        // Copy
        let left2 = left;
        assert_eq!(left, left2);

        // Inequality
        assert_ne!(left, right);

        // Clone
        let right2 = right;
        assert_eq!(right, right2);
    }

    #[test]
    fn session_proof_debug() {
        let proof = SessionProof {
            channel_id: 42,
            obligation_kind: ObligationKind::SendPermit,
        };
        let dbg = format!("{proof:?}");
        assert!(dbg.contains("42"));
        assert!(dbg.contains("SendPermit"));
    }

    #[test]
    fn two_phase_reserve_msg_debug_clone() {
        let msg = two_phase::ReserveMsg {
            kind: ObligationKind::Lease,
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Lease"));

        let cloned = msg;
        assert_eq!(cloned.kind, ObligationKind::Lease);
    }

    #[test]
    fn two_phase_abort_msg_debug_clone() {
        let msg = two_phase::AbortMsg {
            reason: "budget_exhausted".to_string(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("budget_exhausted"));

        let cloned = msg;
        assert_eq!(cloned.reason, "budget_exhausted");
    }

    #[test]
    fn selected_left_variant() {
        let s: Selected<u32, &str> = Selected::Left(42);
        match s {
            Selected::Left(v) => assert_eq!(v, 42),
            Selected::Right(_) => panic!("expected Left"),
        }
    }

    #[test]
    fn selected_right_variant() {
        let s: Selected<u32, &str> = Selected::Right("hello");
        match s {
            Selected::Right(v) => assert_eq!(v, "hello"),
            Selected::Left(_) => panic!("expected Right"),
        }
    }

    #[test]
    fn chan_accessors() {
        let (sender, receiver) = send_permit::new_session::<u32>(55);
        assert_eq!(sender.channel_id(), 55);
        assert_eq!(sender.obligation_kind(), ObligationKind::SendPermit);
        assert_eq!(receiver.channel_id(), 55);
        assert_eq!(receiver.obligation_kind(), ObligationKind::SendPermit);

        // Drive both to End
        let sender = sender.send(send_permit::ReserveMsg);
        let sender = sender.select_left();
        let sender = sender.send(0_u32);
        let _ = sender.close();
        let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
        match receiver.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(0_u32);
                let _ = ch.close();
            }
            Selected::Right(_) => panic!("expected Left"),
        }
    }

    #[test]
    fn lease_new_session_obligation_kind() {
        let (holder, resource) = lease::new_session(99);
        assert_eq!(holder.obligation_kind(), ObligationKind::Lease);
        assert_eq!(resource.obligation_kind(), ObligationKind::Lease);

        // Drive to End
        let holder = holder.send(lease::AcquireMsg);
        let holder = holder.select_right();
        let holder = holder.send(lease::ReleaseMsg);
        let _ = holder.close();

        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _ = ch.close();
            }
            Selected::Left(_) => panic!("expected Right"),
        }
    }

    /// Invariant: lease protocol supports multiple renew cycles before release,
    /// each creating a fresh loop iteration.
    #[test]
    fn lease_multiple_renew_cycles() {
        let (holder, resource) = lease::new_session(300);

        // Holder: Acquire.
        let holder = holder.send(lease::AcquireMsg);

        // First loop: choose Renew.
        let holder = holder.select_left();
        let holder = holder.send(lease::RenewMsg);
        let _proof1 = holder.close();

        // Resource side first loop.
        let (_, resource) = resource.recv(lease::AcquireMsg);
        match resource.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(lease::RenewMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Renew"),
        }

        // Second loop iteration.
        let (holder2, resource2) = lease::renew_loop(300);
        let holder2 = holder2.select_left(); // Renew again
        let holder2 = holder2.send(lease::RenewMsg);
        let _proof2 = holder2.close();

        match resource2.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(lease::RenewMsg);
                let _proof = ch.close();
            }
            Selected::Right(_) => panic!("expected Renew 2"),
        }

        // Third loop: finally Release.
        let (holder3, resource3) = lease::renew_loop(300);
        let holder3 = holder3.select_right(); // Release
        let holder3 = holder3.send(lease::ReleaseMsg);
        let proof = holder3.close();
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);

        match resource3.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                let _proof = ch.close();
            }
            Selected::Left(_) => panic!("expected Release"),
        }
    }

    // =================================================================
    // Transport-backed session tests (G2 — bead v2ofj7.7.2)
    // =================================================================

    #[test]
    fn transport_backed_send_permit_happy_path() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(100, ObligationKind::SendPermit, 4);

        assert!(sender.is_transport_backed());
        assert!(receiver.is_transport_backed());

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            // Initiator: Send ReserveMsg
            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();

            // Responder: Recv ReserveMsg
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            // Initiator: Select Send branch (left)
            let sender = sender.select_left_async(&cx).await.unwrap();

            // Responder: Offer and receive branch choice
            let receiver = match receiver.offer_async(&cx).await.unwrap() {
                Selected::Left(ch) => ch,
                Selected::Right(_) => panic!("expected Left (Send) branch"),
            };

            // Initiator: Send the payload
            let sender = sender.send_async(&cx, 42_u64).await.unwrap();

            // Responder: Recv the payload
            let (value, receiver) = receiver.recv_async(&cx).await.unwrap();
            assert_eq!(value, 42_u64);

            // Both sides close
            let proof_s = sender.close();
            let proof_r = receiver.close();
            assert_eq!(proof_s.channel_id, 100);
            assert_eq!(proof_r.channel_id, 100);
            assert_eq!(proof_s.obligation_kind, ObligationKind::SendPermit);
        });
    }

    #[test]
    fn transport_backed_send_permit_abort_path() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(200, ObligationKind::SendPermit, 4);

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            // Initiator: Select Abort branch (right)
            let sender = sender.select_right_async(&cx).await.unwrap();

            let receiver = match receiver.offer_async(&cx).await.unwrap() {
                Selected::Right(ch) => ch,
                Selected::Left(_) => panic!("expected Right (Abort) branch"),
            };

            let sender = sender.send_async(&cx, send_permit::AbortMsg).await.unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            let proof_s = sender.close();
            let proof_r = receiver.close();
            assert_eq!(proof_s.obligation_kind, ObligationKind::SendPermit);
            assert_eq!(proof_r.obligation_kind, ObligationKind::SendPermit);
        });
    }

    #[test]
    fn transport_backed_peer_drop_returns_closed() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(300, ObligationKind::SendPermit, 4);

        // Drop the receiver immediately
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let result = sender.send_async(&cx, send_permit::ReserveMsg).await;
            match result {
                Err(SessionError::Closed) => {} // expected
                Err(other) => panic!("expected Closed, got {other}"),
                Ok(ch) => {
                    ch.disarm_for_test();
                    panic!("expected error, got Ok");
                }
            }
        });
    }

    #[test]
    fn transport_backed_send_async_cancelled_cx_returns_cancelled() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(301, ObligationKind::SendPermit, 4);
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed send cancelled",
            ));

            let result = sender.send_async(&cx, send_permit::ReserveMsg).await;
            assert!(matches!(result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_send_async_unpolled_future_drop_does_not_panic() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(3011, ObligationKind::SendPermit, 4);
        let cx = Cx::for_testing();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let future = sender.send_async(&cx, send_permit::ReserveMsg);
            drop(future);
        }));

        receiver.disarm_for_test();
        assert!(
            result.is_ok(),
            "dropping an unpolled send_async future must not trip the session leak drop bomb"
        );
    }

    #[test]
    fn transport_backed_recv_async_cancelled_cx_returns_cancelled() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(302, ObligationKind::SendPermit, 4);
        sender.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed recv cancelled",
            ));

            let result = receiver.recv_async(&cx).await;
            assert!(matches!(result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_recv_async_unpolled_future_drop_does_not_panic() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(3021, ObligationKind::SendPermit, 4);
        let cx = Cx::for_testing();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let future = receiver.recv_async(&cx);
            drop(future);
        }));

        sender.disarm_for_test();
        assert!(
            result.is_ok(),
            "dropping an unpolled recv_async future must not trip the session leak drop bomb"
        );
    }

    #[test]
    fn transport_backed_select_async_cancelled_cx_returns_cancelled() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let cancelled_cx = Cx::for_testing();
            cancelled_cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed select cancelled",
            ));

            let (sender_left, receiver_left) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(303, ObligationKind::SendPermit, 4);
            let sender_left = sender_left
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_left) = receiver_left.recv_async(&cx).await.unwrap();
            let left_result = sender_left.select_left_async(&cancelled_cx).await;
            receiver_left.disarm_for_test();
            assert!(matches!(left_result, Err(SessionError::Cancelled)));

            let (sender_right, receiver_right) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(304, ObligationKind::SendPermit, 4);
            let sender_right = sender_right
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_right) = receiver_right.recv_async(&cx).await.unwrap();
            let right_result = sender_right.select_right_async(&cancelled_cx).await;
            receiver_right.disarm_for_test();
            assert!(matches!(right_result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_select_async_unpolled_future_drop_does_not_panic() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            let (sender_left, receiver_left) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(3031, ObligationKind::SendPermit, 4);
            let sender_left = sender_left
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_left) = receiver_left.recv_async(&cx).await.unwrap();

            let left_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let future = sender_left.select_left_async(&cx);
                drop(future);
            }));
            receiver_left.disarm_for_test();
            assert!(
                left_result.is_ok(),
                "dropping an unpolled select_left_async future must not panic"
            );

            let (sender_right, receiver_right) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(3032, ObligationKind::SendPermit, 4);
            let sender_right = sender_right
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_right) = receiver_right.recv_async(&cx).await.unwrap();

            let right_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let future = sender_right.select_right_async(&cx);
                drop(future);
            }));
            receiver_right.disarm_for_test();
            assert!(
                right_result.is_ok(),
                "dropping an unpolled select_right_async future must not panic"
            );
        });
    }

    #[test]
    fn transport_backed_offer_async_cancelled_cx_returns_cancelled() {
        let (sender, receiver) = new_transport_pair::<
            send_permit::InitiatorSession<u64>,
            send_permit::ResponderSession<u64>,
        >(305, ObligationKind::SendPermit, 4);

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();
            sender.disarm_for_test();

            let cancelled_cx = Cx::for_testing();
            cancelled_cx.set_cancel_reason(crate::types::CancelReason::user(
                "transport-backed offer cancelled",
            ));

            let result = receiver.offer_async(&cancelled_cx).await;
            assert!(matches!(result, Err(SessionError::Cancelled)));
        });
    }

    #[test]
    fn transport_backed_offer_async_unpolled_future_drop_does_not_panic() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let (sender, receiver) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(3051, ObligationKind::SendPermit, 4);

            let sender = sender
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver) = receiver.recv_async(&cx).await.unwrap();

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let future = receiver.offer_async(&cx);
                drop(future);
            }));

            sender.disarm_for_test();
            assert!(
                result.is_ok(),
                "dropping an unpolled offer_async future must not trip the session leak drop bomb"
            );
        });
    }

    #[test]
    fn transport_backed_recv_offer_and_select_peer_drop_return_closed() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();

            let (sender_recv, receiver_recv) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(306, ObligationKind::SendPermit, 4);
            sender_recv.disarm_for_test();
            let recv_result = receiver_recv.recv_async(&cx).await;
            assert!(matches!(recv_result, Err(SessionError::Closed)));

            let (sender_offer, receiver_offer) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(307, ObligationKind::SendPermit, 4);
            let sender_offer = sender_offer
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_offer) = receiver_offer.recv_async(&cx).await.unwrap();
            sender_offer.disarm_for_test();
            let offer_result = receiver_offer.offer_async(&cx).await;
            assert!(matches!(offer_result, Err(SessionError::Closed)));

            let (sender_select, receiver_select) = new_transport_pair::<
                send_permit::InitiatorSession<u64>,
                send_permit::ResponderSession<u64>,
            >(308, ObligationKind::SendPermit, 4);
            let sender_select = sender_select
                .send_async(&cx, send_permit::ReserveMsg)
                .await
                .unwrap();
            let (_, receiver_select) = receiver_select.recv_async(&cx).await.unwrap();
            receiver_select.disarm_for_test();
            let select_result = sender_select.select_left_async(&cx).await;
            assert!(matches!(select_result, Err(SessionError::Closed)));
        });
    }

    #[test]
    #[should_panic(expected = "select_left_async called on non-transport-backed session channel")]
    fn select_left_async_panics_without_transport_backing() {
        let (sender, receiver) = send_permit::new_session::<u64>(309);
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let sender = sender.send(send_permit::ReserveMsg);
            let _ = sender.select_left_async(&cx).await;
        });
    }

    #[test]
    #[should_panic(expected = "select_right_async called on non-transport-backed session channel")]
    fn select_right_async_panics_without_transport_backing() {
        let (sender, receiver) = send_permit::new_session::<u64>(310);
        receiver.disarm_for_test();

        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let sender = sender.send(send_permit::ReserveMsg);
            let _ = sender.select_right_async(&cx).await;
        });
    }

    #[test]
    fn transport_backed_is_transport_backed_flag() {
        let (pure_s, pure_r) = send_permit::new_session::<u32>(1);
        assert!(!pure_s.is_transport_backed());
        assert!(!pure_r.is_transport_backed());
        pure_s.disarm_for_test();
        pure_r.disarm_for_test();

        let (trans_s, trans_r) = new_transport_pair::<
            send_permit::InitiatorSession<u32>,
            send_permit::ResponderSession<u32>,
        >(2, ObligationKind::SendPermit, 4);
        assert!(trans_s.is_transport_backed());
        assert!(trans_r.is_transport_backed());
        trans_s.disarm_for_test();
        trans_r.disarm_for_test();
    }

    #[test]
    fn session_error_display() {
        assert_eq!(SessionError::Cancelled.to_string(), "session cancelled");
        assert_eq!(SessionError::Closed.to_string(), "session peer closed");
        assert_eq!(
            SessionError::ProtocolViolation {
                expected: "u64",
                actual: "String"
            }
            .to_string(),
            "protocol violation: expected u64, got String"
        );
    }
}
