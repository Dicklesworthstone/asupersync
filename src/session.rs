//! Session types for protocol-safe communication.
//!
//! Session types encode communication protocols at the type level, ensuring
//! protocol compliance at compile time. This module provides:
//!
//! - **Core protocol building blocks**: `Send`, `Recv`, `Choose`, `Offer`, `End`
//! - **Duality**: Every session type has a dual — if one endpoint sends, the other receives
//! - **Typed endpoints**: Communication channels that advance through protocol states
//!
//! # Protocol Example
//!
//! A simple request-response protocol:
//!
//! ```no_run
//! use asupersync::session::{Dual, End, Recv, Send};
//! # struct Request;
//! # struct Response;
//!
//! // Client side: send a request, receive a response
//! type ClientProtocol = Send<Request, Recv<Response, End>>;
//!
//! // Server side is the dual: receive a request, send a response
//! type ServerProtocol = Dual<ClientProtocol>;
//! // = Recv<Request, Send<Response, End>>
//! ```
//!
//! # Design
//!
//! Session types are zero-sized marker types that exist only at compile time.
//! They encode the protocol as a type-level state machine. Each communication
//! operation consumes the current endpoint and returns one at the next state,
//! ensuring protocol steps are followed in order and exactly once (affine use).
//!
//! # Compile-Time Protocol Compliance
//!
//! Protocol violations are type errors. The following shows correct usage:
//!
//! ```rust
//! use asupersync::session::{Send, Recv, End, Session, Dual};
//!
//! // Dual of Send<T, End> is Recv<T, End>
//! fn _check_duality() {
//!     fn _assert_same<A, B>() where A: Session<Dual = B>, B: Session<Dual = A> {}
//!     _assert_same::<Send<u32, End>, Recv<u32, End>>();
//! }
//! ```
//!
//! Attempting to call `send` on a `Recv` endpoint is a type error:
//!
//! ```compile_fail
//! use asupersync::session::{Recv, End, channel};
//!
//! // ERROR: Endpoint<Recv<u32, End>> does not have a send() method
//! async fn wrong_direction() {
//!     let cx = asupersync::cx::Cx::for_testing();
//!     type P = Recv<u32, End>;
//!     let (ep, _peer) = channel::<P>();
//!     ep.send(&cx, 42).await.unwrap();
//! }
//! ```
//!
//! Attempting to close an endpoint before the protocol completes is a type error:
//!
//! ```compile_fail
//! use asupersync::session::{Send, End, channel};
//!
//! // ERROR: Endpoint<Send<u32, End>> does not have close()
//! fn premature_close() {
//!     type P = Send<u32, End>;
//!     let (ep, _peer) = channel::<P>();
//!     ep.close(); // Only Endpoint<End> has close()
//! }
//! ```
//!
//! Calling `recv` on a `Send` endpoint is a type error:
//!
//! ```compile_fail
//! use asupersync::session::{Send, End, channel};
//!
//! // ERROR: Endpoint<Send<u32, End>> does not have recv()
//! async fn recv_on_send() {
//!     let cx = asupersync::cx::Cx::for_testing();
//!     type P = Send<u32, End>;
//!     let (ep, _peer) = channel::<P>();
//!     ep.recv(&cx).await.unwrap();
//! }
//! ```
//!
//! # Obligation Protocol Facade
//!
//! The [`obligation`] submodule is the public facade for the obligation-backed
//! typestate protocols shipped in [`crate::obligation::session_types`]. Keep
//! the two surfaces distinct:
//!
//! | Use this surface | When |
//! | --- | --- |
//! | [`channel`] plus [`Endpoint`] | You need a general binary session channel for an application protocol. |
//! | [`obligation::send_permit`] | You are proving the two-phase reserve/send-or-abort protocol. |
//! | [`obligation::lease`] | You are proving acquire/renew/release resource ownership. |
//! | [`obligation::two_phase`] | You are proving reserve/commit-or-abort effects. |
//! | [`crate::obligation::choreography`] | You need a global choreography DSL; code generation remains an obligation-module surface. |
//!
//! The obligation facade is not exported through a prelude. Session protocols
//! encode linear state transitions, so callers should import the exact protocol
//! they are driving.
//!
//! The API surface map already records the root [`crate::session`] module as the
//! public entry point; these protocol modules are nested under that entry.
//!
//! Choreography disposition: [`crate::obligation::choreography`] remains an
//! experimental obligation-module surface. The global-protocol builder is useful
//! for documenting and validating choreographies, but the projection/codegen
//! path is still separate from this facade, so it is intentionally not re-exported
//! as `session::obligation::*`.
//!
//! Negative-space compile-fail examples live alongside the implementation in
//! [`crate::obligation::session_types`]. They prove that out-of-order sends,
//! premature closes, and late aborts fail at compile time.
//!
//! SendPermit commit path:
//!
//! ```
//! use asupersync::session::obligation::{Branch, Selected, send_permit};
//!
//! let (sender, receiver) = send_permit::new_session::<u64>(100);
//!
//! let sender = sender.send(send_permit::ReserveMsg);
//! let sender = sender.select_left();
//! let sender = sender.send(42);
//! let sender_proof = sender.close();
//!
//! let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
//! let receiver_proof = match receiver.offer(Branch::Left) {
//!     Selected::Left(channel) => {
//!         let (value, channel) = channel.recv(42);
//!         assert_eq!(value, 42);
//!         channel.close()
//!     }
//!     Selected::Right(_) => panic!("expected send branch"),
//! };
//!
//! assert_eq!(sender_proof.channel_id, receiver_proof.channel_id);
//! ```
//!
//! Lease release path:
//!
//! ```
//! use asupersync::session::obligation::{Branch, Selected, lease};
//!
//! let (holder, resource) = lease::new_session(200);
//!
//! let holder = holder.send(lease::AcquireMsg);
//! let holder = holder.select_right();
//! let holder = holder.send(lease::ReleaseMsg);
//! let holder_proof = holder.close();
//!
//! let (_, resource) = resource.recv(lease::AcquireMsg);
//! let resource_proof = match resource.offer(Branch::Right) {
//!     Selected::Right(channel) => {
//!         let (_, channel) = channel.recv(lease::ReleaseMsg);
//!         channel.close()
//!     }
//!     Selected::Left(_) => panic!("expected release branch"),
//! };
//!
//! assert_eq!(holder_proof.channel_id, resource_proof.channel_id);
//! ```
//!
//! Two-phase commit path:
//!
//! ```
//! use asupersync::record::ObligationKind;
//! use asupersync::session::obligation::{Branch, Selected, two_phase};
//!
//! let kind = ObligationKind::IoOp;
//! let (initiator, executor) = two_phase::new_session(300, kind);
//! let reserve = two_phase::ReserveMsg { kind };
//!
//! let initiator = initiator.send(reserve.clone());
//! let initiator = initiator.select_left();
//! let initiator = initiator.send(two_phase::CommitMsg);
//! let initiator_proof = initiator.close();
//!
//! let (received, executor) = executor.recv(reserve);
//! assert_eq!(received.kind, kind);
//! let executor_proof = match executor.offer(Branch::Left) {
//!     Selected::Left(channel) => {
//!         let (_, channel) = channel.recv(two_phase::CommitMsg);
//!         channel.close()
//!     }
//!     Selected::Right(_) => panic!("expected commit branch"),
//! };
//!
//! assert_eq!(initiator_proof.obligation_kind, executor_proof.obligation_kind);
//! ```

use crate::types::outcome::Outcome;
use std::marker::PhantomData;

/// Public facade for obligation-backed session protocols.
///
/// This module re-exports the shipped obligation typestate protocols from
/// [`crate::obligation::session_types`] under `asupersync::session` so users can
/// discover the general binary session API and the obligation-specific
/// protocols from one public module.
pub mod obligation {
    pub use crate::obligation::session_types::{
        Branch, Chan, End, Initiator, Offer, Rec, Recv, Responder, Select, Selected, Send,
        SessionError, SessionProof, SessionProtocolAdoptionSpec, TracingContract,
        TransportBridgeContract, Var, delegation, lease, new_transport_pair, send_permit,
        session_protocol_adoption_specs, silent_session_consume_count, two_phase,
    };
}

// ---------- Core session type building blocks ----------

/// A protocol step that sends a value of type `T`, then continues with `Next`.
pub struct Send<T, Next: Session> {
    _phantom: PhantomData<(T, Next)>,
}

/// A protocol step that receives a value of type `T`, then continues with `Next`.
pub struct Recv<T, Next: Session> {
    _phantom: PhantomData<(T, Next)>,
}

/// A protocol step where this endpoint chooses between two continuations.
///
/// The peer must offer both branches (see [`Offer`]).
pub struct Choose<A: Session, B: Session> {
    _phantom: PhantomData<(A, B)>,
}

/// A protocol step where this endpoint offers two continuations for the peer to choose.
///
/// The peer selects a branch (see [`Choose`]).
pub struct Offer<A: Session, B: Session> {
    _phantom: PhantomData<(A, B)>,
}

/// Protocol termination — no further communication.
pub struct End;

// ---------- Session trait ----------

/// Marker trait for valid session types.
///
/// Every session type has a `Dual` — the complementary protocol that the
/// other endpoint must follow. Duality is involutive: `Dual<Dual<S>> = S`.
pub trait Session: std::marker::Send + 'static {
    /// The dual (complementary) session type.
    ///
    /// Duality swaps Send↔Recv and Choose↔Offer, recursing into continuations.
    type Dual: Session<Dual = Self>;
}

// ---------- Session implementations ----------

impl Session for End {
    type Dual = Self;
}

impl<T: std::marker::Send + 'static, Next: Session> Session for self::Send<T, Next> {
    type Dual = Recv<T, Next::Dual>;
}

impl<T: std::marker::Send + 'static, Next: Session> Session for Recv<T, Next> {
    type Dual = self::Send<T, Next::Dual>;
}

impl<A: Session, B: Session> Session for Choose<A, B> {
    type Dual = Offer<A::Dual, B::Dual>;
}

impl<A: Session, B: Session> Session for Offer<A, B> {
    type Dual = Choose<A::Dual, B::Dual>;
}

// ---------- Dual type alias ----------

/// Computes the dual of a session type.
///
/// This is a convenience alias for `<S as Session>::Dual`.
///
/// # Examples
///
/// ```no_run
/// use asupersync::session::{Dual, End, Recv, Send};
/// # struct Request;
/// # struct Response;
///
/// type Client = Send<Request, Recv<Response, End>>;
/// type Server = Dual<Client>;
/// // Server = Recv<Request, Send<Response, End>>
/// ```
pub type Dual<S> = <S as Session>::Dual;

// ---------- Typed endpoints ----------

/// A typed endpoint at session state `S`.
///
/// Endpoints are affine: each operation consumes the endpoint and returns
/// a new one at the next protocol state. Dropping an endpoint before `End`
/// is a type error enforced by the protocol structure.
///
/// The underlying transport uses the crate's two-phase MPSC channels with
/// `Box<dyn Any>` type erasure. Each protocol step sends/receives one value.
pub struct Endpoint<S: Session> {
    _session: PhantomData<S>,
    /// Channel for sending data to the peer.
    tx: crate::channel::mpsc::Sender<Box<dyn std::any::Any + std::marker::Send>>,
    /// Channel for receiving data from the peer.
    rx: crate::channel::mpsc::Receiver<Box<dyn std::any::Any + std::marker::Send>>,
}

/// Error returned when a session operation fails.
#[derive(Debug)]
pub enum SessionError {
    /// The peer disconnected before the protocol completed.
    Disconnected,
    /// The received value did not match the expected type.
    TypeMismatch,
    /// The operation was cancelled.
    Cancelled,
}

/// Creates a pair of dual session-typed endpoints.
///
/// Returns `(Endpoint<S>, Endpoint<Dual<S>>)` — the two sides of the protocol.
/// The underlying channels have capacity 1 (session types are synchronous).
///
/// # Example
///
/// ```no_run
/// use asupersync::session::{self, End, Send};
///
/// type Client = Send<String, End>;
/// let (client, server) = session::channel::<Client>();
/// // client: Endpoint<Send<String, End>>
/// // server: Endpoint<Recv<String, End>>
/// ```
#[must_use]
pub fn channel<S: Session>() -> (Endpoint<S>, Endpoint<Dual<S>>) {
    let (tx1, rx1) = crate::channel::mpsc::channel(1);
    let (tx2, rx2) = crate::channel::mpsc::channel(1);

    let ep1 = Endpoint {
        _session: PhantomData,
        tx: tx1,
        rx: rx2,
    };
    let ep2 = Endpoint {
        _session: PhantomData,
        tx: tx2,
        rx: rx1,
    };

    (ep1, ep2)
}

fn map_send_error<T>(error: &crate::channel::mpsc::SendError<T>) -> SessionError {
    match error {
        crate::channel::mpsc::SendError::Disconnected(_) => SessionError::Disconnected,
        crate::channel::mpsc::SendError::Cancelled(_) => SessionError::Cancelled,
        crate::channel::mpsc::SendError::Full(_) => {
            debug_assert!(
                false,
                "async session send unexpectedly returned SendError::Full"
            );
            SessionError::Disconnected
        }
    }
}

impl<T, Next> Endpoint<self::Send<T, Next>>
where
    T: std::marker::Send + 'static,
    Next: Session,
{
    /// Send a value to the peer, advancing the protocol to the next state.
    ///
    /// Consumes this endpoint and returns a new one at state `Next`.
    /// Uses the crate's two-phase send (reserve/commit) for cancel-safety.
    pub async fn send(self, cx: &crate::cx::Cx, value: T) -> Outcome<Endpoint<Next>, SessionError> {
        let Self { tx, rx, .. } = self;
        let boxed: Box<dyn std::any::Any + std::marker::Send> = Box::new(value);
        if let Err(error) = tx.send(cx, boxed).await {
            return Outcome::Err(map_send_error(&error));
        }
        Outcome::Ok(Endpoint {
            _session: PhantomData,
            tx,
            rx,
        })
    }
}

impl<T, Next> Endpoint<Recv<T, Next>>
where
    T: std::marker::Send + 'static,
    Next: Session,
{
    /// Receive a value from the peer, advancing the protocol to the next state.
    ///
    /// Consumes this endpoint and returns the value plus a new endpoint at state `Next`.
    pub async fn recv(self, cx: &crate::cx::Cx) -> Outcome<(T, Endpoint<Next>), SessionError> {
        let Self { tx, mut rx, .. } = self;
        let boxed = match rx.recv(cx).await {
            Ok(b) => b,
            Err(e) => {
                return Outcome::Err(match e {
                    crate::channel::mpsc::RecvError::Cancelled => SessionError::Cancelled,
                    crate::channel::mpsc::RecvError::Disconnected
                    | crate::channel::mpsc::RecvError::Empty => SessionError::Disconnected,
                });
            }
        };
        let value = match boxed.downcast::<T>() {
            Ok(v) => v,
            Err(_) => return Outcome::Err(SessionError::TypeMismatch),
        };
        Outcome::Ok((
            *value,
            Endpoint {
                _session: PhantomData,
                tx,
                rx,
            },
        ))
    }
}

impl<A: Session, B: Session> Endpoint<Choose<A, B>> {
    /// Choose the left branch of the protocol.
    ///
    /// Sends the choice to the peer and returns an endpoint at state `A`.
    pub async fn choose_left(self, cx: &crate::cx::Cx) -> Outcome<Endpoint<A>, SessionError> {
        let Self { tx, rx, .. } = self;
        let boxed: Box<dyn std::any::Any + std::marker::Send> = Box::new(Branch::Left);
        if let Err(error) = tx.send(cx, boxed).await {
            return Outcome::Err(map_send_error(&error));
        }
        Outcome::Ok(Endpoint {
            _session: PhantomData,
            tx,
            rx,
        })
    }

    /// Choose the right branch of the protocol.
    ///
    /// Sends the choice to the peer and returns an endpoint at state `B`.
    pub async fn choose_right(self, cx: &crate::cx::Cx) -> Outcome<Endpoint<B>, SessionError> {
        let Self { tx, rx, .. } = self;
        let boxed: Box<dyn std::any::Any + std::marker::Send> = Box::new(Branch::Right);
        if let Err(error) = tx.send(cx, boxed).await {
            return Outcome::Err(map_send_error(&error));
        }
        Outcome::Ok(Endpoint {
            _session: PhantomData,
            tx,
            rx,
        })
    }
}

/// Result of an offer operation — the peer's chosen branch.
pub enum Offered<A: Session, B: Session> {
    /// Peer chose the left branch.
    Left(Endpoint<A>),
    /// Peer chose the right branch.
    Right(Endpoint<B>),
}

impl<A: Session, B: Session> Endpoint<Offer<A, B>> {
    /// Wait for the peer to choose a branch.
    ///
    /// Returns the chosen branch as an `Offered` enum.
    pub async fn offer(self, cx: &crate::cx::Cx) -> Outcome<Offered<A, B>, SessionError> {
        let Self { tx, mut rx, .. } = self;
        let boxed = match rx.recv(cx).await {
            Ok(b) => b,
            Err(e) => {
                return Outcome::Err(match e {
                    crate::channel::mpsc::RecvError::Cancelled => SessionError::Cancelled,
                    crate::channel::mpsc::RecvError::Disconnected
                    | crate::channel::mpsc::RecvError::Empty => SessionError::Disconnected,
                });
            }
        };
        let branch = match boxed.downcast::<Branch>() {
            Ok(b) => b,
            Err(_) => return Outcome::Err(SessionError::TypeMismatch),
        };
        match *branch {
            Branch::Left => Outcome::Ok(Offered::Left(Endpoint {
                _session: PhantomData,
                tx,
                rx,
            })),
            Branch::Right => Outcome::Ok(Offered::Right(Endpoint {
                _session: PhantomData,
                tx,
                rx,
            })),
        }
    }
}

impl Endpoint<End> {
    /// Close a completed protocol endpoint.
    ///
    /// This is the only way to properly terminate a session. Consuming the
    /// endpoint at the `End` state prevents protocol steps from being skipped.
    pub fn close(self) {
        // Endpoint is consumed; channels are dropped.
    }
}

// ---------- Choice direction ----------

/// Direction chosen by `Choose` — left or right branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// Select the left/first branch.
    Left,
    /// Select the right/second branch.
    Right,
}

// ---------- Tests ----------

#[cfg(test)]
#[path = "session_inline_tests.rs"]
mod tests;
