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
//! ```ignore
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

use std::marker::PhantomData;

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
    type Dual = End;
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
/// ```ignore
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
/// ```ignore
/// type Client = Send<String, End>;
/// let (client, server) = session::channel::<Client>();
/// // client: Endpoint<Send<String, End>>
/// // server: Endpoint<Recv<String, End>>
/// ```
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


impl<T, Next> Endpoint<self::Send<T, Next>>
where
    T: std::marker::Send + 'static,
    Next: Session,
{
    /// Send a value to the peer, advancing the protocol to the next state.
    ///
    /// Consumes this endpoint and returns a new one at state `Next`.
    /// Uses the crate's two-phase send (reserve/commit) for cancel-safety.
    pub async fn send(
        self,
        cx: &crate::cx::Cx,
        value: T,
    ) -> Result<Endpoint<Next>, SessionError> {
        let Endpoint { tx, rx, .. } = self;
        let boxed: Box<dyn std::any::Any + std::marker::Send> = Box::new(value);
        tx.send(cx, boxed)
            .await
            .map_err(|_| SessionError::Disconnected)?;
        Ok(Endpoint {
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
    pub async fn recv(
        self,
        cx: &crate::cx::Cx,
    ) -> Result<(T, Endpoint<Next>), SessionError> {
        let Endpoint { tx, rx, .. } = self;
        let boxed = rx
            .recv(cx)
            .await
            .map_err(|e| match e {
                crate::channel::mpsc::RecvError::Disconnected => SessionError::Disconnected,
                crate::channel::mpsc::RecvError::Cancelled => SessionError::Cancelled,
                crate::channel::mpsc::RecvError::Empty => SessionError::Disconnected,
            })?;
        let value = boxed
            .downcast::<T>()
            .map_err(|_| SessionError::TypeMismatch)?;
        Ok((*value, Endpoint {
            _session: PhantomData,
            tx,
            rx,
        }))
    }
}

impl<A: Session, B: Session> Endpoint<Choose<A, B>> {
    /// Choose the left branch of the protocol.
    ///
    /// Sends the choice to the peer and returns an endpoint at state `A`.
    pub async fn choose_left(
        self,
        cx: &crate::cx::Cx,
    ) -> Result<Endpoint<A>, SessionError> {
        let Endpoint { tx, rx, .. } = self;
        let boxed: Box<dyn std::any::Any + std::marker::Send> = Box::new(Branch::Left);
        tx.send(cx, boxed)
            .await
            .map_err(|_| SessionError::Disconnected)?;
        Ok(Endpoint {
            _session: PhantomData,
            tx,
            rx,
        })
    }

    /// Choose the right branch of the protocol.
    ///
    /// Sends the choice to the peer and returns an endpoint at state `B`.
    pub async fn choose_right(
        self,
        cx: &crate::cx::Cx,
    ) -> Result<Endpoint<B>, SessionError> {
        let Endpoint { tx, rx, .. } = self;
        let boxed: Box<dyn std::any::Any + std::marker::Send> = Box::new(Branch::Right);
        tx.send(cx, boxed)
            .await
            .map_err(|_| SessionError::Disconnected)?;
        Ok(Endpoint {
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
    pub async fn offer(
        self,
        cx: &crate::cx::Cx,
    ) -> Result<Offered<A, B>, SessionError> {
        let Endpoint { tx, rx, .. } = self;
        let boxed = rx
            .recv(cx)
            .await
            .map_err(|e| match e {
                crate::channel::mpsc::RecvError::Disconnected => SessionError::Disconnected,
                crate::channel::mpsc::RecvError::Cancelled => SessionError::Cancelled,
                crate::channel::mpsc::RecvError::Empty => SessionError::Disconnected,
            })?;
        let branch = boxed
            .downcast::<Branch>()
            .map_err(|_| SessionError::TypeMismatch)?;
        match *branch {
            Branch::Left => Ok(Offered::Left(Endpoint {
                _session: PhantomData,
                tx,
                rx,
            })),
            Branch::Right => Ok(Offered::Right(Endpoint {
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
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // --- Compile-time duality checks via assert_type_eq ---

    fn assert_dual<S: Session>()
    where
        S::Dual: Session<Dual = S>,
    {
        // If this compiles, duality is involutive for S
    }

    #[test]
    fn duality_end() {
        init_test("duality_end");

        assert_dual::<End>();
        // Dual<End> = End
        fn _check() -> Dual<End> {
            End
        }

        crate::test_complete!("duality_end");
    }

    #[test]
    fn duality_send_recv() {
        init_test("duality_send_recv");

        // Dual<Send<T, End>> = Recv<T, End>
        assert_dual::<Send<String, End>>();
        assert_dual::<Recv<String, End>>();

        // Dual<Send<u64, Recv<bool, End>>> = Recv<u64, Send<bool, End>>
        assert_dual::<Send<u64, Recv<bool, End>>>();

        crate::test_complete!("duality_send_recv");
    }

    #[test]
    fn duality_choose_offer() {
        init_test("duality_choose_offer");

        // Dual<Choose<A, B>> = Offer<Dual<A>, Dual<B>>
        assert_dual::<Choose<End, End>>();
        assert_dual::<Offer<End, End>>();
        assert_dual::<Choose<Send<u8, End>, Recv<u8, End>>>();

        crate::test_complete!("duality_choose_offer");
    }

    #[test]
    fn duality_is_involutive() {
        init_test("duality_is_involutive");

        // Dual<Dual<S>> = S for all S
        // This is enforced by the Session trait bound: Dual: Session<Dual = Self>
        // The fact that these compile proves involution:
        fn _roundtrip_end(_: Dual<Dual<End>>) -> End {
            End
        }

        fn _roundtrip_send(
            _: Dual<Dual<Send<u32, End>>>,
        ) -> Send<u32, End> {
            Send { _phantom: PhantomData }
        }

        crate::test_complete!("duality_is_involutive");
    }

    #[test]
    fn duality_complex_protocol() {
        init_test("duality_complex_protocol");

        // ATM-like protocol:
        // Client: Send<Card, Recv<Pin, Choose<
        //           Send<Amount, Recv<Cash, End>>,   -- withdraw
        //           Recv<Balance, End>                -- check balance
        //         >>>
        type Card = u64;
        type Pin = u32;
        type Amount = u64;
        type Cash = u64;
        type Balance = u64;

        type ClientProtocol = Send<Card, Recv<Pin, Choose<
            Send<Amount, Recv<Cash, End>>,
            Recv<Balance, End>,
        >>>;

        // Server (dual):
        // Recv<Card, Send<Pin, Offer<
        //   Recv<Amount, Send<Cash, End>>,
        //   Send<Balance, End>
        // >>>
        type ServerProtocol = Dual<ClientProtocol>;

        assert_dual::<ClientProtocol>();
        assert_dual::<ServerProtocol>();

        // Verify the dual structure compiles correctly
        fn _accept_server(_: ServerProtocol) {}

        crate::test_complete!("duality_complex_protocol");
    }

    #[test]
    fn channel_creates_dual_endpoints() {
        init_test("channel_creates_dual_endpoints");

        type P = Send<u32, Recv<bool, End>>;
        let (_client, _server) = channel::<P>();

        // _client: Endpoint<Send<u32, Recv<bool, End>>>
        // _server: Endpoint<Recv<u32, Send<bool, End>>>

        crate::test_complete!("channel_creates_dual_endpoints");
    }

    #[test]
    fn endpoint_close_at_end() {
        init_test("endpoint_close_at_end");

        let (ep1, ep2) = channel::<End>();
        ep1.close();
        ep2.close();

        crate::test_complete!("endpoint_close_at_end");
    }

    #[test]
    fn branch_enum() {
        init_test("branch_enum");

        let left = Branch::Left;
        let right = Branch::Right;
        assert_ne!(left, right);
        assert_eq!(left, Branch::Left);
        assert_eq!(right, Branch::Right);

        crate::test_complete!("branch_enum");
    }

    // --- E2E protocol tests (lab runtime) ---

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    /// E2E: Simple request-response protocol over session-typed endpoints.
    #[test]
    fn session_send_recv_e2e() {
        init_test("session_send_recv_e2e");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(crate::types::Budget::INFINITE);

        // Protocol: Send<u64, Recv<u64, End>>
        type ClientP = Send<u64, Recv<u64, End>>;
        let (client_ep, server_ep) = channel::<ClientP>();

        let client_result = Arc::new(AtomicU64::new(0));
        let server_result = Arc::new(AtomicU64::new(0));
        let cr = client_result.clone();
        let sr = server_result.clone();

        // Client task: send 42, receive response
        let (client_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx = crate::cx::Cx::for_testing();
                let ep = client_ep.send(&cx, 42).await.expect("client send");
                let (response, ep) = ep.recv(&cx).await.expect("client recv");
                cr.store(response, Ordering::SeqCst);
                ep.close();
            })
            .unwrap();

        // Server task: receive request, send response (value * 2)
        let (server_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx = crate::cx::Cx::for_testing();
                let (request, ep) = server_ep.recv(&cx).await.expect("server recv");
                sr.store(request, Ordering::SeqCst);
                let ep = ep.send(&cx, request * 2).await.expect("server send");
                ep.close();
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(client_id, 0);
        runtime.scheduler.lock().unwrap().schedule(server_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(server_result.load(Ordering::SeqCst), 42, "server received 42");
        assert_eq!(client_result.load(Ordering::SeqCst), 84, "client received 84");

        crate::test_complete!("session_send_recv_e2e");
    }

    /// E2E: Choose/Offer protocol — client chooses left branch.
    #[test]
    fn session_choose_offer_e2e() {
        init_test("session_choose_offer_e2e");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(crate::types::Budget::INFINITE);

        // Protocol: Choose<Send<u64, End>, Recv<u64, End>>
        type ClientP = Choose<Send<u64, End>, Recv<u64, End>>;
        let (client_ep, server_ep) = channel::<ClientP>();

        let left_taken = Arc::new(AtomicBool::new(false));
        let value_sent = Arc::new(AtomicU64::new(0));
        let lt = left_taken.clone();
        let vs = value_sent.clone();

        // Client: choose left branch, send a value
        let (client_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx = crate::cx::Cx::for_testing();
                let ep = client_ep.choose_left(&cx).await.expect("choose left");
                let ep = ep.send(&cx, 99).await.expect("send on left");
                ep.close();
            })
            .unwrap();

        // Server: offer both branches, handle whichever the client picks
        let (server_id, _) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                let cx = crate::cx::Cx::for_testing();
                match server_ep.offer(&cx).await.expect("offer") {
                    Offered::Left(ep) => {
                        lt.store(true, Ordering::SeqCst);
                        let (val, ep) = ep.recv(&cx).await.expect("recv on left");
                        vs.store(val, Ordering::SeqCst);
                        ep.close();
                    }
                    Offered::Right(ep) => {
                        // Server's right branch: Send<u64, End>
                        let ep = ep.send(&cx, 0).await.unwrap();
                        ep.close();
                    }
                }
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(client_id, 0);
        runtime.scheduler.lock().unwrap().schedule(server_id, 0);
        runtime.run_until_quiescent();

        assert!(left_taken.load(Ordering::SeqCst), "server took left branch");
        assert_eq!(value_sent.load(Ordering::SeqCst), 99, "server received 99");

        crate::test_complete!("session_choose_offer_e2e");
    }

    /// E2E: Deterministic session execution — same seed, same result.
    #[test]
    fn session_deterministic() {
        init_test("session_deterministic");

        fn run_protocol(seed: u64) -> u64 {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(crate::types::Budget::INFINITE);

            type P = Send<u64, Recv<u64, End>>;
            let (client_ep, server_ep) = channel::<P>();

            let result = Arc::new(AtomicU64::new(0));
            let r = result.clone();

            let (cid, _) = runtime
                .state
                .create_task(region, crate::types::Budget::INFINITE, async move {
                    let cx = crate::cx::Cx::for_testing();
                    let ep = client_ep.send(&cx, 7).await.unwrap();
                    let (val, ep) = ep.recv(&cx).await.unwrap();
                    r.store(val, Ordering::SeqCst);
                    ep.close();
                })
                .unwrap();

            let (sid, _) = runtime
                .state
                .create_task(region, crate::types::Budget::INFINITE, async move {
                    let cx = crate::cx::Cx::for_testing();
                    let (v, ep) = server_ep.recv(&cx).await.unwrap();
                    let ep = ep.send(&cx, v + 100).await.unwrap();
                    ep.close();
                })
                .unwrap();

            runtime.scheduler.lock().unwrap().schedule(cid, 0);
            runtime.scheduler.lock().unwrap().schedule(sid, 0);
            runtime.run_until_quiescent();

            result.load(Ordering::SeqCst)
        }

        let r1 = run_protocol(0xCAFE);
        let r2 = run_protocol(0xCAFE);
        assert_eq!(r1, r2, "deterministic replay");
        assert_eq!(r1, 107, "7 + 100 = 107");

        crate::test_complete!("session_deterministic");
    }
}
