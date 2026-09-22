//! Native, bounded datagrams beneath the authenticated PBFT driver.
//!
//! A caller supplies the already-bound socket and resolved, static peer routes.
//! No DNS, socket creation, key generation, thread, or detached task occurs here.
//! UDP remains unreliable: this adapter supplies neither retransmission nor
//! congestion control, and it does not complete the experimental PBFT protocol.

use super::authenticated::{PbftAuthenticator, PbftPacketTransport};
use super::types::ReplicaId;
use crate::error::{Error, ErrorKind, Result};
use crate::net::UdpSocket;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// Common IPv4 UDP payload ceiling. Keep a fixed bound on both allocation and
// socket writes; do not enable jumbograms or application-layer fragmentation.
const MAX_DATAGRAM_ALLOCATION: usize = 65_507;

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput).with_message(message)
}

fn socket_error(error: io::Error) -> Error {
    Error::new(ErrorKind::ConnectionLost).with_message(format!("PBFT UDP I/O failed: {error}"))
}

fn truncated_datagram(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE)
    }
    #[cfg(not(windows))]
    {
        let _ = error;
        false
    }
}

/// A native UDP packet transport for a single authenticated node owner.
///
/// The socket must be unconnected and bound to the exact local roster address.
/// Every route must be unique, nonzero-port, unicast, resolved, and in the
/// socket's address family. Endpoints behind NAT require their own packet
/// transport; this static adapter does not discover or rewrite mappings.
/// The source-address filter is routing hygiene, NOT authentication: use this
/// only beneath `AuthenticatedPbftNode` or `AuthenticatedPbftTransport`.
///
/// At most one operation may own the socket at a time. A competing operation
/// fails explicitly instead of replacing another receive waker. A private
/// lease returns the socket when an operation finishes, errors, or is dropped;
/// no blocking lock is held across an await. The native socket retains its
/// normal reactor registration until reuse or socket destruction.
///
/// Receive allocation never exceeds the caller's packet bound. A full buffer
/// is discarded because portable UDP cannot distinguish an exact-fit datagram
/// from a truncated larger one. Accordingly, the usable wire maximum is one
/// byte below the configured allocation bound, and writes enforce that same
/// ceiling. Set compatible bounds on all peers. The application driver's
/// conservative proposal preflight reserves substantially more metadata space
/// than the current view-zero encoding needs; standalone adapter users must
/// additionally observe `max_datagram_bytes` before sending.
///
/// Broadcast sends are sequential and exclude the local replica. Failure or
/// cancellation can leave an arbitrary delivered prefix; retries are not an
/// exactly-once transport guarantee. Unknown sources and full-buffer packets
/// are discarded with a scheduler yield, allowing controller cancellation to
/// wake even under continuous hostile traffic. OS-level I/O errors propagate.
pub struct UdpPbftTransport {
    socket: Mutex<Option<UdpSocket>>,
    local: usize,
    peers: Vec<SocketAddr>,
    allocation_bound: usize,
}

impl fmt::Debug for UdpPbftTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPbftTransport")
            .field("local_replica", &self.local)
            .field("replica_count", &self.peers.len())
            .field("max_datagram_bytes", &self.max_datagram_bytes())
            .finish_non_exhaustive()
    }
}

impl UdpPbftTransport {
    /// Attach an explicitly owned socket to the authenticator's ordered roster.
    ///
    /// The authentication packet bound must be at most 65,507 bytes. A larger
    /// configuration is refused rather than silently clipping or fragmenting it.
    /// The signing key is not retained or copied by the datagram transport.
    pub fn new(
        socket: UdpSocket,
        auth: &PbftAuthenticator,
        peers: Vec<SocketAddr>,
    ) -> Result<Self> {
        let allocation_bound = auth.max_packet_bytes();
        if allocation_bound > MAX_DATAGRAM_ALLOCATION
            || peers.len() != auth.membership().replica_count()
        {
            return Err(invalid("PBFT UDP roster or packet bound is incompatible"));
        }
        let local = auth.local_replica().as_str().parse::<usize>()
            .map_err(|_| invalid("PBFT UDP local replica is invalid"))?;
        let address = socket.local_addr().map_err(socket_error)?;
        if peers.get(local) != Some(&address) || socket.peer_addr().is_ok() {
            return Err(invalid("PBFT UDP socket must be unconnected and bound to its local route"));
        }
        let mut unique = HashSet::with_capacity(peers.len());
        for peer in &peers {
            if peer.port() == 0
                || peer.ip().is_unspecified()
                || peer.ip().is_multicast()
                || peer.ip() == IpAddr::V4(Ipv4Addr::BROADCAST)
                || peer.is_ipv4() != address.is_ipv4()
                || !unique.insert(*peer)
            {
                return Err(invalid("PBFT UDP routes must be distinct resolved unicast endpoints"));
            }
        }
        Ok(Self {
            socket: Mutex::new(Some(socket)),
            local,
            peers,
            allocation_bound,
        })
    }

    /// Largest datagram accepted by this adapter, excluding the guard byte.
    #[must_use]
    pub const fn max_datagram_bytes(&self) -> usize {
        self.allocation_bound - 1
    }

    fn recipient(&self, replica: &ReplicaId) -> Result<SocketAddr> {
        if replica.as_str().len() > 4 {
            return Err(invalid("PBFT UDP recipient is invalid"));
        }
        let index = replica.as_str().parse::<usize>()
            .map_err(|_| invalid("PBFT UDP recipient is invalid"))?;
        if index == self.local || index.to_string() != replica.as_str() {
            return Err(invalid("PBFT UDP recipient must be another canonical replica"));
        }
        self.peers.get(index).copied()
            .ok_or_else(|| invalid("PBFT UDP recipient is outside the static roster"))
    }

    fn validate_size(&self, size: usize) -> Result<()> {
        if size == 0 || size >= self.allocation_bound {
            return Err(invalid("PBFT UDP packet exceeds the usable datagram bound"));
        }
        Ok(())
    }

    fn lease(&self) -> Result<SocketLease<'_>> {
        let socket = self.socket.lock().take().ok_or_else(|| {
            Error::new(ErrorKind::InvalidStateTransition)
                .with_message("PBFT UDP socket already has an operation owner")
        })?;
        Ok(SocketLease { owner: &self.socket, socket: Some(socket) })
    }
}

struct SocketLease<'a> {
    owner: &'a Mutex<Option<UdpSocket>>,
    socket: Option<UdpSocket>,
}

impl SocketLease<'_> {
    fn socket(&mut self) -> &mut UdpSocket {
        self.socket.as_mut().expect("leased socket is present until drop")
    }
}

impl Drop for SocketLease<'_> {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            let displaced = self.owner.lock().replace(socket);
            // Retire anything unexpected only after the mutex is unlocked.
            drop(displaced);
        }
    }
}

impl PbftPacketTransport for UdpPbftTransport {
    async fn send_packet(&self, recipient: &ReplicaId, packet: Vec<u8>) -> Result<()> {
        let address = self.recipient(recipient)?;
        self.validate_size(packet.len())?;
        let mut socket = self.lease()?;
        let written = socket.socket().send_to(&packet, address).await.map_err(socket_error)?;
        if written != packet.len() {
            return Err(invalid("PBFT UDP did not send a complete datagram"));
        }
        Ok(())
    }

    async fn broadcast_packet(&self, packet: Vec<u8>) -> Result<()> {
        self.validate_size(packet.len())?;
        let mut socket = self.lease()?;
        for (index, address) in self.peers.iter().enumerate() {
            if index == self.local {
                continue;
            }
            let written = socket.socket().send_to(&packet, *address).await.map_err(socket_error)?;
            if written != packet.len() {
                return Err(invalid("PBFT UDP did not send a complete datagram"));
            }
        }
        Ok(())
    }

    async fn receive_packet(&self, max_packet_bytes: usize) -> Result<Vec<u8>> {
        let limit = max_packet_bytes.min(self.allocation_bound);
        if limit < 2 {
            return Err(invalid("PBFT UDP receive bound must include a guard byte"));
        }
        let mut socket = self.lease()?;
        let mut packet = vec![0; limit];
        loop {
            let (received, source) = match socket.socket().recv_from(&mut packet).await {
                Ok(datagram) => datagram,
                Err(error) if truncated_datagram(&error) => {
                    // Winsock reports truncation as WSAEMSGSIZE instead of a
                    // full buffer. It must not turn a large unsigned datagram
                    // into a fatal error for the authenticated message pump.
                    crate::future::yield_now().await;
                    continue;
                }
                Err(error) => return Err(socket_error(error)),
            };
            if received < limit
                && source != self.peers[self.local]
                && self.peers.contains(&source)
            {
                packet.truncate(received);
                return Ok(packet);
            }
            // Keep the exact allocation bound while retiring a possibly
            // truncated datagram. Never authenticate only its retained prefix.
            crate::future::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::distributed::consensus::authenticated::{
        AuthenticatedPbftNode, PbftIngressOutcome, PbftMembership,
    };
    use crate::distributed::consensus::pbft::{PbftConfig, PbftMessage, PbftStateMachine};
    use crate::distributed::consensus::types::{
        ConsensusRequest, ConsensusResponse, MessageDigest, SequenceNumber, ViewNumber,
    };
    use crate::runtime::RuntimeBuilder;
    use crate::types::{CancelKind, Outcome, Time};
    use nkeys::{KeyPair, KeyPairType};
    use sha2::{Digest, Sha256};
    use std::future::{Future, poll_fn};
    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    fn auth(local: usize, limit: usize) -> Arc<PbftAuthenticator> {
        let key = |index: usize| {
            let seed: [u8; 32] = Sha256::digest(index.to_be_bytes()).into();
            KeyPair::new_from_raw(KeyPairType::User, seed).unwrap()
        };
        let keys: Vec<_> = (0..4).map(|i| key(i).public_key()).collect();
        Arc::new(PbftAuthenticator::new(
            PbftMembership::new([8; 32], 11, &keys).unwrap(),
            ReplicaId::new(local.to_string()), key(local), limit,
        ).unwrap())
    }

    fn sockets() -> (Vec<StdUdpSocket>, Vec<SocketAddr>) {
        let sockets: Vec<_> = (0..4).map(|_| StdUdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        let routes = sockets.iter().map(|socket| socket.local_addr().unwrap()).collect();
        (sockets, routes)
    }

    fn request() -> ConsensusRequest {
        ConsensusRequest::new("native-client".into(), Time::from_millis(41), b"native-bytes".to_vec())
    }

    #[derive(Clone, Default)]
    struct Application(Arc<StdMutex<Vec<Vec<u8>>>>);

    struct RelayWake {
        parent: Waker,
        count: Arc<AtomicUsize>,
    }

    impl Wake for RelayWake {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.parent.wake_by_ref();
        }
    }

    impl PbftStateMachine for Application {
        fn apply(&mut self, request: &ConsensusRequest) -> Outcome<Vec<u8>, String> {
            self.0.lock().unwrap().push(request.operation.clone());
            let mut result = b"native-result:".to_vec();
            result.extend_from_slice(&request.operation);
            Outcome::Ok(result)
        }
    }

    #[test]
    fn native_signed_quorum_executes_on_both_runtime_models_with_a_silent_backup() {
        for workers in [false, true] {
            for live in [4, 3] {
                let runtime = if workers {
                    RuntimeBuilder::new().worker_threads(2).build().unwrap()
                } else {
                    RuntimeBuilder::current_thread().build().unwrap()
                };
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (sockets, routes) = sockets();
                    let mut inactive = Vec::new();
                    let applications: Vec<_> = (0..live).map(|_| Application::default()).collect();
                    let mut nodes = Vec::new();
                    for (local, socket) in sockets.into_iter().enumerate() {
                        if local >= live {
                            inactive.push(socket); // Bound but deliberately never responds.
                            continue;
                        }
                        let auth = auth(local, 4096);
                        let wire = UdpPbftTransport::new(
                            UdpSocket::from_std(socket).unwrap(), &auth, routes.clone(),
                        ).unwrap();
                        nodes.push(AuthenticatedPbftNode::new(
                            PbftConfig::new(4, 1).unwrap(), wire, auth, applications[local].clone(),
                        ).unwrap());
                    }
                    let request = request();
                    nodes[0].submit_request(&cx, request.clone()).await.unwrap();
                    let responses = {
                        // Drive each node in the same owned root future. Keep
                        // pending node futures alive, never cancel another
                        // node's partially processed packet merely because a
                        // peer made progress. No spawned protocol tasks.
                        let mut pumps: Vec<_> = nodes.iter_mut().map(|node| {
                            let cx = &cx;
                            let request = &request;
                            Box::pin(async move {
                                loop {
                                    if let Some(response) = node.committed_response(request)? {
                                        return Ok::<_, Error>(response);
                                    }
                                    node.receive_one(cx).await?;
                                    crate::future::yield_now().await;
                                }
                            })
                        }).collect();
                        let mut outputs: Vec<Option<ConsensusResponse>> = (0..live).map(|_| None).collect();
                        let join = poll_fn(|task| {
                            for (index, pump) in pumps.iter_mut().enumerate() {
                                if outputs[index].is_some() { continue; }
                                match pump.as_mut().poll(task) {
                                    Poll::Ready(Ok(response)) => outputs[index] = Some(response),
                                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                    Poll::Pending => {}
                                }
                            }
                            if outputs.iter().all(Option::is_some) {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            }
                        });
                        crate::time::timeout(cx.now(), Duration::from_secs(5), join)
                            .await.expect("native quorum deadline").expect("native quorum result");
                        outputs
                    };
                    for (index, response) in responses.into_iter().enumerate() {
                        let response = response.unwrap();
                        assert_eq!(response.sequence, SequenceNumber::new(1));
                        assert_eq!(response.result, Outcome::Ok(b"native-result:native-bytes".to_vec()));
                        assert_eq!(applications[index].0.lock().unwrap().as_slice(), &[b"native-bytes".to_vec()]);
                        let replay = nodes[index].submit_and_wait(&cx, request.clone()).await.unwrap();
                        assert_eq!(replay.sequence, response.sequence);
                        assert_eq!(replay.result, response.result);
                        assert_eq!(applications[index].0.lock().unwrap().len(), 1);
                    }
                    drop(inactive);
                });
                assert!(runtime.is_quiescent());
            }
        }
    }

    #[test]
    fn native_receive_lease_returns_after_witnessed_pending_drop_or_cancellation() {
        for cancel in [false, true] {
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            runtime.block_on(async {
                let (mut sockets, routes) = sockets();
                let receiver = sockets.remove(1);
                let authority = auth(1, 4096);
                let wire = UdpPbftTransport::new(UdpSocket::from_std(receiver).unwrap(), &authority, routes.clone()).unwrap();
                let mut node = AuthenticatedPbftNode::new(
                    PbftConfig::new(4, 1).unwrap(), wire, authority, Application::default(),
                ).unwrap();
                let stop = Cx::detached_cancel_context();
                {
                    let mut receive = Box::pin(node.receive_one(&stop));
                    let wakes = Arc::new(AtomicUsize::new(0));
                    poll_fn(|task| {
                        let relay = Waker::from(Arc::new(RelayWake {
                            parent: task.waker().clone(),
                            count: Arc::clone(&wakes),
                        }));
                        assert!(receive.as_mut().poll(&mut Context::from_waker(&relay)).is_pending(), "must register native receive first");
                        Poll::Ready(())
                    }).await;
                    if cancel {
                        let before = wakes.load(Ordering::SeqCst);
                        stop.cancel_fast(CancelKind::User);
                        assert!(wakes.load(Ordering::SeqCst) > before, "native wait must be woken before repoll");
                        assert!(receive.await.unwrap_err().is_cancelled());
                    } else {
                        drop(receive);
                    }
                }
                // A complete signed vote after retirement proves the socket
                // was returned and remains usable, not merely that we exited.
                let primary = auth(0, 4096);
                let vote = PbftMessage::Prepare {
                    view: ViewNumber::new(0), sequence: SequenceNumber::new(1),
                    digest: MessageDigest::from_bytes([4; 32]), replica_id: ReplicaId::new("0".into()),
                };
                let packet = primary.seal(None, &vote).unwrap();
                sockets[0].send_to(&packet, routes[1]).unwrap();
                let cx = Cx::current().unwrap();
                let result = crate::time::timeout(cx.now(), Duration::from_secs(2), node.receive_one(&cx)).await.unwrap().unwrap();
                assert_eq!(result, PbftIngressOutcome::Processed);
                assert_eq!(node.last_applied().unwrap(), SequenceNumber::new(0));
            });
            assert!(runtime.is_quiescent());
        }
    }

    #[test]
    fn native_receive_rejects_truncated_signed_prefix_and_foreign_source() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let (mut sockets, routes) = sockets();
            let receiver = sockets.remove(1);
            let authority = auth(1, 4096);
            let limit = authority.max_packet_bytes();
            let wire = UdpPbftTransport::new(UdpSocket::from_std(receiver).unwrap(), &authority, routes.clone()).unwrap();
            let primary = auth(0, 4096);
            let packet = primary.seal(None, &PbftMessage::Request(request())).unwrap();
            let outsider = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            let mut foreign_request = request();
            foreign_request.operation = b"different-foreign-source".to_vec();
            let foreign = primary.seal(None, &PbftMessage::Request(foreign_request)).unwrap();
            outsider.send_to(&foreign, routes[1]).unwrap();

            // Construct a VALID signed packet exactly the size of the receive
            // allocation. Appending any suffix then produces a dangerous
            // truncated prefix: an implementation that only verifies retained
            // bytes would accept a packet whose full transcript was not signed.
            let mut full = request();
            full.operation = Vec::new();
            let base = serde_json::to_vec(&PbftMessage::Request(full.clone())).unwrap().len();
            full.operation = vec![0; (4096 - base).div_ceil(2)];
            let encoded = serde_json::to_vec(&PbftMessage::Request(full.clone())).unwrap().len();
            full.client_id.push_str(&"x".repeat(4096 - encoded));
            let exact_fit = primary.seal(None, &PbftMessage::Request(full)).unwrap();
            assert_eq!(exact_fit.len(), limit);
            assert!(authority.open(&exact_fit).is_ok(), "negative-control prefix is authentic");
            let mut oversized = exact_fit.clone();
            oversized.extend_from_slice(&[7; 20]);
            sockets[0].send_to(&oversized, routes[1]).unwrap();
            sockets[0].send_to(&exact_fit, routes[1]).unwrap();
            sockets[0].send_to(&packet, routes[1]).unwrap();
            let cx = Cx::current().unwrap();
            let received = crate::time::timeout(cx.now(), Duration::from_secs(2), wire.receive_packet(limit))
                .await.unwrap().unwrap();
            assert_eq!(received, packet);
            assert!(authority.open(&received).is_ok());
            assert!(received.len() <= wire.max_datagram_bytes());
        });
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn native_transport_refuses_competing_operations_and_restores_ownership_on_drop() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let (mut sockets, routes) = sockets();
            let socket = sockets.remove(0);
            let authority = auth(0, 4096);
            let wire = UdpPbftTransport::new(UdpSocket::from_std(socket).unwrap(), &authority, routes).unwrap();
            let mut pending = Box::pin(wire.receive_packet(authority.max_packet_bytes()));
            poll_fn(|task| {
                assert!(pending.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            assert!(wire.send_packet(&ReplicaId::new("1".into()), vec![1]).await.is_err());
            drop(pending);
            wire.send_packet(&ReplicaId::new("1".into()), vec![1]).await.unwrap();
            assert!(wire.socket.lock().is_some());
        });
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn native_constructor_and_send_bounds_fail_before_datagram_delivery() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            for case in 0..5 {
                let (mut sockets, mut routes) = sockets();
                let socket = sockets.remove(0);
                let authority = auth(0, if case == 0 { 65_507 } else { 4096 });
                match case {
                    1 => routes[1] = routes[0],
                    2 => routes[1].set_port(0),
                    3 => routes[1] = "224.0.0.1:3000".parse().unwrap(),
                    4 => { socket.connect(routes[1]).unwrap(); }
                    _ => {}
                }
                assert!(UdpPbftTransport::new(UdpSocket::from_std(socket).unwrap(), &authority, routes).is_err());
            }
            let (mut sockets, routes) = sockets();
            let socket = sockets.remove(0);
            let authority = auth(0, 4096);
            let wire = UdpPbftTransport::new(UdpSocket::from_std(socket).unwrap(), &authority, routes).unwrap();
            let recipient = ReplicaId::new("1".into());
            assert!(wire.send_packet(&recipient, vec![0; authority.max_packet_bytes()]).await.is_err());
            assert!(wire.send_packet(&ReplicaId::new("01".into()), vec![1]).await.is_err());
            assert!(wire.send_packet(&ReplicaId::new("0".into()), vec![1]).await.is_err());
            assert!(wire.receive_packet(1).await.is_err());
            sockets[0].set_nonblocking(true).unwrap();
            assert_eq!(sockets[0].recv_from(&mut [0; 8]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert!(wire.socket.lock().is_some());
        });
        assert!(runtime.is_quiescent());
    }
}
