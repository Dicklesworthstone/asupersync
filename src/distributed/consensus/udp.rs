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
                    crate::runtime::yield_now().await;
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
            crate::runtime::yield_now().await;
        }
    }
}

#[cfg(test)]
#[path = "udp_inline_tests.rs"]
mod tests;
