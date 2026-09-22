//! UDP transport adapter for SWIM membership packets (support-class scoped).
//!
//! Binds the membership wire codec ([`super::wire`]) to a [`UdpSocket`]: each
//! membership [`Packet`] is encoded into a single MTU-budgeted datagram and
//! sent, and inbound datagrams are decoded back into packets. This is the
//! support-class UDP lane for the pure SWIM core (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.4`).
//!
//! Production WAN hardening — path-MTU discovery, congestion response,
//! authentication, retransmission policy — is explicitly **out of scope** and
//! left as an adapter-lane follow-up. There is no blanket production claim: SWIM
//! is loss-tolerant by design (the gossip buffer re-disseminates), so a
//! best-effort datagram lane is the right shape here.

use super::swim::Packet;
use super::wire::{DEFAULT_MTU, EncodedDatagram, WireError, decode_packet, encode_packet};
use crate::net::UdpSocket;
use std::io;
use std::net::SocketAddr;

/// Buffer size for an inbound datagram (a full UDP datagram fits in 64 KiB).
const RECV_BUFFER_BYTES: usize = 65_536;

/// Error returned by the membership UDP adapter.
#[derive(Debug)]
pub enum UdpMembershipError {
    /// Underlying socket I/O failed.
    Io(io::Error),
    /// A datagram could not be encoded or decoded by the wire codec.
    Wire(WireError),
}

impl std::fmt::Display for UdpMembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "udp membership io error: {e}"),
            Self::Wire(e) => write!(f, "udp membership wire error: {e}"),
        }
    }
}

impl std::error::Error for UdpMembershipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Wire(e) => Some(e),
        }
    }
}

impl From<io::Error> for UdpMembershipError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<WireError> for UdpMembershipError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// A best-effort UDP transport for SWIM membership packets.
///
/// Wraps a caller-bound [`UdpSocket`]; the caller chooses the bind address so
/// the adapter stays free of address-resolution policy.
pub struct UdpMembershipTransport {
    socket: UdpSocket,
    mtu: usize,
    recv_buffer: Vec<u8>,
}

impl UdpMembershipTransport {
    /// Wraps a bound socket with the default MTU budget ([`DEFAULT_MTU`]).
    #[must_use]
    pub fn new(socket: UdpSocket) -> Self {
        Self::with_mtu(socket, DEFAULT_MTU)
    }

    /// Wraps a bound socket with an explicit MTU budget.
    #[must_use]
    pub fn with_mtu(socket: UdpSocket, mtu: usize) -> Self {
        Self {
            socket,
            mtu,
            recv_buffer: vec![0u8; RECV_BUFFER_BYTES],
        }
    }

    /// The local address the underlying socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The MTU budget used when encoding outbound packets.
    #[must_use]
    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    /// Encodes `packet` (truncating gossip to the MTU budget) and sends it to
    /// `target` as a single datagram. Returns the encoding receipt so callers
    /// can observe how much gossip rode out vs. was dropped.
    pub async fn send(
        &mut self,
        target: SocketAddr,
        packet: &Packet,
    ) -> Result<EncodedDatagram, UdpMembershipError> {
        let datagram = encode_packet(packet, self.mtu)?;
        self.socket.send_to(&datagram.bytes, target).await?;
        Ok(datagram)
    }

    /// Receives the next datagram and decodes it into a [`Packet`], returning
    /// the source address.
    pub async fn recv(&mut self) -> Result<(SocketAddr, Packet), UdpMembershipError> {
        let (len, from) = self.socket.recv_from(&mut self.recv_buffer).await?;
        let packet = decode_packet(&self.recv_buffer[..len])?;
        Ok((from, packet))
    }
}

// The native driver retains encoded packets itself, so a Pending send never
// reruns gossip selection/encoding. Raw receive allows address/size admission
// before decoding untrusted data. Public one-packet APIs remain unchanged.
#[cfg(not(target_arch = "wasm32"))]
impl UdpMembershipTransport {
    pub(super) fn is_connected(&self) -> bool {
        self.socket.peer_addr().is_ok()
    }

    pub(super) fn poll_raw_recv(
        &mut self,
        task: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<(SocketAddr, &[u8])>> {
        match self.socket.poll_recv_from(task, &mut self.recv_buffer) {
            std::task::Poll::Ready(Ok((len, source))) => {
                std::task::Poll::Ready(Ok((source, &self.recv_buffer[..len])))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    pub(super) fn poll_raw_send(
        &mut self,
        task: &mut std::task::Context<'_>,
        target: SocketAddr,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        use std::future::Future;
        // SocketAddr takes lookup_all's synchronous literal-address path, not
        // DNS/spawn_blocking. Only the native socket poll can return Pending;
        // its readiness registration belongs to the socket, not this future.
        let mut send = std::pin::pin!(self.socket.send_to(bytes, target));
        send.as_mut().poll(task)
    }
}
