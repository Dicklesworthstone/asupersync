//! Authenticated RaptorQ symbols over bounded, unreliable UDP datagrams.
//!
//! A datagram contains exactly one canonical `ASUPSYM` version-one singleton
//! batch, without the byte-stream length prefix. Packet boundaries are the
//! framing. Reordering, duplication, and packet loss remain visible to the
//! RaptorQ decoder; this adapter neither retransmits nor acknowledges packets.
//!
//! Invalid packets are counted and discarded as erasures. A malformed or
//! unauthenticated datagram cannot poison the next packet or reserve a symbol
//! identity. Genuine socket errors terminate the endpoint. Applications must
//! bound receive time with their original [`crate::Cx`] deadline, for example
//! through [`crate::raptorq::RaptorQReceiver::start_receive_object`]: UDP has no
//! end-of-stream or remote close indication.

use super::{SinkError, StreamError, SymbolFrameLimits, SymbolSink, SymbolStream};
use crate::distributed::symbol_service::{
    SymbolBatchLimits, SymbolStoreError, decode_symbol_batch, encode_symbol_batch,
};
use crate::net::UdpSocket;
use crate::security::{AuthKey, AuthenticatedSymbol};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

// The smaller portable IPv4/IPv6 UDP payload ceiling, excluding IP/UDP headers.
const MAX_DATAGRAM_BYTES: usize = 65_507;
const DATAGRAMS_PER_POLL: usize = 32;

/// Checked bounds for one symbol and its complete UDP datagram.
///
/// The payload bound excludes the canonical batch's 74-byte overhead. The
/// default 1024-byte symbol therefore uses a 1098-byte UDP payload. A larger
/// configured limit may require IP fragmentation; path MTU discovery and
/// congestion control belong to the caller's transport policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolDatagramLimits {
    frame: SymbolFrameLimits,
}

impl SymbolDatagramLimits {
    /// Refuse zero, overflowing, or nonportable datagram sizes before allocation.
    pub fn new(max_symbol_bytes: usize) -> io::Result<Self> {
        let frame = SymbolFrameLimits::new(max_symbol_bytes)?;
        if frame.batch_limits().max_encoded_bytes > MAX_DATAGRAM_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authenticated symbol exceeds the portable UDP datagram limit",
            ));
        }
        Ok(Self { frame })
    }

    /// Maximum symbol payload length, excluding authentication and framing.
    #[must_use]
    pub const fn max_symbol_bytes(self) -> usize {
        self.frame.max_symbol_bytes()
    }

    /// Maximum complete canonical batch carried in one UDP packet.
    #[must_use]
    pub const fn max_datagram_bytes(self) -> usize {
        self.frame.batch_limits().max_encoded_bytes
    }

    fn batch(self) -> SymbolBatchLimits {
        self.frame.batch_limits()
    }
}

impl Default for SymbolDatagramLimits {
    fn default() -> Self {
        Self::new(1024).expect("default symbol datagram size is representable")
    }
}

fn validate_peer(socket: &UdpSocket, peer: SocketAddr) -> io::Result<()> {
    if peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symbol datagrams require a concrete unicast peer",
        ));
    }
    if socket.peer_addr().is_ok_and(|connected| connected != peer) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP socket is connected to a different symbol peer",
        ));
    }
    Ok(())
}

fn cancelled() -> bool {
    crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendState {
    Open,
    Closed,
    Failed,
}

/// A symbol sink that sends one authenticated symbol per UDP datagram.
///
/// The owned socket may be unconnected or connected to `peer`. Every send
/// explicitly addresses that peer, including when another socket clone changes
/// the kernel's connected destination. Do not concurrently reconnect shared
/// socket clones: platforms can refuse such sends or filter their replies.
///
/// `Ready(Ok(()))` means the OS accepted the complete datagram. `Pending` has
/// accepted nothing and retains no new symbol or payload. A retry may submit
/// the same symbol, or abandon it and submit another. There is no hidden send
/// queue, so flush is local and immediate. Close seals this adapter; it sends
/// no packet and does not shut down another owner of the same socket.
///
/// Zero-tag symbols are refused. Other tags are transmitted unchanged and
/// verified by the receiving key. Neither send nor flush establishes receipt,
/// remote decoding, durable storage, or an authenticated peer identity.
pub struct UdpSymbolSink {
    socket: UdpSocket,
    peer: SocketAddr,
    limits: SymbolDatagramLimits,
    state: SendState,
    datagrams_sent: u64,
}

impl UdpSymbolSink {
    /// Wrap an already bound socket and an explicit peer without sending data.
    pub fn new(
        socket: UdpSocket,
        peer: SocketAddr,
        limits: SymbolDatagramLimits,
    ) -> io::Result<Self> {
        validate_peer(&socket, peer)?;
        Ok(Self {
            socket,
            peer,
            limits,
            state: SendState::Open,
            datagrams_sent: 0,
        })
    }

    /// Fixed numeric destination used for every send.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Bound local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Immutable datagram and payload limits.
    #[must_use]
    pub const fn limits(&self) -> SymbolDatagramLimits {
        self.limits
    }

    /// Complete datagrams accepted by the local OS, not remote acknowledgements.
    #[must_use]
    pub const fn datagrams_sent(&self) -> u64 {
        self.datagrams_sent
    }

    /// Recover the socket. This adapter never retains a partial datagram.
    #[must_use]
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

impl SymbolSink for UdpSymbolSink {
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if self.state == SendState::Open {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(SinkError::Closed))
        }
    }

    fn poll_send(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        if this.state != SendState::Open {
            return Poll::Ready(Err(SinkError::Closed));
        }
        if symbol.tag().is_zero() || symbol.symbol().data().len() > this.limits.max_symbol_bytes() {
            return Poll::Ready(Err(SinkError::SendFailed {
                reason: "symbol datagram requires a nonzero tag and a bounded payload".to_owned(),
            }));
        }
        // The address is already numeric, so the hot path bypasses DNS while
        // preserving the ordinary send_to capability gate.
        if let Err(error) = crate::cx::io_gate::require_ambient_io("transport::UdpSymbolSink::send") {
            return Poll::Ready(Err(error.into()));
        }
        if cancelled() {
            return Poll::Ready(Err(SinkError::Cancelled));
        }
        let encoded = match encode_symbol_batch(std::slice::from_ref(&symbol), this.limits.batch()) {
            Ok(encoded) => encoded,
            Err(error) => {
                return Poll::Ready(Err(SinkError::SendFailed {
                    reason: error.to_string(),
                }));
            }
        };
        // A panic after the syscall may leave acceptance unknown. Fail closed
        // if a caller catches it and polls this adapter again.
        this.state = SendState::Failed;
        match this.socket.poll_send_to(cx, encoded.as_ref(), &[this.peer]) {
            Poll::Pending => {
                this.state = SendState::Open;
                Poll::Pending
            }
            Poll::Ready(Ok(n)) if n == encoded.as_ref().len() => {
                this.datagrams_sent = this.datagrams_sent.saturating_add(1);
                this.state = SendState::Open;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP send did not accept exactly one complete symbol datagram",
            )
            .into())),
            Poll::Ready(Err(error)) => {
                if error.kind() == io::ErrorKind::Interrupted && cancelled() {
                    Poll::Ready(Err(SinkError::Cancelled))
                } else {
                    Poll::Ready(Err(error.into()))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if self.state == SendState::Failed {
            Poll::Ready(Err(SinkError::Closed))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        if this.state == SendState::Failed {
            Poll::Ready(Err(SinkError::Closed))
        } else {
            this.state = SendState::Closed;
            Poll::Ready(Ok(()))
        }
    }
}

impl fmt::Debug for UdpSymbolSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSymbolSink")
            .field("peer", &self.peer)
            .field("limits", &self.limits)
            .field("state", &self.state)
            .field("datagrams_sent", &self.datagrams_sent)
            .finish_non_exhaustive()
    }
}

/// Packet admission counts; invalid packets are erasures, never decode input.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpSymbolStreamStats {
    /// Datagrams consumed, including discarded packets.
    pub datagrams_received: u64,
    /// Authenticated symbols yielded to the caller; duplicates are included.
    pub symbols_received: u64,
    /// Datagrams from a different source address.
    pub rejected_peer: u64,
    /// Canonical packets whose authentication tag did not verify.
    pub rejected_authentication: u64,
    /// Noncanonical, empty, truncated, trailing-data, or nonsingleton packets.
    pub rejected_format: u64,
    /// Packets beyond the configured complete datagram bound.
    pub rejected_oversize: u64,
}

/// A single-peer symbol stream that authenticates each complete UDP datagram.
///
/// Malformed, oversized, wrong-peer, and bad-tag packets are discarded and
/// counted as erasures, allowing authentic repair symbols to recover the
/// object. Every poll consumes at most 32 packets, including rejected packets,
/// before yielding. A pending socket arranges its own readiness wake.
///
/// One reusable receive buffer is bounded to the maximum datagram plus one
/// sentinel byte. Oversized packets therefore cannot be truncated into a valid
/// canonical prefix. Zero-length packets are invalid data, not EOF. Socket
/// errors and caught provider panics terminate the stream. Dropping a pending
/// borrowing receive loses no accepted symbol: delivery and authentication are
/// completed within one poll.
pub struct UdpSymbolStream {
    socket: UdpSocket,
    peer: SocketAddr,
    key: AuthKey,
    limits: SymbolDatagramLimits,
    buffer: Vec<u8>,
    stats: UdpSymbolStreamStats,
    ended: bool,
}

impl UdpSymbolStream {
    /// Wrap a bound socket, fixed peer, and explicit receiver authentication key.
    pub fn new(
        socket: UdpSocket,
        peer: SocketAddr,
        key: AuthKey,
        limits: SymbolDatagramLimits,
    ) -> io::Result<Self> {
        validate_peer(&socket, peer)?;
        Ok(Self {
            socket,
            peer,
            key,
            limits,
            buffer: vec![0; limits.max_datagram_bytes() + 1],
            stats: UdpSymbolStreamStats::default(),
            ended: false,
        })
    }

    /// Exact packet source accepted by this adapter.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Bound local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Immutable datagram and payload limits.
    #[must_use]
    pub const fn limits(&self) -> SymbolDatagramLimits {
        self.limits
    }

    /// Snapshot packet admission counters without exposing keys or payloads.
    #[must_use]
    pub const fn stats(&self) -> UdpSymbolStreamStats {
        self.stats
    }

    /// Recover the socket; UDP packet boundaries leave no partial frame to resume.
    #[must_use]
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

impl SymbolStream for UdpSymbolStream {
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        this.ended = true;
        if let Err(error) = crate::cx::io_gate::require_ambient_io("transport::UdpSymbolStream::receive") {
            return Poll::Ready(Some(Err(error.into())));
        }
        for _ in 0..DATAGRAMS_PER_POLL {
            let (length, peer) = match this.socket.poll_recv_from(cx, &mut this.buffer) {
                Poll::Pending => {
                    this.ended = false;
                    return Poll::Pending;
                }
                Poll::Ready(Ok(received)) => received,
                Poll::Ready(Err(error)) => {
                    // Windows consumes a truncated datagram but reports its
                    // oversize as WSAEMSGSIZE instead of returning the prefix.
                    #[cfg(windows)]
                    if error.raw_os_error()
                        == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE)
                    {
                        this.stats.datagrams_received =
                            this.stats.datagrams_received.saturating_add(1);
                        this.stats.rejected_oversize = this.stats.rejected_oversize.saturating_add(1);
                        continue;
                    }
                    if error.kind() == io::ErrorKind::Interrupted {
                        if cancelled() {
                            return Poll::Ready(Some(Err(StreamError::Cancelled)));
                        }
                        continue;
                    }
                    return Poll::Ready(Some(Err(error.into())));
                }
            };
            this.stats.datagrams_received = this.stats.datagrams_received.saturating_add(1);
            if peer != this.peer {
                this.stats.rejected_peer = this.stats.rejected_peer.saturating_add(1);
                continue;
            }
            if length > this.limits.max_datagram_bytes() {
                this.stats.rejected_oversize = this.stats.rejected_oversize.saturating_add(1);
                continue;
            }
            match decode_symbol_batch(&this.buffer[..length], &this.key, this.limits.batch()) {
                Ok(mut symbols) => {
                    let symbol = symbols.pop().expect("canonical singleton batch admitted");
                    this.stats.symbols_received = this.stats.symbols_received.saturating_add(1);
                    this.ended = false;
                    return Poll::Ready(Some(Ok(symbol)));
                }
                Err(SymbolStoreError::Authentication) => {
                    this.stats.rejected_authentication =
                        this.stats.rejected_authentication.saturating_add(1);
                }
                Err(_) => {
                    this.stats.rejected_format = this.stats.rejected_format.saturating_add(1);
                }
            }
        }
        cx.waker().wake_by_ref();
        this.ended = false;
        Poll::Pending
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.ended {
            (0, Some(0))
        } else {
            (0, None)
        }
    }

    fn is_exhausted(&self) -> bool {
        self.ended
    }
}

impl fmt::Debug for UdpSymbolStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSymbolStream")
            .field("peer", &self.peer)
            .field("limits", &self.limits)
            .field("stats", &self.stats)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "udp_tests.rs"]
mod tests;
