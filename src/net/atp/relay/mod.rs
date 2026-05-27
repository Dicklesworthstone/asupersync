//! Opaque ATP relay reservation and forwarding model.
//!
//! The relay layer is metadata-only. It authorizes transfer-scoped relay
//! reservations, forwards encrypted ATP packets without parsing object
//! plaintext, records path proof telemetry, and models UDP-first with
//! TCP/TLS port 443 fallback for hostile networks.

use crate::atp::path::{
    PathBudget, PathCandidate, PathCandidateId, PathFailureKind, PathKind, PathOutcome,
    PathSecurity, PathSuccessKind, PathTraceId,
};
use crate::net::atp::rendezvous::{CandidateSignature, PeerId, TransferNonce};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};

/// TCP/TLS fallback port used by locked-down egress networks.
pub const TCP_TLS_443_PORT: u16 = 443;

/// ATP relay tunnel frame magic.
pub const RELAY_WIRE_MAGIC: [u8; 4] = *b"ATPR";

/// Current ATP relay tunnel frame format version.
pub const RELAY_WIRE_VERSION: u8 = 1;

const RELAY_WIRE_FORWARD_FRAME_KIND: u8 = 1;
const RELAY_WIRE_HEADER_LEN: usize = 4 + 1 + 1 + 1 + 16 + 16 + 32 + 8 + 8 + 32 + 4;
const RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN: usize = 4;

/// Relay transport policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayTransport {
    /// UDP relay carrying encrypted ATP datagrams.
    Udp,
    /// TCP/TLS fallback on port 443 with head-of-line blocking caveats.
    TcpTls443,
}

impl RelayTransport {
    /// Stable path/proof code for this transport.
    #[must_use]
    pub const fn path_code(self) -> &'static str {
        match self {
            Self::Udp => "atp_relay_udp",
            Self::TcpTls443 => "atp_relay_tcp_tls_443",
        }
    }

    /// Default network port for this transport.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Udp => 0,
            Self::TcpTls443 => TCP_TLS_443_PORT,
        }
    }

    /// Explicit fallback reason for proof artifacts and operator logs.
    #[must_use]
    pub const fn fallback_reason(self) -> Option<&'static str> {
        match self {
            Self::Udp => None,
            Self::TcpTls443 => Some("udp_unavailable_tcp_tls_443"),
        }
    }

    /// Shared path graph kind represented by this relay transport.
    #[must_use]
    pub const fn path_kind(self) -> PathKind {
        match self {
            Self::Udp => PathKind::AtpRelayUdp,
            Self::TcpTls443 => PathKind::AtpRelayTcpTls443,
        }
    }

    const fn wire_code(self) -> u8 {
        match self {
            Self::Udp => 0,
            Self::TcpTls443 => 1,
        }
    }

    const fn from_wire_code(code: u8) -> Result<Self, RelayError> {
        match code {
            0 => Ok(Self::Udp),
            1 => Ok(Self::TcpTls443),
            _ => Err(RelayError::InvalidRelayWireFrame),
        }
    }
}

/// Stable identifier for one relay reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayReservationId(u128);

impl RelayReservationId {
    /// Construct a non-zero relay reservation id.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::ZeroReservationId`] when `raw` is zero.
    pub const fn new(raw: u128) -> Result<Self, RelayError> {
        if raw == 0 {
            return Err(RelayError::ZeroReservationId);
        }
        Ok(Self(raw))
    }

    /// Return the raw reservation id.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// End-to-end proof tag carried by encrypted ATP packets.
///
/// The relay stores and forwards this tag but does not verify or mint verified
/// chunks. Endpoint verification remains end-to-end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofTag([u8; 32]);

impl ProofTag {
    /// Construct a non-zero proof tag.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidProofTag`] when all bytes are zero.
    pub fn new(bytes: [u8; 32]) -> Result<Self, RelayError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RelayError::InvalidProofTag);
        }
        Ok(Self(bytes))
    }

    /// Return proof tag bytes.
    #[must_use]
    pub const fn bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Opaque encrypted packet accepted by the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRelayPacket {
    sequence: u64,
    transport: RelayTransport,
    payload: Vec<u8>,
    proof_tag: ProofTag,
    sent_at_micros: u64,
}

impl OpaqueRelayPacket {
    /// Build an opaque packet.
    ///
    /// `sent_at_micros` is a transfer-local monotonic timestamp. Relay latency
    /// summaries compare it with the relay's receive timestamp and saturate at
    /// zero if an out-of-domain timestamp is observed.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::EmptyPacket`] when the payload is empty.
    pub fn new(
        sequence: u64,
        transport: RelayTransport,
        payload: Vec<u8>,
        proof_tag: ProofTag,
        sent_at_micros: u64,
    ) -> Result<Self, RelayError> {
        if payload.is_empty() {
            return Err(RelayError::EmptyPacket);
        }

        Ok(Self {
            sequence,
            transport,
            payload,
            proof_tag,
            sent_at_micros,
        })
    }

    /// Packet sequence number within the end-to-end ATP flow.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Transport used for this packet.
    #[must_use]
    pub const fn transport(&self) -> RelayTransport {
        self.transport
    }

    /// Opaque encrypted bytes forwarded by the relay.
    #[must_use]
    pub fn opaque_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// Number of opaque bytes.
    #[must_use]
    pub fn opaque_len(&self) -> usize {
        self.payload.len()
    }

    /// End-to-end proof tag carried unchanged through the relay.
    #[must_use]
    pub const fn proof_tag(&self) -> &ProofTag {
        &self.proof_tag
    }

    /// Sender-side transfer-local timestamp used for latency summaries.
    #[must_use]
    pub const fn sent_at_micros(&self) -> u64 {
        self.sent_at_micros
    }
}

/// Transport-neutral relay tunnel frame.
///
/// The same canonical frame is carried over UDP relay datagrams and the
/// TCP/TLS 443 fallback stream. It contains only routing/proof metadata plus
/// opaque encrypted ATP bytes; object paths, manifests, and plaintext chunks
/// remain end-to-end encrypted outside relay authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayWireFrame {
    reservation_id: RelayReservationId,
    transfer_nonce: TransferNonce,
    from_peer_id: PeerId,
    packet: OpaqueRelayPacket,
}

/// Result of decoding from a TCP/TLS 443 relay byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayWireRecordDecode {
    /// More stream bytes are required before a complete record can be decoded.
    NeedMore {
        /// Minimum total buffered bytes required to retry decoding this record.
        minimum_len: usize,
    },
    /// A complete record was decoded from the start of the input buffer.
    Complete {
        /// Decoded relay tunnel frame.
        frame: RelayWireFrame,
        /// Number of bytes consumed from the start of the input buffer.
        consumed: usize,
    },
}

/// Bounded TCP/TLS 443 relay stream adapter.
///
/// TCP/TLS fallback is a byte stream, not a datagram channel. This adapter owns
/// the byte buffer between socket reads and canonical relay frames, enforces a
/// deterministic upper bound, and drains length-prefixed relay records without
/// trusting plaintext or application message boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTcpTlsStreamBuffer {
    buffered: Vec<u8>,
    max_payload_bytes: usize,
    max_buffered_bytes: usize,
}

/// Stable identifier for one accepted TCP/TLS 443 relay stream.
///
/// The relay socket loop should allocate this only after TLS/session admission
/// has authenticated the peer attached to the stream. The stream id is local to
/// the relay process and is intentionally separate from ATP transfer ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayTcpTlsStreamId(u128);

impl RelayTcpTlsStreamId {
    /// Construct a non-zero TCP/TLS relay stream id.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::ZeroTcpTlsStreamId`] when `raw` is zero.
    pub const fn new(raw: u128) -> Result<Self, RelayError> {
        if raw == 0 {
            return Err(RelayError::ZeroTcpTlsStreamId);
        }
        Ok(Self(raw))
    }

    /// Return the raw relay-local stream id.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// Bounds for the relay endpoint admission directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayEndpointDirectoryQuota {
    /// Maximum UDP socket endpoints retained at once.
    pub max_udp_endpoints: usize,
    /// Maximum TCP/TLS stream bindings retained at once.
    pub max_tcp_tls_streams: usize,
}

impl RelayEndpointDirectoryQuota {
    /// Validate endpoint directory bounds.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] when either bound is zero.
    pub const fn validate(self) -> Result<Self, RelayError> {
        if self.max_udp_endpoints == 0 || self.max_tcp_tls_streams == 0 {
            return Err(RelayError::InvalidQuota);
        }
        Ok(self)
    }
}

impl Default for RelayEndpointDirectoryQuota {
    fn default() -> Self {
        Self {
            max_udp_endpoints: 16_384,
            max_tcp_tls_streams: 16_384,
        }
    }
}

/// Socket-facing endpoint admission directory for the relay.
///
/// Relay frames contain a self-declared peer id, but socket ingress must not
/// trust that field. This directory is the boundary between path/rendezvous/TLS
/// admission and relay forwarding: a socket address or TCP/TLS stream id maps to
/// the authenticated peer id, and service helpers compare that admitted peer
/// against decoded frame metadata before any quota, usage, proof, or queue state
/// can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayEndpointBinding {
    peer_id: PeerId,
    generation: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayEndpointDirectory {
    udp_endpoints: BTreeMap<SocketAddr, RelayEndpointBinding>,
    tcp_tls_streams: BTreeMap<RelayTcpTlsStreamId, RelayEndpointBinding>,
    quota: RelayEndpointDirectoryQuota,
    next_admission_generation: u64,
}

impl RelayEndpointDirectory {
    /// Construct an empty endpoint directory.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] when any quota bound is zero.
    pub fn new(quota: RelayEndpointDirectoryQuota) -> Result<Self, RelayError> {
        Ok(Self {
            udp_endpoints: BTreeMap::new(),
            tcp_tls_streams: BTreeMap::new(),
            quota: quota.validate()?,
            next_admission_generation: 0,
        })
    }

    /// Number of admitted UDP endpoints.
    #[must_use]
    pub fn udp_endpoint_count(&self) -> usize {
        self.udp_endpoints.len()
    }

    /// Number of admitted TCP/TLS streams.
    #[must_use]
    pub fn tcp_tls_stream_count(&self) -> usize {
        self.tcp_tls_streams.len()
    }

    /// Bind a UDP socket endpoint to an authenticated peer id.
    ///
    /// The operation is idempotent for the same endpoint/peer pair and fails
    /// closed if a different peer is already bound to the endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidRelayEndpoint`] for wildcard/port-zero
    /// addresses, [`RelayError::DuplicateRelayEndpoint`] for conflicting
    /// bindings, and [`RelayError::QuotaExceeded`] when the directory is full.
    pub fn bind_udp_endpoint(
        &mut self,
        peer_id: PeerId,
        endpoint: SocketAddr,
    ) -> Result<(), RelayError> {
        validate_relay_socket_endpoint(endpoint)?;
        if let Some(binding) = self.udp_endpoints.get(&endpoint) {
            if binding.peer_id != peer_id {
                return Err(RelayError::DuplicateRelayEndpoint);
            }
        }
        if self.udp_endpoints.contains_key(&endpoint) {
            let generation = self.next_endpoint_admission_generation();
            if let Some(binding) = self.udp_endpoints.get_mut(&endpoint) {
                binding.generation = generation;
            }
            return Ok(());
        }
        if self.udp_endpoints.len() >= self.quota.max_udp_endpoints {
            return Err(RelayError::QuotaExceeded);
        }
        let binding = RelayEndpointBinding {
            peer_id,
            generation: self.next_endpoint_admission_generation(),
        };
        self.udp_endpoints.insert(endpoint, binding);
        Ok(())
    }

    /// Resolve the authenticated peer id for a UDP socket endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the endpoint has not
    /// passed admission.
    pub fn peer_for_udp_endpoint(&self, endpoint: SocketAddr) -> Result<PeerId, RelayError> {
        self.udp_endpoints
            .get(&endpoint)
            .map(|binding| binding.peer_id)
            .ok_or(RelayError::UnknownRelayEndpoint)
    }

    /// Return the preferred UDP endpoint admitted for `peer_id`.
    ///
    /// Peers can legitimately rebind when NAT mappings change. The relay
    /// therefore prefers the most recently admitted endpoint for a peer instead
    /// of the lexicographically first address, while keeping deterministic
    /// ordering for replay if admission generations ever tie.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the peer has no UDP
    /// endpoint in the directory.
    pub fn first_udp_endpoint_for_peer(&self, peer_id: PeerId) -> Result<SocketAddr, RelayError> {
        self.udp_endpoints
            .iter()
            .filter_map(|(endpoint, binding)| {
                (binding.peer_id == peer_id).then_some((binding.generation, *endpoint))
            })
            .max_by_key(|(generation, endpoint)| (*generation, *endpoint))
            .map(|(_, endpoint)| endpoint)
            .ok_or(RelayError::UnknownRelayEndpoint)
    }

    /// Remove a UDP endpoint binding, returning the peer that was bound.
    pub fn unbind_udp_endpoint(&mut self, endpoint: SocketAddr) -> Option<PeerId> {
        self.udp_endpoints
            .remove(&endpoint)
            .map(|binding| binding.peer_id)
    }

    /// Bind a TCP/TLS stream id to an authenticated peer id.
    ///
    /// The operation is idempotent for the same stream/peer pair and fails
    /// closed if a different peer is already bound to the stream id.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::DuplicateRelayEndpoint`] for conflicting bindings
    /// and [`RelayError::QuotaExceeded`] when the directory is full.
    pub fn bind_tcp_tls_stream(
        &mut self,
        peer_id: PeerId,
        stream_id: RelayTcpTlsStreamId,
    ) -> Result<(), RelayError> {
        if let Some(binding) = self.tcp_tls_streams.get(&stream_id) {
            if binding.peer_id != peer_id {
                return Err(RelayError::DuplicateRelayEndpoint);
            }
        }
        if self.tcp_tls_streams.contains_key(&stream_id) {
            let generation = self.next_endpoint_admission_generation();
            if let Some(binding) = self.tcp_tls_streams.get_mut(&stream_id) {
                binding.generation = generation;
            }
            return Ok(());
        }
        if self.tcp_tls_streams.len() >= self.quota.max_tcp_tls_streams {
            return Err(RelayError::QuotaExceeded);
        }
        let binding = RelayEndpointBinding {
            peer_id,
            generation: self.next_endpoint_admission_generation(),
        };
        self.tcp_tls_streams.insert(stream_id, binding);
        Ok(())
    }

    /// Resolve the authenticated peer id for a TCP/TLS stream id.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the stream has not
    /// passed admission.
    pub fn peer_for_tcp_tls_stream(
        &self,
        stream_id: RelayTcpTlsStreamId,
    ) -> Result<PeerId, RelayError> {
        self.tcp_tls_streams
            .get(&stream_id)
            .map(|binding| binding.peer_id)
            .ok_or(RelayError::UnknownRelayEndpoint)
    }

    /// Remove a TCP/TLS stream binding, returning the peer that was bound.
    pub fn unbind_tcp_tls_stream(&mut self, stream_id: RelayTcpTlsStreamId) -> Option<PeerId> {
        self.tcp_tls_streams
            .remove(&stream_id)
            .map(|binding| binding.peer_id)
    }

    /// Return the preferred TCP/TLS stream admitted for `peer_id`.
    ///
    /// A reconnecting peer may have an older still-admitted stream and a newer
    /// stream during handoff. Egress uses the most recently admitted stream so a
    /// successful reconnect can take over without draining to a stale writer.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the peer has no
    /// TCP/TLS stream in the directory.
    pub fn first_tcp_tls_stream_for_peer(
        &self,
        peer_id: PeerId,
    ) -> Result<RelayTcpTlsStreamId, RelayError> {
        self.tcp_tls_streams
            .iter()
            .filter_map(|(stream_id, binding)| {
                (binding.peer_id == peer_id).then_some((binding.generation, *stream_id))
            })
            .max_by_key(|(generation, stream_id)| (*generation, *stream_id))
            .map(|(_, stream_id)| stream_id)
            .ok_or(RelayError::UnknownRelayEndpoint)
    }

    fn next_endpoint_admission_generation(&mut self) -> u64 {
        self.next_admission_generation = self.next_admission_generation.saturating_add(1);
        self.next_admission_generation
    }
}

/// Encoded TCP/TLS stream write selected by the socket loop.
///
/// [`RelayTcpTlsRecord`] carries the bytes and peer identity. The actual socket
/// writer also needs the relay-local stream id that was admitted for that peer,
/// so the socket loop wraps the record with the concrete stream destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTcpTlsStreamWrite {
    stream_id: RelayTcpTlsStreamId,
    record: RelayTcpTlsRecord,
}

impl RelayTcpTlsStreamWrite {
    /// Relay-local stream id to write to.
    #[must_use]
    pub const fn stream_id(&self) -> RelayTcpTlsStreamId {
        self.stream_id
    }

    /// Peer id whose TCP/TLS stream should receive this record.
    #[must_use]
    pub const fn to_peer_id(&self) -> PeerId {
        self.record.to_peer_id()
    }

    /// Reservation id represented by the encoded record.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.record.reservation_id()
    }

    /// Length-prefixed TCP/TLS relay record bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.record.bytes()
    }

    /// Number of opaque ATP ciphertext bytes represented by this record.
    #[must_use]
    pub const fn opaque_bytes(&self) -> u64 {
        self.record.opaque_bytes()
    }

    /// Borrow the underlying TCP/TLS relay record.
    #[must_use]
    pub const fn record(&self) -> &RelayTcpTlsRecord {
        &self.record
    }

    /// Consume this value and return the underlying TCP/TLS relay record.
    #[must_use]
    pub fn into_record(self) -> RelayTcpTlsRecord {
        self.record
    }
}

/// TCP/TLS stream accepted by the relay socket loop.
///
/// The relay socket loop allocates the relay-local stream id and admits the
/// stream to an already-authenticated peer in one operation. The returned
/// `TcpStream` is still the caller's responsibility to configure for blocking,
/// nonblocking, TLS wrapping, and readiness integration.
#[derive(Debug)]
pub struct RelayAcceptedTcpTlsStream {
    stream_id: RelayTcpTlsStreamId,
    peer_id: PeerId,
    peer_addr: SocketAddr,
    stream: TcpStream,
}

impl RelayAcceptedTcpTlsStream {
    /// Relay-local stream id allocated for this accepted connection.
    #[must_use]
    pub const fn stream_id(&self) -> RelayTcpTlsStreamId {
        self.stream_id
    }

    /// Authenticated peer id bound to this accepted stream.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Socket peer address reported by `TcpListener::accept`.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Borrow the accepted TCP stream.
    #[must_use]
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Mutably borrow the accepted TCP stream.
    #[must_use]
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Consume this value and return the accepted TCP stream.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayTcpTlsPendingWrite {
    peer_id: PeerId,
    bytes: Vec<u8>,
    written: usize,
}

impl RelayTcpTlsPendingWrite {
    fn from_record(record: RelayTcpTlsRecord) -> Self {
        let peer_id = record.to_peer_id();
        Self {
            peer_id,
            bytes: record.into_bytes(),
            written: 0,
        }
    }

    fn remaining(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.written)
    }

    fn advance(&mut self, written: usize) {
        self.written = self.written.saturating_add(written).min(self.bytes.len());
    }

    fn is_complete(&self) -> bool {
        self.written >= self.bytes.len()
    }
}

/// Errors from the concrete relay socket I/O boundary.
///
/// Relay protocol failures stay in [`RelayError`]. This type adds the OS-facing
/// cases a nonblocking UDP loop must handle without weakening the deterministic
/// relay model or consuming queued packets before a socket write has completed.
#[derive(Debug, thiserror::Error)]
pub enum RelaySocketIoError {
    /// The socket was not ready for this nonblocking read or write attempt.
    #[error("relay socket would block")]
    WouldBlock,
    /// Caller scratch space cannot distinguish a valid maximum-size relay frame
    /// from a truncated oversized UDP datagram.
    #[error("relay UDP receive buffer too small: capacity {capacity}, required {required}")]
    DatagramBufferTooSmall {
        /// Caller-provided receive buffer length.
        capacity: usize,
        /// Minimum receive buffer length for this relay socket loop.
        required: usize,
    },
    /// UDP datagram filled the whole scratch buffer, so `std::net::UdpSocket`
    /// cannot prove whether bytes were truncated by the OS.
    #[error("relay UDP datagram may be truncated: received {received}, capacity {capacity}")]
    TruncatedDatagram {
        /// Bytes copied into the scratch buffer.
        received: usize,
        /// Caller-provided receive buffer length.
        capacity: usize,
    },
    /// UDP writes are datagram-oriented; a short successful write is treated as
    /// an I/O boundary failure instead of committing the relay queue entry.
    #[error("relay UDP socket short write: sent {sent} of {expected} bytes")]
    ShortUdpWrite {
        /// Bytes reported by `send_to`.
        sent: usize,
        /// Encoded datagram bytes expected.
        expected: usize,
    },
    /// Caller supplied no scratch space for a TCP/TLS stream read.
    #[error("relay TCP/TLS read buffer is empty")]
    TcpTlsReadBufferEmpty,
    /// TCP/TLS stream reached EOF and was closed by the socket loop.
    #[error("relay TCP/TLS stream closed: {stream_id:?}")]
    TcpTlsStreamClosed {
        /// Relay-local stream id that closed.
        stream_id: RelayTcpTlsStreamId,
    },
    /// A TCP/TLS stream writer accepted zero bytes while a record was pending.
    #[error(
        "relay TCP/TLS stream write made no progress: stream {stream_id:?}, remaining {remaining} bytes"
    )]
    TcpTlsWriteZero {
        /// Relay-local stream id being written.
        stream_id: RelayTcpTlsStreamId,
        /// Remaining bytes in the staged TCP/TLS record.
        remaining: usize,
    },
    /// Relay-level validation or state transition failed.
    #[error(transparent)]
    Relay {
        /// Relay error propagated from deterministic relay state.
        #[from]
        source: RelayError,
    },
    /// Operating-system socket I/O failed.
    #[error("relay socket I/O failed")]
    Io {
        /// Source socket error.
        #[source]
        source: io::Error,
    },
}

impl From<io::Error> for RelaySocketIoError {
    fn from(source: io::Error) -> Self {
        if source.kind() == io::ErrorKind::WouldBlock {
            Self::WouldBlock
        } else {
            Self::Io { source }
        }
    }
}

/// Deterministic summary for one relay socket service turn.
///
/// A production daemon can emit these fields as structured logs. Tests can use
/// them as replay-stable evidence that a turn made only the intended progress
/// and that socket readiness misses did not mutate relay state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelaySocketTurnSummary {
    /// UDP relay datagrams read from the OS socket and accepted by relay state.
    pub udp_datagrams_received: usize,
    /// UDP relay datagrams written to admitted peer socket endpoints.
    pub udp_datagrams_sent: usize,
    /// TCP/TLS stream read calls that supplied at least one byte to relay state.
    pub tcp_tls_chunks_read: usize,
    /// Opaque ATP packets forwarded from decoded TCP/TLS stream records.
    pub tcp_tls_packets_forwarded: usize,
    /// TCP/TLS streams that reached EOF and were closed by the socket loop.
    pub tcp_tls_streams_closed: usize,
    /// TCP/TLS bytes accepted by concrete stream writers.
    pub tcp_tls_bytes_written: usize,
    /// Nonblocking socket operations that had no readiness in this turn.
    pub socket_would_block: usize,
    /// Egress attempts that found no queued packet or record for the peer.
    pub empty_egress_attempts: usize,
}

impl RelaySocketTurnSummary {
    /// Return true when the turn moved any relay traffic or closed a stream.
    #[must_use]
    pub const fn made_progress(self) -> bool {
        self.udp_datagrams_received > 0
            || self.udp_datagrams_sent > 0
            || self.tcp_tls_chunks_read > 0
            || self.tcp_tls_packets_forwarded > 0
            || self.tcp_tls_streams_closed > 0
            || self.tcp_tls_bytes_written > 0
    }
}

/// Deterministic socket-facing relay loop state.
///
/// This is the boundary a real UDP socket loop or TCP/TLS accept/read/write loop
/// can use without trusting self-declared peer ids inside relay frames. Endpoint
/// admission binds physical socket identities to authenticated peers, TCP/TLS
/// stream buffers retain only incomplete records under a fixed bound, and egress
/// helpers resolve concrete socket destinations before dequeueing relay packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySocketLoop {
    endpoints: RelayEndpointDirectory,
    tcp_tls_streams: BTreeMap<RelayTcpTlsStreamId, RelayTcpTlsStreamBuffer>,
    tcp_tls_pending_writes: BTreeMap<RelayTcpTlsStreamId, RelayTcpTlsPendingWrite>,
    max_payload_bytes: usize,
    max_tcp_tls_buffered_bytes: usize,
    next_tcp_tls_stream_id: u128,
}

impl RelaySocketLoop {
    /// Construct an empty socket-loop state model.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] when endpoint, payload, or stream
    /// buffer bounds are unusable.
    pub fn new(
        endpoint_quota: RelayEndpointDirectoryQuota,
        max_payload_bytes: usize,
        max_tcp_tls_buffered_bytes: usize,
    ) -> Result<Self, RelayError> {
        let endpoints = RelayEndpointDirectory::new(endpoint_quota)?;
        let _ = RelayTcpTlsStreamBuffer::new(max_payload_bytes, max_tcp_tls_buffered_bytes)?;
        Ok(Self {
            endpoints,
            tcp_tls_streams: BTreeMap::new(),
            tcp_tls_pending_writes: BTreeMap::new(),
            max_payload_bytes,
            max_tcp_tls_buffered_bytes,
            next_tcp_tls_stream_id: 1,
        })
    }

    /// Borrow the current endpoint admission directory.
    #[must_use]
    pub const fn endpoints(&self) -> &RelayEndpointDirectory {
        &self.endpoints
    }

    /// Number of retained TCP/TLS stream buffers.
    #[must_use]
    pub fn tcp_tls_stream_buffer_count(&self) -> usize {
        self.tcp_tls_streams.len()
    }

    /// Number of staged TCP/TLS stream records that still have bytes to write.
    #[must_use]
    pub fn tcp_tls_pending_write_count(&self) -> usize {
        self.tcp_tls_pending_writes.len()
    }

    /// Minimum scratch-buffer capacity for [`Self::recv_udp_socket_once`].
    ///
    /// The extra byte is intentional. `std::net::UdpSocket::recv_from` does not
    /// expose a portable truncation flag, so the relay requires a scratch buffer
    /// one byte larger than the largest valid relay UDP frame. A read that fills
    /// that buffer is then known to be oversized or truncated and is rejected
    /// before any relay state is mutated.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] or [`RelayError::PacketTooLarge`]
    /// when the configured payload bound cannot produce a safe capacity.
    pub fn udp_socket_recv_buffer_capacity(&self) -> Result<usize, RelayError> {
        udp_socket_recv_buffer_capacity_for(self.max_payload_bytes)
    }

    /// Admit a UDP socket endpoint for an authenticated peer.
    ///
    /// # Errors
    ///
    /// Propagates endpoint validation, duplicate-binding, and quota errors from
    /// [`RelayEndpointDirectory::bind_udp_endpoint`].
    pub fn admit_udp_endpoint(
        &mut self,
        peer_id: PeerId,
        endpoint: SocketAddr,
    ) -> Result<(), RelayError> {
        self.endpoints.bind_udp_endpoint(peer_id, endpoint)
    }

    /// Close a UDP endpoint binding.
    pub fn close_udp_endpoint(&mut self, endpoint: SocketAddr) -> Option<PeerId> {
        self.endpoints.unbind_udp_endpoint(endpoint)
    }

    /// Admit a TCP/TLS stream for an authenticated peer and allocate its buffer.
    ///
    /// # Errors
    ///
    /// Propagates duplicate-binding and quota errors from the endpoint directory.
    pub fn admit_tcp_tls_stream(
        &mut self,
        peer_id: PeerId,
        stream_id: RelayTcpTlsStreamId,
    ) -> Result<(), RelayError> {
        let stream = if self.tcp_tls_streams.contains_key(&stream_id) {
            None
        } else {
            Some(RelayTcpTlsStreamBuffer::new(
                self.max_payload_bytes,
                self.max_tcp_tls_buffered_bytes,
            )?)
        };
        self.endpoints.bind_tcp_tls_stream(peer_id, stream_id)?;
        if let Some(stream) = stream {
            self.tcp_tls_streams.insert(stream_id, stream);
        }
        Ok(())
    }

    /// Close a TCP/TLS stream and discard retained partial record bytes.
    pub fn close_tcp_tls_stream(&mut self, stream_id: RelayTcpTlsStreamId) -> Option<PeerId> {
        self.tcp_tls_streams.remove(&stream_id);
        self.tcp_tls_pending_writes.remove(&stream_id);
        self.endpoints.unbind_tcp_tls_stream(stream_id)
    }

    /// Accept one TCP/TLS stream from a concrete listener and bind it to a peer.
    ///
    /// The peer id must already come from the caller's authenticated admission
    /// layer, such as TLS/session capability validation. This helper only joins
    /// the OS accept boundary to the relay-local stream id and endpoint
    /// directory. A nonblocking listener with no pending connection returns
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` for an empty nonblocking listener, OS I/O errors from
    /// `accept`, or relay admission errors such as quota exhaustion.
    pub fn accept_tcp_tls_stream_once(
        &mut self,
        listener: &TcpListener,
        peer_id: PeerId,
    ) -> Result<Option<RelayAcceptedTcpTlsStream>, RelaySocketIoError> {
        if self.endpoints.tcp_tls_stream_count() >= self.endpoints.quota.max_tcp_tls_streams {
            return Err(RelayError::QuotaExceeded.into());
        }

        let (stream, peer_addr) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stream_id = self.allocate_tcp_tls_stream_id()?;
        self.admit_tcp_tls_stream(peer_id, stream_id)?;
        Ok(Some(RelayAcceptedTcpTlsStream {
            stream_id,
            peer_id,
            peer_addr,
            stream,
        }))
    }

    /// Return pending incomplete bytes for an admitted TCP/TLS stream.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the stream is no longer
    /// admitted or its buffer has been closed.
    pub fn tcp_tls_pending_len(&self, stream_id: RelayTcpTlsStreamId) -> Result<usize, RelayError> {
        self.tcp_tls_streams
            .get(&stream_id)
            .map(RelayTcpTlsStreamBuffer::pending_len)
            .ok_or(RelayError::UnknownRelayEndpoint)
    }

    /// Return pending outbound bytes for an admitted TCP/TLS stream.
    ///
    /// This covers records already moved out of the relay queue into the socket
    /// loop's write buffer because a prior `write` accepted only a prefix.
    #[must_use]
    pub fn tcp_tls_pending_write_len(&self, stream_id: RelayTcpTlsStreamId) -> usize {
        self.tcp_tls_pending_writes
            .get(&stream_id)
            .map_or(0, RelayTcpTlsPendingWrite::remaining_len)
    }

    /// Ingest one UDP datagram read from a relay socket.
    ///
    /// The source address is resolved before frame decode, so unadmitted
    /// addresses cannot exercise reservation, nonce, quota, proof, or queue
    /// state.
    ///
    /// # Errors
    ///
    /// Returns endpoint, frame, auth, quota, lifecycle, or transport errors from
    /// the relay service.
    pub fn ingest_udp_datagram(
        &self,
        service: &mut RelayService,
        now_micros: u64,
        src_addr: SocketAddr,
        datagram: &[u8],
    ) -> Result<ForwardedPacket, RelayError> {
        service.forward_udp_datagram_from_endpoint(
            now_micros,
            &self.endpoints,
            src_addr,
            datagram,
            self.max_payload_bytes,
        )
    }

    /// Read and forward at most one datagram from a concrete UDP socket.
    ///
    /// This helper is intentionally one-shot: production loops should call it
    /// after readiness notification or on a nonblocking socket and preserve the
    /// returned `Ok(None)` as "no datagram was available." Endpoint admission is
    /// still checked before frame decode.
    ///
    /// # Errors
    ///
    /// Returns [`RelaySocketIoError::DatagramBufferTooSmall`] when `scratch`
    /// cannot safely detect truncation, [`RelaySocketIoError::TruncatedDatagram`]
    /// for oversized UDP input, OS socket errors, or relay validation errors.
    pub fn recv_udp_socket_once(
        &self,
        service: &mut RelayService,
        now_micros: u64,
        socket: &UdpSocket,
        scratch: &mut [u8],
    ) -> Result<Option<ForwardedPacket>, RelaySocketIoError> {
        let required = self.udp_socket_recv_buffer_capacity()?;
        if scratch.len() < required {
            return Err(RelaySocketIoError::DatagramBufferTooSmall {
                capacity: scratch.len(),
                required,
            });
        }

        let (received, src_addr) = match socket.recv_from(scratch) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if received == scratch.len() {
            return Err(RelaySocketIoError::TruncatedDatagram {
                received,
                capacity: scratch.len(),
            });
        }

        self.ingest_udp_datagram(service, now_micros, src_addr, &scratch[..received])
            .map(Some)
            .map_err(Into::into)
    }

    /// Read and forward at most one chunk from a concrete TCP/TLS stream.
    ///
    /// The stream must already be admitted to an authenticated peer. A
    /// nonblocking `WouldBlock` returns `Ok(None)` without mutating relay state.
    /// EOF closes the stream binding and discards retained partial input/output
    /// bytes for that stream.
    ///
    /// # Errors
    ///
    /// Returns [`RelaySocketIoError::TcpTlsReadBufferEmpty`] when `scratch` is
    /// empty, [`RelaySocketIoError::TcpTlsStreamClosed`] on EOF, OS socket errors,
    /// or relay validation errors from decoded records.
    pub fn recv_tcp_tls_stream_once<R: io::Read>(
        &mut self,
        service: &mut RelayService,
        now_micros: u64,
        stream_id: RelayTcpTlsStreamId,
        stream: &mut R,
        scratch: &mut [u8],
    ) -> Result<Option<Vec<ForwardedPacket>>, RelaySocketIoError> {
        if scratch.is_empty() {
            return Err(RelaySocketIoError::TcpTlsReadBufferEmpty);
        }

        let received = match stream.read(scratch) {
            Ok(0) => {
                let _ = self.close_tcp_tls_stream(stream_id);
                return Err(RelaySocketIoError::TcpTlsStreamClosed { stream_id });
            }
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        self.ingest_tcp_tls_stream_bytes(service, now_micros, stream_id, &scratch[..received])
            .map(Some)
            .map_err(Into::into)
    }

    /// Read and forward at most one chunk from an accepted TCP/TLS stream.
    ///
    /// This is the preferred concrete-stream entry point because the stream id
    /// and `TcpStream` stay bundled in the value returned by
    /// [`Self::accept_tcp_tls_stream_once`].
    ///
    /// # Errors
    ///
    /// Propagates [`Self::recv_tcp_tls_stream_once`] errors.
    pub fn recv_accepted_tcp_tls_stream_once(
        &mut self,
        service: &mut RelayService,
        now_micros: u64,
        accepted: &mut RelayAcceptedTcpTlsStream,
        scratch: &mut [u8],
    ) -> Result<Option<Vec<ForwardedPacket>>, RelaySocketIoError> {
        let stream_id = accepted.stream_id();
        self.recv_tcp_tls_stream_once(
            service,
            now_micros,
            stream_id,
            accepted.stream_mut(),
            scratch,
        )
    }

    /// Ingest bytes read from an admitted TCP/TLS 443 stream.
    ///
    /// Unknown streams are rejected before buffering. Admitted streams fail
    /// closed on decode or forwarding errors: the stream binding and incomplete
    /// bytes are removed so a malformed or unauthorized record cannot poison a
    /// later read.
    ///
    /// # Errors
    ///
    /// Returns endpoint, stream-buffer, frame, auth, quota, lifecycle, or
    /// transport errors from the relay service.
    pub fn ingest_tcp_tls_stream_bytes(
        &mut self,
        service: &mut RelayService,
        now_micros: u64,
        stream_id: RelayTcpTlsStreamId,
        bytes: &[u8],
    ) -> Result<Vec<ForwardedPacket>, RelayError> {
        let from_peer_id = self.endpoints.peer_for_tcp_tls_stream(stream_id)?;
        let result = match self.tcp_tls_streams.get_mut(&stream_id) {
            Some(stream) => {
                service.forward_tcp_tls_stream_bytes(now_micros, from_peer_id, stream, bytes)
            }
            None => Err(RelayError::UnknownRelayEndpoint),
        };
        if result.is_err() {
            let _ = self.close_tcp_tls_stream(stream_id);
        }
        result
    }

    /// Drain one queued UDP relay packet to the peer's admitted socket endpoint.
    ///
    /// The destination endpoint is resolved before dequeueing so peer disconnects
    /// do not silently drop queued relay traffic.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the peer has no admitted
    /// UDP endpoint, or encoding/state errors from the relay service.
    pub fn drain_udp_datagram_for_peer(
        &mut self,
        service: &mut RelayService,
        peer_id: PeerId,
    ) -> Result<Option<RelayUdpDatagram>, RelayError> {
        let dst_addr = self.endpoints.first_udp_endpoint_for_peer(peer_id)?;
        service.dequeue_udp_datagram_for_peer(peer_id, dst_addr, self.max_payload_bytes)
    }

    /// Write at most one queued UDP relay datagram to a concrete socket.
    ///
    /// The queued relay packet is only committed after `send_to` reports that
    /// the complete encoded datagram was accepted by the OS. A nonblocking
    /// `WouldBlock` or I/O error leaves the queue front intact for a later
    /// retry.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the peer has no admitted
    /// UDP endpoint, [`RelaySocketIoError::WouldBlock`] when a nonblocking socket
    /// cannot accept a write, [`RelaySocketIoError::ShortUdpWrite`] for an
    /// unexpected short datagram write, or relay encoding/state errors.
    pub fn send_udp_socket_once(
        &mut self,
        service: &mut RelayService,
        socket: &UdpSocket,
        peer_id: PeerId,
    ) -> Result<Option<usize>, RelaySocketIoError> {
        let dst_addr = self.endpoints.first_udp_endpoint_for_peer(peer_id)?;
        let Some(datagram) =
            service.peek_udp_datagram_for_peer(peer_id, dst_addr, self.max_payload_bytes)?
        else {
            return Ok(None);
        };

        let expected = datagram.payload().len();
        let sent = match socket.send_to(datagram.payload(), datagram.dst_addr()) {
            Ok(sent) => sent,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(RelaySocketIoError::WouldBlock);
            }
            Err(error) => return Err(error.into()),
        };
        if sent != expected {
            return Err(RelaySocketIoError::ShortUdpWrite { sent, expected });
        }

        service.commit_udp_datagram_for_peer(peer_id, datagram.reservation_id())?;
        Ok(Some(sent))
    }

    /// Drain one queued TCP/TLS relay record to the peer's admitted stream.
    ///
    /// The stream id is resolved before dequeueing so peer disconnects do not
    /// silently drop queued relay traffic.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the peer has no admitted
    /// TCP/TLS stream, or encoding/state errors from the relay service.
    pub fn drain_tcp_tls_record_for_peer(
        &mut self,
        service: &mut RelayService,
        peer_id: PeerId,
    ) -> Result<Option<RelayTcpTlsStreamWrite>, RelayError> {
        let stream_id = self.endpoints.first_tcp_tls_stream_for_peer(peer_id)?;
        let Some(record) =
            service.dequeue_tcp_tls_record_for_peer(peer_id, self.max_payload_bytes)?
        else {
            return Ok(None);
        };
        Ok(Some(RelayTcpTlsStreamWrite { stream_id, record }))
    }

    /// Write queued TCP/TLS relay bytes to an admitted concrete stream.
    ///
    /// TCP is a byte stream, so a successful write may accept only a prefix of
    /// the record. The socket loop therefore peeks a full relay record, writes
    /// it, commits the service queue only after the writer accepts at least one
    /// byte, and retains any suffix in an internal pending-write buffer. Later
    /// calls continue writing the retained suffix before another record can be
    /// dequeued for that stream. The explicit stream id resolves the
    /// authenticated peer before the queue is inspected, so a caller cannot
    /// drain another peer's queued record by passing an unrelated writer.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] when the peer has no admitted
    /// TCP/TLS stream, [`RelaySocketIoError::WouldBlock`] when a nonblocking
    /// stream cannot accept bytes, [`RelaySocketIoError::TcpTlsWriteZero`] when
    /// the writer makes no progress, or relay encoding/state errors.
    pub fn send_tcp_tls_stream_once<W: io::Write>(
        &mut self,
        service: &mut RelayService,
        stream_id: RelayTcpTlsStreamId,
        stream: &mut W,
    ) -> Result<Option<usize>, RelaySocketIoError> {
        let peer_id = self.endpoints.peer_for_tcp_tls_stream(stream_id)?;
        if !self.tcp_tls_pending_writes.contains_key(&stream_id) {
            let Some(record) =
                service.peek_tcp_tls_record_for_peer(peer_id, self.max_payload_bytes)?
            else {
                return Ok(None);
            };
            let reservation_id = record.reservation_id();
            let mut pending = RelayTcpTlsPendingWrite::from_record(record);
            let remaining_len = pending.remaining_len();
            let written = match stream.write(pending.remaining()) {
                Ok(0) => {
                    return Err(RelaySocketIoError::TcpTlsWriteZero {
                        stream_id,
                        remaining: remaining_len,
                    });
                }
                Ok(written) => written,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Err(RelaySocketIoError::WouldBlock);
                }
                Err(error) => return Err(error.into()),
            };
            pending.advance(written);
            service.commit_tcp_tls_record_for_peer(peer_id, reservation_id)?;
            if !pending.is_complete() {
                self.tcp_tls_pending_writes.insert(stream_id, pending);
            }
            return Ok(Some(written));
        }

        let pending = self
            .tcp_tls_pending_writes
            .get_mut(&stream_id)
            .ok_or(RelayError::UnknownRelayEndpoint)?;
        debug_assert_eq!(pending.peer_id, peer_id);
        let remaining_len = pending.remaining_len();
        let written = match stream.write(pending.remaining()) {
            Ok(0) => {
                return Err(RelaySocketIoError::TcpTlsWriteZero {
                    stream_id,
                    remaining: remaining_len,
                });
            }
            Ok(written) => written,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(RelaySocketIoError::WouldBlock);
            }
            Err(error) => return Err(error.into()),
        };
        pending.advance(written);
        if pending.is_complete() {
            let removed = self
                .tcp_tls_pending_writes
                .remove(&stream_id)
                .expect("pending write exists after completed write");
            debug_assert_eq!(removed.peer_id, peer_id);
        }

        Ok(Some(written))
    }

    /// Write queued TCP/TLS relay bytes to an accepted concrete stream.
    ///
    /// This is the preferred concrete-stream entry point because the stream id
    /// and writer stay bundled in the accepted-stream value.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::send_tcp_tls_stream_once`] errors.
    pub fn send_accepted_tcp_tls_stream_once(
        &mut self,
        service: &mut RelayService,
        accepted: &mut RelayAcceptedTcpTlsStream,
    ) -> Result<Option<usize>, RelaySocketIoError> {
        let stream_id = accepted.stream_id();
        self.send_tcp_tls_stream_once(service, stream_id, accepted.stream_mut())
    }

    /// Service one deterministic socket-loop turn over admitted UDP/TCP sockets.
    ///
    /// The turn performs at most one UDP read, at most one TCP read per accepted
    /// stream, at most one UDP write per admitted UDP peer, and at most one TCP
    /// write per accepted stream. Nonblocking readiness misses are counted in
    /// the returned summary and are not reported as hard failures. Other relay
    /// validation or OS errors fail the turn immediately without converting the
    /// deterministic relay model into an implicit retry loop.
    ///
    /// # Errors
    ///
    /// Returns malformed frame/auth/quota/lifecycle errors from the relay
    /// service, caller buffer errors, closed TCP/TLS stream errors converted into
    /// summary counters, TCP/TLS zero-progress writes, or non-`WouldBlock` OS
    /// I/O errors.
    pub fn service_socket_turn_once(
        &mut self,
        service: &mut RelayService,
        now_micros: u64,
        udp_socket: Option<&UdpSocket>,
        udp_scratch: &mut [u8],
        tcp_streams: &mut [RelayAcceptedTcpTlsStream],
        tcp_scratch: &mut [u8],
    ) -> Result<RelaySocketTurnSummary, RelaySocketIoError> {
        let mut summary = RelaySocketTurnSummary::default();

        if let Some(socket) = udp_socket {
            match self.recv_udp_socket_once(service, now_micros, socket, udp_scratch) {
                Ok(Some(_)) => summary.udp_datagrams_received += 1,
                Ok(None) | Err(RelaySocketIoError::WouldBlock) => {
                    summary.socket_would_block += 1;
                }
                Err(error) => return Err(error),
            }
        }

        for accepted in tcp_streams.iter_mut() {
            let stream_id = accepted.stream_id();
            if self.endpoints.peer_for_tcp_tls_stream(stream_id).is_err() {
                continue;
            }
            match self.recv_accepted_tcp_tls_stream_once(service, now_micros, accepted, tcp_scratch)
            {
                Ok(Some(forwarded)) => {
                    summary.tcp_tls_chunks_read += 1;
                    summary.tcp_tls_packets_forwarded += forwarded.len();
                }
                Ok(None) | Err(RelaySocketIoError::WouldBlock) => {
                    summary.socket_would_block += 1;
                }
                Err(RelaySocketIoError::TcpTlsStreamClosed { .. }) => {
                    summary.tcp_tls_streams_closed += 1;
                }
                Err(error) => return Err(error),
            }
        }

        if let Some(socket) = udp_socket {
            let udp_peers: BTreeSet<_> = self
                .endpoints
                .udp_endpoints
                .values()
                .map(|binding| binding.peer_id)
                .collect();
            for peer_id in udp_peers {
                match self.send_udp_socket_once(service, socket, peer_id) {
                    Ok(Some(_)) => summary.udp_datagrams_sent += 1,
                    Ok(None) => summary.empty_egress_attempts += 1,
                    Err(RelaySocketIoError::WouldBlock) => summary.socket_would_block += 1,
                    Err(error) => return Err(error),
                }
            }
        }

        for accepted in tcp_streams.iter_mut() {
            let stream_id = accepted.stream_id();
            if self.endpoints.peer_for_tcp_tls_stream(stream_id).is_err() {
                continue;
            }
            match self.send_accepted_tcp_tls_stream_once(service, accepted) {
                Ok(Some(written)) => summary.tcp_tls_bytes_written += written,
                Ok(None) => summary.empty_egress_attempts += 1,
                Err(RelaySocketIoError::WouldBlock) => summary.socket_would_block += 1,
                Err(error) => return Err(error),
            }
        }

        Ok(summary)
    }

    fn allocate_tcp_tls_stream_id(&mut self) -> Result<RelayTcpTlsStreamId, RelayError> {
        let start = self.next_tcp_tls_stream_id.max(1);
        let mut raw = start;
        loop {
            let stream_id = RelayTcpTlsStreamId::new(raw)?;
            self.next_tcp_tls_stream_id = raw.checked_add(1).unwrap_or(1);
            if !self.tcp_tls_streams.contains_key(&stream_id)
                && !self.endpoints.tcp_tls_streams.contains_key(&stream_id)
                && !self.tcp_tls_pending_writes.contains_key(&stream_id)
            {
                return Ok(stream_id);
            }
            raw = self.next_tcp_tls_stream_id;
            if raw == start {
                return Err(RelayError::QuotaExceeded);
            }
        }
    }
}

impl RelayTcpTlsStreamBuffer {
    /// Construct an empty bounded stream buffer.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] when either bound is zero or the
    /// buffer cannot hold the smallest possible TCP/TLS relay record.
    pub fn new(max_payload_bytes: usize, max_buffered_bytes: usize) -> Result<Self, RelayError> {
        if max_payload_bytes == 0
            || max_buffered_bytes < RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN + RELAY_WIRE_HEADER_LEN
        {
            return Err(RelayError::InvalidQuota);
        }
        Ok(Self {
            buffered: Vec::new(),
            max_payload_bytes,
            max_buffered_bytes,
        })
    }

    /// Number of buffered stream bytes that have not formed complete records.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.buffered.len()
    }

    /// Maximum pending stream bytes this adapter will retain.
    #[must_use]
    pub const fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
    }

    /// Remaining bytes that can be accepted before the buffer bound is hit.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.max_buffered_bytes.saturating_sub(self.buffered.len())
    }

    /// Discard buffered bytes after a caller closes a malformed stream.
    pub fn clear(&mut self) {
        self.buffered.clear();
    }

    /// Append bytes read from a TCP/TLS stream.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::PacketTooLarge`] when retaining `bytes` would
    /// exceed the configured stream-buffer bound.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<(), RelayError> {
        let next_len = self
            .buffered
            .len()
            .checked_add(bytes.len())
            .ok_or(RelayError::PacketTooLarge)?;
        if next_len > self.max_buffered_bytes {
            return Err(RelayError::PacketTooLarge);
        }
        self.buffered.extend_from_slice(bytes);
        Ok(())
    }

    /// Decode and remove the next complete record, if available.
    ///
    /// # Errors
    ///
    /// Returns relay frame validation errors for malformed records and
    /// [`RelayError::PacketTooLarge`] when an advertised record can never fit
    /// under this adapter's pending-byte bound. On error, the buffered bytes are
    /// left intact so the caller can close the stream and preserve the offending
    /// bytes for deterministic diagnostics.
    pub fn pop_next_frame(&mut self) -> Result<Option<RelayWireFrame>, RelayError> {
        match RelayWireFrame::decode_tcp_tls_record(&self.buffered, self.max_payload_bytes)? {
            RelayWireRecordDecode::NeedMore { minimum_len } => {
                if minimum_len > self.max_buffered_bytes {
                    return Err(RelayError::PacketTooLarge);
                }
                Ok(None)
            }
            RelayWireRecordDecode::Complete { frame, consumed } => {
                self.buffered.drain(..consumed);
                Ok(Some(frame))
            }
        }
    }

    /// Decode and remove every currently complete record.
    ///
    /// # Errors
    ///
    /// Returns relay frame validation errors for malformed records.
    pub fn drain_available_frames(&mut self) -> Result<Vec<RelayWireFrame>, RelayError> {
        let mut frames = Vec::new();
        while let Some(frame) = self.pop_next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }
}

impl RelayWireFrame {
    /// Construct a relay tunnel frame for one opaque ATP packet.
    #[must_use]
    pub const fn new(
        reservation_id: RelayReservationId,
        transfer_nonce: TransferNonce,
        from_peer_id: PeerId,
        packet: OpaqueRelayPacket,
    ) -> Self {
        Self {
            reservation_id,
            transfer_nonce,
            from_peer_id,
            packet,
        }
    }

    /// Reservation id carried on the relay tunnel frame.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.reservation_id
    }

    /// Transfer nonce bound into the relay reservation grant.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Peer that submitted this frame to the relay.
    #[must_use]
    pub const fn from_peer_id(&self) -> PeerId {
        self.from_peer_id
    }

    /// Opaque packet carried by this frame.
    #[must_use]
    pub const fn packet(&self) -> &OpaqueRelayPacket {
        &self.packet
    }

    /// Encode this frame into the canonical relay tunnel wire format.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] when `max_payload_bytes` is zero and
    /// [`RelayError::PacketTooLarge`] when the opaque packet cannot fit within
    /// the caller's transport policy.
    pub fn encode(&self, max_payload_bytes: usize) -> Result<Vec<u8>, RelayError> {
        let payload = self.packet.opaque_bytes();
        let payload_len = payload.len();
        if max_payload_bytes == 0 {
            return Err(RelayError::InvalidQuota);
        }
        if payload_len > max_payload_bytes || payload_len > u32::MAX as usize {
            return Err(RelayError::PacketTooLarge);
        }

        let encoded_len = RELAY_WIRE_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(RelayError::PacketTooLarge)?;
        let mut encoded = Vec::with_capacity(encoded_len);
        encoded.extend_from_slice(&RELAY_WIRE_MAGIC);
        encoded.push(RELAY_WIRE_VERSION);
        encoded.push(RELAY_WIRE_FORWARD_FRAME_KIND);
        encoded.push(self.packet.transport().wire_code());
        encoded.extend_from_slice(&self.reservation_id.get().to_be_bytes());
        encoded.extend_from_slice(&self.transfer_nonce.get().to_be_bytes());
        encoded.extend_from_slice(&self.from_peer_id.bytes());
        encoded.extend_from_slice(&self.packet.sequence().to_be_bytes());
        encoded.extend_from_slice(&self.packet.sent_at_micros().to_be_bytes());
        encoded.extend_from_slice(&self.packet.proof_tag().bytes());
        encoded.extend_from_slice(&(payload_len as u32).to_be_bytes());
        encoded.extend_from_slice(payload);
        Ok(encoded)
    }

    /// Encode this frame as one TCP/TLS 443 stream record.
    ///
    /// TCP/TLS fallback is a byte stream, so it needs an explicit record
    /// boundary around the canonical relay frame. UDP callers should use
    /// [`Self::encode`] directly.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidRelayWireFrame`] when the frame carries a
    /// non-TCP/TLS relay transport, and otherwise propagates [`Self::encode`]
    /// validation errors.
    pub fn encode_tcp_tls_record(&self, max_payload_bytes: usize) -> Result<Vec<u8>, RelayError> {
        if self.packet.transport() != RelayTransport::TcpTls443 {
            return Err(RelayError::InvalidRelayWireFrame);
        }
        let encoded_frame = self.encode(max_payload_bytes)?;
        let frame_len =
            u32::try_from(encoded_frame.len()).map_err(|_| RelayError::PacketTooLarge)?;
        let mut record =
            Vec::with_capacity(RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN + encoded_frame.len());
        record.extend_from_slice(&frame_len.to_be_bytes());
        record.extend_from_slice(&encoded_frame);
        Ok(record)
    }

    /// Decode a canonical relay tunnel frame from one complete datagram or an
    /// already isolated TCP/TLS record payload.
    ///
    /// Callers reading the TCP/TLS 443 byte stream should use
    /// [`Self::decode_tcp_tls_record`] so the length prefix is handled before
    /// this frame decoder runs.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::TruncatedRelayWireFrame`] for short input,
    /// [`RelayError::UnsupportedRelayWireVersion`] for future versions,
    /// [`RelayError::UnsupportedRelayWireFrameKind`] for unknown frame kinds,
    /// and validation errors for invalid identifiers, proof tags, or payloads.
    pub fn decode(bytes: &[u8], max_payload_bytes: usize) -> Result<Self, RelayError> {
        if max_payload_bytes == 0 {
            return Err(RelayError::InvalidQuota);
        }
        if bytes.len() < RELAY_WIRE_HEADER_LEN {
            return Err(RelayError::TruncatedRelayWireFrame);
        }
        if bytes[0..4] != RELAY_WIRE_MAGIC {
            return Err(RelayError::InvalidRelayWireFrame);
        }
        if bytes[4] != RELAY_WIRE_VERSION {
            return Err(RelayError::UnsupportedRelayWireVersion);
        }
        if bytes[5] != RELAY_WIRE_FORWARD_FRAME_KIND {
            return Err(RelayError::UnsupportedRelayWireFrameKind);
        }

        let transport = RelayTransport::from_wire_code(bytes[6])?;
        let reservation_id = RelayReservationId::new(read_u128(bytes, 7)?)?;
        let transfer_nonce = TransferNonce::new(read_u128(bytes, 23)?)
            .map_err(|_| RelayError::InvalidRelayWireFrame)?;
        let from_peer_id = PeerId::new(read_array::<32>(bytes, 39)?)
            .map_err(|_| RelayError::InvalidRelayWireFrame)?;
        let sequence = read_u64(bytes, 71)?;
        let sent_at_micros = read_u64(bytes, 79)?;
        let proof_tag = ProofTag::new(read_array::<32>(bytes, 87)?)?;
        let payload_len = read_u32(bytes, 119)? as usize;
        if payload_len == 0 {
            return Err(RelayError::EmptyPacket);
        }
        if payload_len > max_payload_bytes {
            return Err(RelayError::PacketTooLarge);
        }
        let expected_len = RELAY_WIRE_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(RelayError::PacketTooLarge)?;
        if bytes.len() < expected_len {
            return Err(RelayError::TruncatedRelayWireFrame);
        }
        if bytes.len() != expected_len {
            return Err(RelayError::InvalidRelayWireFrame);
        }
        let packet = OpaqueRelayPacket::new(
            sequence,
            transport,
            bytes[RELAY_WIRE_HEADER_LEN..expected_len].to_vec(),
            proof_tag,
            sent_at_micros,
        )?;

        Ok(Self {
            reservation_id,
            transfer_nonce,
            from_peer_id,
            packet,
        })
    }

    /// Decode the next TCP/TLS 443 stream record from the start of `bytes`.
    ///
    /// The decoder accepts coalesced records by reporting the number of bytes
    /// consumed, and it treats short buffers as [`RelayWireRecordDecode::NeedMore`]
    /// instead of an error so stream readers can accumulate bytes without
    /// conflating partial network delivery with malformed peer input.
    ///
    /// # Errors
    ///
    /// Returns validation errors for malformed record lengths or malformed
    /// relay frames.
    pub fn decode_tcp_tls_record(
        bytes: &[u8],
        max_payload_bytes: usize,
    ) -> Result<RelayWireRecordDecode, RelayError> {
        if max_payload_bytes == 0 {
            return Err(RelayError::InvalidQuota);
        }
        if bytes.len() < RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN {
            return Ok(RelayWireRecordDecode::NeedMore {
                minimum_len: RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN,
            });
        }

        let frame_len = read_u32(bytes, 0)? as usize;
        if frame_len < RELAY_WIRE_HEADER_LEN {
            return Err(RelayError::InvalidRelayWireFrame);
        }
        let max_frame_len = RELAY_WIRE_HEADER_LEN
            .checked_add(max_payload_bytes)
            .ok_or(RelayError::PacketTooLarge)?;
        if frame_len > max_frame_len {
            return Err(RelayError::PacketTooLarge);
        }
        let record_len = RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN
            .checked_add(frame_len)
            .ok_or(RelayError::PacketTooLarge)?;
        if bytes.len() < record_len {
            return Ok(RelayWireRecordDecode::NeedMore {
                minimum_len: record_len,
            });
        }

        let frame = Self::decode(
            &bytes[RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN..record_len],
            max_payload_bytes,
        )?;
        if frame.packet.transport() != RelayTransport::TcpTls443 {
            return Err(RelayError::InvalidRelayWireFrame);
        }

        Ok(RelayWireRecordDecode::Complete {
            frame,
            consumed: record_len,
        })
    }

    /// Decode exactly one TCP/TLS 443 stream record.
    ///
    /// This helper is useful for tests and length-delimited readers that have
    /// already isolated one record. Stream readers that may hold partial or
    /// coalesced bytes should use [`Self::decode_tcp_tls_record`].
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::TruncatedRelayWireFrame`] for incomplete records,
    /// [`RelayError::InvalidRelayWireFrame`] for trailing bytes after the first
    /// complete record, and validation errors for malformed frames.
    pub fn decode_complete_tcp_tls_record(
        bytes: &[u8],
        max_payload_bytes: usize,
    ) -> Result<Self, RelayError> {
        match Self::decode_tcp_tls_record(bytes, max_payload_bytes)? {
            RelayWireRecordDecode::NeedMore { .. } => Err(RelayError::TruncatedRelayWireFrame),
            RelayWireRecordDecode::Complete { frame, consumed } if consumed == bytes.len() => {
                Ok(frame)
            }
            RelayWireRecordDecode::Complete { .. } => Err(RelayError::InvalidRelayWireFrame),
        }
    }

    /// Submit this decoded frame into the relay service forwarding path.
    ///
    /// # Errors
    ///
    /// Propagates [`RelayService::forward`] validation errors.
    pub fn forward_into(
        self,
        service: &mut RelayService,
        now_micros: u64,
    ) -> Result<ForwardedPacket, RelayError> {
        service.forward_wire_frame(now_micros, self)
    }
}

/// Per-reservation relay quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayQuota {
    /// Maximum packets accepted for one reservation.
    pub max_packets_per_reservation: u64,
    /// Maximum opaque bytes accepted for one reservation.
    pub max_bytes_per_reservation: u64,
    /// Maximum opaque bytes accepted in one packet.
    pub max_packet_bytes: usize,
}

impl RelayQuota {
    /// Validate quota fields.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] when any quota bound is zero.
    pub const fn validate(self) -> Result<Self, RelayError> {
        if self.max_packets_per_reservation == 0
            || self.max_bytes_per_reservation == 0
            || self.max_packet_bytes == 0
        {
            return Err(RelayError::InvalidQuota);
        }
        Ok(self)
    }
}

impl Default for RelayQuota {
    fn default() -> Self {
        Self {
            max_packets_per_reservation: 4_096,
            max_bytes_per_reservation: 64 * 1024 * 1024,
            max_packet_bytes: 64 * 1024,
        }
    }
}

/// Transfer-scoped grant authorizing two peers to use a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayReservationGrant {
    source_peer_id: PeerId,
    destination_peer_id: PeerId,
    transfer_nonce: TransferNonce,
    expires_at_micros: u64,
    quota: RelayQuota,
    allowed_transports: BTreeSet<RelayTransport>,
    signature: CandidateSignature,
}

impl RelayReservationGrant {
    /// Build a relay reservation grant.
    ///
    /// # Errors
    ///
    /// Returns an error for identical peers, invalid quotas, empty transport
    /// policy, or an already-expired grant.
    pub fn new(
        source_peer_id: PeerId,
        destination_peer_id: PeerId,
        transfer_nonce: TransferNonce,
        expires_at_micros: u64,
        quota: RelayQuota,
        allowed_transports: &[RelayTransport],
        signature: CandidateSignature,
    ) -> Result<Self, RelayError> {
        if source_peer_id == destination_peer_id {
            return Err(RelayError::LoopbackReservation);
        }
        if expires_at_micros == 0 {
            return Err(RelayError::ExpiredReservation);
        }

        let allowed_transports = allowed_transports.iter().copied().collect::<BTreeSet<_>>();
        if allowed_transports.is_empty() {
            return Err(RelayError::TransportUnavailable);
        }

        Ok(Self {
            source_peer_id,
            destination_peer_id,
            transfer_nonce,
            expires_at_micros,
            quota: quota.validate()?,
            allowed_transports,
            signature,
        })
    }

    /// Build the normal UDP-first, TCP/TLS 443 fallback grant.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::new`] validation errors.
    pub fn udp_first_tcp_tls_443(
        source_peer_id: PeerId,
        destination_peer_id: PeerId,
        transfer_nonce: TransferNonce,
        expires_at_micros: u64,
        quota: RelayQuota,
        signature: CandidateSignature,
    ) -> Result<Self, RelayError> {
        Self::new(
            source_peer_id,
            destination_peer_id,
            transfer_nonce,
            expires_at_micros,
            quota,
            &[RelayTransport::Udp, RelayTransport::TcpTls443],
            signature,
        )
    }

    /// Source peer allowed to send through this reservation.
    #[must_use]
    pub const fn source_peer_id(&self) -> PeerId {
        self.source_peer_id
    }

    /// Destination peer allowed to send through this reservation.
    #[must_use]
    pub const fn destination_peer_id(&self) -> PeerId {
        self.destination_peer_id
    }

    /// Transfer nonce bound into this grant.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Grant expiry timestamp.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    /// Quota bound into this grant.
    #[must_use]
    pub const fn quota(&self) -> RelayQuota {
        self.quota
    }

    /// Grant signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &CandidateSignature {
        &self.signature
    }

    /// Whether a transport is allowed by the endpoint-signed grant.
    #[must_use]
    pub fn allows_transport(&self, transport: RelayTransport) -> bool {
        self.allowed_transports.contains(&transport)
    }
}

/// Authorization verifier for relay grants.
pub trait RelayAuthorizationVerifier {
    /// Return true when the relay grant is authentic and transfer-scoped.
    fn verify(&self, grant: &RelayReservationGrant) -> bool;
}

impl<F> RelayAuthorizationVerifier for F
where
    F: Fn(&RelayReservationGrant) -> bool,
{
    fn verify(&self, grant: &RelayReservationGrant) -> bool {
        self(grant)
    }
}

/// Self-hosted relay service configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServiceConfig {
    relay_id: String,
    max_active_reservations: usize,
    udp_enabled: bool,
    tcp_tls_443_enabled: bool,
    retain_state_on_restart: bool,
    log_peer_ids: bool,
}

impl RelayServiceConfig {
    /// Construct relay service config.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::EmptyRelayId`] when the relay id is blank and
    /// [`RelayError::InvalidQuota`] when `max_active_reservations` is zero.
    pub fn new(
        relay_id: impl Into<String>,
        max_active_reservations: usize,
    ) -> Result<Self, RelayError> {
        let relay_id = relay_id.into();
        if relay_id.trim().is_empty() {
            return Err(RelayError::EmptyRelayId);
        }
        if max_active_reservations == 0 {
            return Err(RelayError::InvalidQuota);
        }

        Ok(Self {
            relay_id,
            max_active_reservations,
            udp_enabled: true,
            tcp_tls_443_enabled: true,
            retain_state_on_restart: true,
            log_peer_ids: false,
        })
    }

    /// Relay id used in logs and proof artifacts.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Maximum active reservations accepted by this relay.
    #[must_use]
    pub const fn max_active_reservations(&self) -> usize {
        self.max_active_reservations
    }

    /// Whether UDP relay is enabled.
    #[must_use]
    pub const fn udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// Whether TCP/TLS 443 fallback is enabled.
    #[must_use]
    pub const fn tcp_tls_443_enabled(&self) -> bool {
        self.tcp_tls_443_enabled
    }

    /// Whether restart snapshots should retain active relay state.
    #[must_use]
    pub const fn retain_state_on_restart(&self) -> bool {
        self.retain_state_on_restart
    }

    /// Whether logs may include redacted peer id prefixes.
    #[must_use]
    pub const fn log_peer_ids(&self) -> bool {
        self.log_peer_ids
    }

    /// Configure UDP availability.
    #[must_use]
    pub const fn with_udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
    }

    /// Configure TCP/TLS 443 fallback availability.
    #[must_use]
    pub const fn with_tcp_tls_443_enabled(mut self, enabled: bool) -> Self {
        self.tcp_tls_443_enabled = enabled;
        self
    }

    /// Configure restart retention.
    #[must_use]
    pub const fn with_retain_state_on_restart(mut self, retain: bool) -> Self {
        self.retain_state_on_restart = retain;
        self
    }

    /// Configure peer id redaction in event logs.
    #[must_use]
    pub const fn with_log_peer_ids(mut self, enabled: bool) -> Self {
        self.log_peer_ids = enabled;
        self
    }
}

impl Default for RelayServiceConfig {
    fn default() -> Self {
        Self {
            relay_id: "local-atp-relay".to_owned(),
            max_active_reservations: 1024,
            udp_enabled: true,
            tcp_tls_443_enabled: true,
            retain_state_on_restart: true,
            log_peer_ids: false,
        }
    }
}

/// Relay path candidate emitted after a reservation is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPathCandidate {
    reservation_id: RelayReservationId,
    path_id: String,
    primary_transport: RelayTransport,
    fallback_transport: Option<RelayTransport>,
    relay_id: String,
}

impl RelayPathCandidate {
    /// Reservation id backing this path.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.reservation_id
    }

    /// Path id used by path racing and proof artifacts.
    #[must_use]
    pub fn path_id(&self) -> &str {
        &self.path_id
    }

    /// Primary transport, preferring UDP when available.
    #[must_use]
    pub const fn primary_transport(&self) -> RelayTransport {
        self.primary_transport
    }

    /// Optional fallback transport.
    #[must_use]
    pub const fn fallback_transport(&self) -> Option<RelayTransport> {
        self.fallback_transport
    }

    /// Relay id selected for this path.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Shared path graph kind represented by the primary relay transport.
    #[must_use]
    pub const fn path_kind(&self) -> PathKind {
        self.primary_transport.path_kind()
    }

    /// Shared path graph kind represented by the fallback relay transport.
    #[must_use]
    pub fn fallback_path_kind(&self) -> Option<PathKind> {
        self.fallback_transport.map(RelayTransport::path_kind)
    }

    /// Convert this relay reservation into the shared ATP path graph model.
    ///
    /// The caller supplies the path-candidate id and trace id because those are
    /// race-local identities. The relay reservation id remains in the relay
    /// proof artifact, while the path graph receives the transport kind,
    /// security defaults, and deterministic attempt budget it needs for racing
    /// and loser-drain diagnostics.
    #[must_use]
    pub fn to_path_candidate(&self, id: PathCandidateId, trace_id: PathTraceId) -> PathCandidate {
        let kind = self.path_kind();
        PathCandidate::new(id, kind, trace_id)
            .with_budget(PathBudget::default())
            .with_security(PathSecurity::for_kind(kind))
    }
}

/// Packet emitted from a relay queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedPacket {
    reservation_id: RelayReservationId,
    from_peer_id: PeerId,
    to_peer_id: PeerId,
    packet: OpaqueRelayPacket,
    received_at_micros: u64,
}

impl ForwardedPacket {
    /// Reservation id used for the forwarded packet.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.reservation_id
    }

    /// Source peer.
    #[must_use]
    pub const fn from_peer_id(&self) -> PeerId {
        self.from_peer_id
    }

    /// Destination peer.
    #[must_use]
    pub const fn to_peer_id(&self) -> PeerId {
        self.to_peer_id
    }

    /// Opaque packet forwarded unchanged.
    #[must_use]
    pub const fn packet(&self) -> &OpaqueRelayPacket {
        &self.packet
    }

    /// Relay receive timestamp.
    #[must_use]
    pub const fn received_at_micros(&self) -> u64 {
        self.received_at_micros
    }
}

/// Encoded UDP datagram ready for a relay socket send.
///
/// This is the socket-facing representation of a queued relay packet. It carries
/// the canonical [`RelayWireFrame`] bytes and destination endpoint selected by
/// the caller's peer directory. The payload is still opaque ATP ciphertext plus
/// relay routing/proof metadata; the relay does not inspect object plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUdpDatagram {
    dst_addr: SocketAddr,
    to_peer_id: PeerId,
    reservation_id: RelayReservationId,
    payload: Vec<u8>,
    opaque_bytes: u64,
}

impl RelayUdpDatagram {
    /// Destination socket address for this datagram.
    #[must_use]
    pub const fn dst_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    /// Peer id whose endpoint should receive this datagram.
    #[must_use]
    pub const fn to_peer_id(&self) -> PeerId {
        self.to_peer_id
    }

    /// Reservation id represented by the encoded frame.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.reservation_id
    }

    /// Canonical relay frame bytes to send over UDP.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume this value and return the datagram payload bytes.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Number of opaque ATP ciphertext bytes represented by this datagram.
    #[must_use]
    pub const fn opaque_bytes(&self) -> u64 {
        self.opaque_bytes
    }
}

/// Encoded TCP/TLS 443 stream record ready for a relay socket write.
///
/// Unlike UDP, TCP/TLS fallback is a byte stream, so the canonical
/// [`RelayWireFrame`] is wrapped in the length-prefixed stream record format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTcpTlsRecord {
    to_peer_id: PeerId,
    reservation_id: RelayReservationId,
    bytes: Vec<u8>,
    opaque_bytes: u64,
}

impl RelayTcpTlsRecord {
    /// Peer id whose TCP/TLS stream should receive this record.
    #[must_use]
    pub const fn to_peer_id(&self) -> PeerId {
        self.to_peer_id
    }

    /// Reservation id represented by the encoded record.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.reservation_id
    }

    /// Length-prefixed TCP/TLS relay record bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume this value and return the stream record bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of opaque ATP ciphertext bytes represented by this record.
    #[must_use]
    pub const fn opaque_bytes(&self) -> u64 {
        self.opaque_bytes
    }
}

/// Packet loss summary for a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLossSummary {
    /// Lost packets.
    pub lost_packets: u64,
    /// Total packets considered.
    pub total_packets: u64,
    /// Loss ratio in parts per million.
    pub loss_ppm: u32,
}

/// Per-reservation relay latency summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLatencySummary {
    /// Number of latency samples included.
    pub sample_count: u64,
    /// Latest observed relay latency.
    pub latest_latency_micros: u64,
    /// Minimum observed relay latency.
    pub min_latency_micros: u64,
    /// Maximum observed relay latency.
    pub max_latency_micros: u64,
    /// Sum of all observed relay latencies.
    pub total_latency_micros: u64,
    /// Truncated arithmetic mean of observed relay latencies.
    pub average_latency_micros: u64,
}

impl RelayLatencySummary {
    fn first(latency_micros: u64) -> Self {
        Self {
            sample_count: 1,
            latest_latency_micros: latency_micros,
            min_latency_micros: latency_micros,
            max_latency_micros: latency_micros,
            total_latency_micros: latency_micros,
            average_latency_micros: latency_micros,
        }
    }

    fn record(&mut self, latency_micros: u64) {
        self.sample_count = self.sample_count.saturating_add(1);
        self.latest_latency_micros = latency_micros;
        self.min_latency_micros = self.min_latency_micros.min(latency_micros);
        self.max_latency_micros = self.max_latency_micros.max(latency_micros);
        self.total_latency_micros = self.total_latency_micros.saturating_add(latency_micros);
        self.average_latency_micros = self.total_latency_micros / self.sample_count.max(1);
    }
}

/// Per-reservation forwarding counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayUsage {
    /// Forwarded packet count.
    pub forwarded_packets: u64,
    /// Forwarded opaque byte count.
    pub forwarded_bytes: u64,
    /// Packets intentionally dropped or reported lost.
    pub dropped_packets: u64,
    /// Packets forwarded over UDP.
    pub udp_packets: u64,
    /// Packets forwarded over TCP/TLS 443.
    pub tcp_tls_443_packets: u64,
    /// Most recent loss summary.
    pub loss_summary: Option<RelayLossSummary>,
    /// Relay receive latency summary.
    pub latency_summary: Option<RelayLatencySummary>,
}

impl RelayUsage {
    fn record_latency(&mut self, latency_micros: u64) {
        match &mut self.latency_summary {
            Some(summary) => summary.record(latency_micros),
            None => self.latency_summary = Some(RelayLatencySummary::first(latency_micros)),
        }
    }
}

/// Redaction-safe relay event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEventKind {
    /// Reservation accepted.
    ReservationAccepted,
    /// Packet forwarded.
    PacketForwarded,
    /// Packet loss recorded.
    PacketLossRecorded,
    /// Quota rejected a packet or reservation.
    QuotaRejected,
    /// Authorization rejected a grant or packet sender.
    AuthorizationRejected,
    /// Reservation expired.
    ReservationExpired,
    /// Reservation cancelled.
    ReservationCancelled,
    /// State restored after restart.
    RestartRestored,
}

/// Redaction-safe relay event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEvent {
    /// Event kind.
    pub kind: RelayEventKind,
    /// Relay id.
    pub relay_id: String,
    /// Reservation id, when scoped to one reservation.
    pub reservation_id: Option<RelayReservationId>,
    /// Transfer nonce, when scoped to one transfer.
    pub transfer_nonce: Option<TransferNonce>,
    /// Path id, when available.
    pub path_id: Option<String>,
    /// Redacted source peer id.
    pub from_peer: Option<String>,
    /// Redacted destination peer id.
    pub to_peer: Option<String>,
    /// Relay transport, when applicable.
    pub transport: Option<RelayTransport>,
    /// Opaque byte count.
    pub opaque_bytes: u64,
    /// Loss summary visible in this log event, if known.
    pub loss_summary: Option<RelayLossSummary>,
    /// Relay latency summary visible in this log event, if known.
    pub latency_summary: Option<RelayLatencySummary>,
    /// Stable quota decision code.
    pub quota_decision: &'static str,
    /// Fallback reason, when TCP/TLS 443 is used.
    pub fallback_reason: Option<&'static str>,
    /// Deterministic replay pointer.
    pub replay_pointer: u64,
}

/// Proof artifact for path diagnostics and replay logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayProofArtifact {
    /// Relay id.
    pub relay_id: String,
    /// Reservation id.
    pub reservation_id: RelayReservationId,
    /// Transfer nonce.
    pub transfer_nonce: TransferNonce,
    /// Path id used by path racing.
    pub path_id: String,
    /// Primary transport.
    pub primary_transport: RelayTransport,
    /// Optional fallback transport.
    pub fallback_transport: Option<RelayTransport>,
    /// Reservation acceptance time in monotonic microseconds.
    pub accepted_at_micros: u64,
    /// Stable quota decision code.
    pub quota_decision: &'static str,
    /// Stable fallback reason code.
    pub fallback_reason: Option<&'static str>,
    /// Opaque bytes forwarded.
    pub opaque_bytes_forwarded: u64,
    /// Packets forwarded.
    pub packets_forwarded: u64,
    /// Loss summary, if recorded.
    pub loss_summary: Option<RelayLossSummary>,
    /// Relay latency summary, if packets were forwarded.
    pub latency_summary: Option<RelayLatencySummary>,
    /// Redacted source peer id.
    pub redacted_source_peer: String,
    /// Redacted destination peer id.
    pub redacted_destination_peer: String,
    /// Replay pointer for deterministic logs.
    pub replay_pointer: u64,
    /// Relay preserved end-to-end proof tags without minting verified chunks.
    pub e2e_proof_preserved: bool,
}

impl RelayProofArtifact {
    /// Convert relay proof telemetry into a shared path-race success outcome.
    ///
    /// The relay still does not verify object plaintext or mint verified
    /// chunks. The byte counters copied into the path outcome are opaque relay
    /// bytes used for diagnostics and replay correlation.
    #[must_use]
    pub const fn to_path_success_outcome(
        &self,
        completed_at_micros: u64,
        observed_rtt_micros: Option<u64>,
    ) -> PathOutcome {
        PathOutcome::success(
            PathSuccessKind::RelaySelected,
            completed_at_micros,
            observed_rtt_micros,
        )
        .with_bytes(self.opaque_bytes_forwarded, self.opaque_bytes_forwarded)
    }
}

/// Restart snapshot for self-hosted relay recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRestartSnapshot {
    config: RelayServiceConfig,
    reservations: Vec<(RelayReservationId, RelayReservationState)>,
    usage: Vec<(RelayReservationId, RelayUsage)>,
    queues: Vec<(PeerId, Vec<ForwardedPacket>)>,
    events: Vec<RelayEvent>,
    replay_pointer: u64,
}

impl RelayRestartSnapshot {
    /// Number of active reservations captured.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }
}

/// In-memory deterministic relay service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayService {
    config: RelayServiceConfig,
    reservations: BTreeMap<RelayReservationId, RelayReservationState>,
    usage: BTreeMap<RelayReservationId, RelayUsage>,
    queues: BTreeMap<PeerId, VecDeque<ForwardedPacket>>,
    events: Vec<RelayEvent>,
    replay_pointer: u64,
}

impl RelayService {
    /// Construct an empty relay service.
    #[must_use]
    pub fn new(config: RelayServiceConfig) -> Self {
        Self {
            config,
            reservations: BTreeMap::new(),
            usage: BTreeMap::new(),
            queues: BTreeMap::new(),
            events: Vec::new(),
            replay_pointer: 0,
        }
    }

    /// Relay service config.
    #[must_use]
    pub const fn config(&self) -> &RelayServiceConfig {
        &self.config
    }

    /// Redaction-safe event log.
    #[must_use]
    pub fn events(&self) -> &[RelayEvent] {
        &self.events
    }

    /// Per-reservation usage counters.
    #[must_use]
    pub fn usage(&self, reservation_id: RelayReservationId) -> Option<RelayUsage> {
        self.usage.get(&reservation_id).copied()
    }

    /// Accept a relay reservation and emit a path candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when auth, expiry, quota, transport, or path-id
    /// validation fails.
    pub fn reserve<V>(
        &mut self,
        now_micros: u64,
        reservation_id: RelayReservationId,
        path_id: impl Into<String>,
        grant: RelayReservationGrant,
        verifier: &V,
    ) -> Result<RelayPathCandidate, RelayError>
    where
        V: RelayAuthorizationVerifier,
    {
        let path_id = path_id.into();
        if path_id.trim().is_empty() {
            return Err(RelayError::EmptyPathId);
        }
        if !verifier.verify(&grant) {
            self.push_event(RelayEventDraft {
                kind: RelayEventKind::AuthorizationRejected,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(grant.transfer_nonce),
                path_id: Some(path_id.clone()),
                from_peer: Some(grant.source_peer_id),
                to_peer: Some(grant.destination_peer_id),
                transport: None,
                opaque_bytes: 0,
                loss_summary: None,
                latency_summary: None,
                quota_decision: "grant_authorization_rejected",
                fallback_reason: None,
            });
            return Err(RelayError::InvalidAuthorization);
        }
        if grant.expires_at_micros <= now_micros {
            return Err(RelayError::ExpiredReservation);
        }
        let _expired_reservations = self.expire_reservations(now_micros);
        if self.reservations.contains_key(&reservation_id) {
            return Err(RelayError::DuplicateReservation);
        }
        if self.active_reservation_count(now_micros) >= self.config.max_active_reservations {
            self.push_event(RelayEventDraft {
                kind: RelayEventKind::QuotaRejected,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(grant.transfer_nonce),
                path_id: Some(path_id.clone()),
                from_peer: Some(grant.source_peer_id),
                to_peer: Some(grant.destination_peer_id),
                transport: None,
                opaque_bytes: 0,
                loss_summary: None,
                latency_summary: None,
                quota_decision: "active_reservation_quota_rejected",
                fallback_reason: None,
            });
            return Err(RelayError::QuotaExceeded);
        }

        let (primary_transport, fallback_transport) = self.select_transports(&grant)?;
        let state = RelayReservationState {
            grant,
            path_id: path_id.clone(),
            accepted_at_micros: now_micros,
            primary_transport,
            fallback_transport,
            cancelled: false,
            expired: false,
        };

        self.push_event(RelayEventDraft {
            kind: RelayEventKind::ReservationAccepted,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(path_id.clone()),
            from_peer: Some(state.grant.source_peer_id),
            to_peer: Some(state.grant.destination_peer_id),
            transport: Some(primary_transport),
            opaque_bytes: 0,
            loss_summary: None,
            latency_summary: None,
            quota_decision: "reservation_accepted",
            fallback_reason: primary_transport.fallback_reason(),
        });

        let candidate = RelayPathCandidate {
            reservation_id,
            path_id,
            primary_transport,
            fallback_transport,
            relay_id: self.config.relay_id.clone(),
        };
        self.reservations.insert(reservation_id, state);
        self.usage.insert(reservation_id, RelayUsage::default());
        Ok(candidate)
    }

    /// Forward an opaque encrypted packet between authorized peers.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unknown, unauthorized, expired,
    /// cancelled, over quota, or uses an unavailable transport.
    pub fn forward(
        &mut self,
        now_micros: u64,
        reservation_id: RelayReservationId,
        from_peer_id: PeerId,
        packet: OpaqueRelayPacket,
    ) -> Result<ForwardedPacket, RelayError> {
        let state = self
            .reservations
            .get(&reservation_id)
            .cloned()
            .ok_or(RelayError::UnknownReservation)?;

        let to_peer_id = if from_peer_id == state.grant.source_peer_id {
            state.grant.destination_peer_id
        } else if from_peer_id == state.grant.destination_peer_id {
            state.grant.source_peer_id
        } else {
            self.push_event(RelayEventDraft {
                kind: RelayEventKind::AuthorizationRejected,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(state.grant.transfer_nonce),
                path_id: Some(state.path_id.clone()),
                from_peer: Some(from_peer_id),
                to_peer: None,
                transport: Some(packet.transport),
                opaque_bytes: packet.opaque_len() as u64,
                loss_summary: None,
                latency_summary: None,
                quota_decision: "peer_authorization_rejected",
                fallback_reason: None,
            });
            return Err(RelayError::UnauthorizedPeer);
        };

        if state.cancelled {
            return Err(RelayError::ReservationCancelled);
        }
        if state.expired || state.grant.expires_at_micros <= now_micros {
            self.expire_reservation(reservation_id)?;
            return Err(RelayError::ExpiredReservation);
        }

        if !state.grant.allows_transport(packet.transport)
            || !self.transport_available(packet.transport)
        {
            return Err(RelayError::TransportUnavailable);
        }

        let usage_snapshot = self.apply_quota(
            reservation_id,
            &state,
            from_peer_id,
            to_peer_id,
            &packet,
            now_micros,
        )?;

        let forwarded = ForwardedPacket {
            reservation_id,
            from_peer_id,
            to_peer_id,
            packet,
            received_at_micros: now_micros,
        };

        self.queues
            .entry(to_peer_id)
            .or_default()
            .push_back(forwarded.clone());

        self.push_event(RelayEventDraft {
            kind: RelayEventKind::PacketForwarded,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(state.path_id.clone()),
            from_peer: Some(from_peer_id),
            to_peer: Some(to_peer_id),
            transport: Some(forwarded.packet.transport),
            opaque_bytes: forwarded.packet.opaque_len() as u64,
            loss_summary: usage_snapshot.loss_summary,
            latency_summary: usage_snapshot.latency_summary,
            quota_decision: "packet_accepted",
            fallback_reason: forwarded.packet.transport.fallback_reason(),
        });

        Ok(forwarded)
    }

    /// Authenticate and forward a decoded relay tunnel frame.
    ///
    /// This is the transport-neutral boundary for already authenticated frame
    /// sources. Socket adapters that know the physical endpoint identity should
    /// call [`Self::forward_wire_frame_from_peer`] so the frame source cannot be
    /// self-declared by untrusted bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidAuthorization`] when the frame nonce does
    /// not match the reservation grant. Otherwise propagates [`Self::forward`]
    /// validation errors.
    pub fn forward_wire_frame(
        &mut self,
        now_micros: u64,
        frame: RelayWireFrame,
    ) -> Result<ForwardedPacket, RelayError> {
        let state = self
            .reservations
            .get(&frame.reservation_id)
            .cloned()
            .ok_or(RelayError::UnknownReservation)?;
        if state.grant.transfer_nonce != frame.transfer_nonce {
            self.push_event(RelayEventDraft {
                kind: RelayEventKind::AuthorizationRejected,
                reservation_id: Some(frame.reservation_id),
                transfer_nonce: Some(frame.transfer_nonce),
                path_id: Some(state.path_id),
                from_peer: Some(frame.from_peer_id),
                to_peer: None,
                transport: Some(frame.packet.transport),
                opaque_bytes: frame.packet.opaque_len() as u64,
                loss_summary: None,
                latency_summary: None,
                quota_decision: "transfer_nonce_mismatch_rejected",
                fallback_reason: None,
            });
            return Err(RelayError::InvalidAuthorization);
        }

        self.forward(
            now_micros,
            frame.reservation_id,
            frame.from_peer_id,
            frame.packet,
        )
    }

    /// Authenticate and forward a decoded frame from an endpoint-admitted peer.
    ///
    /// Socket loops should use this boundary after UDP address admission, TLS
    /// session authentication, or peer-directory lookup has mapped the physical
    /// endpoint to `from_peer_id`. The frame's self-declared source must match
    /// that authenticated peer identity before reservation auth, quota, usage, or
    /// queue state can be mutated.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnauthorizedPeer`] when endpoint admission and frame
    /// metadata disagree. Otherwise propagates [`Self::forward_wire_frame`]
    /// validation errors.
    pub fn forward_wire_frame_from_peer(
        &mut self,
        now_micros: u64,
        from_peer_id: PeerId,
        frame: RelayWireFrame,
    ) -> Result<ForwardedPacket, RelayError> {
        if frame.from_peer_id() != from_peer_id {
            self.push_endpoint_peer_mismatch(from_peer_id, &frame);
            return Err(RelayError::UnauthorizedPeer);
        }
        self.forward_wire_frame(now_micros, frame)
    }

    /// Decode and forward one UDP relay datagram.
    ///
    /// Real UDP socket loops can feed received datagram bytes into this method
    /// after endpoint admission has mapped the sender address to `from_peer_id`.
    /// TCP/TLS frames wrapped into UDP datagrams, or datagrams whose self-declared
    /// peer id disagrees with endpoint admission, fail closed before quota,
    /// usage, or queue state is mutated.
    ///
    /// # Errors
    ///
    /// Returns relay frame validation or forwarding validation errors.
    pub fn forward_udp_datagram(
        &mut self,
        now_micros: u64,
        from_peer_id: PeerId,
        datagram: &[u8],
        max_payload_bytes: usize,
    ) -> Result<ForwardedPacket, RelayError> {
        let frame = RelayWireFrame::decode(datagram, max_payload_bytes)?;
        if frame.packet.transport() != RelayTransport::Udp {
            return Err(RelayError::InvalidRelayWireFrame);
        }
        self.forward_wire_frame_from_peer(now_micros, from_peer_id, frame)
    }

    /// Resolve UDP endpoint admission, then decode and forward one datagram.
    ///
    /// Socket loops should prefer this helper when the only trusted identity
    /// attached to the read is the source [`SocketAddr`]. Unknown endpoints are
    /// rejected before frame decoding so unadmitted addresses cannot exercise
    /// reservation, quota, or proof state.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] for unadmitted addresses and
    /// otherwise propagates [`Self::forward_udp_datagram`] errors.
    pub fn forward_udp_datagram_from_endpoint(
        &mut self,
        now_micros: u64,
        endpoints: &RelayEndpointDirectory,
        src_addr: SocketAddr,
        datagram: &[u8],
        max_payload_bytes: usize,
    ) -> Result<ForwardedPacket, RelayError> {
        let from_peer_id = endpoints.peer_for_udp_endpoint(src_addr)?;
        self.forward_udp_datagram(now_micros, from_peer_id, datagram, max_payload_bytes)
    }

    /// Append TCP/TLS stream bytes, decode complete relay records, and forward
    /// them in stream order.
    ///
    /// Partial records remain in `stream` for the next socket read. The stream
    /// bound applies to bytes retained between decodes, so a single socket read
    /// may contain multiple valid records as long as each record can be drained
    /// under the configured pending-byte limit. `from_peer_id` must be the peer
    /// identity authenticated for the TCP/TLS stream; any decoded record claiming
    /// a different source peer fails closed before quota, usage, or queue state
    /// is mutated for that record. Malformed records or forwarding failures stop
    /// processing immediately; any already forwarded earlier records have gone
    /// through the normal quota, auth, and proof/log path.
    ///
    /// # Errors
    ///
    /// Returns stream-buffer, relay frame, or forwarding validation errors.
    pub fn forward_tcp_tls_stream_bytes(
        &mut self,
        now_micros: u64,
        from_peer_id: PeerId,
        stream: &mut RelayTcpTlsStreamBuffer,
        bytes: &[u8],
    ) -> Result<Vec<ForwardedPacket>, RelayError> {
        let mut forwarded = Vec::new();

        let mut remaining = bytes;
        loop {
            while let Some(frame) = stream.pop_next_frame()? {
                forwarded.push(self.forward_wire_frame_from_peer(
                    now_micros,
                    from_peer_id,
                    frame,
                )?);
            }

            if remaining.is_empty() {
                break;
            }

            let accepted = remaining.len().min(stream.remaining_capacity());
            if accepted == 0 {
                return Err(RelayError::PacketTooLarge);
            }
            stream.push_bytes(&remaining[..accepted])?;
            remaining = &remaining[accepted..];
        }

        Ok(forwarded)
    }

    /// Resolve TCP/TLS stream admission, then forward stream bytes in order.
    ///
    /// Unknown stream ids are rejected before decoding so unadmitted sockets
    /// cannot probe reservation ids, transfer nonces, quotas, or lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownRelayEndpoint`] for unadmitted streams and
    /// otherwise propagates [`Self::forward_tcp_tls_stream_bytes`] errors.
    pub fn forward_tcp_tls_stream_bytes_from_endpoint(
        &mut self,
        now_micros: u64,
        endpoints: &RelayEndpointDirectory,
        stream_id: RelayTcpTlsStreamId,
        stream: &mut RelayTcpTlsStreamBuffer,
        bytes: &[u8],
    ) -> Result<Vec<ForwardedPacket>, RelayError> {
        let from_peer_id = endpoints.peer_for_tcp_tls_stream(stream_id)?;
        self.forward_tcp_tls_stream_bytes(now_micros, from_peer_id, stream, bytes)
    }

    /// Encode the next UDP packet queued for `peer_id` as a socket datagram.
    ///
    /// The method only consumes the queue front when that packet is actually a
    /// UDP relay packet and encoding succeeds. If a TCP/TLS packet is at the
    /// front of the peer queue, `Ok(None)` is returned and the queue is left
    /// intact so the TCP/TLS writer can preserve per-peer delivery order.
    ///
    /// # Errors
    ///
    /// Returns relay frame encoding errors or [`RelayError::UnknownReservation`]
    /// if the queued packet references state that no longer exists.
    pub fn dequeue_udp_datagram_for_peer(
        &mut self,
        peer_id: PeerId,
        dst_addr: SocketAddr,
        max_payload_bytes: usize,
    ) -> Result<Option<RelayUdpDatagram>, RelayError> {
        let Some(datagram) =
            self.peek_udp_datagram_for_peer(peer_id, dst_addr, max_payload_bytes)?
        else {
            return Ok(None);
        };
        self.commit_udp_datagram_for_peer(peer_id, datagram.reservation_id())?;
        Ok(Some(datagram))
    }

    /// Encode the next UDP packet queued for `peer_id` without consuming it.
    ///
    /// This is the first phase of UDP socket egress. It lets a concrete socket
    /// loop attempt `send_to` and only call [`Self::commit_udp_datagram_for_peer`]
    /// after the OS accepts the whole datagram.
    ///
    /// # Errors
    ///
    /// Returns relay frame encoding errors or [`RelayError::UnknownReservation`]
    /// if the queued packet references state that no longer exists.
    pub fn peek_udp_datagram_for_peer(
        &self,
        peer_id: PeerId,
        dst_addr: SocketAddr,
        max_payload_bytes: usize,
    ) -> Result<Option<RelayUdpDatagram>, RelayError> {
        let Some((forwarded, _transfer_nonce, encoded)) =
            self.encode_front_for_peer_transport(peer_id, RelayTransport::Udp, max_payload_bytes)?
        else {
            return Ok(None);
        };

        Ok(Some(RelayUdpDatagram {
            dst_addr,
            to_peer_id: peer_id,
            reservation_id: forwarded.reservation_id,
            payload: encoded,
            opaque_bytes: forwarded.packet.opaque_len() as u64,
        }))
    }

    /// Commit the UDP datagram previously returned by [`Self::peek_udp_datagram_for_peer`].
    ///
    /// The queue front must still be the same reservation and transport. This
    /// prevents an OS write loop from accidentally consuming a newer or
    /// different packet if relay state was advanced between peek and commit.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownReservation`] when the peer queue is empty
    /// or the queue front no longer matches `reservation_id`, and
    /// [`RelayError::InvalidRelayWireFrame`] if the queue front is not a UDP
    /// relay packet.
    pub fn commit_udp_datagram_for_peer(
        &mut self,
        peer_id: PeerId,
        reservation_id: RelayReservationId,
    ) -> Result<(), RelayError> {
        let Some(forwarded) = self.queues.get(&peer_id).and_then(VecDeque::front) else {
            return Err(RelayError::UnknownReservation);
        };
        if forwarded.reservation_id != reservation_id {
            return Err(RelayError::UnknownReservation);
        }
        if forwarded.packet.transport() != RelayTransport::Udp {
            return Err(RelayError::InvalidRelayWireFrame);
        }

        let popped = self
            .dequeue_for_peer(peer_id)
            .ok_or(RelayError::UnknownReservation)?;
        debug_assert_eq!(popped.reservation_id, reservation_id);
        debug_assert_eq!(popped.packet.transport(), RelayTransport::Udp);
        Ok(())
    }

    /// Encode the next TCP/TLS 443 packet queued for `peer_id` as one stream record.
    ///
    /// The method mirrors [`Self::dequeue_udp_datagram_for_peer`]: it only
    /// consumes the queue front when the packet belongs on the TCP/TLS fallback
    /// stream and record encoding has already succeeded.
    ///
    /// # Errors
    ///
    /// Returns relay frame encoding errors or [`RelayError::UnknownReservation`]
    /// if the queued packet references state that no longer exists.
    pub fn dequeue_tcp_tls_record_for_peer(
        &mut self,
        peer_id: PeerId,
        max_payload_bytes: usize,
    ) -> Result<Option<RelayTcpTlsRecord>, RelayError> {
        let Some(record) = self.peek_tcp_tls_record_for_peer(peer_id, max_payload_bytes)? else {
            return Ok(None);
        };
        self.commit_tcp_tls_record_for_peer(peer_id, record.reservation_id())?;
        Ok(Some(record))
    }

    /// Encode the next TCP/TLS 443 packet queued for `peer_id` without consuming it.
    ///
    /// This is the first phase of TCP/TLS socket egress. The socket loop can move
    /// the bytes into its pending-write buffer and only call
    /// [`Self::commit_tcp_tls_record_for_peer`] once the complete record is owned
    /// by that buffer.
    ///
    /// # Errors
    ///
    /// Returns relay frame encoding errors or [`RelayError::UnknownReservation`]
    /// if the queued packet references state that no longer exists.
    pub fn peek_tcp_tls_record_for_peer(
        &self,
        peer_id: PeerId,
        max_payload_bytes: usize,
    ) -> Result<Option<RelayTcpTlsRecord>, RelayError> {
        let Some((forwarded, _transfer_nonce, encoded)) = self.encode_front_for_peer_transport(
            peer_id,
            RelayTransport::TcpTls443,
            max_payload_bytes,
        )?
        else {
            return Ok(None);
        };

        Ok(Some(RelayTcpTlsRecord {
            to_peer_id: peer_id,
            reservation_id: forwarded.reservation_id,
            bytes: encoded,
            opaque_bytes: forwarded.packet.opaque_len() as u64,
        }))
    }

    /// Commit the TCP/TLS record previously returned by [`Self::peek_tcp_tls_record_for_peer`].
    ///
    /// The queue front must still be the same reservation and transport. This
    /// prevents a stream writer from consuming a newer or different packet if
    /// relay state advanced between peek and commit.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownReservation`] when the peer queue is empty
    /// or the queue front no longer matches `reservation_id`, and
    /// [`RelayError::InvalidRelayWireFrame`] if the queue front is not a TCP/TLS
    /// relay packet.
    pub fn commit_tcp_tls_record_for_peer(
        &mut self,
        peer_id: PeerId,
        reservation_id: RelayReservationId,
    ) -> Result<(), RelayError> {
        let Some(forwarded) = self.queues.get(&peer_id).and_then(VecDeque::front) else {
            return Err(RelayError::UnknownReservation);
        };
        if forwarded.reservation_id != reservation_id {
            return Err(RelayError::UnknownReservation);
        }
        if forwarded.packet.transport() != RelayTransport::TcpTls443 {
            return Err(RelayError::InvalidRelayWireFrame);
        }

        let popped = self
            .dequeue_for_peer(peer_id)
            .ok_or(RelayError::UnknownReservation)?;
        debug_assert_eq!(popped.reservation_id, reservation_id);
        debug_assert_eq!(popped.packet.transport(), RelayTransport::TcpTls443);
        Ok(())
    }

    /// Dequeue the next forwarded packet for a peer.
    #[must_use]
    pub fn dequeue_for_peer(&mut self, peer_id: PeerId) -> Option<ForwardedPacket> {
        let forwarded = self.queues.get_mut(&peer_id).and_then(VecDeque::pop_front);
        if self.queues.get(&peer_id).is_some_and(VecDeque::is_empty) {
            self.queues.remove(&peer_id);
        }
        forwarded
    }

    /// Cancel a reservation under structured cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownReservation`] when the reservation is absent.
    pub fn cancel_reservation(
        &mut self,
        reservation_id: RelayReservationId,
    ) -> Result<(), RelayError> {
        let already_terminal = self
            .reservations
            .get(&reservation_id)
            .ok_or(RelayError::UnknownReservation)?
            .is_terminal();
        if already_terminal {
            return Ok(());
        }

        let (dropped_queued_packets, dropped_queued_bytes) =
            self.drain_queued_packets_for_reservation(reservation_id);
        if let Some(usage) = self.usage.get_mut(&reservation_id) {
            usage.dropped_packets = usage.dropped_packets.saturating_add(dropped_queued_packets);
        }

        let event = {
            let state = self
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            state.cancelled = true;
            let usage_snapshot = self.usage.get(&reservation_id).copied().unwrap_or_default();
            RelayEventDraft {
                kind: RelayEventKind::ReservationCancelled,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(state.grant.transfer_nonce),
                path_id: Some(state.path_id.clone()),
                from_peer: Some(state.grant.source_peer_id),
                to_peer: Some(state.grant.destination_peer_id),
                transport: Some(state.primary_transport),
                opaque_bytes: dropped_queued_bytes,
                quota_decision: if dropped_queued_packets == 0 {
                    "reservation_cancelled"
                } else {
                    "reservation_cancelled_queued_packets_drained"
                },
                loss_summary: usage_snapshot.loss_summary,
                latency_summary: usage_snapshot.latency_summary,
                fallback_reason: Self::fallback_reason_for_usage(state, usage_snapshot),
            }
        };
        self.push_event(event);
        Ok(())
    }

    /// Expire every live reservation whose grant is no longer valid.
    ///
    /// Expiration is a lifecycle transition, not just a forward-time rejection:
    /// queued packets are drained, drop counters are updated, and restart
    /// snapshots stop retaining the expired reservation.
    #[must_use]
    pub fn expire_reservations(&mut self, now_micros: u64) -> usize {
        let expired_ids = self
            .reservations
            .iter()
            .filter(|(_, state)| {
                !state.is_terminal() && state.grant.expires_at_micros <= now_micros
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut expired_count = 0;

        for reservation_id in expired_ids {
            if self.expire_reservation(reservation_id).is_ok() {
                expired_count += 1;
            }
        }

        expired_count
    }

    /// Record a packet loss summary for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown reservations, invalid totals, or
    /// reservations that already reached a terminal lifecycle state.
    pub fn record_packet_loss(
        &mut self,
        reservation_id: RelayReservationId,
        lost_packets: u64,
        total_packets: u64,
    ) -> Result<RelayLossSummary, RelayError> {
        let state = self
            .reservations
            .get(&reservation_id)
            .cloned()
            .ok_or(RelayError::UnknownReservation)?;
        if state.cancelled {
            return Err(RelayError::ReservationCancelled);
        }
        if state.expired {
            return Err(RelayError::ExpiredReservation);
        }
        if total_packets == 0 || lost_packets > total_packets {
            return Err(RelayError::InvalidLossSummary);
        }

        let loss_ppm_u64 = lost_packets.saturating_mul(1_000_000) / total_packets;
        let loss_ppm = u32::try_from(loss_ppm_u64).map_err(|_| RelayError::InvalidLossSummary)?;
        let summary = RelayLossSummary {
            lost_packets,
            total_packets,
            loss_ppm,
        };
        let usage_snapshot = {
            let usage = self
                .usage
                .get_mut(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            usage.dropped_packets = usage.dropped_packets.saturating_add(lost_packets);
            usage.loss_summary = Some(summary);
            *usage
        };

        self.push_event(RelayEventDraft {
            kind: RelayEventKind::PacketLossRecorded,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(state.path_id.clone()),
            from_peer: Some(state.grant.source_peer_id),
            to_peer: Some(state.grant.destination_peer_id),
            transport: Some(state.primary_transport),
            opaque_bytes: usage_snapshot.forwarded_bytes,
            loss_summary: usage_snapshot.loss_summary,
            latency_summary: usage_snapshot.latency_summary,
            quota_decision: "loss_summary_recorded",
            fallback_reason: Self::fallback_reason_for_usage(&state, usage_snapshot),
        });

        Ok(summary)
    }

    /// Build a deterministic restart snapshot.
    #[must_use]
    pub fn snapshot(&self) -> RelayRestartSnapshot {
        let (reservations, usage, queues) = if self.config.retain_state_on_restart {
            let retained_reservation_ids = self
                .reservations
                .iter()
                .filter(|(_, state)| !state.is_terminal())
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>();
            (
                self.reservations
                    .iter()
                    .filter(|(id, _)| retained_reservation_ids.contains(*id))
                    .map(|(id, state)| (*id, state.clone()))
                    .collect(),
                self.usage
                    .iter()
                    .filter(|(id, _)| retained_reservation_ids.contains(*id))
                    .map(|(id, usage)| (*id, *usage))
                    .collect(),
                self.queues
                    .iter()
                    .filter_map(|(peer, queue)| {
                        let retained_packets = queue
                            .iter()
                            .filter(|packet| {
                                retained_reservation_ids.contains(&packet.reservation_id)
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        if retained_packets.is_empty() {
                            None
                        } else {
                            Some((*peer, retained_packets))
                        }
                    })
                    .collect(),
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        RelayRestartSnapshot {
            config: self.config.clone(),
            reservations,
            usage,
            queues,
            events: self.events.clone(),
            replay_pointer: self.replay_pointer,
        }
    }

    /// Restore relay service state after restart.
    #[must_use]
    pub fn restore(snapshot: RelayRestartSnapshot) -> Self {
        let mut service = Self {
            config: snapshot.config,
            reservations: snapshot.reservations.into_iter().collect(),
            usage: snapshot.usage.into_iter().collect(),
            queues: snapshot
                .queues
                .into_iter()
                .map(|(peer, packets)| (peer, VecDeque::from(packets)))
                .collect(),
            events: snapshot.events,
            replay_pointer: snapshot.replay_pointer,
        };
        service.push_event(RelayEventDraft {
            kind: RelayEventKind::RestartRestored,
            reservation_id: None,
            transfer_nonce: None,
            path_id: None,
            from_peer: None,
            to_peer: None,
            transport: None,
            opaque_bytes: 0,
            loss_summary: None,
            latency_summary: None,
            quota_decision: "restart_restored",
            fallback_reason: None,
        });
        service
    }

    /// Build a relay proof artifact.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownReservation`] when the reservation is absent.
    pub fn proof_artifact(
        &self,
        reservation_id: RelayReservationId,
    ) -> Result<RelayProofArtifact, RelayError> {
        let state = self
            .reservations
            .get(&reservation_id)
            .ok_or(RelayError::UnknownReservation)?;
        let usage = self
            .usage
            .get(&reservation_id)
            .copied()
            .ok_or(RelayError::UnknownReservation)?;

        Ok(RelayProofArtifact {
            relay_id: self.config.relay_id.clone(),
            reservation_id,
            transfer_nonce: state.grant.transfer_nonce,
            path_id: state.path_id.clone(),
            primary_transport: state.primary_transport,
            fallback_transport: state.fallback_transport,
            accepted_at_micros: state.accepted_at_micros,
            quota_decision: "quota_accounted",
            fallback_reason: Self::fallback_reason_for_usage(state, usage),
            opaque_bytes_forwarded: usage.forwarded_bytes,
            packets_forwarded: usage.forwarded_packets,
            loss_summary: usage.loss_summary,
            latency_summary: usage.latency_summary,
            redacted_source_peer: self.redact_peer(state.grant.source_peer_id),
            redacted_destination_peer: self.redact_peer(state.grant.destination_peer_id),
            replay_pointer: self.replay_pointer,
            e2e_proof_preserved: true,
        })
    }

    fn encode_front_for_peer_transport(
        &self,
        peer_id: PeerId,
        transport: RelayTransport,
        max_payload_bytes: usize,
    ) -> Result<Option<(ForwardedPacket, TransferNonce, Vec<u8>)>, RelayError> {
        let Some(forwarded) = self.queues.get(&peer_id).and_then(VecDeque::front) else {
            return Ok(None);
        };
        if forwarded.packet.transport() != transport {
            return Ok(None);
        }

        let transfer_nonce = self.transfer_nonce_for(forwarded)?;
        let frame = RelayWireFrame::new(
            forwarded.reservation_id,
            transfer_nonce,
            forwarded.from_peer_id,
            forwarded.packet.clone(),
        );
        let encoded = match transport {
            RelayTransport::Udp => frame.encode(max_payload_bytes)?,
            RelayTransport::TcpTls443 => frame.encode_tcp_tls_record(max_payload_bytes)?,
        };

        Ok(Some((forwarded.clone(), transfer_nonce, encoded)))
    }

    fn transfer_nonce_for(&self, forwarded: &ForwardedPacket) -> Result<TransferNonce, RelayError> {
        self.reservations
            .get(&forwarded.reservation_id)
            .map(|state| state.grant.transfer_nonce)
            .ok_or(RelayError::UnknownReservation)
    }

    fn active_reservation_count(&self, now_micros: u64) -> usize {
        self.reservations
            .values()
            .filter(|state| !state.is_terminal() && state.grant.expires_at_micros > now_micros)
            .count()
    }

    fn select_transports(
        &self,
        grant: &RelayReservationGrant,
    ) -> Result<(RelayTransport, Option<RelayTransport>), RelayError> {
        let udp_available = grant.allows_transport(RelayTransport::Udp) && self.config.udp_enabled;
        let tcp_available =
            grant.allows_transport(RelayTransport::TcpTls443) && self.config.tcp_tls_443_enabled;

        match (udp_available, tcp_available) {
            (true, true) => Ok((RelayTransport::Udp, Some(RelayTransport::TcpTls443))),
            (true, false) => Ok((RelayTransport::Udp, None)),
            (false, true) => Ok((RelayTransport::TcpTls443, None)),
            (false, false) => Err(RelayError::TransportUnavailable),
        }
    }

    fn fallback_reason_for_usage(
        state: &RelayReservationState,
        usage: RelayUsage,
    ) -> Option<&'static str> {
        if state.primary_transport == RelayTransport::TcpTls443 || usage.tcp_tls_443_packets > 0 {
            RelayTransport::TcpTls443.fallback_reason()
        } else {
            None
        }
    }

    fn expire_reservation(&mut self, reservation_id: RelayReservationId) -> Result<(), RelayError> {
        let already_expired_or_cancelled = {
            let state = self
                .reservations
                .get(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            state.is_terminal()
        };
        if already_expired_or_cancelled {
            return Ok(());
        }

        let (dropped_queued_packets, dropped_queued_bytes) =
            self.drain_queued_packets_for_reservation(reservation_id);
        if let Some(usage) = self.usage.get_mut(&reservation_id) {
            usage.dropped_packets = usage.dropped_packets.saturating_add(dropped_queued_packets);
        }

        let event = {
            let state = self
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            state.expired = true;
            let usage_snapshot = self.usage.get(&reservation_id).copied().unwrap_or_default();
            RelayEventDraft {
                kind: RelayEventKind::ReservationExpired,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(state.grant.transfer_nonce),
                path_id: Some(state.path_id.clone()),
                from_peer: Some(state.grant.source_peer_id),
                to_peer: Some(state.grant.destination_peer_id),
                transport: Some(state.primary_transport),
                opaque_bytes: dropped_queued_bytes,
                quota_decision: if dropped_queued_packets == 0 {
                    "reservation_expired"
                } else {
                    "reservation_expired_queued_packets_drained"
                },
                loss_summary: usage_snapshot.loss_summary,
                latency_summary: usage_snapshot.latency_summary,
                fallback_reason: Self::fallback_reason_for_usage(state, usage_snapshot),
            }
        };
        self.push_event(event);
        Ok(())
    }

    fn transport_available(&self, transport: RelayTransport) -> bool {
        match transport {
            RelayTransport::Udp => self.config.udp_enabled,
            RelayTransport::TcpTls443 => self.config.tcp_tls_443_enabled,
        }
    }

    fn apply_quota(
        &mut self,
        reservation_id: RelayReservationId,
        state: &RelayReservationState,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
        packet: &OpaqueRelayPacket,
        now_micros: u64,
    ) -> Result<RelayUsage, RelayError> {
        let packet_len = packet.opaque_len();
        if packet_len > state.grant.quota.max_packet_bytes {
            self.push_quota_rejected(reservation_id, state, from_peer_id, to_peer_id, packet);
            return Err(RelayError::PacketTooLarge);
        }

        let packet_len_u64 = u64::try_from(packet_len).map_err(|_| RelayError::QuotaExceeded)?;
        let usage = self
            .usage
            .get_mut(&reservation_id)
            .ok_or(RelayError::UnknownReservation)?;
        if usage.forwarded_packets >= state.grant.quota.max_packets_per_reservation {
            self.push_quota_rejected(reservation_id, state, from_peer_id, to_peer_id, packet);
            return Err(RelayError::QuotaExceeded);
        }

        let next_bytes = usage
            .forwarded_bytes
            .checked_add(packet_len_u64)
            .ok_or(RelayError::QuotaExceeded)?;
        if next_bytes > state.grant.quota.max_bytes_per_reservation {
            self.push_quota_rejected(reservation_id, state, from_peer_id, to_peer_id, packet);
            return Err(RelayError::QuotaExceeded);
        }

        usage.forwarded_packets += 1;
        usage.forwarded_bytes = next_bytes;
        match packet.transport {
            RelayTransport::Udp => usage.udp_packets += 1,
            RelayTransport::TcpTls443 => usage.tcp_tls_443_packets += 1,
        }
        usage.record_latency(now_micros.saturating_sub(packet.sent_at_micros()));
        Ok(*usage)
    }

    fn drain_queued_packets_for_reservation(
        &mut self,
        reservation_id: RelayReservationId,
    ) -> (u64, u64) {
        let mut dropped_packets = 0_u64;
        let mut dropped_bytes = 0_u64;
        let mut empty_peers = Vec::new();

        for (peer_id, queue) in &mut self.queues {
            queue.retain(|forwarded| {
                if forwarded.reservation_id == reservation_id {
                    dropped_packets = dropped_packets.saturating_add(1);
                    dropped_bytes =
                        dropped_bytes.saturating_add(forwarded.packet.opaque_len() as u64);
                    false
                } else {
                    true
                }
            });
            if queue.is_empty() {
                empty_peers.push(*peer_id);
            }
        }

        for peer_id in empty_peers {
            self.queues.remove(&peer_id);
        }

        (dropped_packets, dropped_bytes)
    }

    fn push_endpoint_peer_mismatch(&mut self, endpoint_peer_id: PeerId, frame: &RelayWireFrame) {
        let Some(state) = self.reservations.get(&frame.reservation_id).cloned() else {
            return;
        };
        self.push_event(RelayEventDraft {
            kind: RelayEventKind::AuthorizationRejected,
            reservation_id: Some(frame.reservation_id),
            transfer_nonce: Some(frame.transfer_nonce),
            path_id: Some(state.path_id),
            from_peer: Some(endpoint_peer_id),
            to_peer: None,
            transport: Some(frame.packet.transport),
            opaque_bytes: frame.packet.opaque_len() as u64,
            loss_summary: None,
            latency_summary: None,
            quota_decision: "endpoint_peer_mismatch_rejected",
            fallback_reason: None,
        });
    }

    fn push_quota_rejected(
        &mut self,
        reservation_id: RelayReservationId,
        state: &RelayReservationState,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
        packet: &OpaqueRelayPacket,
    ) {
        self.push_event(RelayEventDraft {
            kind: RelayEventKind::QuotaRejected,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(state.path_id.clone()),
            from_peer: Some(from_peer_id),
            to_peer: Some(to_peer_id),
            transport: Some(packet.transport),
            opaque_bytes: packet.opaque_len() as u64,
            loss_summary: None,
            latency_summary: None,
            quota_decision: "packet_quota_rejected",
            fallback_reason: packet.transport.fallback_reason(),
        });
    }

    fn push_event(&mut self, draft: RelayEventDraft) {
        self.replay_pointer = self.replay_pointer.saturating_add(1);
        self.events.push(RelayEvent {
            kind: draft.kind,
            relay_id: self.config.relay_id.clone(),
            reservation_id: draft.reservation_id,
            transfer_nonce: draft.transfer_nonce,
            path_id: draft.path_id,
            from_peer: draft.from_peer.map(|peer| self.redact_peer(peer)),
            to_peer: draft.to_peer.map(|peer| self.redact_peer(peer)),
            transport: draft.transport,
            opaque_bytes: draft.opaque_bytes,
            loss_summary: draft.loss_summary,
            latency_summary: draft.latency_summary,
            quota_decision: draft.quota_decision,
            fallback_reason: draft.fallback_reason,
            replay_pointer: self.replay_pointer,
        });
    }

    fn redact_peer(&self, peer_id: PeerId) -> String {
        if !self.config.log_peer_ids {
            return "peer:redacted".to_owned();
        }

        let bytes = peer_id.bytes();
        format!("peer:{:02x}{:02x}...", bytes[0], bytes[1])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayReservationState {
    grant: RelayReservationGrant,
    path_id: String,
    accepted_at_micros: u64,
    primary_transport: RelayTransport,
    fallback_transport: Option<RelayTransport>,
    cancelled: bool,
    expired: bool,
}

impl RelayReservationState {
    fn is_terminal(&self) -> bool {
        self.cancelled || self.expired
    }
}

#[derive(Debug)]
struct RelayEventDraft {
    kind: RelayEventKind,
    reservation_id: Option<RelayReservationId>,
    transfer_nonce: Option<TransferNonce>,
    path_id: Option<String>,
    from_peer: Option<PeerId>,
    to_peer: Option<PeerId>,
    transport: Option<RelayTransport>,
    opaque_bytes: u64,
    loss_summary: Option<RelayLossSummary>,
    latency_summary: Option<RelayLatencySummary>,
    quota_decision: &'static str,
    fallback_reason: Option<&'static str>,
}

/// Relay service errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// Reservation id was zero.
    #[error("relay reservation id is zero")]
    ZeroReservationId,
    /// TCP/TLS relay stream id was zero.
    #[error("relay tcp/tls stream id is zero")]
    ZeroTcpTlsStreamId,
    /// Relay id was empty.
    #[error("relay id is empty")]
    EmptyRelayId,
    /// Relay endpoint address or stream binding was invalid.
    #[error("invalid relay endpoint")]
    InvalidRelayEndpoint,
    /// Relay endpoint is already bound to a different peer.
    #[error("duplicate relay endpoint")]
    DuplicateRelayEndpoint,
    /// Relay endpoint has not been admitted.
    #[error("unknown relay endpoint")]
    UnknownRelayEndpoint,
    /// Path id was empty.
    #[error("relay path id is empty")]
    EmptyPathId,
    /// Packet payload was empty.
    #[error("relay packet is empty")]
    EmptyPacket,
    /// Quota was invalid.
    #[error("relay quota is invalid")]
    InvalidQuota,
    /// Proof tag was invalid.
    #[error("relay proof tag is invalid")]
    InvalidProofTag,
    /// Reservation connects the same peer to itself.
    #[error("relay reservation cannot loop back to the same peer")]
    LoopbackReservation,
    /// Reservation id already exists.
    #[error("duplicate relay reservation")]
    DuplicateReservation,
    /// Reservation does not exist.
    #[error("unknown relay reservation")]
    UnknownReservation,
    /// Reservation or grant has expired.
    #[error("expired relay reservation")]
    ExpiredReservation,
    /// Reservation was cancelled.
    #[error("relay reservation was cancelled")]
    ReservationCancelled,
    /// Peer is not authorized for this reservation.
    #[error("unauthorized relay peer")]
    UnauthorizedPeer,
    /// Relay authorization failed.
    #[error("invalid relay authorization")]
    InvalidAuthorization,
    /// Transport is not allowed or unavailable.
    #[error("relay transport unavailable")]
    TransportUnavailable,
    /// Quota was exceeded.
    #[error("relay quota exceeded")]
    QuotaExceeded,
    /// Packet exceeds per-packet quota.
    #[error("relay packet too large")]
    PacketTooLarge,
    /// Packet loss summary is invalid.
    #[error("invalid relay loss summary")]
    InvalidLossSummary,
    /// Relay tunnel frame is malformed.
    #[error("invalid relay wire frame")]
    InvalidRelayWireFrame,
    /// Relay tunnel frame ended before all required fields were available.
    #[error("truncated relay wire frame")]
    TruncatedRelayWireFrame,
    /// Relay tunnel frame version is not supported by this implementation.
    #[error("unsupported relay wire frame version")]
    UnsupportedRelayWireVersion,
    /// Relay tunnel frame kind is not supported by this implementation.
    #[error("unsupported relay wire frame kind")]
    UnsupportedRelayWireFrameKind,
}

impl RelayError {
    /// Map relay-specific failures into the shared path graph failure taxonomy.
    #[must_use]
    pub const fn path_failure_kind(self) -> PathFailureKind {
        match self {
            Self::InvalidAuthorization | Self::UnauthorizedPeer | Self::UnknownRelayEndpoint => {
                PathFailureKind::AuthFailure
            }
            Self::TransportUnavailable
            | Self::UnknownReservation
            | Self::ExpiredReservation
            | Self::ReservationCancelled => PathFailureKind::RelayUnavailable,
            Self::QuotaExceeded
            | Self::PacketTooLarge
            | Self::InvalidQuota
            | Self::DuplicateRelayEndpoint => PathFailureKind::PolicyDenied,
            Self::ZeroReservationId
            | Self::ZeroTcpTlsStreamId
            | Self::EmptyRelayId
            | Self::InvalidRelayEndpoint
            | Self::EmptyPathId
            | Self::EmptyPacket
            | Self::InvalidProofTag
            | Self::LoopbackReservation
            | Self::DuplicateReservation
            | Self::InvalidLossSummary
            | Self::InvalidRelayWireFrame
            | Self::TruncatedRelayWireFrame
            | Self::UnsupportedRelayWireVersion
            | Self::UnsupportedRelayWireFrameKind => PathFailureKind::ProtocolError,
        }
    }
}

fn validate_relay_socket_endpoint(endpoint: SocketAddr) -> Result<(), RelayError> {
    if endpoint.port() == 0 {
        return Err(RelayError::InvalidRelayEndpoint);
    }
    match endpoint.ip() {
        IpAddr::V4(addr) if addr.is_unspecified() => Err(RelayError::InvalidRelayEndpoint),
        IpAddr::V6(addr) if addr.is_unspecified() => Err(RelayError::InvalidRelayEndpoint),
        _ => Ok(()),
    }
}

fn udp_socket_recv_buffer_capacity_for(max_payload_bytes: usize) -> Result<usize, RelayError> {
    if max_payload_bytes == 0 {
        return Err(RelayError::InvalidQuota);
    }

    RELAY_WIRE_HEADER_LEN
        .checked_add(max_payload_bytes)
        .and_then(|capacity| capacity.checked_add(1))
        .ok_or(RelayError::PacketTooLarge)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], RelayError> {
    let end = offset
        .checked_add(N)
        .ok_or(RelayError::TruncatedRelayWireFrame)?;
    let Some(slice) = bytes.get(offset..end) else {
        return Err(RelayError::TruncatedRelayWireFrame);
    };
    slice
        .try_into()
        .map_err(|_| RelayError::TruncatedRelayWireFrame)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RelayError> {
    Ok(u32::from_be_bytes(read_array::<4>(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, RelayError> {
    Ok(u64::from_be_bytes(read_array::<8>(bytes, offset)?))
}

fn read_u128(bytes: &[u8], offset: usize) -> Result<u128, RelayError> {
    Ok(u128::from_be_bytes(read_array::<16>(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::new([seed; 32]).expect("peer")
    }

    fn transfer_nonce(raw: u128) -> TransferNonce {
        TransferNonce::new(raw).expect("transfer nonce")
    }

    fn reservation_id(raw: u128) -> RelayReservationId {
        RelayReservationId::new(raw).expect("reservation id")
    }

    fn proof_tag(seed: u8) -> ProofTag {
        ProofTag::new([seed; 32]).expect("proof tag")
    }

    fn signature() -> CandidateSignature {
        CandidateSignature::new(vec![1, 2, 3]).expect("signature")
    }

    fn grant(expires_at_micros: u64, quota: RelayQuota) -> RelayReservationGrant {
        RelayReservationGrant::udp_first_tcp_tls_443(
            peer(1),
            peer(2),
            transfer_nonce(9),
            expires_at_micros,
            quota,
            signature(),
        )
        .expect("grant")
    }

    fn packet(transport: RelayTransport, payload: &[u8], sequence: u64) -> OpaqueRelayPacket {
        packet_sent_at(transport, payload, sequence, 10)
    }

    fn packet_sent_at(
        transport: RelayTransport,
        payload: &[u8],
        sequence: u64,
        sent_at_micros: u64,
    ) -> OpaqueRelayPacket {
        OpaqueRelayPacket::new(
            sequence,
            transport,
            payload.to_vec(),
            proof_tag(7),
            sent_at_micros,
        )
        .expect("packet")
    }

    #[test]
    fn endpoint_directory_binds_socket_endpoints_to_authenticated_peers() {
        let mut directory = RelayEndpointDirectory::new(RelayEndpointDirectoryQuota {
            max_udp_endpoints: 2,
            max_tcp_tls_streams: 2,
        })
        .expect("directory");
        let udp_endpoint = SocketAddr::from(([192, 0, 2, 10], 40_000));
        let second_udp_endpoint = SocketAddr::from(([192, 0, 2, 11], 40_001));
        let stream_id = RelayTcpTlsStreamId::new(700).expect("stream id");
        let second_stream_id = RelayTcpTlsStreamId::new(701).expect("second stream id");

        assert_eq!(
            RelayTcpTlsStreamId::new(0).expect_err("zero stream id"),
            RelayError::ZeroTcpTlsStreamId
        );
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(1), SocketAddr::from(([0, 0, 0, 0], 40_000)))
                .expect_err("wildcard endpoint"),
            RelayError::InvalidRelayEndpoint
        );
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(1), SocketAddr::from(([192, 0, 2, 12], 0)))
                .expect_err("port-zero endpoint"),
            RelayError::InvalidRelayEndpoint
        );

        directory
            .bind_udp_endpoint(peer(1), udp_endpoint)
            .expect("bind udp");
        directory
            .bind_udp_endpoint(peer(1), udp_endpoint)
            .expect("idempotent udp bind");
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(2), udp_endpoint)
                .expect_err("conflicting udp bind"),
            RelayError::DuplicateRelayEndpoint
        );
        assert_eq!(
            directory
                .peer_for_udp_endpoint(udp_endpoint)
                .expect("udp peer"),
            peer(1)
        );
        assert_eq!(
            directory
                .first_udp_endpoint_for_peer(peer(1))
                .expect("udp endpoint for peer"),
            udp_endpoint
        );
        directory
            .bind_udp_endpoint(peer(1), second_udp_endpoint)
            .expect("migrated udp endpoint");
        assert_eq!(
            directory
                .first_udp_endpoint_for_peer(peer(1))
                .expect("fresh udp endpoint for peer"),
            second_udp_endpoint
        );
        assert_eq!(
            directory
                .peer_for_udp_endpoint(SocketAddr::from(([192, 0, 2, 99], 40_099)))
                .expect_err("unknown udp endpoint"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(3), SocketAddr::from(([192, 0, 2, 13], 40_002)))
                .expect_err("udp endpoint quota"),
            RelayError::QuotaExceeded
        );
        assert_eq!(directory.unbind_udp_endpoint(udp_endpoint), Some(peer(1)));
        assert_eq!(
            directory
                .first_udp_endpoint_for_peer(peer(1))
                .expect("fresh udp endpoint survives stale unbind"),
            second_udp_endpoint
        );
        assert_eq!(
            directory
                .peer_for_udp_endpoint(udp_endpoint)
                .expect_err("unbound udp endpoint"),
            RelayError::UnknownRelayEndpoint
        );

        directory
            .bind_tcp_tls_stream(peer(1), stream_id)
            .expect("bind tcp stream");
        directory
            .bind_tcp_tls_stream(peer(1), stream_id)
            .expect("idempotent tcp bind");
        assert_eq!(
            directory
                .bind_tcp_tls_stream(peer(2), stream_id)
                .expect_err("conflicting tcp bind"),
            RelayError::DuplicateRelayEndpoint
        );
        assert_eq!(
            directory
                .peer_for_tcp_tls_stream(stream_id)
                .expect("tcp stream peer"),
            peer(1)
        );
        directory
            .bind_tcp_tls_stream(peer(1), second_stream_id)
            .expect("reconnected tcp stream");
        assert_eq!(
            directory
                .first_tcp_tls_stream_for_peer(peer(1))
                .expect("fresh tcp stream for peer"),
            second_stream_id
        );
        assert_eq!(
            directory
                .bind_tcp_tls_stream(
                    peer(3),
                    RelayTcpTlsStreamId::new(702).expect("third stream id"),
                )
                .expect_err("tcp stream quota"),
            RelayError::QuotaExceeded
        );
        assert_eq!(directory.unbind_tcp_tls_stream(stream_id), Some(peer(1)));
        assert_eq!(
            directory
                .first_tcp_tls_stream_for_peer(peer(1))
                .expect("fresh tcp stream survives stale unbind"),
            second_stream_id
        );
        assert_eq!(
            directory
                .peer_for_tcp_tls_stream(stream_id)
                .expect_err("unbound tcp stream"),
            RelayError::UnknownRelayEndpoint
        );
    }

    #[test]
    fn udp_first_reservation_emits_tcp_tls_443_fallback_candidate() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        let candidate = service
            .reserve(
                10,
                reservation_id(1),
                "path-relay-1",
                grant(1_000, RelayQuota::default()),
                &|grant: &RelayReservationGrant| grant.signature().bytes() == [1, 2, 3],
            )
            .expect("reservation");

        assert_eq!(candidate.primary_transport(), RelayTransport::Udp);
        assert_eq!(
            candidate.fallback_transport(),
            Some(RelayTransport::TcpTls443)
        );
        assert_eq!(candidate.path_id(), "path-relay-1");
        assert_eq!(service.events()[0].quota_decision, "reservation_accepted");
        assert_eq!(service.events()[0].fallback_reason, None);
    }

    #[test]
    fn tcp_tls_443_is_selected_when_udp_is_disabled() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);

        let candidate = service
            .reserve(
                10,
                reservation_id(2),
                "path-relay-2",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(candidate.primary_transport(), RelayTransport::TcpTls443);
        assert_eq!(
            candidate.primary_transport().fallback_reason(),
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn relay_candidate_converts_to_path_graph_candidate() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);
        let relay_candidate = service
            .reserve(
                10,
                reservation_id(33),
                "path-relay-33",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(relay_candidate.path_kind(), PathKind::AtpRelayTcpTls443);
        assert_eq!(relay_candidate.fallback_path_kind(), None);

        let path_candidate =
            relay_candidate.to_path_candidate(PathCandidateId::new(333), PathTraceId::new(333_000));
        assert_eq!(path_candidate.id, PathCandidateId::new(333));
        assert_eq!(path_candidate.kind, PathKind::AtpRelayTcpTls443);
        assert_eq!(path_candidate.trace_id, PathTraceId::new(333_000));
        assert!(path_candidate.security.authenticated_peer);
        assert!(path_candidate.security.end_to_end_encrypted);
        assert!(!path_candidate.security.exposes_local_ip_to_peer);
        assert!(path_candidate.security.relay_metadata_visible);
    }

    #[test]
    fn relay_proof_and_errors_convert_to_path_graph_outcomes() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(34),
                "path-relay-34",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(34),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        let proof = service
            .proof_artifact(reservation_id(34))
            .expect("proof artifact");
        let latency = proof.latency_summary.expect("latency summary");
        assert_eq!(latency.sample_count, 1);
        assert_eq!(latency.latest_latency_micros, 10);
        let outcome = proof.to_path_success_outcome(30, Some(10));
        assert!(outcome.is_success());
        assert_eq!(outcome.observed_rtt_micros, Some(10));
        assert_eq!(outcome.bytes_sent, proof.opaque_bytes_forwarded);
        assert_eq!(outcome.bytes_received, proof.opaque_bytes_forwarded);

        assert_eq!(
            RelayError::InvalidAuthorization.path_failure_kind(),
            PathFailureKind::AuthFailure
        );
        assert_eq!(
            RelayError::TransportUnavailable.path_failure_kind(),
            PathFailureKind::RelayUnavailable
        );
        assert_eq!(
            RelayError::PacketTooLarge.path_failure_kind(),
            PathFailureKind::PolicyDenied
        );
        assert_eq!(
            RelayError::InvalidProofTag.path_failure_kind(),
            PathFailureKind::ProtocolError
        );
    }

    #[test]
    fn forwards_opaque_bytes_and_preserves_proof_tag() {
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(3),
                "path-relay-3",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let original = packet(RelayTransport::Udp, b"ciphertext", 42);
        let forwarded = service
            .forward(20, reservation_id(3), peer(1), original.clone())
            .expect("forward");

        assert_eq!(forwarded.to_peer_id(), peer(2));
        assert_eq!(forwarded.packet().opaque_bytes(), b"ciphertext");
        assert_eq!(forwarded.packet().proof_tag(), original.proof_tag());
        assert_eq!(
            service.dequeue_for_peer(peer(2)).expect("queued packet"),
            forwarded
        );
    }

    #[test]
    fn latency_summary_tracks_min_max_latest_and_average() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(35),
                "path-relay-35",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        service
            .forward(
                20,
                reservation_id(35),
                peer(1),
                packet_sent_at(RelayTransport::Udp, b"first", 1, 12),
            )
            .expect("first forward");
        service
            .forward(
                35,
                reservation_id(35),
                peer(2),
                packet_sent_at(RelayTransport::Udp, b"second", 2, 20),
            )
            .expect("second forward");

        let proof = service
            .proof_artifact(reservation_id(35))
            .expect("proof artifact");
        let latency = proof.latency_summary.expect("latency summary");
        assert_eq!(latency.sample_count, 2);
        assert_eq!(latency.latest_latency_micros, 15);
        assert_eq!(latency.min_latency_micros, 8);
        assert_eq!(latency.max_latency_micros, 15);
        assert_eq!(latency.total_latency_micros, 23);
        assert_eq!(latency.average_latency_micros, 11);
    }

    #[test]
    fn relay_wire_frame_round_trips_and_forwards_through_service() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(36),
                "path-relay-36",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let frame = RelayWireFrame::new(
            reservation_id(36),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"encrypted-relay-payload", 7, 70),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode relay frame");
        assert!(encoded.starts_with(&RELAY_WIRE_MAGIC));
        assert!(!encoded.windows(10).any(|window| window == b"object-path"));

        let wrong_nonce_frame = RelayWireFrame::new(
            reservation_id(36),
            transfer_nonce(99),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"wrong-transfer", 8, 72),
        );
        assert_eq!(
            wrong_nonce_frame
                .forward_into(&mut service, 91)
                .expect_err("wrong transfer nonce"),
            RelayError::InvalidAuthorization
        );
        assert_eq!(
            service.usage(reservation_id(36)).expect("usage"),
            RelayUsage::default()
        );
        assert!(service.events().iter().any(|event| {
            event.kind == RelayEventKind::AuthorizationRejected
                && event.quota_decision == "transfer_nonce_mismatch_rejected"
        }));

        let decoded = RelayWireFrame::decode(&encoded, RelayQuota::default().max_packet_bytes)
            .expect("decode relay frame");
        assert_eq!(decoded.reservation_id(), reservation_id(36));
        assert_eq!(decoded.transfer_nonce(), transfer_nonce(9));
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().opaque_bytes(), b"encrypted-relay-payload");
        assert_eq!(decoded.packet().sequence(), 7);

        let forwarded = decoded
            .forward_into(&mut service, 90)
            .expect("decoded relay frame forwards");
        assert_eq!(forwarded.to_peer_id(), peer(2));
        assert_eq!(
            service
                .proof_artifact(reservation_id(36))
                .expect("proof")
                .latency_summary
                .expect("latency")
                .latest_latency_micros,
            20
        );
    }

    #[test]
    fn relay_wire_frame_rejects_truncated_trailing_oversize_and_unknown_headers() {
        let frame = RelayWireFrame::new(
            reservation_id(37),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::TcpTls443, b"encrypted", 8),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode relay frame");

        assert_eq!(
            RelayWireFrame::decode(&encoded[..RELAY_WIRE_HEADER_LEN - 1], 1024)
                .expect_err("truncated"),
            RelayError::TruncatedRelayWireFrame
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            RelayWireFrame::decode(&trailing, 1024).expect_err("trailing bytes"),
            RelayError::InvalidRelayWireFrame
        );

        assert_eq!(
            RelayWireFrame::decode(&encoded, 4).expect_err("payload too large"),
            RelayError::PacketTooLarge
        );

        let mut unsupported_version = encoded.clone();
        unsupported_version[4] = RELAY_WIRE_VERSION.saturating_add(1);
        assert_eq!(
            RelayWireFrame::decode(&unsupported_version, 1024).expect_err("version"),
            RelayError::UnsupportedRelayWireVersion
        );

        let mut unsupported_kind = encoded;
        unsupported_kind[5] = RELAY_WIRE_FORWARD_FRAME_KIND.saturating_add(1);
        assert_eq!(
            RelayWireFrame::decode(&unsupported_kind, 1024).expect_err("kind"),
            RelayError::UnsupportedRelayWireFrameKind
        );
    }

    #[test]
    fn relay_wire_tcp_tls_records_decode_partial_and_coalesced_stream_bytes() {
        let first = RelayWireFrame::new(
            reservation_id(38),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::TcpTls443, b"first-stream-record", 1),
        );
        let second = RelayWireFrame::new(
            reservation_id(38),
            transfer_nonce(9),
            peer(2),
            packet(RelayTransport::TcpTls443, b"second-stream-record", 2),
        );
        let first_record = first
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode first record");
        let second_record = second
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode second record");
        let udp_frame = RelayWireFrame::new(
            reservation_id(38),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::Udp, b"udp-on-tcp-record", 3),
        );

        assert_eq!(
            udp_frame
                .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
                .expect_err("tcp record encoder rejects udp frame transport"),
            RelayError::InvalidRelayWireFrame
        );
        let udp_encoded = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode raw udp relay frame");
        let udp_len = u32::try_from(udp_encoded.len()).expect("udp frame len fits in u32");
        let mut udp_inside_tcp_record =
            Vec::with_capacity(RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN + udp_encoded.len());
        udp_inside_tcp_record.extend_from_slice(&udp_len.to_be_bytes());
        udp_inside_tcp_record.extend_from_slice(&udp_encoded);
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&udp_inside_tcp_record, 1024)
                .expect_err("tcp record decoder rejects udp frame transport"),
            RelayError::InvalidRelayWireFrame
        );

        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&first_record[..2], 1024)
                .expect("partial prefix"),
            RelayWireRecordDecode::NeedMore { minimum_len: 4 }
        );
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&first_record[..8], 1024).expect("partial frame"),
            RelayWireRecordDecode::NeedMore {
                minimum_len: first_record.len()
            }
        );

        let mut coalesced = first_record.clone();
        coalesced.extend_from_slice(&second_record);
        let RelayWireRecordDecode::Complete {
            frame: decoded_first,
            consumed: first_consumed,
        } = RelayWireFrame::decode_tcp_tls_record(&coalesced, 1024).expect("decode first record")
        else {
            panic!("first coalesced record should be complete");
        };
        assert_eq!(first_consumed, first_record.len());
        assert_eq!(
            decoded_first.packet().opaque_bytes(),
            b"first-stream-record"
        );
        assert_eq!(
            RelayWireFrame::decode_complete_tcp_tls_record(&coalesced, 1024)
                .expect_err("coalesced bytes are not exactly one record"),
            RelayError::InvalidRelayWireFrame
        );

        let RelayWireRecordDecode::Complete {
            frame: decoded_second,
            consumed: second_consumed,
        } = RelayWireFrame::decode_tcp_tls_record(&coalesced[first_consumed..], 1024)
            .expect("decode second record")
        else {
            panic!("second coalesced record should be complete");
        };
        assert_eq!(second_consumed, second_record.len());
        assert_eq!(decoded_second.from_peer_id(), peer(2));
        assert_eq!(decoded_second.packet().sequence(), 2);

        let exact = RelayWireFrame::decode_complete_tcp_tls_record(&second_record, 1024)
            .expect("decode exactly one record");
        assert_eq!(exact.packet().opaque_bytes(), b"second-stream-record");

        let mut invalid_short_record = first_record;
        let invalid_short_len =
            u32::try_from(RELAY_WIRE_HEADER_LEN - 1).expect("relay header len fits in u32");
        invalid_short_record[..4].copy_from_slice(&invalid_short_len.to_be_bytes());
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&invalid_short_record, 1024)
                .expect_err("invalid frame length"),
            RelayError::InvalidRelayWireFrame
        );
        let mut oversize_record = second_record;
        let oversize_len =
            u32::try_from(RELAY_WIRE_HEADER_LEN + 5).expect("relay header len fits in u32");
        oversize_record[..4].copy_from_slice(&oversize_len.to_be_bytes());
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&oversize_record, 4)
                .expect_err("oversize record"),
            RelayError::PacketTooLarge
        );
    }

    #[test]
    fn relay_tcp_tls_stream_buffer_drains_partial_coalesced_records_with_bounds() {
        assert_eq!(
            RelayTcpTlsStreamBuffer::new(1024, RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN)
                .expect_err("buffer smaller than the minimum record is invalid"),
            RelayError::InvalidQuota
        );

        let first = RelayWireFrame::new(
            reservation_id(39),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::TcpTls443, b"buffered-first", 1),
        );
        let second = RelayWireFrame::new(
            reservation_id(39),
            transfer_nonce(9),
            peer(2),
            packet(RelayTransport::TcpTls443, b"buffered-second", 2),
        );
        let first_record = first
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode first buffered record");
        let second_record = second
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode second buffered record");
        let mut stream = RelayTcpTlsStreamBuffer::new(
            RelayQuota::default().max_packet_bytes,
            first_record.len() + second_record.len(),
        )
        .expect("stream buffer");

        stream
            .push_bytes(&first_record[..3])
            .expect("buffer partial prefix");
        assert_eq!(stream.pending_len(), 3);
        assert_eq!(stream.pop_next_frame().expect("partial decode"), None);
        stream
            .push_bytes(&first_record[3..])
            .expect("finish first record");
        let decoded_first = stream
            .pop_next_frame()
            .expect("decode first")
            .expect("first complete");
        assert_eq!(decoded_first.packet().opaque_bytes(), b"buffered-first");
        assert_eq!(stream.pending_len(), 0);

        let mut coalesced = second_record.clone();
        coalesced.extend_from_slice(&first_record);
        stream
            .push_bytes(&coalesced)
            .expect("buffer coalesced records");
        let drained = stream
            .drain_available_frames()
            .expect("drain coalesced records");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].from_peer_id(), peer(2));
        assert_eq!(drained[1].from_peer_id(), peer(1));
        assert_eq!(stream.pending_len(), 0);

        let mut tight_stream = RelayTcpTlsStreamBuffer::new(
            RelayQuota::default().max_packet_bytes,
            first_record.len(),
        )
        .expect("tight stream buffer");
        tight_stream
            .push_bytes(&first_record)
            .expect("fill buffer exactly with one record");
        assert_eq!(
            tight_stream
                .push_bytes(&[0])
                .expect_err("bounded buffer rejects unbounded stream growth"),
            RelayError::PacketTooLarge
        );
        assert_eq!(tight_stream.pending_len(), first_record.len());
        tight_stream.clear();
        assert_eq!(tight_stream.pending_len(), 0);

        let undersized_cap = first_record.len() - 1;
        let mut undersized_stream =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, undersized_cap)
                .expect("undersized stream buffer still holds minimum record header");
        undersized_stream
            .push_bytes(&first_record[..undersized_cap])
            .expect("fill undersized buffer with incomplete record");
        assert_eq!(
            undersized_stream
                .pop_next_frame()
                .expect_err("record that can never fit the buffer fails closed"),
            RelayError::PacketTooLarge
        );
        assert_eq!(undersized_stream.pending_len(), undersized_cap);

        let udp_frame = RelayWireFrame::new(
            reservation_id(39),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::Udp, b"udp-in-stream-buffer", 3),
        );
        let udp_encoded = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode raw udp relay frame");
        let udp_len = u32::try_from(udp_encoded.len()).expect("udp frame len fits in u32");
        let mut udp_record =
            Vec::with_capacity(RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN + udp_encoded.len());
        udp_record.extend_from_slice(&udp_len.to_be_bytes());
        udp_record.extend_from_slice(&udp_encoded);
        stream.push_bytes(&udp_record).expect("buffer bad record");
        assert_eq!(
            stream
                .pop_next_frame()
                .expect_err("stream buffer rejects udp record on tcp path"),
            RelayError::InvalidRelayWireFrame
        );
        assert_eq!(
            stream.pending_len(),
            udp_record.len(),
            "malformed bytes are retained for caller diagnostics before close"
        );
    }

    #[test]
    fn udp_socket_ingress_and_egress_round_trip_without_plaintext_authority() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(40),
                "path-relay-40",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let frame = RelayWireFrame::new(
            reservation_id(40),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"udp-socket-ciphertext", 1, 90),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        assert_eq!(
            service
                .forward_udp_datagram(
                    124,
                    peer(3),
                    &encoded,
                    RelayQuota::default().max_packet_bytes
                )
                .expect_err("endpoint peer mismatch must not forward"),
            RelayError::UnauthorizedPeer
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(40))
                .expect("proof after rejected endpoint mismatch")
                .packets_forwarded,
            0
        );
        assert!(service.events().iter().any(|event| {
            event.kind == RelayEventKind::AuthorizationRejected
                && event.transport == Some(RelayTransport::Udp)
                && event.quota_decision == "endpoint_peer_mismatch_rejected"
        }));
        let forwarded = service
            .forward_udp_datagram(
                125,
                peer(1),
                &encoded,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("udp datagram forwards");
        assert_eq!(forwarded.to_peer_id(), peer(2));
        assert_eq!(forwarded.packet().opaque_bytes(), b"udp-socket-ciphertext");

        let dst_addr = SocketAddr::from(([127, 0, 0, 1], 45_000));
        let datagram = service
            .dequeue_udp_datagram_for_peer(
                peer(2),
                dst_addr,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("encode outbound udp datagram")
            .expect("queued udp packet");
        assert_eq!(datagram.dst_addr(), dst_addr);
        assert_eq!(datagram.to_peer_id(), peer(2));
        assert_eq!(datagram.reservation_id(), reservation_id(40));
        assert_eq!(
            datagram.opaque_bytes(),
            u64::try_from(b"udp-socket-ciphertext".len()).expect("ciphertext len fits in u64")
        );

        let decoded =
            RelayWireFrame::decode(datagram.payload(), RelayQuota::default().max_packet_bytes)
                .expect("decode outbound datagram frame");
        assert_eq!(decoded.reservation_id(), reservation_id(40));
        assert_eq!(decoded.transfer_nonce(), transfer_nonce(9));
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().transport(), RelayTransport::Udp);
        assert_eq!(decoded.packet().opaque_bytes(), b"udp-socket-ciphertext");
        assert!(
            service
                .dequeue_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("empty udp queue")
                .is_none()
        );
    }

    #[test]
    fn udp_socket_egress_peek_does_not_consume_before_commit() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(41),
                "path-relay-41",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let frame = RelayWireFrame::new(
            reservation_id(41),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"udp-peek-ciphertext", 1, 90),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        service
            .forward_udp_datagram(
                125,
                peer(1),
                &encoded,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("udp datagram forwards");

        let dst_addr = SocketAddr::from(([127, 0, 0, 1], 45_001));
        let first = service
            .peek_udp_datagram_for_peer(peer(2), dst_addr, RelayQuota::default().max_packet_bytes)
            .expect("peek queued udp")
            .expect("queued udp packet");
        let second = service
            .peek_udp_datagram_for_peer(peer(2), dst_addr, RelayQuota::default().max_packet_bytes)
            .expect("peek queued udp again")
            .expect("queue remains intact after peek");
        assert_eq!(first, second);
        assert_eq!(
            service
                .commit_udp_datagram_for_peer(peer(2), reservation_id(999))
                .expect_err("wrong reservation does not consume queue"),
            RelayError::UnknownReservation
        );
        assert!(
            service
                .peek_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("peek after failed commit")
                .is_some()
        );

        service
            .commit_udp_datagram_for_peer(peer(2), reservation_id(41))
            .expect("commit sent datagram");
        assert!(
            service
                .peek_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("empty queue after commit")
                .is_none()
        );
    }

    #[test]
    fn tcp_tls_egress_peek_does_not_consume_before_commit() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(43),
                "path-relay-43",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                125,
                reservation_id(43),
                peer(1),
                packet_sent_at(RelayTransport::TcpTls443, b"tcp-peek-ciphertext", 1, 90),
            )
            .expect("tcp fallback packet forwards");

        let first = service
            .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
            .expect("peek queued tcp")
            .expect("queued tcp packet");
        let second = service
            .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
            .expect("peek queued tcp again")
            .expect("queue remains intact after tcp peek");
        assert_eq!(first, second);
        assert_eq!(
            service
                .commit_tcp_tls_record_for_peer(peer(2), reservation_id(999))
                .expect_err("wrong reservation does not consume tcp queue"),
            RelayError::UnknownReservation
        );
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after failed tcp commit")
                .is_some()
        );

        service
            .commit_tcp_tls_record_for_peer(peer(2), reservation_id(43))
            .expect("commit sent tcp record");
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("empty tcp queue after commit")
                .is_none()
        );
    }

    #[test]
    fn tcp_tls_socket_write_uses_explicit_stream_binding_before_dequeue() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(44),
                "path-relay-44",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                125,
                reservation_id(44),
                peer(1),
                packet_sent_at(RelayTransport::TcpTls443, b"stream-bound-ciphertext", 1, 90),
            )
            .expect("tcp fallback packet forwards");

        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 1,
                max_tcp_tls_streams: 2,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let source_stream = RelayTcpTlsStreamId::new(44).expect("source stream");
        let destination_stream = RelayTcpTlsStreamId::new(45).expect("destination stream");
        socket_loop
            .admit_tcp_tls_stream(peer(1), source_stream)
            .expect("admit source stream");
        socket_loop
            .admit_tcp_tls_stream(peer(2), destination_stream)
            .expect("admit destination stream");

        let mut wrong_writer = Vec::new();
        assert_eq!(
            socket_loop
                .send_tcp_tls_stream_once(&mut service, source_stream, &mut wrong_writer)
                .expect("source stream has no outbound record"),
            None
        );
        assert!(wrong_writer.is_empty());
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("destination queue remains after wrong stream id")
                .is_some()
        );

        let mut destination_writer = Vec::new();
        let written = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut destination_writer)
            .expect("destination stream writes queued record")
            .expect("bytes written");
        assert_eq!(written, destination_writer.len());
        let decoded = RelayWireFrame::decode_complete_tcp_tls_record(
            &destination_writer,
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode written record");
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().opaque_bytes(), b"stream-bound-ciphertext");
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("queue drained only after destination stream write")
                .is_none()
        );
    }

    #[test]
    fn tcp_tls_socket_write_commits_queue_only_after_positive_write() {
        struct WouldBlockWriter;

        impl io::Write for WouldBlockWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct ZeroWriter;

        impl io::Write for ZeroWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Ok(0)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct PrefixWriter {
            max_write: usize,
            bytes: Vec<u8>,
        }

        impl io::Write for PrefixWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let accepted = self.max_write.min(buf.len());
                self.bytes.extend_from_slice(&buf[..accepted]);
                Ok(accepted)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(45),
                "path-relay-45",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                125,
                reservation_id(45),
                peer(1),
                packet_sent_at(
                    RelayTransport::TcpTls443,
                    b"commit-after-positive-write",
                    1,
                    90,
                ),
            )
            .expect("tcp fallback packet forwards");

        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 1,
                max_tcp_tls_streams: 1,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let destination_stream = RelayTcpTlsStreamId::new(45).expect("destination stream");
        socket_loop
            .admit_tcp_tls_stream(peer(2), destination_stream)
            .expect("admit destination stream");

        let err = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut WouldBlockWriter)
            .expect_err("would-block must not commit queued tcp record");
        assert!(matches!(err, RelaySocketIoError::WouldBlock));
        assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after would-block")
                .is_some()
        );

        let err = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut ZeroWriter)
            .expect_err("zero write must not commit queued tcp record");
        match err {
            RelaySocketIoError::TcpTlsWriteZero {
                stream_id,
                remaining,
            } => {
                assert_eq!(stream_id, destination_stream);
                assert!(remaining > 0);
            }
            other => panic!("unexpected zero-write error: {other:?}"),
        }
        assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after zero write")
                .is_some()
        );

        let mut partial_writer = PrefixWriter {
            max_write: 7,
            bytes: Vec::new(),
        };
        let first_write = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut partial_writer)
            .expect("positive prefix write")
            .expect("bytes written");
        assert_eq!(first_write, 7);
        assert!(socket_loop.tcp_tls_pending_write_len(destination_stream) > 0);
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after positive write")
                .is_none()
        );

        partial_writer.max_write = usize::MAX;
        while socket_loop.tcp_tls_pending_write_len(destination_stream) > 0 {
            let written = socket_loop
                .send_tcp_tls_stream_once(&mut service, destination_stream, &mut partial_writer)
                .expect("flush retained tcp suffix")
                .expect("suffix bytes written");
            assert!(written > 0);
        }
        assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);

        let decoded = RelayWireFrame::decode_complete_tcp_tls_record(
            &partial_writer.bytes,
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode fully written record");
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(
            decoded.packet().opaque_bytes(),
            b"commit-after-positive-write"
        );
    }

    #[test]
    fn endpoint_admission_helpers_reject_unknown_or_mismatched_socket_sources() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(42),
                "path-relay-42",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        let mut directory = RelayEndpointDirectory::default();
        let source_udp = SocketAddr::from(([203, 0, 113, 10], 47_000));
        let wrong_udp = SocketAddr::from(([203, 0, 113, 11], 47_001));
        let source_stream = RelayTcpTlsStreamId::new(42).expect("source stream");
        let wrong_stream = RelayTcpTlsStreamId::new(43).expect("wrong stream");
        directory
            .bind_udp_endpoint(peer(1), source_udp)
            .expect("bind source udp");
        directory
            .bind_udp_endpoint(peer(3), wrong_udp)
            .expect("bind wrong udp");
        directory
            .bind_tcp_tls_stream(peer(1), source_stream)
            .expect("bind source stream");
        directory
            .bind_tcp_tls_stream(peer(3), wrong_stream)
            .expect("bind wrong stream");

        let udp_frame = RelayWireFrame::new(
            reservation_id(42),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"udp-endpoint-ciphertext", 1, 90),
        );
        let udp_datagram = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        assert_eq!(
            service
                .forward_udp_datagram_from_endpoint(
                    100,
                    &directory,
                    SocketAddr::from(([203, 0, 113, 99], 47_099)),
                    &udp_datagram,
                    RelayQuota::default().max_packet_bytes,
                )
                .expect_err("unknown udp endpoint"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(42))
                .expect("proof after unknown udp endpoint")
                .packets_forwarded,
            0
        );
        assert_eq!(
            service
                .forward_udp_datagram_from_endpoint(
                    101,
                    &directory,
                    wrong_udp,
                    &udp_datagram,
                    RelayQuota::default().max_packet_bytes,
                )
                .expect_err("mismatched udp endpoint"),
            RelayError::UnauthorizedPeer
        );
        let udp_forwarded = service
            .forward_udp_datagram_from_endpoint(
                102,
                &directory,
                source_udp,
                &udp_datagram,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("forward admitted udp endpoint");
        assert_eq!(udp_forwarded.to_peer_id(), peer(2));

        let tcp_frame = RelayWireFrame::new(
            reservation_id(42),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(
                RelayTransport::TcpTls443,
                b"tcp-endpoint-ciphertext",
                2,
                110,
            ),
        );
        let tcp_record = tcp_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode tcp record");
        let mut unknown_stream_buffer =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("unknown stream buffer");
        assert_eq!(
            service
                .forward_tcp_tls_stream_bytes_from_endpoint(
                    120,
                    &directory,
                    RelayTcpTlsStreamId::new(44).expect("unknown stream"),
                    &mut unknown_stream_buffer,
                    &tcp_record,
                )
                .expect_err("unknown tcp stream"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(unknown_stream_buffer.pending_len(), 0);

        let mut wrong_stream_buffer =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("wrong stream buffer");
        assert_eq!(
            service
                .forward_tcp_tls_stream_bytes_from_endpoint(
                    121,
                    &directory,
                    wrong_stream,
                    &mut wrong_stream_buffer,
                    &tcp_record,
                )
                .expect_err("mismatched tcp stream"),
            RelayError::UnauthorizedPeer
        );
        assert!(service.events().iter().any(|event| {
            event.kind == RelayEventKind::AuthorizationRejected
                && event.quota_decision == "endpoint_peer_mismatch_rejected"
                && event.transport == Some(RelayTransport::TcpTls443)
        }));

        let mut source_stream_buffer =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("source stream buffer");
        let tcp_forwarded = service
            .forward_tcp_tls_stream_bytes_from_endpoint(
                122,
                &directory,
                source_stream,
                &mut source_stream_buffer,
                &tcp_record,
            )
            .expect("forward admitted tcp stream");
        assert_eq!(tcp_forwarded.len(), 1);
        assert_eq!(tcp_forwarded[0].to_peer_id(), peer(2));
    }

    #[test]
    fn tcp_listener_accept_allocates_and_admits_stream_ids() {
        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 1,
                max_tcp_tls_streams: 1,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("listener nonblocking");
        assert!(
            socket_loop
                .accept_tcp_tls_stream_once(&listener, peer(1))
                .expect("empty nonblocking accept")
                .is_none()
        );
        listener
            .set_nonblocking(false)
            .expect("listener blocking for deterministic accept");

        let client = TcpStream::connect(listener.local_addr().expect("listener addr"))
            .expect("client connects");
        let accepted = socket_loop
            .accept_tcp_tls_stream_once(&listener, peer(1))
            .expect("accept stream")
            .expect("accepted stream");
        assert_eq!(accepted.stream_id().get(), 1);
        assert_eq!(accepted.peer_id(), peer(1));
        assert_eq!(
            accepted.peer_addr(),
            client.local_addr().expect("client local addr")
        );
        assert_eq!(
            socket_loop
                .endpoints()
                .peer_for_tcp_tls_stream(accepted.stream_id())
                .expect("accepted stream admitted"),
            peer(1)
        );
        assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 1);

        let _second_client = TcpStream::connect(listener.local_addr().expect("listener addr"))
            .expect("second client connects");
        let err = socket_loop
            .accept_tcp_tls_stream_once(&listener, peer(2))
            .expect_err("quota prevents second accepted stream");
        match err {
            RelaySocketIoError::Relay {
                source: RelayError::QuotaExceeded,
            } => {}
            other => panic!("unexpected accept error: {other:?}"),
        }
        assert_eq!(socket_loop.endpoints().tcp_tls_stream_count(), 1);
        assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 1);
    }

    #[test]
    fn relay_socket_loop_bridges_admitted_endpoints_and_closes_bad_streams() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(48),
                "path-relay-48",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 4,
                max_tcp_tls_streams: 4,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let source_udp = SocketAddr::from(([203, 0, 113, 40], 47_040));
        let destination_udp = SocketAddr::from(([203, 0, 113, 41], 47_041));
        let source_stream = RelayTcpTlsStreamId::new(48).expect("source stream");
        let destination_stream = RelayTcpTlsStreamId::new(49).expect("destination stream");
        let orphaned_stream = RelayTcpTlsStreamId::new(50).expect("orphaned stream");

        socket_loop
            .admit_udp_endpoint(peer(1), source_udp)
            .expect("admit source udp");
        socket_loop
            .admit_udp_endpoint(peer(2), destination_udp)
            .expect("admit destination udp");
        socket_loop
            .admit_tcp_tls_stream(peer(1), source_stream)
            .expect("admit source tcp");
        socket_loop
            .admit_tcp_tls_stream(peer(2), destination_stream)
            .expect("admit destination tcp");
        socket_loop
            .admit_tcp_tls_stream(peer(1), orphaned_stream)
            .expect("admit stream for orphan-buffer regression");
        socket_loop.tcp_tls_streams.remove(&orphaned_stream);
        assert_eq!(
            socket_loop
                .ingest_tcp_tls_stream_bytes(&mut service, 80, orphaned_stream, b"")
                .expect_err("admitted stream without buffer fails closed"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(
            socket_loop
                .endpoints()
                .peer_for_tcp_tls_stream(orphaned_stream)
                .expect_err("orphaned stream binding is removed"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(socket_loop.endpoints().udp_endpoint_count(), 2);
        assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 2);

        let udp_frame = RelayWireFrame::new(
            reservation_id(48),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"loop-udp-ciphertext", 1, 90),
        );
        let udp_datagram = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        let udp_forwarded = socket_loop
            .ingest_udp_datagram(&mut service, 100, source_udp, &udp_datagram)
            .expect("ingest admitted udp datagram");
        assert_eq!(udp_forwarded.to_peer_id(), peer(2));
        assert_eq!(
            socket_loop
                .drain_udp_datagram_for_peer(&mut service, peer(3))
                .expect_err("unknown udp destination"),
            RelayError::UnknownRelayEndpoint
        );
        let drained_udp = socket_loop
            .drain_udp_datagram_for_peer(&mut service, peer(2))
            .expect("drain udp")
            .expect("queued udp datagram");
        assert_eq!(drained_udp.dst_addr(), destination_udp);
        let decoded_udp = RelayWireFrame::decode(
            drained_udp.payload(),
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode drained udp");
        assert_eq!(decoded_udp.from_peer_id(), peer(1));
        assert_eq!(decoded_udp.packet().opaque_bytes(), b"loop-udp-ciphertext");

        let tcp_frame = RelayWireFrame::new(
            reservation_id(48),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::TcpTls443, b"loop-tcp-ciphertext", 2, 110),
        );
        let tcp_record = tcp_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode tcp record");
        assert_eq!(
            socket_loop
                .ingest_tcp_tls_stream_bytes(&mut service, 120, source_stream, &tcp_record[..2])
                .expect("partial tcp prefix"),
            Vec::new()
        );
        assert_eq!(
            socket_loop
                .tcp_tls_pending_len(source_stream)
                .expect("source pending bytes"),
            2
        );
        let tcp_forwarded = socket_loop
            .ingest_tcp_tls_stream_bytes(&mut service, 121, source_stream, &tcp_record[2..])
            .expect("complete tcp record");
        assert_eq!(tcp_forwarded.len(), 1);
        let drained_tcp = socket_loop
            .drain_tcp_tls_record_for_peer(&mut service, peer(2))
            .expect("drain tcp")
            .expect("queued tcp record");
        assert_eq!(drained_tcp.stream_id(), destination_stream);
        assert_eq!(drained_tcp.to_peer_id(), peer(2));
        let decoded_tcp = RelayWireFrame::decode_complete_tcp_tls_record(
            drained_tcp.bytes(),
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode drained tcp");
        assert_eq!(decoded_tcp.packet().opaque_bytes(), b"loop-tcp-ciphertext");

        let mismatch_frame = RelayWireFrame::new(
            reservation_id(48),
            transfer_nonce(9),
            peer(3),
            packet_sent_at(RelayTransport::TcpTls443, b"bad-stream-ciphertext", 3, 130),
        );
        let mismatch_record = mismatch_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode mismatch record");
        assert_eq!(
            socket_loop
                .ingest_tcp_tls_stream_bytes(&mut service, 140, source_stream, &mismatch_record)
                .expect_err("mismatched stream source"),
            RelayError::UnauthorizedPeer
        );
        assert_eq!(
            socket_loop
                .tcp_tls_pending_len(source_stream)
                .expect_err("bad stream closed"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(
            socket_loop
                .close_tcp_tls_stream(destination_stream)
                .expect("close destination stream"),
            peer(2)
        );
        assert_eq!(
            socket_loop
                .drain_tcp_tls_record_for_peer(&mut service, peer(2))
                .expect_err("closed tcp destination"),
            RelayError::UnknownRelayEndpoint
        );
    }

    #[test]
    fn socket_adapters_fail_closed_and_preserve_transport_order() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(41),
                "path-relay-41",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let tcp_frame = RelayWireFrame::new(
            reservation_id(41),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::TcpTls443, b"tcp-stream-ciphertext", 1, 90),
        );
        let canonical_tcp_frame = tcp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode canonical tcp frame");
        assert_eq!(
            service
                .forward_udp_datagram(
                    100,
                    peer(1),
                    &canonical_tcp_frame,
                    RelayQuota::default().max_packet_bytes
                )
                .expect_err("tcp frame must not enter udp datagram ingress"),
            RelayError::InvalidRelayWireFrame
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(41))
                .expect("proof after rejected udp ingress")
                .packets_forwarded,
            0
        );

        let tcp_record = tcp_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode tcp record");
        let mut mismatched_stream =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("mismatched stream buffer");
        assert_eq!(
            service
                .forward_tcp_tls_stream_bytes(124, peer(3), &mut mismatched_stream, &tcp_record)
                .expect_err("endpoint peer mismatch must not forward tcp record"),
            RelayError::UnauthorizedPeer
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(41))
                .expect("proof after rejected tcp endpoint mismatch")
                .packets_forwarded,
            0
        );
        assert!(service.events().iter().any(|event| {
            event.kind == RelayEventKind::AuthorizationRejected
                && event.transport == Some(RelayTransport::TcpTls443)
                && event.quota_decision == "endpoint_peer_mismatch_rejected"
        }));
        let mut stream =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("stream buffer");
        let forwarded = service
            .forward_tcp_tls_stream_bytes(125, peer(1), &mut stream, &tcp_record)
            .expect("tcp stream forwards");
        assert_eq!(forwarded.len(), 1);

        let dst_addr = SocketAddr::from(([127, 0, 0, 1], 45_001));
        assert!(
            service
                .dequeue_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("udp egress sees tcp front and preserves it")
                .is_none()
        );
        let record = service
            .dequeue_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
            .expect("encode outbound tcp record")
            .expect("queued tcp packet");
        assert_eq!(record.to_peer_id(), peer(2));
        assert_eq!(record.reservation_id(), reservation_id(41));
        assert_eq!(
            record.opaque_bytes(),
            u64::try_from(b"tcp-stream-ciphertext".len()).expect("ciphertext len fits in u64")
        );
        let decoded = RelayWireFrame::decode_complete_tcp_tls_record(
            record.bytes(),
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode outbound tcp record");
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().transport(), RelayTransport::TcpTls443);
        assert_eq!(decoded.packet().opaque_bytes(), b"tcp-stream-ciphertext");
        assert!(
            service
                .dequeue_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("empty tcp queue")
                .is_none()
        );
    }

    #[test]
    fn dequeue_removes_empty_peer_queue_from_restart_snapshot() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(25),
                "path-relay-25",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(25),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        assert!(service.dequeue_for_peer(peer(2)).is_some());
        let snapshot = service.snapshot();
        assert!(
            snapshot
                .queues
                .iter()
                .all(|(queued_peer, _)| *queued_peer != peer(2))
        );
        assert!(
            snapshot
                .queues
                .iter()
                .all(|(_, queued_packets)| !queued_packets.is_empty())
        );
    }

    #[test]
    fn rejects_quota_overflow_and_logs_rejection() {
        let quota = RelayQuota {
            max_packets_per_reservation: 1,
            max_bytes_per_reservation: 4,
            max_packet_bytes: 4,
        };
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(4),
                "path-relay-4",
                grant(1_000, quota),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        service
            .forward(
                20,
                reservation_id(4),
                peer(1),
                packet(RelayTransport::Udp, b"abcd", 1),
            )
            .expect("first packet");
        assert_eq!(
            service
                .forward(
                    21,
                    reservation_id(4),
                    peer(1),
                    packet(RelayTransport::Udp, b"e", 2)
                )
                .expect_err("quota"),
            RelayError::QuotaExceeded
        );
        assert!(
            service
                .events()
                .iter()
                .any(|event| event.kind == RelayEventKind::QuotaRejected)
        );
    }

    #[test]
    fn rejects_expired_reservations_and_unauthorized_peers() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    20,
                    reservation_id(5),
                    "expired",
                    grant(20, RelayQuota::default()),
                    &|_: &RelayReservationGrant| true,
                )
                .expect_err("expired"),
            RelayError::ExpiredReservation
        );

        service
            .reserve(
                10,
                reservation_id(6),
                "path-relay-6",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(6),
                    peer(3),
                    packet(RelayTransport::Udp, b"ciphertext", 1)
                )
                .expect_err("unauthorized"),
            RelayError::UnauthorizedPeer
        );
    }

    #[test]
    fn invalid_grant_authorization_is_logged_without_accepting_reservation() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    10,
                    reservation_id(17),
                    "path-relay-17",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("auth"),
            RelayError::InvalidAuthorization
        );

        let event = service.events().last().expect("auth event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(17)));
        assert_eq!(event.path_id.as_deref(), Some("path-relay-17"));
        assert_eq!(event.from_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.to_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.transport, None);
        assert_eq!(event.opaque_bytes, 0);
        assert_eq!(event.quota_decision, "grant_authorization_rejected");
        assert_eq!(
            service
                .proof_artifact(reservation_id(17))
                .expect_err("rejected reservation must not be installed"),
            RelayError::UnknownReservation
        );
    }

    #[test]
    fn invalid_grant_authorization_precedes_duplicate_and_capacity_checks() {
        let config = RelayServiceConfig::new("tiny-relay", 1).expect("config");
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(19),
                "path-relay-19",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .reserve(
                    11,
                    reservation_id(19),
                    "path-relay-duplicate-invalid",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid duplicate grant"),
            RelayError::InvalidAuthorization
        );
        assert_eq!(
            service
                .reserve(
                    12,
                    reservation_id(20),
                    "path-relay-over-capacity-invalid",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid over-capacity grant"),
            RelayError::InvalidAuthorization
        );

        let auth_rejections = service
            .events()
            .iter()
            .filter(|event| event.kind == RelayEventKind::AuthorizationRejected)
            .count();
        assert_eq!(auth_rejections, 2);
        assert!(
            service
                .events()
                .iter()
                .all(|event| event.quota_decision != "active_reservation_quota_rejected")
        );
    }

    #[test]
    fn invalid_grant_authorization_precedes_expiry_check() {
        let mut service = RelayService::new(RelayServiceConfig::default());

        assert_eq!(
            service
                .reserve(
                    20,
                    reservation_id(32),
                    "path-relay-32",
                    grant(20, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid expired grant"),
            RelayError::InvalidAuthorization
        );

        let event = service.events().last().expect("auth rejection event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(32)));
        assert_eq!(event.quota_decision, "grant_authorization_rejected");
        assert_eq!(event.path_id.as_deref(), Some("path-relay-32"));
        assert_eq!(
            service
                .proof_artifact(reservation_id(32))
                .expect_err("invalid grant must not install expired reservation"),
            RelayError::UnknownReservation
        );
    }

    #[test]
    fn unauthorized_peer_rejection_is_logged_before_transport_policy() {
        let config = RelayServiceConfig::default().with_tcp_tls_443_enabled(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(18),
                "path-relay-18",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(18),
                    peer(9),
                    packet(RelayTransport::TcpTls443, b"ciphertext", 1),
                )
                .expect_err("unauthorized"),
            RelayError::UnauthorizedPeer
        );

        let event = service.events().last().expect("auth event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(18)));
        assert_eq!(event.from_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.to_peer, None);
        assert_eq!(event.transport, Some(RelayTransport::TcpTls443));
        assert_eq!(event.opaque_bytes, 10);
        assert_eq!(event.quota_decision, "peer_authorization_rejected");
        assert_eq!(event.fallback_reason, None);
        assert_eq!(
            service.usage(reservation_id(18)).expect("usage"),
            RelayUsage::default()
        );
    }

    #[test]
    fn unauthorized_peer_rejection_precedes_lifecycle_state() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(21),
                "path-relay-21",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .cancel_reservation(reservation_id(21))
            .expect("cancel");

        assert_eq!(
            service
                .forward(
                    40,
                    reservation_id(21),
                    peer(9),
                    packet(RelayTransport::Udp, b"ciphertext", 1),
                )
                .expect_err("unauthorized cancellation probe"),
            RelayError::UnauthorizedPeer
        );
        let cancelled_probe_event = service.events().last().expect("auth event");
        assert_eq!(
            cancelled_probe_event.kind,
            RelayEventKind::AuthorizationRejected
        );
        assert_eq!(
            cancelled_probe_event.quota_decision,
            "peer_authorization_rejected"
        );

        service
            .reserve(
                10,
                reservation_id(22),
                "path-relay-22",
                grant(20, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        assert_eq!(
            service
                .forward(
                    30,
                    reservation_id(22),
                    peer(9),
                    packet(RelayTransport::Udp, b"ciphertext", 2),
                )
                .expect_err("unauthorized expiry probe"),
            RelayError::UnauthorizedPeer
        );
        let expired_probe_event = service.events().last().expect("auth event");
        assert_eq!(
            expired_probe_event.kind,
            RelayEventKind::AuthorizationRejected
        );
        assert!(
            service
                .events()
                .iter()
                .filter(|event| event.reservation_id == Some(reservation_id(22)))
                .all(|event| event.kind != RelayEventKind::ReservationExpired)
        );
    }

    #[test]
    fn quota_rejection_logs_actual_packet_direction() {
        let quota = RelayQuota {
            max_packets_per_reservation: 4,
            max_bytes_per_reservation: 4,
            max_packet_bytes: 4,
        };
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(23),
                "path-relay-23",
                grant(1_000, quota),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(23),
                    peer(2),
                    packet(RelayTransport::Udp, b"abcde", 1),
                )
                .expect_err("oversized reverse packet"),
            RelayError::PacketTooLarge
        );

        let event = service.events().last().expect("quota event");
        assert_eq!(event.kind, RelayEventKind::QuotaRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(23)));
        assert_eq!(event.from_peer.as_deref(), Some("peer:0202..."));
        assert_eq!(event.to_peer.as_deref(), Some("peer:0101..."));
        assert_eq!(event.opaque_bytes, 5);
        assert_eq!(event.quota_decision, "packet_quota_rejected");
        assert_eq!(
            service.usage(reservation_id(23)).expect("usage"),
            RelayUsage::default()
        );
    }

    #[test]
    fn rejects_invalid_auth_and_cancelled_reservations() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    10,
                    reservation_id(7),
                    "path-relay-7",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("auth"),
            RelayError::InvalidAuthorization
        );

        service
            .reserve(
                10,
                reservation_id(8),
                "path-relay-8",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .cancel_reservation(reservation_id(8))
            .expect("cancel");
        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(8),
                    peer(1),
                    packet(RelayTransport::Udp, b"ciphertext", 1)
                )
                .expect_err("cancelled"),
            RelayError::ReservationCancelled
        );
    }

    #[test]
    fn cancellation_drains_queued_packets_for_reservation() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(12),
                "path-relay-12",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(12),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        service
            .cancel_reservation(reservation_id(12))
            .expect("cancel");

        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        let usage = service.usage(reservation_id(12)).expect("usage");
        assert_eq!(usage.dropped_packets, 1);
        assert_eq!(
            service
                .events()
                .last()
                .expect("cancel event")
                .quota_decision,
            "reservation_cancelled_queued_packets_drained"
        );
    }

    #[test]
    fn cancel_reservation_is_idempotent_after_first_drain() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(24),
                "path-relay-24",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(24),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        service
            .cancel_reservation(reservation_id(24))
            .expect("first cancel");
        let events_after_first_cancel = service.events().len();
        let usage_after_first_cancel = service.usage(reservation_id(24)).expect("usage");
        service
            .cancel_reservation(reservation_id(24))
            .expect("second cancel");

        assert_eq!(service.events().len(), events_after_first_cancel);
        assert_eq!(
            service.usage(reservation_id(24)).expect("usage"),
            usage_after_first_cancel
        );
        assert_eq!(usage_after_first_cancel.dropped_packets, 1);
        assert_eq!(service.dequeue_for_peer(peer(2)), None);
    }

    #[test]
    fn expired_reservations_do_not_consume_active_capacity() {
        let config = RelayServiceConfig::new("tiny-relay", 1).expect("config");
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(13),
                "path-relay-13",
                grant(20, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("first reservation");

        let candidate = service
            .reserve(
                30,
                reservation_id(14),
                "path-relay-14",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("expired reservation should not occupy the only active slot");

        assert_eq!(candidate.reservation_id(), reservation_id(14));
        assert_eq!(service.snapshot().reservation_count(), 1);
        assert!(
            service
                .snapshot()
                .reservations
                .iter()
                .all(|(id, _)| *id != reservation_id(13))
        );
        assert!(
            service
                .events()
                .iter()
                .any(|event| event.reservation_id == Some(reservation_id(13))
                    && event.kind == RelayEventKind::ReservationExpired)
        );
    }

    #[test]
    fn forwarding_after_expiry_drains_queued_packets_and_blocks_restart_retention() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(26),
                "path-relay-26",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(26),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");

        assert_eq!(
            service
                .forward(
                    31,
                    reservation_id(26),
                    peer(1),
                    packet(RelayTransport::Udp, b"late", 2),
                )
                .expect_err("expired forward"),
            RelayError::ExpiredReservation
        );

        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        let usage = service.usage(reservation_id(26)).expect("usage");
        assert_eq!(usage.forwarded_packets, 1);
        assert_eq!(usage.dropped_packets, 1);

        let event = service.events().last().expect("expiry event");
        assert_eq!(event.kind, RelayEventKind::ReservationExpired);
        assert_eq!(
            event.quota_decision,
            "reservation_expired_queued_packets_drained"
        );
        assert_eq!(event.opaque_bytes, 10);
        assert_eq!(service.snapshot().reservation_count(), 0);
    }

    #[test]
    fn expire_reservations_drains_only_expired_queues() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(27),
                "path-relay-27",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("expired candidate");
        service
            .reserve(
                10,
                reservation_id(28),
                "path-relay-28",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("active candidate");
        service
            .forward(
                20,
                reservation_id(27),
                peer(1),
                packet(RelayTransport::Udp, b"expired", 1),
            )
            .expect("expired queued before cutoff");
        let active_packet = service
            .forward(
                20,
                reservation_id(28),
                peer(1),
                packet(RelayTransport::Udp, b"active", 2),
            )
            .expect("active queued");

        assert_eq!(service.expire_reservations(31), 1);
        assert_eq!(service.active_reservation_count(20), 1);
        assert_eq!(
            service.dequeue_for_peer(peer(2)).expect("active packet"),
            active_packet
        );
        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        assert_eq!(
            service
                .proof_artifact(reservation_id(27))
                .expect("expired proof remains auditable")
                .packets_forwarded,
            1
        );
        assert_eq!(service.snapshot().reservation_count(), 1);
        assert_eq!(
            service
                .snapshot()
                .reservations
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![reservation_id(28)]
        );
    }

    #[test]
    fn cancellation_after_expiry_is_terminal_idempotent() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(29),
                "path-relay-29",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(29),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");
        assert_eq!(
            service
                .forward(
                    31,
                    reservation_id(29),
                    peer(1),
                    packet(RelayTransport::Udp, b"late", 2),
                )
                .expect_err("expired"),
            RelayError::ExpiredReservation
        );
        let events_after_expiry = service.events().len();
        let usage_after_expiry = service.usage(reservation_id(29)).expect("usage");

        service
            .cancel_reservation(reservation_id(29))
            .expect("cancel after expiry is a no-op");

        assert_eq!(service.events().len(), events_after_expiry);
        assert_eq!(
            service.usage(reservation_id(29)).expect("usage"),
            usage_after_expiry
        );
        assert_eq!(
            service.events().last().expect("expiry event").kind,
            RelayEventKind::ReservationExpired
        );
    }

    #[test]
    fn packet_loss_after_cancellation_does_not_mutate_usage_or_proof() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(30),
                "path-relay-30",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(30),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");
        service
            .cancel_reservation(reservation_id(30))
            .expect("cancel");

        let events_after_cancel = service.events().len();
        let usage_after_cancel = service.usage(reservation_id(30)).expect("usage");
        let proof_after_cancel = service
            .proof_artifact(reservation_id(30))
            .expect("proof artifact");

        assert_eq!(
            service
                .record_packet_loss(reservation_id(30), 1, 10)
                .expect_err("terminal reservations reject loss summaries"),
            RelayError::ReservationCancelled
        );
        assert_eq!(
            service
                .record_packet_loss(reservation_id(30), 1, 0)
                .expect_err("terminal lifecycle wins over malformed loss summary"),
            RelayError::ReservationCancelled
        );

        assert_eq!(service.events().len(), events_after_cancel);
        assert_eq!(
            service.usage(reservation_id(30)).expect("usage"),
            usage_after_cancel
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(30))
                .expect("proof artifact"),
            proof_after_cancel
        );
        assert_eq!(usage_after_cancel.loss_summary, None);
        assert_eq!(
            service.events().last().expect("cancel event").kind,
            RelayEventKind::ReservationCancelled
        );
    }

    #[test]
    fn packet_loss_after_expiry_does_not_mutate_usage_or_proof() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(31),
                "path-relay-31",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(31),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");

        assert_eq!(service.expire_reservations(31), 1);
        let events_after_expiry = service.events().len();
        let usage_after_expiry = service.usage(reservation_id(31)).expect("usage");
        let proof_after_expiry = service
            .proof_artifact(reservation_id(31))
            .expect("proof artifact");

        assert_eq!(
            service
                .record_packet_loss(reservation_id(31), 1, 10)
                .expect_err("expired reservations reject loss summaries"),
            RelayError::ExpiredReservation
        );
        assert_eq!(
            service
                .record_packet_loss(reservation_id(31), 1, 0)
                .expect_err("terminal lifecycle wins over malformed loss summary"),
            RelayError::ExpiredReservation
        );

        assert_eq!(service.events().len(), events_after_expiry);
        assert_eq!(
            service.usage(reservation_id(31)).expect("usage"),
            usage_after_expiry
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(31))
                .expect("proof artifact"),
            proof_after_expiry
        );
        assert_eq!(usage_after_expiry.loss_summary, None);
        assert_eq!(
            service.events().last().expect("expiry event").kind,
            RelayEventKind::ReservationExpired
        );
    }

    #[test]
    fn tcp_tls_fallback_reason_is_reported_only_after_tcp_path_is_used() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(15),
                "path-relay-15",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("pre-forward artifact")
                .fallback_reason,
            None
        );
        service
            .forward(
                20,
                reservation_id(15),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("udp forward");
        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("udp artifact")
                .fallback_reason,
            None
        );
        service
            .forward(
                21,
                reservation_id(15),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 2),
            )
            .expect("tcp fallback forward");
        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("tcp artifact")
                .fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn cancellation_event_preserves_tcp_tls_fallback_reason_after_tcp_use() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(16),
                "path-relay-16",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(16),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 1),
            )
            .expect("tcp fallback forward");

        service
            .cancel_reservation(reservation_id(16))
            .expect("cancel");

        let cancel_event = service.events().last().expect("cancel event");
        assert_eq!(cancel_event.kind, RelayEventKind::ReservationCancelled);
        assert_eq!(
            cancel_event.fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn restart_snapshot_recovers_active_reservations_and_queues() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(9),
                "path-relay-9",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        let forwarded = service
            .forward(
                20,
                reservation_id(9),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        let snapshot = service.snapshot();
        assert_eq!(snapshot.reservation_count(), 1);

        let mut restored = RelayService::restore(snapshot);
        let restored_proof = restored
            .proof_artifact(reservation_id(9))
            .expect("restored proof");
        let restored_latency = restored_proof
            .latency_summary
            .expect("restored latency summary");
        assert_eq!(restored_latency.sample_count, 1);
        assert_eq!(restored_latency.latest_latency_micros, 10);
        assert_eq!(
            restored.dequeue_for_peer(peer(2)).expect("restored packet"),
            forwarded
        );
        assert!(
            restored
                .events()
                .iter()
                .any(|event| event.kind == RelayEventKind::RestartRestored)
        );
    }

    #[test]
    fn packet_loss_and_proof_artifact_are_redaction_safe() {
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(10),
                "path-relay-10",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(10),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 1),
            )
            .expect("forward");
        let loss = service
            .record_packet_loss(reservation_id(10), 1, 10)
            .expect("loss");
        let artifact = service
            .proof_artifact(reservation_id(10))
            .expect("artifact");

        assert_eq!(loss.loss_ppm, 100_000);
        assert_eq!(artifact.loss_summary, Some(loss));
        assert_eq!(artifact.accepted_at_micros, 10);
        assert_eq!(
            artifact.fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
        assert_eq!(artifact.opaque_bytes_forwarded, 10);
        assert_eq!(artifact.redacted_source_peer, "peer:0101...");
        assert!(!artifact.redacted_source_peer.contains("0101010101010101"));
        assert!(artifact.e2e_proof_preserved);
    }

    #[test]
    fn disabled_restart_retention_drops_active_state() {
        let config = RelayServiceConfig::default().with_retain_state_on_restart(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(11),
                "path-relay-11",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let snapshot = service.snapshot();
        assert_eq!(snapshot.reservation_count(), 0);

        let restored = RelayService::restore(snapshot);
        assert_eq!(
            restored
                .proof_artifact(reservation_id(11))
                .expect_err("dropped state"),
            RelayError::UnknownReservation
        );
    }
}
