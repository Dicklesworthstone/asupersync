//! Cx-integrated native QUIC connection orchestration.
//!
//! This type composes:
//! - TLS/key-phase progression (`QuicTlsMachine`)
//! - transport/loss-recovery lifecycle (`QuicTransportMachine`)
//! - stream/flow-control state (`StreamTable`)
//!
//! It intentionally stays runtime-agnostic and does not perform socket I/O.

use crate::bytes::{Buf, Bytes, BytesMut};
use crate::cx::Cx;
use crate::net::atp::protocol::quic_frames::{QuicFrame, QuicFrameError, QuicFrameType};
use crate::net::atp::protocol::varint::{VARINT_MAX, VarInt};
use crate::net::quic_core::TransportParameters;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::task::{Context as TaskContext, Poll, Waker};

use super::streams::{
    FlowControlError, QuicStreamError, QuicStreamIo, StreamDirection, StreamId, StreamReadiness,
    StreamRole, StreamTable, StreamTableError, StreamWindows,
};
use super::tls::{CryptoLevel, KeyUpdateEvent, QuicTlsError, QuicTlsMachine};
#[cfg(feature = "tls")]
use super::tls::{QuicServerIdentityVerification, QuicServerIdentityVerifier};
use super::transport::{
    AckEvent, AckRange, AckRangeSet, PacketNumberSpace, QuicConnectionState, QuicTransportMachine,
    SentPacketMeta, TransportError,
};

/// Native-connection errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeQuicConnectionError {
    /// Operation was cancelled via `Cx`.
    Cancelled,
    /// TLS/key-phase state error.
    Tls(QuicTlsError),
    /// Transport lifecycle or recovery state error.
    Transport(TransportError),
    /// Stream-table error.
    StreamTable(StreamTableError),
    /// Stream-state error.
    Stream(QuicStreamError),
    /// Frame encoding/decoding error.
    Frame(QuicFrameError),
    /// Congestion-control window would be exceeded.
    CongestionLimited {
        /// Requested in-flight bytes for the packet.
        requested: u64,
        /// Current bytes in flight.
        bytes_in_flight: u64,
        /// Current congestion window.
        congestion_window: u64,
    },
    /// Server anti-amplification limit would be exceeded before peer address validation.
    AmplificationLimited {
        /// Requested datagram bytes for the attempted send.
        requested: u64,
        /// Bytes already sent while amplification-limited.
        bytes_sent: u64,
        /// Bytes received from the peer while amplification-limited.
        bytes_received: u64,
        /// Maximum bytes permitted before validation.
        limit: u64,
    },
    /// DATAGRAM payload would encode to a frame larger than the peer's limit.
    DatagramTooLarge {
        /// Application payload bytes requested by the caller.
        payload_len: usize,
        /// Encoded DATAGRAM frame bytes including type and length fields.
        encoded_len: usize,
        /// Current maximum DATAGRAM frame size.
        max_frame_size: usize,
    },
    /// Receive-side DATAGRAM queue is full in a strict receiver path.
    DatagramReceiveQueueFull {
        /// Maximum buffered inbound DATAGRAM payloads.
        capacity: usize,
    },
    /// Invalid operation for current connection state.
    InvalidState(&'static str),
}

impl fmt::Display for NativeQuicConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::Tls(err) => write!(f, "{err}"),
            Self::Transport(err) => write!(f, "{err}"),
            Self::StreamTable(err) => write!(f, "{err}"),
            Self::Stream(err) => write!(f, "{err}"),
            Self::Frame(err) => write!(f, "{err}"),
            Self::CongestionLimited {
                requested,
                bytes_in_flight,
                congestion_window,
            } => write!(
                f,
                "congestion window exceeded: requested={requested}, in_flight={bytes_in_flight}, cwnd={congestion_window}"
            ),
            Self::AmplificationLimited {
                requested,
                bytes_sent,
                bytes_received,
                limit,
            } => write!(
                f,
                "anti-amplification limit exceeded: requested={requested}, sent={bytes_sent}, received={bytes_received}, limit={limit}"
            ),
            Self::DatagramTooLarge {
                payload_len,
                encoded_len,
                max_frame_size,
            } => write!(
                f,
                "datagram frame too large: payload_len={payload_len}, encoded_len={encoded_len}, max_frame_size={max_frame_size}"
            ),
            Self::DatagramReceiveQueueFull { capacity } => write!(
                f,
                "inbound datagram receive queue full: capacity={capacity}; drain buffered payloads before processing more"
            ),
            Self::InvalidState(msg) => write!(f, "invalid native quic connection state: {msg}"),
        }
    }
}

impl std::error::Error for NativeQuicConnectionError {}

impl NativeQuicConnectionError {
    /// Whether receive reassembly has run out of metadata capacity.
    ///
    /// Packet drivers may discard this packet without acknowledging it and
    /// continue receiving gap-closing input. The peer can retransmit reliable
    /// frames under a fresh packet number. This predicate preserves the public
    /// exhaustive error enum and the existing direct STREAM API error value.
    #[must_use]
    pub fn is_stream_reassembly_backpressure(&self) -> bool {
        matches!(self, Self::InvalidState(message) if *message == STREAM_REASSEMBLY_LIMIT_ERROR)
    }
}

impl From<QuicTlsError> for NativeQuicConnectionError {
    fn from(value: QuicTlsError) -> Self {
        Self::Tls(value)
    }
}

impl From<TransportError> for NativeQuicConnectionError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<QuicFrameError> for NativeQuicConnectionError {
    fn from(value: QuicFrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<StreamTableError> for NativeQuicConnectionError {
    fn from(value: StreamTableError) -> Self {
        Self::StreamTable(value)
    }
}

impl From<QuicStreamError> for NativeQuicConnectionError {
    fn from(value: QuicStreamError) -> Self {
        Self::Stream(value)
    }
}

/// Configuration for a native QUIC connection state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeQuicConnectionConfig {
    /// Endpoint role for stream-ID ownership.
    pub role: StreamRole,
    /// Local bidirectional stream limit.
    pub max_local_bidi: u64,
    /// Local unidirectional stream limit.
    pub max_local_uni: u64,
    /// Per-stream send window.
    pub send_window: u64,
    /// Per-stream receive window.
    pub recv_window: u64,
    /// Connection-level send-data limit.
    pub connection_send_limit: u64,
    /// Connection-level receive-data limit.
    pub connection_recv_limit: u64,
    /// Peer-advertised RFC 9221 `max_datagram_frame_size` cap for DATAGRAM frames.
    pub max_datagram_frame_size: usize,
    /// Drain timeout used by graceful close.
    pub drain_timeout_micros: u64,
}

/// Reliable frame identity retained until one carrying packet is acknowledged.
///
/// STREAM payload bytes themselves remain in `StreamTable`; this ledger only
/// remembers the stream/offset key needed to release or requeue that copy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RetransmittableFrameRef {
    HandshakeDone,
    Stream {
        stream_id: StreamId,
        offset: u64,
        data_len: usize,
        fin: bool,
    },
    ResetStream {
        stream_id: StreamId,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: StreamId,
        error_code: u64,
    },
}

impl RetransmittableFrameRef {
    fn from_frame(frame: &QuicFrame) -> Option<Self> {
        match frame {
            QuicFrame::HandshakeDone => Some(Self::HandshakeDone),
            QuicFrame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => Some(Self::Stream {
                stream_id: StreamId(stream_id.value()),
                offset: offset.map_or(0, VarInt::value),
                data_len: data.len(),
                fin: *fin,
            }),
            QuicFrame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => Some(Self::ResetStream {
                stream_id: StreamId(stream_id.value()),
                error_code: error_code.value(),
                final_size: final_size.value(),
            }),
            QuicFrame::StopSending {
                stream_id,
                error_code,
            } => Some(Self::StopSending {
                stream_id: StreamId(stream_id.value()),
                error_code: error_code.value(),
            }),
            _ => None,
        }
    }

    fn control_frame(&self) -> Option<QuicFrame> {
        match *self {
            Self::HandshakeDone => Some(QuicFrame::HandshakeDone),
            Self::Stream { .. } => None,
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => Some(QuicFrame::ResetStream {
                stream_id: VarInt::from_u64_unchecked(stream_id.0),
                error_code: VarInt::from_u64_unchecked(error_code),
                final_size: VarInt::from_u64_unchecked(final_size),
            }),
            Self::StopSending {
                stream_id,
                error_code,
            } => Some(QuicFrame::StopSending {
                stream_id: VarInt::from_u64_unchecked(stream_id.0),
                error_code: VarInt::from_u64_unchecked(error_code),
            }),
        }
    }
}

impl Default for NativeQuicConnectionConfig {
    fn default() -> Self {
        Self {
            role: StreamRole::Client,
            max_local_bidi: 128,
            max_local_uni: 128,
            send_window: 1 << 20,
            recv_window: 1 << 20,
            connection_send_limit: 16 << 20,
            connection_recv_limit: 16 << 20,
            max_datagram_frame_size: MAX_DATAGRAM_FRAME_SIZE,
            drain_timeout_micros: 3_000_000,
        }
    }
}

/// Cx-integrated native QUIC connection machine.
#[derive(Debug, Clone)]
pub struct NativeQuicConnection {
    role: StreamRole,
    tls: QuicTlsMachine,
    transport: QuicTransportMachine,
    streams: StreamTable,
    next_packet_numbers: [u64; 3],
    /// First packet number eligible to use the current updated send key.
    /// A subsequent locally initiated update needs a real ACK at this floor
    /// or above; the peer's key-phase bit alone is not confirmation.
    local_key_update_floor: Option<u64>,
    received_ack_trackers: [ReceivedPacketTracker; 3],
    migration_disabled: bool,
    /// Peer-advertised `ack_delay_exponent` (RFC 9000 §18.2; default 3). Scales
    /// the ACK Delay field of 1-RTT ACK frames into microseconds
    /// (asupersync-mc7m2r).
    peer_ack_delay_exponent: u32,
    /// Peer-advertised `max_ack_delay` in microseconds (RFC 9000 §18.2; default
    /// 25 ms). Bounds the RTT-sample `ack_delay` once the handshake is confirmed
    /// (RFC 9002 §5.3, asupersync-mc7m2r).
    peer_max_ack_delay_micros: u64,
    active_path_id: u64,
    migration_events: u64,
    drain_timeout_micros: u64,
    negotiated_idle_timeout_micros: Option<u64>,
    /// True only when the peer's CONNECTION_CLOSE frame initiated the current
    /// draining/closed state. Local shutdown paths leave this false so upper
    /// protocol adapters never misreport operator cleanup as a client abort.
    peer_close_observed: bool,
    /// Frame type of the peer frame that broke a transport rule, when that
    /// violation started the current close. The local CONNECTION_CLOSE is then
    /// the transport variant (0x1c) carrying it (RFC 9000 section 19.19).
    local_close_frame_type: Option<u64>,
    peer_address_validated: bool,
    /// Whether a verifying TLS handshake has validated the server's certificate
    /// chain against configured roots. Defaults to `false`; a client connection
    /// fails closed at handshake confirmation unless this is set, so an
    /// unauthenticated server identity can never be accepted (br-asupersync-7pwwwe).
    server_identity_verified: bool,
    anti_amplification_bytes_received: u64,
    anti_amplification_bytes_sent: u64,
    pending_control_frames: VecDeque<QuicFrame>,
    /// One managed PTO may commit one PING packet outside cwnd. This permit
    /// never admits ordinary control, STREAM, or DATAGRAM frames.
    pending_pto_probe: bool,
    /// Whether this connection owns reliable frame ACK/loss recovery. ATP
    /// disables this because its native link has an external packet/frame
    /// ledger with pacing-aware recovery.
    internal_retransmission_tracking: bool,
    /// Reliable frame references retained per packet-number space and packet.
    in_flight_retransmittable_frames: [BTreeMap<u64, Vec<RetransmittableFrameRef>>; 3],
    /// Bounded inbound queue of decoded DATAGRAM payloads awaiting the
    /// application's `recv_datagram` (RFC 9221). The receive side never evicts
    /// buffered payloads: once full, newly-arrived DATAGRAMs are counted as
    /// receive drops so survivors already accepted by the queue remain
    /// available to the decoder.
    inbound_datagrams: VecDeque<Bytes>,
    /// Total DATAGRAM frames accepted into the receive queue.
    datagrams_received: u64,
    /// Total inbound DATAGRAM payloads dropped before enqueue because the
    /// bounded receive queue was full.
    datagrams_dropped_on_receive: u64,
    /// Task waiting for the next inbound DATAGRAM payload.
    inbound_datagram_waker: Option<Waker>,
    /// Outbound DATAGRAM payloads queued by `send_datagram`, drained into
    /// `QuicFrame::Datagram` frames by `generate_frames` in 1-RTT packets.
    outbound_datagrams: VecDeque<Bytes>,
    /// Total DATAGRAM frames emitted onto the wire by `generate_frames`.
    datagrams_sent: u64,
    /// Total outbound DATAGRAM payloads evicted by the bounded drop-oldest queue.
    datagrams_dropped_on_send: u64,
    /// Peer-advertised maximum DATAGRAM frame size.
    max_datagram_frame_size: usize,
    /// This endpoint's own advertised `max_datagram_frame_size` once a bind
    /// path records it (`Some(0)` when DATAGRAM support was not offered).
    /// `None` keeps accepting every DATAGRAM, for construction paths that do
    /// not record their offer.
    local_max_datagram_frame_size: Option<usize>,
    /// Largest frame payload that fits one protected 1-RTT packet on this
    /// connection (GH#66). Admission bounds DATAGRAM frames by the smaller of
    /// this and `max_datagram_frame_size`, so an admitted payload can never
    /// produce a packet that assembly must refuse.
    one_rtt_frame_budget: usize,
}

/// Default cap on remotely-initiated streams (per direction) accepted from the
/// wire, mirroring the `max_local_*` default. Bounds memory against a peer that
/// opens unbounded streams (RFC 9000 §4.6 `MAX_STREAMS`): a well-behaved peer
/// respecting its own ≤128 local limit produces sequence indices `0..=127`
/// (all below the cap), so only a misbehaving peer is rejected. Override
/// per-connection with [`NativeQuicConnection::set_remote_stream_limits`].
///
/// NOTE: this is a static initial cap; dynamic credit extension via emitted
/// `MAX_STREAMS` frames (so long-lived connections can open more streams as old
/// ones close) is a separate enhancement.
const DEFAULT_MAX_REMOTE_STREAMS: u64 = 128;

/// Maximum number of decoded inbound DATAGRAM payloads buffered before newly
/// arrived DATAGRAM payloads are dropped and counted. The receiver never evicts
/// buffered symbols.
///
/// Keep this large enough for bulk native ATP rounds after MATRIX-39 DATAGRAM
/// coalescing: a 50 MiB encrypted transfer can produce roughly 46k symbol
/// datagrams before repair. The native link also caps socket receive width by
/// remaining DATAGRAM slots divided by the expected symbol frames per UDP packet,
/// so this larger no-evict envelope lets the receiver drain full UDP batches
/// from the kernel instead of self-backpressuring after a short burst.
const MAX_INBOUND_DATAGRAMS: usize = 65_536;

// NOTE (oh6gm2 flush-efficiency, 2026-07-07): replacing the per-frame
// probe-encode (encode into a throwaway buffer to learn the frame length for
// packet budgeting) with exact arithmetic lengths was A/B-REFUTED as a
// clean-large lever: source_stream phase telemetry showed generate_micros
// UNCHANGED (the probe memcpy totals only ~50 ms over a 500M transfer), the
// large clean cells measured worse (no mechanism found — likely ambient
// load), and small/medium cells slightly better. The dominant "generate"
// cost lives in the stream pop/queue mechanics (`pop_stream_frame_for` and
// the pending-queue bookkeeping), not the probe encode — profile there next.

/// Upper bound on SACK ranges encoded per ACK frame (newest ranges first).
/// Keeps every ACK packet inside one conservative MTU; see
/// `ReceivedPacketTracker::ack_frame`. A netns A/B at 4096 ranges reproduced
/// the tree-manifest wedge identically, so this bound is not load-bearing for
/// that failure (br-asupersync-u6m3dy forensics, 2026-07-06).
///
/// Sizing: 96 ranges × ~8 bytes worst-case varints ≈ 780 bytes, inside the
/// ~1163-byte lossy-path packet payload with coalescing headroom. The
/// original 32 was conservative and measurably costly at 500M scale: even
/// 0.1% loss over ~66K packets accretes ~66 permanent pn-space ranges, so a
/// 32-range window left delivered packets unreportable and the sender's
/// packet-threshold recovery re-sent 60-175 MB of already-delivered data per
/// transfer (the 500M/good fast-vs-slow bimodality tracked exactly this
/// spurious volume — br-asupersync-oh6gm2 forensics, 2026-07-07).
const MAX_ACK_FRAME_RANGES: usize = 96;

/// Maximum number of received packet-number ranges retained per number space.
///
/// The wire encoder advertises only [`MAX_ACK_FRAME_RANGES`] newest ranges.
/// Retaining four wire windows gives reordered packets several ACK cycles to
/// bridge nearby gaps while bounding both memory and the cost of ordered
/// insertion. Dropping older ranges is permitted by RFC 9000 §13.2.3.
const MAX_TRACKED_ACK_RANGES: usize = MAX_ACK_FRAME_RANGES * 4;

/// Maximum number of disjoint receive fragments buffered for one stream.
///
/// Flow control bounds bytes, but without a separate metadata bound an
/// authenticated peer can fill the receive window with tiny disjoint ranges
/// and amplify each byte into a tree node plus reassembly work.
pub(crate) const MAX_BUFFERED_STREAM_REASSEMBLY_FRAGMENTS: usize = 4096;

/// Maximum number of out-of-order receive fragments buffered across all of a
/// connection's streams. The per-stream bound alone admits that many on every
/// stream the peer may open (128 + 128 by default): about 1M one-byte holes,
/// hundreds of MB of tree and buffer metadata for a few MB of credit.
pub(crate) const MAX_BUFFERED_CONNECTION_REASSEMBLY_FRAGMENTS: usize =
    4 * MAX_BUFFERED_STREAM_REASSEMBLY_FRAGMENTS;
const STREAM_REASSEMBLY_LIMIT_ERROR: &str = "stream receive reassembly fragment limit exceeded";

/// Maximum number of outbound DATAGRAM payloads queued before `send_datagram`
/// drops the oldest queued payload to keep the unreliable send path bounded.
const MAX_OUTBOUND_DATAGRAMS: usize = 256;

/// Largest DATAGRAM *frame* (RFC 9221 `max_datagram_frame_size` semantics) this
/// endpoint will emit; a `send_datagram` whose encoded frame would exceed this
/// is rejected so a single datagram always fits one 1-RTT packet.
const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;

/// Largest frame payload that fits one protected 1-RTT packet when the
/// destination connection ID has its maximum length (GH#66). Every connection
/// starts here; the packet assemblers narrow it to the exact destination CID
/// through [`NativeQuicConnection::set_one_rtt_frame_budget`].
const CONSERVATIVE_ONE_RTT_FRAME_BUDGET: usize =
    super::connection_manager::PROTECTED_1RTT_MAX_PACKET_BYTES
        - (1 + crate::net::quic_core::ConnectionId::MAX_LEN
            + super::connection_manager::PROTECTED_1RTT_PACKET_NUMBER_LEN as usize
            + super::connection_manager::PROTECTED_1RTT_TAG_LEN);

/// Opt-in stderr tracing for QUIC transport bring-up/diagnosis. Off unless the
/// `ATP_QUIC_TRACE` env var is set, so the production path stays silent.
macro_rules! quictrace {
    ($($arg:tt)*) => {
        if std::env::var_os("ATP_QUIC_TRACE").is_some() {
            eprintln!("[atp-quic] {}", format!($($arg)*));
        }
    };
}

impl NativeQuicConnection {
    /// Construct a new connection machine.
    #[must_use]
    pub fn new(config: NativeQuicConnectionConfig) -> Self {
        let mut streams = StreamTable::new_with_connection_limits(
            config.role,
            config.max_local_bidi,
            config.max_local_uni,
            config.send_window,
            config.recv_window,
            config.connection_send_limit,
            config.connection_recv_limit,
        );
        // Bound remotely-initiated streams so a peer cannot force unbounded
        // stream allocations from the wire (RFC 9000 §4.6 MAX_STREAMS).
        streams.set_remote_stream_limits(DEFAULT_MAX_REMOTE_STREAMS, DEFAULT_MAX_REMOTE_STREAMS);
        Self {
            role: config.role,
            tls: QuicTlsMachine::new(),
            transport: QuicTransportMachine::new(),
            streams,
            next_packet_numbers: [0, 0, 0],
            local_key_update_floor: None,
            received_ack_trackers: [
                ReceivedPacketTracker::default(),
                ReceivedPacketTracker::default(),
                ReceivedPacketTracker::default(),
            ],
            migration_disabled: false,
            peer_ack_delay_exponent: 3,
            peer_max_ack_delay_micros: 25_000,
            active_path_id: 0,
            migration_events: 0,
            drain_timeout_micros: config.drain_timeout_micros,
            negotiated_idle_timeout_micros: None,
            peer_close_observed: false,
            local_close_frame_type: None,
            peer_address_validated: config.role == StreamRole::Client,
            server_identity_verified: false,
            anti_amplification_bytes_received: 0,
            anti_amplification_bytes_sent: 0,
            pending_control_frames: VecDeque::new(),
            pending_pto_probe: false,
            internal_retransmission_tracking: true,
            in_flight_retransmittable_frames: std::array::from_fn(|_| BTreeMap::new()),
            inbound_datagrams: VecDeque::new(),
            datagrams_received: 0,
            datagrams_dropped_on_receive: 0,
            inbound_datagram_waker: None,
            outbound_datagrams: VecDeque::new(),
            datagrams_sent: 0,
            datagrams_dropped_on_send: 0,
            max_datagram_frame_size: config.max_datagram_frame_size,
            local_max_datagram_frame_size: None,
            one_rtt_frame_budget: CONSERVATIVE_ONE_RTT_FRAME_BUDGET,
        }
    }

    /// Record the `max_datagram_frame_size` this endpoint advertised. From then
    /// on a DATAGRAM frame the peer was never invited to send, or one larger
    /// than the offer, is a protocol violation and is never queued (RFC 9221
    /// §3). The TLS bind path in `udp_connection` is the production caller.
    #[cfg(any(test, feature = "tls"))]
    pub(crate) fn set_local_max_datagram_frame_size(&mut self, advertised: Option<u64>) {
        self.local_max_datagram_frame_size =
            Some(advertised.map_or(0, |max| usize::try_from(max).unwrap_or(usize::MAX)));
    }

    /// Bound outbound DATAGRAM admission by this connection's protected 1-RTT
    /// packet budget (GH#66).
    ///
    /// `max_frame_bytes` is the largest frame payload that fits one protected
    /// packet for the destination connection ID in use; the packet assemblers
    /// call this with the same value they enforce, so admission and assembly
    /// agree. Until it is called, the conservative maximum-CID budget applies.
    pub(crate) fn set_one_rtt_frame_budget(&mut self, max_frame_bytes: usize) {
        self.one_rtt_frame_budget = max_frame_bytes.max(1);
    }

    /// Largest frame payload that fits one protected 1-RTT packet here.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn one_rtt_frame_budget(&self) -> usize {
        self.one_rtt_frame_budget
    }

    /// Select the owner of reliable STREAM/RESET_STREAM/STOP_SENDING recovery.
    ///
    /// The generic native connection owns this by default. A composed transport
    /// that already retains the same frame identities (currently ATP's native
    /// link) must disable it before generating application packets so ACK/loss
    /// processing has exactly one recovery authority.
    pub fn set_internal_retransmission_tracking(
        &mut self,
        enabled: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        if enabled == self.internal_retransmission_tracking {
            return Ok(());
        }
        if self
            .in_flight_retransmittable_frames
            .iter()
            .any(|ledger| !ledger.is_empty())
        {
            return Err(NativeQuicConnectionError::InvalidState(
                "retransmission ownership must be selected before packet generation",
            ));
        }
        self.internal_retransmission_tracking = enabled;
        Ok(())
    }

    /// Current transport state.
    #[must_use]
    pub fn state(&self) -> QuicConnectionState {
        self.transport.state()
    }

    /// Whether the peer's CONNECTION_CLOSE frame initiated the current close.
    #[must_use]
    pub fn close_was_peer_initiated(&self) -> bool {
        self.peer_close_observed
            && matches!(
                self.transport.state(),
                QuicConnectionState::Draining | QuicConnectionState::Closed
            )
    }

    /// The frame type the local CONNECTION_CLOSE reports. `Some` when a peer
    /// frame that broke a transport rule started the close, which makes it a
    /// transport close (0x1c); `None` for an application close (0x1d).
    pub(crate) fn local_close_frame_type(&self) -> Option<VarInt> {
        self.local_close_frame_type.map(VarInt::from_u64_unchecked)
    }

    /// Whether application (1-RTT) data can be sent.
    #[must_use]
    pub fn can_send_1rtt(&self) -> bool {
        self.tls.can_send_1rtt() && self.transport.state() == QuicConnectionState::Established
    }

    /// Whether 0-RTT application-data packets may be sent in current state.
    #[must_use]
    pub fn can_send_0rtt(&self) -> bool {
        self.role == StreamRole::Client
            && self.tls.can_send_0rtt()
            && self.transport.state() == QuicConnectionState::Handshaking
    }

    /// Access TLS machine snapshot.
    #[must_use]
    pub fn tls(&self) -> &QuicTlsMachine {
        &self.tls
    }

    /// Access transport machine snapshot.
    #[must_use]
    pub fn transport(&self) -> &QuicTransportMachine {
        &self.transport
    }

    pub(crate) fn negotiated_idle_timeout_micros(&self) -> Option<u64> {
        self.negotiated_idle_timeout_micros
    }

    #[cfg(feature = "tls")]
    pub(crate) fn set_negotiated_idle_timeout(
        &mut self,
        local: &crate::net::quic_core::TransportParameters,
        peer: &crate::net::quic_core::TransportParameters,
    ) {
        self.negotiated_idle_timeout_micros =
            crate::net::quic_core::TransportParameters::effective_max_idle_timeout(local, peer)
                .map(|millis| millis.saturating_mul(1_000));
    }

    /// Access stream table snapshot.
    #[must_use]
    pub fn streams(&self) -> &StreamTable {
        &self.streams
    }

    /// Install the per-type initial stream windows negotiated in the transport
    /// parameters (RFC 9000 §18.2) before any stream opens.
    ///
    /// `send` holds the peer-advertised windows and `recv` the locally
    /// advertised ones; see [`StreamWindows`] for the stream-type mapping.
    pub fn set_initial_stream_windows(&mut self, send: StreamWindows, recv: StreamWindows) {
        self.streams.set_initial_stream_windows(send, recv);
    }

    /// Start handshake.
    pub fn begin_handshake(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.begin_handshake()?;
        if self.role == StreamRole::Server && self.anti_amplification_bytes_received == 0 {
            // A valid QUIC client Initial datagram is padded to at least 1200 bytes.
            self.anti_amplification_bytes_received = 1_200;
        }
        Ok(())
    }

    /// Mark handshake keys installed.
    pub fn on_handshake_keys_available(
        &mut self,
        cx: &Cx,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.tls.on_handshake_keys_available()?;
        Ok(())
    }

    /// Mark 1-RTT keys installed.
    pub fn on_1rtt_keys_available(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.tls.on_1rtt_keys_available()?;
        Ok(())
    }

    /// Records that a verifying TLS handshake has validated the server's
    /// certificate chain against the configured trust roots.
    ///
    /// This is the only way to clear the fail-closed server-identity gate on a
    /// client connection. It must be called only after a genuine certificate
    /// verification (chain + hostname + `CertificateVerify` signature) has
    /// succeeded — there is deliberately no insecure "skip verify" toggle on the
    /// production path (br-asupersync-7pwwwe).
    pub fn record_verified_server_identity(&mut self) {
        self.server_identity_verified = true;
    }

    /// Establish application readiness after verified TLS completion.
    ///
    /// Client peer confirmation remains separate until HANDSHAKE_DONE arrives.
    pub(crate) fn on_authenticated_handshake_complete(
        &mut self,
        cx: &Cx,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        if self.tls.level() != CryptoLevel::OneRtt {
            return Err(NativeQuicConnectionError::Tls(
                QuicTlsError::HandshakeNotConfirmed,
            ));
        }
        // SECURITY (br-asupersync-7pwwwe): a client MUST NOT treat the connection
        // as authenticated/established without having verified the server's
        // certificate chain against configured roots. The native QUIC TLS path
        // performs no certificate exchange/verification, so confirming an
        // unverified client connection would accept any server identity
        // (MITM exposure). Fail closed unless a verifying handshake recorded a
        // successful validation. (Servers do not verify a server certificate.)
        if self.role == StreamRole::Client && !self.server_identity_verified {
            return Err(NativeQuicConnectionError::Tls(
                QuicTlsError::ServerCertificateUnverified,
            ));
        }
        self.transport.on_established()?;
        self.tls.on_authenticated_handshake_complete()?;
        self.peer_address_validated = true;
        Ok(())
    }

    /// Confirm handshake and transition transport to `Established`.
    pub fn on_handshake_confirmed(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        self.on_authenticated_handshake_complete(cx)?;
        let first_confirmation = !self.tls.handshake_confirmed();
        self.tls.on_handshake_confirmed()?;
        if first_confirmation && self.role == StreamRole::Server {
            // RFC 9000 sections 19.20 and 13.3: confirm to the client and
            // retain this control frame through the normal ACK/loss ledger.
            self.pending_control_frames
                .push_back(QuicFrame::HandshakeDone);
        }
        let server_identity_verified = if self.role == StreamRole::Client {
            "true"
        } else {
            "not_applicable"
        };
        quic_trace(
            cx,
            "atp_quic.handshake.confirmed",
            &[
                ("role", self.role_label()),
                ("server_identity_verified", server_identity_verified),
            ],
        );
        Ok(())
    }

    /// Verify the peer's X.509 server identity and confirm the handshake.
    ///
    /// This is the client-side production path for the server-identity gate:
    /// WebPKI/rustls must accept the presented chain for the configured roots
    /// and hostname before the connection records `server_identity_verified`
    /// and transitions to 1-RTT established. Bad roots, expired certificates,
    /// wrong hostnames, empty chains, and malformed names all fail closed before
    /// any application data can be sent.
    #[cfg(feature = "tls")]
    pub fn verify_server_identity_and_confirm_handshake(
        &mut self,
        cx: &Cx,
        verifier: &QuicServerIdentityVerifier,
        hostname: &str,
        presented_chain: crate::tls::CertificateChain,
        now: rustls_pki_types::UnixTime,
    ) -> Result<QuicServerIdentityVerification, NativeQuicConnectionError> {
        checkpoint(cx)?;
        if self.role != StreamRole::Client {
            return Err(NativeQuicConnectionError::InvalidState(
                "server identity verification is client-only",
            ));
        }
        quic_trace(
            cx,
            "atp_quic.cert_verify.start",
            &[("role", self.role_label())],
        );
        let receipt = match verifier.verify_server_chain(hostname, presented_chain, now) {
            Ok(receipt) => receipt,
            Err(err) => {
                quic_trace(
                    cx,
                    "atp_quic.cert_verify.fail",
                    &[("role", self.role_label()), ("code", err.code())],
                );
                return Err(NativeQuicConnectionError::Tls(err));
            }
        };
        self.record_verified_server_identity();
        let chain_len = receipt.chain_len.to_string();
        let root_count = receipt.root_count.to_string();
        quic_trace(
            cx,
            "atp_quic.cert_verify.ok",
            &[
                ("role", self.role_label()),
                ("chain_len", chain_len.as_str()),
                ("root_count", root_count.as_str()),
            ],
        );
        self.on_handshake_confirmed(cx)?;
        Ok(receipt)
    }

    /// Open a local bidirectional stream.
    pub fn open_local_bidi(&mut self, cx: &Cx) -> Result<StreamId, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        let id = self.streams.open_local_bidi()?;
        Ok(id)
    }

    /// Open a local unidirectional stream.
    pub fn open_local_uni(&mut self, cx: &Cx) -> Result<StreamId, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        let id = self.streams.open_local_uni()?;
        Ok(id)
    }

    /// Accept a remote stream ID.
    pub fn accept_remote_stream(
        &mut self,
        cx: &Cx,
        id: StreamId,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_open_state()?;
        self.streams.accept_remote_stream(id)?;
        Ok(())
    }

    /// Configure the maximum number of remotely-initiated streams (per
    /// direction) this connection will accept from the wire (RFC 9000 §4.6
    /// `MAX_STREAMS`). Bounds memory against a peer that opens unbounded
    /// streams; defaults to `DEFAULT_MAX_REMOTE_STREAMS` per direction.
    pub fn set_remote_stream_limits(&mut self, max_remote_bidi: u64, max_remote_uni: u64) {
        // RFC 9000 section 4.6: a stream count above 2^60 cannot be encoded as
        // a stream ID, and a peer must treat MAX_STREAMS above it as a
        // FRAME_ENCODING_ERROR (br-asupersync-5f1fcj).
        let max_remote_bidi = max_remote_bidi.min(1u64 << 60);
        let max_remote_uni = max_remote_uni.min(1u64 << 60);
        let (old_bidi, old_uni) = self.streams.remote_stream_limits();
        self.streams
            .set_remote_stream_limits(max_remote_bidi, max_remote_uni);
        if self.transport.state() == QuicConnectionState::Established {
            if max_remote_bidi > old_bidi {
                self.queue_max_streams_frame(max_remote_bidi, true);
            }
            if max_remote_uni > old_uni {
                self.queue_max_streams_frame(max_remote_uni, false);
            }
        }
    }

    fn queue_max_streams_frame(&mut self, maximum_streams: u64, bidirectional: bool) {
        self.pending_control_frames
            .push_back(QuicFrame::MaxStreams {
                maximum_streams: VarInt::from_u64_unchecked(maximum_streams),
                bidirectional,
            });
    }

    fn queue_control_frame_once(&mut self, frame: QuicFrame) {
        if !self.pending_control_frames.contains(&frame) {
            self.pending_control_frames.push_back(frame);
        }
    }

    /// Whether a control frame (ACK, MAX_STREAM_DATA, STREAM_DATA_BLOCKED …)
    /// is queued for the next flush.
    #[must_use]
    pub fn has_pending_control_frames(&self) -> bool {
        !self.pending_control_frames.is_empty()
    }

    /// Whether any STREAM frames remain queued for packet assembly.
    #[must_use]
    pub fn has_pending_stream_frames(&self) -> bool {
        self.streams.has_pending_stream_frames()
    }

    /// Whether one STREAM has frames queued for packet assembly.
    #[must_use]
    pub fn has_pending_stream_frames_for(&self, id: StreamId) -> bool {
        self.streams.has_pending_stream_frames_for(id)
    }

    /// Number of queued STREAM frames waiting for packet assembly.
    #[must_use]
    pub fn pending_stream_frame_count(&self) -> usize {
        self.streams.pending_stream_frame_count()
    }

    /// Queued STREAM payload bytes waiting for packet assembly.
    #[must_use]
    pub fn pending_stream_data_bytes(&self) -> u64 {
        self.streams.pending_stream_data_bytes()
    }

    /// Queued STREAM payload bytes waiting for packet assembly on one stream.
    #[must_use]
    pub fn pending_stream_data_bytes_for(&self, id: StreamId) -> u64 {
        self.streams.pending_stream_data_bytes_for(id)
    }

    /// Poll the application payload capacity available to one stream.
    ///
    /// The returned capacity is bounded by both the stream and connection
    /// send windows. `Pending` registers `task_cx` for either corresponding
    /// flow-control update.
    pub fn poll_stream_send_capacity(
        &mut self,
        cx: &Cx,
        id: StreamId,
        required: u64,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<u64, NativeQuicConnectionError>> {
        if let Err(err) = checkpoint(cx) {
            return Poll::Ready(Err(err));
        }
        if let Err(err) = self.ensure_data_state() {
            return Poll::Ready(Err(err));
        }
        match self
            .streams
            .poll_stream_send_capacity(id, required, task_cx)
        {
            Poll::Ready(result) => Poll::Ready(result.map_err(map_stream_table_error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Poll until one stream has no prior queued frame and enough capacity for
    /// a new application frame.
    pub fn poll_stream_write_ready(
        &mut self,
        cx: &Cx,
        id: StreamId,
        required: u64,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<u64, NativeQuicConnectionError>> {
        if let Err(err) = checkpoint(cx) {
            return Poll::Ready(Err(err));
        }
        if let Err(err) = self.ensure_data_state() {
            return Poll::Ready(Err(err));
        }
        match self.streams.poll_stream_write_ready(id, required, task_cx) {
            Poll::Ready(result) => Poll::Ready(result.map_err(map_stream_table_error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Poll until one stream has no frame left in packet assembly, including
    /// after its send side became terminal.
    pub fn poll_stream_queue_drained(
        &mut self,
        cx: &Cx,
        id: StreamId,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), NativeQuicConnectionError>> {
        if let Err(err) = checkpoint(cx) {
            return Poll::Ready(Err(err));
        }
        if let Err(err) = self.ensure_stream_active_state() {
            return Poll::Ready(Err(err));
        }
        match self.streams.poll_stream_queue_drained(id, task_cx) {
            Poll::Ready(result) => Poll::Ready(result.map_err(map_stream_table_error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Account bytes written to a stream.
    pub fn write_stream(
        &mut self,
        cx: &Cx,
        id: StreamId,
        len: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        self.streams
            .write_stream(id, len)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Queue application bytes for reliable STREAM frame emission.
    pub fn write_stream_bytes(
        &mut self,
        cx: &Cx,
        id: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        let len = data.len() as u64;
        let result = self.streams.write_stream_bytes(id, data, fin);
        if let Err(StreamTableError::Stream(QuicStreamError::Flow(FlowControlError::Exhausted {
            ..
        }))) = &result
        {
            self.queue_blocked_frame(id, len);
        }
        result.map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Account bytes received on a stream.
    pub fn receive_stream(
        &mut self,
        cx: &Cx,
        id: StreamId,
        len: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .receive_stream(id, len)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Read contiguous STREAM bytes already reassembled for the application.
    pub fn read_stream_bytes(
        &mut self,
        cx: &Cx,
        id: StreamId,
        max_len: usize,
    ) -> Result<Bytes, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        let bytes = self
            .streams
            .read_stream_bytes(id, max_len)
            .map_err(map_stream_table_error)?;
        if !bytes.is_empty() {
            // Application drain advances bounded receive windows; put the new
            // MAX_STREAM_DATA advertisements on the next outgoing flush.
            for (stream, limit) in self.streams.advance_bounded_recv_windows() {
                self.queue_max_stream_data_frame(stream, limit);
            }
        }
        Ok(bytes)
    }

    /// Install a bounded receive window on `id` (accepting the remote stream
    /// early when needed) and queue the initial MAX_STREAM_DATA
    /// advertisement. Bounds the peer's un-read bytes — and therefore this
    /// endpoint's reassembly memory — to roughly one window.
    pub fn configure_stream_recv_window(
        &mut self,
        cx: &Cx,
        id: StreamId,
        window: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let applied = self
            .streams
            .configure_stream_recv_window(id, window)
            .map_err(map_stream_table_error)?;
        self.queue_max_stream_data_frame(id, applied);
        Ok(applied)
    }

    /// Let the bounded receive window on `id` grow up to `max_window` bytes
    /// when the peer reports STREAM_DATA_BLOCKED at our advertised edge (see
    /// `StreamTable::note_peer_stream_data_blocked` for the growth gates).
    pub fn allow_stream_recv_window_growth(
        &mut self,
        cx: &Cx,
        id: StreamId,
        max_window: u64,
        fragment_ceiling: usize,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.streams
            .allow_stream_recv_window_growth(id, max_window, fragment_ceiling)
            .map_err(map_stream_table_error)
    }

    /// The peer's current `MAX_STREAM_DATA` limit for `id` (`None` for an
    /// unknown stream).
    #[must_use]
    pub fn stream_send_limit(&self, id: StreamId) -> Option<u64> {
        self.streams.stream_send_limit(id).ok()
    }

    /// Current bounded receive window of `id` (`None` = unbounded).
    pub fn stream_recv_window_bytes(
        &self,
        id: StreamId,
    ) -> Result<Option<u64>, NativeQuicConnectionError> {
        self.streams
            .stream_recv_window_bytes(id)
            .map_err(map_stream_table_error)
    }

    /// Tell the peer our send side is blocked on its `MAX_STREAM_DATA` limit
    /// for `id` (a STREAM_DATA_BLOCKED frame on the next flush).
    ///
    /// The stream write path queues this frame on its own when a write hits
    /// `FlowControlError::Exhausted`; a sender that waits for credit before
    /// writing (the paced ATP source stream) never reaches that error, so it
    /// reports the stall explicitly through this entry point. The frame is
    /// idempotent for the receiver: it only ever grows a window whose growth
    /// the receiver allowed.
    pub fn report_stream_data_blocked(
        &mut self,
        cx: &Cx,
        id: StreamId,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        self.queue_stream_data_blocked(id);
        Ok(())
    }

    /// Increase the connection receive limit and advertise it with MAX_DATA.
    pub fn advertise_connection_recv_limit(
        &mut self,
        cx: &Cx,
        limit: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        if limit > VARINT_MAX {
            return Err(NativeQuicConnectionError::InvalidState(
                "MAX_DATA limit exceeds QUIC varint range",
            ));
        }
        if limit < self.streams.connection_recv_limit() {
            return Ok(());
        }
        self.streams
            .increase_connection_recv_limit(limit)
            .map_err(QuicStreamError::Flow)?;
        self.pending_control_frames.retain(|frame| {
            !matches!(
                frame,
                QuicFrame::MaxData { maximum_data } if maximum_data.value() <= limit
            )
        });
        self.pending_control_frames.push_back(QuicFrame::MaxData {
            maximum_data: VarInt(limit),
        });
        Ok(())
    }

    /// Lower a freshly-opened local stream's send-credit limit to mirror the
    /// bounded window the peer enforces for that stream; the limit then grows
    /// only via peer MAX_STREAM_DATA frames.
    pub fn set_fresh_stream_send_limit(
        &mut self,
        cx: &Cx,
        id: StreamId,
        limit: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.streams
            .set_fresh_stream_send_limit(id, limit)
            .map_err(map_stream_table_error)
    }

    /// Clamp one stream's send limit at or above bytes already consumed.
    ///
    /// This deterministic test hook plants an exact post-handshake
    /// `MAX_STREAM_DATA` stall without constraining earlier control traffic.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn constrain_stream_send_limit_for_testing(
        &mut self,
        cx: &Cx,
        id: StreamId,
        limit: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        self.set_fresh_stream_send_limit(cx, id, limit)
    }

    /// Clamp connection send credit at or above bytes already consumed.
    ///
    /// This deterministic test hook plants an exact post-handshake `MAX_DATA`
    /// stall without constraining earlier control traffic.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn constrain_connection_send_limit_for_testing(
        &mut self,
        cx: &Cx,
        limit: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        Ok(self
            .streams
            .constrain_connection_send_limit_for_testing(limit))
    }

    /// Consume the next deterministic receive-side stream notification.
    ///
    /// Notifications cover contiguous bytes, FIN, peer RESET_STREAM, and a
    /// local receive stop. They are edge-triggered: callers should drain or
    /// disposition the reported stream before requesting another notification.
    pub fn next_readable_stream(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<StreamReadiness>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        Ok(self.streams.take_next_readable_stream())
    }

    /// Poll for the next receive-side stream notification without busy-polling.
    pub fn poll_next_readable_stream(
        &mut self,
        cx: &Cx,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<StreamReadiness, NativeQuicConnectionError>> {
        if let Err(err) = checkpoint(cx) {
            return Poll::Ready(Err(err));
        }
        if let Err(err) = self.ensure_stream_active_state() {
            return Poll::Ready(Err(err));
        }
        match self.streams.poll_next_readable_stream(task_cx) {
            Poll::Ready(readiness) => Poll::Ready(Ok(readiness)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Remaining send credit for one stream (0 for unknown streams).
    #[must_use]
    pub fn stream_send_credit_remaining(&self, id: StreamId) -> u64 {
        self.streams.stream_send_credit_remaining(id)
    }

    /// Queue a MAX_STREAM_DATA advertisement, replacing any pending one for
    /// the same stream with a lower maximum (advertisements are monotonic).
    fn queue_max_stream_data_frame(&mut self, id: StreamId, limit: u64) {
        self.pending_control_frames.retain(|frame| {
            !matches!(
                frame,
                QuicFrame::MaxStreamData {
                    stream_id,
                    maximum_stream_data,
                } if stream_id.value() == id.0 && maximum_stream_data.value() <= limit
            )
        });
        self.pending_control_frames
            .push_back(QuicFrame::MaxStreamData {
                stream_id: VarInt(id.0),
                maximum_stream_data: VarInt(limit),
            });
    }

    /// Whether an application STREAM read has consumed through FIN.
    pub fn is_stream_read_eof(&self, id: StreamId) -> Result<bool, NativeQuicConnectionError> {
        self.streams
            .is_stream_read_eof(id)
            .map_err(map_stream_table_error)
    }

    /// Bounded payload prefix retained when peer RESET_STREAM discarded a
    /// stream's receive buffer.
    pub fn reset_stream_buffered_prefix(
        &self,
        id: StreamId,
    ) -> Result<Bytes, NativeQuicConnectionError> {
        self.streams
            .reset_stream_buffered_prefix(id)
            .map_err(map_stream_table_error)
    }

    /// Borrow a stream as an `AsyncRead + AsyncWrite` adapter.
    pub fn stream_io(
        &mut self,
        cx: &Cx,
        id: StreamId,
    ) -> Result<QuicStreamIo<'_>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams.stream_io(id).map_err(map_stream_table_error)
    }

    /// Requeue a previously emitted STREAM frame after packet loss.
    pub fn requeue_sent_stream_frame(
        &mut self,
        cx: &Cx,
        id: StreamId,
        offset: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        self.streams
            .requeue_sent_stream_frame(id, offset)
            .map_err(map_stream_table_error)
    }

    /// Release the retained retransmission copy of an acknowledged
    /// STREAM frame so sender memory does not scale with transfer size.
    pub fn release_sent_stream_frame(
        &mut self,
        id: StreamId,
        offset: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        self.streams
            .release_sent_stream_frame(id, offset)
            .map_err(map_stream_table_error)
    }

    /// Account bytes received on a stream at an explicit offset.
    pub fn receive_stream_segment(
        &mut self,
        cx: &Cx,
        id: StreamId,
        offset: u64,
        len: u64,
        is_fin: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .receive_stream_segment(id, offset, len, is_fin)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Receive STREAM payload bytes at an explicit offset.
    pub fn receive_stream_bytes(
        &mut self,
        cx: &Cx,
        id: StreamId,
        offset: u64,
        data: Bytes,
        is_fin: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        if self
            .streams
            .stream_reassembly_limits_would_be_exceeded(
                id,
                offset,
                data.len() as u64,
                is_fin,
                MAX_BUFFERED_STREAM_REASSEMBLY_FRAGMENTS,
                MAX_BUFFERED_CONNECTION_REASSEMBLY_FRAGMENTS,
            )
            .map_err(map_stream_table_error)?
        {
            return Err(NativeQuicConnectionError::InvalidState(
                STREAM_REASSEMBLY_LIMIT_ERROR,
            ));
        }
        self.streams
            .receive_stream_bytes(id, offset, data, is_fin)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Set stream final size.
    pub fn set_stream_final_size(
        &mut self,
        cx: &Cx,
        id: StreamId,
        final_size: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .set_stream_final_size(id, final_size)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Process peer STOP_SENDING for a local stream.
    pub fn on_stop_sending(
        &mut self,
        cx: &Cx,
        id: StreamId,
        error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        if error_code > VARINT_MAX {
            return Err(NativeQuicConnectionError::InvalidState(
                "STOP_SENDING error code must fit a QUIC varint",
            ));
        }
        if id.direction() == StreamDirection::Unidirectional && !id.is_local_for(self.role) {
            return Err(NativeQuicConnectionError::InvalidState(
                "STOP_SENDING is invalid for a receive-only stream",
            ));
        }
        let should_reset = self
            .streams
            .stream(id)
            .map_err(map_stream_table_error)?
            .send_reset
            .is_none();
        self.streams
            .on_stop_sending(id, error_code)
            .map_err(map_stream_table_error)?;
        // RFC 9000 section 3.5: receiving STOP_SENDING requires terminating
        // an unfinished send side with RESET_STREAM. Reuse the peer's
        // application code and the already-committed send offset.
        if should_reset {
            let final_size = self
                .streams
                .stream(id)
                .map_err(map_stream_table_error)?
                .send_offset;
            self.reset_stream_send(cx, id, error_code, final_size)?;
        }
        Ok(())
    }

    /// Locally stop receiving on a stream.
    pub fn stop_receiving(
        &mut self,
        cx: &Cx,
        id: StreamId,
        error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        if error_code > VARINT_MAX {
            return Err(NativeQuicConnectionError::InvalidState(
                "STOP_SENDING error code must fit a QUIC varint",
            ));
        }
        let already_stopped = self
            .streams
            .stream(id)
            .map_err(map_stream_table_error)?
            .receive_stopped_error_code
            .is_some();
        self.streams
            .stop_receiving(id, error_code)
            .map_err(map_stream_table_error)?;
        if !already_stopped {
            self.queue_control_frame_once(QuicFrame::StopSending {
                stream_id: VarInt::from_u64_unchecked(id.0),
                error_code: VarInt::from_u64_unchecked(error_code),
            });
        }
        Ok(())
    }

    /// Process peer RESET_STREAM for a stream receive-side.
    pub fn reset_stream_receive(
        &mut self,
        cx: &Cx,
        id: StreamId,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        self.streams
            .reset_stream_receive(id, error_code, final_size)
            .map_err(map_stream_table_error)?;
        Ok(())
    }

    /// Locally reset stream send-side (`RESET_STREAM`).
    pub fn reset_stream_send(
        &mut self,
        cx: &Cx,
        id: StreamId,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_stream_active_state()?;
        if error_code > VARINT_MAX || final_size > VARINT_MAX {
            return Err(NativeQuicConnectionError::InvalidState(
                "RESET_STREAM values must fit QUIC varints",
            ));
        }
        self.streams
            .reset_stream_send(id, error_code, final_size)
            .map_err(map_stream_table_error)?;
        self.discard_retransmittable_stream_refs(id);
        self.queue_control_frame_once(QuicFrame::ResetStream {
            stream_id: VarInt::from_u64_unchecked(id.0),
            error_code: VarInt::from_u64_unchecked(error_code),
            final_size: VarInt::from_u64_unchecked(final_size),
        });
        Ok(())
    }

    /// Graceful close (enters draining).
    pub fn begin_close(
        &mut self,
        cx: &Cx,
        now_micros: u64,
        app_error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        let close_was_unattributed = !matches!(
            self.transport.state(),
            QuicConnectionState::Draining | QuicConnectionState::Closed
        );
        self.transport.start_draining_with_code(
            now_micros,
            self.drain_timeout_micros,
            app_error_code,
        )?;
        if close_was_unattributed {
            self.peer_close_observed = false;
        }
        Ok(())
    }

    /// Immediate terminal close.
    pub fn close_immediately(
        &mut self,
        cx: &Cx,
        app_error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        if !matches!(
            self.transport.state(),
            QuicConnectionState::Draining | QuicConnectionState::Closed
        ) {
            self.peer_close_observed = false;
        }
        self.transport.close_immediately(app_error_code);
        Ok(())
    }

    /// RFC 9000 section 10.2: a peer frame that breaks a transport rule closes
    /// the connection at once with the matching transport error. Errors with
    /// no peer cause, such as cancellation or reassembly backpressure, leave
    /// the connection open, and so does a state that cannot start draining.
    fn close_on_peer_violation(
        &mut self,
        error: &NativeQuicConnectionError,
        frame_type: u64,
        now_micros: u64,
    ) {
        let Some(code) = peer_violation_code(error) else {
            return;
        };
        if matches!(
            self.transport.state(),
            QuicConnectionState::Draining | QuicConnectionState::Closed
        ) {
            return;
        }
        if self
            .transport
            .start_draining_with_code(now_micros, self.drain_timeout_micros, code)
            .is_ok()
        {
            self.peer_close_observed = false;
            self.local_close_frame_type = Some(frame_type);
        }
    }

    /// Only the locally initiated close may bypass the ordinary draining send
    /// gate. No application, ACK, probe, or peer-close response is admitted here.
    pub(crate) fn is_local_close_frame(&self, frames: &[QuicFrame]) -> bool {
        self.state() == QuicConnectionState::Draining
            && !self.peer_close_observed
            && self.tls.can_send_1rtt()
            && matches!(frames, [QuicFrame::ConnectionClose {
                error_code, frame_type, reason_phrase,
            }] if Some(error_code.value()) == self.transport.close_code()
                && *frame_type == self.local_close_frame_type()
                && reason_phrase.is_empty())
    }

    pub(crate) fn validate_local_close_packet(
        &self,
        cx: &Cx,
        bytes: u64,
        frames: &[QuicFrame],
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        if !self.is_local_close_frame(frames) {
            return Err(NativeQuicConnectionError::InvalidState(
                "terminal packet must contain only the local CONNECTION_CLOSE",
            ));
        }
        self.ensure_anti_amplification_limit(bytes)
    }

    /// Commit a protected close without creating congestion/recovery work for
    /// a connection that has already stopped sending ordinary packets.
    pub(crate) fn on_local_close_packet_sent(
        &mut self,
        cx: &Cx,
        bytes: u64,
        frames: &[QuicFrame],
    ) -> Result<u64, NativeQuicConnectionError> {
        self.validate_local_close_packet(cx, bytes, frames)?;
        let number = self.next_packet_number(PacketNumberSpace::ApplicationData)?;
        if self.role == StreamRole::Server && !self.peer_address_validated {
            self.anti_amplification_bytes_sent =
                self.anti_amplification_bytes_sent.saturating_add(bytes);
        }
        Ok(number)
    }

    /// Poll transport timers (drain deadline).
    pub fn poll(&mut self, cx: &Cx, now_micros: u64) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.poll(now_micros);
        Ok(())
    }

    /// Enable session resumption/0-RTT mode for current handshake.
    pub fn enable_resumption_0rtt(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        if self.role != StreamRole::Client {
            return Err(NativeQuicConnectionError::InvalidState(
                "0-RTT resumption is client-only",
            ));
        }
        self.tls.enable_resumption();
        Ok(())
    }

    /// Disable session resumption/0-RTT mode.
    pub fn disable_resumption_0rtt(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.tls.disable_resumption();
        Ok(())
    }

    /// Set active-migration policy (typically sourced from peer transport params).
    pub fn set_active_migration_disabled(
        &mut self,
        cx: &Cx,
        disabled: bool,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.migration_disabled = disabled;
        Ok(())
    }

    /// Apply peer transport parameters that affect the native data plane.
    ///
    /// RFC 9221 DATAGRAM support is opt-in: if the peer omits
    /// `max_datagram_frame_size`, this connection fails closed for later
    /// DATAGRAM sends by setting the effective cap to zero.
    pub fn apply_peer_transport_parameters(
        &mut self,
        cx: &Cx,
        params: &TransportParameters,
    ) -> Result<(), NativeQuicConnectionError> {
        self.apply_peer_transport_parameters_with_datagram_cap(cx, params, usize::MAX)
    }

    /// Apply authenticated peer settings while retaining the UDP owner's local
    /// DATAGRAM admission policy. Keep all validation and field assignment in
    /// this shared path so live handshakes cannot omit ACK or migration state.
    pub(crate) fn apply_peer_transport_parameters_with_datagram_cap(
        &mut self,
        cx: &Cx,
        params: &TransportParameters,
        local_datagram_cap: usize,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        // TransportParameters is publicly constructible, so callers can bypass
        // the wire parser. Reject invalid exponents before changing any state
        // or allowing an oversized shift in decode_ack_delay.
        let ack_delay_exponent = params.ack_delay_exponent.unwrap_or(3);
        if ack_delay_exponent > 20 {
            return Err(NativeQuicConnectionError::InvalidState(
                "peer ack_delay_exponent exceeds 20",
            ));
        }
        let max_ack_delay_millis = params.max_ack_delay.unwrap_or(25);
        if max_ack_delay_millis >= (1 << 14) {
            return Err(NativeQuicConnectionError::InvalidState(
                "peer max_ack_delay must be below 16384 milliseconds",
            ));
        }
        let peer_datagram_cap = match params.max_datagram_frame_size {
            Some(max) => usize::try_from(max).map_err(|_| {
                NativeQuicConnectionError::InvalidState(
                    "peer max_datagram_frame_size exceeds platform usize",
                )
            })?,
            None => 0,
        };
        // Preflight every fallible conversion before committing any state.
        self.migration_disabled = params.disable_active_migration;
        self.max_datagram_frame_size = peer_datagram_cap.min(local_datagram_cap);
        // The validated exponent scales the ACK Delay field of 1-RTT ACKs.
        self.peer_ack_delay_exponent =
            u32::try_from(ack_delay_exponent).expect("validated QUIC ACK delay exponent");
        // RFC 9000 §18.2: max_ack_delay defaults to 25 ms and is carried in
        // milliseconds; convert to microseconds. Feed it to the transport
        // machine so both the RTT `ack_delay` clamp (RFC 9002 §5.3) and the PTO
        // computation use the negotiated value (asupersync-mc7m2r).
        let max_ack_delay_micros = max_ack_delay_millis * 1_000;
        self.peer_max_ack_delay_micros = max_ack_delay_micros;
        self.transport
            .set_peer_max_ack_delay_micros(max_ack_delay_micros);
        Ok(())
    }

    /// Credit bytes received from the peer before address validation completes.
    pub fn on_datagram_received(
        &mut self,
        cx: &Cx,
        bytes: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.anti_amplification_bytes_received =
            self.anti_amplification_bytes_received.saturating_add(bytes);
        Ok(())
    }

    /// Mark the peer address as validated, lifting server anti-amplification limits.
    pub fn validate_peer_address(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.peer_address_validated = true;
        Ok(())
    }

    /// Current active path identifier.
    #[must_use]
    pub fn active_path_id(&self) -> u64 {
        self.active_path_id
    }

    /// Number of successful path migrations observed.
    #[must_use]
    pub fn migration_events(&self) -> u64 {
        self.migration_events
    }

    /// Request migration to a new path identifier.
    pub fn request_path_migration(
        &mut self,
        cx: &Cx,
        new_path_id: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        if self.migration_disabled {
            return Err(NativeQuicConnectionError::InvalidState(
                "active migration disabled by transport parameters",
            ));
        }
        if self.transport.state() != QuicConnectionState::Established {
            return Err(NativeQuicConnectionError::InvalidState(
                "path migration requires established state",
            ));
        }
        if new_path_id == self.active_path_id {
            return Ok(self.migration_events);
        }
        self.active_path_id = new_path_id;
        self.migration_events = self.migration_events.saturating_add(1);
        Ok(self.migration_events)
    }

    /// Track transport metadata for a sent packet and return its assigned packet
    /// number.
    ///
    /// This method has no frame slice and therefore cannot bind reliable
    /// STREAM/RESET_STREAM/STOP_SENDING recovery. Native packet assemblers that
    /// send frames returned by [`Self::generate_frames`] should call
    /// [`Self::on_packet_sent_with_frames`] instead.
    pub fn on_packet_sent(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        bytes: u64,
        ack_eliciting: bool,
        in_flight: bool,
        time_sent_micros: u64,
    ) -> Result<u64, NativeQuicConnectionError> {
        self.on_packet_sent_inner(
            cx,
            space,
            bytes,
            ack_eliciting,
            in_flight,
            time_sent_micros,
            true,
        )
    }

    fn on_packet_sent_inner(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        bytes: u64,
        ack_eliciting: bool,
        in_flight: bool,
        time_sent_micros: u64,
        enforce_congestion_admission: bool,
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_packet_send_state(space)?;
        if enforce_congestion_admission && in_flight && !self.transport.can_send(bytes) {
            return Err(NativeQuicConnectionError::CongestionLimited {
                requested: bytes,
                bytes_in_flight: self.transport.bytes_in_flight(),
                congestion_window: self.transport.congestion_window_bytes(),
            });
        }
        self.ensure_anti_amplification_limit(bytes)?;
        let pn = self.next_packet_number(space)?;
        self.transport.on_packet_sent(SentPacketMeta {
            space,
            packet_number: pn,
            bytes,
            ack_eliciting,
            in_flight,
            time_sent_micros,
        });
        if self.role == StreamRole::Server && !self.peer_address_validated {
            self.anti_amplification_bytes_sent =
                self.anti_amplification_bytes_sent.saturating_add(bytes);
        }
        Ok(pn)
    }

    /// Record a sent packet and bind its exact reliable frames to the assigned
    /// packet number for ACK/loss recovery.
    ///
    /// Packet assembly is deliberately stateless: callers pass the frames that
    /// were actually committed to this packet, so skipped handshake output,
    /// send admission refusal, and packet-protection failure cannot shift a
    /// hidden generation queue and associate recovery state with the wrong
    /// packet.
    pub fn on_packet_sent_with_frames(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        bytes: u64,
        ack_eliciting: bool,
        in_flight: bool,
        time_sent_micros: u64,
        frames: &[QuicFrame],
    ) -> Result<u64, NativeQuicConnectionError> {
        let packet_number =
            self.on_packet_sent(cx, space, bytes, ack_eliciting, in_flight, time_sent_micros)?;
        if self.internal_retransmission_tracking {
            let refs = retransmittable_frame_refs(frames);
            if !refs.is_empty() {
                self.in_flight_retransmittable_frames[packet_number_space_idx(space)]
                    .insert(packet_number, refs);
            }
        }
        Ok(packet_number)
    }

    /// Process ACK.
    pub fn on_ack_received(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        acked_packet_numbers: &[u64],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> Result<AckEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let event = self.transport.on_ack_received(
            space,
            acked_packet_numbers,
            ack_delay_micros,
            now_micros,
        );
        let mut acked = acked_packet_numbers.to_vec();
        acked.sort_unstable();
        self.acknowledge_retransmittable_packets(space, |packet_number| {
            acked.binary_search(&packet_number).is_ok()
        })?;
        let lost_packet_numbers = self.transport.take_newly_lost_packet_numbers(space);
        self.requeue_lost_retransmittable_packets(space, &lost_packet_numbers)?;
        Ok(event)
    }

    /// Process ACK via explicit ranges.
    pub fn on_ack_ranges(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        ack_ranges: &[AckRange],
        ack_delay_micros: u64,
        now_micros: u64,
    ) -> Result<AckEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let event = self
            .transport
            .on_ack_ranges(space, ack_ranges, ack_delay_micros, now_micros);
        let acked = AckRangeSet::new(ack_ranges);
        self.acknowledge_retransmittable_packets(space, |packet_number| {
            acked.contains(packet_number)
        })?;
        let lost_packet_numbers = self.transport.take_newly_lost_packet_numbers(space);
        self.requeue_lost_retransmittable_packets(space, &lost_packet_numbers)?;
        Ok(event)
    }

    /// Compute PTO deadline.
    pub fn pto_deadline_micros(
        &self,
        cx: &Cx,
        now_micros: u64,
    ) -> Result<Option<u64>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        Ok(self.transport.pto_deadline_micros(now_micros))
    }

    /// Record PTO timeout firing (backoff).
    pub fn on_pto_expired(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.on_pto_expired();
        Ok(())
    }

    /// Release expired ack-eliciting in-flight packets in `space` as lost.
    pub fn on_loss_timeout_expired(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        now_micros: u64,
    ) -> Result<AckEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let event = self.transport.on_loss_timeout_expired(space, now_micros);
        let lost_packet_numbers = self.transport.take_newly_lost_packet_numbers(space);
        self.requeue_lost_retransmittable_packets(space, &lost_packet_numbers)?;
        Ok(event)
    }

    /// Record a PTO firing and queue an ack-eliciting probe frame.
    pub fn on_probe_timeout(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        self.on_pto_expired(cx)?;
        for space in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            self.requeue_in_flight_retransmittable_frames(space)?;
        }
        self.pending_control_frames.push_back(QuicFrame::Ping);
        Ok(())
    }

    /// Rearm a due managed PTO and authorize one bounded 1-RTT PING probe.
    /// Unlike the legacy queue-based callback, repeated expirations never add
    /// control frames or copy the reliable-frame ledger. ACK/loss processing
    /// still owns retransmission of the original flight.
    pub(crate) fn on_managed_probe_timeout(
        &mut self,
        cx: &Cx,
        now_micros: u64,
    ) -> Result<Option<u64>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let Some(deadline) = self.transport.pto_deadline_micros(now_micros) else {
            self.pending_pto_probe = false;
            return Ok(None);
        };
        if deadline > now_micros {
            return Ok(Some(deadline));
        }
        let next_deadline = self.transport.on_pto_expired_at(now_micros);
        self.pending_pto_probe = next_deadline.is_some();
        Ok(next_deadline)
    }

    /// Build only the PING authorized by the latest managed PTO, without
    /// draining any queued application or control frames. Failed packet
    /// protection leaves the permit available for another attempt; only packet
    /// commitment consumes it.
    pub(crate) fn generate_pto_probe_frames(
        &self,
        cx: &Cx,
        max_frame_bytes: usize,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        if !self.pending_pto_probe || max_frame_bytes == 0 {
            return Ok(Vec::new());
        }
        if !self.can_send_1rtt() {
            return Err(NativeQuicConnectionError::InvalidState(
                "managed PTO probe requires established 1-RTT state",
            ));
        }
        Ok(vec![QuicFrame::Ping])
    }

    /// Commit the managed probe after packet protection succeeds. Only one
    /// PING packet of at most 1200 bytes may bypass cwnd for each fired PTO
    /// (RFC 9002 section 7.5). State, anti-amplification, packet numbers, and
    /// in-flight accounting use the ordinary send path. No reliable frames
    /// need ledger entries because this seam admits only PING.
    pub(crate) fn on_pto_probe_packet_sent(
        &mut self,
        cx: &Cx,
        bytes: u64,
        time_sent_micros: u64,
        frames: &[QuicFrame],
    ) -> Result<u64, NativeQuicConnectionError> {
        checkpoint(cx)?;
        if !self.can_send_1rtt() {
            return Err(NativeQuicConnectionError::InvalidState(
                "managed PTO probe requires established 1-RTT state",
            ));
        }
        if !self.pending_pto_probe
            || !(1..=1_200).contains(&bytes)
            || !matches!(frames, [QuicFrame::Ping])
        {
            return Err(NativeQuicConnectionError::InvalidState(
                "managed PTO permits one PING packet of at most 1200 bytes",
            ));
        }
        let packet_number = self.on_packet_sent_inner(
            cx,
            PacketNumberSpace::ApplicationData,
            bytes,
            true,
            true,
            time_sent_micros,
            false,
        )?;
        self.pending_pto_probe = false;
        Ok(packet_number)
    }

    /// Record successful delivery by a deterministic/in-memory transport that
    /// deliberately bypasses packet-number loss recovery.
    pub(crate) fn on_generated_frames_delivered(
        &mut self,
        frames: &[QuicFrame],
    ) -> Result<(), NativeQuicConnectionError> {
        let delivered = retransmittable_frame_refs(frames);
        self.release_retransmittable_refs(&delivered)
    }

    /// Requeue a generated packet deliberately dropped by a deterministic
    /// transport before it was associated with loss recovery.
    pub(crate) fn on_generated_frames_dropped(
        &mut self,
        frames: &[QuicFrame],
    ) -> Result<(), NativeQuicConnectionError> {
        let dropped = retransmittable_frame_refs(frames);
        self.requeue_retransmittable_refs(&dropped)
    }

    fn acknowledge_retransmittable_packets(
        &mut self,
        space: PacketNumberSpace,
        mut is_acked: impl FnMut(u64) -> bool,
    ) -> Result<(), NativeQuicConnectionError> {
        if !self.internal_retransmission_tracking {
            return Ok(());
        }
        let ledger = &mut self.in_flight_retransmittable_frames[packet_number_space_idx(space)];
        let acked_packet_numbers = ledger
            .keys()
            .copied()
            .filter(|packet_number| is_acked(*packet_number))
            .collect::<Vec<_>>();
        let mut acknowledged = Vec::new();
        for packet_number in acked_packet_numbers {
            if let Some(mut refs) = ledger.remove(&packet_number) {
                acknowledged.append(&mut refs);
            }
        }
        self.release_retransmittable_refs(&acknowledged)
    }

    fn release_retransmittable_refs(
        &mut self,
        acknowledged: &[RetransmittableFrameRef],
    ) -> Result<(), NativeQuicConnectionError> {
        // Other in-flight copies of the acknowledged frames leave the ledgers
        // in one pass; a pass per frame made one large ACK cost (frames
        // acknowledged x frames in flight) (br-asupersync-5f1fcj).
        let mut released = BTreeSet::new();
        let mut result = Ok(());
        for frame_ref in acknowledged {
            if let RetransmittableFrameRef::Stream {
                stream_id,
                offset,
                data_len,
                fin,
            } = frame_ref
                && let Err(error) = self
                    .streams
                    .release_sent_stream_frame_if_matches(*stream_id, *offset, *data_len, *fin)
            {
                result = Err(map_stream_table_error(error));
                break;
            }
            if let Some(control) = frame_ref.control_frame() {
                self.pending_control_frames
                    .retain(|candidate| candidate != &control);
            }
            released.insert(frame_ref);
        }
        if !released.is_empty() {
            for ledger in &mut self.in_flight_retransmittable_frames {
                ledger.retain(|_, refs| {
                    refs.retain(|candidate| !released.contains(candidate));
                    !refs.is_empty()
                });
            }
        }
        result
    }

    fn discard_retransmittable_stream_refs(&mut self, stream_id: StreamId) {
        for ledger in &mut self.in_flight_retransmittable_frames {
            ledger.retain(|_, refs| {
                refs.retain(|frame_ref| {
                    !matches!(
                        frame_ref,
                        RetransmittableFrameRef::Stream {
                            stream_id: candidate,
                            ..
                        } if *candidate == stream_id
                    )
                });
                !refs.is_empty()
            });
        }
    }

    fn requeue_in_flight_retransmittable_frames(
        &mut self,
        space: PacketNumberSpace,
    ) -> Result<(), NativeQuicConnectionError> {
        if !self.internal_retransmission_tracking {
            return Ok(());
        }
        let refs = self.in_flight_retransmittable_frames[packet_number_space_idx(space)]
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        self.requeue_retransmittable_refs(&refs)
    }

    fn requeue_lost_retransmittable_packets(
        &mut self,
        space: PacketNumberSpace,
        lost_packet_numbers: &[u64],
    ) -> Result<(), NativeQuicConnectionError> {
        if !self.internal_retransmission_tracking || lost_packet_numbers.is_empty() {
            return Ok(());
        }
        let ledger = &mut self.in_flight_retransmittable_frames[packet_number_space_idx(space)];
        let mut lost_refs = Vec::new();
        for packet_number in lost_packet_numbers {
            if let Some(mut refs) = ledger.remove(packet_number) {
                lost_refs.append(&mut refs);
            }
        }
        self.requeue_retransmittable_refs(&lost_refs)
    }

    fn requeue_retransmittable_refs(
        &mut self,
        refs: &[RetransmittableFrameRef],
    ) -> Result<(), NativeQuicConnectionError> {
        // Requeue at the front in reverse traversal so the next packet keeps
        // the original wire order (notably RESET_STREAM before a paired
        // STOP_SENDING emitted by HTTP/3 cancellation).
        for frame_ref in refs.iter().rev() {
            match frame_ref {
                RetransmittableFrameRef::Stream {
                    stream_id, offset, ..
                } => {
                    self.streams
                        .requeue_sent_stream_frame(*stream_id, *offset)
                        .map_err(map_stream_table_error)?;
                }
                _ => {
                    let control = frame_ref
                        .control_frame()
                        .expect("non-STREAM retransmittable frame has a wire form");
                    if !self.pending_control_frames.contains(&control) {
                        self.pending_control_frames.push_front(control);
                    }
                }
            }
        }
        Ok(())
    }

    /// Queue an ack-eliciting PING without advancing PTO backoff state.
    pub fn queue_ping(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        self.pending_control_frames.push_back(QuicFrame::Ping);
        Ok(())
    }

    /// Request local key update.
    pub fn request_local_key_update(
        &mut self,
        cx: &Cx,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.request_local_key_update()?;
        Ok(evt)
    }

    /// RFC 9001 section 6.1 eligibility for automatic local initiation.
    /// Peer-triggered updates use the existing request/commit path directly:
    /// they must update the send key before acknowledging the peer's packet.
    pub(crate) fn can_initiate_local_key_update(&self) -> bool {
        self.can_send_1rtt()
            && self.tls.handshake_confirmed()
            && self.local_key_update_floor.is_none_or(|floor| {
                self.transport
                    .largest_acked_packet_number(PacketNumberSpace::ApplicationData)
                    .is_some_and(|acked| acked >= floor)
            })
    }

    /// Commit local key update once keys are installed.
    pub fn commit_local_key_update(
        &mut self,
        cx: &Cx,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.commit_local_key_update()?;
        if matches!(evt, KeyUpdateEvent::LocalUpdateScheduled { .. }) {
            self.local_key_update_floor = Some(
                self.next_packet_numbers[packet_number_space_idx(PacketNumberSpace::ApplicationData)],
            );
        }
        Ok(evt)
    }

    /// Process peer key phase.
    pub fn on_peer_key_phase(
        &mut self,
        cx: &Cx,
        phase: bool,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.on_peer_key_phase(phase)?;
        Ok(evt)
    }

    /// Process a peer key phase observed on an authenticated 1-RTT packet,
    /// using the packet number to disambiguate a genuine key update from a
    /// delayed previous-phase packet (RFC 9001 §6.3, asupersync-1bheeo).
    pub fn on_peer_key_phase_pn(
        &mut self,
        cx: &Cx,
        phase: bool,
        packet_number: u64,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.on_peer_key_phase_pn(phase, packet_number)?;
        Ok(evt)
    }

    /// Next locally initiated stream eligible for write scheduling.
    pub fn next_writable_stream(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<StreamId>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.ensure_data_state()?;
        Ok(self.streams.next_writable_stream())
    }

    fn ensure_data_state(&self) -> Result<(), NativeQuicConnectionError> {
        if self.transport.state() == QuicConnectionState::Closed {
            return Err(NativeQuicConnectionError::InvalidState(
                "connection is closed",
            ));
        }
        if !(self.can_send_1rtt() || self.can_send_0rtt()) {
            return Err(NativeQuicConnectionError::InvalidState(
                "1-RTT traffic not yet enabled",
            ));
        }
        Ok(())
    }

    fn ensure_stream_open_state(&self) -> Result<(), NativeQuicConnectionError> {
        if self.transport.state() != QuicConnectionState::Established {
            return Err(NativeQuicConnectionError::InvalidState(
                "new application streams require established state",
            ));
        }
        Ok(())
    }

    fn ensure_stream_active_state(&self) -> Result<(), NativeQuicConnectionError> {
        if matches!(
            self.transport.state(),
            QuicConnectionState::Established | QuicConnectionState::Draining
        ) {
            return Ok(());
        }
        Err(NativeQuicConnectionError::InvalidState(
            "stream operation requires established or draining state",
        ))
    }

    fn ensure_packet_send_state(
        &self,
        space: PacketNumberSpace,
    ) -> Result<(), NativeQuicConnectionError> {
        if matches!(
            self.transport.state(),
            QuicConnectionState::Draining | QuicConnectionState::Closed
        ) {
            return Err(NativeQuicConnectionError::InvalidState(
                "packet send requires non-draining, non-closed connection state",
            ));
        }
        if matches!(space, PacketNumberSpace::ApplicationData)
            && !self.can_send_1rtt()
            && !self.can_send_0rtt()
        {
            return Err(NativeQuicConnectionError::InvalidState(
                "application-data packets require established 1-RTT state",
            ));
        }
        Ok(())
    }

    fn next_packet_number(
        &mut self,
        space: PacketNumberSpace,
    ) -> Result<u64, NativeQuicConnectionError> {
        let idx = packet_number_space_idx(space);
        let out = self.next_packet_number_for_protection(space)?;
        self.next_packet_numbers[idx] = out + 1;
        Ok(out)
    }

    /// Read the packet number that packet protection must bind without
    /// advancing transport state. The caller commits that exact number through
    /// `on_packet_sent_with_frames` only after protection succeeds.
    pub(crate) fn next_packet_number_for_protection(
        &self,
        space: PacketNumberSpace,
    ) -> Result<u64, NativeQuicConnectionError> {
        let out = self.next_packet_numbers[packet_number_space_idx(space)];
        // RFC 9000 §17.1: packet numbers are integers in [0, 2^62-1] inclusive.
        // The exhaustion guard rejects when `out` is already past the last
        // valid packet number, not when it equals the last valid one.
        if out > (1u64 << 62) - 1 {
            return Err(NativeQuicConnectionError::InvalidState(
                "packet number limit reached; connection must be closed",
            ));
        }
        Ok(out)
    }

    fn ensure_anti_amplification_limit(&self, bytes: u64) -> Result<(), NativeQuicConnectionError> {
        if self.role != StreamRole::Server || self.peer_address_validated {
            return Ok(());
        }
        let limit = self.anti_amplification_bytes_received.saturating_mul(3);
        let attempted = self.anti_amplification_bytes_sent.saturating_add(bytes);
        if attempted > limit {
            return Err(NativeQuicConnectionError::AmplificationLimited {
                requested: bytes,
                bytes_sent: self.anti_amplification_bytes_sent,
                bytes_received: self.anti_amplification_bytes_received,
                limit,
            });
        }
        Ok(())
    }

    fn role_label(&self) -> &'static str {
        match self.role {
            StreamRole::Client => "client",
            StreamRole::Server => "server",
        }
    }
}

fn checkpoint(cx: &Cx) -> Result<(), NativeQuicConnectionError> {
    cx.checkpoint()
        .map_err(|_| NativeQuicConnectionError::Cancelled)
}

fn map_stream_table_error(err: StreamTableError) -> NativeQuicConnectionError {
    match err {
        StreamTableError::Stream(stream_err) => NativeQuicConnectionError::Stream(stream_err),
        other => NativeQuicConnectionError::StreamTable(other),
    }
}

/// RFC 9000 section 20.1 transport error codes for peer stream and frame
/// violations.
const FLOW_CONTROL_ERROR: u64 = 0x03;
const STREAM_LIMIT_ERROR: u64 = 0x04;
const STREAM_STATE_ERROR: u64 = 0x05;
const FINAL_SIZE_ERROR: u64 = 0x06;
const FRAME_ENCODING_ERROR: u64 = 0x07;
const PROTOCOL_VIOLATION: u64 = 0x0a;

/// RFC 9000 section 12.4, Table 3: Initial and Handshake packets carry only
/// PADDING, PING, ACK, CRYPTO and the transport CONNECTION_CLOSE. Initial
/// keys derive from the client's connection ID, so an on-path party can forge
/// an Initial packet; nothing else may reach stream or connection state there.
const FRAME_NOT_PERMITTED_IN_PACKET_SPACE: &str =
    "frame type is not permitted in an Initial or Handshake packet";

fn frame_permitted_in_space(frame: &QuicFrame, space: PacketNumberSpace) -> bool {
    space == PacketNumberSpace::ApplicationData
        || matches!(
            frame,
            QuicFrame::Padding { .. }
                | QuicFrame::Ping
                | QuicFrame::Ack { .. }
                | QuicFrame::Crypto { .. }
                | QuicFrame::ConnectionClose {
                    frame_type: Some(_),
                    ..
                }
        )
}

/// The transport error code for an error raised while applying a peer's frame,
/// or `None` when the error has no peer cause (it fails closed: an unmapped
/// error never closes the connection).
fn peer_violation_code(error: &NativeQuicConnectionError) -> Option<u64> {
    let stream_error = match error {
        NativeQuicConnectionError::Frame(_) => return Some(FRAME_ENCODING_ERROR),
        NativeQuicConnectionError::InvalidState(message)
            if *message == FRAME_NOT_PERMITTED_IN_PACKET_SPACE =>
        {
            return Some(PROTOCOL_VIOLATION);
        }
        NativeQuicConnectionError::Stream(stream_error) => stream_error,
        NativeQuicConnectionError::StreamTable(table_error) => match table_error {
            StreamTableError::StreamLimitExceeded { .. } => return Some(STREAM_LIMIT_ERROR),
            // Frames for a locally initiated stream not yet opened, or for the
            // direction a stream does not have (sections 19.4 to 19.13).
            StreamTableError::UnknownStream(_)
            | StreamTableError::InvalidRemoteStream(_)
            | StreamTableError::StreamNotWritable(_)
            | StreamTableError::StreamNotReadable(_) => return Some(STREAM_STATE_ERROR),
            StreamTableError::Stream(stream_error) => stream_error,
            StreamTableError::DuplicateStream(_) => return None,
        },
        _ => return None,
    };
    match stream_error {
        QuicStreamError::Flow(FlowControlError::Exhausted { .. }) => Some(FLOW_CONTROL_ERROR),
        QuicStreamError::InvalidFinalSize { .. } | QuicStreamError::InconsistentReset { .. } => {
            Some(FINAL_SIZE_ERROR)
        }
        // Section 19.8: an offset plus length above 2^62 - 1.
        QuicStreamError::OffsetOverflow { .. } => Some(FRAME_ENCODING_ERROR),
        _ => None,
    }
}

/// Copies a STREAM, CRYPTO or DATAGRAM payload that uses less than a quarter
/// of its `datagram_len`-byte datagram, so holding it does not keep the whole
/// datagram allocated (see [`NativeQuicConnection::decode_frames_bytes`]).
fn unpin_small_payload(frame: QuicFrame, datagram_len: usize) -> QuicFrame {
    let small = |data: &Bytes| data.len().saturating_mul(4) < datagram_len;
    match frame {
        QuicFrame::Stream {
            stream_id,
            offset,
            data,
            fin,
        } if small(&data) => QuicFrame::Stream {
            stream_id,
            offset,
            data: Bytes::copy_from_slice(&data),
            fin,
        },
        QuicFrame::Crypto { offset, data } if small(&data) => QuicFrame::Crypto {
            offset,
            data: Bytes::copy_from_slice(&data),
        },
        QuicFrame::Datagram { data } if small(&data) => QuicFrame::Datagram {
            data: Bytes::copy_from_slice(&data),
        },
        other => other,
    }
}

/// The wire type of a decoded frame, for the Frame Type field of a transport
/// CONNECTION_CLOSE. STREAM reports its OFF and FIN bits; the decoded frame
/// does not keep the LEN bit.
fn received_frame_type(frame: &QuicFrame) -> u64 {
    let frame_type = match frame {
        QuicFrame::Padding { .. } => QuicFrameType::Padding,
        QuicFrame::Ping => QuicFrameType::Ping,
        QuicFrame::Ack { ecn_counts, .. } => {
            if ecn_counts.is_some() {
                QuicFrameType::AckEcn
            } else {
                QuicFrameType::Ack
            }
        }
        QuicFrame::ResetStream { .. } => QuicFrameType::ResetStream,
        QuicFrame::StopSending { .. } => QuicFrameType::StopSending,
        QuicFrame::Crypto { .. } => QuicFrameType::Crypto,
        QuicFrame::NewToken { .. } => QuicFrameType::NewToken,
        QuicFrame::Stream { offset, fin, .. } => {
            return QuicFrameType::StreamBase as u64
                | if offset.is_some() { 0x04 } else { 0 }
                | u64::from(*fin);
        }
        QuicFrame::MaxData { .. } => QuicFrameType::MaxData,
        QuicFrame::MaxStreamData { .. } => QuicFrameType::MaxStreamData,
        QuicFrame::MaxStreams { bidirectional, .. } => {
            if *bidirectional {
                QuicFrameType::MaxStreamsBidi
            } else {
                QuicFrameType::MaxStreamsUni
            }
        }
        QuicFrame::DataBlocked { .. } => QuicFrameType::DataBlocked,
        QuicFrame::StreamDataBlocked { .. } => QuicFrameType::StreamDataBlocked,
        QuicFrame::StreamsBlocked { bidirectional, .. } => {
            if *bidirectional {
                QuicFrameType::StreamsBlockedBidi
            } else {
                QuicFrameType::StreamsBlockedUni
            }
        }
        QuicFrame::NewConnectionId { .. } => QuicFrameType::NewConnectionId,
        QuicFrame::RetireConnectionId { .. } => QuicFrameType::RetireConnectionId,
        QuicFrame::PathChallenge { .. } => QuicFrameType::PathChallenge,
        QuicFrame::PathResponse { .. } => QuicFrameType::PathResponse,
        QuicFrame::ConnectionClose { frame_type, .. } => {
            if frame_type.is_some() {
                QuicFrameType::ConnectionCloseQuic
            } else {
                QuicFrameType::ConnectionCloseApp
            }
        }
        QuicFrame::HandshakeDone => QuicFrameType::HandshakeDone,
        QuicFrame::Datagram { .. } => QuicFrameType::Datagram,
    };
    frame_type as u64
}

fn quic_trace(cx: &Cx, event: &str, fields: &[(&str, &str)]) {
    if std::env::var_os("ATP_QUIC_TRACE").is_some() {
        cx.trace_with_fields(event, fields);
    }
}

impl NativeQuicConnection {
    /// Process a decoded packet payload and update connection state.
    pub fn process_packet_payload(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        packet_number: u64,
        payload: &[u8],
        now_micros: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        let frames = match Self::decode_frames(payload) {
            Ok(frames) => frames,
            Err(error) => {
                // RFC 9000 section 12.4: a frame that does not parse, an
                // unknown type included, is a FRAME_ENCODING_ERROR.
                let frame_type = match &error {
                    NativeQuicConnectionError::Frame(QuicFrameError::UnknownFrameType(
                        frame_type,
                    )) => *frame_type,
                    _ => 0,
                };
                self.close_on_peer_violation(&error, frame_type, now_micros);
                return Err(error);
            }
        };
        self.process_packet_frames(cx, space, packet_number, &frames, now_micros)
    }

    /// Process the already-decoded frames of one packet and update connection
    /// state.
    ///
    /// This is the single-decode hot path: callers that already decoded the
    /// packet's frames (for example to count DATAGRAM slots before admission)
    /// pass them here directly instead of paying a second decode + payload
    /// copy via [`Self::process_packet_payload`].
    ///
    /// Reassembly-capacity refusal precedes all frame effects and queues no
    /// ACK. Drivers can recognize it with
    /// [`NativeQuicConnectionError::is_stream_reassembly_backpressure`], discard
    /// this packet, and continue receiving. Other frame errors retain their
    /// ordinary processing semantics; this is not a general packet rollback.
    /// A peer close ends packet processing immediately: preceding effects remain,
    /// but trailing frames and subsequent packets cannot mutate the draining
    /// connection or queue acknowledgements.
    ///
    /// A frame that breaks a stream, flow-control or frame-encoding rule closes
    /// the connection with the matching RFC 9000 transport error before the
    /// error returns: the connection drains, and its local CONNECTION_CLOSE is
    /// the transport variant naming the offending frame type. An Initial or
    /// Handshake packet carrying a frame that RFC 9000 section 12.4 does not
    /// permit there closes it with PROTOCOL_VIOLATION before any of the
    /// packet's frames takes effect.
    pub fn process_packet_frames(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        packet_number: u64,
        frames: &[QuicFrame],
        now_micros: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        if matches!(
            self.transport.state(),
            QuicConnectionState::Draining | QuicConnectionState::Closed
        ) {
            return Ok(());
        }
        // Checked for the whole packet before any frame takes effect.
        if let Some(frame) = frames
            .iter()
            .find(|frame| !frame_permitted_in_space(frame, space))
        {
            let error =
                NativeQuicConnectionError::InvalidState(FRAME_NOT_PERMITTED_IN_PACKET_SPACE);
            self.close_on_peer_violation(&error, received_frame_type(frame), now_micros);
            return Err(error);
        }
        if self.streams.packet_reassembly_limits_would_be_exceeded(
            frames,
            MAX_BUFFERED_STREAM_REASSEMBLY_FRAGMENTS,
            MAX_BUFFERED_CONNECTION_REASSEMBLY_FRAGMENTS,
        ) {
            return Err(NativeQuicConnectionError::InvalidState(
                STREAM_REASSEMBLY_LIMIT_ERROR,
            ));
        }
        let ack_eliciting = frames.iter().any(frame_is_ack_eliciting);

        let mut index = 0usize;
        while index < frames.len() {
            if matches!(frames[index], QuicFrame::Datagram { .. }) {
                let start = index;
                while index < frames.len() && matches!(frames[index], QuicFrame::Datagram { .. }) {
                    index = index.saturating_add(1);
                }
                self.process_datagram_frame_run(cx, &frames[start..index], space)?;
            } else {
                if let Err(error) = self.process_frame_at(cx, &frames[index], space, now_micros) {
                    let frame_type = received_frame_type(&frames[index]);
                    self.close_on_peer_violation(&error, frame_type, now_micros);
                    return Err(error);
                }
                if matches!(frames[index], QuicFrame::ConnectionClose { .. }) {
                    // The peer has ended this connection. In particular, do
                    // not let a trailing frame turn the close into an error
                    // or enqueue an ACK/PATH_RESPONSE after entering draining.
                    return Ok(());
                }
                index = index.saturating_add(1);
            }
        }

        if ack_eliciting {
            self.queue_ack_frame(space, packet_number);
        } else {
            self.observe_non_ack_eliciting_packet(space, packet_number);
        }

        Ok(())
    }

    /// Process an incoming QUIC frame and update connection state.
    pub fn process_frame(
        &mut self,
        cx: &Cx,
        frame: &QuicFrame,
        space: PacketNumberSpace,
    ) -> Result<(), NativeQuicConnectionError> {
        self.process_frame_at(cx, frame, space, 0)
    }

    /// Decode an ACK frame's ACK Delay field into microseconds for RTT
    /// estimation (RFC 9000 §19.3, RFC 9002 §5.3, asupersync-mc7m2r).
    ///
    /// The field is expressed in units of `2^ack_delay_exponent` microseconds:
    /// 1-RTT ACKs use the peer's negotiated exponent; Initial and Handshake ACKs
    /// use the default exponent 3. Once the handshake is confirmed, the result is
    /// clamped by the peer's `max_ack_delay` so a peer cannot deflate our RTT
    /// estimate (and thereby shorten our loss/PTO timers) by over-reporting delay.
    fn decode_ack_delay(&self, space: PacketNumberSpace, raw_value: u64) -> u64 {
        let exponent = if space == PacketNumberSpace::ApplicationData {
            self.peer_ack_delay_exponent
        } else {
            3
        };
        let scaled = raw_value.saturating_mul(1u64 << exponent);
        if space == PacketNumberSpace::ApplicationData && self.tls.handshake_confirmed() {
            scaled.min(self.peer_max_ack_delay_micros)
        } else {
            scaled
        }
    }

    fn process_frame_at(
        &mut self,
        cx: &Cx,
        frame: &QuicFrame,
        space: PacketNumberSpace,
        now_micros: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        match frame {
            QuicFrame::Padding { .. } | QuicFrame::Ping => Ok(()),
            QuicFrame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
                ..
            } => {
                let ranges = ack_frame_ranges(
                    largest_acknowledged.value(),
                    first_ack_range.value(),
                    ack_ranges,
                )?;
                let ack_delay_micros = self.decode_ack_delay(space, ack_delay.value());
                let _ = self.on_ack_ranges(cx, space, &ranges, ack_delay_micros, now_micros)?;
                Ok(())
            }
            QuicFrame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => {
                let id = StreamId(stream_id.value());
                if self.streams.stream(id).is_err() {
                    self.accept_remote_stream(cx, id)?;
                }
                let frame_offset = offset.map_or(0, VarInt::value);
                self.receive_stream_bytes(cx, id, frame_offset, data.clone(), *fin)?;
                self.trace_stream_frame(cx, "recv", id, frame_offset, data.len(), *fin, false);
                Ok(())
            }
            QuicFrame::Crypto { .. } => {
                if self.transport.state() == QuicConnectionState::Idle {
                    self.transport.begin_handshake()?;
                }
                Ok(())
            }
            QuicFrame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                let id = StreamId(stream_id.value());
                // RFC 9000 19.4: a send-only stream has no receive side to reset.
                if id.direction() == StreamDirection::Unidirectional && id.is_local_for(self.role) {
                    return Err(StreamTableError::StreamNotReadable(id).into());
                }
                if self.streams.stream(id).is_err() {
                    self.accept_remote_stream(cx, id)?;
                }
                self.reset_stream_receive(cx, id, error_code.value(), final_size.value())?;
                Ok(())
            }
            QuicFrame::StopSending {
                stream_id,
                error_code,
            } => {
                let id = StreamId(stream_id.value());
                if self.streams.stream(id).is_err() {
                    self.accept_remote_stream(cx, id)?;
                }
                self.on_stop_sending(cx, id, error_code.value())?;
                Ok(())
            }
            QuicFrame::MaxData { maximum_data } => {
                self.streams
                    .increase_connection_send_limit(maximum_data.value())
                    .map_err(QuicStreamError::Flow)?;
                Ok(())
            }
            QuicFrame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                let id = StreamId(stream_id.value());
                // RFC 9000 19.10: a receive-only stream takes no send credit.
                if id.direction() == StreamDirection::Unidirectional && !id.is_local_for(self.role)
                {
                    return Err(StreamTableError::StreamNotWritable(id).into());
                }
                // RFC 9000 3.2: credit for the sending part of a peer's
                // bidirectional stream also opens it. It can overtake the
                // peer's first STREAM frame when that packet is lost.
                if id.direction() == StreamDirection::Bidirectional
                    && self.streams.stream(id).is_err()
                {
                    self.accept_remote_stream(cx, id)?;
                }
                self.streams
                    .increase_stream_send_limit(id, maximum_stream_data.value())
                    .map_err(map_stream_table_error)?;
                Ok(())
            }
            QuicFrame::MaxStreams {
                maximum_streams,
                bidirectional,
            } => {
                if space != PacketNumberSpace::ApplicationData {
                    return Err(NativeQuicConnectionError::InvalidState(
                        "MAX_STREAMS requires application data packet space",
                    ));
                }
                // Stream IDs have two type bits inside the 62-bit QUIC
                // integer. A grant of 2^60 streams is valid, but any larger
                // value would authorize an unencodable ID (RFC 9000 19.11).
                // Validate before changing either direction's credit.
                let maximum_streams = maximum_streams.value();
                if maximum_streams > (1u64 << 60) {
                    return Err(QuicFrameError::InvalidFormat(
                        "MAX_STREAMS exceeds the 2^60 stream limit".to_owned(),
                    )
                    .into());
                }
                let direction = if *bidirectional {
                    StreamDirection::Bidirectional
                } else {
                    StreamDirection::Unidirectional
                };
                self.streams
                    .increase_local_stream_limit(direction, maximum_streams);
                Ok(())
            }
            QuicFrame::PathChallenge { data } => {
                // Answer the newest challenge only: a peer that streams
                // challenges faster than we send must not grow the control
                // queue without bound (asupersync-bi2462.107).
                self.pending_control_frames
                    .retain(|pending| !matches!(pending, QuicFrame::PathResponse { .. }));
                self.pending_control_frames
                    .push_back(QuicFrame::PathResponse { data: *data });
                Ok(())
            }
            QuicFrame::PathResponse { .. } => {
                // This endpoint never sends PATH_CHALLENGE, so no response can
                // match one; it must not validate the peer's address
                // (RFC 9000 §8.2.3). The handshake validates it instead.
                Ok(())
            }
            QuicFrame::ConnectionClose { error_code, .. } => {
                let close_was_unattributed = !matches!(
                    self.transport.state(),
                    QuicConnectionState::Draining | QuicConnectionState::Closed
                );
                self.transport.start_draining_with_code(
                    now_micros,
                    self.drain_timeout_micros,
                    error_code.value(),
                )?;
                if close_was_unattributed {
                    self.peer_close_observed = true;
                }
                Ok(())
            }
            QuicFrame::HandshakeDone => {
                if self.role != StreamRole::Client {
                    return Err(NativeQuicConnectionError::InvalidState(
                        "server cannot receive HANDSHAKE_DONE",
                    ));
                }
                if space != PacketNumberSpace::ApplicationData {
                    return Err(NativeQuicConnectionError::InvalidState(
                        "HANDSHAKE_DONE requires application data packet space",
                    ));
                }
                self.on_handshake_confirmed(cx)
            }
            QuicFrame::Datagram { .. } => {
                self.process_datagram_frame_run(cx, std::slice::from_ref(frame), space)?;
                Ok(())
            }
            QuicFrame::StreamDataBlocked {
                stream_id,
                maximum_stream_data,
            } => {
                // Sender-gated growth of a bounded receive window: the peer
                // says our advertised limit is its binding constraint. The
                // stream table decides whether the window may grow (cap,
                // hysteresis, one full window consumed since the last growth)
                // and returns the advertisement to put on the wire.
                let id = StreamId(stream_id.value());
                // RFC 9000 19.13: a send-only stream has no receive window.
                if id.direction() == StreamDirection::Unidirectional && id.is_local_for(self.role) {
                    return Err(StreamTableError::StreamNotReadable(id).into());
                }
                // RFC 9000 3.2: STREAM_DATA_BLOCKED opens a peer's stream,
                // as STREAM and RESET_STREAM do.
                if self.streams.stream(id).is_err() {
                    self.accept_remote_stream(cx, id)?;
                }
                if let Some(limit) = self
                    .streams
                    .note_peer_stream_data_blocked(id, maximum_stream_data.value())
                    .map_err(map_stream_table_error)?
                {
                    self.queue_max_stream_data_frame(id, limit);
                }
                Ok(())
            }
            // RFC 9000 19.14: as with MAX_STREAMS, a count above 2^60 cannot
            // name an encodable stream ID.
            QuicFrame::StreamsBlocked {
                maximum_streams, ..
            } if maximum_streams.value() > (1u64 << 60) => Err(QuicFrameError::InvalidFormat(
                "STREAMS_BLOCKED exceeds the 2^60 stream limit".to_owned(),
            )
            .into()),
            QuicFrame::NewToken { .. }
            | QuicFrame::NewConnectionId { .. }
            | QuicFrame::RetireConnectionId { .. }
            | QuicFrame::DataBlocked { .. }
            | QuicFrame::StreamsBlocked { .. } => Ok(()),
        }
    }

    fn process_datagram_frame_run(
        &mut self,
        cx: &Cx,
        frames: &[QuicFrame],
        space: PacketNumberSpace,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        if frames.is_empty() {
            return Ok(());
        }
        if let Some(local_max) = self.local_max_datagram_frame_size {
            if local_max == 0 {
                return Err(NativeQuicConnectionError::InvalidState(
                    "DATAGRAM frame received without an advertised max_datagram_frame_size",
                ));
            }
            for frame in frames {
                let QuicFrame::Datagram { data } = frame else {
                    unreachable!("datagram frame run contained non-datagram frame");
                };
                // The limit covers the whole frame; one type byte is its
                // smallest possible overhead.
                if data.len().saturating_add(1) > local_max {
                    return Err(NativeQuicConnectionError::InvalidState(
                        "DATAGRAM frame exceeds the advertised max_datagram_frame_size",
                    ));
                }
            }
        }

        let available = MAX_INBOUND_DATAGRAMS.saturating_sub(self.inbound_datagrams.len());
        let accept = available.min(frames.len());
        let mut accepted_bytes = 0usize;
        for frame in &frames[..accept] {
            let QuicFrame::Datagram { data } = frame else {
                unreachable!("datagram frame run contained non-datagram frame");
            };
            accepted_bytes = accepted_bytes.saturating_add(data.len());
            self.inbound_datagrams.push_back(data.clone());
        }
        if accept > 0 {
            self.datagrams_received = self
                .datagrams_received
                .saturating_add(u64::try_from(accept).unwrap_or(u64::MAX));
            quictrace!(
                "event=datagram_recv_batch frames={} bytes={} src_cid=unavailable path_id={} pn_space={:?} queue_len={} receive_overflow=false total_received={} total_dropped={}",
                accept,
                accepted_bytes,
                self.active_path_id,
                space,
                self.inbound_datagrams.len(),
                self.datagrams_received,
                self.datagrams_dropped_on_receive
            );
            if let Some(waker) = self.inbound_datagram_waker.take() {
                waker.wake();
            }
        }

        if accept < frames.len() {
            let mut dropped_bytes = 0usize;
            for frame in &frames[accept..] {
                let QuicFrame::Datagram { data } = frame else {
                    unreachable!("datagram frame run contained non-datagram frame");
                };
                dropped_bytes = dropped_bytes.saturating_add(data.len());
            }
            let dropped = frames.len() - accept;
            self.datagrams_dropped_on_receive = self
                .datagrams_dropped_on_receive
                .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
            quictrace!(
                "event=datagram_recv_drop frames={} bytes={} src_cid=unavailable path_id={} pn_space={:?} queue_len={} capacity={} total_received={} total_dropped={}",
                dropped,
                dropped_bytes,
                self.active_path_id,
                space,
                self.inbound_datagrams.len(),
                MAX_INBOUND_DATAGRAMS,
                self.datagrams_received,
                self.datagrams_dropped_on_receive
            );
        }

        Ok(())
    }

    /// Receive the next decoded DATAGRAM payload, if one is buffered.
    ///
    /// This is the application-facing receive surface for RFC 9221 datagrams:
    /// frames decoded by [`Self::process_packet_payload`] are enqueued in a
    /// bounded, no-evict queue and handed out here in arrival order.
    /// Returns `None` when no datagram is currently available; it does not
    /// block, so a higher-level `poll_recv_datagram` can layer a waker on top.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.inbound_datagrams.pop_front()
    }

    /// Receive up to `max_datagrams` decoded DATAGRAM payloads into `out`.
    ///
    /// The batch preserves arrival order and clears `out` before writing. This
    /// lets hot consumers amortize queue traffic without changing the
    /// application-facing single-DATAGRAM receive contract.
    pub fn recv_datagram_batch(
        &mut self,
        max_datagrams: usize,
        out: &mut VecDeque<Bytes>,
    ) -> usize {
        out.clear();
        let take = max_datagrams.min(self.inbound_datagrams.len());
        out.reserve(take);
        for _ in 0..take {
            if let Some(datagram) = self.inbound_datagrams.pop_front() {
                out.push_back(datagram);
            }
        }
        out.len()
    }

    /// Poll for the next decoded DATAGRAM payload without busy-polling.
    ///
    /// This is the Cx-aware receive surface used by higher-level event-loop
    /// adapters: cancellation is observed through [`Cx::checkpoint`], an
    /// available payload returns immediately, and an empty queue registers the
    /// task waker for the next DATAGRAM arrival.
    pub fn poll_recv_datagram(
        &mut self,
        cx: &Cx,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Bytes, NativeQuicConnectionError>> {
        if let Err(err) = checkpoint(cx) {
            return Poll::Ready(Err(err));
        }

        if let Some(datagram) = self.inbound_datagrams.pop_front() {
            return Poll::Ready(Ok(datagram));
        }

        let should_replace = self
            .inbound_datagram_waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(task_cx.waker()));
        if should_replace {
            self.inbound_datagram_waker = Some(task_cx.waker().clone());
        }
        Poll::Pending
    }

    /// Number of inbound DATAGRAM payloads currently buffered for the
    /// application.
    #[must_use]
    pub fn pending_datagram_count(&self) -> usize {
        self.inbound_datagrams.len()
    }

    /// Maximum inbound DATAGRAM payloads buffered before newly-arrived payloads
    /// are dropped and counted.
    #[must_use]
    pub fn inbound_datagram_capacity(&self) -> usize {
        MAX_INBOUND_DATAGRAMS
    }

    /// Remaining inbound DATAGRAM payload slots before newly-arrived payloads
    /// are dropped and counted.
    #[must_use]
    pub fn inbound_datagram_remaining_capacity(&self) -> usize {
        MAX_INBOUND_DATAGRAMS.saturating_sub(self.inbound_datagrams.len())
    }

    /// Total DATAGRAM frames accepted into the receive queue.
    #[must_use]
    pub fn datagrams_received(&self) -> u64 {
        self.datagrams_received
    }

    /// Total inbound DATAGRAM payloads dropped before enqueue because the
    /// bounded receive queue was full.
    #[must_use]
    pub fn datagrams_dropped_on_receive(&self) -> u64 {
        self.datagrams_dropped_on_receive
    }

    /// Queue an unreliable application datagram (RFC 9221) for transmission.
    ///
    /// The payload is later drained by [`Self::generate_frames`] into a
    /// `QuicFrame::Datagram` carried in a 1-RTT packet. The queue is bounded and
    /// fountain-tolerant: on overflow, the oldest not-yet-emitted payload is
    /// dropped so a fast producer cannot grow memory without bound.
    ///
    /// # Errors
    ///
    /// Returns [`NativeQuicConnectionError::DatagramTooLarge`] if the encoded
    /// frame would exceed the maximum DATAGRAM frame size, or
    /// [`NativeQuicConnectionError::Cancelled`] if `cx` is cancelled before the
    /// enqueue.
    pub fn send_datagram(
        &mut self,
        cx: &Cx,
        payload: Bytes,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.enqueue_datagram(cx, payload)
    }

    fn enqueue_datagram(
        &mut self,
        cx: &Cx,
        payload: Bytes,
    ) -> Result<(), NativeQuicConnectionError> {
        // RFC 9221: a sender MUST NOT send a DATAGRAM frame larger than the
        // peer-advertised max_datagram_frame_size. The frame must also fit one
        // protected 1-RTT packet on this connection (GH#66): a peer may
        // advertise 65535, but the packet assemblers refuse anything above the
        // protected packet cap, and that refusal is connection-fatal on the
        // sender's own drive path. Admission is where a typed refusal belongs.
        let payload_len = payload.len();
        let frame = QuicFrame::Datagram {
            data: payload.clone(),
        };
        let mut probe = BytesMut::new();
        frame.encode(&mut probe)?;
        let max_frame_size = self.max_datagram_frame_size.min(self.one_rtt_frame_budget);
        if probe.len() > max_frame_size {
            let encoded_len_s = probe.len().to_string();
            let max_frame_size_s = max_frame_size.to_string();
            let payload_len_s = payload_len.to_string();
            quic_trace(
                cx,
                "ATP_QUIC_TRACE datagram_send_drop",
                &[
                    ("reason", "too_large"),
                    ("payload_len", payload_len_s.as_str()),
                    ("encoded_len", encoded_len_s.as_str()),
                    ("max_frame_size", max_frame_size_s.as_str()),
                    ("pn", "none"),
                ],
            );
            quictrace!(
                "event=datagram_send_drop reason=too_large size={} encoded_len={} max_frame_size={} pn=none",
                payload_len,
                probe.len(),
                max_frame_size
            );
            return Err(NativeQuicConnectionError::DatagramTooLarge {
                payload_len,
                encoded_len: probe.len(),
                max_frame_size,
            });
        }

        let mut dropped_oldest = false;
        if self.outbound_datagrams.len() >= MAX_OUTBOUND_DATAGRAMS {
            if let Some(dropped) = self.outbound_datagrams.pop_front() {
                self.datagrams_dropped_on_send = self.datagrams_dropped_on_send.saturating_add(1);
                dropped_oldest = true;
                let dropped_len_s = dropped.len().to_string();
                let dropped_total_s = self.datagrams_dropped_on_send.to_string();
                quic_trace(
                    cx,
                    "ATP_QUIC_TRACE datagram_send_drop",
                    &[
                        ("reason", "queue_full_drop_oldest"),
                        ("payload_len", dropped_len_s.as_str()),
                        ("total_dropped", dropped_total_s.as_str()),
                        ("pn", "pending"),
                    ],
                );
                quictrace!(
                    "event=datagram_send_drop reason=queue_full_drop_oldest size={} total_dropped={} pn=pending",
                    dropped.len(),
                    self.datagrams_dropped_on_send
                );
            }
        }
        self.outbound_datagrams.push_back(payload);
        let queue_len_s = self.outbound_datagrams.len().to_string();
        let dropped_s = dropped_oldest.to_string();
        let dropped_total_s = self.datagrams_dropped_on_send.to_string();
        let payload_len_s = payload_len.to_string();
        quic_trace(
            cx,
            "ATP_QUIC_TRACE datagram_send_enqueue",
            &[
                ("reason", "queued"),
                ("payload_len", payload_len_s.as_str()),
                ("queue_len", queue_len_s.as_str()),
                ("dropped_oldest", dropped_s.as_str()),
                ("total_dropped", dropped_total_s.as_str()),
                ("pn", "pending"),
            ],
        );
        quictrace!(
            "event=datagram_send_enqueue reason=queued size={} queue_len={} dropped_oldest={} total_dropped={} pn=pending",
            payload_len,
            self.outbound_datagrams.len(),
            dropped_oldest,
            self.datagrams_dropped_on_send
        );
        Ok(())
    }

    /// Queue several unreliable application datagrams for transmission after a
    /// single cancellation checkpoint. The per-payload size and bounded-queue
    /// checks are identical to [`Self::send_datagram`]; the batch form exists so
    /// ATP/QUIC symbol producers can hand a full flush window to the connection
    /// without ping-ponging through the queue one symbol at a time.
    ///
    /// Returns the number of payloads queued before any error.
    pub fn send_datagram_batch<I>(
        &mut self,
        cx: &Cx,
        payloads: I,
    ) -> Result<usize, NativeQuicConnectionError>
    where
        I: IntoIterator<Item = Bytes>,
    {
        checkpoint(cx)?;
        let mut queued = 0usize;
        for payload in payloads {
            self.enqueue_datagram(cx, payload)?;
            queued = queued.saturating_add(1);
        }
        Ok(queued)
    }

    /// Number of queued outbound DATAGRAM payloads awaiting transmission.
    #[must_use]
    pub fn pending_outbound_datagram_count(&self) -> usize {
        self.outbound_datagrams.len()
    }

    /// Total DATAGRAM frames emitted onto the wire by [`Self::generate_frames`].
    #[must_use]
    pub fn datagrams_sent(&self) -> u64 {
        self.datagrams_sent
    }

    /// Total outbound DATAGRAM payloads dropped by the bounded send queue.
    #[must_use]
    pub fn datagrams_dropped_on_send(&self) -> u64 {
        self.datagrams_dropped_on_send
    }

    /// Drain queued control frames (and, in 1-RTT, queued DATAGRAM payloads)
    /// for packet assembly.
    pub fn generate_frames(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        max_frame_bytes: usize,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        self.generate_frames_inner(cx, space, max_frame_bytes, true)
    }

    /// Generate non-DATAGRAM frames only, leaving queued application DATAGRAMs
    /// buffered for a later data-plane send attempt.
    ///
    /// ATP's native lossy sender uses this when DATAGRAM congestion accounting
    /// says no more data packets fit, but ACK/control/STREAM frames still need
    /// to make forward progress.
    pub fn generate_non_datagram_frames(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        max_frame_bytes: usize,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        self.generate_frames_inner(cx, space, max_frame_bytes, false)
    }

    /// Drain only pending ACK frames without touching congestion-controlled
    /// control, STREAM, or DATAGRAM state.
    ///
    /// Protected UDP owners use this when the congestion window cannot admit a
    /// full MTU-sized packet. ACK-only packets are not congestion controlled,
    /// so they may still make recovery progress while every destructive data
    /// generator remains untouched until admission succeeds.
    pub(crate) fn generate_pending_ack_frames(
        &mut self,
        cx: &Cx,
        max_frame_bytes: usize,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let mut frames = Vec::new();
        let mut used = 0usize;
        let mut index = 0usize;

        while index < self.pending_control_frames.len() {
            let Some(frame) = self.pending_control_frames.get(index) else {
                break;
            };
            if !matches!(frame, QuicFrame::Ack { .. }) {
                index += 1;
                continue;
            }

            let mut encoded = BytesMut::new();
            frame.encode(&mut encoded)?;
            let frame_len = encoded.len();
            if used.saturating_add(frame_len) > max_frame_bytes {
                break;
            }

            let frame = self
                .pending_control_frames
                .remove(index)
                .expect("ACK index came from the same queue");
            used = used.saturating_add(frame_len);
            frames.push(frame);
            if used >= max_frame_bytes {
                break;
            }
        }

        Ok(frames)
    }

    /// Drain only pending ACK frames, exactly as the protected UDP driver's
    /// congestion-blocked admission branch does.
    ///
    /// This deterministic test seam lets socket-free harnesses mirror
    /// `NativeQuicUdpConnection::flush` (a cwnd-full sender still emits
    /// ACK-only packets) without duplicating the driver's ACK queue walk.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn generate_ack_only_frames_for_testing(
        &mut self,
        cx: &Cx,
        max_frame_bytes: usize,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        self.generate_pending_ack_frames(cx, max_frame_bytes)
    }

    /// Generate only STREAM frames for one application stream.
    ///
    /// This is used by ATP's paced source-stream bulk path, where coalescing
    /// unrelated control STREAM or flow-control frames into the same large packet
    /// would make the packet NewReno-governed instead of ATP-pacer-governed.
    pub fn generate_stream_frames_for(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        stream: StreamId,
        max_frame_bytes: usize,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        if space != PacketNumberSpace::ApplicationData {
            return Ok(Vec::new());
        }

        let mut frames = Vec::new();
        let mut used = 0usize;

        let mut deferred_control = VecDeque::new();
        while let Some(frame) = self.pending_control_frames.pop_front() {
            if frame_is_ack_eliciting(&frame) {
                deferred_control.push_back(frame);
                continue;
            }
            let mut encoded = BytesMut::new();
            frame.encode(&mut encoded)?;
            let frame_len = encoded.len();
            if !frames.is_empty() && used.saturating_add(frame_len) > max_frame_bytes {
                deferred_control.push_front(frame);
                break;
            }
            used = used.saturating_add(frame_len);
            frames.push(frame);
            if used >= max_frame_bytes {
                break;
            }
        }
        for frame in deferred_control.into_iter().rev() {
            self.pending_control_frames.push_front(frame);
        }

        while used.saturating_add(32) <= max_frame_bytes {
            let payload_budget = max_frame_bytes.saturating_sub(used).saturating_sub(32);
            let Some(payload) = self.streams.pop_stream_frame_for(stream, payload_budget) else {
                break;
            };
            let frame = QuicFrame::Stream {
                stream_id: VarInt::from_u64_unchecked(payload.stream_id.0),
                offset: (payload.offset != 0).then_some(VarInt::from_u64_unchecked(payload.offset)),
                data: payload.data.clone(),
                fin: payload.fin,
            };
            let mut encoded = BytesMut::new();
            frame.encode(&mut encoded)?;
            let frame_len = encoded.len();
            if !frames.is_empty() && used.saturating_add(frame_len) > max_frame_bytes {
                self.streams
                    .requeue_unemitted_stream_frame(payload)
                    .map_err(map_stream_table_error)?;
                break;
            }
            used = used.saturating_add(frame_len);
            if let QuicFrame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } = &frame
            {
                self.trace_stream_frame(
                    cx,
                    "send",
                    StreamId(stream_id.value()),
                    offset.map_or(0, VarInt::value),
                    data.len(),
                    *fin,
                    payload.retransmit,
                );
            }
            frames.push(frame);
            if used >= max_frame_bytes {
                break;
            }
        }

        Ok(frames)
    }

    fn generate_frames_inner(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        max_frame_bytes: usize,
        include_datagrams: bool,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let mut frames = Vec::new();
        let mut used = 0usize;

        let mut control_index = 0;
        while let Some(frame) = self.pending_control_frames.get(control_index) {
            if matches!(frame, QuicFrame::HandshakeDone)
                && space != PacketNumberSpace::ApplicationData
            {
                control_index += 1;
                continue;
            }
            let mut encoded = BytesMut::new();
            frame.encode(&mut encoded)?;
            let frame_len = encoded.len();
            if !frames.is_empty() && used.saturating_add(frame_len) > max_frame_bytes {
                break;
            }
            let frame = self
                .pending_control_frames
                .remove(control_index)
                .expect("control index came from the same queue");
            used = used.saturating_add(frame_len);
            frames.push(frame);
            if used >= max_frame_bytes {
                break;
            }
        }

        // STREAM and DATAGRAM frames are application (1-RTT) data only; never
        // emit them in the Initial/Handshake spaces. Drain into the same byte
        // budget, leaving the remainder queued so a small packet does not drop
        // application data on the floor.
        if space == PacketNumberSpace::ApplicationData {
            while used.saturating_add(32) <= max_frame_bytes {
                let payload_budget = max_frame_bytes.saturating_sub(used).saturating_sub(32);
                let Some(payload) = self.streams.pop_next_stream_frame(payload_budget) else {
                    break;
                };
                let frame = QuicFrame::Stream {
                    stream_id: VarInt::from_u64_unchecked(payload.stream_id.0),
                    offset: (payload.offset != 0)
                        .then_some(VarInt::from_u64_unchecked(payload.offset)),
                    data: payload.data.clone(),
                    fin: payload.fin,
                };
                let mut encoded = BytesMut::new();
                frame.encode(&mut encoded)?;
                let frame_len = encoded.len();
                if !frames.is_empty() && used.saturating_add(frame_len) > max_frame_bytes {
                    self.streams
                        .requeue_unemitted_stream_frame(payload)
                        .map_err(map_stream_table_error)?;
                    break;
                }
                used = used.saturating_add(frame_len);
                if let QuicFrame::Stream {
                    stream_id,
                    offset,
                    data,
                    fin,
                } = &frame
                {
                    self.trace_stream_frame(
                        cx,
                        "send",
                        StreamId(stream_id.value()),
                        offset.map_or(0, VarInt::value),
                        data.len(),
                        *fin,
                        payload.retransmit,
                    );
                }
                frames.push(frame);
                if used >= max_frame_bytes {
                    break;
                }
            }

            if include_datagrams {
                while let Some(payload) = self.outbound_datagrams.pop_front() {
                    let frame = QuicFrame::Datagram { data: payload };
                    let mut encoded = BytesMut::new();
                    frame.encode(&mut encoded)?;
                    let frame_len = encoded.len();
                    if frame_len > max_frame_bytes {
                        // A DATAGRAM that cannot fit even an otherwise empty
                        // packet must never be emitted: the packet assembler
                        // would refuse it and take the connection down (GH#66).
                        // Admission normally prevents this; drop and count it
                        // rather than trust that the budget never shrank.
                        self.datagrams_dropped_on_send =
                            self.datagrams_dropped_on_send.saturating_add(1);
                        quictrace!(
                            "event=datagram_send_drop reason=exceeds_packet_budget encoded_len={} max_frame_bytes={}",
                            frame_len,
                            max_frame_bytes
                        );
                        continue;
                    }
                    if !frames.is_empty() && used.saturating_add(frame_len) > max_frame_bytes {
                        let QuicFrame::Datagram { data } = frame else {
                            unreachable!("frame was just constructed as a DATAGRAM");
                        };
                        self.outbound_datagrams.push_front(data);
                        break;
                    }
                    used = used.saturating_add(frame_len);
                    self.datagrams_sent = self.datagrams_sent.saturating_add(1);
                    let size_s = frame_len.to_string();
                    let total_sent_s = self.datagrams_sent.to_string();
                    let queue_len_s = self.outbound_datagrams.len().to_string();
                    let pn_hint_s = self.next_packet_numbers[2].to_string();
                    quic_trace(
                        cx,
                        "ATP_QUIC_TRACE datagram_send_emit",
                        &[
                            ("reason", "emitted"),
                            ("encoded_len", size_s.as_str()),
                            ("queue_len", queue_len_s.as_str()),
                            ("total_sent", total_sent_s.as_str()),
                            ("pn", pn_hint_s.as_str()),
                        ],
                    );
                    quictrace!(
                        "event=datagram_send_emit reason=emitted encoded_len={} queue_len={} total_sent={} pn={}",
                        frame_len,
                        self.outbound_datagrams.len(),
                        self.datagrams_sent,
                        self.next_packet_numbers[2]
                    );
                    frames.push(frame);
                    if used >= max_frame_bytes {
                        break;
                    }
                }
            }
        }

        Ok(frames)
    }

    /// Encode frames into a buffer for packet assembly.
    pub fn encode_frames(
        frames: &[QuicFrame],
        buf: &mut BytesMut,
    ) -> Result<(), NativeQuicConnectionError> {
        for frame in frames {
            frame.encode(buf)?;
        }
        Ok(())
    }

    /// Decode frames from a packet payload.
    pub fn decode_frames(payload: &[u8]) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        let mut frames = Vec::new();
        let mut buf = payload;

        while !buf.is_empty() {
            if let Some(frame) = QuicFrame::decode(&mut buf)? {
                frames.push(frame);
            } else {
                break;
            }
        }

        Ok(frames)
    }

    /// Decode frames from a shared packet payload without copying frame data.
    ///
    /// STREAM/DATAGRAM frame payloads become zero-copy slices of `payload`
    /// (via the `BytesCursor` `copy_to_bytes` override), so the hot receive
    /// path pays no per-frame allocation or memcpy.
    ///
    /// A slice keeps the whole datagram allocated for as long as it is held,
    /// and a receive buffer can hold an out-of-order fragment indefinitely.
    /// So a STREAM, CRYPTO or DATAGRAM payload that uses less than a quarter
    /// of the datagram is copied instead: otherwise a peer could pin up to a
    /// 64 KiB datagram per one-byte fragment. Resident memory then stays
    /// within four times the bytes held, and a frame that fills its datagram
    /// (bulk transfer) stays zero-copy.
    pub fn decode_frames_bytes(
        payload: &Bytes,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        let mut frames = Vec::new();
        let mut cursor = payload.clone().reader();

        while cursor.has_remaining() {
            if let Some(frame) = QuicFrame::decode(&mut cursor)? {
                frames.push(unpin_small_payload(frame, payload.len()));
            } else {
                break;
            }
        }

        Ok(frames)
    }

    /// RFC 9000 19.12 and 19.13: name the limit that refused a write, the
    /// stream's (STREAM_DATA_BLOCKED) or else the connection's (DATA_BLOCKED).
    fn queue_blocked_frame(&mut self, id: StreamId, len: u64) {
        if self.streams.stream_send_credit_remaining(id) < len {
            self.queue_stream_data_blocked(id);
        } else if self.streams.connection_send_remaining() < len {
            let limit = self.streams.connection_send_limit();
            self.pending_control_frames
                .retain(|frame| !matches!(frame, QuicFrame::DataBlocked { .. }));
            self.pending_control_frames
                .push_back(QuicFrame::DataBlocked {
                    maximum_data: VarInt::from_u64_unchecked(limit),
                });
        }
    }

    /// Queue at most one STREAM_DATA_BLOCKED per stream, carrying the current
    /// limit: a writer retrying while blocked adds no frames.
    fn queue_stream_data_blocked(&mut self, id: StreamId) {
        let limit = self.streams.stream_send_limit(id).unwrap_or(0);
        self.pending_control_frames.retain(|frame| {
            !matches!(
                frame,
                QuicFrame::StreamDataBlocked { stream_id, .. } if stream_id.value() == id.0
            )
        });
        self.pending_control_frames
            .push_back(QuicFrame::StreamDataBlocked {
                stream_id: VarInt::from_u64_unchecked(id.0),
                maximum_stream_data: VarInt::from_u64_unchecked(limit),
            });
    }

    fn trace_stream_frame(
        &self,
        cx: &Cx,
        direction: &str,
        id: StreamId,
        offset: u64,
        len: usize,
        fin: bool,
        retransmit: bool,
    ) {
        // Gate the field formatting itself: this runs per received STREAM
        // frame, so the string building must not happen when tracing is off.
        if cx.trace_buffer().is_some() {
            let id_s = id.0.to_string();
            let offset_s = offset.to_string();
            let len_s = len.to_string();
            let fin_s = fin.to_string();
            let retransmit_s = retransmit.to_string();
            cx.trace_with_fields(
                "ATP_QUIC_TRACE stream_frame",
                &[
                    ("direction", direction),
                    ("stream_id", id_s.as_str()),
                    ("offset", offset_s.as_str()),
                    ("len", len_s.as_str()),
                    ("fin", fin_s.as_str()),
                    ("retransmit", retransmit_s.as_str()),
                ],
            );
        }
        quictrace!(
            "event=stream_frame direction={} stream_id={} offset={} len={} fin={} retransmit={}",
            direction,
            id.0,
            offset,
            len,
            fin,
            retransmit
        );
    }

    /// Record receipt of an ack-eliciting packet whose frames were consumed
    /// outside [`Self::process_packet_frames`] (for example when a receiver
    /// sheds DATAGRAM frames under queue pressure). The packet was
    /// authenticated and received, so the peer's loss detector must see it
    /// acknowledged even though its payload was intentionally dropped.
    pub fn acknowledge_received_packet(&mut self, space: PacketNumberSpace, packet_number: u64) {
        self.queue_ack_frame(space, packet_number);
    }

    /// Record a received non-ack-eliciting packet in the ACK ranges without
    /// eliciting an ACK of its own (RFC 9000 §13.2.1 forbids answering it with
    /// a packet). Keeping ACK-only packet numbers in the ranges means the peer
    /// sees contiguous acknowledgements instead of a gap at every ACK-only
    /// packet it sent (GH#71); the next ACK elicited by an ack-eliciting
    /// packet carries this number along.
    fn observe_non_ack_eliciting_packet(&mut self, space: PacketNumberSpace, packet_number: u64) {
        self.received_ack_trackers[packet_number_space_idx(space)].observe(packet_number);
    }

    fn queue_ack_frame(&mut self, space: PacketNumberSpace, packet_number: u64) {
        let tracker = &mut self.received_ack_trackers[packet_number_space_idx(space)];
        tracker.observe(packet_number);
        let Some(frame) = tracker.ack_frame() else {
            return;
        };
        self.pending_control_frames
            .retain(|frame| !matches!(frame, QuicFrame::Ack { .. }));
        self.pending_control_frames.push_back(frame);
        if space == PacketNumberSpace::ApplicationData {
            // Re-attach current bounded-window advertisements to every outgoing
            // ACK: MAX_STREAM_DATA is an idempotent monotonic maximum, so this
            // costs a few bytes per ACK packet and guarantees a lost window
            // update can never wedge a credit-blocked sender. (Advertisements
            // advance only on application reads — consumption-clocked, SETTLED
            // after four attempts; see the MATRIX-227 history on
            // advance_bounded_recv_windows before re-trying receipt-clocking.)
            // One pass over the queue for all of them: replacing each stream's
            // frame separately rescanned the queue once per stream, S^2 work
            // on every packet with S bounded-window streams.
            let advertisements = self.streams.bounded_recv_window_advertisements();
            if !advertisements.is_empty() {
                let limits: BTreeMap<u64, u64> = advertisements
                    .iter()
                    .map(|&(stream, limit)| (stream.0, limit))
                    .collect();
                self.pending_control_frames.retain(|frame| {
                    !matches!(
                        frame,
                        QuicFrame::MaxStreamData {
                            stream_id,
                            maximum_stream_data,
                        } if limits
                            .get(&stream_id.value())
                            .is_some_and(|&limit| maximum_stream_data.value() <= limit)
                    )
                });
                for (stream, limit) in advertisements {
                    self.pending_control_frames
                        .push_back(QuicFrame::MaxStreamData {
                            stream_id: VarInt(stream.0),
                            maximum_stream_data: VarInt(limit),
                        });
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ReceivedPacketTracker {
    ranges: Vec<AckRange>,
}

impl ReceivedPacketTracker {
    fn observe(&mut self, packet_number: u64) {
        // In-order fast path: extending (or re-observing) the newest range is
        // the common case on a healthy link.
        if let Some(first) = self.ranges.first_mut() {
            if packet_number >= first.smallest && packet_number <= first.largest {
                return;
            }
            if packet_number == first.largest.saturating_add(1) {
                first.largest = packet_number;
                return;
            }
        }

        // Ranges are newest-first. Binary search by their largest packet
        // number, then inspect only the two neighboring ranges for duplicate,
        // extension, or bridge cases. Vec insertion can shift retained ranges,
        // but the explicit cap keeps that work bounded and avoids the old
        // full sort plus merge-rebuild on every gap packet.
        let insert_at = self
            .ranges
            .partition_point(|range| range.largest > packet_number);

        if insert_at > 0 {
            let newer_idx = insert_at - 1;
            let newer = self.ranges[newer_idx];
            if packet_number >= newer.smallest {
                return;
            }
            if packet_number.saturating_add(1) == newer.smallest {
                self.ranges[newer_idx].smallest = packet_number;
                if insert_at < self.ranges.len()
                    && self.ranges[insert_at].largest.saturating_add(1) >= packet_number
                {
                    let older = self.ranges.remove(insert_at);
                    self.ranges[newer_idx].smallest =
                        self.ranges[newer_idx].smallest.min(older.smallest);
                }
                return;
            }
        }

        if let Some(older) = self.ranges.get_mut(insert_at) {
            if packet_number == older.largest {
                return;
            }
            if older.largest.saturating_add(1) == packet_number {
                older.largest = packet_number;
                return;
            }
        }

        // A packet older than the retained window cannot affect a future ACK
        // frame. Avoid inserting it only to truncate it immediately.
        if insert_at == self.ranges.len() && self.ranges.len() == MAX_TRACKED_ACK_RANGES {
            return;
        }

        self.ranges.insert(
            insert_at,
            AckRange {
                largest: packet_number,
                smallest: packet_number,
            },
        );
        self.ranges.truncate(MAX_TRACKED_ACK_RANGES);
    }

    fn ack_frame(&self) -> Option<QuicFrame> {
        let first = *self.ranges.first()?;
        let mut previous_smallest = first.smallest;
        let mut ack_ranges = Vec::new();

        // Bound the encoded SACK ranges to the newest window. Under sustained
        // loss the tracker can hold hundreds of ranges, and an unbounded ACK
        // frame grows past one MTU — the resulting IP-fragmented feedback
        // packet then dies at the per-fragment loss rate exactly when feedback
        // matters most (br-asupersync-u6m3dy). Omitted older ranges are legal
        // per RFC 9000 §13.2.3: the peer keeps those packets in flight and
        // recovers them through later ACKs or its own loss/PTO retransmit.
        for range in self.ranges.iter().skip(1).take(MAX_ACK_FRAME_RANGES - 1) {
            let gap = previous_smallest
                .saturating_sub(range.largest)
                .saturating_sub(2);
            ack_ranges.push(crate::net::atp::protocol::quic_frames::AckRange {
                gap: VarInt::from_u64_unchecked(gap),
                ack_range_length: VarInt::from_u64_unchecked(
                    range.largest.saturating_sub(range.smallest),
                ),
            });
            previous_smallest = range.smallest;
        }

        Some(QuicFrame::Ack {
            largest_acknowledged: VarInt::from_u64_unchecked(first.largest),
            ack_delay: VarInt::from_u64_unchecked(0),
            ack_range_count: VarInt::from_u64_unchecked(ack_ranges.len() as u64),
            first_ack_range: VarInt::from_u64_unchecked(
                first.largest.saturating_sub(first.smallest),
            ),
            ack_ranges,
            ecn_counts: None,
        })
    }
}

fn packet_number_space_idx(space: PacketNumberSpace) -> usize {
    match space {
        PacketNumberSpace::Initial => 0,
        PacketNumberSpace::Handshake => 1,
        PacketNumberSpace::ApplicationData => 2,
    }
}

fn retransmittable_frame_refs(frames: &[QuicFrame]) -> Vec<RetransmittableFrameRef> {
    frames
        .iter()
        .filter_map(RetransmittableFrameRef::from_frame)
        .collect()
}

fn frame_is_ack_eliciting(frame: &QuicFrame) -> bool {
    // RFC 9000 §13.2.1: all frames other than ACK, PADDING, and CONNECTION_CLOSE
    // are ack-eliciting. CONNECTION_CLOSE must not be treated as ack-eliciting,
    // otherwise a packet carrying only CONNECTION_CLOSE would queue an ACK while
    // the connection transitions to draining/closing.
    !matches!(
        frame,
        QuicFrame::Padding { .. } | QuicFrame::Ack { .. } | QuicFrame::ConnectionClose { .. }
    )
}

fn ack_frame_ranges(
    largest_acknowledged: u64,
    first_ack_range: u64,
    ack_ranges: &[crate::net::atp::protocol::quic_frames::AckRange],
) -> Result<Vec<AckRange>, NativeQuicConnectionError> {
    let first_smallest = largest_acknowledged.checked_sub(first_ack_range).ok_or(
        NativeQuicConnectionError::InvalidState("ACK first range exceeds largest packet number"),
    )?;
    let mut ranges = vec![AckRange::new(largest_acknowledged, first_smallest).ok_or(
        NativeQuicConnectionError::InvalidState("invalid ACK first range"),
    )?];
    let mut previous_smallest = first_smallest;

    for range in ack_ranges {
        let gap = range.gap.value();
        let next_largest = previous_smallest.checked_sub(gap.saturating_add(2)).ok_or(
            NativeQuicConnectionError::InvalidState(
                "ACK range gap underflowed packet number space",
            ),
        )?;
        let next_smallest = next_largest
            .checked_sub(range.ack_range_length.value())
            .ok_or(NativeQuicConnectionError::InvalidState(
                "ACK range length exceeds largest packet number",
            ))?;
        ranges.push(
            AckRange::new(next_largest, next_smallest)
                .ok_or(NativeQuicConnectionError::InvalidState("invalid ACK range"))?,
        );
        previous_smallest = next_smallest;
    }

    Ok(ranges)
}

#[cfg(test)]
#[path = "connection_inline_tests.rs"]
mod tests;
