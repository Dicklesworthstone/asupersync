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
use crate::net::atp::protocol::quic_frames::{QuicFrame, QuicFrameError};
use crate::net::atp::protocol::varint::{VARINT_MAX, VarInt};
use crate::net::quic_core::TransportParameters;
use std::collections::VecDeque;
use std::fmt;
use std::task::{Context as TaskContext, Poll, Waker};

use super::streams::{
    FlowControlError, QuicStreamError, QuicStreamIo, StreamId, StreamRole, StreamTable,
    StreamTableError,
};
use super::tls::{CryptoLevel, KeyUpdateEvent, QuicTlsError, QuicTlsMachine};
#[cfg(feature = "tls")]
use super::tls::{QuicServerIdentityVerification, QuicServerIdentityVerifier};
use super::transport::{
    AckEvent, AckRange, PacketNumberSpace, QuicConnectionState, QuicTransportMachine,
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
    received_ack_trackers: [ReceivedPacketTracker; 3],
    migration_disabled: bool,
    active_path_id: u64,
    migration_events: u64,
    drain_timeout_micros: u64,
    peer_address_validated: bool,
    /// Whether a verifying TLS handshake has validated the server's certificate
    /// chain against configured roots. Defaults to `false`; a client connection
    /// fails closed at handshake confirmation unless this is set, so an
    /// unauthenticated server identity can never be accepted (br-asupersync-7pwwwe).
    server_identity_verified: bool,
    anti_amplification_bytes_received: u64,
    anti_amplification_bytes_sent: u64,
    pending_control_frames: VecDeque<QuicFrame>,
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

/// Maximum number of outbound DATAGRAM payloads queued before `send_datagram`
/// drops the oldest queued payload to keep the unreliable send path bounded.
const MAX_OUTBOUND_DATAGRAMS: usize = 256;

/// Largest DATAGRAM *frame* (RFC 9221 `max_datagram_frame_size` semantics) this
/// endpoint will emit; a `send_datagram` whose encoded frame would exceed this
/// is rejected so a single datagram always fits one 1-RTT packet.
const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;

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
            received_ack_trackers: [
                ReceivedPacketTracker::default(),
                ReceivedPacketTracker::default(),
                ReceivedPacketTracker::default(),
            ],
            migration_disabled: false,
            active_path_id: 0,
            migration_events: 0,
            drain_timeout_micros: config.drain_timeout_micros,
            peer_address_validated: config.role == StreamRole::Client,
            server_identity_verified: false,
            anti_amplification_bytes_received: 0,
            anti_amplification_bytes_sent: 0,
            pending_control_frames: VecDeque::new(),
            inbound_datagrams: VecDeque::new(),
            datagrams_received: 0,
            datagrams_dropped_on_receive: 0,
            inbound_datagram_waker: None,
            outbound_datagrams: VecDeque::new(),
            datagrams_sent: 0,
            datagrams_dropped_on_send: 0,
            max_datagram_frame_size: config.max_datagram_frame_size,
        }
    }

    /// Current transport state.
    #[must_use]
    pub fn state(&self) -> QuicConnectionState {
        self.transport.state()
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

    /// Access stream table snapshot.
    #[must_use]
    pub fn streams(&self) -> &StreamTable {
        &self.streams
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

    /// Confirm handshake and transition transport to `Established`.
    pub fn on_handshake_confirmed(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
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
        self.tls.on_handshake_confirmed()?;
        self.peer_address_validated = true;
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
    /// streams; defaults to [`DEFAULT_MAX_REMOTE_STREAMS`] per direction.
    pub fn set_remote_stream_limits(&mut self, max_remote_bidi: u64, max_remote_uni: u64) {
        let max_remote_bidi = max_remote_bidi.min(VARINT_MAX);
        let max_remote_uni = max_remote_uni.min(VARINT_MAX);
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
        let result = self.streams.write_stream_bytes(id, data, fin);
        if let Err(StreamTableError::Stream(QuicStreamError::Flow(FlowControlError::Exhausted {
            ..
        }))) = &result
        {
            self.queue_stream_data_blocked(id);
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
        self.streams
            .on_stop_sending(id, error_code)
            .map_err(map_stream_table_error)?;
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
        self.streams
            .stop_receiving(id, error_code)
            .map_err(map_stream_table_error)?;
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
        self.streams
            .reset_stream_send(id, error_code, final_size)
            .map_err(map_stream_table_error)?;
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
        self.transport.start_draining_with_code(
            now_micros,
            self.drain_timeout_micros,
            app_error_code,
        )?;
        Ok(())
    }

    /// Immediate terminal close.
    pub fn close_immediately(
        &mut self,
        cx: &Cx,
        app_error_code: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
        self.transport.close_immediately(app_error_code);
        Ok(())
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
        checkpoint(cx)?;
        self.migration_disabled = params.disable_active_migration;
        self.max_datagram_frame_size = match params.max_datagram_frame_size {
            Some(max) => usize::try_from(max).map_err(|_| {
                NativeQuicConnectionError::InvalidState(
                    "peer max_datagram_frame_size exceeds platform usize",
                )
            })?,
            None => 0,
        };
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

    /// Track a sent packet and return assigned packet number.
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
        Ok(self
            .transport
            .on_ack_ranges(space, ack_ranges, ack_delay_micros, now_micros))
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
        Ok(self.transport.on_loss_timeout_expired(space, now_micros))
    }

    /// Record a PTO firing and queue an ack-eliciting probe frame.
    pub fn on_probe_timeout(&mut self, cx: &Cx) -> Result<(), NativeQuicConnectionError> {
        self.on_pto_expired(cx)?;
        self.pending_control_frames.push_back(QuicFrame::Ping);
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

    /// Commit local key update once keys are installed.
    pub fn commit_local_key_update(
        &mut self,
        cx: &Cx,
    ) -> Result<KeyUpdateEvent, NativeQuicConnectionError> {
        checkpoint(cx)?;
        let evt = self.tls.commit_local_key_update()?;
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
        let idx = match space {
            PacketNumberSpace::Initial => 0,
            PacketNumberSpace::Handshake => 1,
            PacketNumberSpace::ApplicationData => 2,
        };
        let out = self.next_packet_numbers[idx];
        // RFC 9000 §17.1: packet numbers are integers in [0, 2^62-1] inclusive.
        // The exhaustion guard rejects when `out` is already past the last
        // valid packet number, not when it equals the last valid one.
        if out > (1u64 << 62) - 1 {
            return Err(NativeQuicConnectionError::InvalidState(
                "packet number limit reached; connection must be closed",
            ));
        }
        self.next_packet_numbers[idx] = out + 1;
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
        let frames = Self::decode_frames(payload)?;
        self.process_packet_frames(cx, space, packet_number, &frames, now_micros)
    }

    /// Process the already-decoded frames of one packet and update connection
    /// state.
    ///
    /// This is the single-decode hot path: callers that already decoded the
    /// packet's frames (for example to count DATAGRAM slots before admission)
    /// pass them here directly instead of paying a second decode + payload
    /// copy via [`Self::process_packet_payload`].
    pub fn process_packet_frames(
        &mut self,
        cx: &Cx,
        space: PacketNumberSpace,
        packet_number: u64,
        frames: &[QuicFrame],
        now_micros: u64,
    ) -> Result<(), NativeQuicConnectionError> {
        checkpoint(cx)?;
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
                self.process_frame_at(cx, &frames[index], space, now_micros)?;
                index = index.saturating_add(1);
            }
        }

        if ack_eliciting {
            self.queue_ack_frame(space, packet_number);
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
                let _ = self.on_ack_ranges(cx, space, &ranges, ack_delay.value(), now_micros)?;
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
                self.on_stop_sending(cx, StreamId(stream_id.value()), error_code.value())?;
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
                self.streams
                    .increase_stream_send_limit(
                        StreamId(stream_id.value()),
                        maximum_stream_data.value(),
                    )
                    .map_err(map_stream_table_error)?;
                Ok(())
            }
            QuicFrame::PathChallenge { data } => {
                self.pending_control_frames
                    .push_back(QuicFrame::PathResponse { data: *data });
                Ok(())
            }
            QuicFrame::PathResponse { .. } => {
                self.peer_address_validated = true;
                Ok(())
            }
            QuicFrame::ConnectionClose { error_code, .. } => {
                self.begin_close(cx, now_micros, error_code.value())?;
                Ok(())
            }
            QuicFrame::HandshakeDone => {
                if self.role == StreamRole::Client && self.tls.level() == CryptoLevel::OneRtt {
                    self.on_handshake_confirmed(cx)?;
                }
                Ok(())
            }
            QuicFrame::Datagram { .. } => {
                self.process_datagram_frame_run(cx, std::slice::from_ref(frame), space)?;
                Ok(())
            }
            QuicFrame::MaxStreams { .. }
            | QuicFrame::DataBlocked { .. }
            | QuicFrame::StreamDataBlocked { .. }
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
        // peer-advertised max_datagram_frame_size. Bound the encoded frame so a
        // single datagram always fits one 1-RTT packet.
        let payload_len = payload.len();
        let frame = QuicFrame::Datagram {
            data: payload.clone(),
        };
        let mut probe = BytesMut::new();
        frame.encode(&mut probe)?;
        let max_frame_size = self.max_datagram_frame_size;
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

        while let Some(frame) = self.pending_control_frames.pop_front() {
            let mut encoded = BytesMut::new();
            frame.encode(&mut encoded)?;
            let frame_len = encoded.len();
            if !frames.is_empty() && used.saturating_add(frame_len) > max_frame_bytes {
                self.pending_control_frames.push_front(frame);
                break;
            }
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
    pub fn decode_frames_bytes(
        payload: &Bytes,
    ) -> Result<Vec<QuicFrame>, NativeQuicConnectionError> {
        let mut frames = Vec::new();
        let mut cursor = payload.clone().reader();

        while cursor.has_remaining() {
            if let Some(frame) = QuicFrame::decode(&mut cursor)? {
                frames.push(frame);
            } else {
                break;
            }
        }

        Ok(frames)
    }

    fn queue_stream_data_blocked(&mut self, id: StreamId) {
        let limit = self.streams.stream_send_limit(id).unwrap_or(0);
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
            // advance only on application reads — consumption-clocked on
            // purpose; see the MATRIX-224 congestion-collapse refutation on
            // advance_bounded_recv_windows before "fixing" hole stalls here.)
            for (stream, limit) in self.streams.bounded_recv_window_advertisements() {
                self.queue_max_stream_data_frame(stream, limit);
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
        // In-order fast path: extending (or re-observing) the newest range
        // avoids the per-packet sort + merged-Vec rebuild below, which is the
        // common case on a healthy link.
        if let Some(first) = self.ranges.first_mut() {
            if packet_number == first.largest.saturating_add(1) {
                first.largest = packet_number;
                return;
            }
            if packet_number >= first.smallest && packet_number <= first.largest {
                return;
            }
        }
        self.ranges.push(AckRange {
            largest: packet_number,
            smallest: packet_number,
        });
        self.ranges.sort_by(|lhs, rhs| {
            rhs.largest
                .cmp(&lhs.largest)
                .then_with(|| rhs.smallest.cmp(&lhs.smallest))
        });

        let mut merged: Vec<AckRange> = Vec::with_capacity(self.ranges.len());
        for range in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && range.largest.saturating_add(1) >= last.smallest
            {
                last.smallest = last.smallest.min(range.smallest);
                continue;
            }
            merged.push(range);
        }
        self.ranges = merged;
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(feature = "tls")]
    use crate::tls::{Certificate, CertificateChain, RootCertStore};
    #[cfg(feature = "tls")]
    use std::time::Duration;

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    #[cfg(feature = "tls")]
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.crt");

    #[cfg(feature = "tls")]
    fn fixed_cert_validity_time() -> rustls_pki_types::UnixTime {
        rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_780_000_000))
    }

    #[cfg(feature = "tls")]
    fn trusted_identity_material() -> (QuicServerIdentityVerifier, CertificateChain) {
        let certs = Certificate::from_pem(TEST_CERT_PEM).expect("fixture cert parses");
        let mut roots = RootCertStore::empty();
        roots
            .add(&certs[0])
            .expect("fixture cert can be a test trust anchor");
        let verifier = QuicServerIdentityVerifier::from_root_store(roots).expect("build verifier");
        (verifier, CertificateChain::from(certs))
    }

    fn established_conn() -> NativeQuicConnection {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        // A real verifying handshake would validate the server cert here; the
        // helper records it so the fail-closed gate (br-7pwwwe) lets the
        // state-machine tests reach the confirmed state.
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx).expect("confirmed");
        conn
    }

    fn established_server_conn() -> NativeQuicConnection {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.on_handshake_confirmed(&cx).expect("confirmed");
        conn
    }

    #[test]
    fn client_fails_closed_on_confirm_without_verified_server_identity() {
        // br-asupersync-7pwwwe: the native QUIC TLS path performs no certificate
        // exchange/verification, so a client that never recorded a verified
        // server identity must fail closed at handshake confirmation instead of
        // accepting an unauthenticated server (MITM exposure).
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        let err = conn
            .on_handshake_confirmed(&cx)
            .expect_err("client confirm must fail closed without a verified server identity");
        assert!(
            matches!(
                err,
                NativeQuicConnectionError::Tls(QuicTlsError::ServerCertificateUnverified)
            ),
            "expected ServerCertificateUnverified, got {err:?}"
        );
    }

    #[test]
    fn client_confirms_after_recording_verified_server_identity() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx)
            .expect("client confirms once a verifying handshake has recorded server identity");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn client_verifies_server_identity_before_confirming_handshake() {
        let cx = test_cx();
        let (verifier, chain) = trusted_identity_material();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");

        let receipt = conn
            .verify_server_identity_and_confirm_handshake(
                &cx,
                &verifier,
                "localhost",
                chain,
                fixed_cert_validity_time(),
            )
            .expect("valid server identity confirms handshake");

        assert_eq!(receipt.chain_len, 1);
        assert_eq!(receipt.root_count, 1);
        assert_eq!(conn.state(), QuicConnectionState::Established);
        assert!(conn.can_send_1rtt());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn client_rejects_bad_server_identity_without_confirming_handshake() {
        let cx = test_cx();
        let (verifier, chain) = trusted_identity_material();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");

        let err = conn
            .verify_server_identity_and_confirm_handshake(
                &cx,
                &verifier,
                "not-localhost.example",
                chain,
                fixed_cert_validity_time(),
            )
            .expect_err("bad hostname must fail closed");

        assert!(matches!(
            err,
            NativeQuicConnectionError::Tls(QuicTlsError::CryptoProviderFailure { .. })
        ));
        assert_eq!(conn.state(), QuicConnectionState::Handshaking);
        assert!(!conn.can_send_1rtt());
        let confirm_err = conn
            .on_handshake_confirmed(&cx)
            .expect_err("failed verification must not set identity gate");
        assert!(matches!(
            confirm_err,
            NativeQuicConnectionError::Tls(QuicTlsError::ServerCertificateUnverified)
        ));
    }

    #[test]
    fn cannot_open_data_stream_before_1rtt_enabled() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
        );
    }

    #[test]
    fn cannot_accept_remote_stream_before_established() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let remote = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        let err = conn
            .accept_remote_stream(&cx, remote)
            .expect_err("must fail before established");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "new application streams require established state"
            )
        );
    }

    #[test]
    fn established_connection_can_open_and_write_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 12).expect("write");
        conn.receive_stream(&cx, stream, 4).expect("receive");
        conn.set_stream_final_size(&cx, stream, 3)
            .expect_err("final size must not regress");
    }

    #[test]
    fn packet_numbers_increase_per_space() {
        let cx = test_cx();
        let mut conn = established_conn();
        let pn0 = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_000)
            .expect("pn0");
        let pn1 = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_100)
            .expect("pn1");
        let pn2 = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_200,
            )
            .expect("pn2");
        assert_eq!(pn0, 0);
        assert_eq!(pn1, 1);
        assert_eq!(pn2, 0);
    }

    #[test]
    fn application_data_packets_require_established_1rtt() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect_err("appdata before 1-rtt must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "application-data packets require established 1-RTT state"
            )
        );
    }

    #[test]
    fn queue_ping_emits_ack_eliciting_ping_without_stream_payload() {
        let cx = test_cx();
        let mut conn = established_conn();

        conn.queue_ping(&cx).expect("queue ping");
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("queued ping should generate");

        assert_eq!(frames, vec![QuicFrame::Ping]);
    }

    #[test]
    fn packet_send_is_rejected_after_close() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0x77).expect("close");
        let err = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_000)
            .expect_err("send after close must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "packet send requires non-draining, non-closed connection state"
            )
        );
    }

    #[test]
    fn packet_send_is_rejected_after_begin_close_enters_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0x77).expect("begin close");

        let err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                50_100,
            )
            .expect_err("send after begin_close must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "packet send requires non-draining, non-closed connection state"
            )
        );
    }

    #[test]
    fn bounded_recv_window_advertises_via_reads_and_reattaches_on_acks() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        let advertised = conn
            .configure_stream_recv_window(&cx, stream, 100)
            .expect("configure window");
        assert_eq!(advertised, 100);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("initial advertisement");
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(100),
        }));

        // Draining past a quarter window queues a fresh advertisement.
        conn.receive_stream_bytes(&cx, stream, 0, Bytes::from_static(&[7u8; 40]), false)
            .expect("inbound bytes");
        assert_eq!(
            conn.read_stream_bytes(&cx, stream, 40)
                .expect("drain")
                .len(),
            40
        );
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("advertisement after drain");
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(140),
        }));

        // Every ApplicationData ACK re-attaches the current advertisement, so
        // a lost MAX_STREAM_DATA can never wedge a credit-blocked sender.
        conn.acknowledge_received_packet(PacketNumberSpace::ApplicationData, 9);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 256)
            .expect("ack with advertisement");
        assert!(frames.iter().any(|f| matches!(f, QuicFrame::Ack { .. })));
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(140),
        }));
    }

    #[test]
    fn ack_path_repeats_consumption_clocked_window_past_head_of_line_hole() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.configure_stream_recv_window(&cx, stream, 100)
            .expect("configure window");
        // A segment lands beyond a head-of-line hole (0..10 missing): the
        // application cannot read, and the ACK-attached advertisement must
        // REPEAT the consumption-clocked limit (100), not chase the received
        // offset — the credit stall is this path's congestion control (see
        // the MATRIX-224 refutation on advance_bounded_recv_windows).
        conn.receive_stream_bytes(&cx, stream, 10, Bytes::from_static(&[7u8; 40]), false)
            .expect("inbound bytes past hole");
        assert!(
            conn.read_stream_bytes(&cx, stream, 100)
                .expect("read")
                .is_empty()
        );
        conn.acknowledge_received_packet(PacketNumberSpace::ApplicationData, 3);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 256)
            .expect("ack with advertisement");
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(100),
        }));
        assert!(!frames.iter().any(|frame| matches!(
            frame,
            QuicFrame::MaxStreamData { stream_id, maximum_stream_data }
                if stream_id.value() == stream.0 && maximum_stream_data.value() > 100
        )));
    }

    #[test]
    fn stop_sending_is_enforced_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_uni(&cx).expect("open");
        conn.write_stream(&cx, stream, 4).expect("write");
        conn.on_stop_sending(&cx, stream, 77).expect("stop_sending");
        let err = conn.write_stream(&cx, stream, 1).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::SendStopped { code: 77 })
        );
    }

    #[test]
    fn reset_stream_frame_aborts_receive_side_and_preserves_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.receive_stream_bytes(&cx, stream, 0, Bytes::from_static(b"abc"), false)
            .expect("buffer inbound bytes");

        conn.process_frame(
            &cx,
            &QuicFrame::ResetStream {
                stream_id: VarInt::from_u64_unchecked(stream.0),
                error_code: VarInt::from_u64_unchecked(0x44),
                final_size: VarInt::from_u64_unchecked(8),
            },
            PacketNumberSpace::ApplicationData,
        )
        .expect("reset stream");

        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.recv_reset, Some((0x44, 8)));
        assert_eq!(s.final_size, Some(8));

        let err = conn
            .receive_stream_bytes(&cx, stream, 3, Bytes::from_static(b"d"), false)
            .expect_err("STREAM frames after RESET_STREAM are rejected");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::ReceiveReset {
                code: 0x44,
                final_size: 8
            })
        );

        let err = conn
            .read_stream_bytes(&cx, stream, 8)
            .expect_err("buffered data is discarded after RESET_STREAM");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::ReceiveReset {
                code: 0x44,
                final_size: 8
            })
        );
    }

    #[test]
    fn out_of_order_receive_segment_reassembles_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.receive_stream_segment(&cx, stream, 5, 5, false)
            .expect("out-of-order");
        assert_eq!(
            conn.streams().stream(stream).expect("stream").recv_offset,
            0
        );
        conn.receive_stream_segment(&cx, stream, 0, 5, false)
            .expect("fill gap");
        assert_eq!(
            conn.streams().stream(stream).expect("stream").recv_offset,
            10
        );
    }

    #[test]
    fn stream_payload_frames_round_trip_via_connection_api() {
        let cx = test_cx();
        let mut tx = established_conn();
        let stream = tx.open_local_bidi(&cx).expect("open");
        let payload = Bytes::from_static(b"manifest-control-stream");
        tx.write_stream_bytes(&cx, stream, payload.clone(), true)
            .expect("queue bytes");

        let first = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("first frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("first stream frame");
        let lost = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("lost frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("lost stream frame");
        let lost_offset = match &lost {
            QuicFrame::Stream { offset, .. } => offset.map_or(0, VarInt::value),
            _ => unreachable!("lost is a STREAM frame"),
        };
        let last = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("last frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("last stream frame");
        tx.requeue_sent_stream_frame(&cx, stream, lost_offset)
            .expect("requeue lost frame");
        let retransmit = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("retransmit frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("retransmitted stream frame");

        let mut rx = established_server_conn();
        for frame in [last, retransmit, first] {
            rx.process_frame(&cx, &frame, PacketNumberSpace::ApplicationData)
                .expect("process stream frame");
        }
        let mut out = Vec::new();
        while !rx.is_stream_read_eof(stream).expect("eof check") {
            let chunk = rx.read_stream_bytes(&cx, stream, 8).expect("read bytes");
            assert!(!chunk.is_empty(), "stream must not stall after retransmit");
            out.extend_from_slice(&chunk);
        }
        assert_eq!(out, payload.as_ref());
    }

    #[test]
    fn pending_stream_frames_track_partial_packetization() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream_bytes(
            &cx,
            stream,
            Bytes::from_static(b"source-stream-payload"),
            true,
        )
        .expect("queue source stream bytes");

        assert!(
            conn.has_pending_stream_frames(),
            "queued source bytes must be visible to drain loops"
        );
        assert!(
            conn.has_pending_stream_frames_for(stream),
            "queued source bytes must be visible by stream id"
        );
        let first = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("first packet")
            .into_iter()
            .any(|frame| matches!(frame, QuicFrame::Stream { .. }));
        assert!(first, "first packet should carry a STREAM frame");
        assert!(
            conn.has_pending_stream_frames(),
            "partial packetization must leave the stream pending"
        );
        let second = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("final packet")
            .into_iter()
            .any(|frame| matches!(frame, QuicFrame::Stream { .. }));
        assert!(second, "final packet should carry the STREAM tail");
        assert!(
            !conn.has_pending_stream_frames(),
            "source-stream drain may finish only after queued STREAM frames clear"
        );
        assert!(
            !conn.has_pending_stream_frames_for(stream),
            "stream-id predicate must clear with the stream queue"
        );
    }

    #[test]
    fn generate_stream_frames_for_drains_only_requested_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let source = conn.open_local_bidi(&cx).expect("source stream");
        let control = conn.open_local_bidi(&cx).expect("control stream");
        conn.pending_control_frames.push_back(QuicFrame::Ack {
            largest_acknowledged: VarInt::from_u64_unchecked(7),
            ack_delay: VarInt::from_u64_unchecked(0),
            ack_range_count: VarInt::from_u64_unchecked(0),
            first_ack_range: VarInt::from_u64_unchecked(0),
            ack_ranges: Vec::new(),
            ecn_counts: None,
        });
        conn.pending_control_frames.push_back(QuicFrame::MaxData {
            maximum_data: VarInt::from_u64_unchecked(4096),
        });
        conn.write_stream_bytes(&cx, control, Bytes::from_static(b"control"), true)
            .expect("queue control stream");
        conn.write_stream_bytes(&cx, source, Bytes::from_static(b"source"), true)
            .expect("queue source stream");

        let frames = conn
            .generate_stream_frames_for(&cx, PacketNumberSpace::ApplicationData, source, 128)
            .expect("source-only packet");
        assert!(
            frames.iter().all(|frame| matches!(
                frame,
                QuicFrame::Stream { stream_id, .. } if stream_id.value() == source.0
            ) || matches!(
                frame,
                QuicFrame::Ack { .. } | QuicFrame::Padding { .. }
            )),
            "source-only generator must not coalesce other stream or ack-eliciting control frames"
        );
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::Ack { .. })),
            "source-only generator should still coalesce non-ack-eliciting ACK frames"
        );
        assert!(
            !frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::MaxData { .. })),
            "source-only generator must defer ack-eliciting control frames"
        );
        assert!(!conn.has_pending_stream_frames_for(source));
        assert!(
            conn.has_pending_stream_frames_for(control),
            "control stream must stay queued for the normal generator"
        );

        let control_frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("control packet");
        assert!(
            control_frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::MaxData { .. })),
            "normal generator should drain deferred ack-eliciting control frames"
        );
        assert!(
            control_frames.iter().any(|frame| matches!(
                frame,
                QuicFrame::Stream { stream_id, .. } if stream_id.value() == control.0
            )),
            "normal generator should still drain the deferred control stream"
        );
    }

    #[test]
    fn connection_stream_io_adapter_round_trips_one_payload() {
        let cx = test_cx();
        let mut tx = established_conn();
        let stream = tx.open_local_bidi(&cx).expect("open");
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);

        {
            let mut io = tx.stream_io(&cx, stream).expect("stream io");
            let poll = crate::io::AsyncWrite::poll_write(
                std::pin::Pin::new(&mut io),
                &mut task_cx,
                b"abc",
            );
            assert!(matches!(poll, Poll::Ready(Ok(3))));
        }
        let frame = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("stream frame");

        let mut rx = established_server_conn();
        rx.process_frame(&cx, &frame, PacketNumberSpace::ApplicationData)
            .expect("process stream frame");
        let mut storage = [0u8; 8];
        let mut read_buf = crate::io::ReadBuf::new(&mut storage);
        {
            let mut io = rx.stream_io(&cx, stream).expect("stream io");
            let poll = crate::io::AsyncRead::poll_read(
                std::pin::Pin::new(&mut io),
                &mut task_cx,
                &mut read_buf,
            );
            assert!(matches!(poll, Poll::Ready(Ok(()))));
        }
        assert_eq!(read_buf.filled(), b"abc");
    }

    #[test]
    fn stream_flow_exhaustion_queues_stream_data_blocked() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            send_window: 4,
            connection_send_limit: 4,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx).expect("confirmed");
        let stream = conn.open_local_bidi(&cx).expect("open");
        let err = conn
            .write_stream_bytes(&cx, stream, Bytes::from_static(b"abcde"), false)
            .expect_err("flow controlled");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::Flow(
                FlowControlError::Exhausted { .. }
            ))
        ));
        let blocked = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::StreamDataBlocked { .. } => Some(frame),
                _ => None,
            });
        assert!(blocked.is_some(), "STREAM_DATA_BLOCKED must be emitted");
    }

    #[test]
    fn on_ack_ranges_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            10_000,
        )
        .expect("sent");
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            10_050,
        )
        .expect("sent");
        let ranges = [AckRange::new(1, 0).expect("range")];
        let ack = conn
            .on_ack_ranges(&cx, PacketNumberSpace::ApplicationData, &ranges, 0, 20_000)
            .expect("ack");
        assert_eq!(ack.acked_packets, 2);
    }

    #[test]
    fn queued_ack_does_not_regress_largest_on_reordered_packets() {
        let mut conn = established_conn();
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 5);
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 3);

        let acks = conn
            .pending_control_frames
            .iter()
            .filter_map(|frame| match frame {
                QuicFrame::Ack {
                    largest_acknowledged,
                    first_ack_range,
                    ack_ranges,
                    ..
                } => Some((*largest_acknowledged, *first_ack_range, ack_ranges)),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(acks.len(), 1, "ACK queue should coalesce stale ACK frames");
        let (largest, first_range, ranges) = acks[0];
        assert_eq!(largest.value(), 5);
        assert_eq!(first_range.value(), 0);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].gap.value(), 0);
        assert_eq!(ranges[0].ack_range_length.value(), 0);
    }

    #[test]
    fn queued_ack_coalesces_contiguous_received_packets() {
        let mut conn = established_conn();
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 5);
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 4);
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 3);

        let ack = conn
            .pending_control_frames
            .iter()
            .find_map(|frame| match frame {
                QuicFrame::Ack {
                    largest_acknowledged,
                    first_ack_range,
                    ack_ranges,
                    ..
                } => Some((*largest_acknowledged, *first_ack_range, ack_ranges)),
                _ => None,
            })
            .expect("ACK frame queued");

        assert_eq!(ack.0.value(), 5);
        assert_eq!(ack.1.value(), 2);
        assert!(ack.2.is_empty());
    }

    #[test]
    fn begin_close_records_application_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0xdead).expect("close");
        assert_eq!(conn.transport().close_code(), Some(0xdead));
    }

    #[test]
    fn receive_stream_allowed_while_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.begin_close(&cx, 50_000, 0xdead).expect("close");
        conn.receive_stream(&cx, stream, 1)
            .expect("receive while draining");
    }

    #[test]
    fn write_is_blocked_when_congestion_window_is_full() {
        let cx = test_cx();
        let mut conn = established_conn();
        for _ in 0..20 {
            let send = conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                10_000,
            );
            if matches!(
                send,
                Err(NativeQuicConnectionError::CongestionLimited { .. })
            ) {
                return;
            }
        }
        panic!("expected congestion to limit packet sends"); // ubs:ignore - test assertion
    }

    #[test]
    fn handshake_confirm_does_not_mutate_tls_if_transport_is_not_handshaking() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        // Record verification so this test exercises the transport-state guard
        // rather than the br-7pwwwe server-identity gate.
        conn.record_verified_server_identity();
        let err = conn.on_handshake_confirmed(&cx).expect_err("must fail");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Transport(TransportError::InvalidStateTransition {
                from: QuicConnectionState::Idle,
                to: QuicConnectionState::Established
            })
        ));
        assert!(!conn.tls().can_send_1rtt());
    }

    // --- Gap 1: Cancellation path via Cx (Cancelled error variant) ---

    #[test]
    fn cancelled_cx_returns_cancelled_error() {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let err = conn.begin_handshake(&cx).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    #[test]
    fn cancelled_cx_blocks_open_local_bidi() {
        let cx = test_cx();
        let mut conn = established_conn();
        cx.set_cancel_requested(true);
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    #[test]
    fn cancelled_cx_blocks_poll() {
        let cx = test_cx();
        let mut conn = established_conn();
        cx.set_cancel_requested(true);
        let err = conn.poll(&cx, 1_000_000).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    // --- Gap 2: close_immediately via NativeQuicConnection wrapper ---

    #[test]
    fn close_immediately_transitions_to_closed_with_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0xbeef).expect("close");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
        assert_eq!(conn.transport().close_code(), Some(0xbeef));
    }

    #[test]
    fn close_immediately_from_handshaking() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.close_immediately(&cx, 42).expect("close");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
        assert_eq!(conn.transport().close_code(), Some(42));
    }

    // --- Gap 3: poll drives drain-to-closed transition ---

    #[test]
    fn poll_drives_drain_to_closed_when_deadline_reached() {
        let cx = test_cx();
        let mut conn = established_conn();
        let drain_timeout = conn.drain_timeout_micros;
        let now = 100_000u64;
        conn.begin_close(&cx, now, 0x1234).expect("drain");
        assert_eq!(conn.state(), QuicConnectionState::Draining);

        conn.poll(&cx, now + drain_timeout - 1)
            .expect("poll before deadline");
        assert_eq!(conn.state(), QuicConnectionState::Draining);

        conn.poll(&cx, now + drain_timeout)
            .expect("poll at deadline");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
    }

    #[test]
    fn poll_noop_when_not_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.poll(&cx, 999_999).expect("poll");
        assert_eq!(conn.state(), QuicConnectionState::Established);
    }

    // --- Gap 4: reset_stream_send via connection API ---

    #[test]
    fn reset_stream_send_records_reset_on_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 10).expect("write");
        conn.reset_stream_send(&cx, stream, 0x77, 10)
            .expect("reset");
        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.send_reset, Some((0x77, 10)));
    }

    #[test]
    fn reset_stream_send_rejects_final_size_below_sent() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 20).expect("write");
        let err = conn
            .reset_stream_send(&cx, stream, 0x01, 5)
            .expect_err("must fail");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::InvalidFinalSize { .. })
        ));
    }

    // --- Gap 5: stop_receiving via connection API ---

    #[test]
    fn stop_receiving_blocks_subsequent_receives() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.stop_receiving(&cx, stream, 0x42)
            .expect("stop_receiving");
        let err = conn
            .receive_stream(&cx, stream, 1)
            .expect_err("must fail after stop_receiving");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::ReceiveStopped { code: 0x42 })
        );
    }

    #[test]
    fn stop_receiving_records_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.stop_receiving(&cx, stream, 99).expect("stop");
        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.receive_stopped_error_code, Some(99));
    }

    // --- Gap 6: Key update methods via connection API ---

    #[test]
    fn request_and_commit_local_key_update() {
        let cx = test_cx();
        let mut conn = established_conn();
        let scheduled = conn.request_local_key_update(&cx).expect("request");
        assert_eq!(
            scheduled,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );
        let committed = conn.commit_local_key_update(&cx).expect("commit");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );
        assert!(conn.tls().local_key_phase());
    }

    #[test]
    fn on_peer_key_phase_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert!(!conn.tls().remote_key_phase());
        let evt = conn.on_peer_key_phase(&cx, true).expect("peer update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1,
            }
        );
        assert!(conn.tls().remote_key_phase());
    }

    #[test]
    fn duplicate_peer_key_phase_returns_no_change() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_peer_key_phase(&cx, true).expect("first");
        let evt = conn.on_peer_key_phase(&cx, true).expect("second same");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
    }

    #[test]
    fn appdata_packets_allowed_with_0rtt_resumption() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.enable_resumption_0rtt(&cx).expect("enable 0-rtt");

        assert!(conn.can_send_0rtt());
        let pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect("0-rtt appdata send");
        assert_eq!(pn, 0);
    }

    #[test]
    fn client_can_open_and_write_stream_during_0rtt() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.enable_resumption_0rtt(&cx).expect("enable 0-rtt");

        let stream = conn.open_local_bidi(&cx).expect("open 0-rtt stream");
        conn.write_stream(&cx, stream, 32)
            .expect("write 0-rtt stream");
    }

    #[test]
    fn disable_resumption_0rtt_revokes_client_early_data() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.enable_resumption_0rtt(&cx).expect("enable 0-rtt");
        assert!(conn.can_send_0rtt());

        conn.disable_resumption_0rtt(&cx).expect("disable 0-rtt");

        assert!(!conn.can_send_0rtt());
        let err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect_err("application data must fail after disabling 0-rtt");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "application-data packets require established 1-RTT state"
            )
        );
    }

    #[test]
    fn server_cannot_enable_0rtt_resumption() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");

        let err = conn
            .enable_resumption_0rtt(&cx)
            .expect_err("server must not opt into 0-rtt sending");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("0-RTT resumption is client-only")
        );
        assert!(!conn.can_send_0rtt());
    }

    #[test]
    fn server_send_is_limited_by_anti_amplification_budget() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");

        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_000)
            .expect("first flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_100)
            .expect("second flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_200)
            .expect("third flight");

        let err = conn
            .on_packet_sent(&cx, PacketNumberSpace::Handshake, 1, true, true, 10_300)
            .expect_err("fourth flight must exceed 3x limit");
        assert_eq!(
            err,
            NativeQuicConnectionError::AmplificationLimited {
                requested: 1,
                bytes_sent: 3_600,
                bytes_received: 1_200,
                limit: 3_600,
            }
        );
    }

    #[test]
    fn peer_address_validation_lifts_anti_amplification_limit() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_000)
            .expect("first flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_100)
            .expect("second flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_200)
            .expect("third flight");

        conn.validate_peer_address(&cx).expect("validate");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_300)
            .expect("validated peer may exceed prior 3x limit");
    }

    #[test]
    fn path_migration_requires_established_state() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn
            .request_path_migration(&cx, 7)
            .expect_err("must fail while handshaking");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("path migration requires established state")
        );
    }

    #[test]
    fn path_migration_is_blocked_when_disabled() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.set_active_migration_disabled(&cx, true)
            .expect("set policy");
        let err = conn
            .request_path_migration(&cx, 9)
            .expect_err("must fail when migration disabled");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "active migration disabled by transport parameters"
            )
        );
    }

    #[test]
    fn path_migration_updates_active_path_and_counter() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert_eq!(conn.active_path_id(), 0);
        assert_eq!(conn.migration_events(), 0);

        let n = conn
            .request_path_migration(&cx, 3)
            .expect("first migration");
        assert_eq!(n, 1);
        assert_eq!(conn.active_path_id(), 3);
        assert_eq!(conn.migration_events(), 1);

        let n = conn
            .request_path_migration(&cx, 3)
            .expect("same path is idempotent");
        assert_eq!(n, 1);
        assert_eq!(conn.migration_events(), 1);

        let n = conn
            .request_path_migration(&cx, 11)
            .expect("second migration");
        assert_eq!(n, 2);
        assert_eq!(conn.active_path_id(), 11);
        assert_eq!(conn.migration_events(), 2);
    }

    // --- Gap 7: next_writable_stream via connection API ---

    #[test]
    fn next_writable_stream_returns_open_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, Some(stream));
    }

    #[test]
    fn next_writable_stream_returns_none_when_no_streams() {
        let cx = test_cx();
        let mut conn = established_conn();
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, None);
    }

    #[test]
    fn next_writable_stream_skips_stopped_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let s1 = conn.open_local_bidi(&cx).expect("open1");
        let s2 = conn.open_local_bidi(&cx).expect("open2");
        conn.on_stop_sending(&cx, s1, 99).expect("stop s1");
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, Some(s2));
    }

    // --- Gap 8: Write operations after Close -> InvalidState ---

    #[test]
    fn write_stream_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn
            .write_stream(&cx, stream, 1)
            .expect_err("must fail after close");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    #[test]
    fn open_local_bidi_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    #[test]
    fn next_writable_stream_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.open_local_bidi(&cx).expect("open");
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn
            .next_writable_stream(&cx)
            .expect_err("must fail after close");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    // --- Gap 9: accept_remote_stream while draining -> InvalidState ---

    #[test]
    fn accept_remote_stream_while_draining_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0xdead).expect("drain");
        assert_eq!(conn.state(), QuicConnectionState::Draining);
        let remote = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        let err = conn
            .accept_remote_stream(&cx, remote)
            .expect_err("must fail while draining");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "new application streams require established state"
            )
        );
    }

    #[test]
    fn accept_remote_stream_enforces_default_remote_limit() {
        // `NativeQuicConnection::new` must install a finite cap on
        // remotely-initiated streams (RFC 9000 §4.6 MAX_STREAMS) so a peer
        // cannot force unbounded stream allocations from the wire. The default
        // client connection accepts server-initiated (remote) streams; sequence
        // `DEFAULT_MAX_REMOTE_STREAMS - 1` is the highest within-limit index and
        // `DEFAULT_MAX_REMOTE_STREAMS` is the first index that must be rejected.
        let cx = test_cx();
        let mut conn = established_conn();
        let within = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            DEFAULT_MAX_REMOTE_STREAMS - 1,
        );
        conn.accept_remote_stream(&cx, within)
            .expect("highest within-limit remote stream accepted");
        let over = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            DEFAULT_MAX_REMOTE_STREAMS,
        );
        let err = conn
            .accept_remote_stream(&cx, over)
            .expect_err("remote stream at the limit must be rejected");
        assert!(
            matches!(
                err,
                NativeQuicConnectionError::StreamTable(
                    StreamTableError::StreamLimitExceeded { .. }
                )
            ),
            "expected StreamLimitExceeded, got: {err:?}"
        );
    }

    #[test]
    fn set_remote_stream_limits_overrides_default() {
        // The per-connection override tightens (or relaxes) the wire cap.
        let cx = test_cx();
        let mut conn = established_conn();
        conn.set_remote_stream_limits(1, 1);
        let first = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        conn.accept_remote_stream(&cx, first)
            .expect("first remote stream within tightened limit");
        let second = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            1,
        );
        let err = conn
            .accept_remote_stream(&cx, second)
            .expect_err("second remote stream exceeds tightened limit");
        assert!(matches!(
            err,
            NativeQuicConnectionError::StreamTable(StreamTableError::StreamLimitExceeded { .. })
        ));
    }

    #[test]
    fn increasing_remote_stream_limits_emits_max_streams_frames() {
        let cx = test_cx();
        let mut conn = established_conn();

        conn.set_remote_stream_limits(256, 512);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("control frames should generate");

        assert_eq!(
            frames,
            vec![
                QuicFrame::MaxStreams {
                    maximum_streams: VarInt::from_u64_unchecked(256),
                    bidirectional: true,
                },
                QuicFrame::MaxStreams {
                    maximum_streams: VarInt::from_u64_unchecked(512),
                    bidirectional: false,
                },
            ]
        );

        conn.set_remote_stream_limits(128, 128);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("lowering limits should not emit MAX_STREAMS");
        assert!(frames.is_empty());
    }

    #[test]
    fn application_datagram_generation_coalesces_many_payloads_when_budget_allows() {
        let cx = test_cx();
        let mut conn = established_conn();
        let datagram_count = 64usize;

        for idx in 0..datagram_count {
            let payload = Bytes::from(vec![(idx % 251) as u8; 64]);
            conn.send_datagram(&cx, payload)
                .expect("queue outbound datagram");
        }

        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("coalesced datagram frames should generate");
        let emitted = frames
            .iter()
            .filter(|frame| matches!(frame, QuicFrame::Datagram { .. }))
            .count();

        assert_eq!(emitted, datagram_count);
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_sent(), datagram_count as u64);
    }

    #[test]
    fn non_datagram_generation_leaves_application_datagrams_queued() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.queue_ping(&cx).expect("queue control ping");
        conn.send_datagram(&cx, Bytes::from_static(b"symbol"))
            .expect("queue outbound datagram");

        let frames = conn
            .generate_non_datagram_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("non-datagram frames should generate");

        assert_eq!(frames, vec![QuicFrame::Ping]);
        assert_eq!(conn.pending_outbound_datagram_count(), 1);
        assert_eq!(conn.datagrams_sent(), 0);

        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("queued datagram should remain sendable");
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::Datagram { .. }))
        );
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_sent(), 1);
    }

    #[test]
    fn application_datagram_batch_enqueue_preserves_order() {
        let cx = test_cx();
        let mut conn = established_conn();
        let payloads = (0..8)
            .map(|idx| Bytes::from(vec![idx as u8; 4]))
            .collect::<Vec<_>>();

        let queued = conn
            .send_datagram_batch(&cx, payloads.clone())
            .expect("batch queues outbound datagrams");

        assert_eq!(queued, payloads.len());
        assert_eq!(conn.pending_outbound_datagram_count(), payloads.len());
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("coalesced datagram frames should generate");
        let emitted = frames
            .into_iter()
            .filter_map(|frame| match frame {
                QuicFrame::Datagram { data } => Some(data),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(emitted, payloads);
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_sent(), queued as u64);
    }

    #[test]
    fn process_packet_payload_batches_coalesced_datagrams_in_order() {
        let cx = test_cx();
        let mut conn = established_conn();
        let payloads = (0..8)
            .map(|idx| Bytes::from(vec![idx as u8; 4]))
            .collect::<Vec<_>>();
        let mut packet_payload = BytesMut::new();
        for payload in &payloads {
            QuicFrame::Datagram {
                data: payload.clone(),
            }
            .encode(&mut packet_payload)
            .expect("datagram frame encodes");
        }

        conn.process_packet_payload(
            &cx,
            PacketNumberSpace::ApplicationData,
            7,
            &packet_payload,
            1,
        )
        .expect("coalesced datagram packet accepted");

        assert_eq!(conn.pending_datagram_count(), payloads.len());
        assert_eq!(conn.datagrams_received(), payloads.len() as u64);
        for expected in payloads {
            assert_eq!(conn.recv_datagram().expect("queued datagram"), expected);
        }
        assert!(conn.recv_datagram().is_none());
    }

    #[test]
    fn inbound_datagram_queue_drops_new_overflow_without_evicting_survivors() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert_eq!(conn.inbound_datagram_capacity(), MAX_INBOUND_DATAGRAMS);
        assert_eq!(
            conn.inbound_datagram_remaining_capacity(),
            MAX_INBOUND_DATAGRAMS
        );

        for idx in 0..MAX_INBOUND_DATAGRAMS {
            let payload = Bytes::from(vec![(idx % 251) as u8]);
            conn.process_frame(
                &cx,
                &QuicFrame::Datagram { data: payload },
                PacketNumberSpace::ApplicationData,
            )
            .expect("within-capacity datagram accepted");
        }

        assert_eq!(conn.pending_datagram_count(), MAX_INBOUND_DATAGRAMS);
        assert_eq!(conn.inbound_datagram_remaining_capacity(), 0);
        assert_eq!(conn.datagrams_received(), MAX_INBOUND_DATAGRAMS as u64);
        assert_eq!(conn.datagrams_dropped_on_receive(), 0);

        conn.process_frame(
            &cx,
            &QuicFrame::Datagram {
                data: Bytes::from_static(b"overflow"),
            },
            PacketNumberSpace::ApplicationData,
        )
        .expect("full inbound datagram queue treats new payload as counted loss");
        assert_eq!(conn.pending_datagram_count(), MAX_INBOUND_DATAGRAMS);
        assert_eq!(conn.datagrams_received(), MAX_INBOUND_DATAGRAMS as u64);
        assert_eq!(conn.datagrams_dropped_on_receive(), 1);

        for idx in 0..MAX_INBOUND_DATAGRAMS {
            let payload = conn.recv_datagram().expect("survivor preserved");
            assert_eq!(payload.as_ref(), &[(idx % 251) as u8]);
        }
        assert!(conn.recv_datagram().is_none());
        assert_eq!(
            conn.inbound_datagram_remaining_capacity(),
            MAX_INBOUND_DATAGRAMS
        );
    }

    #[test]
    fn recv_datagram_batch_preserves_order_and_limit() {
        let cx = test_cx();
        let mut conn = established_conn();

        for idx in 0u8..5 {
            conn.process_frame(
                &cx,
                &QuicFrame::Datagram {
                    data: Bytes::from(vec![idx]),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("datagram accepted");
        }

        let mut batch = VecDeque::new();
        assert_eq!(conn.recv_datagram_batch(0, &mut batch), 0);
        assert!(batch.is_empty());
        assert_eq!(conn.pending_datagram_count(), 5);

        assert_eq!(conn.recv_datagram_batch(3, &mut batch), 3);
        let first: Vec<_> = batch.iter().map(|bytes| bytes[0]).collect();
        assert_eq!(first, vec![0, 1, 2]);
        assert_eq!(conn.pending_datagram_count(), 2);

        assert_eq!(conn.recv_datagram_batch(10, &mut batch), 2);
        let second: Vec<_> = batch.iter().map(|bytes| bytes[0]).collect();
        assert_eq!(second, vec![3, 4]);
        assert_eq!(conn.pending_datagram_count(), 0);
        assert_eq!(conn.recv_datagram_batch(10, &mut batch), 0);
        assert!(batch.is_empty());
    }

    // --- Gap 10: NativeQuicConnectionError Display/From impls ---

    #[test]
    fn display_cancelled() {
        let err = NativeQuicConnectionError::Cancelled;
        assert_eq!(format!("{err}"), "operation cancelled");
    }

    #[test]
    fn display_congestion_limited() {
        let err = NativeQuicConnectionError::CongestionLimited {
            requested: 1500,
            bytes_in_flight: 12000,
            congestion_window: 12000,
        };
        assert_eq!(
            format!("{err}"),
            "congestion window exceeded: requested=1500, in_flight=12000, cwnd=12000"
        );
    }

    #[test]
    fn display_invalid_state() {
        let err = NativeQuicConnectionError::InvalidState("test message");
        assert_eq!(
            format!("{err}"),
            "invalid native quic connection state: test message"
        );
    }

    #[test]
    fn display_datagram_too_large() {
        let err = NativeQuicConnectionError::DatagramTooLarge {
            payload_len: 4096,
            encoded_len: 4099,
            max_frame_size: 1200,
        };
        assert_eq!(
            format!("{err}"),
            "datagram frame too large: payload_len=4096, encoded_len=4099, max_frame_size=1200"
        );
    }

    #[test]
    fn display_datagram_receive_queue_full() {
        let err = NativeQuicConnectionError::DatagramReceiveQueueFull {
            capacity: MAX_INBOUND_DATAGRAMS,
        };
        assert_eq!(
            format!("{err}"),
            format!(
                "inbound datagram receive queue full: capacity={MAX_INBOUND_DATAGRAMS}; drain buffered payloads before processing more"
            )
        );
    }

    #[test]
    fn from_quic_tls_error() {
        let tls_err = QuicTlsError::HandshakeNotConfirmed;
        let conn_err: NativeQuicConnectionError = tls_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Tls(tls_err));
    }

    #[test]
    fn from_transport_error() {
        let transport_err = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Established,
        };
        let conn_err: NativeQuicConnectionError = transport_err.clone().into();
        assert_eq!(
            conn_err,
            NativeQuicConnectionError::Transport(transport_err)
        );
    }

    #[test]
    fn from_quic_frame_error() {
        let frame_err = QuicFrameError::UnexpectedEof;
        let conn_err: NativeQuicConnectionError = frame_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Frame(frame_err));
    }

    #[test]
    fn from_stream_table_error() {
        let st_err = StreamTableError::UnknownStream(StreamId(99));
        let conn_err: NativeQuicConnectionError = st_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::StreamTable(st_err));
    }

    #[test]
    fn from_quic_stream_error() {
        let stream_err = QuicStreamError::SendStopped { code: 42 };
        let conn_err: NativeQuicConnectionError = stream_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Stream(stream_err));
    }

    #[test]
    fn display_tls_error_passthrough() {
        let inner = QuicTlsError::HandshakeNotConfirmed;
        let err = NativeQuicConnectionError::Tls(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_transport_error_passthrough() {
        let inner = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Closed,
        };
        let err = NativeQuicConnectionError::Transport(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_frame_error_passthrough() {
        let inner = QuicFrameError::UnknownFrameType(0x40);
        let err = NativeQuicConnectionError::Frame(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_stream_table_error_passthrough() {
        let inner = StreamTableError::UnknownStream(StreamId(7));
        let err = NativeQuicConnectionError::StreamTable(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_stream_error_passthrough() {
        let inner = QuicStreamError::SendStopped { code: 100 };
        let err = NativeQuicConnectionError::Stream(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn next_packet_number_accepts_max_valid_then_rejects_overflow() {
        // RFC 9000 §17.1: packet numbers in [0, 2^62-1] inclusive.
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        // Seed the Initial space cursor at 2^62 - 1: that exact value is the
        // last valid packet number and must be issued exactly once before the
        // exhaustion guard fires.
        conn.next_packet_numbers[0] = (1u64 << 62) - 1;
        let pn = conn
            .next_packet_number(PacketNumberSpace::Initial)
            .expect("max valid packet number must be issuable");
        assert_eq!(pn, (1u64 << 62) - 1);
        let err = conn
            .next_packet_number(PacketNumberSpace::Initial)
            .expect_err("packet number 2^62 must be rejected");
        assert!(matches!(
            err,
            NativeQuicConnectionError::InvalidState(
                "packet number limit reached; connection must be closed"
            )
        ));
    }
}
