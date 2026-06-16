//! ATP-over-QUIC transport (Phase B scaffold).
//!
//! This module is the public-API skeleton for the *adaptive RaptorQ-over-QUIC*
//! data plane — the production ATP transport meant to beat rsync on lossy,
//! high-latency internet paths. It deliberately mirrors the public surface of
//! [`crate::net::atp::transport_tcp`] *exactly* so callers (the `atp` CLI, the
//! `atpd` daemon, fleet/loopback E2E harnesses) can target QUIC by swapping the
//! transport module and config type, with no other call-site changes.
//!
//! # Status: scaffold (`asupersync-arq-quic-epic-b0k8qo.2.1`, "B1")
//!
//! The wire-level send/receive coroutines are **not yet wired** — they land in:
//!
//! - [`send_path`] → `asupersync-arq-quic-epic-b0k8qo.2.2` (B2: QUIC sender
//!   coroutine — connect, verify identity, manifest, encode + spray RaptorQ
//!   symbols across QUIC DATAGRAMs, fountain feedback).
//! - [`receive_once`] / [`receive_connection`] / [`serve`] →
//!   `asupersync-arq-quic-epic-b0k8qo.2.3` (B3: QUIC receiver coroutine —
//!   accept, manifest, feed the decoder from DATAGRAMs, verify, commit).
//!
//! Until then every transfer entry point **fails closed**: it validates its
//! configuration, emits a structured config summary, and returns
//! [`QuicTransportError::NotImplemented`]. There is no code path that reports a
//! fake success or moves zero bytes silently — the epic's non-negotiable
//! "every unwired op fails closed (typed error, never fake success)" rule.
//!
//! # Why a scaffold can land ahead of the Phase A data plane
//!
//! The tracker gates Phase B on Phase A (`...b0k8qo.1`, the QUIC application
//! data plane). That ordering is real for the *implementation* in B2/B3, which
//! consumes the Phase A DATAGRAM/STREAM/packet-protection surfaces. The
//! *scaffold*, however, only depends on already-landed pieces: the shared
//! bounded-memory helpers in [`crate::net::atp::transport_common`] (F0) and the
//! `transport_tcp` template it mirrors. Because every op fails closed, the
//! scaffold never touches the (still in-flight) Phase A data plane, so it is
//! safe — and useful — to land now: B2/B3 fill in bodies against a frozen public
//! API, and downstream Phase B/G/H beads can reference real types.
//!
//! # Reused wire / report types
//!
//! The manifest, receipt, and report types are intentionally **reused** from
//! [`crate::net::atp::transport_tcp`] (re-exported below) rather than
//! re-declared, so QUIC and TCP transfers commit to the byte-identical
//! manifest/merkle schema. A later refactor may hoist these into
//! `transport_common`; the re-export keeps the QUIC public surface stable
//! across that move.
//!
//! # Integrity & bounded memory (inherited contract)
//!
//! When wired, this transport keeps `transport_tcp`'s fail-closed integrity
//! guarantee (per-entry SHA-256 + rebuilt flat-object-graph merkle root vs. the
//! manifest, atomic commit only on a full match) and its `O(symbol/chunk size)`
//! peak-memory bound (stream to/from disk; never hold a whole entry, let alone
//! the whole transfer, in memory).

pub mod symbol_datagram;
pub mod symbol_envelope;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, MAX_FRAME_SIZE, ProtocolVersion};
use crate::net::atp::transport_common::StreamingError;
use crate::net::quic_native::{
    ManagedQuicEndpoint, NativeQuicConnection, QuicConnection, StreamId,
};
use crate::types::symbol::ObjectId;

// Reuse the manifest / receipt / report wire+value types so QUIC and TCP share
// one schema (see module docs). These are the "reuse manifest/report/receipt"
// half of the B1 acceptance.
pub use crate::net::atp::transport_tcp::{
    ManifestEntry, ReceiveReceipt, ReceiveReport, SendReport, TransferManifest,
};

// The RaptorQ symbol-envelope codec (the framing of a symbol inside a QUIC
// DATAGRAM) — the foundational piece B2/B3 build the sender/receiver on.
pub use symbol_envelope::{
    ATP_QUIC_SYMBOL_MAGIC, AUTH_ENVELOPE_HEADER_LEN, ENVELOPE_HEADER_LEN, QuicSymbolEnvelope,
    QuicSymbolEnvelopeError,
};

// The Symbol <-> QUIC-datagram bridge: maps types::symbol::Symbol to/from the
// envelope and moves it over the A6 QuicConnection datagram plane. The reusable
// data-path core for the B2 sender and B3 receiver coroutines.
pub use symbol_datagram::{
    SymbolDatagramError, envelope_to_symbol, recv_symbol_envelope, send_symbol, symbol_to_envelope,
};

/// Protocol identifier carried in the QUIC handshake; bump on wire-incompatible
/// changes. Distinct from `transport_tcp` (`1`) and `transport_rq` (`2`).
pub const ATP_QUIC_PROTOCOL: u32 = 3;

/// Default streaming hash/read buffer size. Bounds the sender's per-file
/// streaming pass; peak RSS is `O(chunk_size)`, independent of transfer size.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Default RaptorQ symbol payload size, kept small enough that one symbol plus
/// its envelope fits a single QUIC DATAGRAM well under a 1500-byte path MTU.
pub const DEFAULT_SYMBOL_SIZE: u16 = 1024;

/// Default RaptorQ source-block ceiling in bytes.
pub const DEFAULT_MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Default ceiling on a single QUIC DATAGRAM's application payload.
///
/// Tracks the RFC 9221 `max_datagram_frame_size` budget; a RaptorQ symbol
/// envelope must fit within this, so it is validated against
/// [`QuicConfig::symbol_size`].
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;

/// Default round-0 repair multiplier (`>= 1.0`). The tiny default proactive
/// RaptorQ tail keeps the fast source-first shape while absorbing sparse loss.
pub const DEFAULT_REPAIR_OVERHEAD: f64 = 1.001;

/// Default ceiling on a single transfer's total bytes.
pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default maximum time to wait for a connected peer to make protocol progress.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum time to wait for the QUIC handshake to complete.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum time a one-shot receiver waits for the initial accept.
pub const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default number of accepted transfers a persistent server processes at once.
pub const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 64;

/// Default bound on fountain feedback rounds before failing closed.
pub const DEFAULT_MAX_FEEDBACK_ROUNDS: u32 = 16;

/// Tuning knobs for the ATP-over-QUIC transport.
///
/// Mirrors the role of [`transport_tcp::TransferConfig`] while adding the
/// RaptorQ-over-QUIC knobs (symbol size, block size, repair overhead, datagram
/// budget, feedback rounds) that the B2/B3 coroutines will consume.
///
/// [`transport_tcp::TransferConfig`]: crate::net::atp::transport_tcp::TransferConfig
#[derive(Debug, Clone, Copy)]
pub struct QuicConfig {
    /// Streaming hash/read buffer size in bytes.
    pub chunk_size: usize,
    /// RaptorQ symbol payload size in bytes.
    pub symbol_size: u16,
    /// Maximum RaptorQ source-block size in bytes.
    pub max_block_size: usize,
    /// Maximum application payload carried in one QUIC DATAGRAM.
    pub max_datagram_size: usize,
    /// Extra repair fraction sprayed in round 0 (`>= 1.0`).
    pub repair_overhead: f64,
    /// Maximum total bytes a single transfer may carry.
    pub max_transfer_bytes: u64,
    /// Maximum time to wait for the next protocol frame before failing closed.
    pub idle_timeout: Duration,
    /// Maximum time to wait for the QUIC handshake to complete.
    pub handshake_timeout: Duration,
    /// Maximum time a one-shot receive waits for `accept()`. In persistent
    /// `serve()` this doubles as the idle cancellation-checkpoint interval.
    pub accept_timeout: Duration,
    /// Maximum number of connections `serve()` may process concurrently.
    /// A value of zero is treated as one active connection.
    pub max_active_connections: usize,
    /// Maximum fountain feedback rounds before a transfer fails closed.
    pub max_feedback_rounds: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            accept_timeout: DEFAULT_ACCEPT_TIMEOUT,
            max_active_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
            max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
        }
    }
}

impl QuicConfig {
    /// Validate the configuration, failing closed on any nonsensical knob before
    /// the transport opens a socket or allocates a buffer. Attacker-irrelevant
    /// (this is the *local* operator's config) but it turns silent misbehavior
    /// (zero timeouts that would hang, a symbol that cannot fit a datagram) into
    /// an explicit typed error.
    pub fn validate(&self) -> Result<(), QuicTransportError> {
        if self.chunk_size == 0 {
            return Err(QuicTransportError::Config(
                "chunk_size must be greater than 0".to_string(),
            ));
        }
        if self.symbol_size == 0 {
            return Err(QuicTransportError::Config(
                "symbol_size must be greater than 0".to_string(),
            ));
        }
        if self.max_block_size == 0 {
            return Err(QuicTransportError::Config(
                "max_block_size must be greater than 0".to_string(),
            ));
        }
        // A symbol payload (symbol_size) plus its worst-case (authenticated)
        // envelope header must fit one QUIC DATAGRAM. Use the authenticated
        // header so the bound holds regardless of the per-transfer auth posture.
        let min_datagram = usize::from(self.symbol_size) + AUTH_ENVELOPE_HEADER_LEN;
        if self.max_datagram_size < min_datagram {
            return Err(QuicTransportError::Config(format!(
                "max_datagram_size ({}) must be at least symbol_size ({}) + the \
                 {AUTH_ENVELOPE_HEADER_LEN}-byte authenticated envelope header = {min_datagram} \
                 so a symbol fits one DATAGRAM",
                self.max_datagram_size, self.symbol_size
            )));
        }
        if self.repair_overhead < 1.0 || self.repair_overhead.is_nan() {
            return Err(QuicTransportError::Config(format!(
                "repair_overhead ({}) must be >= 1.0",
                self.repair_overhead
            )));
        }
        if self.max_transfer_bytes == 0 {
            return Err(QuicTransportError::Config(
                "max_transfer_bytes must be greater than 0".to_string(),
            ));
        }
        if self.idle_timeout.is_zero() {
            return Err(QuicTransportError::Config(
                "idle_timeout must be greater than 0".to_string(),
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(QuicTransportError::Config(
                "handshake_timeout must be greater than 0".to_string(),
            ));
        }
        if self.accept_timeout.is_zero() {
            return Err(QuicTransportError::Config(
                "accept_timeout must be greater than 0".to_string(),
            ));
        }
        if self.max_feedback_rounds == 0 {
            return Err(QuicTransportError::Config(
                "max_feedback_rounds must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Errors from the ATP-over-QUIC transport.
///
/// Mirrors [`transport_tcp::TransportError`] (so error handling is uniform
/// across transports) and adds [`QuicTransportError::Config`] for invalid
/// configuration, [`QuicTransportError::Quic`] for native QUIC failures, and
/// [`QuicTransportError::NotImplemented`] for the still-unwired scaffold ops.
///
/// [`transport_tcp::TransportError`]: crate::net::atp::transport_tcp::TransportError
#[derive(Debug, thiserror::Error)]
pub enum QuicTransportError {
    /// Network or local I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Frame codec error.
    #[error("frame error: {0}")]
    Frame(String),
    /// JSON (de)serialization error for a control frame.
    #[error("control frame decode error: {0}")]
    Control(String),
    /// The peer rejected the handshake.
    #[error("handshake rejected by peer: {0}")]
    HandshakeRejected(String),
    /// An unexpected frame type arrived for the current protocol state.
    #[error("unexpected frame: got {got:?}, expected {expected}")]
    Unexpected {
        /// The frame type actually received.
        got: FrameType,
        /// A description of what was expected.
        expected: &'static str,
    },
    /// The transfer exceeded the configured size ceiling.
    #[error("transfer exceeds maximum size ({size} > {max} bytes)")]
    TooLarge {
        /// Declared or observed size.
        size: u64,
        /// Configured maximum.
        max: u64,
    },
    /// Integrity verification failed (SHA-256 or merkle-root mismatch).
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    /// The source path was invalid (missing, unsupported type).
    #[error("invalid source path: {0}")]
    Source(String),
    /// The transport configuration was invalid.
    #[error("invalid transport configuration: {0}")]
    Config(String),
    /// A native QUIC endpoint/connection error.
    #[error("native QUIC error: {0}")]
    Quic(String),
    /// The transfer was cancelled via the capability context.
    #[error("transfer cancelled")]
    Cancelled,
    /// A transport operation exceeded its configured timeout.
    #[error("transport timeout during {operation} after {timeout:?}")]
    Timeout {
        /// Operation that timed out.
        operation: &'static str,
        /// Configured timeout duration.
        timeout: Duration,
    },
    /// A transfer entry point that is not yet wired (B2/B3). Failing closed with
    /// this typed error is the scaffold's contract: never report fake success.
    #[error(
        "transport_quic operation '{operation}' is not yet wired (lands in {wired_by}); \
         failing closed instead of reporting fake success"
    )]
    NotImplemented {
        /// The unwired entry point.
        operation: &'static str,
        /// The bead that wires it.
        wired_by: &'static str,
    },
}

impl From<StreamingError> for QuicTransportError {
    fn from(err: StreamingError) -> Self {
        Self::Source(err.into_message())
    }
}

impl From<crate::net::quic_native::NativeQuicConnectionError> for QuicTransportError {
    fn from(err: crate::net::quic_native::NativeQuicConnectionError) -> Self {
        Self::Quic(err.to_string())
    }
}

// ─── Control-plane payloads (JSON over one QUIC stream) ─────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct QuicHello {
    protocol: u32,
    role: String,
    peer_id: String,
    symbol_size: u16,
    max_block_size: u64,
    #[serde(default)]
    symbol_auth: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct QuicHelloAck {
    accepted: bool,
    peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Receiver → sender fountain feedback: entries still needing more symbols.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct QuicNeedMore {
    pending: Vec<u32>,
}

#[allow(dead_code)]
fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, QuicTransportError> {
    let payload =
        serde_json::to_vec(value).map_err(|err| QuicTransportError::Control(err.to_string()))?;
    let frame = Frame::new(ProtocolVersion::CURRENT, ty, payload)
        .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    let encoded_len = frame.encoded_len() as u64;
    if encoded_len > MAX_FRAME_SIZE {
        return Err(QuicTransportError::Frame(format!(
            "{ty:?} JSON frame encodes to {encoded_len} bytes (max {MAX_FRAME_SIZE}); \
             split or chunk the manifest/control payload"
        )));
    }
    Ok(frame)
}

#[allow(dead_code)]
fn parse_json<T: for<'de> Deserialize<'de>>(frame: &Frame) -> Result<T, QuicTransportError> {
    serde_json::from_slice(frame.payload())
        .map_err(|err| QuicTransportError::Control(err.to_string()))
}

#[allow(dead_code)]
fn parse_json_frame<T: for<'de> Deserialize<'de>>(
    frame: &Frame,
    expected: FrameType,
    expected_name: &'static str,
) -> Result<T, QuicTransportError> {
    if frame.frame_type() != expected {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: expected_name,
        });
    }
    parse_json(frame)
}

/// Derive the per-entry RaptorQ [`ObjectId`] deterministically from the
/// transfer id and entry index, matching `transport_rq` so the symbol bridge can
/// resolve envelope routing without carrying object ids on the wire.
#[allow(dead_code)]
fn entry_object_id(transfer_id: &str, index: u32) -> ObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(index.to_be_bytes());
    let digest = hasher.finalize();
    let high = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let low = u64::from_be_bytes([
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ]);
    ObjectId::new(high, low)
}

/// First 8 bytes of a transfer-id digest as the QUIC DATAGRAM routing tag.
///
/// This is a cheap stray-packet filter and routing key, not a security
/// boundary; per-symbol auth lives in the symbol envelope/auth context.
#[allow(dead_code)]
fn transfer_tag(transfer_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.tag.v1\0");
    hasher.update(transfer_id.as_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

/// Maximum control-stream chunk read per decode attempt.
#[allow(dead_code)]
const CONTROL_READ_CHUNK: usize = 64 * 1024;

/// ATP frame transport over one QUIC bidirectional control stream.
///
/// This is the reliable control-plane half B2/B3 need: canonical ATP
/// [`Frame`](crate::net::atp::protocol::frames::Frame) wire bytes are queued
/// through the A6 control-stream API, and inbound bytes are incrementally
/// decoded with the same [`AtpFrameCodec`] TCP uses. It is deliberately
/// non-blocking: `try_recv` returns `Ok(None)` when the stream has only a
/// partial frame or no bytes yet; the caller decides how to pump/wait.
///
/// The B2/B3 adapter is covered by inline tests here before the higher-level
/// send/receive coroutines call it; keep the dead-code allowance pinned to this
/// interim helper until those call sites land.
#[allow(dead_code)]
pub struct QuicFrameTransport {
    stream: StreamId,
    codec: AtpFrameCodec,
    rbuf: BytesMut,
}

#[allow(dead_code)]
impl QuicFrameTransport {
    /// Open a local bidirectional control stream.
    pub fn open(cx: &Cx, conn: &mut QuicConnection) -> Result<Self, QuicTransportError> {
        let stream = conn.open_control_stream(cx)?;
        Ok(Self::for_stream(stream))
    }

    /// Bind to an already-known control stream id.
    ///
    /// B3 uses this for the first client-initiated stream until the high-level
    /// QUIC API exposes an accept-next-remote-control-stream helper.
    pub fn for_stream(stream: StreamId) -> Self {
        Self {
            stream,
            codec: AtpFrameCodec::new(),
            rbuf: BytesMut::new(),
        }
    }

    /// Underlying QUIC stream id.
    #[must_use]
    pub fn stream(&self) -> StreamId {
        self.stream
    }

    /// Encode and queue a canonical ATP frame on the control stream.
    pub fn send(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
        frame: &crate::net::atp::protocol::frames::Frame,
    ) -> Result<(), QuicTransportError> {
        let wire = frame
            .to_wire_bytes()
            .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
        conn.write_control(cx, self.stream, Bytes::from(wire), false)?;
        Ok(())
    }

    /// Serialize a typed JSON control payload, wrap it in the requested ATP frame
    /// type, and queue it on the control stream.
    pub fn send_json<T: Serialize>(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
        ty: FrameType,
        value: &T,
    ) -> Result<(), QuicTransportError> {
        let frame = json_frame(ty, value)?;
        self.send(cx, conn, &frame)
    }

    /// Try to decode the next complete ATP frame from the control stream.
    pub fn try_recv(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
    ) -> Result<Option<crate::net::atp::protocol::frames::Frame>, QuicTransportError> {
        if let Some(frame) = self
            .codec
            .decode(&mut self.rbuf)
            .map_err(|err| QuicTransportError::Frame(err.to_string()))?
        {
            return Ok(Some(frame));
        }

        let chunk = conn.read_control(cx, self.stream, CONTROL_READ_CHUNK)?;
        if chunk.is_empty() {
            return Ok(None);
        }
        self.rbuf.extend_from_slice(&chunk);
        self.codec
            .decode(&mut self.rbuf)
            .map_err(|err| QuicTransportError::Frame(err.to_string()))
    }

    /// Try to receive a typed JSON control payload, rejecting unexpected frame
    /// types before deserializing attacker-controlled JSON bytes.
    pub fn try_recv_json<T: for<'de> Deserialize<'de>>(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
        expected: FrameType,
        expected_name: &'static str,
    ) -> Result<Option<T>, QuicTransportError> {
        let Some(frame) = self.try_recv(cx, conn)? else {
            return Ok(None);
        };
        parse_json_frame(&frame, expected, expected_name).map(Some)
    }
}

#[allow(dead_code)]
fn next_control_frame(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    operation: &'static str,
) -> Result<Frame, QuicTransportError> {
    control
        .try_recv(cx, conn)?
        .ok_or_else(|| QuicTransportError::Frame(format!("{operation}: no complete frame ready")))
}

#[allow(dead_code)]
fn sender_hello(peer_id: &str, config: &QuicConfig, symbol_auth: bool) -> QuicHello {
    QuicHello {
        protocol: ATP_QUIC_PROTOCOL,
        role: "sender".to_string(),
        peer_id: peer_id.to_string(),
        symbol_size: config.symbol_size,
        max_block_size: u64::try_from(config.max_block_size).unwrap_or(u64::MAX),
        symbol_auth,
    }
}

#[allow(dead_code)]
fn reject_hello_reason(
    hello: &QuicHello,
    config: &QuicConfig,
    expected_symbol_auth: bool,
) -> Option<String> {
    if hello.protocol != ATP_QUIC_PROTOCOL {
        return Some(format!(
            "unsupported protocol {} (this peer speaks {ATP_QUIC_PROTOCOL})",
            hello.protocol
        ));
    }
    if hello.symbol_size == 0 {
        return Some("symbol_size must be greater than 0".to_string());
    }
    if hello.max_block_size == 0 {
        return Some("max_block_size must be greater than 0".to_string());
    }
    let min_datagram = usize::from(hello.symbol_size) + AUTH_ENVELOPE_HEADER_LEN;
    if min_datagram > config.max_datagram_size {
        return Some(format!(
            "sender symbol_size ({}) plus {AUTH_ENVELOPE_HEADER_LEN}-byte authenticated envelope \
             header exceeds receiver max_datagram_size ({})",
            hello.symbol_size, config.max_datagram_size
        ));
    }
    let max_block_size = u64::try_from(config.max_block_size).unwrap_or(u64::MAX);
    if hello.max_block_size > max_block_size {
        return Some(format!(
            "sender max_block_size ({}) exceeds receiver max_block_size ({max_block_size})",
            hello.max_block_size
        ));
    }
    if hello.symbol_auth != expected_symbol_auth {
        return Some(format!(
            "symbol authentication mismatch: sender={}, receiver={expected_symbol_auth}",
            hello.symbol_auth
        ));
    }
    None
}

// B2/B3 coroutine helpers are exercised by deterministic loopback tests before
// the public transfer entry points call them.
#[allow(dead_code)]
fn send_sender_hello(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    config: &QuicConfig,
    peer_id: &str,
    symbol_auth: bool,
) -> Result<(), QuicTransportError> {
    let frame = json_frame(
        FrameType::Handshake,
        &sender_hello(peer_id, config, symbol_auth),
    )?;
    control.send(cx, conn, &frame)
}

#[allow(dead_code)]
fn receive_sender_hello_and_ack(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    config: &QuicConfig,
    peer_id: &str,
    expected_symbol_auth: bool,
) -> Result<QuicHello, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive sender handshake")?;
    if frame.frame_type() != FrameType::Handshake {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: QuicHello = parse_json(&frame)?;
    let reason = reject_hello_reason(&hello, config, expected_symbol_auth);
    let accepted = reason.is_none();
    let ack = QuicHelloAck {
        accepted,
        peer_id: peer_id.to_string(),
        reason: reason.clone(),
    };
    let ack_frame = json_frame(FrameType::HandshakeAck, &ack)?;
    control.send(cx, conn, &ack_frame)?;
    if let Some(reason) = reason {
        return Err(QuicTransportError::HandshakeRejected(reason));
    }
    Ok(hello)
}

#[allow(dead_code)]
fn receive_sender_hello_ack(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<QuicHelloAck, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive sender handshake ack")?;
    if frame.frame_type() != FrameType::HandshakeAck {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let ack: QuicHelloAck = parse_json(&frame)?;
    if !ack.accepted {
        return Err(QuicTransportError::HandshakeRejected(
            ack.reason
                .clone()
                .unwrap_or_else(|| "no reason given".to_string()),
        ));
    }
    Ok(ack)
}

/// Emit a deterministic, structured config summary at the start of a transport
/// operation (the "config summary on start" logging requirement). Routes
/// through [`Cx::trace_with_fields`] so production stays silent unless a trace
/// sink is attached — no stdout/stderr from the runtime. The env-gated
/// `ATP_QUIC_TRACE` hook (see `quic_native`) remains the per-frame diagnostic
/// channel for the B2/B3 wire paths.
fn trace_config_summary(cx: &Cx, operation: &str, config: &QuicConfig, peer_id: &str) {
    let protocol = ATP_QUIC_PROTOCOL.to_string();
    let symbol_size = config.symbol_size.to_string();
    let max_block_size = config.max_block_size.to_string();
    let max_datagram_size = config.max_datagram_size.to_string();
    let repair_overhead = format!("{:.4}", config.repair_overhead);
    let max_transfer_bytes = config.max_transfer_bytes.to_string();
    let chunk_size = config.chunk_size.to_string();
    let idle_timeout = format!("{:?}", config.idle_timeout);
    let handshake_timeout = format!("{:?}", config.handshake_timeout);
    let accept_timeout = format!("{:?}", config.accept_timeout);
    let max_active_connections = config.max_active_connections.to_string();
    let max_feedback_rounds = config.max_feedback_rounds.to_string();
    cx.trace_with_fields(
        "atp_quic.transport.start",
        &[
            ("operation", operation),
            ("protocol", &protocol),
            ("peer_id", peer_id),
            ("chunk_size", &chunk_size),
            ("symbol_size", &symbol_size),
            ("max_block_size", &max_block_size),
            ("max_datagram_size", &max_datagram_size),
            ("repair_overhead", &repair_overhead),
            ("max_transfer_bytes", &max_transfer_bytes),
            ("idle_timeout", &idle_timeout),
            ("handshake_timeout", &handshake_timeout),
            ("accept_timeout", &accept_timeout),
            ("max_active_connections", &max_active_connections),
            ("max_feedback_rounds", &max_feedback_rounds),
        ],
    );
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Transfer the file or directory at `source` to `addr` over a QUIC connection.
///
/// Mirrors [`transport_tcp::send_path`]. **Scaffold:** validates the config,
/// emits a config summary, then fails closed with
/// [`QuicTransportError::NotImplemented`]. Wired by B2
/// (`asupersync-arq-quic-epic-b0k8qo.2.2`).
///
/// [`transport_tcp::send_path`]: crate::net::atp::transport_tcp::send_path
pub async fn send_path(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<SendReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "send_path", &config, peer_id);
    // Inputs accepted but the wire path is not yet implemented; reference them so
    // the API shape is fixed without an unused-parameter warning.
    let _ = (&addr, source);
    Err(QuicTransportError::NotImplemented {
        operation: "send_path",
        wired_by: "asupersync-arq-quic-epic-b0k8qo.2.2 (B2: QUIC sender coroutine)",
    })
}

// ─── Public API: receive ─────────────────────────────────────────────────────

/// Accept exactly one transfer on `endpoint`, write it to `dest_dir`, verify it,
/// and return a report.
///
/// Mirrors [`transport_tcp::receive_once`] (with a [`ManagedQuicEndpoint`] in
/// place of a `TcpListener`). **Scaffold:** validates the config, emits a config
/// summary, then fails closed with [`QuicTransportError::NotImplemented`]. Wired
/// by B3 (`asupersync-arq-quic-epic-b0k8qo.2.3`).
///
/// [`transport_tcp::receive_once`]: crate::net::atp::transport_tcp::receive_once
pub async fn receive_once(
    cx: &Cx,
    endpoint: &ManagedQuicEndpoint,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "receive_once", &config, peer_id);
    let _ = (endpoint, dest_dir);
    Err(QuicTransportError::NotImplemented {
        operation: "receive_once",
        wired_by: "asupersync-arq-quic-epic-b0k8qo.2.3 (B3: QUIC receiver coroutine)",
    })
}

/// Drive a single accepted QUIC connection through the receive protocol.
///
/// Mirrors [`transport_tcp::receive_connection`] (with a
/// [`NativeQuicConnection`] in place of a `TcpStream`). **Scaffold:** validates
/// the config, emits a config summary, then fails closed with
/// [`QuicTransportError::NotImplemented`]. Wired by B3
/// (`asupersync-arq-quic-epic-b0k8qo.2.3`).
///
/// [`transport_tcp::receive_connection`]: crate::net::atp::transport_tcp::receive_connection
// `connection` is owned by value to mirror `transport_tcp::receive_connection`'s
// `stream: TcpStream` exactly; B3 consumes it to drive the receive protocol.
#[allow(clippy::needless_pass_by_value)]
pub async fn receive_connection(
    cx: &Cx,
    connection: NativeQuicConnection,
    peer: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "receive_connection", &config, peer_id);
    // `connection` is taken by value (it owns the accepted QUIC connection, as
    // `receive_connection` owns its `TcpStream`); borrow it so it drops normally
    // at scope end without an unused-variable warning.
    let _ = (&connection, &peer, dest_dir);
    Err(QuicTransportError::NotImplemented {
        operation: "receive_connection",
        wired_by: "asupersync-arq-quic-epic-b0k8qo.2.3 (B3: QUIC receiver coroutine)",
    })
}

/// Run a persistent accept loop, handling each accepted connection as a receive.
///
/// Mirrors [`transport_tcp::serve`] (with a [`ManagedQuicEndpoint`] in place of
/// a `TcpListener`). **Scaffold:** validates the config, emits a config summary,
/// then fails closed with [`QuicTransportError::NotImplemented`]. Wired by B3
/// (`asupersync-arq-quic-epic-b0k8qo.2.3`).
///
/// [`transport_tcp::serve`]: crate::net::atp::transport_tcp::serve
// Owned `endpoint` / `dest_dir` / `peer_id` / `on_result` mirror
// `transport_tcp::serve`'s by-value signature exactly; B3 consumes them when it
// drives the accept loop and spawns per-connection receive tasks.
#[allow(clippy::needless_pass_by_value)]
pub async fn serve<F>(
    cx: &Cx,
    endpoint: ManagedQuicEndpoint,
    dest_dir: PathBuf,
    config: QuicConfig,
    peer_id: String,
    on_result: F,
) -> Result<(), QuicTransportError>
where
    F: FnMut(Result<ReceiveReport, QuicTransportError>),
{
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "serve", &config, &peer_id);
    let _ = (&endpoint, &dest_dir, &on_result);
    Err(QuicTransportError::NotImplemented {
        operation: "serve",
        wired_by: "asupersync-arq-quic-epic-b0k8qo.2.3 (B3: QUIC receiver coroutine)",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::frames::{Frame, ProtocolVersion};
    use crate::net::quic_native::{
        DEFAULT_MAX_PACKET_BYTES, NativeQuicConnectionConfig, QuicConnection, StreamDirection,
        StreamRole, establish_loopback, pump_app_data, pump_until_idle,
    };

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        futures_lite::future::block_on(fut)
    }

    fn established_pair() -> (Cx<crate::cx::cap::All>, QuicConnection, QuicConnection) {
        let cx = Cx::for_testing();
        let mut client = QuicConnection::client(NativeQuicConnectionConfig::default());
        let mut server = QuicConnection::server(NativeQuicConnectionConfig::default());
        client.record_verified_server_identity();
        establish_loopback(&cx, &mut client, &mut server).expect("loopback establishes");
        (cx, client, server)
    }

    #[test]
    fn default_config_validates() {
        assert!(QuicConfig::default().validate().is_ok());
    }

    #[test]
    fn default_config_uses_published_constants() {
        let c = QuicConfig::default();
        assert_eq!(c.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(c.symbol_size, DEFAULT_SYMBOL_SIZE);
        assert_eq!(c.max_block_size, DEFAULT_MAX_BLOCK_SIZE);
        assert_eq!(c.max_datagram_size, DEFAULT_MAX_DATAGRAM_SIZE);
        assert_eq!(c.max_transfer_bytes, DEFAULT_MAX_TRANSFER_BYTES);
        assert_eq!(c.idle_timeout, DEFAULT_IDLE_TIMEOUT);
        assert_eq!(c.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
        assert_eq!(c.accept_timeout, DEFAULT_ACCEPT_TIMEOUT);
        assert_eq!(c.max_active_connections, DEFAULT_MAX_ACTIVE_CONNECTIONS);
        assert_eq!(c.max_feedback_rounds, DEFAULT_MAX_FEEDBACK_ROUNDS);
    }

    #[test]
    fn validate_rejects_zero_symbol_size() {
        let c = QuicConfig {
            symbol_size: 0,
            ..QuicConfig::default()
        };
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("symbol_size")
        ));
    }

    #[test]
    fn validate_rejects_datagram_smaller_than_symbol() {
        let c = QuicConfig {
            symbol_size: 2000,
            max_datagram_size: 1200,
            ..QuicConfig::default()
        };
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("max_datagram_size")
        ));
    }

    #[test]
    fn validate_requires_room_for_envelope_header() {
        // The raw symbol fits the datagram, but symbol + the (authenticated)
        // envelope header does not -> must still fail closed; the header is not
        // free, so checking only symbol_size <= max_datagram_size is too lax.
        let c = QuicConfig {
            symbol_size: 1199,
            max_datagram_size: 1200,
            ..QuicConfig::default()
        };
        assert!(usize::from(c.symbol_size) < c.max_datagram_size);
        assert!(usize::from(c.symbol_size) + AUTH_ENVELOPE_HEADER_LEN > c.max_datagram_size);
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("envelope header")
        ));
    }

    #[test]
    fn validate_rejects_repair_overhead_below_one_and_nan() {
        let low = QuicConfig {
            repair_overhead: 0.5,
            ..QuicConfig::default()
        };
        assert!(matches!(
            low.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("repair_overhead")
        ));
        let nan = QuicConfig {
            repair_overhead: f64::NAN,
            ..QuicConfig::default()
        };
        assert!(matches!(
            nan.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("repair_overhead")
        ));
    }

    #[test]
    fn validate_rejects_zero_timeouts() {
        for c in [
            QuicConfig {
                idle_timeout: Duration::ZERO,
                ..QuicConfig::default()
            },
            QuicConfig {
                handshake_timeout: Duration::ZERO,
                ..QuicConfig::default()
            },
            QuicConfig {
                accept_timeout: Duration::ZERO,
                ..QuicConfig::default()
            },
        ] {
            assert!(matches!(c.validate(), Err(QuicTransportError::Config(_))));
        }
    }

    #[test]
    fn not_implemented_error_names_operation_and_bead() {
        let e = QuicTransportError::NotImplemented {
            operation: "send_path",
            wired_by: "asupersync-arq-quic-epic-b0k8qo.2.2 (B2: QUIC sender coroutine)",
        };
        let rendered = e.to_string();
        assert!(rendered.contains("send_path"));
        assert!(rendered.contains("b0k8qo.2.2"));
        assert!(rendered.contains("failing closed"));
    }

    #[test]
    fn quic_frame_transport_round_trips_canonical_atp_frames() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);

        let hello = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::Handshake,
            b"hello".to_vec(),
        )
        .expect("handshake frame");
        let manifest = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectManifest,
            b"manifest-json".to_vec(),
        )
        .expect("manifest frame");

        tx.send(&cx, &mut client, &hello).expect("send hello");
        tx.send(&cx, &mut client, &manifest).expect("send manifest");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let got_hello = rx
            .try_recv(&cx, &mut server)
            .expect("decode hello")
            .expect("hello frame available");
        assert_eq!(got_hello.frame_type(), FrameType::Handshake);
        assert_eq!(got_hello.payload(), b"hello");

        let got_manifest = rx
            .try_recv(&cx, &mut server)
            .expect("decode manifest")
            .expect("manifest frame available");
        assert_eq!(got_manifest.frame_type(), FrameType::ObjectManifest);
        assert_eq!(got_manifest.payload(), b"manifest-json");
        assert!(
            rx.try_recv(&cx, &mut server)
                .expect("empty control stream")
                .is_none()
        );
    }

    #[test]
    fn quic_frame_transport_buffers_partial_frame_until_complete() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let first_client_bidi = crate::net::quic_native::StreamId::local(
            StreamRole::Client,
            StreamDirection::Bidirectional,
            0,
        );
        assert_eq!(tx.stream(), first_client_bidi);
        let mut rx = QuicFrameTransport::for_stream(first_client_bidi);

        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectManifest,
            vec![0xA5; 4096],
        )
        .expect("large manifest frame");
        tx.send(&cx, &mut client, &frame).expect("send large frame");

        let moved = pump_app_data(&cx, &mut client, &mut server, 256, 2_000)
            .expect("pump one partial packet");
        assert!(moved > 0);
        assert!(
            rx.try_recv(&cx, &mut server)
                .expect("partial frame is buffered")
                .is_none(),
            "partial control-frame bytes must not decode early"
        );

        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_001,
        )
        .expect("pump remaining frame bytes");
        let got = rx
            .try_recv(&cx, &mut server)
            .expect("decode complete frame")
            .expect("complete frame available");
        assert_eq!(got.frame_type(), FrameType::ObjectManifest);
        assert_eq!(got.payload(), &[0xA5; 4096]);
    }

    #[test]
    fn quic_frame_transport_round_trips_typed_json_control_payloads() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);
        let manifest = TransferManifest {
            transfer_id: "transfer42".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: 9,
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
                metadata: None,
            }],
        };

        tx.send_json(&cx, &mut client, FrameType::ObjectManifest, &manifest)
            .expect("send manifest JSON frame");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let got = rx
            .try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect("receive manifest JSON frame")
            .expect("manifest available");
        assert_eq!(got, manifest);
        assert!(
            rx.try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect("empty control stream")
            .is_none()
        );
    }

    #[test]
    fn quic_frame_transport_rejects_unexpected_json_control_frame_type() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);
        let receipt = ReceiveReceipt {
            committed: true,
            bytes_received: 9,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            reason: None,
            committed_paths: vec!["/dest/a/b.txt".to_string()],
        };

        tx.send_json(&cx, &mut client, FrameType::Proof, &receipt)
            .expect("send proof JSON frame");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let err = rx
            .try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect_err("wrong frame type must fail closed");
        match err {
            QuicTransportError::Unexpected { got, expected } => {
                assert_eq!(got, FrameType::Proof);
                assert_eq!(expected, "ObjectManifest");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn quic_frame_transport_rejects_malformed_json_control_payload() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);
        let bad = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectManifest,
            b"not-json".to_vec(),
        )
        .expect("malformed JSON frame");

        tx.send(&cx, &mut client, &bad)
            .expect("send malformed JSON frame");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let err = rx
            .try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect_err("malformed JSON must fail closed");
        assert!(matches!(err, QuicTransportError::Control(message) if !message.is_empty()));
    }

    #[test]
    fn quic_control_payloads_round_trip_as_json_frames() {
        let hello = QuicHello {
            protocol: ATP_QUIC_PROTOCOL,
            role: "sender".to_string(),
            peer_id: "peer-a".to_string(),
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: u64::try_from(DEFAULT_MAX_BLOCK_SIZE).unwrap_or(u64::MAX),
            symbol_auth: true,
        };
        let hello_frame = json_frame(FrameType::Handshake, &hello).expect("hello frame");
        assert_eq!(hello_frame.version(), ProtocolVersion::CURRENT);
        assert_eq!(hello_frame.frame_type(), FrameType::Handshake);
        assert_eq!(
            parse_json::<QuicHello>(&hello_frame).expect("parse hello"),
            hello
        );

        let ack = QuicHelloAck {
            accepted: false,
            peer_id: "peer-b".to_string(),
            reason: Some("unsupported protocol".to_string()),
        };
        let ack_frame = json_frame(FrameType::HandshakeAck, &ack).expect("ack frame");
        assert_eq!(ack_frame.frame_type(), FrameType::HandshakeAck);
        assert_eq!(
            parse_json::<QuicHelloAck>(&ack_frame).expect("parse ack"),
            ack
        );

        let need_more = QuicNeedMore {
            pending: vec![0, 2, 7],
        };
        let feedback_frame =
            json_frame(FrameType::ObjectRequest, &need_more).expect("feedback frame");
        assert_eq!(feedback_frame.frame_type(), FrameType::ObjectRequest);
        assert_eq!(
            parse_json::<QuicNeedMore>(&feedback_frame).expect("parse feedback"),
            need_more
        );
    }

    #[test]
    fn quic_control_handshake_accepts_matching_sender() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig::default();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            3_000,
        )
        .expect("deliver hello");

        let hello = receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        assert_eq!(hello.protocol, ATP_QUIC_PROTOCOL);
        assert_eq!(hello.peer_id, "sender-peer");
        assert_eq!(hello.symbol_size, DEFAULT_SYMBOL_SIZE);
        assert_eq!(
            hello.max_block_size,
            u64::try_from(DEFAULT_MAX_BLOCK_SIZE).unwrap_or(u64::MAX)
        );

        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            3_001,
        )
        .expect("deliver ack");
        let ack = receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives accepted ack");
        assert!(ack.accepted);
        assert_eq!(ack.peer_id, "receiver-peer");
        assert_eq!(ack.reason, None);
    }

    #[test]
    fn quic_control_handshake_rejects_wrong_protocol_and_reports_reason() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig::default();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        let bad_hello = QuicHello {
            protocol: ATP_QUIC_PROTOCOL + 99,
            role: "sender".to_string(),
            peer_id: "sender-peer".to_string(),
            symbol_size: config.symbol_size,
            max_block_size: u64::try_from(config.max_block_size).unwrap_or(u64::MAX),
            symbol_auth: false,
        };
        let frame = json_frame(FrameType::Handshake, &bad_hello).expect("bad hello frame");
        sender_control
            .send(&cx, &mut client, &frame)
            .expect("send bad hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            4_000,
        )
        .expect("deliver bad hello");

        let err = receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect_err("receiver rejects wrong protocol");
        assert!(matches!(
            err,
            QuicTransportError::HandshakeRejected(reason)
                if reason.contains("unsupported protocol")
        ));

        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            4_001,
        )
        .expect("deliver rejected ack");
        let err = receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect_err("sender sees rejected ack");
        assert!(matches!(
            err,
            QuicTransportError::HandshakeRejected(reason)
                if reason.contains("unsupported protocol")
        ));
    }

    #[test]
    fn parse_json_rejects_wrong_payload_shape() {
        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectRequest,
            b"not-json".to_vec(),
        )
        .expect("malformed json frame");

        assert!(matches!(
            parse_json::<QuicNeedMore>(&frame),
            Err(QuicTransportError::Control(message)) if !message.is_empty()
        ));
    }

    #[test]
    fn quic_entry_object_id_and_transfer_tag_are_deterministic() {
        let first_object = entry_object_id("transfer-1", 0);
        assert_eq!(first_object, entry_object_id("transfer-1", 0));
        assert_ne!(first_object, entry_object_id("transfer-1", 1));
        assert_ne!(first_object, entry_object_id("transfer-2", 0));

        let first_tag = transfer_tag("transfer-1");
        assert_eq!(first_tag, transfer_tag("transfer-1"));
        assert_ne!(first_tag, transfer_tag("transfer-2"));
        assert_ne!(first_tag, 0);
    }

    #[test]
    fn timeout_error_names_operation_and_duration() {
        let e = QuicTransportError::Timeout {
            operation: "receive frame",
            timeout: Duration::from_secs(60),
        };
        let rendered = e.to_string();
        assert!(rendered.contains("receive frame"));
        assert!(rendered.contains("60s"));
    }

    #[test]
    fn too_large_error_names_sizes() {
        let e = QuicTransportError::TooLarge { size: 99, max: 10 };
        let rendered = e.to_string();
        assert!(rendered.contains("99"));
        assert!(rendered.contains("10"));
    }

    #[test]
    fn streaming_error_maps_to_source() {
        let e: QuicTransportError = StreamingError::new("boom".to_string()).into();
        assert!(matches!(e, QuicTransportError::Source(m) if m.contains("boom")));
    }

    #[test]
    fn send_path_fails_closed_with_not_implemented() {
        let cx = Cx::for_testing();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(send_path(
            &cx,
            addr,
            Path::new("/nonexistent/source"),
            QuicConfig::default(),
            "sender",
        ));
        assert!(matches!(
            result,
            Err(QuicTransportError::NotImplemented {
                operation: "send_path",
                ..
            })
        ));
    }

    #[test]
    fn send_path_rejects_invalid_config_before_not_implemented() {
        let cx = Cx::for_testing();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let cfg = QuicConfig {
            idle_timeout: Duration::ZERO,
            ..QuicConfig::default()
        };
        let result = block_on(send_path(&cx, addr, Path::new("/x"), cfg, "sender"));
        assert!(matches!(result, Err(QuicTransportError::Config(_))));
    }

    #[test]
    fn receive_connection_fails_closed_with_not_implemented() {
        use crate::net::quic_native::NativeQuicConnectionConfig;
        let cx = Cx::for_testing();
        let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(receive_connection(
            &cx,
            conn,
            peer,
            Path::new("/tmp"),
            QuicConfig::default(),
            "receiver",
        ));
        assert!(matches!(
            result,
            Err(QuicTransportError::NotImplemented {
                operation: "receive_connection",
                ..
            })
        ));
    }

    #[test]
    fn reused_manifest_json_roundtrips() {
        let manifest = TransferManifest {
            transfer_id: "abc".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: 9,
            merkle_root_hex: "00".repeat(32),
            // J1 (b0k8qo.11.1, LilacPine): shared manifest gained an optional
            // metadata commitment + per-entry metadata; portable transfers leave
            // them None. Additive cross-edit to keep HEAD compiling.
            metadata_root_hex: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
                metadata: None,
            }],
        };
        let json = serde_json::to_vec(&manifest).unwrap();
        let back: TransferManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn reused_receipt_json_roundtrips() {
        let receipt = ReceiveReceipt {
            committed: true,
            bytes_received: 42,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            reason: None,
            committed_paths: vec!["/dest/a.txt".to_string()],
        };
        let json = serde_json::to_vec(&receipt).unwrap();
        let back: ReceiveReceipt = serde_json::from_slice(&json).unwrap();
        assert_eq!(receipt, back);
    }
}
