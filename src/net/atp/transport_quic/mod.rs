//! ATP-over-QUIC transport (Phase B scaffold).
//!
//! This module is the public-API skeleton for the *adaptive RaptorQ-over-QUIC*
//! data plane — the production ATP transport meant to beat rsync on lossy,
//! high-latency internet paths. It deliberately mirrors the public surface of
//! [`crate::net::atp::transport_tcp`] *exactly* so callers (the `atp` CLI, the
//! `atpd` daemon, fleet/loopback E2E harnesses) can target QUIC by swapping the
//! transport module and config type, with no other call-site changes.
//!
//! # Status: partially wired (`asupersync-arq-quic-epic-b0k8qo.2`)
//!
//! The endpoint-level send/receive coroutines still land in:
//!
//! - [`send_path`] → `asupersync-arq-quic-epic-b0k8qo.2.2` (B2: QUIC sender
//!   coroutine — connect, verify identity, manifest, encode + spray RaptorQ
//!   symbols across QUIC DATAGRAMs, fountain feedback).
//! - [`receive_once`] consumes one connection already routed into a
//!   [`ManagedQuicEndpoint`] and delegates to the wired accepted-connection
//!   receiver body. Live endpoint pumping and persistent serving remain B3
//!   follow-up work.
//! - [`serve`] drains connections already routed into a
//!   [`ManagedQuicEndpoint`] and delegates each one to the same accepted-
//!   connection receiver body. Live endpoint pumping and indefinite listener
//!   ownership remain native endpoint follow-up work.
//!
//! Until a given transfer entry point is wired, it **fails closed**: it
//! validates its configuration, emits a structured config summary, and returns
//! [`QuicTransportError::NotImplemented`]. There is no code path that reports a
//! fake success or moves zero bytes silently — the epic's non-negotiable
//! "every unwired op fails closed (typed error, never fake success)" rule.
//! [`receive_connection`] is the first wired B3 receiver surface: it consumes an
//! already-established native QUIC connection, verifies decoded entries, commits
//! them under the destination root, and returns a real report. [`receive_once`]
//! now removes a routed endpoint connection and drives that same body. [`serve`]
//! drains the currently routed queue with per-connection callbacks. Live
//! endpoint event-loop pumping and sender-side [`send_path`] native
//! connect/identity wiring remain fail-closed until their B2/B3 slices land.
//!
//! # Why a scaffold can land ahead of the Phase A data plane
//!
//! The tracker gates Phase B on Phase A (`...b0k8qo.1`, the QUIC application
//! data plane). That ordering is real for the *implementation* in B2/B3, which
//! consumes the Phase A DATAGRAM/STREAM/packet-protection surfaces. The
//! first scaffolds, however, only depended on already-landed pieces: the shared
//! bounded-memory helpers in [`crate::net::atp::transport_common`] (F0) and the
//! `transport_tcp` template it mirrors. The accepted-connection
//! [`receive_connection`] body now consumes the landed Phase A native STREAM and
//! DATAGRAM surfaces, while the still-unwired endpoint operations continue to
//! fail closed.
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
//! # Integrity & current memory boundary
//!
//! The accepted-connection receiver keeps `transport_tcp`'s fail-closed
//! integrity guarantee (per-entry SHA-256 + rebuilt flat-object-graph merkle
//! root vs. the manifest, atomic commit only on a full match). The Phase B QUIC
//! bridge is not yet B5 bounded-memory evidence: the sender still materializes
//! entry bytes for the current [`EncodingPipeline`] API and the receiver stores
//! decoded entry bytes before `write_atomic`. B5 must replace those transitional
//! `Vec<u8>` bridges with streaming/staging equivalents before claiming
//! `O(symbol/chunk size)` RSS.

pub mod symbol_datagram;
pub mod symbol_envelope;

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder;
use crate::config::EncodingConfig;
use crate::cx::Cx;
use crate::decoding::{
    DecodingConfig, DecodingPipeline, MissingSourceSymbol, RejectReason, SymbolAcceptResult,
};
use crate::encoding::EncodingPipeline;
use crate::io::AsyncReadExt;
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, MAX_FRAME_SIZE, ProtocolVersion};
use crate::net::atp::transport_common::{
    EntryDigest, SourceEntry, StreamingError, collect_entries, flat_merkle_root_from_digests,
    flat_merkle_root_from_slices, hash_file_streaming, hex_encode,
};
use crate::net::quic_native::{
    ManagedEndpointError, ManagedQuicEndpoint, NativeQuicConnection, QuicConnection,
    StreamDirection, StreamId, StreamRole,
};
use crate::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};

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

pub use crate::net::atp::transport_rq::adaptive::{
    AdaptiveController as QuicAdaptiveController, AdaptivePolicy as QuicAdaptivePolicy,
    BlockPlan as QuicAdaptiveBlockPlan, PathEstimate as QuicPathEstimate,
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

/// Default adaptive datagram fan-out hint.
///
/// Phase D wires true multi-connection fan-out. Until then this remains a
/// bounded, explicit controller output carried in the transfer config so C1 can
/// prove deterministic arm application without changing the single-connection
/// B2/B3 data path.
pub const DEFAULT_DATAGRAM_FANOUT: usize = 1;

/// Tuning knobs for the ATP-over-QUIC transport.
///
/// Mirrors the role of [`transport_tcp::TransferConfig`] while adding the
/// RaptorQ-over-QUIC knobs (symbol size, block size, repair overhead, datagram
/// budget, feedback rounds) that the B2/B3 coroutines will consume.
///
/// [`transport_tcp::TransferConfig`]: crate::net::atp::transport_tcp::TransferConfig
#[derive(Debug, Clone)]
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
    /// Adaptive controller's datagram fan-out hint.
    ///
    /// The current B2/B3 QUIC implementation uses one connection. This field
    /// intentionally records the selected C1 arm now; Phase D consumes it for
    /// multi-connection fan-out.
    pub datagram_fanout: usize,
    /// Optional per-symbol authentication context for QUIC DATAGRAM symbols.
    ///
    /// When present, senders append an HMAC tag to every symbol envelope and
    /// receivers verify every symbol before decoding.
    pub symbol_auth_context: Option<SecurityContext>,
    /// Explicit escape hatch for trusted loopback/lab links that intentionally
    /// accept integrity-vs-manifest only.
    pub allow_unauthenticated_symbols: bool,
}

/// Public per-symbol authentication posture for ATP-over-QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicSymbolAuthMode {
    /// Symbols are signed and verified with a configured [`SecurityContext`].
    Authenticated,
    /// Symbols are deliberately unauthenticated on a trusted loopback/lab link.
    TrustedUnauthenticated,
    /// No auth context was configured and no explicit trusted opt-out was set.
    MissingAuthenticationContext,
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
            datagram_fanout: DEFAULT_DATAGRAM_FANOUT,
            symbol_auth_context: None,
            allow_unauthenticated_symbols: false,
        }
    }
}

impl QuicConfig {
    /// Require per-symbol authentication with this context.
    #[must_use]
    pub fn with_symbol_auth(mut self, context: SecurityContext) -> Self {
        self.symbol_auth_context = Some(context);
        self.allow_unauthenticated_symbols = false;
        self
    }

    /// Explicitly allow unauthenticated symbols for trusted loopback/lab links.
    #[must_use]
    pub fn allow_unauthenticated_for_trusted_transport(mut self) -> Self {
        self.symbol_auth_context = None;
        self.allow_unauthenticated_symbols = true;
        self
    }

    /// Return the configured per-symbol authentication posture.
    #[must_use]
    pub fn symbol_auth_mode(&self) -> QuicSymbolAuthMode {
        if self.symbol_auth_context.is_some() {
            return QuicSymbolAuthMode::Authenticated;
        }
        if self.allow_unauthenticated_symbols {
            return QuicSymbolAuthMode::TrustedUnauthenticated;
        }
        QuicSymbolAuthMode::MissingAuthenticationContext
    }

    /// Validate that the symbol-auth posture is deliberate.
    pub fn validate_symbol_auth_mode(&self) -> Result<(), QuicTransportError> {
        self.symbol_auth_context().map(|_| ())
    }

    fn symbol_auth_context(&self) -> Result<Option<SecurityContext>, QuicTransportError> {
        if let Some(context) = &self.symbol_auth_context {
            return Ok(Some(context.clone()));
        }
        if self.allow_unauthenticated_symbols {
            return Ok(None);
        }
        Err(QuicTransportError::Config(
            "ATP-over-QUIC requires symbol_auth_context; call with_symbol_auth(...) or \
             explicitly opt into allow_unauthenticated_for_trusted_transport() for loopback/lab use"
                .to_string(),
        ))
    }

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
        if self.datagram_fanout == 0 {
            return Err(QuicTransportError::Config(
                "datagram_fanout must be greater than 0".to_string(),
            ));
        }
        self.validate_symbol_auth_mode()?;
        Ok(())
    }
}

/// QUIC-side adaptive arm selected by the deterministic C1 controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuicAdaptiveArm {
    /// Source symbols per RaptorQ block.
    pub k: u32,
    /// QUIC transfer repair multiplier (`1.0 + extra_repair_fraction`).
    pub repair_overhead: f64,
    /// Datagram fan-out hint for Phase D multi-connection spray.
    pub datagram_fanout: usize,
}

impl QuicAdaptiveArm {
    /// Convert the shared adaptive controller's block plan into QUIC config
    /// terms. The shared controller reports overhead as an extra fraction; the
    /// QUIC transfer config stores the multiplier used by the encoder.
    pub fn from_block_plan(plan: QuicAdaptiveBlockPlan) -> Result<Self, QuicTransportError> {
        if plan.k == 0 {
            return Err(QuicTransportError::Config(
                "adaptive arm k must be greater than 0".to_string(),
            ));
        }
        if !plan.overhead.is_finite() || plan.overhead < 0.0 {
            return Err(QuicTransportError::Config(format!(
                "adaptive arm overhead ({}) must be finite and >= 0.0",
                plan.overhead
            )));
        }
        if plan.fanout == 0 {
            return Err(QuicTransportError::Config(
                "adaptive arm fanout must be greater than 0".to_string(),
            ));
        }
        Ok(Self {
            k: plan.k,
            repair_overhead: 1.0 + plan.overhead,
            datagram_fanout: plan.fanout,
        })
    }

    /// Apply this arm to a transfer config. This is pure and side-effect-free;
    /// the caller can run it once per epoch and pass the returned config into
    /// the existing B2/B3 transfer helpers.
    pub fn apply_to_config(self, mut config: QuicConfig) -> Result<QuicConfig, QuicTransportError> {
        let k = usize::try_from(self.k).map_err(|_| {
            QuicTransportError::Config(format!("adaptive arm k ({}) does not fit usize", self.k))
        })?;
        config.max_block_size =
            usize::from(config.symbol_size)
                .checked_mul(k)
                .ok_or_else(|| {
                    QuicTransportError::Config(format!(
                        "adaptive arm k ({}) overflows max_block_size for symbol_size {}",
                        self.k, config.symbol_size
                    ))
                })?;
        config.repair_overhead = self.repair_overhead;
        config.datagram_fanout = self.datagram_fanout;
        config.validate()?;
        Ok(config)
    }
}

/// Apply a shared adaptive controller block plan to QUIC transfer configuration.
pub fn apply_quic_adaptive_block_plan(
    config: QuicConfig,
    plan: QuicAdaptiveBlockPlan,
) -> Result<QuicConfig, QuicTransportError> {
    QuicAdaptiveArm::from_block_plan(plan)?.apply_to_config(config)
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
    /// The fountain feedback loop exhausted its configured round budget.
    #[error(
        "transfer did not converge after {rounds} feedback rounds ({pending} entries still incomplete)"
    )]
    NoConvergence {
        /// Feedback rounds attempted.
        rounds: u32,
        /// Entries still undecoded.
        pending: usize,
    },
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

impl From<ManagedEndpointError> for QuicTransportError {
    fn from(err: ManagedEndpointError) -> Self {
        match err {
            ManagedEndpointError::Cancelled => Self::Cancelled,
            other => Self::Quic(other.to_string()),
        }
    }
}

impl From<SymbolDatagramError> for QuicTransportError {
    fn from(err: SymbolDatagramError) -> Self {
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
    /// Entry indices that have not yet decoded.
    pending: Vec<u32>,
    /// Sparse systematic source symbols missing from incomplete blocks.
    #[serde(default)]
    source_symbols: Vec<QuicSourceSymbolRequest>,
}

/// Request for retransmission of one systematic source symbol.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct QuicSourceSymbolRequest {
    entry: u32,
    sbn: u8,
    esi: u32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum QuicControlReply {
    Proof(ReceiveReceipt),
    NeedMore(QuicNeedMore),
}

#[allow(dead_code)]
fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, QuicTransportError> {
    let payload =
        serde_json::to_vec(value).map_err(|err| QuicTransportError::Control(err.to_string()))?;
    let frame = Frame::new(ProtocolVersion::CURRENT, ty, payload)
        .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    let encoded_len = u64::try_from(frame.encoded_len()).unwrap_or(u64::MAX);
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

#[allow(dead_code)]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

#[allow(dead_code)]
fn transfer_id_hex(merkle_root_hex: &str, total_bytes: u64, file_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.quic.transfer-id.v1\0");
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update(u64::try_from(file_count).unwrap_or(u64::MAX).to_be_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest[..16])
}

#[allow(dead_code)]
fn manifest_from_entries(
    root_name: &str,
    is_directory: bool,
    entries: &[(String, Vec<u8>)],
) -> TransferManifest {
    let total_bytes = entries.iter().fold(0u64, |acc, (_, bytes)| {
        acc.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
    });
    let merkle_root_hex = flat_merkle_root_from_slices(
        entries
            .iter()
            .map(|(rel_path, bytes)| (rel_path.as_str(), bytes.as_slice())),
    );
    let manifest_entries = entries
        .iter()
        .enumerate()
        .map(|(i, (rel_path, bytes))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: rel_path.clone(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256_hex: sha256_hex(bytes),
            metadata: None,
        })
        .collect::<Vec<_>>();
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, manifest_entries.len());
    TransferManifest {
        transfer_id,
        root_name: root_name.to_string(),
        is_directory,
        total_bytes,
        merkle_root_hex,
        metadata_root_hex: None,
        entries: manifest_entries,
    }
}

#[allow(dead_code)]
struct QuicEntryEncoder {
    index: u32,
    object_id: ObjectId,
    bytes: Vec<u8>,
    repair_cursor: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct QuicSourceEntry {
    index: u32,
    rel_path: String,
    abs_path: PathBuf,
    size: u64,
    object_id: ObjectId,
    sha256_hex: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct QuicPreparedSource {
    manifest: TransferManifest,
    entries: Vec<QuicSourceEntry>,
}

#[allow(dead_code)]
struct QuicEntryDecoder {
    index: u32,
    object_id: ObjectId,
    size: u64,
    pipeline: Option<DecodingPipeline>,
    complete: bool,
    data: Vec<u8>,
}

#[allow(dead_code)]
struct QuicConnectionTransferOutcome {
    manifest: TransferManifest,
    send_report: SendReport,
    receipt: ReceiveReceipt,
    symbols_sent: u64,
    symbols_accepted: u64,
}

#[allow(dead_code)]
struct QuicSenderFeedbackState<'a> {
    manifest: &'a TransferManifest,
    encoders: &'a mut [QuicEntryEncoder],
    config: &'a QuicConfig,
    peer: SocketAddr,
    feedback_rounds: u32,
    symbols_sent: u64,
}

#[allow(dead_code)]
impl<'a> QuicSenderFeedbackState<'a> {
    fn new(
        manifest: &'a TransferManifest,
        encoders: &'a mut [QuicEntryEncoder],
        config: &'a QuicConfig,
        peer: SocketAddr,
        symbols_sent: u64,
    ) -> Self {
        Self {
            manifest,
            encoders,
            config,
            peer,
            feedback_rounds: 0,
            symbols_sent,
        }
    }
}

#[allow(dead_code)]
fn encoders_from_entries(
    manifest: &TransferManifest,
    entries: &[(String, Vec<u8>)],
) -> Vec<QuicEntryEncoder> {
    manifest
        .entries
        .iter()
        .zip(entries)
        .map(|(entry, (_, bytes))| QuicEntryEncoder {
            index: entry.index,
            object_id: entry_object_id(&manifest.transfer_id, entry.index),
            bytes: bytes.clone(),
            repair_cursor: 0,
        })
        .collect()
}

#[allow(dead_code)]
async fn prepare_source_manifest(
    cx: &Cx,
    source: &Path,
    config: &QuicConfig,
) -> Result<QuicPreparedSource, QuicTransportError> {
    config.validate()?;
    let (root_name, is_directory, source_entries) = collect_entries(source).await?;
    let _ = quic_safe_base_for_root_name(Path::new("base"), &root_name)?;
    if is_directory && source_entries.is_empty() {
        return Err(QuicTransportError::Source(format!(
            "transport_quic does not yet encode empty directory root {root_name}"
        )));
    }
    let mut read_buf = vec![0_u8; config.chunk_size];
    let mut digests = Vec::with_capacity(source_entries.len());
    let mut total_bytes = 0u64;

    for source_entry in &source_entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        quic_join_relative(Path::new("base"), &source_entry.rel_path)?;
        reject_unencoded_source_entry(source_entry).await?;

        let (size, content_id, content_sha256) =
            hash_file_streaming(&source_entry.abs_path, &mut read_buf).await?;
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(QuicTransportError::TooLarge {
                size: u64::MAX,
                max: config.max_transfer_bytes,
            })?;
        if total_bytes > config.max_transfer_bytes {
            return Err(QuicTransportError::TooLarge {
                size: total_bytes,
                max: config.max_transfer_bytes,
            });
        }
        digests.push(EntryDigest {
            rel_path: source_entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
    }

    let merkle_root_hex = flat_merkle_root_from_digests(&digests);
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, digests.len());
    let manifest_entries = digests
        .iter()
        .enumerate()
        .map(|(i, digest)| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: digest.rel_path.clone(),
            size: digest.size,
            sha256_hex: hex_encode(&digest.content_sha256),
            metadata: None,
        })
        .collect::<Vec<_>>();
    let manifest = TransferManifest {
        transfer_id,
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex,
        metadata_root_hex: None,
        entries: manifest_entries,
    };
    validate_quic_manifest(&manifest, config)?;

    let entries = source_entries
        .into_iter()
        .zip(digests)
        .map(|(source_entry, digest)| {
            let entry = &manifest.entries[digest_index(&manifest, &digest.rel_path)?];
            Ok(QuicSourceEntry {
                index: entry.index,
                rel_path: entry.rel_path.clone(),
                abs_path: source_entry.abs_path,
                size: entry.size,
                object_id: entry_object_id(&manifest.transfer_id, entry.index),
                sha256_hex: entry.sha256_hex.clone(),
            })
        })
        .collect::<Result<Vec<_>, QuicTransportError>>()?;

    Ok(QuicPreparedSource { manifest, entries })
}

fn digest_index(manifest: &TransferManifest, rel_path: &str) -> Result<usize, QuicTransportError> {
    manifest
        .entries
        .iter()
        .position(|entry| entry.rel_path == rel_path)
        .ok_or_else(|| {
            QuicTransportError::Source(format!(
                "prepared source entry {rel_path} missing from manifest"
            ))
        })
}

async fn reject_unencoded_source_entry(entry: &SourceEntry) -> Result<(), QuicTransportError> {
    let meta = crate::fs::metadata(&entry.abs_path)
        .await
        .map_err(|err| StreamingError::new(format!("{}: {err}", entry.abs_path.display())))?;
    if meta.is_file() {
        return Ok(());
    }
    if meta.is_dir() {
        return Err(QuicTransportError::Source(format!(
            "transport_quic does not yet encode explicit directory entry {}",
            entry.rel_path
        )));
    }
    Err(QuicTransportError::Source(format!(
        "{}: not a regular file",
        entry.abs_path.display()
    )))
}

#[allow(dead_code)]
fn object_params_for(
    object_id: ObjectId,
    size: u64,
    symbol_size: u16,
    max_block_size: usize,
) -> ObjectParams {
    let symbol_size_usize = usize::from(symbol_size.max(1));
    let total = usize::try_from(size).unwrap_or(usize::MAX);
    let mut blocks = 0u16;
    let mut max_k = 0usize;
    if total > 0 {
        let mut offset = 0usize;
        let block_limit = max_block_size.max(1);
        while offset < total {
            let len = (total - offset).min(block_limit);
            let k = len.div_ceil(symbol_size_usize);
            max_k = max_k.max(k);
            blocks = blocks.saturating_add(1);
            offset += len;
        }
    }
    ObjectParams::new(
        object_id,
        size,
        symbol_size,
        blocks,
        u16::try_from(max_k).unwrap_or(u16::MAX),
    )
}

#[allow(dead_code)]
fn decoders_from_manifest(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<Vec<QuicEntryDecoder>, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();
    manifest
        .entries
        .iter()
        .map(|entry| {
            let object_id = entry_object_id(&manifest.transfer_id, entry.index);
            let dconfig = DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                repair_overhead: config.repair_overhead,
                min_overhead: 0,
                max_buffered_symbols: 0,
                block_timeout: Duration::from_secs(0),
                verify_auth: symbol_auth_enabled,
            };
            let mut pipeline = if let Some(context) = &symbol_auth {
                DecodingPipeline::with_auth(dconfig, context.clone())
            } else {
                DecodingPipeline::new(dconfig)
            };
            let params = object_params_for(
                object_id,
                entry.size,
                config.symbol_size,
                config.max_block_size,
            );
            pipeline.set_object_params(params).map_err(|err| {
                QuicTransportError::Control(format!(
                    "entry {} RaptorQ object metadata rejected: {err}",
                    entry.index
                ))
            })?;
            Ok(QuicEntryDecoder {
                index: entry.index,
                object_id,
                size: entry.size,
                pipeline: Some(pipeline),
                complete: entry.size == 0,
                data: Vec::new(),
            })
        })
        .collect()
}

#[allow(dead_code)]
fn encoding_pipeline(config: &QuicConfig) -> EncodingPipeline {
    EncodingPipeline::new(
        EncodingConfig {
            repair_overhead: config.repair_overhead,
            max_block_size: config.max_block_size,
            symbol_size: config.symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        SymbolPool::new(PoolConfig::default()),
    )
}

#[allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn initial_repair_per_block(data_len: usize, config: &QuicConfig) -> usize {
    if config.repair_overhead <= 1.0 {
        0
    } else {
        let block_source_symbols = data_len
            .min(config.max_block_size.max(1))
            .div_ceil(usize::from(config.symbol_size.max(1)))
            .max(1);
        ((block_source_symbols as f64) * (config.repair_overhead - 1.0)).ceil() as usize
    }
}

fn repair_batch_per_block(config: &QuicConfig) -> usize {
    let block_k = config
        .max_block_size
        .div_ceil(usize::from(config.symbol_size.max(1)))
        .max(1);
    (block_k / 4).max(16)
}

#[allow(dead_code)]
fn spray_symbol_round(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    pending: &std::collections::BTreeSet<u32>,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    with_source: bool,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let repair_batch = repair_batch_per_block(config);
    for entry in encoders
        .iter_mut()
        .filter(|entry| pending.contains(&entry.index))
    {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let already = entry.repair_cursor;
        let target_repair = if with_source {
            initial_repair_per_block(entry.bytes.len(), config)
        } else {
            already.saturating_add(repair_batch)
        };
        let repair_count = target_repair.saturating_sub(already);
        if !with_source && repair_count == 0 {
            entry.repair_cursor = target_repair;
            continue;
        }

        let mut pipeline = encoding_pipeline(config);
        if with_source {
            for encoded in pipeline.encode_with_repair(entry.object_id, &entry.bytes, target_repair)
            {
                let symbol = encoded
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
            }
        } else {
            for encoded in
                pipeline.encode_repair_range(entry.object_id, &entry.bytes, already, repair_count)
            {
                let symbol = encoded
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
            }
        }
        entry.repair_cursor = target_repair;
    }
    Ok(sent)
}

#[allow(dead_code)]
fn source_symbol_for_request(
    enc: &QuicEntryEncoder,
    request: QuicSourceSymbolRequest,
    config: &QuicConfig,
) -> Result<Symbol, QuicTransportError> {
    if request.entry != enc.index {
        return Err(QuicTransportError::Integrity(format!(
            "source request entry mismatch: request={}, encoder={}",
            request.entry, enc.index
        )));
    }
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_start = usize::from(request.sbn)
        .checked_mul(config.max_block_size)
        .ok_or_else(|| {
            QuicTransportError::Integrity("source request block offset overflow".to_string())
        })?;
    if block_start >= enc.bytes.len() {
        return Err(QuicTransportError::Integrity(format!(
            "source request block {} outside entry {} ({} bytes)",
            request.sbn,
            enc.index,
            enc.bytes.len()
        )));
    }

    let block_len = config.max_block_size.min(enc.bytes.len() - block_start);
    let block_k = block_len.div_ceil(symbol_size).max(1);
    let esi = usize::try_from(request.esi).map_err(|_| {
        QuicTransportError::Integrity("source request ESI does not fit usize".to_string())
    })?;
    if esi >= block_k {
        return Err(QuicTransportError::Integrity(format!(
            "source request esi {} outside entry {} block {} K={}",
            request.esi, enc.index, request.sbn, block_k
        )));
    }

    let start = block_start + esi * symbol_size;
    let end = (start + symbol_size).min(block_start + block_len);
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        buffer[..end - start].copy_from_slice(&enc.bytes[start..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

#[allow(dead_code)]
fn send_source_symbol_requests(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &[QuicEntryEncoder],
    requests: &[QuicSourceSymbolRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let enc = encoders
            .iter()
            .find(|entry| entry.index == request.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "receiver requested source symbol for unknown entry {}",
                    request.entry
                ))
            })?;
        let symbol = source_symbol_for_request(enc, *request, config)?;
        let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
        send_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
        sent = sent.saturating_add(1);
    }
    Ok(sent)
}

#[allow(dead_code)]
fn spray_initial_symbols(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let pending = encoders
        .iter()
        .map(|entry| entry.index)
        .collect::<std::collections::BTreeSet<_>>();
    spray_symbol_round(
        cx,
        conn,
        manifest,
        encoders,
        &pending,
        config,
        symbol_auth,
        true,
    )
}

#[allow(dead_code)]
fn send_repair_round_and_object_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    need: &QuicNeedMore,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    if need.pending.is_empty() && need.source_symbols.is_empty() {
        send_object_complete(cx, conn, control)?;
        return Ok(0);
    }
    for entry in &need.pending {
        if !manifest
            .entries
            .iter()
            .any(|manifest| manifest.index == *entry)
        {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair for unknown entry {entry}"
            )));
        }
    }
    let pending = need
        .pending
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for request in &need.source_symbols {
        if !pending.contains(&request.entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested source symbol for non-pending entry {}",
                request.entry
            )));
        }
    }
    let sent = if need.source_symbols.is_empty() {
        spray_symbol_round(
            cx,
            conn,
            manifest,
            encoders,
            &pending,
            config,
            symbol_auth,
            false,
        )?
    } else {
        send_source_symbol_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.source_symbols,
            config,
            symbol_auth,
        )?
    };
    send_object_complete(cx, conn, control)?;
    Ok(sent)
}

#[allow(dead_code)]
async fn read_source_entry_bytes(
    cx: &Cx,
    entry: &QuicSourceEntry,
    config: &QuicConfig,
) -> Result<Vec<u8>, QuicTransportError> {
    // Transitional bridge: the manifest hash pass is streaming, but the
    // current EncodingPipeline API still accepts an in-memory object payload.
    // Do not use this helper as bounded-memory evidence for B5.
    let capacity = usize::try_from(entry.size).map_err(|_| QuicTransportError::TooLarge {
        size: entry.size,
        max: config.max_transfer_bytes,
    })?;
    let mut file = crate::fs::File::open(&entry.abs_path)
        .await
        .map_err(|err| {
            QuicTransportError::Source(format!("{}: {err}", entry.abs_path.display()))
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut buf = vec![0_u8; config.chunk_size.max(1)];
    let mut read = 0u64;
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let n = file.read(&mut buf).await.map_err(|err| {
            QuicTransportError::Source(format!("{}: {err}", entry.abs_path.display()))
        })?;
        if n == 0 {
            break;
        }
        read = read.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if read > entry.size {
            return Err(QuicTransportError::Source(format!(
                "{} grew while preparing QUIC symbols (read {read} bytes, manifest size {})",
                entry.abs_path.display(),
                entry.size
            )));
        }
        bytes.extend_from_slice(&buf[..n]);
    }

    if read != entry.size {
        return Err(QuicTransportError::Source(format!(
            "{} changed while preparing QUIC symbols (read {read} bytes, manifest size {})",
            entry.abs_path.display(),
            entry.size
        )));
    }
    let got_sha = sha256_hex(&bytes);
    if got_sha != entry.sha256_hex {
        return Err(QuicTransportError::Integrity(format!(
            "{} changed while preparing QUIC symbols (sha256 {got_sha}, manifest {})",
            entry.abs_path.display(),
            entry.sha256_hex
        )));
    }
    Ok(bytes)
}

#[allow(dead_code)]
async fn encoders_from_prepared_source(
    cx: &Cx,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<Vec<QuicEntryEncoder>, QuicTransportError> {
    let mut encoders = Vec::with_capacity(prepared.entries.len());
    for entry in &prepared.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let bytes = read_source_entry_bytes(cx, entry, config).await?;
        encoders.push(QuicEntryEncoder {
            index: entry.index,
            object_id: entry.object_id,
            bytes,
            repair_cursor: 0,
        });
    }
    Ok(encoders)
}

#[allow(dead_code)]
fn send_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    let symbol_auth = config.symbol_auth_context()?;
    send_manifest(cx, conn, control, manifest)?;
    let symbols_sent =
        spray_initial_symbols(cx, conn, manifest, encoders, config, symbol_auth.as_ref())?;
    send_object_complete(cx, conn, control)?;
    Ok(symbols_sent)
}

#[allow(dead_code)]
async fn send_prepared_source_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(&prepared.manifest, config)?;
    let mut encoders = encoders_from_prepared_source(cx, prepared, config).await?;
    send_manifest_symbols_complete(cx, conn, control, &prepared.manifest, &mut encoders, config)
}

#[allow(dead_code)]
fn finish_sender_transfer(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    peer: SocketAddr,
    receipt: ReceiveReceipt,
) -> Result<SendReport, QuicTransportError> {
    send_close(cx, conn, control)?;
    if !receipt.committed {
        return Err(QuicTransportError::Integrity(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit".to_string()),
        ));
    }

    Ok(SendReport {
        transfer_id: manifest.transfer_id.clone(),
        bytes_sent: manifest.total_bytes,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        merkle_root_hex: manifest.merkle_root_hex.clone(),
        receipt,
        peer,
    })
}

#[allow(dead_code)]
fn handle_sender_feedback_or_proof(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    state: &mut QuicSenderFeedbackState<'_>,
) -> Result<Option<SendReport>, QuicTransportError> {
    match receive_proof_or_need_more(cx, conn, control)? {
        QuicControlReply::Proof(receipt) => {
            finish_sender_transfer(cx, conn, control, state.manifest, state.peer, receipt).map(Some)
        }
        QuicControlReply::NeedMore(need) => {
            state.feedback_rounds = state.feedback_rounds.saturating_add(1);
            if state.feedback_rounds > state.config.max_feedback_rounds {
                return Err(QuicTransportError::NoConvergence {
                    rounds: state.feedback_rounds,
                    pending: need.pending.len(),
                });
            }
            if need.pending.is_empty() && need.source_symbols.is_empty() {
                return Ok(None);
            }
            let symbol_auth = state.config.symbol_auth_context()?;
            let sent = send_repair_round_and_object_complete(
                cx,
                conn,
                control,
                state.manifest,
                state.encoders,
                &need,
                state.config,
                symbol_auth.as_ref(),
            )?;
            state.symbols_sent = state.symbols_sent.saturating_add(sent);
            Ok(None)
        }
    }
}

#[allow(dead_code)]
fn receive_proof_close_and_report(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    peer: SocketAddr,
) -> Result<SendReport, QuicTransportError> {
    let receipt = match receive_proof_or_need_more(cx, conn, control)? {
        QuicControlReply::Proof(receipt) => receipt,
        QuicControlReply::NeedMore(need) => {
            return Err(QuicTransportError::Integrity(format!(
                "sender received NeedMore instead of proof for entries {:?}",
                need.pending
            )));
        }
    };
    finish_sender_transfer(cx, conn, control, manifest, peer, receipt)
}

#[allow(dead_code)]
fn feed_authenticated_symbol(
    decoder: &mut QuicEntryDecoder,
    auth_symbol: AuthenticatedSymbol,
) -> Result<bool, QuicTransportError> {
    if decoder.complete {
        return Ok(false);
    }
    let Some(pipeline) = decoder.pipeline.as_mut() else {
        return Ok(false);
    };
    match pipeline.feed(auth_symbol) {
        Ok(
            SymbolAcceptResult::Accepted { .. }
            | SymbolAcceptResult::DecodingStarted { .. }
            | SymbolAcceptResult::BlockComplete { .. },
        ) => Ok(true),
        Ok(SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed)) => Err(
            QuicTransportError::Integrity("symbol authentication failed".to_string()),
        ),
        Ok(SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_)) => Ok(false),
        Err(err) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected symbol: {err}"
        ))),
    }
}

fn authenticated_symbol_from_envelope(
    envelope: &QuicSymbolEnvelope,
    object_id: ObjectId,
    auth_required: bool,
) -> Result<AuthenticatedSymbol, QuicTransportError> {
    let symbol = envelope_to_symbol(envelope, object_id);
    if auth_required {
        let tag = envelope.auth_tag.ok_or_else(|| {
            QuicTransportError::Integrity("authenticated symbol envelope missing tag".to_string())
        })?;
        return Ok(AuthenticatedSymbol::from_parts(
            symbol,
            AuthenticationTag::from_bytes(tag),
        ));
    }
    Ok(AuthenticatedSymbol::new_unauthenticated(symbol))
}

#[allow(dead_code)]
fn drain_symbol_datagrams(
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut accepted = 0u64;
    while let Some(envelope) = recv_symbol_envelope(conn, auth_required)? {
        if envelope.transfer_tag != tag {
            return Err(QuicTransportError::Integrity(format!(
                "symbol transfer tag mismatch: got {}, expected {tag}",
                envelope.transfer_tag
            )));
        }
        if envelope.payload.len() != usize::from(config.symbol_size) {
            return Err(QuicTransportError::Integrity(format!(
                "symbol payload has {} bytes, expected {}",
                envelope.payload.len(),
                config.symbol_size
            )));
        }
        let decoder = decoders
            .iter_mut()
            .find(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        let auth_symbol =
            authenticated_symbol_from_envelope(&envelope, decoder.object_id, auth_required)?;
        if feed_authenticated_symbol(decoder, auth_symbol)? {
            accepted = accepted.saturating_add(1);
        }
    }
    Ok(accepted)
}

#[allow(dead_code)]
fn assemble_completed_entries(decoders: &mut [QuicEntryDecoder]) {
    for decoder in decoders {
        if decoder.complete
            || !decoder
                .pipeline
                .as_ref()
                .is_some_and(DecodingPipeline::is_complete)
        {
            continue;
        }
        let Some(pipeline) = decoder.pipeline.take() else {
            continue;
        };
        if let Ok(mut bytes) = pipeline.into_data() {
            bytes.truncate(usize::try_from(decoder.size).unwrap_or(usize::MAX));
            decoder.data = bytes;
            decoder.complete = true;
        }
    }
}

#[allow(dead_code)]
fn pending_entries(decoders: &[QuicEntryDecoder]) -> Vec<u32> {
    decoders
        .iter()
        .filter(|decoder| !decoder.complete)
        .map(|decoder| decoder.index)
        .collect()
}

#[allow(dead_code)]
fn source_symbol_requests(
    decoders: &[QuicEntryDecoder],
    limit: usize,
) -> Vec<QuicSourceSymbolRequest> {
    let mut requests = Vec::new();
    for decoder in decoders {
        if decoder.complete {
            continue;
        }
        let Some(pipeline) = decoder.pipeline.as_ref() else {
            continue;
        };
        let remaining = if limit == 0 {
            0
        } else {
            limit.saturating_sub(requests.len())
        };
        if limit != 0 && remaining == 0 {
            break;
        }
        requests.extend(pipeline.missing_source_symbols(remaining).into_iter().map(
            |MissingSourceSymbol { sbn, esi }| QuicSourceSymbolRequest {
                entry: decoder.index,
                sbn,
                esi,
            },
        ));
        if limit != 0 && requests.len() >= limit {
            break;
        }
    }
    requests
}

#[allow(dead_code)]
fn verify_in_memory_receipt(
    manifest: &TransferManifest,
    decoders: &[QuicEntryDecoder],
) -> ReceiveReceipt {
    let mut decoded = std::collections::HashMap::new();
    for decoder in decoders {
        decoded.insert(decoder.index, decoder.data.clone());
    }

    let mut sha_ok = true;
    let mut received = 0u64;
    for entry in &manifest.entries {
        let Some(bytes) = decoded.get(&entry.index) else {
            sha_ok = false;
            continue;
        };
        received = received.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != entry.size
            || sha256_hex(bytes) != entry.sha256_hex
        {
            sha_ok = false;
        }
    }

    let rebuilt = manifest
        .entries
        .iter()
        .map(|entry| {
            (
                entry.rel_path.clone(),
                decoded.get(&entry.index).cloned().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let merkle_ok = flat_merkle_root_from_slices(
        rebuilt
            .iter()
            .map(|(rel_path, bytes)| (rel_path.as_str(), bytes.as_slice())),
    ) == manifest.merkle_root_hex;
    let committed = sha_ok && merkle_ok && pending_entries(decoders).is_empty();
    let committed_paths = if committed {
        manifest
            .entries
            .iter()
            .map(|entry| format!("/quic-memory/{}/{}", manifest.root_name, entry.rel_path))
            .collect()
    } else {
        Vec::new()
    };
    ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        sha_ok,
        merkle_ok,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else if !merkle_ok {
            Some("merkle-root mismatch".to_string())
        } else {
            Some("entries still pending".to_string())
        },
        committed_paths,
    }
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

/// ATP frame transport over an accepted native QUIC control stream.
///
/// This mirrors [`QuicFrameTransport`] for the B3 public receive path, whose
/// API accepts a [`NativeQuicConnection`] by value. The lower native connection
/// already owns reassembled stream bytes and buffered DATAGRAM payloads for an
/// accepted peer, but it is not wrapped in the high-level [`QuicConnection`]
/// handle. Keep this adapter small and receiver-scoped until the managed
/// endpoint exposes a first-class accepted-connection handle.
#[allow(dead_code)]
struct NativeQuicFrameTransport {
    stream: StreamId,
    codec: AtpFrameCodec,
    rbuf: BytesMut,
}

#[allow(dead_code)]
impl NativeQuicFrameTransport {
    fn for_stream(stream: StreamId) -> Self {
        Self {
            stream,
            codec: AtpFrameCodec::new(),
            rbuf: BytesMut::new(),
        }
    }

    fn send(
        &mut self,
        cx: &Cx,
        conn: &mut NativeQuicConnection,
        frame: &Frame,
    ) -> Result<(), QuicTransportError> {
        let wire = frame
            .to_wire_bytes()
            .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
        conn.write_stream_bytes(cx, self.stream, Bytes::from(wire), false)?;
        Ok(())
    }

    fn send_json<T: Serialize>(
        &mut self,
        cx: &Cx,
        conn: &mut NativeQuicConnection,
        ty: FrameType,
        value: &T,
    ) -> Result<(), QuicTransportError> {
        let frame = json_frame(ty, value)?;
        self.send(cx, conn, &frame)
    }

    fn try_recv(
        &mut self,
        cx: &Cx,
        conn: &mut NativeQuicConnection,
    ) -> Result<Option<Frame>, QuicTransportError> {
        if let Some(frame) = self
            .codec
            .decode(&mut self.rbuf)
            .map_err(|err| QuicTransportError::Frame(err.to_string()))?
        {
            return Ok(Some(frame));
        }

        let chunk = conn.read_stream_bytes(cx, self.stream, CONTROL_READ_CHUNK)?;
        if chunk.is_empty() {
            return Ok(None);
        }
        self.rbuf.extend_from_slice(&chunk);
        self.codec
            .decode(&mut self.rbuf)
            .map_err(|err| QuicTransportError::Frame(err.to_string()))
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
fn next_native_control_frame(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
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
fn receive_native_sender_hello_and_ack(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    config: &QuicConfig,
    peer_id: &str,
    expected_symbol_auth: bool,
) -> Result<QuicHello, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive sender handshake")?;
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

#[allow(dead_code)]
fn send_manifest(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::ObjectManifest, manifest)
}

#[allow(dead_code)]
fn receive_manifest(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<TransferManifest, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive transfer manifest")?;
    parse_json_frame(&frame, FrameType::ObjectManifest, "ObjectManifest")
}

#[allow(dead_code)]
fn receive_native_manifest(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<TransferManifest, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive transfer manifest")?;
    parse_json_frame(&frame, FrameType::ObjectManifest, "ObjectManifest")
}

#[allow(dead_code)]
fn send_empty_control_frame(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    frame_type: FrameType,
) -> Result<(), QuicTransportError> {
    let frame =
        Frame::empty(frame_type).map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    control.send(cx, conn, &frame)
}

#[allow(dead_code)]
fn send_object_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<(), QuicTransportError> {
    send_empty_control_frame(cx, conn, control, FrameType::ObjectComplete)
}

#[allow(dead_code)]
fn receive_object_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<(), QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive object-complete marker")?;
    if frame.frame_type() != FrameType::ObjectComplete {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "ObjectComplete",
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn receive_native_object_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<(), QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive object-complete marker")?;
    if frame.frame_type() != FrameType::ObjectComplete {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "ObjectComplete",
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn send_need_more(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    need: &QuicNeedMore,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::ObjectRequest, need)
}

#[allow(dead_code)]
fn send_proof(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    receipt: &ReceiveReceipt,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::Proof, receipt)
}

#[allow(dead_code)]
fn send_native_need_more(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    need: &QuicNeedMore,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::ObjectRequest, need)
}

#[allow(dead_code)]
fn send_native_proof(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    receipt: &ReceiveReceipt,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::Proof, receipt)
}

#[allow(dead_code)]
fn receive_proof_or_need_more(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<QuicControlReply, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive proof or fountain feedback")?;
    match frame.frame_type() {
        FrameType::Proof => parse_json::<ReceiveReceipt>(&frame).map(QuicControlReply::Proof),
        FrameType::ObjectRequest => {
            parse_json::<QuicNeedMore>(&frame).map(QuicControlReply::NeedMore)
        }
        got => Err(QuicTransportError::Unexpected {
            got,
            expected: "Proof | ObjectRequest",
        }),
    }
}

#[allow(dead_code)]
fn send_close(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<(), QuicTransportError> {
    send_empty_control_frame(cx, conn, control, FrameType::Close)
}

#[allow(dead_code)]
fn send_native_close(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<(), QuicTransportError> {
    let frame =
        Frame::empty(FrameType::Close).map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    control.send(cx, conn, &frame)
}

fn first_client_bidi_stream() -> StreamId {
    StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0)
}

fn recv_native_symbol_envelope(
    conn: &mut NativeQuicConnection,
    auth_required: bool,
) -> Result<Option<QuicSymbolEnvelope>, QuicTransportError> {
    match conn.recv_datagram() {
        Some(bytes) => QuicSymbolEnvelope::decode(&bytes, auth_required)
            .map(Some)
            .map_err(SymbolDatagramError::from)
            .map_err(QuicTransportError::from),
        None => Ok(None),
    }
}

fn drain_native_symbol_datagrams(
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut accepted = 0u64;
    while let Some(envelope) = recv_native_symbol_envelope(conn, auth_required)? {
        if envelope.transfer_tag != tag {
            return Err(QuicTransportError::Integrity(format!(
                "symbol transfer tag mismatch: got {}, expected {tag}",
                envelope.transfer_tag
            )));
        }
        if envelope.payload.len() != usize::from(config.symbol_size) {
            return Err(QuicTransportError::Integrity(format!(
                "symbol payload has {} bytes, expected {}",
                envelope.payload.len(),
                config.symbol_size
            )));
        }
        let decoder = decoders
            .iter_mut()
            .find(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        let auth_symbol =
            authenticated_symbol_from_envelope(&envelope, decoder.object_id, auth_required)?;
        if feed_authenticated_symbol(decoder, auth_symbol)? {
            accepted = accepted.saturating_add(1);
        }
    }
    Ok(accepted)
}

fn validate_quic_manifest(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    if manifest.total_bytes > config.max_transfer_bytes {
        return Err(QuicTransportError::TooLarge {
            size: manifest.total_bytes,
            max: config.max_transfer_bytes,
        });
    }
    if !manifest.is_directory && manifest.entries.len() != 1 {
        return Err(QuicTransportError::Source(
            "single-file transfer manifest must contain exactly one entry".to_string(),
        ));
    }
    if manifest.metadata_root_hex.is_some()
        || manifest
            .entries
            .iter()
            .any(|entry| entry.metadata.is_some())
    {
        return Err(QuicTransportError::Source(
            "transport_quic receive_connection does not yet commit metadata-bearing manifests"
                .to_string(),
        ));
    }

    let mut seen_paths = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for (expected, entry) in manifest.entries.iter().enumerate() {
        let expected = u32::try_from(expected).unwrap_or(u32::MAX);
        if entry.index != expected {
            return Err(QuicTransportError::Source(format!(
                "manifest entry index {} is not sequential (expected {expected})",
                entry.index
            )));
        }
        if entry.rel_path.is_empty() {
            return Err(QuicTransportError::Source(
                "manifest entry rel_path is empty".to_string(),
            ));
        }
        quic_join_relative(Path::new("base"), &entry.rel_path)?;
        if !seen_paths.insert(entry.rel_path.clone()) {
            return Err(QuicTransportError::Source(format!(
                "duplicate manifest entry path {}",
                entry.rel_path
            )));
        }
        if entry.sha256_hex.len() != 64 || !entry.sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(QuicTransportError::Source(format!(
                "manifest entry {} has invalid sha256_hex",
                entry.index
            )));
        }
        total = total.saturating_add(entry.size);
        if total > config.max_transfer_bytes {
            return Err(QuicTransportError::TooLarge {
                size: total,
                max: config.max_transfer_bytes,
            });
        }
    }
    if total != manifest.total_bytes {
        return Err(QuicTransportError::Source(format!(
            "manifest total_bytes {} does not match entry sum {total}",
            manifest.total_bytes
        )));
    }
    Ok(())
}

fn quic_safe_base_for_root_name(
    dest_dir: &Path,
    root_name: &str,
) -> Result<PathBuf, QuicTransportError> {
    if root_name.is_empty() {
        return Err(QuicTransportError::Source(
            "manifest root_name is empty".to_string(),
        ));
    }
    let root = Path::new(root_name);
    if root.is_absolute() {
        return Err(QuicTransportError::Source(format!(
            "unsafe manifest root_name: {root_name}"
        )));
    }
    let mut components = root.components();
    let Some(Component::Normal(component)) = components.next() else {
        return Err(QuicTransportError::Source(format!(
            "unsafe manifest root_name: {root_name}"
        )));
    };
    if components.next().is_some() {
        return Err(QuicTransportError::Source(format!(
            "unsafe manifest root_name: {root_name}"
        )));
    }
    let component_str = component.to_string_lossy();
    if component_str == "."
        || component_str == ".."
        || component_str.contains('/')
        || component_str.contains('\\')
        || component_str.contains(':')
    {
        return Err(QuicTransportError::Source(format!(
            "unsafe manifest root_name: {root_name}"
        )));
    }
    Ok(dest_dir.join(component))
}

fn quic_join_relative(base: &Path, rel: &str) -> Result<PathBuf, QuicTransportError> {
    if rel.is_empty() || Path::new(rel).is_absolute() {
        return Err(QuicTransportError::Source(format!(
            "unsafe path component in entry: {rel}"
        )));
    }
    let mut out = base.to_path_buf();
    for component in rel.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('\\')
            || component.contains(':')
        {
            return Err(QuicTransportError::Source(format!(
                "unsafe path component in entry: {rel}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

async fn commit_decoded_entries(
    cx: &Cx,
    dest_dir: &Path,
    manifest: &TransferManifest,
    decoders: &[QuicEntryDecoder],
) -> Result<(ReceiveReceipt, Vec<PathBuf>), QuicTransportError> {
    let mut receipt = verify_in_memory_receipt(manifest, decoders);
    if !receipt.committed {
        return Ok((receipt, Vec::new()));
    }

    let base = quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    let mut committed_paths = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let decoder = decoders
            .iter()
            .find(|decoder| decoder.index == entry.index)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "decoded entry {} missing during commit",
                    entry.index
                ))
            })?;
        let out_path = if manifest.is_directory {
            quic_join_relative(&base, &entry.rel_path)?
        } else {
            base.clone()
        };
        if let Some(parent) = out_path.parent() {
            crate::fs::create_dir_all(parent).await?;
        }
        crate::fs::write_atomic(&out_path, &decoder.data).await?;
        committed_paths.push(out_path);
    }

    receipt.committed_paths = committed_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    Ok((receipt, committed_paths))
}

fn receive_native_symbol_round(
    cx: &Cx,
    connection: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    symbols_accepted: &mut u64,
    feedback_rounds: &mut u32,
) -> Result<Option<QuicNeedMore>, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    *symbols_accepted = (*symbols_accepted).saturating_add(drain_native_symbol_datagrams(
        connection, manifest, decoders, config,
    )?);
    receive_native_object_complete(cx, connection, control)?;
    assemble_completed_entries(decoders);

    let pending = pending_entries(decoders);
    if pending.is_empty() {
        return Ok(None);
    }
    if *feedback_rounds >= config.max_feedback_rounds {
        return Err(QuicTransportError::NoConvergence {
            rounds: *feedback_rounds,
            pending: pending.len(),
        });
    }
    let need = QuicNeedMore {
        pending,
        source_symbols: source_symbol_requests(decoders, 2048),
    };
    let round = (*feedback_rounds).saturating_add(1);
    let pending_count = need.pending.len().to_string();
    let source_request_count = need.source_symbols.len().to_string();
    let accepted_count = symbols_accepted.to_string();
    let round_text = round.to_string();
    cx.trace_with_fields(
        "atp_quic.receive.need_more",
        &[
            ("round", round_text.as_str()),
            ("pending", pending_count.as_str()),
            ("source_requests", source_request_count.as_str()),
            ("symbols_accepted", accepted_count.as_str()),
        ],
    );
    send_native_need_more(cx, connection, control, &need)?;
    *feedback_rounds = round;
    Ok(Some(need))
}

async fn receive_established_native_connection(
    cx: &Cx,
    mut connection: NativeQuicConnection,
    peer: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    let mut control = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();

    receive_native_sender_hello_and_ack(
        cx,
        &mut connection,
        &mut control,
        &config,
        peer_id,
        symbol_auth_enabled,
    )?;
    let manifest = receive_native_manifest(cx, &mut connection, &mut control)?;
    validate_quic_manifest(&manifest, &config)?;
    let mut decoders = decoders_from_manifest(&manifest, &config)?;
    let mut symbols_accepted = 0u64;
    let mut feedback_rounds = 0u32;

    loop {
        if receive_native_symbol_round(
            cx,
            &mut connection,
            &mut control,
            &manifest,
            &mut decoders,
            &config,
            &mut symbols_accepted,
            &mut feedback_rounds,
        )?
        .is_none()
        {
            break;
        }
    }

    let (receipt, committed_paths) =
        commit_decoded_entries(cx, dest_dir, &manifest, &decoders).await?;
    send_native_proof(cx, &mut connection, &mut control, &receipt)?;
    let _ = send_native_close(cx, &mut connection, &mut control);

    if !receipt.committed {
        return Err(QuicTransportError::Integrity(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit".to_string()),
        ));
    }

    Ok(ReceiveReport {
        transfer_id: manifest.transfer_id,
        bytes_received: receipt.bytes_received,
        files: receipt.files,
        committed: true,
        committed_paths,
        peer,
    })
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
    let datagram_fanout = config.datagram_fanout.to_string();
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
            ("datagram_fanout", &datagram_fanout),
        ],
    );
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Transfer the file or directory at `source` to `addr` over a QUIC connection.
///
/// Mirrors [`transport_tcp::send_path`]. The B2 sender now performs the
/// streaming source walk/hash/manifest preflight, then fails closed at the
/// still-unwired native QUIC connect/identity boundary. Wired by B2
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
    let prepared = prepare_source_manifest(cx, source, &config).await?;
    let _ = (addr, prepared);
    Err(QuicTransportError::NotImplemented {
        operation: "send_path",
        wired_by: "asupersync-arq-quic-epic-b0k8qo.2.2 (B2: native QUIC connect + identity)",
    })
}

// ─── Public API: receive ─────────────────────────────────────────────────────

/// Accept exactly one transfer on `endpoint`, write it to `dest_dir`, verify it,
/// and return a report.
///
/// Mirrors [`transport_tcp::receive_once`] (with a [`ManagedQuicEndpoint`] in
/// place of a `TcpListener`). This entry point consumes the next connection
/// already routed into the managed endpoint and delegates to
/// [`receive_connection`]. Endpoint packet pumping is still owned by the native
/// endpoint layer; when no routed connection is available, this function fails
/// closed with a typed accept timeout rather than reporting fake success.
///
/// [`transport_tcp::receive_once`]: crate::net::atp::transport_tcp::receive_once
pub async fn receive_once(
    cx: &Cx,
    endpoint: &mut ManagedQuicEndpoint,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "receive_once", &config, peer_id);

    let Some(accepted) = endpoint.take_next_connection(cx)? else {
        return Err(QuicTransportError::Timeout {
            operation: "receive_once accept",
            timeout: config.accept_timeout,
        });
    };

    let connection_id = format!("{:?}", accepted.connection_id);
    let peer = accepted.peer_addr.to_string();
    cx.trace_with_fields(
        "atp_quic.receive_once.accepted",
        &[
            ("connection_id", connection_id.as_str()),
            ("peer", peer.as_str()),
            ("peer_id", peer_id),
        ],
    );

    receive_established_native_connection(
        cx,
        accepted.connection,
        accepted.peer_addr,
        dest_dir,
        config,
        peer_id,
    )
    .await
}

/// Drive a single accepted QUIC connection through the receive protocol.
///
/// Mirrors [`transport_tcp::receive_connection`] (with a
/// [`NativeQuicConnection`] in place of a `TcpStream`). The caller supplies an
/// already-established native QUIC connection whose first client-initiated
/// bidirectional stream carries ATP control frames and whose DATAGRAM queue
/// carries RaptorQ symbols. Endpoint accept/connect and continuous event-loop
/// pumping remain separate B2/B3 work; this function is the accepted-connection
/// receiver body.
///
/// [`transport_tcp::receive_connection`]: crate::net::atp::transport_tcp::receive_connection
// `connection` is owned by value to mirror `transport_tcp::receive_connection`'s
// `stream: TcpStream` exactly; B3 consumes it to drive the receive protocol.
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
    receive_established_native_connection(cx, connection, peer, dest_dir, config, peer_id).await
}

/// Drain routed endpoint connections, handling each accepted connection as a
/// receive.
///
/// Mirrors [`transport_tcp::serve`] (with a [`ManagedQuicEndpoint`] in place of
/// a `TcpListener`). This B3 slice handles connections already routed into the
/// managed endpoint. Live endpoint packet pumping and indefinite listener
/// ownership remain lower-level native endpoint work.
///
/// [`transport_tcp::serve`]: crate::net::atp::transport_tcp::serve
// Owned `endpoint` / `dest_dir` / `peer_id` / `on_result` mirror
// `transport_tcp::serve`'s by-value signature exactly; this queued-connection
// B3 slice consumes them while draining already-routed connections.
#[allow(clippy::needless_pass_by_value)]
pub async fn serve<F>(
    cx: &Cx,
    mut endpoint: ManagedQuicEndpoint,
    dest_dir: PathBuf,
    config: QuicConfig,
    peer_id: String,
    mut on_result: F,
) -> Result<(), QuicTransportError>
where
    F: FnMut(Result<ReceiveReport, QuicTransportError>),
{
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "serve", &config, &peer_id);

    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let Some(accepted) = endpoint.take_next_connection(cx)? else {
            return Ok(());
        };
        let connection_id = format!("{:?}", accepted.connection_id);
        let peer = accepted.peer_addr.to_string();
        cx.trace_with_fields(
            "atp_quic.serve.accepted",
            &[
                ("connection_id", connection_id.as_str()),
                ("peer", peer.as_str()),
                ("peer_id", peer_id.as_str()),
            ],
        );
        let result = receive_established_native_connection(
            cx,
            accepted.connection,
            accepted.peer_addr,
            &dest_dir,
            config.clone(),
            &peer_id,
        )
        .await;
        on_result(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::frames::{Frame, ProtocolVersion};
    use crate::net::quic_native::{
        DEFAULT_MAX_PACKET_BYTES, NativeQuicConnectionConfig, PacketNumberSpace, QuicConnection,
        StreamDirection, StreamRole, establish_loopback, pump_app_data, pump_until_idle,
    };

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        futures_lite::future::block_on(fut)
    }

    fn trusted_quic_config() -> QuicConfig {
        QuicConfig::default().allow_unauthenticated_for_trusted_transport()
    }

    fn auth_quic_config(seed: u64) -> QuicConfig {
        QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(seed))
    }

    fn established_pair() -> (Cx<crate::cx::cap::All>, QuicConnection, QuicConnection) {
        let cx = Cx::for_testing();
        let mut client = QuicConnection::client(NativeQuicConnectionConfig::default());
        let mut server = QuicConnection::server(NativeQuicConnectionConfig::default());
        client.record_verified_server_identity();
        establish_loopback(&cx, &mut client, &mut server).expect("loopback establishes");
        (cx, client, server)
    }

    fn pump_native_until_idle(
        cx: &Cx,
        from: &mut NativeQuicConnection,
        to: &mut NativeQuicConnection,
        next_packet_number: &mut u64,
        max_packet_bytes: usize,
        now_micros: u64,
    ) -> Result<usize, QuicTransportError> {
        let mut total = 0usize;
        for _ in 0..32 {
            let frames =
                from.generate_frames(cx, PacketNumberSpace::ApplicationData, max_packet_bytes)?;
            if frames.is_empty() {
                return Ok(total);
            }
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload)?;
            let packet_number = *next_packet_number;
            *next_packet_number = (*next_packet_number).saturating_add(1);
            to.process_packet_payload(
                cx,
                PacketNumberSpace::ApplicationData,
                packet_number,
                &payload,
                now_micros,
            )?;
            total = total.saturating_add(frames.len());
        }
        Err(QuicTransportError::Quic(
            "native pump did not drain within iteration cap".to_string(),
        ))
    }

    fn sample_manifest() -> TransferManifest {
        TransferManifest {
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
        }
    }

    fn sample_receipt() -> ReceiveReceipt {
        ReceiveReceipt {
            committed: true,
            bytes_received: 9,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            reason: None,
            committed_paths: vec!["/dest/a/b.txt".to_string()],
        }
    }

    fn varied_bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| {
                let i = u64::try_from(i).unwrap_or(u64::MAX);
                let mixed = i
                    .wrapping_mul(37)
                    .wrapping_add(u64::from(seed).wrapping_mul(11))
                    % 251;
                u8::try_from(mixed).unwrap_or(0)
            })
            .collect()
    }

    fn drive_in_memory_loopback_transfer(
        cx: &Cx,
        sender: &mut QuicConnection,
        receiver: &mut QuicConnection,
        entries: &[(String, Vec<u8>)],
        config: QuicConfig,
    ) -> Result<QuicConnectionTransferOutcome, QuicTransportError> {
        config.validate()?;
        let symbol_auth = config.symbol_auth_context()?;
        let symbol_auth_enabled = symbol_auth.is_some();
        let manifest = manifest_from_entries("payload", true, entries);
        let mut sender_control = QuicFrameTransport::open(cx, sender)?;
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            cx,
            sender,
            &mut sender_control,
            &config,
            "sender-peer",
            symbol_auth_enabled,
        )?;
        pump_until_idle(cx, sender, receiver, DEFAULT_MAX_PACKET_BYTES, 5_000)
            .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            cx,
            receiver,
            &mut receiver_control,
            &config,
            "receiver-peer",
            symbol_auth_enabled,
        )?;
        pump_until_idle(cx, receiver, sender, DEFAULT_MAX_PACKET_BYTES, 5_001)
            .expect("deliver sender hello ack");
        let ack = receive_sender_hello_ack(cx, sender, &mut sender_control)?;
        assert_eq!(ack.peer_id, "receiver-peer");

        let mut encoders = encoders_from_entries(&manifest, entries);
        let symbols_sent = send_manifest_symbols_complete(
            cx,
            sender,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )?;
        pump_until_idle(cx, sender, receiver, DEFAULT_MAX_PACKET_BYTES, 5_002)
            .expect("deliver manifest, symbols, and object-complete");

        let received_manifest = receive_manifest(cx, receiver, &mut receiver_control)?;
        if received_manifest != manifest {
            return Err(QuicTransportError::Integrity(
                "receiver decoded a different manifest".to_string(),
            ));
        }
        let mut decoders = decoders_from_manifest(&received_manifest, &config)?;
        let symbols_accepted =
            drain_symbol_datagrams(receiver, &received_manifest, &mut decoders, &config)?;
        receive_object_complete(cx, receiver, &mut receiver_control)?;
        assemble_completed_entries(&mut decoders);
        let pending = pending_entries(&decoders);
        if pending.is_empty() {
            let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
            send_proof(cx, receiver, &mut receiver_control, &receipt)?;
        } else {
            send_need_more(
                cx,
                receiver,
                &mut receiver_control,
                &QuicNeedMore {
                    pending,
                    source_symbols: source_symbol_requests(&decoders, 2048),
                },
            )?;
        }
        pump_until_idle(cx, receiver, sender, DEFAULT_MAX_PACKET_BYTES, 5_003)
            .expect("deliver proof");

        let peer = "127.0.0.1:4433".parse().expect("peer addr");
        let (send_report, symbols_sent) = {
            let mut feedback =
                QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, symbols_sent);
            let report =
                handle_sender_feedback_or_proof(cx, sender, &mut sender_control, &mut feedback)?
                    .ok_or_else(|| {
                        QuicTransportError::Integrity(
                            "sender received repair feedback in no-repair loopback transfer"
                                .to_string(),
                        )
                    })?;
            (report, feedback.symbols_sent)
        };
        let receipt = send_report.receipt.clone();
        pump_until_idle(cx, sender, receiver, DEFAULT_MAX_PACKET_BYTES, 5_004)
            .expect("deliver close");
        let close =
            next_control_frame(cx, receiver, &mut receiver_control, "receive sender close")?;
        if close.frame_type() != FrameType::Close {
            return Err(QuicTransportError::Unexpected {
                got: close.frame_type(),
                expected: "Close",
            });
        }

        Ok(QuicConnectionTransferOutcome {
            manifest,
            send_report,
            receipt,
            symbols_sent,
            symbols_accepted,
        })
    }

    #[test]
    fn default_config_requires_symbol_auth_or_trusted_mode() {
        let err = QuicConfig::default()
            .validate()
            .expect_err("default config must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Config(m) if m.contains("symbol_auth_context")
        ));
        assert!(trusted_quic_config().validate().is_ok());
        assert!(auth_quic_config(7).validate().is_ok());
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
        assert_eq!(c.datagram_fanout, DEFAULT_DATAGRAM_FANOUT);
        assert_eq!(
            c.symbol_auth_mode(),
            QuicSymbolAuthMode::MissingAuthenticationContext
        );
    }

    #[test]
    fn validate_rejects_zero_symbol_size() {
        let c = QuicConfig {
            symbol_size: 0,
            ..trusted_quic_config()
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
            ..trusted_quic_config()
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
            ..trusted_quic_config()
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
            ..trusted_quic_config()
        };
        assert!(matches!(
            low.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("repair_overhead")
        ));
        let nan = QuicConfig {
            repair_overhead: f64::NAN,
            ..trusted_quic_config()
        };
        assert!(matches!(
            nan.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("repair_overhead")
        ));
    }

    #[test]
    fn validate_rejects_zero_datagram_fanout() {
        let c = QuicConfig {
            datagram_fanout: 0,
            ..trusted_quic_config()
        };
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("datagram_fanout")
        ));
    }

    fn quic_path_estimate(loss: f64, bw: f64) -> QuicPathEstimate {
        QuicPathEstimate {
            rtt_s: 0.075,
            loss_p_hat: loss,
            loss_p_bar: loss,
            bw_median_bps: bw,
            bw_trough_bps: bw * 0.7,
            enc_symbols_per_s: 2_000_000.0,
            dec_symbols_per_s: 1_500_000.0,
            coding_ref_k: 1024,
            coding_gamma: 1.5,
            samples: 8,
        }
    }

    #[test]
    fn quic_adaptive_controller_is_deterministic_given_seed() {
        let run = || {
            let mut controller = QuicAdaptiveController::new(QuicAdaptivePolicy::default(), 0xA7A7);
            controller.update_estimate(quic_path_estimate(0.02, 12_000_000.0));
            let mut trajectory = Vec::new();
            for _ in 0..24 {
                let plan = controller
                    .next_block_plan(DEFAULT_SYMBOL_SIZE)
                    .expect("enough evidence activates the controller");
                let quic_arm =
                    QuicAdaptiveArm::from_block_plan(plan).expect("valid controller arm");
                trajectory.push((
                    quic_arm.k,
                    quic_arm.repair_overhead,
                    quic_arm.datagram_fanout,
                ));
                controller.observe(
                    u64::from(plan.k),
                    u64::from(plan.k),
                    0.01,
                    u64::from(plan.k) * u64::from(DEFAULT_SYMBOL_SIZE),
                );
            }
            trajectory
        };

        assert_eq!(run(), run(), "same seed and rewards must replay exactly");
    }

    #[test]
    fn quic_adaptive_arm_rejects_invalid_controller_output() {
        assert!(matches!(
            QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
                k: 0,
                overhead: 0.1,
                fanout: 1,
            }),
            Err(QuicTransportError::Config(m)) if m.contains("k")
        ));
        assert!(matches!(
            QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
                k: 128,
                overhead: f64::NAN,
                fanout: 1,
            }),
            Err(QuicTransportError::Config(m)) if m.contains("overhead")
        ));
        assert!(matches!(
            QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
                k: 128,
                overhead: 0.1,
                fanout: 0,
            }),
            Err(QuicTransportError::Config(m)) if m.contains("fanout")
        ));
    }

    #[test]
    fn quic_adaptive_arm_applies_to_loopback_transfer_config() {
        let plan = QuicAdaptiveBlockPlan {
            k: 2,
            overhead: 0.25,
            fanout: 3,
        };
        let config = apply_quic_adaptive_block_plan(
            QuicConfig {
                symbol_size: 128,
                ..trusted_quic_config()
            },
            plan,
        )
        .expect("adaptive plan applies to QUIC config");

        assert_eq!(config.max_block_size, 256);
        assert_eq!(config.repair_overhead, 1.25);
        assert_eq!(config.datagram_fanout, 3);

        let (cx, mut sender, mut receiver) = established_pair();
        let entries = vec![("adaptive.txt".to_string(), varied_bytes(192, 17))];
        let outcome =
            drive_in_memory_loopback_transfer(&cx, &mut sender, &mut receiver, &entries, config)
                .expect("adapted QUIC config drives the existing loopback transfer");

        assert!(outcome.receipt.committed);
        assert_eq!(outcome.send_report.files, 1);
        assert_eq!(outcome.send_report.bytes_sent, 192);
        assert!(
            outcome.symbols_sent >= 3,
            "source symbols plus adaptive repair should be sprayed"
        );
    }

    #[test]
    fn validate_rejects_zero_timeouts() {
        for c in [
            QuicConfig {
                idle_timeout: Duration::ZERO,
                ..trusted_quic_config()
            },
            QuicConfig {
                handshake_timeout: Duration::ZERO,
                ..trusted_quic_config()
            },
            QuicConfig {
                accept_timeout: Duration::ZERO,
                ..trusted_quic_config()
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
        let manifest = sample_manifest();

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
        let receipt = sample_receipt();

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
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 2,
                sbn: 1,
                esi: 15,
            }],
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
    fn quic_control_need_more_defaults_missing_source_symbols() {
        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectRequest,
            br#"{"pending":[3,5]}"#.to_vec(),
        )
        .expect("need-more frame");

        let need = parse_json::<QuicNeedMore>(&frame).expect("parse legacy need-more shape");
        assert_eq!(need.pending, vec![3, 5]);
        assert!(need.source_symbols.is_empty());
    }

    #[test]
    fn quic_control_manifest_helper_round_trips() {
        let (cx, mut client, mut server) = established_pair();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());
        let manifest = sample_manifest();

        send_manifest(&cx, &mut client, &mut sender_control, &manifest).expect("send manifest");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_100,
        )
        .expect("deliver manifest");

        let got = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receive manifest helper");
        assert_eq!(got, manifest);
    }

    #[test]
    fn quic_control_round_marker_feedback_proof_and_close_helpers_round_trip() {
        let (cx, mut client, mut server) = established_pair();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_object_complete(&cx, &mut client, &mut sender_control).expect("send object-complete");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_200,
        )
        .expect("deliver object-complete");
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receive object-complete");

        let need = QuicNeedMore {
            pending: vec![1, 3],
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 3,
                sbn: 2,
                esi: 99,
            }],
        };
        send_need_more(&cx, &mut server, &mut receiver_control, &need).expect("send need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            2_201,
        )
        .expect("deliver need-more");
        match receive_proof_or_need_more(&cx, &mut client, &mut sender_control)
            .expect("receive need-more")
        {
            QuicControlReply::NeedMore(got) => assert_eq!(got, need),
            QuicControlReply::Proof(other) => panic!("unexpected proof: {other:?}"),
        }

        let receipt = sample_receipt();
        send_proof(&cx, &mut server, &mut receiver_control, &receipt).expect("send proof");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            2_202,
        )
        .expect("deliver proof");
        match receive_proof_or_need_more(&cx, &mut client, &mut sender_control)
            .expect("receive proof")
        {
            QuicControlReply::Proof(got) => assert_eq!(got, receipt),
            QuicControlReply::NeedMore(other) => panic!("unexpected need-more: {other:?}"),
        }

        send_close(&cx, &mut client, &mut sender_control).expect("send close");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_203,
        )
        .expect("deliver close");
        let close = next_control_frame(&cx, &mut server, &mut receiver_control, "receive close")
            .expect("receive close");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn quic_control_reply_helper_rejects_unexpected_frame() {
        let (cx, mut client, mut server) = established_pair();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());
        let manifest = sample_manifest();

        send_manifest(&cx, &mut client, &mut sender_control, &manifest).expect("send manifest");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_300,
        )
        .expect("deliver manifest");

        let err = receive_proof_or_need_more(&cx, &mut server, &mut receiver_control)
            .expect_err("manifest is not a sender feedback reply");
        match err {
            QuicTransportError::Unexpected { got, expected } => {
                assert_eq!(got, FrameType::ObjectManifest);
                assert_eq!(expected, "Proof | ObjectRequest");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn quic_prepare_source_manifest_hashes_files_with_streaming_digests() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(257, 31);
        let beta = varied_bytes(513, 37);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");

        let config = QuicConfig {
            chunk_size: 17,
            max_transfer_bytes: 2_048,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares");

        assert_eq!(prepared.manifest.root_name, "payload");
        assert!(prepared.manifest.is_directory);
        assert_eq!(prepared.manifest.total_bytes, 770);
        assert_eq!(prepared.manifest.entries.len(), 2);
        assert_eq!(prepared.manifest.entries[0].rel_path, "alpha.bin");
        assert_eq!(prepared.manifest.entries[1].rel_path, "nested/beta.bin");
        assert_eq!(
            prepared.manifest.merkle_root_hex,
            flat_merkle_root_from_slices([
                ("alpha.bin", alpha.as_slice()),
                ("nested/beta.bin", beta.as_slice()),
            ])
        );
        assert_eq!(prepared.manifest.entries[0].sha256_hex, sha256_hex(&alpha));
        assert_eq!(prepared.manifest.entries[1].sha256_hex, sha256_hex(&beta));

        assert_eq!(prepared.entries.len(), 2);
        assert_eq!(prepared.entries[0].index, 0);
        assert_eq!(prepared.entries[0].rel_path, "alpha.bin");
        assert_eq!(prepared.entries[0].abs_path, root.join("alpha.bin"));
        assert_eq!(
            prepared.entries[0].size,
            u64::try_from(alpha.len()).expect("alpha length fits u64")
        );
        assert_eq!(
            prepared.entries[0].object_id,
            entry_object_id(&prepared.manifest.transfer_id, 0)
        );
        assert_eq!(
            prepared.entries[1].object_id,
            entry_object_id(&prepared.manifest.transfer_id, 1)
        );
        assert_eq!(
            prepared.entries[1].sha256_hex,
            prepared.manifest.entries[1].sha256_hex
        );
    }

    #[test]
    fn quic_prepare_source_manifest_rejects_explicit_directory_entry() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("empty")).expect("create empty dir");

        let err = block_on(prepare_source_manifest(&cx, &root, &trusted_quic_config()))
            .expect_err("empty directory marker is not encoded yet");
        assert!(matches!(
            err,
            QuicTransportError::Source(message)
                if message.contains("explicit directory entry empty")
        ));
    }

    #[test]
    fn quic_prepare_source_manifest_rejects_empty_directory_root() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(&root).expect("create empty root");

        let err = block_on(prepare_source_manifest(&cx, &root, &trusted_quic_config()))
            .expect_err("empty directory root is not encoded yet");
        assert!(matches!(
            err,
            QuicTransportError::Source(message)
                if message.contains("empty directory root payload")
        ));
    }

    #[test]
    fn quic_prepare_source_manifest_enforces_transfer_size_ceiling() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("payload.bin");
        std::fs::write(&file, b"12345").expect("write file");
        let config = QuicConfig {
            chunk_size: 2,
            max_transfer_bytes: 4,
            ..trusted_quic_config()
        };

        let err = block_on(prepare_source_manifest(&cx, &file, &config))
            .expect_err("oversize source must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::TooLarge { size: 5, max: 4 }
        ));
    }

    #[test]
    fn quic_connection_level_transfer_reaches_proof_over_control_and_datagrams() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let entries = vec![
            ("alpha.bin".to_string(), varied_bytes(384, 3)),
            ("nested/beta.bin".to_string(), varied_bytes(900, 7)),
        ];

        let outcome =
            drive_in_memory_loopback_transfer(&cx, &mut client, &mut server, &entries, config)
                .expect("connection-level transfer reaches proof");

        assert!(outcome.receipt.committed);
        assert!(outcome.receipt.sha_ok);
        assert!(outcome.receipt.merkle_ok);
        assert_eq!(outcome.receipt.bytes_received, 1_284);
        assert_eq!(outcome.receipt.files, 2);
        assert_eq!(outcome.manifest.entries.len(), 2);
        assert_eq!(
            outcome.send_report.transfer_id,
            outcome.manifest.transfer_id
        );
        assert_eq!(outcome.send_report.bytes_sent, outcome.manifest.total_bytes);
        assert_eq!(outcome.send_report.files, 2);
        assert_eq!(
            outcome.send_report.merkle_root_hex,
            outcome.manifest.merkle_root_hex
        );
        assert_eq!(
            outcome.send_report.receipt.committed_paths,
            outcome.receipt.committed_paths
        );
        assert!(
            outcome.symbols_sent > 0,
            "sender must emit QUIC DATAGRAM symbols"
        );
        assert!(
            outcome.symbols_accepted > 0,
            "receiver must feed decoded QUIC DATAGRAM symbols"
        );
        assert!(
            outcome
                .receipt
                .committed_paths
                .contains(&"/quic-memory/payload/nested/beta.bin".to_string())
        );
    }

    #[test]
    fn quic_connection_level_transfer_verifies_symbol_auth_tags() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..auth_quic_config(0xA7_51)
        };
        let entries = vec![
            ("alpha.bin".to_string(), varied_bytes(384, 53)),
            ("nested/beta.bin".to_string(), varied_bytes(640, 59)),
        ];
        let expected_source_symbols = entries
            .iter()
            .map(|(_, bytes)| bytes.len().div_ceil(usize::from(config.symbol_size)))
            .sum::<usize>();

        let outcome =
            drive_in_memory_loopback_transfer(&cx, &mut client, &mut server, &entries, config)
                .expect("authenticated QUIC loopback transfer reaches proof");

        assert!(outcome.receipt.committed);
        assert_eq!(outcome.send_report.bytes_sent, 1_024);
        assert_eq!(
            outcome.symbols_accepted,
            u64::try_from(expected_source_symbols).unwrap_or(u64::MAX)
        );
        assert!(outcome.symbols_sent >= outcome.symbols_accepted);
    }

    #[test]
    fn quic_symbol_auth_rejects_bad_tag_before_decode() {
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            ..auth_quic_config(0xBAD7_A6)
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 61))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let symbol = Symbol::from_slice(
            SymbolId::new(decoders[0].object_id, 0, 0),
            &entries[0].1,
            SymbolKind::Source,
        );
        let bad = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

        let err = feed_authenticated_symbol(&mut decoders[0], bad)
            .expect_err("bad auth tag must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("authentication failed")
        ));
    }

    #[test]
    fn quic_prepared_source_loopback_transfer_reaches_proof_from_disk_files() {
        let (cx, mut client, mut server) = established_pair();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(384, 41);
        let beta = varied_bytes(640, 43);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");
        let config = QuicConfig {
            chunk_size: 31,
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares from disk");
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
            7_000,
        )
        .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            7_001,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives ack");

        let symbols_sent = block_on(send_prepared_source_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &prepared,
            &config,
        ))
        .expect("prepared source sends manifest and symbols");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_002,
        )
        .expect("deliver prepared source transfer");

        let received_manifest = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receiver decodes manifest");
        assert_eq!(received_manifest, prepared.manifest);
        let mut decoders = decoders_from_manifest(&received_manifest, &config).expect("decoders");
        let symbols_accepted =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains symbols");
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees object complete");
        assemble_completed_entries(&mut decoders);
        assert!(
            pending_entries(&decoders).is_empty(),
            "prepared source symbols should decode without repair feedback"
        );
        let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
        assert!(receipt.committed);
        send_proof(&cx, &mut server, &mut receiver_control, &receipt).expect("send proof");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            7_003,
        )
        .expect("deliver proof");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let report = receive_proof_close_and_report(
            &cx,
            &mut client,
            &mut sender_control,
            &prepared.manifest,
            peer,
        )
        .expect("sender receives proof report");
        assert_eq!(report.transfer_id, prepared.manifest.transfer_id);
        assert_eq!(report.bytes_sent, 1_024);
        assert_eq!(report.files, 2);
        assert_eq!(report.receipt.bytes_received, 1_024);
        assert!(symbols_sent > 0);
        assert!(symbols_accepted > 0);
        assert_eq!(prepared.entries[0].rel_path, "alpha.bin");
        assert_eq!(prepared.entries[1].rel_path, "nested/beta.bin");
    }

    #[test]
    fn quic_sender_repair_feedback_round_recovers_after_source_loss() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(384, 47))];
        let manifest = manifest_from_entries("payload", true, &entries);
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
            8_000,
        )
        .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_001,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives ack");

        let mut encoders = encoders_from_entries(&manifest, &entries);
        let initial_sent = send_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )
        .expect("send source-only round");
        assert_eq!(initial_sent, 3);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_002,
        )
        .expect("deliver source-only round");

        let dropped = server.recv_datagram().expect("drop one source datagram");
        assert!(!dropped.is_empty());
        let received_manifest = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receiver decodes manifest");
        let mut decoders = decoders_from_manifest(&received_manifest, &config).expect("decoders");
        let accepted_before =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains surviving source symbols");
        assert_eq!(accepted_before, 2);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees initial object complete");
        assemble_completed_entries(&mut decoders);
        let pending = pending_entries(&decoders);
        assert_eq!(pending, vec![0]);
        let need = QuicNeedMore {
            pending,
            source_symbols: source_symbol_requests(&decoders, 2048),
        };
        assert!(
            !need.source_symbols.is_empty(),
            "receiver should report sparse missing source symbols"
        );
        send_need_more(&cx, &mut server, &mut receiver_control, &need).expect("send need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_003,
        )
        .expect("deliver need-more");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut feedback =
            QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, initial_sent);
        let report =
            handle_sender_feedback_or_proof(&cx, &mut client, &mut sender_control, &mut feedback)
                .expect("sender handles need-more");
        assert!(report.is_none());
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(feedback.symbols_sent, 4);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_004,
        )
        .expect("deliver repair round");

        let source_envelope = recv_symbol_envelope(&mut server, false)
            .expect("source retransmit envelope parses")
            .expect("source retransmit datagram delivered");
        assert!(!source_envelope.is_repair);
        assert_eq!(source_envelope.entry, 0);
        assert_eq!(source_envelope.sbn, 0);
        assert_eq!(source_envelope.esi, 0);
        let source_symbol =
            authenticated_symbol_from_envelope(&source_envelope, decoders[0].object_id, false)
                .expect("source symbol");
        assert!(source_symbol.symbol().kind().is_source());
        assert!(feed_authenticated_symbol(&mut decoders[0], source_symbol).expect("feed source"));
        let accepted_extra =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains any extra feedback symbols");
        assert_eq!(accepted_extra, 0);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees repair object complete");
        assemble_completed_entries(&mut decoders);
        assert!(
            pending_entries(&decoders).is_empty(),
            "repair round should converge after a dropped source symbol"
        );
        let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
        send_proof(&cx, &mut server, &mut receiver_control, &receipt).expect("send proof");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_005,
        )
        .expect("deliver proof");

        let report =
            handle_sender_feedback_or_proof(&cx, &mut client, &mut sender_control, &mut feedback)
                .expect("sender receives proof report")
                .expect("proof completes transfer");
        assert_eq!(report.transfer_id, manifest.transfer_id);
        assert_eq!(report.receipt.bytes_received, 384);
        assert_eq!(report.files, 1);
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(feedback.symbols_sent, 4);
    }

    #[test]
    fn receive_connection_commits_established_native_quic_transfer() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let entries = vec![
            ("alpha.bin".to_string(), varied_bytes(384, 23)),
            ("nested/beta.bin".to_string(), varied_bytes(640, 29)),
        ];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        send_manifest(&cx, &mut client, &mut sender_control, &manifest).expect("send manifest");
        let mut encoders = encoders_from_entries(&manifest, &entries);
        let symbol_auth = config.symbol_auth_context().expect("auth posture");
        let sent = spray_initial_symbols(
            &cx,
            &mut client,
            &manifest,
            &mut encoders,
            &config,
            symbol_auth.as_ref(),
        )
        .expect("spray");
        assert!(sent > 0);
        send_object_complete(&cx, &mut client, &mut sender_control).expect("send complete");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_000,
        )
        .expect("deliver accepted connection payload");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let temp = tempfile::tempdir().expect("temp dir");
        let report = block_on(receive_connection(
            &cx,
            server.inner().clone(),
            peer,
            temp.path(),
            config,
            "receiver-peer",
        ))
        .expect("receive connection commits");

        assert!(report.committed);
        assert_eq!(report.transfer_id, manifest.transfer_id);
        assert_eq!(report.bytes_received, 1_024);
        assert_eq!(report.files, 2);
        assert_eq!(report.peer, peer);
        assert_eq!(
            std::fs::read(temp.path().join("payload/alpha.bin")).expect("read alpha"),
            entries[0].1
        );
        assert_eq!(
            std::fs::read(temp.path().join("payload/nested/beta.bin")).expect("read beta"),
            entries[1].1
        );
    }

    #[test]
    fn native_receive_rounds_commit_after_source_symbol_retransmit() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            max_feedback_rounds: 2,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(384, 47))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        let mut encoders = encoders_from_entries(&manifest, &entries);
        let initial_sent = send_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )
        .expect("send source-only round");
        assert_eq!(initial_sent, 3);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_200,
        )
        .expect("deliver initial transfer payload");

        let mut native_server = server.inner().clone();
        let dropped = native_server
            .recv_datagram()
            .expect("drop one source datagram");
        assert!(!dropped.is_empty());
        let mut receiver_control = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());
        receive_native_sender_hello_and_ack(
            &cx,
            &mut native_server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("native receiver accepts hello");
        let received_manifest =
            receive_native_manifest(&cx, &mut native_server, &mut receiver_control)
                .expect("native receiver decodes manifest");
        assert_eq!(received_manifest, manifest);
        let mut decoders = decoders_from_manifest(&received_manifest, &config).expect("decoders");
        let mut symbols_accepted = 0u64;
        let mut feedback_rounds = 0u32;
        let need = match receive_native_symbol_round(
            &cx,
            &mut native_server,
            &mut receiver_control,
            &received_manifest,
            &mut decoders,
            &config,
            &mut symbols_accepted,
            &mut feedback_rounds,
        )
        .expect("initial native receive round asks for repair")
        {
            Some(need) => need,
            None => panic!("dropped source symbol should require repair"),
        };
        assert_eq!(symbols_accepted, 2);
        assert_eq!(feedback_rounds, 1);
        assert_eq!(need.pending, vec![0]);
        assert!(
            !need.source_symbols.is_empty(),
            "receiver should ask for the missing source symbol"
        );

        let symbol_auth = config.symbol_auth_context().expect("auth posture");
        let repair_sent = send_repair_round_and_object_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &received_manifest,
            &mut encoders,
            &need,
            &config,
            symbol_auth.as_ref(),
        )
        .expect("sender retransmits requested source symbol");
        assert_eq!(repair_sent, 1);
        let mut native_client = client.inner().clone();
        let mut client_packet_number = 0u64;
        let moved = pump_native_until_idle(
            &cx,
            &mut native_client,
            &mut native_server,
            &mut client_packet_number,
            DEFAULT_MAX_PACKET_BYTES,
            6_201,
        )
        .expect("deliver repair payload to receiver-owned native connection");
        assert!(moved > 0);

        assert!(matches!(
            receive_native_symbol_round(
                &cx,
                &mut native_server,
                &mut receiver_control,
                &received_manifest,
                &mut decoders,
                &config,
                &mut symbols_accepted,
                &mut feedback_rounds,
            )
            .expect("repair native receive round converges"),
            None
        ));
        assert_eq!(symbols_accepted, 3);
        assert_eq!(feedback_rounds, 1);

        let temp = tempfile::tempdir().expect("temp dir");
        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            temp.path(),
            &received_manifest,
            &decoders,
        ))
        .expect("commit decoded repair result");
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
        assert_eq!(receipt.bytes_received, 384);
        assert_eq!(committed_paths.len(), 1);
        assert_eq!(
            std::fs::read(temp.path().join("payload/alpha.bin")).expect("read alpha"),
            entries[0].1
        );
    }

    #[test]
    fn receive_connection_exhausts_native_repair_round_budget() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            max_feedback_rounds: 1,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(384, 47))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        let mut encoders = encoders_from_entries(&manifest, &entries);
        send_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )
        .expect("send source-only round");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_100,
        )
        .expect("deliver initial transfer payload");

        let dropped = server.recv_datagram().expect("drop one source datagram");
        assert!(!dropped.is_empty());
        send_object_complete(&cx, &mut client, &mut sender_control)
            .expect("send empty second round marker");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_101,
        )
        .expect("deliver second object-complete marker");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let temp = tempfile::tempdir().expect("temp dir");
        let err = block_on(receive_connection(
            &cx,
            server.inner().clone(),
            peer,
            temp.path(),
            config,
            "receiver-peer",
        ))
        .expect_err("receiver should exhaust repair feedback budget");

        assert!(matches!(
            err,
            QuicTransportError::NoConvergence {
                rounds: 1,
                pending: 1,
            }
        ));
    }

    #[test]
    fn quic_receiver_feedback_synthesizes_missing_source_symbol_requests() {
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(384, 13))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let decoders = decoders_from_manifest(&manifest, &config).expect("decoders");

        let first_two = source_symbol_requests(&decoders, 2);
        assert_eq!(
            first_two,
            vec![
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 0,
                    esi: 0,
                },
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 0,
                    esi: 1,
                },
            ]
        );

        let all = source_symbol_requests(&decoders, 0);
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[2],
            QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 2,
            }
        );
    }

    #[test]
    fn quic_source_symbol_request_rebuilds_exact_source_payload() {
        let config = QuicConfig {
            symbol_size: 512,
            max_block_size: 1024,
            ..trusted_quic_config()
        };
        let bytes: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
        let enc = QuicEntryEncoder {
            index: 7,
            object_id: entry_object_id("source-request", 7),
            bytes: bytes.clone(),
            repair_cursor: 0,
        };

        let first_block_tail = source_symbol_for_request(
            &enc,
            QuicSourceSymbolRequest {
                entry: 7,
                sbn: 0,
                esi: 1,
            },
            &config,
        )
        .expect("source symbol");
        assert!(first_block_tail.kind().is_source());
        assert_eq!(first_block_tail.sbn(), 0);
        assert_eq!(first_block_tail.esi(), 1);
        assert_eq!(first_block_tail.data(), &bytes[512..1024]);

        let final_block = source_symbol_for_request(
            &enc,
            QuicSourceSymbolRequest {
                entry: 7,
                sbn: 1,
                esi: 0,
            },
            &config,
        )
        .expect("final source symbol");
        assert_eq!(&final_block.data()[..476], &bytes[1024..]);
        assert!(final_block.data()[476..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn quic_control_handshake_accepts_matching_sender() {
        let (cx, mut client, mut server) = established_pair();
        let config = trusted_quic_config();
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
        assert!(ack.reason.is_none());
    }

    #[test]
    fn quic_control_handshake_rejects_wrong_protocol_and_reports_reason() {
        let (cx, mut client, mut server) = established_pair();
        let config = trusted_quic_config();
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
    fn send_path_rejects_missing_source_before_connect() {
        let cx = Cx::for_testing();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(send_path(
            &cx,
            addr,
            Path::new("/nonexistent/source"),
            trusted_quic_config(),
            "sender",
        ));
        assert!(matches!(result, Err(QuicTransportError::Source(_))));
    }

    #[test]
    fn send_path_valid_source_fails_closed_at_native_connect_boundary() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("payload.bin");
        std::fs::write(&source, b"payload").expect("write source");
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(send_path(
            &cx,
            addr,
            &source,
            trusted_quic_config(),
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
            ..trusted_quic_config()
        };
        let result = block_on(send_path(&cx, addr, Path::new("/x"), cfg, "sender"));
        assert!(matches!(result, Err(QuicTransportError::Config(_))));
    }

    #[test]
    fn receive_connection_rejects_missing_control_stream_without_scaffold_success() {
        use crate::net::quic_native::NativeQuicConnectionConfig;
        let cx = Cx::for_testing();
        let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(receive_connection(
            &cx,
            conn,
            peer,
            Path::new("/tmp"),
            trusted_quic_config(),
            "receiver",
        ));
        match result {
            Ok(report) => panic!("missing control stream must not fake success: {report:?}"),
            Err(QuicTransportError::NotImplemented {
                operation: "receive_connection",
                ..
            }) => panic!("receive_connection should be wired past the B1 scaffold"),
            Err(_) => {}
        }
    }

    #[test]
    fn quic_receiver_rejects_unsafe_manifest_root_names() {
        let dest = Path::new("dest");
        assert_eq!(
            quic_safe_base_for_root_name(dest, "payload").expect("safe root"),
            dest.join("payload")
        );

        for root_name in [
            ".",
            "..",
            "../payload",
            "nested/payload",
            "/tmp/payload",
            "payload\\evil",
            "C:payload",
        ] {
            match quic_safe_base_for_root_name(dest, root_name) {
                Err(QuicTransportError::Source(message)) => {
                    assert!(
                        message.contains("root_name"),
                        "source error should name root_name for {root_name:?}: {message}"
                    );
                }
                other => panic!("unsafe root_name {root_name:?} must fail closed, got {other:?}"),
            }
        }
    }

    #[test]
    fn quic_receiver_rejects_unsafe_manifest_relative_paths() {
        let base = Path::new("base");
        assert_eq!(
            quic_join_relative(base, "nested/file.bin").expect("safe relative path"),
            base.join("nested").join("file.bin")
        );

        for rel_path in [
            "",
            ".",
            "../file.bin",
            "/abs/file.bin",
            "nested/../file.bin",
            "nested/./file.bin",
            "nested//file.bin",
            "nested\\file.bin",
            "C:file.bin",
        ] {
            match quic_join_relative(base, rel_path) {
                Err(QuicTransportError::Source(message)) => {
                    assert!(
                        message.contains("unsafe path"),
                        "source error should name unsafe path for {rel_path:?}: {message}"
                    );
                }
                other => panic!("unsafe rel_path {rel_path:?} must fail closed, got {other:?}"),
            }
        }
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
