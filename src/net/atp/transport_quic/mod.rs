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
//! root vs. the manifest, atomic commit only on a full match). The native UDP
//! QUIC sender uses file-backed encoders that read one source block at a time,
//! and the receiver stages decoded blocks directly to disk before final
//! verification/commit. The in-memory encoder/decoder helpers remain for unit
//! tests and scaffold-only drivers; they are not the B5 bounded-memory proof
//! path.

#[cfg(feature = "tls")]
pub mod native_link;
pub mod symbol_datagram;
pub mod symbol_envelope;

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::object::{ContentId, MetadataPolicy};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder;
use crate::config::EncodingConfig;
use crate::cx::Cx;
use crate::decoding::{
    BlockDecodeJob, BlockDecodeOutcome, BlockStateKind, DecodingConfig, DecodingPipeline,
    DeferredSymbolAcceptResult, MissingSourceSymbol, RejectReason, SymbolAcceptResult,
    run_block_decode_job,
};
use crate::encoding::EncodingPipeline;
use crate::io::AsyncReadExt;
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, MAX_FRAME_SIZE, ProtocolVersion};
use crate::net::atp::quic::AtpTransportMetrics;
use crate::net::atp::transport_common::{
    EntryDigest, EntryMetadata, FileKind, MetadataApplyReport, StreamingError,
    apply_entry_metadata, collect_entries, flat_merkle_root_from_digests,
    flat_merkle_root_from_slices, hash_file_streaming, hex_encode, metadata_commitment,
    read_entry_metadata,
};
use crate::net::atp::transport_rq::{
    RqConfig, RqError, effective_max_block_size_for_largest_entry as rq_effective_max_block_size,
};
use crate::net::quic_native::{
    ManagedEndpointError, ManagedQuicEndpoint, NativeQuicConnection, NativeQuicConnectionError,
    QuicConnection, QuicPathStats, QuicTransportMachine, StreamDirection, StreamId, StreamRole,
    StreamTableError,
};
use crate::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::transport::{
    AggregatorConfig, MultipathAggregator, PathId, ReordererConfig, TransportPath,
};
use crate::types::Time;
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};

/// Opt-in stderr tracing for ATP/QUIC fountain-feedback diagnosis. This uses the
/// same environment switch as the RQ transport so a single MATRIX run can
/// capture both paths.
fn quic_rqtrace(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("ATP_RQ_TRACE").is_some() {
        eprintln!("[ATP_RQ_TRACE] [atp-quic] {args}");
    }
}

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
    BlockPlan as QuicAdaptiveBlockPlan,
    DEFAULT_COLD_START_PACING_BYTES_PER_S as QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S,
    PathEstimate as QuicPathEstimate, PathSignalSample as QuicPathSignalSample,
    RateMatchedPacingPlan as QuicRateMatchedPacingPlan,
    rate_matched_pacing_plan as rq_rate_matched_pacing_plan,
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

/// Default RaptorQ source-block size in bytes.
///
/// With 1 KiB symbols this targets K ~= 512 source symbols per block, matching
/// the RQ transport's effective block plan for normal transfer entries. The
/// sender carries this value in the QUIC Hello and the receiver rejects
/// mismatches, so mixed-version peers fail closed instead of silently decoding
/// with different block geometry.
pub const DEFAULT_MAX_BLOCK_SIZE: usize = 512 * 1024;

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
///
/// Lossy ATP/QUIC must let RaptorQ repair loop until block convergence or the
/// transfer deadline. A small round count can strand the final per-block
/// deficits even while the receiver is still making progress, so the default is
/// deliberately high; tests and callers can still set a lower explicit cap.
pub const DEFAULT_MAX_FEEDBACK_ROUNDS: u32 = 1024;

/// Maximum sparse source-symbol retransmit requests accepted in one feedback round.
const MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND: usize = 2048;

/// Maximum targeted repair block entries accepted in one feedback round.
const MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND: usize = 16_384;

/// Maximum targeted fresh repair symbols accepted in one feedback round.
const MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND: usize = 1 << 20;

/// Maximum native QUIC DATAGRAM symbols decoded before returning to the async
/// receiver loop.
///
/// Keep this aligned with the native receiver pump width: one UDP pump turn can
/// enqueue 512 symbols, so the decoder must be able to drain that full batch on
/// arrival before asking the sender for repair. Smaller slices let the no-evict
/// receive queue grow behind the decoder under lossy bursts and can manufacture
/// unnecessary NeedMore rounds.
const NATIVE_SYMBOL_DRAIN_BATCH: usize = 512;

/// Maximum native QUIC receiver decode jobs one entry may have in flight.
///
/// Mirrors the post-MATRIX-49/50 RQ receiver bound: enough fan-out to keep
/// independent bounded-K blocks off the hot receive pump, while avoiding
/// unbounded blocking-pool and decoded-block memory pressure under bursty loss.
const QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY: usize = 64;
/// Maximum native QUIC receiver decode jobs one transfer may have in flight.
///
/// The per-entry bound alone is insufficient for tree transfers: thousands of
/// small files could otherwise multiply the blocking-pool queue and retained
/// decoded-block memory by entry count. Once this transfer-wide window is full,
/// decode falls back to the existing inline path until ready jobs drain.
const QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER: usize = 64;
/// Keep tiny encrypted tree entries on the inline decode path. A 50M encrypted
/// bulk object still has enough independent K512 blocks to amortize blocking-pool
/// dispatch; sub-8MiB entries usually do not.
const QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const QUIC_PARALLEL_DECODE_MIN_SOURCE_BLOCKS: usize = 32;

const QUIC_PRIMARY_RECEIVE_PATH_ID: PathId = PathId(1);

/// Default adaptive datagram fan-out hint.
///
/// Phase D wires true multi-connection fan-out. Until then this remains a
/// bounded, explicit controller output carried in the transfer config so C1 can
/// prove deterministic arm application without changing the single-connection
/// B2/B3 data path.
pub const DEFAULT_DATAGRAM_FANOUT: usize = 1;

/// Default upper bound for one paced QUIC DATAGRAM spray burst.
///
/// C3 still lets the congestion window choose a smaller burst. This cap prevents
/// a very large cwnd estimate from turning one scheduler slice into an unbounded
/// outbound queue while still letting the native encrypted link coalesce a
/// near-full jumbo 1-RTT packet of symbol DATAGRAM frames after MATRIX-39
/// removed the old one-symbol packet budget.
pub const DEFAULT_MAX_SPRAY_SYMBOLS_PER_FLUSH: usize = 54;

const QUIC_SPRAY_BURST_RTT_FRACTION: f64 = 0.125;
const QUIC_SPRAY_MIN_PAUSE: Duration = Duration::from_millis(1);
const QUIC_SPRAY_MAX_PAUSE: Duration = Duration::from_secs(1);
const QUIC_SPRAY_MIN_BACKOFF: f64 = 0.10;
const QUIC_AIMD_LOSS_DECREASE_THRESHOLD: f64 = 0.03;
const QUIC_AIMD_CLEAN_INCREASE_THRESHOLD: f64 = 0.0015;
const QUIC_AIMD_MULTIPLICATIVE_DECREASE: f64 = 0.50;
const QUIC_AIMD_ADDITIVE_INCREASE_BYTES_PER_S: u64 = 1024 * 1024;
const QUIC_AIMD_MIN_RATE_BPS: u64 = 512 * 1024;
const QUIC_AIMD_MAX_RATE_BPS: u64 = 64 * 1024 * 1024;
const QUIC_FEEDBACK_REPAIR_LOSS_ENABLE_MIN: f64 = 0.005;
const QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION: f64 = 0.25;
const QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_MIN: f64 = 0.005;
const QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD: f64 = 0.50;

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
    /// Optional sender bandwidth cap in bytes per second.
    ///
    /// This is the internal transport knob that future CLI `--bwlimit` plumbing
    /// will set. `None` lets QUIC path signals select the pacing rate.
    pub bwlimit_bps: Option<u64>,
    /// Maximum DATAGRAM symbols queued before a paced flush.
    ///
    /// The live decision is the minimum of this cap, the cwnd-derived burst, and
    /// any bwlimit/responsiveness backoff.
    pub max_spray_symbols_per_flush: usize,
    /// Normalized host pressure used by the pacing policy.
    ///
    /// `0.0` means no local responsiveness pressure; `1.0` means saturated. The
    /// caller owns sampling CPU/loadavg/cgroup pressure and passes the snapshot
    /// here, keeping this library path deterministic and ambient-free.
    pub responsiveness_pressure: f64,
    /// Optional per-symbol authentication context for QUIC DATAGRAM symbols.
    ///
    /// When present, senders append an HMAC tag to every symbol envelope and
    /// receivers verify every symbol before decoding.
    pub symbol_auth_context: Option<SecurityContext>,
    /// Explicit escape hatch for trusted loopback/lab links that intentionally
    /// accept integrity-vs-manifest only.
    pub allow_unauthenticated_symbols: bool,
    /// Filesystem-metadata fidelity policy for manifest entries.
    pub metadata_policy: MetadataPolicy,
    /// Opt-in recreation of safe special files. Defaults to skip-and-trace.
    pub allow_special_files: bool,
    /// Opt-in hardlink preservation within a transfer.
    pub preserve_hardlinks: bool,
    /// Deterministic test/diagnostic symbol-loss injection. When nonzero, the
    /// sender skips every Nth symbol on the *initial* spray only (never on a
    /// repair round), so the fountain feedback loop must recover them. Zero
    /// disables injection. Mirrors `transport_rq`'s `debug_drop_one_in`.
    pub debug_drop_one_in: u32,
    /// Client-side TLS trust for [`send_path`]: the server name to verify and the
    /// root certificates that gate the handshake (no insecure skip-verify path).
    /// Required to open a real native QUIC connection; absent fails closed.
    #[cfg(feature = "tls")]
    pub client_tls: Option<native_link::QuicClientTls>,
    /// Server-side TLS material for the native receive path: the presented
    /// certificate chain and private key. Required to accept a real native QUIC
    /// connection; absent fails closed.
    #[cfg(feature = "tls")]
    pub server_tls: Option<native_link::QuicServerTls>,
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
            bwlimit_bps: None,
            max_spray_symbols_per_flush: DEFAULT_MAX_SPRAY_SYMBOLS_PER_FLUSH,
            responsiveness_pressure: 0.0,
            symbol_auth_context: None,
            allow_unauthenticated_symbols: false,
            metadata_policy: MetadataPolicy::default(),
            allow_special_files: false,
            preserve_hardlinks: false,
            debug_drop_one_in: 0,
            #[cfg(feature = "tls")]
            client_tls: None,
            #[cfg(feature = "tls")]
            server_tls: None,
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
        if matches!(self.bwlimit_bps, Some(0)) {
            return Err(QuicTransportError::Config(
                "bwlimit_bps must be greater than 0 when set".to_string(),
            ));
        }
        if self.max_spray_symbols_per_flush == 0 {
            return Err(QuicTransportError::Config(
                "max_spray_symbols_per_flush must be greater than 0".to_string(),
            ));
        }
        if !self.responsiveness_pressure.is_finite()
            || !(0.0..=1.0).contains(&self.responsiveness_pressure)
        {
            return Err(QuicTransportError::Config(
                "responsiveness_pressure must be finite and in [0.0, 1.0]".to_string(),
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

/// Result of one QUIC adaptive pacing epoch.
#[derive(Debug, Clone)]
pub struct QuicAdaptivePacingDecision {
    /// Transfer config with the selected block/FEC/fan-out geometry and raw
    /// pacing cap applied.
    pub config: QuicConfig,
    /// Shared calibrated rate plan used to produce this decision.
    pub rate_plan: QuicRateMatchedPacingPlan,
    /// QUIC spray pacing decision derived from `config` and the current path
    /// signal.
    pub spray: QuicSprayPacingDecision,
}

/// Convert a shared adaptive path estimate into a QUIC transfer config and
/// spray pacing decision.
///
/// This is the Phase-C bridge from `PathEstimate` to QUIC's datagram pacing:
/// the shared model computes calibrated FEC overhead and a raw rate cap
/// `lambda`, where useful payload is bounded by `lambda / (1 + epsilon)`.
/// QUIC applies that raw cap through the existing deterministic spray pacer.
/// If evidence is too thin, the fixed transfer geometry is preserved and only a
/// conservative cold-start rate cap is applied.
pub fn quic_adaptive_rate_matched_pacing_decision(
    config: &QuicConfig,
    estimate: &QuicPathEstimate,
    path: QuicPathSignalSample,
    policy: &QuicAdaptivePolicy,
    cpu_parallelism: usize,
) -> Result<QuicAdaptivePacingDecision, QuicTransportError> {
    config.validate()?;

    let cold_start_bytes_per_s = config
        .bwlimit_bps
        .map_or(QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S, |cap| {
            cap.max(1) as f64
        });
    let max_burst_datagrams = u32::try_from(config.max_spray_symbols_per_flush)
        .unwrap_or(u32::MAX)
        .max(1);
    let rate_plan = rq_rate_matched_pacing_plan(
        estimate,
        policy,
        config.symbol_size,
        cold_start_bytes_per_s,
        max_burst_datagrams,
    );

    let mut adapted = if rate_plan.cold_start {
        config.clone()
    } else {
        apply_quic_adaptive_block_plan(config.clone(), rate_plan.block)?
    };
    adapted.bwlimit_bps = Some(adaptive_raw_pacing_bytes_per_s(config, rate_plan));
    adapted.max_spray_symbols_per_flush = adapted
        .max_spray_symbols_per_flush
        .min(usize::try_from(rate_plan.max_burst_datagrams).unwrap_or(usize::MAX))
        .max(1);
    adapted.validate()?;

    let spray =
        quic_spray_pacing_decision_from_config_with_cpu(&adapted, path.clamped(), cpu_parallelism);

    Ok(QuicAdaptivePacingDecision {
        config: adapted,
        rate_plan,
        spray,
    })
}

fn adaptive_raw_pacing_bytes_per_s(
    config: &QuicConfig,
    rate_plan: QuicRateMatchedPacingPlan,
) -> u64 {
    let raw_bytes = rate_plan
        .raw_pacing_bits_per_s
        .saturating_add(7)
        .checked_div(8)
        .unwrap_or(1)
        .max(1);
    config
        .bwlimit_bps
        .map_or(raw_bytes, |cap| cap.max(1).min(raw_bytes))
}

const MIN_QUIC_SPRAY_PACING_RTT_S: f64 = 0.001;
const MAX_QUIC_SPRAY_PACING_RTT_S: f64 = 60.0;
const MIN_QUIC_SPRAY_RATE_BPS: u64 = 1;

/// Deterministic machine-responsiveness pressure sampled by the caller.
///
/// The transport does not read load average or CPU state itself; that would be
/// ambient authority and would make lab replay depend on the host. Operators or
/// future CLI wiring can feed normalized values in `[0, 1]`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct QuicMachinePressure {
    /// CPU saturation pressure, where `0.0` is idle and `1.0` is saturated.
    pub cpu_pressure: f64,
    /// Load/backlog pressure, where `0.0` is healthy and `1.0` is saturated.
    pub load_pressure: f64,
}

impl QuicMachinePressure {
    #[must_use]
    fn clamped(self) -> Self {
        Self {
            cpu_pressure: clamp_unit_pressure(self.cpu_pressure),
            load_pressure: clamp_unit_pressure(self.load_pressure),
        }
    }

    #[must_use]
    fn max_pressure(self) -> f64 {
        self.cpu_pressure.max(self.load_pressure)
    }
}

/// Inputs for one QUIC symbol-spray pacing epoch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuicSprayPacingInput {
    /// Latest QUIC recovery/congestion-control signals.
    pub path: QuicPathSignalSample,
    /// RaptorQ symbol payload bytes.
    pub symbol_size: u16,
    /// Maximum application DATAGRAM payload bytes.
    pub max_datagram_size: usize,
    /// Future Phase-D fan-out hint. Until multi-connection fan-out lands, this
    /// divides the per-connection budget so an N-way sender cannot multiply the
    /// aggregate offered load by N.
    pub datagram_fanout: usize,
    /// Optional user/operator bandwidth cap in bytes per second. J6 wires this
    /// from `--bwlimit`; C3 keeps it as a pure input.
    pub bandwidth_limit_bps: Option<u64>,
    /// Caller-sampled host responsiveness pressure.
    pub machine_pressure: QuicMachinePressure,
    /// Hard burst ceiling before a flush/yield, independent of path cwnd.
    pub burst_cap_symbols: usize,
}

/// The limiting factor chosen for a QUIC spray pacing epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicSprayPacingLimiter {
    /// Congestion window / RTT derived pacing is the active limiter.
    CongestionWindow,
    /// The fixed burst ceiling capped a larger cwnd/rate budget.
    BurstCap,
    /// Recent loss reduced the pacing rate.
    LossBackoff,
    /// Machine responsiveness pressure reduced the pacing rate.
    ResponsivenessBackoff,
    /// The optional bandwidth cap reduced the pacing rate.
    BandwidthLimit,
}

impl QuicSprayPacingLimiter {
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            Self::CongestionWindow => "cwnd",
            Self::BurstCap => "burst_cap",
            Self::LossBackoff => "loss",
            Self::ResponsivenessBackoff => "responsiveness",
            Self::BandwidthLimit => "bandwidth_limit",
        }
    }
}

/// Deterministic QUIC symbol-spray pacing decision for one epoch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuicSprayPacingDecision {
    /// Maximum symbols queued before flushing the native QUIC data plane.
    pub max_burst_symbols: usize,
    /// Pause after each burst so the receiver and kernel socket drain.
    pub pause_after_burst: Duration,
    /// Effective pacing rate in bytes per second after all caps/backoffs.
    pub pacing_rate_bps: u64,
    /// Raw cwnd converted to symbol slots.
    pub cwnd_symbols: usize,
    /// Per-fan-out share of the cwnd symbol budget.
    pub cwnd_share_symbols: usize,
    /// Loss multiplier applied to the cwnd/RTT rate.
    pub loss_backoff: f64,
    /// Machine responsiveness multiplier applied to the rate.
    pub responsiveness_backoff: f64,
    /// Clamped RTT used for the rate calculation.
    pub path_rtt_s: f64,
    /// Clamped path cwnd bytes used for the rate calculation.
    pub path_cwnd_bytes: u64,
    /// Clamped recent loss rate used for the rate calculation.
    pub path_loss_rate: f64,
    /// Active limiting factor.
    pub limiter: QuicSprayPacingLimiter,
}

impl QuicSprayPacingDecision {
    /// Emit this pacing epoch as structured trace fields. This is intended to
    /// run once per symbol round, never per symbol.
    pub fn trace_epoch(&self, cx: &Cx, epoch: u64) {
        let epoch = epoch.to_string();
        let max_burst_symbols = self.max_burst_symbols.to_string();
        let pause_after_burst_micros = self.pause_after_burst.as_micros().to_string();
        let pacing_rate_bps = self.pacing_rate_bps.to_string();
        let cwnd_symbols = self.cwnd_symbols.to_string();
        let cwnd_share_symbols = self.cwnd_share_symbols.to_string();
        let loss_backoff = format!("{:.6}", self.loss_backoff);
        let responsiveness_backoff = format!("{:.6}", self.responsiveness_backoff);
        let path_rtt_s = format!("{:.6}", self.path_rtt_s);
        let path_cwnd_bytes = self.path_cwnd_bytes.to_string();
        let path_loss_rate = format!("{:.6}", self.path_loss_rate);

        cx.trace_with_fields(
            "atp_quic.spray.pacing_epoch",
            &[
                ("transport", "quic"),
                ("epoch", &epoch),
                ("max_burst_symbols", &max_burst_symbols),
                ("pause_after_burst_micros", &pause_after_burst_micros),
                ("pacing_rate_bps", &pacing_rate_bps),
                ("cwnd_symbols", &cwnd_symbols),
                ("cwnd_share_symbols", &cwnd_share_symbols),
                ("loss_backoff", &loss_backoff),
                ("responsiveness_backoff", &responsiveness_backoff),
                ("path_rtt_s", &path_rtt_s),
                ("path_cwnd_bytes", &path_cwnd_bytes),
                ("path_loss_rate", &path_loss_rate),
                ("limiter", self.limiter.as_str()),
            ],
        );
    }
}

/// Convert QUIC path signals and caller-supplied caps into one bounded spray
/// pacing decision.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
pub fn quic_spray_pacing_decision(input: QuicSprayPacingInput) -> QuicSprayPacingDecision {
    let path = input.path.clamped();
    let machine_pressure = input.machine_pressure.clamped();
    let symbol_payload = usize::from(input.symbol_size.max(1))
        .saturating_add(AUTH_ENVELOPE_HEADER_LEN)
        .min(input.max_datagram_size.max(1));
    let fanout = input.datagram_fanout.max(1);
    let burst_cap = input.burst_cap_symbols.max(1);
    let rtt_s = path
        .smoothed_rtt_s
        .clamp(MIN_QUIC_SPRAY_PACING_RTT_S, MAX_QUIC_SPRAY_PACING_RTT_S);

    let cwnd_symbols_u64 = path
        .congestion_window_bytes
        .checked_div(u64::try_from(symbol_payload).unwrap_or(u64::MAX).max(1))
        .unwrap_or(0)
        .max(1);
    let cwnd_symbols = usize::try_from(cwnd_symbols_u64).unwrap_or(usize::MAX);
    let cwnd_share_symbols = (cwnd_symbols / fanout).max(1);

    let base_rate = path.congestion_window_bytes as f64 / rtt_s;
    let loss_backoff = (1.0 - (2.0 * path.loss_rate)).clamp(QUIC_SPRAY_MIN_BACKOFF, 1.0);
    let pressure = machine_pressure.max_pressure();
    let responsiveness_backoff = (1.0 - (0.75 * pressure)).clamp(QUIC_SPRAY_MIN_BACKOFF, 1.0);
    let mut rate = (base_rate / fanout as f64) * loss_backoff * responsiveness_backoff;

    let cap_applied = if let Some(cap) = input.bandwidth_limit_bps {
        let cap = cap.max(MIN_QUIC_SPRAY_RATE_BPS);
        if rate > cap as f64 {
            rate = cap as f64;
            true
        } else {
            false
        }
    } else {
        false
    };

    let rate = if rate.is_finite() && rate > 0.0 {
        rate
    } else {
        MIN_QUIC_SPRAY_RATE_BPS as f64
    };
    let pacing_rate_bps = rate.ceil().max(MIN_QUIC_SPRAY_RATE_BPS as f64) as u64;
    let burst_by_rate = ((rate * rtt_s * QUIC_SPRAY_BURST_RTT_FRACTION) / symbol_payload as f64)
        .ceil()
        .max(1.0) as usize;
    let max_burst_symbols = burst_by_rate.min(cwnd_share_symbols).min(burst_cap).max(1);
    let burst_bytes = u64::try_from(max_burst_symbols)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::try_from(symbol_payload).unwrap_or(u64::MAX).max(1));
    let pause_after_burst = pacing_pause_for_bytes(burst_bytes, pacing_rate_bps);

    let limiter = if cap_applied {
        QuicSprayPacingLimiter::BandwidthLimit
    } else if pressure > 0.0 {
        QuicSprayPacingLimiter::ResponsivenessBackoff
    } else if path.loss_rate > 0.0 {
        QuicSprayPacingLimiter::LossBackoff
    } else if burst_cap < burst_by_rate.min(cwnd_share_symbols) {
        QuicSprayPacingLimiter::BurstCap
    } else {
        QuicSprayPacingLimiter::CongestionWindow
    };

    QuicSprayPacingDecision {
        max_burst_symbols,
        pause_after_burst,
        pacing_rate_bps,
        cwnd_symbols,
        cwnd_share_symbols,
        loss_backoff,
        responsiveness_backoff,
        path_rtt_s: rtt_s,
        path_cwnd_bytes: path.congestion_window_bytes,
        path_loss_rate: path.loss_rate,
        limiter,
    }
}

/// Build a C3 pacing decision from a transfer config and C2 path signal.
#[must_use]
pub fn quic_spray_pacing_decision_from_config(
    config: &QuicConfig,
    path: QuicPathSignalSample,
) -> QuicSprayPacingDecision {
    quic_spray_pacing_decision_from_config_with_cpu(config, path, usize::MAX)
}

/// Build a C3/D1 pacing decision with an explicit CPU parallelism bound.
#[must_use]
pub fn quic_spray_pacing_decision_from_config_with_cpu(
    config: &QuicConfig,
    path: QuicPathSignalSample,
    cpu_parallelism: usize,
) -> QuicSprayPacingDecision {
    quic_spray_pacing_decision(QuicSprayPacingInput {
        path,
        symbol_size: config.symbol_size,
        max_datagram_size: config.max_datagram_size,
        datagram_fanout: quic_effective_datagram_fanout(config, cpu_parallelism),
        bandwidth_limit_bps: config.bwlimit_bps,
        machine_pressure: QuicMachinePressure {
            cpu_pressure: config.responsiveness_pressure,
            load_pressure: 0.0,
        },
        burst_cap_symbols: config.max_spray_symbols_per_flush,
    })
}

/// Bound the configured QUIC DATAGRAM fan-out by connection and CPU capacity.
///
/// `QuicConfig::validate` rejects zero fan-out, but this helper is deliberately
/// total so callers that have not validated yet still get one usable lane
/// instead of a divide-by-zero hazard.
#[must_use]
pub fn quic_effective_datagram_fanout(config: &QuicConfig, cpu_parallelism: usize) -> usize {
    config
        .datagram_fanout
        .max(1)
        .min(config.max_active_connections.max(1))
        .min(cpu_parallelism.max(1))
}

/// One RaptorQ source block that is ready for QUIC fan-out scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicFanoutBlock {
    /// Manifest entry index.
    pub entry: u32,
    /// RaptorQ source block number within the entry.
    pub sbn: u8,
    /// Number of source or repair symbols to spray for this block.
    pub symbols: usize,
}

/// One scheduled symbol slot on a bounded QUIC fan-out lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicFanoutSymbolSlot {
    /// Zero-based fan-out lane / connection index.
    pub connection: usize,
    /// Manifest entry index.
    pub entry: u32,
    /// RaptorQ source block number within the entry.
    pub sbn: u8,
    /// Zero-based symbol ordinal within this block's scheduled run.
    pub symbol_index_in_block: usize,
}

/// Deterministic D1 fan-out plan for one symbol-spray epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicFanoutSprayPlan {
    /// Bounded connection count used for this plan.
    pub connection_count: usize,
    /// Ordered symbol slots to spray.
    pub slots: Vec<QuicFanoutSymbolSlot>,
    /// Per-connection symbol counts for tracing and assertions.
    pub per_connection_symbols: Vec<u64>,
    /// Total symbols covered by the plan.
    pub total_symbols: u64,
}

impl QuicFanoutSprayPlan {
    /// Whether this epoch has no positive-symbol work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

/// Binding from a logical fan-out lane to a physical QUIC connection.
///
/// A migrated path changes the physical connection/generation, not the logical
/// symbol lane. Symbols keep their original object/block/ESI identity, so a
/// migration cannot make the receiver treat retransmitted symbols as new data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicFanoutLaneBinding {
    /// Logical lane index emitted by [`QuicBlockInterleavingScheduler`].
    pub logical_connection: usize,
    /// Physical connection index currently serving this lane.
    pub physical_connection: usize,
    /// Monotonic migration generation for this lane.
    pub migration_generation: u64,
}

impl QuicFanoutLaneBinding {
    /// Identity binding for a non-migrated lane.
    #[must_use]
    pub const fn identity(connection: usize) -> Self {
        Self {
            logical_connection: connection,
            physical_connection: connection,
            migration_generation: 0,
        }
    }
}

/// Symbol work assigned to one logical fan-out lane / physical connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicFanoutConnectionBatch {
    /// Logical lane index.
    pub logical_connection: usize,
    /// Physical QUIC connection currently carrying this lane.
    pub physical_connection: usize,
    /// Migration generation for replay/trace assertions.
    pub migration_generation: u64,
    /// Ordered symbol slots for this connection.
    pub slots: Vec<QuicFanoutSymbolSlot>,
}

impl QuicFanoutConnectionBatch {
    /// Number of symbols assigned to this connection in the epoch.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.slots.len()
    }
}

/// Per-connection dispatch view of a fan-out spray epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicFanoutDispatchPlan {
    /// Bounded logical connection count used for this plan.
    pub connection_count: usize,
    /// One deterministic batch per logical connection.
    pub batches: Vec<QuicFanoutConnectionBatch>,
    /// Total symbols covered by the plan.
    pub total_symbols: u64,
}

impl QuicFanoutDispatchPlan {
    /// Whether this epoch has no positive-symbol work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_symbols == 0
    }
}

/// Deterministic block-interleaving scheduler for D1 QUIC fan-out.
///
/// The scheduler streams one symbol slot at a time. It round-robins across
/// blocks first, then across connection lanes, so a large block cannot starve
/// other pending blocks and each configured lane receives work when enough
/// symbols exist.
#[derive(Debug, Clone)]
pub struct QuicBlockInterleavingScheduler {
    blocks: Vec<QuicFanoutBlock>,
    remaining: Vec<usize>,
    emitted: Vec<usize>,
    next_block: usize,
    next_connection: usize,
    connection_count: usize,
}

impl QuicBlockInterleavingScheduler {
    /// Build a scheduler over the non-empty block work items.
    #[must_use]
    pub fn new(blocks: &[QuicFanoutBlock], connection_count: usize) -> Self {
        let blocks = blocks
            .iter()
            .copied()
            .filter(|block| block.symbols > 0)
            .collect::<Vec<_>>();
        let remaining = blocks.iter().map(|block| block.symbols).collect::<Vec<_>>();
        let emitted = vec![0; blocks.len()];
        Self {
            blocks,
            remaining,
            emitted,
            next_block: 0,
            next_connection: 0,
            connection_count: connection_count.max(1),
        }
    }

    /// Number of fan-out lanes this scheduler can feed.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connection_count
    }

    /// Whether no positive-symbol block work was supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl Iterator for QuicBlockInterleavingScheduler {
    type Item = QuicFanoutSymbolSlot;

    fn next(&mut self) -> Option<Self::Item> {
        if self.blocks.is_empty() {
            return None;
        }

        for _ in 0..self.blocks.len() {
            let block_index = self.next_block;
            self.next_block = (self.next_block + 1) % self.blocks.len();
            if self.remaining[block_index] == 0 {
                continue;
            }

            let block = self.blocks[block_index];
            let symbol_index_in_block = self.emitted[block_index];
            self.remaining[block_index] -= 1;
            self.emitted[block_index] += 1;

            let connection = self.next_connection;
            self.next_connection = (self.next_connection + 1) % self.connection_count;

            return Some(QuicFanoutSymbolSlot {
                connection,
                entry: block.entry,
                sbn: block.sbn,
                symbol_index_in_block,
            });
        }

        None
    }
}

/// Plan one bounded QUIC fan-out spray epoch from pending block work.
#[must_use]
pub fn quic_plan_fanout_spray(
    config: &QuicConfig,
    cpu_parallelism: usize,
    blocks: &[QuicFanoutBlock],
) -> QuicFanoutSprayPlan {
    let connection_count = quic_effective_datagram_fanout(config, cpu_parallelism);
    let mut per_connection_symbols = vec![0u64; connection_count];
    let mut slots = Vec::new();

    for slot in QuicBlockInterleavingScheduler::new(blocks, connection_count) {
        if let Some(symbols) = per_connection_symbols.get_mut(slot.connection) {
            *symbols = symbols.saturating_add(1);
        }
        slots.push(slot);
    }

    let total_symbols = slots.len().try_into().unwrap_or(u64::MAX);
    QuicFanoutSprayPlan {
        connection_count,
        slots,
        per_connection_symbols,
        total_symbols,
    }
}

/// Plan a D1/D2 per-connection dispatch epoch with optional migrated lane
/// bindings.
///
/// `lane_bindings` may remap a logical fan-out lane to a new physical QUIC
/// connection after migration. Out-of-range bindings are ignored, so stale
/// migration receipts cannot create extra lanes or bypass the configured fan-out
/// bound.
#[must_use]
pub fn quic_plan_fanout_dispatch(
    config: &QuicConfig,
    cpu_parallelism: usize,
    blocks: &[QuicFanoutBlock],
    lane_bindings: &[QuicFanoutLaneBinding],
) -> QuicFanoutDispatchPlan {
    let spray = quic_plan_fanout_spray(config, cpu_parallelism, blocks);
    let mut bindings = (0..spray.connection_count)
        .map(QuicFanoutLaneBinding::identity)
        .collect::<Vec<_>>();
    for binding in lane_bindings {
        if let Some(slot) = bindings.get_mut(binding.logical_connection) {
            *slot = *binding;
        }
    }

    let mut batches = bindings
        .iter()
        .map(|binding| QuicFanoutConnectionBatch {
            logical_connection: binding.logical_connection,
            physical_connection: binding.physical_connection,
            migration_generation: binding.migration_generation,
            slots: Vec::new(),
        })
        .collect::<Vec<_>>();
    for slot in spray.slots {
        if let Some(batch) = batches.get_mut(slot.connection) {
            batch.slots.push(slot);
        }
    }

    QuicFanoutDispatchPlan {
        connection_count: spray.connection_count,
        batches,
        total_symbols: spray.total_symbols,
    }
}

/// Derive the initial source+proactive-repair symbol work from a transfer
/// manifest.
///
/// This is the Phase-D bridge between the source preflight and the fan-out
/// scheduler: it turns the effective per-entry block geometry into the exact
/// number of symbol slots the round-0 spray will offer, without reading source
/// bytes or changing the wire format.
pub fn quic_initial_fanout_blocks_for_manifest(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<Vec<QuicFanoutBlock>, QuicTransportError> {
    config.validate()?;
    let symbol_size = usize::from(config.symbol_size.max(1));
    let max_block = config.max_block_size.max(1);
    let mut blocks = Vec::new();
    for entry in &manifest.entries {
        let block_count = block_count_for_len(entry.size, config)?;
        for block_index in 0..block_count {
            let block_start = u64::try_from(block_index)
                .unwrap_or(u64::MAX)
                .saturating_mul(u64::try_from(max_block).unwrap_or(u64::MAX));
            let block_len = usize::try_from((entry.size - block_start).min(max_block as u64))
                .unwrap_or(usize::MAX);
            let source_symbols = block_len.div_ceil(symbol_size).max(1);
            let repair_symbols = initial_repair_per_block(block_len, config);
            blocks.push(QuicFanoutBlock {
                entry: entry.index,
                sbn: u8::try_from(block_index).map_err(|_| QuicTransportError::TooLarge {
                    size: entry.size,
                    max: u64::try_from(max_block)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(u64::from(u8::MAX) + 1),
                })?,
                symbols: source_symbols.saturating_add(repair_symbols),
            });
        }
    }
    Ok(blocks)
}

/// Plan the round-0 QUIC fan-out dispatch from a manifest and effective config.
pub fn quic_plan_initial_fanout_dispatch(
    config: &QuicConfig,
    cpu_parallelism: usize,
    manifest: &TransferManifest,
    lane_bindings: &[QuicFanoutLaneBinding],
) -> Result<QuicFanoutDispatchPlan, QuicTransportError> {
    let blocks = quic_initial_fanout_blocks_for_manifest(manifest, config)?;
    Ok(quic_plan_fanout_dispatch(
        config,
        cpu_parallelism,
        &blocks,
        lane_bindings,
    ))
}

/// Emit stable per-connection spray counts for D1 fan-out diagnostics.
pub fn trace_quic_fanout_spray_counts(cx: &Cx, round: u64, counts: &[u64]) {
    let round = round.to_string();
    let connections = counts.len().to_string();
    for (connection, symbols) in counts.iter().enumerate() {
        let connection = connection.to_string();
        let symbols = symbols.to_string();
        cx.trace_with_fields(
            "atp_quic.spray.fanout_connection",
            &[
                ("transport", "quic"),
                ("round", &round),
                ("connection", &connection),
                ("connections", &connections),
                ("symbols", &symbols),
            ],
        );
    }
}

/// Emit stable per-lane dispatch fields for a planned fan-out spray epoch.
pub fn trace_quic_fanout_dispatch_plan(cx: &Cx, round: u64, plan: &QuicFanoutDispatchPlan) {
    let round = round.to_string();
    let connections = plan.connection_count.to_string();
    let total_symbols = plan.total_symbols.to_string();
    for batch in &plan.batches {
        let logical_connection = batch.logical_connection.to_string();
        let physical_connection = batch.physical_connection.to_string();
        let migration_generation = batch.migration_generation.to_string();
        let symbols = batch.symbol_count().to_string();
        cx.trace_with_fields(
            "atp_quic.spray.fanout_dispatch",
            &[
                ("transport", "quic"),
                ("round", &round),
                ("logical_connection", &logical_connection),
                ("physical_connection", &physical_connection),
                ("migration_generation", &migration_generation),
                ("connections", &connections),
                ("symbols", &symbols),
                ("total_symbols", &total_symbols),
            ],
        );
    }
}

#[cfg(feature = "tls")]
pub(crate) fn quic_spray_pacing_decision_from_transport(
    config: &QuicConfig,
    transport: &QuicTransportMachine,
) -> QuicSprayPacingDecision {
    quic_spray_pacing_decision_from_config(config, quic_path_signal_from_transport(transport))
}

fn clamp_unit_pressure(value: f64) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

fn pacing_pause_for_bytes(bytes: u64, rate_bps: u64) -> Duration {
    duration_from_secs_clamped(bytes.max(1) as f64 / rate_bps.max(1) as f64)
}

struct QuicSymbolPacer {
    decision: QuicSprayPacingDecision,
    sent_since_pause: usize,
    epoch: u64,
}

impl QuicSymbolPacer {
    fn from_connection(config: &QuicConfig, connection: &QuicConnection) -> Self {
        Self::new(quic_spray_pacing_decision_from_config(
            config,
            quic_path_signal_from_connection(connection),
        ))
    }

    fn from_native_connection(config: &QuicConfig, connection: &NativeQuicConnection) -> Self {
        Self::new(quic_spray_pacing_decision_from_config(
            config,
            quic_path_signal_from_native_connection(connection),
        ))
    }

    fn new(decision: QuicSprayPacingDecision) -> Self {
        Self {
            decision,
            sent_since_pause: 0,
            epoch: 0,
        }
    }

    async fn after_symbol_sent(&mut self, cx: &Cx) -> Result<(), QuicTransportError> {
        self.sent_since_pause = self.sent_since_pause.saturating_add(1);
        if self.sent_since_pause < self.decision.max_burst_symbols {
            return Ok(());
        }
        self.decision.trace_epoch(cx, self.epoch);
        self.epoch = self.epoch.saturating_add(1);
        self.sent_since_pause = 0;
        crate::time::sleep(cx.now(), self.decision.pause_after_burst).await;
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)
    }
}

/// Convert A6 connection path stats into the shared adaptive reward signal.
///
/// RTT is reported in seconds for the adaptive controller, with smoothed RTT
/// preferred and the latest RTT sample used while smoothing has not initialized.
#[must_use]
pub fn quic_path_signal_from_stats(stats: QuicPathStats) -> QuicPathSignalSample {
    QuicPathSignalSample {
        smoothed_rtt_s: rtt_micros_to_seconds(
            stats.smoothed_rtt_micros.or(stats.latest_rtt_micros),
        ),
        congestion_window_bytes: stats.congestion_window_bytes,
        loss_rate: stats.loss_rate,
    }
    .clamped()
}

/// Snapshot the high-level A6 connection API as an adaptive path signal.
#[must_use]
pub fn quic_path_signal_from_connection(connection: &QuicConnection) -> QuicPathSignalSample {
    quic_path_signal_from_stats(connection.path_stats())
}

/// Snapshot a native QUIC connection as an adaptive path signal.
#[must_use]
pub fn quic_path_signal_from_native_connection(
    connection: &NativeQuicConnection,
) -> QuicPathSignalSample {
    quic_path_signal_from_transport(connection.transport())
}

/// Snapshot the native transport recovery/CC state as an adaptive path signal.
#[must_use]
pub fn quic_path_signal_from_transport(transport: &QuicTransportMachine) -> QuicPathSignalSample {
    let rtt = transport.rtt();
    QuicPathSignalSample {
        smoothed_rtt_s: rtt_micros_to_seconds(
            rtt.smoothed_rtt_micros().or(rtt.latest_rtt_micros()),
        ),
        congestion_window_bytes: transport.congestion_window_bytes(),
        loss_rate: transport.packet_loss_rate(),
    }
    .clamped()
}

/// Convert ATP QUIC metrics snapshots into the shared adaptive reward signal.
#[must_use]
pub fn quic_path_signal_from_metrics(metrics: &AtpTransportMetrics) -> QuicPathSignalSample {
    QuicPathSignalSample {
        smoothed_rtt_s: rtt_micros_to_seconds(
            metrics.smoothed_rtt_micros.or(metrics.latest_rtt_micros),
        ),
        congestion_window_bytes: metrics.congestion_window_bytes,
        loss_rate: metrics.loss_rate,
    }
    .clamped()
}

/// Feed a measured QUIC block outcome plus A6 path stats into the adaptive
/// reward update.
pub fn observe_quic_adaptive_path_stats(
    controller: &mut QuicAdaptiveController,
    sent: u64,
    received: u64,
    wall_s: f64,
    useful_bytes: u64,
    symbol_size: u16,
    stats: QuicPathStats,
) {
    controller.observe_path_signals(
        sent,
        received,
        wall_s,
        useful_bytes,
        symbol_size,
        quic_path_signal_from_stats(stats),
    );
}

fn finite_positive_or(value: f64, fallback: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        fallback.max(1.0)
    }
}

fn duration_from_secs_clamped(seconds: f64) -> Duration {
    Duration::from_secs_f64(
        finite_positive_or(seconds, QUIC_SPRAY_MIN_PAUSE.as_secs_f64()).clamp(
            QUIC_SPRAY_MIN_PAUSE.as_secs_f64(),
            QUIC_SPRAY_MAX_PAUSE.as_secs_f64(),
        ),
    )
}

fn rtt_micros_to_seconds(rtt_micros: Option<u64>) -> f64 {
    rtt_micros.map_or(0.0, |rtt| rtt as f64 / 1_000_000.0)
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
    #[error("[ASUP-E802] handshake rejected by peer: {0}")]
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
        "[ASUP-E801] transfer did not converge after {rounds} feedback rounds ({pending} entries still incomplete); if accepted symbols do not advance decode rank, see [ASUP-E805]"
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
    #[error("[ASUP-E804] transport timeout during {operation} after {timeout:?}")]
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

/// Sender → receiver marker for one completed QUIC symbol spray round.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
struct QuicRoundComplete {
    /// Number of QUIC DATAGRAM symbols the sender emitted in the completed
    /// spray round. Empty legacy ObjectComplete frames parse as unknown.
    #[serde(default)]
    round_symbols_sent: u64,
}

/// Receiver → sender fountain feedback: entries still needing more symbols.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct QuicNeedMore {
    /// Entry indices that have not yet decoded.
    pending: Vec<u32>,
    /// Fresh repair deficits for specific incomplete blocks.
    #[serde(default)]
    repair_blocks: Vec<QuicBlockRepairRequest>,
    /// Sparse systematic source symbols missing from incomplete blocks.
    #[serde(default)]
    source_symbols: Vec<QuicSourceSymbolRequest>,
    /// Matching QUIC DATAGRAM symbols observed by the receiver in the completed
    /// spray round. This is the pacing/loss signal; symbols that do not advance
    /// decode rank still prove that the datagram arrived on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_observed: Option<u64>,
    /// Receiver-computed symbol loss fraction for the completed spray round.
    ///
    /// AIMD uses this explicit wire-loss signal; pending decode pressure remains
    /// separate and only feeds repair/FEC sizing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_loss_fraction: Option<f64>,
    /// Matching QUIC DATAGRAM symbols accepted into a decoder in the completed
    /// spray round. Diagnostic only; duplicates or dependent repair rows can
    /// arrive without improving decode rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_accepted: Option<u64>,
}

/// Request for fresh repair symbols for one incomplete source block.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct QuicBlockRepairRequest {
    entry: u32,
    sbn: u8,
    symbols: u32,
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
fn validate_need_more_feedback(
    manifest: &TransferManifest,
    config: &QuicConfig,
    need: &QuicNeedMore,
) -> Result<std::collections::BTreeSet<u32>, QuicTransportError> {
    if !need.repair_blocks.is_empty() && !need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver requested both fresh repair blocks and source-symbol retransmits".to_string(),
        ));
    }
    if need.repair_blocks.len() > MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND {
        return Err(QuicTransportError::Integrity(format!(
            "receiver requested {} repair blocks in one feedback round (max {})",
            need.repair_blocks.len(),
            MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND
        )));
    }
    if need.source_symbols.len() > MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND {
        return Err(QuicTransportError::Integrity(format!(
            "receiver requested {} source symbols in one feedback round (max {})",
            need.source_symbols.len(),
            MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND
        )));
    }

    let manifest_entries = manifest
        .entries
        .iter()
        .map(|entry| (entry.index, entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut pending = std::collections::BTreeSet::new();
    for entry in &need.pending {
        if !manifest_entries.contains_key(entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair for unknown entry {entry}"
            )));
        }
        if !pending.insert(*entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested duplicate repair entry {entry}"
            )));
        }
    }
    if !pending.is_empty() && need.repair_blocks.is_empty() && need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver NeedMore listed pending entries without targeted repair/source deficits"
                .to_string(),
        ));
    }

    let mut block_requests = std::collections::BTreeSet::new();
    let mut repair_symbols = 0usize;
    for request in &need.repair_blocks {
        if !pending.contains(&request.entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair block for non-pending entry {}",
                request.entry
            )));
        }
        if request.symbols == 0 {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested zero repair symbols for entry={} sbn={}",
                request.entry, request.sbn
            )));
        }
        let Some(entry) = manifest_entries.get(&request.entry).copied() else {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair block for unknown entry {}",
                request.entry
            )));
        };
        validate_feedback_block(entry, request.sbn, config, "repair")?;
        if !block_requests.insert((request.entry, request.sbn)) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested duplicate repair block entry={} sbn={}",
                request.entry, request.sbn
            )));
        }
        repair_symbols =
            repair_symbols.saturating_add(usize::try_from(request.symbols).unwrap_or(usize::MAX));
        if repair_symbols > MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested {repair_symbols} repair symbols in one feedback round (max {})",
                MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND
            )));
        }
    }

    let mut source_requests = std::collections::BTreeSet::new();
    for request in &need.source_symbols {
        if !pending.contains(&request.entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested source symbol for non-pending entry {}",
                request.entry
            )));
        }
        let Some(entry) = manifest_entries.get(&request.entry).copied() else {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested source symbol for unknown entry {}",
                request.entry
            )));
        };
        let block_k = validate_feedback_block(entry, request.sbn, config, "source symbol")?;
        let esi = usize::try_from(request.esi).map_err(|_| {
            QuicTransportError::Integrity(format!(
                "source request esi {} outside entry {} block {} K={block_k}",
                request.esi, request.entry, request.sbn
            ))
        })?;
        if esi >= block_k {
            return Err(QuicTransportError::Integrity(format!(
                "source request esi {} outside entry {} block {} K={block_k}",
                request.esi, request.entry, request.sbn
            )));
        }
        if !source_requests.insert((request.entry, request.sbn, request.esi)) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested duplicate source symbol entry={} sbn={} esi={}",
                request.entry, request.sbn, request.esi
            )));
        }
    }

    Ok(pending)
}

fn validate_feedback_block(
    entry: &ManifestEntry,
    sbn: u8,
    config: &QuicConfig,
    request_kind: &str,
) -> Result<usize, QuicTransportError> {
    let block_count = block_count_for_len(entry.size, config)?;
    let block_index = usize::from(sbn);
    if block_index >= block_count {
        return Err(QuicTransportError::Integrity(format!(
            "receiver requested {request_kind} block {sbn} outside entry {} ({block_count} blocks)",
            entry.index
        )));
    }
    let block_start = u64::from(sbn)
        .checked_mul(config.max_block_size as u64)
        .ok_or_else(|| {
            QuicTransportError::Integrity(format!(
                "receiver requested {request_kind} block offset overflow for entry {}",
                entry.index
            ))
        })?;
    let block_len = usize::try_from((entry.size - block_start).min(config.max_block_size as u64))
        .unwrap_or(usize::MAX);
    Ok(block_len
        .div_ceil(usize::from(config.symbol_size.max(1)))
        .max(1))
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
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
fn parse_quic_round_complete(frame: &Frame) -> Result<QuicRoundComplete, QuicTransportError> {
    if frame.payload().is_empty() {
        Ok(QuicRoundComplete::default())
    } else {
        parse_json(frame)
    }
}

fn receiver_round_loss_fraction(observed: u64, sent: u64) -> Option<f64> {
    if sent == 0 {
        return None;
    }
    let observed = observed.min(sent);
    Some((1.0 - observed as f64 / sent as f64).clamp(0.0, 0.90))
}

fn quic_feedback_repair_overhead(round_loss_fraction: Option<f64>) -> f64 {
    let Some(loss) = round_loss_fraction.filter(|loss| loss.is_finite()) else {
        return 0.0;
    };
    let loss = loss.clamp(0.0, QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD);
    if loss < QUIC_FEEDBACK_REPAIR_LOSS_ENABLE_MIN {
        return 0.0;
    }
    (loss * (1.0 + QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION)
        + QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_MIN)
        .clamp(0.0, QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD)
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
        delta_manifest: None,
    }
}

#[allow(dead_code)]
struct QuicEntryEncoder {
    index: u32,
    object_id: ObjectId,
    source: QuicEntryEncoderSource,
    repair_cursors: Vec<usize>,
}

#[allow(dead_code)]
enum QuicEntryEncoderSource {
    Memory(Vec<u8>),
    File {
        abs_path: PathBuf,
        size: u64,
        sha256_hex: String,
    },
}

#[allow(dead_code)]
impl QuicEntryEncoder {
    fn memory(index: u32, object_id: ObjectId, bytes: Vec<u8>, config: &QuicConfig) -> Self {
        let block_count = block_count_for_len(bytes.len() as u64, config).unwrap_or(1);
        Self {
            index,
            object_id,
            source: QuicEntryEncoderSource::Memory(bytes),
            repair_cursors: vec![0; block_count],
        }
    }

    fn file(entry: &QuicSourceEntry, config: &QuicConfig) -> Result<Self, QuicTransportError> {
        Ok(Self {
            index: entry.index,
            object_id: entry.object_id,
            source: QuicEntryEncoderSource::File {
                abs_path: entry.abs_path.clone(),
                size: entry.size,
                sha256_hex: entry.sha256_hex.clone(),
            },
            repair_cursors: vec![0; block_count_for_len(entry.size, config)?],
        })
    }

    fn size(&self) -> u64 {
        match &self.source {
            QuicEntryEncoderSource::Memory(bytes) => bytes.len() as u64,
            QuicEntryEncoderSource::File { size, .. } => *size,
        }
    }

    fn memory_bytes(&self) -> Result<&[u8], QuicTransportError> {
        match &self.source {
            QuicEntryEncoderSource::Memory(bytes) => Ok(bytes),
            QuicEntryEncoderSource::File { abs_path, .. } => {
                Err(QuicTransportError::Source(format!(
                    "file-backed QUIC encoder for {} must be streamed block-by-block",
                    abs_path.display()
                )))
            }
        }
    }

    fn in_memory_block(&self, sbn: u8, config: &QuicConfig) -> Result<&[u8], QuicTransportError> {
        let bytes = self.memory_bytes()?;
        let block_start = usize::from(sbn)
            .checked_mul(config.max_block_size)
            .ok_or_else(|| {
                QuicTransportError::Integrity("source request block offset overflow".to_string())
            })?;
        if block_start >= bytes.len() {
            return Err(QuicTransportError::Integrity(format!(
                "source request block {sbn} outside entry {} ({} bytes)",
                self.index,
                bytes.len()
            )));
        }
        let block_len = config.max_block_size.min(bytes.len() - block_start);
        Ok(&bytes[block_start..block_start + block_len])
    }

    fn block_count(&self, config: &QuicConfig) -> Result<usize, QuicTransportError> {
        block_count_for_len(self.size(), config)
    }

    fn block_len(&self, sbn: u8, config: &QuicConfig) -> Result<usize, QuicTransportError> {
        let block_start = u64::from(sbn)
            .checked_mul(config.max_block_size as u64)
            .ok_or_else(|| {
                QuicTransportError::Integrity("source request block offset overflow".to_string())
            })?;
        let size = self.size();
        if block_start >= size {
            return Err(QuicTransportError::Integrity(format!(
                "source request block {sbn} outside entry {} ({size} bytes)",
                self.index
            )));
        }
        Ok(
            usize::try_from((size - block_start).min(config.max_block_size as u64))
                .unwrap_or(usize::MAX),
        )
    }

    async fn read_block(
        &self,
        cx: &Cx,
        sbn: u8,
        config: &QuicConfig,
    ) -> Result<Vec<u8>, QuicTransportError> {
        let offset = u64::from(sbn)
            .checked_mul(config.max_block_size as u64)
            .ok_or_else(|| {
                QuicTransportError::Integrity("source request block offset overflow".to_string())
            })?;
        let block_len = self.block_len(sbn, config)?;
        match &self.source {
            QuicEntryEncoderSource::Memory(bytes) => {
                let start = usize::try_from(offset).map_err(|_| {
                    QuicTransportError::Integrity(
                        "source request block offset overflow".to_string(),
                    )
                })?;
                let end = start.saturating_add(block_len);
                Ok(bytes[start..end].to_vec())
            }
            QuicEntryEncoderSource::File {
                abs_path,
                size,
                sha256_hex: _,
            } => {
                cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                let mut file = crate::fs::File::open(abs_path).await.map_err(|err| {
                    QuicTransportError::Source(format!("{}: {err}", abs_path.display()))
                })?;
                file.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|err| {
                        QuicTransportError::Source(format!("{}: {err}", abs_path.display()))
                    })?;
                let mut block = vec![0_u8; block_len];
                let mut read = 0usize;
                while read < block_len {
                    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                    let n = file.read(&mut block[read..]).await.map_err(|err| {
                        QuicTransportError::Source(format!("{}: {err}", abs_path.display()))
                    })?;
                    if n == 0 {
                        return Err(QuicTransportError::Source(format!(
                            "{} changed while preparing QUIC symbols (short read at block {sbn}, \
                             read {read} of {block_len} bytes, manifest size {size})",
                            abs_path.display()
                        )));
                    }
                    read += n;
                }
                Ok(block)
            }
        }
    }

    fn repair_cursor(&self, sbn: u8) -> usize {
        self.repair_cursors
            .get(usize::from(sbn))
            .copied()
            .unwrap_or(0)
    }

    fn set_repair_cursor(&mut self, sbn: u8, cursor: usize) {
        let idx = usize::from(sbn);
        if idx >= self.repair_cursors.len() {
            self.repair_cursors.resize(idx + 1, 0);
        }
        self.repair_cursors[idx] = cursor;
    }
}

fn block_count_for_len(size: u64, config: &QuicConfig) -> Result<usize, QuicTransportError> {
    if size == 0 {
        return Ok(0);
    }
    let max_block = u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX);
    let blocks = size.div_ceil(max_block);
    if blocks > u64::from(u8::MAX) + 1 {
        return Err(QuicTransportError::TooLarge {
            size,
            max: max_block.saturating_mul(u64::from(u8::MAX) + 1),
        });
    }
    usize::try_from(blocks).map_err(|_| QuicTransportError::TooLarge {
        size,
        max: max_block.saturating_mul(u64::from(u8::MAX) + 1),
    })
}

fn effective_quic_max_block_size_for_largest_entry(
    config: &QuicConfig,
    max_entry_len: usize,
) -> Result<usize, QuicTransportError> {
    let rq_config = RqConfig {
        symbol_size: config.symbol_size,
        max_block_size: config.max_block_size,
        ..RqConfig::default()
    };
    rq_effective_max_block_size(&rq_config, max_entry_len).map_err(|err| match err {
        RqError::TooLarge { size, max } => QuicTransportError::TooLarge { size, max },
        other => QuicTransportError::Config(format!(
            "[ASUP-E803] QUIC block-size planning failed: {other}"
        )),
    })
}

fn effective_quic_config_for_largest_entry(
    config: &QuicConfig,
    max_entry_len: usize,
) -> Result<QuicConfig, QuicTransportError> {
    let mut config = config.clone();
    config.max_block_size =
        effective_quic_max_block_size_for_largest_entry(&config, max_entry_len)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
fn effective_quic_config_for_entries(
    config: &QuicConfig,
    entries: &[(String, Vec<u8>)],
) -> Result<QuicConfig, QuicTransportError> {
    let max_entry_len = entries
        .iter()
        .map(|(_, bytes)| bytes.len())
        .max()
        .unwrap_or(0);
    effective_quic_config_for_largest_entry(config, max_entry_len)
}

fn empty_quic_entry_digest(rel_path: String) -> EntryDigest {
    let empty_sha: [u8; 32] = Sha256::digest(b"").into();
    EntryDigest {
        rel_path,
        size: 0,
        content_id: crate::atp::object::ObjectId::content(ContentId::from_bytes(b"")),
        content_sha256: empty_sha,
    }
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
pub(crate) struct QuicPreparedSource {
    manifest: TransferManifest,
    entries: Vec<QuicSourceEntry>,
    max_block_size: usize,
}

impl QuicPreparedSource {
    pub(crate) fn effective_config(&self, config: &QuicConfig) -> QuicConfig {
        let mut config = config.clone();
        config.max_block_size = self.max_block_size;
        config
    }
}

#[allow(dead_code)]
struct QuicEntryDecoder {
    index: u32,
    object_id: ObjectId,
    size: u64,
    pipeline: Option<DecodingPipeline>,
    complete: bool,
    data: Vec<u8>,
    pending_decodes: Vec<QuicPendingDecode>,
}

struct QuicPendingDecode {
    block_sbn: u8,
    started_at: Instant,
    handle: crate::runtime::TaskHandle<BlockDecodeOutcome>,
}

fn quic_pending_decode_jobs(decoders: &[QuicEntryDecoder]) -> usize {
    decoders
        .iter()
        .map(|decoder| decoder.pending_decodes.len())
        .sum()
}

fn quic_block_decode_pending(decoder: &QuicEntryDecoder, block_sbn: u8) -> bool {
    decoder
        .pending_decodes
        .iter()
        .any(|pending| pending.block_sbn == block_sbn)
}

fn quic_entry_source_block_count_for_geometry(entry_size: u64, max_block_size: usize) -> usize {
    if entry_size == 0 {
        return 0;
    }
    let max_block_size = u64::try_from(max_block_size.max(1)).unwrap_or(u64::MAX);
    entry_size
        .div_ceil(max_block_size)
        .min(u64::from(u8::MAX) + 1)
        .try_into()
        .unwrap_or(usize::from(u8::MAX) + 1)
}

#[cfg(test)]
fn quic_should_parallel_decode_entry_geometry(entry_size: u64, max_block_size: usize) -> bool {
    entry_size >= QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES
        && quic_entry_source_block_count_for_geometry(entry_size, max_block_size)
            >= QUIC_PARALLEL_DECODE_MIN_SOURCE_BLOCKS
}

fn quic_entry_source_block_count(decoder: &QuicEntryDecoder, config: &QuicConfig) -> usize {
    quic_entry_source_block_count_for_geometry(decoder.size, config.max_block_size)
}

fn quic_should_parallel_decode_entry(decoder: &QuicEntryDecoder, config: &QuicConfig) -> bool {
    decoder.size >= QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES
        && quic_entry_source_block_count(decoder, config) >= QUIC_PARALLEL_DECODE_MIN_SOURCE_BLOCKS
}

fn quic_transfer_decode_width(decoders: &[QuicEntryDecoder], config: &QuicConfig) -> usize {
    if decoders
        .iter()
        .any(|decoder| quic_should_parallel_decode_entry(decoder, config))
    {
        QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
    } else {
        0
    }
}

fn quic_entry_decode_width_budget(
    decoder: &QuicEntryDecoder,
    config: &QuicConfig,
    transfer_decode_width: usize,
) -> usize {
    if !quic_should_parallel_decode_entry(decoder, config) {
        return 0;
    }
    quic_entry_source_block_count(decoder, config)
        .min(QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
        .min(transfer_decode_width.max(1))
        .max(1)
}

#[cfg(test)]
fn quic_entry_decode_width_budget_for_geometry(
    entry_size: u64,
    max_block_size: usize,
    transfer_decode_width: usize,
) -> usize {
    if !quic_should_parallel_decode_entry_geometry(entry_size, max_block_size) {
        return 0;
    }
    quic_entry_source_block_count_for_geometry(entry_size, max_block_size)
        .min(QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
        .min(transfer_decode_width.max(1))
        .max(1)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) struct QuicDecodedBlock {
    pub(crate) entry: u32,
    pub(crate) sbn: u8,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicDecodeStats {
    pub(crate) decode_count: u64,
    pub(crate) decode_micros: u64,
}

impl QuicDecodeStats {
    fn record_completed_block(&mut self, elapsed: Duration) {
        self.decode_count = self.decode_count.saturating_add(1);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.decode_micros = self.decode_micros.saturating_add(micros);
    }

    fn add(&mut self, other: Self) {
        self.decode_count = self.decode_count.saturating_add(other.decode_count);
        self.decode_micros = self.decode_micros.saturating_add(other.decode_micros);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct QuicRoundSymbolStats {
    observed: u64,
    accepted: u64,
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
    round_symbols_start: u64,
    aimd_rate_bps: u64,
    aimd_feedback_seen: bool,
    last_round_loss_fraction: f64,
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
            round_symbols_start: 0,
            aimd_rate_bps: config
                .bwlimit_bps
                .unwrap_or(QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S as u64)
                .clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS),
            aimd_feedback_seen: false,
            last_round_loss_fraction: 0.0,
        }
    }

    fn sent_this_round(&self) -> u64 {
        self.symbols_sent.saturating_sub(self.round_symbols_start)
    }

    fn observe_need_more(&mut self, need: &QuicNeedMore) {
        let sent_this_round = self.sent_this_round();
        if sent_this_round == 0 {
            return;
        }
        let loss = need
            .round_loss_fraction
            .filter(|loss| loss.is_finite())
            .or_else(|| {
                need.round_symbols_observed
                    .and_then(|observed| receiver_round_loss_fraction(observed, sent_this_round))
            })
            .unwrap_or(0.0)
            .clamp(0.0, 0.90);
        self.aimd_feedback_seen = true;
        self.last_round_loss_fraction = loss;
        if loss > QUIC_AIMD_LOSS_DECREASE_THRESHOLD {
            let reduced =
                (self.aimd_rate_bps as f64 * QUIC_AIMD_MULTIPLICATIVE_DECREASE).ceil() as u64;
            self.aimd_rate_bps = reduced.clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS);
        } else if loss <= QUIC_AIMD_CLEAN_INCREASE_THRESHOLD {
            self.aimd_rate_bps = self
                .aimd_rate_bps
                .saturating_add(QUIC_AIMD_ADDITIVE_INCREASE_BYTES_PER_S)
                .clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS);
        }
    }

    fn next_round_config(&self) -> QuicConfig {
        if !self.aimd_feedback_seen {
            return self.config.clone();
        }
        let mut config = self.config.clone();
        config.bwlimit_bps = Some(
            config
                .bwlimit_bps
                .map_or(self.aimd_rate_bps, |cap| cap.min(self.aimd_rate_bps))
                .clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS),
        );
        config
    }

    fn mark_next_round_started(&mut self, previous_symbols_sent: u64, sent: u64) {
        self.round_symbols_start = previous_symbols_sent;
        self.symbols_sent = self.symbols_sent.saturating_add(sent);
    }
}

fn trace_quic_aimd_feedback(cx: &Cx, state: &QuicSenderFeedbackState<'_>) {
    if cx.trace_buffer().is_none() {
        return;
    }
    let round = state.feedback_rounds.to_string();
    let sent_this_round = state.sent_this_round().to_string();
    let loss = format!("{:.6}", state.last_round_loss_fraction);
    let aimd_rate_bps = state.aimd_rate_bps.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.aimd_feedback",
        &[
            ("transport", "quic"),
            ("round", round.as_str()),
            ("sent_this_round", sent_this_round.as_str()),
            ("round_loss_fraction", loss.as_str()),
            ("aimd_rate_bps", aimd_rate_bps.as_str()),
        ],
    );
}

fn quic_repair_symbol_total(requests: &[QuicBlockRepairRequest]) -> u64 {
    requests.iter().fold(0u64, |acc, request| {
        acc.saturating_add(u64::from(request.symbols))
    })
}

fn quic_repair_block_request_summary(requests: &[QuicBlockRepairRequest]) -> String {
    use std::fmt::Write as _;

    const MAX_TRACE_BLOCKS: usize = 128;

    let mut summary = String::new();
    for (idx, request) in requests.iter().take(MAX_TRACE_BLOCKS).enumerate() {
        if idx != 0 {
            summary.push(';');
        }
        let _ = write!(
            &mut summary,
            "{}:{}:{}",
            request.entry, request.sbn, request.symbols
        );
    }
    if requests.len() > MAX_TRACE_BLOCKS {
        if !summary.is_empty() {
            summary.push(';');
        }
        let _ = write!(
            &mut summary,
            "+{}more",
            requests.len().saturating_sub(MAX_TRACE_BLOCKS)
        );
    }
    summary
}

fn quic_need_more_response_mode(need: &QuicNeedMore) -> &'static str {
    if !need.repair_blocks.is_empty() {
        "block_repair"
    } else if need.pending.is_empty() && need.source_symbols.is_empty() {
        "empty"
    } else if need.source_symbols.is_empty() {
        "missing_deficit"
    } else {
        "source_retransmit"
    }
}

#[allow(clippy::too_many_arguments)]
fn trace_quic_sender_need_more(
    cx: &Cx,
    round: u32,
    symbols_sent_total: u64,
    sent_this_round: u64,
    need: &QuicNeedMore,
    config: &QuicConfig,
    aimd_rate_bps: Option<u64>,
    native_aimd_cap_bps: Option<u64>,
) {
    if std::env::var_os("ATP_RQ_TRACE").is_some() {
        quic_rqtrace(format_args!(
            "sender: NeedMore round={} pending={} repair_blocks={} repair_symbols_requested={} source_requests={} sent_total={} sent_this_round={} observed={} accepted={} loss={:.6} max_feedback_rounds={} repair_symbol_round_cap={} repair_block_request_cap={} repair_block_requests={} aimd_rate_bps={} native_aimd_cap_bps={}",
            round,
            need.pending.len(),
            need.repair_blocks.len(),
            quic_repair_symbol_total(&need.repair_blocks),
            need.source_symbols.len(),
            symbols_sent_total,
            sent_this_round,
            need.round_symbols_observed.unwrap_or(0),
            need.round_symbols_accepted.unwrap_or(0),
            need.round_loss_fraction.unwrap_or(0.0),
            config.max_feedback_rounds,
            MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
            MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND,
            quic_repair_block_request_summary(&need.repair_blocks),
            aimd_rate_bps
                .map(|rate| rate.to_string())
                .unwrap_or_else(|| "none".to_string()),
            native_aimd_cap_bps
                .map(|rate| rate.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
    }
    if cx.trace_buffer().is_none() {
        return;
    }

    let round = round.to_string();
    let symbols_sent_total = symbols_sent_total.to_string();
    let sent_this_round = sent_this_round.to_string();
    let max_feedback_rounds = config.max_feedback_rounds.to_string();
    let pending = need.pending.len().to_string();
    let repair_blocks = need.repair_blocks.len().to_string();
    let repair_symbols_requested = quic_repair_symbol_total(&need.repair_blocks).to_string();
    let source_symbols = need.source_symbols.len().to_string();
    let round_symbols_observed = need.round_symbols_observed.unwrap_or(0).to_string();
    let round_symbols_accepted = need.round_symbols_accepted.unwrap_or(0).to_string();
    let round_loss_fraction = format!("{:.6}", need.round_loss_fraction.unwrap_or(0.0));
    let repair_symbol_round_cap = MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND.to_string();
    let repair_block_request_cap = MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND.to_string();
    let repair_block_requests = quic_repair_block_request_summary(&need.repair_blocks);
    let aimd_rate_bps = aimd_rate_bps.map_or_else(|| "none".to_string(), |rate| rate.to_string());
    let native_aimd_cap_bps =
        native_aimd_cap_bps.map_or_else(|| "none".to_string(), |rate| rate.to_string());

    cx.trace_with_fields(
        "atp_quic.sender.need_more",
        &[
            ("transport", "quic"),
            ("round", round.as_str()),
            ("symbols_sent_total", symbols_sent_total.as_str()),
            ("sent_this_round", sent_this_round.as_str()),
            ("max_feedback_rounds", max_feedback_rounds.as_str()),
            ("pending", pending.as_str()),
            ("repair_blocks", repair_blocks.as_str()),
            (
                "repair_symbols_requested",
                repair_symbols_requested.as_str(),
            ),
            ("source_symbols", source_symbols.as_str()),
            ("round_symbols_observed", round_symbols_observed.as_str()),
            ("round_symbols_accepted", round_symbols_accepted.as_str()),
            ("round_loss_fraction", round_loss_fraction.as_str()),
            ("repair_symbol_round_cap", repair_symbol_round_cap.as_str()),
            (
                "repair_block_request_cap",
                repair_block_request_cap.as_str(),
            ),
            ("repair_block_requests", repair_block_requests.as_str()),
            ("aimd_rate_bps", aimd_rate_bps.as_str()),
            ("native_aimd_cap_bps", native_aimd_cap_bps.as_str()),
        ],
    );
}

fn trace_quic_sender_repair_round(
    cx: &Cx,
    round: u32,
    mode: &str,
    symbols_before: u64,
    emitted_symbols: u64,
    need: &QuicNeedMore,
) {
    if std::env::var_os("ATP_RQ_TRACE").is_some() {
        quic_rqtrace(format_args!(
            "sender: repair_round round={} mode={} symbols_before={} emitted_symbols={} symbols_after={} pending={} repair_blocks={} repair_symbols_requested={} source_requests={} repair_block_requests={}",
            round,
            mode,
            symbols_before,
            emitted_symbols,
            symbols_before.saturating_add(emitted_symbols),
            need.pending.len(),
            need.repair_blocks.len(),
            quic_repair_symbol_total(&need.repair_blocks),
            need.source_symbols.len(),
            quic_repair_block_request_summary(&need.repair_blocks)
        ));
    }
    if cx.trace_buffer().is_none() {
        return;
    }

    let symbols_after_value = symbols_before.saturating_add(emitted_symbols);
    let round = round.to_string();
    let symbols_before = symbols_before.to_string();
    let emitted_symbols = emitted_symbols.to_string();
    let symbols_after = symbols_after_value.to_string();
    let pending = need.pending.len().to_string();
    let repair_blocks = need.repair_blocks.len().to_string();
    let repair_symbols_requested = quic_repair_symbol_total(&need.repair_blocks).to_string();
    let source_symbols = need.source_symbols.len().to_string();
    let repair_block_requests = quic_repair_block_request_summary(&need.repair_blocks);

    cx.trace_with_fields(
        "atp_quic.sender.repair_round",
        &[
            ("transport", "quic"),
            ("round", round.as_str()),
            ("mode", mode),
            ("symbols_before", symbols_before.as_str()),
            ("emitted_symbols", emitted_symbols.as_str()),
            ("symbols_after", symbols_after.as_str()),
            ("pending", pending.as_str()),
            ("repair_blocks", repair_blocks.as_str()),
            (
                "repair_symbols_requested",
                repair_symbols_requested.as_str(),
            ),
            ("source_symbols", source_symbols.as_str()),
            ("repair_block_requests", repair_block_requests.as_str()),
        ],
    );
}

#[cfg(test)]
fn encoders_from_entries(
    manifest: &TransferManifest,
    entries: &[(String, Vec<u8>)],
    config: &QuicConfig,
) -> Result<Vec<QuicEntryEncoder>, QuicTransportError> {
    let config = effective_quic_config_for_entries(config, entries)?;
    Ok(manifest
        .entries
        .iter()
        .zip(entries)
        .map(|(entry, (_, bytes))| {
            QuicEntryEncoder::memory(
                entry.index,
                entry_object_id(&manifest.transfer_id, entry.index),
                bytes.clone(),
                &config,
            )
        })
        .collect())
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
    let mut read_buf = vec![0_u8; config.chunk_size];
    let mut digests = Vec::with_capacity(source_entries.len());
    let mut metadatas = Vec::with_capacity(source_entries.len());
    let mut total_bytes = 0u64;
    let mut hardlink_primary: std::collections::HashMap<(u64, u64), String> =
        std::collections::HashMap::new();

    for source_entry in &source_entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        quic_join_relative(Path::new("base"), &source_entry.rel_path)?;
        let mut metadata =
            read_entry_metadata(&source_entry.abs_path, &config.metadata_policy).await?;
        if config.preserve_hardlinks && matches!(metadata.file_kind, FileKind::Regular) {
            if let Some(key) = crate::net::atp::transport_common::metadata::inode_key_if_regular(
                &source_entry.abs_path,
            )
            .await?
            {
                if let Some(primary) = hardlink_primary.get(&key) {
                    metadata.hardlink_target = Some(primary.clone());
                } else {
                    hardlink_primary.insert(key, source_entry.rel_path.clone());
                }
            }
        }
        let zero_content =
            !matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some();
        let digest = if zero_content {
            empty_quic_entry_digest(source_entry.rel_path.clone())
        } else {
            let (size, content_id, content_sha256) =
                hash_file_streaming(&source_entry.abs_path, &mut read_buf).await?;
            EntryDigest {
                rel_path: source_entry.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            }
        };
        let size = digest.size;
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
        digests.push(digest);
        metadatas.push(metadata);
    }

    let max_entry_len = digests.iter().try_fold(0usize, |max, digest| {
        usize::try_from(digest.size)
            .map(|size| max.max(size))
            .map_err(|_| QuicTransportError::TooLarge {
                size: digest.size,
                max: usize::MAX as u64,
            })
    })?;
    let effective_config = effective_quic_config_for_largest_entry(config, max_entry_len)?;
    let merkle_root_hex = flat_merkle_root_from_digests(&digests);
    let metadata_pairs: Vec<(&str, &EntryMetadata)> = digests
        .iter()
        .zip(&metadatas)
        .map(|(digest, metadata)| (digest.rel_path.as_str(), metadata))
        .collect();
    let metadata_root_hex = metadata_commitment(&metadata_pairs);
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, digests.len());
    let manifest_entries = digests
        .iter()
        .zip(&metadatas)
        .enumerate()
        .map(|(i, (digest, metadata))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: digest.rel_path.clone(),
            size: digest.size,
            sha256_hex: hex_encode(&digest.content_sha256),
            metadata: if metadata.is_bare() {
                None
            } else {
                Some(metadata.clone())
            },
        })
        .collect::<Vec<_>>();
    let manifest = TransferManifest {
        transfer_id,
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex,
        metadata_root_hex,
        entries: manifest_entries,
        delta_manifest: None,
    };
    validate_quic_manifest(&manifest, &effective_config)?;

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

    Ok(QuicPreparedSource {
        manifest,
        entries,
        max_block_size: effective_config.max_block_size,
    })
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
                pending_decodes: Vec::new(),
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
        let bytes = entry.memory_bytes()?;
        let already = entry.repair_cursor(0);
        let target_repair = if with_source {
            initial_repair_per_block(bytes.len(), config)
        } else {
            already.saturating_add(repair_batch)
        };
        let repair_count = target_repair.saturating_sub(already);
        if !with_source && repair_count == 0 {
            entry.set_repair_cursor(0, target_repair);
            continue;
        }

        let mut pipeline = encoding_pipeline(config);
        if with_source {
            for encoded in pipeline.encode_with_repair(entry.object_id, bytes, target_repair) {
                let symbol = encoded
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
            }
        } else {
            for encoded in
                pipeline.encode_repair_range(entry.object_id, bytes, already, repair_count)
            {
                let symbol = encoded
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
            }
        }
        entry.set_repair_cursor(0, target_repair);
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn spray_streaming_symbol_round(
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
    let mut pacer = QuicSymbolPacer::from_connection(config, conn);
    let repair_batch = repair_batch_per_block(config);
    for entry in encoders
        .iter_mut()
        .filter(|entry| pending.contains(&entry.index))
    {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        for block_index in 0..entry.block_count(config)? {
            let sbn = u8::try_from(block_index).map_err(|_| QuicTransportError::TooLarge {
                size: entry.size(),
                max: u64::try_from(config.max_block_size.max(1))
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::from(u8::MAX) + 1),
            })?;
            let block = entry.read_block(cx, sbn, config).await?;
            let already = entry.repair_cursor(sbn);
            let target_repair = if with_source {
                initial_repair_per_block(block.len(), config)
            } else {
                already.saturating_add(repair_batch)
            };
            let repair_count = target_repair.saturating_sub(already);
            if !with_source && repair_count == 0 {
                entry.set_repair_cursor(sbn, target_repair);
                continue;
            }

            let mut pipeline = encoding_pipeline(config);
            let encoded = if with_source {
                EitherNativeEncoding::Source(pipeline.encode_single_block_with_repair(
                    entry.object_id,
                    sbn,
                    &block,
                    target_repair,
                ))
            } else {
                EitherNativeEncoding::Repair(pipeline.encode_single_block_repair_range(
                    entry.object_id,
                    sbn,
                    &block,
                    already,
                    repair_count,
                ))
            };
            for symbol in encoded {
                let symbol = symbol
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
                pacer.after_symbol_sent(cx).await?;
            }
            entry.set_repair_cursor(sbn, target_repair);
        }
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
    let block = enc.in_memory_block(request.sbn, config)?;
    let block_len = block.len();
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

    let start = esi * symbol_size;
    let end = (start + symbol_size).min(block_len);
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        buffer[..end - start].copy_from_slice(&block[start..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

#[allow(dead_code)]
async fn streaming_source_symbol_for_request(
    cx: &Cx,
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
    let block = enc.read_block(cx, request.sbn, config).await?;
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_len = block.len();
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

    let start = esi * symbol_size;
    let end = (start + symbol_size).min(block_len);
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        buffer[..end - start].copy_from_slice(&block[start..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

#[allow(dead_code)]
async fn send_source_symbol_requests(
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
    let mut pacer = QuicSymbolPacer::from_connection(config, conn);
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
        let symbol = streaming_source_symbol_for_request(cx, enc, *request, config).await?;
        let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
        send_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
        sent = sent.saturating_add(1);
        pacer.after_symbol_sent(cx).await?;
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn send_block_repair_requests(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    requests: &[QuicBlockRepairRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_connection(config, conn);
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let enc = encoders
            .iter_mut()
            .find(|entry| entry.index == request.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "receiver requested repair block for unknown entry {}",
                    request.entry
                ))
            })?;
        let repair_count = usize::try_from(request.symbols).map_err(|_| {
            QuicTransportError::Integrity("repair symbol count does not fit usize".to_string())
        })?;
        let block = enc.read_block(cx, request.sbn, config).await?;
        let already = enc.repair_cursor(request.sbn);
        let target_repair = already.saturating_add(repair_count);
        quic_rqtrace(format_args!(
            "sender: repair_block entry={} sbn={} requested_symbols={} repair_cursor_start={} repair_cursor_target={}",
            request.entry, request.sbn, repair_count, already, target_repair
        ));
        let mut pipeline = encoding_pipeline(config);
        for encoded in pipeline.encode_single_block_repair_range(
            enc.object_id,
            request.sbn,
            &block,
            already,
            repair_count,
        ) {
            let symbol = encoded
                .map_err(|err| QuicTransportError::Control(err.to_string()))?
                .into_symbol();
            let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
            send_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
            sent = sent.saturating_add(1);
            pacer.after_symbol_sent(cx).await?;
        }
        enc.set_repair_cursor(request.sbn, target_repair);
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
async fn send_repair_round_and_object_complete(
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
    if need.pending.is_empty() && need.repair_blocks.is_empty() && need.source_symbols.is_empty() {
        send_object_complete(cx, conn, control, 0)?;
        return Ok(0);
    }
    validate_need_more_feedback(manifest, config, need)?;
    let sent = if !need.repair_blocks.is_empty() {
        send_block_repair_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.repair_blocks,
            config,
            symbol_auth,
        )
        .await?
    } else if need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver NeedMore listed pending entries without targeted repair/source deficits"
                .to_string(),
        ));
    } else {
        send_source_symbol_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.source_symbols,
            config,
            symbol_auth,
        )
        .await?
    };
    send_object_complete(cx, conn, control, sent)?;
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
    let config = prepared.effective_config(config);
    config.validate()?;
    let mut encoders = Vec::with_capacity(prepared.entries.len());
    for entry in &prepared.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        encoders.push(QuicEntryEncoder::file(entry, &config)?);
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
    send_object_complete(cx, conn, control, symbols_sent)?;
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
    let config = prepared.effective_config(config);
    config.validate()?;
    validate_quic_manifest(&prepared.manifest, &config)?;
    let mut encoders = encoders_from_prepared_source(cx, prepared, &config).await?;
    let symbol_auth = config.symbol_auth_context()?;
    send_manifest(cx, conn, control, &prepared.manifest)?;
    let pending = encoders
        .iter()
        .map(|entry| entry.index)
        .collect::<std::collections::BTreeSet<_>>();
    let symbols_sent = spray_streaming_symbol_round(
        cx,
        conn,
        &prepared.manifest,
        &mut encoders,
        &pending,
        &config,
        symbol_auth.as_ref(),
        true,
    )
    .await?;
    send_object_complete(cx, conn, control, symbols_sent)?;
    Ok(symbols_sent)
}

#[allow(dead_code)]
fn finish_sender_transfer(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    peer: SocketAddr,
    receipt: ReceiveReceipt,
    symbols_sent: u64,
    feedback_rounds: u32,
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
        symbols_sent,
        feedback_rounds,
        merkle_root_hex: manifest.merkle_root_hex.clone(),
        receipt,
        peer,
    })
}

#[allow(dead_code)]
async fn handle_sender_feedback_or_proof(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    state: &mut QuicSenderFeedbackState<'_>,
) -> Result<Option<SendReport>, QuicTransportError> {
    match receive_proof_or_need_more(cx, conn, control)? {
        QuicControlReply::Proof(receipt) => finish_sender_transfer(
            cx,
            conn,
            control,
            state.manifest,
            state.peer,
            receipt,
            state.symbols_sent,
            state.feedback_rounds,
        )
        .map(Some),
        QuicControlReply::NeedMore(need) => {
            state.feedback_rounds = state.feedback_rounds.saturating_add(1);
            state.observe_need_more(&need);
            trace_quic_aimd_feedback(cx, state);
            trace_quic_sender_need_more(
                cx,
                state.feedback_rounds,
                state.symbols_sent,
                state.sent_this_round(),
                &need,
                state.config,
                Some(state.aimd_rate_bps),
                None,
            );
            if need.pending.is_empty()
                && need.repair_blocks.is_empty()
                && need.source_symbols.is_empty()
            {
                trace_quic_sender_repair_round(
                    cx,
                    state.feedback_rounds,
                    quic_need_more_response_mode(&need),
                    state.symbols_sent,
                    0,
                    &need,
                );
                return Ok(None);
            }
            let round_config = state.next_round_config();
            let symbol_auth = round_config.symbol_auth_context()?;
            let previous_symbols_sent = state.symbols_sent;
            let response_mode = quic_need_more_response_mode(&need);
            let sent = send_repair_round_and_object_complete(
                cx,
                conn,
                control,
                state.manifest,
                state.encoders,
                &need,
                &round_config,
                symbol_auth.as_ref(),
            )
            .await?;
            state.mark_next_round_started(previous_symbols_sent, sent);
            trace_quic_sender_repair_round(
                cx,
                state.feedback_rounds,
                response_mode,
                previous_symbols_sent,
                sent,
                &need,
            );
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
    finish_sender_transfer(cx, conn, control, manifest, peer, receipt, 0, 0)
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

fn materialize_decoder_data_if_complete(
    decoder: &mut QuicEntryDecoder,
) -> Result<(), QuicTransportError> {
    if !decoder
        .pipeline
        .as_ref()
        .is_some_and(DecodingPipeline::is_complete)
    {
        return Ok(());
    }
    let Some(pipeline) = decoder.pipeline.take() else {
        return Ok(());
    };
    let mut bytes = pipeline.into_data().map_err(|err| {
        QuicTransportError::Control(format!(
            "RaptorQ decoder completed but data assembly failed: {err}"
        ))
    })?;
    bytes.truncate(usize::try_from(decoder.size).unwrap_or(usize::MAX));
    decoder.data = bytes;
    decoder.complete = true;
    Ok(())
}

fn finish_quic_decode_outcome(
    decoder: &mut QuicEntryDecoder,
    outcome: BlockDecodeOutcome,
    decode_stats: &mut QuicDecodeStats,
    started_at: Instant,
) -> Result<bool, QuicTransportError> {
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok(false);
        };
        pipeline.finish_decode_job(outcome)
    };
    match result {
        SymbolAcceptResult::BlockComplete { .. } => {
            decode_stats.record_completed_block(started_at.elapsed());
            materialize_decoder_data_if_complete(decoder)?;
            Ok(true)
        }
        SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => Err(
            QuicTransportError::Integrity("symbol authentication failed".to_string()),
        ),
        SymbolAcceptResult::Rejected(reason) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected deferred block: {reason:?}"
        ))),
        SymbolAcceptResult::Accepted { .. }
        | SymbolAcceptResult::DecodingStarted { .. }
        | SymbolAcceptResult::Duplicate => Ok(false),
    }
}

fn feed_authenticated_symbol_deferred(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    auth_symbol: AuthenticatedSymbol,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<bool, QuicTransportError> {
    if decoder.complete {
        return Ok(false);
    }
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok(false);
        };
        pipeline.feed_deferred(auth_symbol)
    };
    let started_at = Instant::now();
    match result {
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete { .. })) => {
            decode_stats.record_completed_block(started_at.elapsed());
            materialize_decoder_data_if_complete(decoder)?;
            Ok(true)
        }
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. },
        )) => Ok(true),
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(
            RejectReason::AuthenticationFailed,
        ))) => Err(QuicTransportError::Integrity(
            "symbol authentication failed".to_string(),
        )),
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_),
        )) => Ok(false),
        Ok(DeferredSymbolAcceptResult::Decode(job)) => {
            let block_sbn = job.sbn();
            let entry_decode_width =
                quic_entry_decode_width_budget(decoder, config, transfer_decode_width);
            if !allow_spawn_decode
                || entry_decode_width <= 1
                || decoder.pending_decodes.len() >= entry_decode_width
            {
                let outcome = run_block_decode_job(job);
                return finish_quic_decode_outcome(decoder, outcome, decode_stats, started_at);
            }
            let fallback_job = job.clone();
            match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
                Ok(handle) => {
                    decoder.pending_decodes.push(QuicPendingDecode {
                        block_sbn,
                        started_at,
                        handle,
                    });
                    Ok(true)
                }
                Err(_) => {
                    let outcome = run_block_decode_job(fallback_job);
                    finish_quic_decode_outcome(decoder, outcome, decode_stats, started_at)
                }
            }
        }
        Err(err) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected symbol: {err}"
        ))),
    }
}

async fn drain_ready_quic_decodes(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    decode_stats: &mut QuicDecodeStats,
) -> Result<u64, QuicTransportError> {
    let mut completed = 0u64;
    for decoder in decoders {
        let mut i = 0usize;
        while i < decoder.pending_decodes.len() {
            if !decoder.pending_decodes[i].handle.is_finished() {
                i += 1;
                continue;
            }
            let mut pending = decoder.pending_decodes.swap_remove(i);
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if finish_quic_decode_outcome(decoder, outcome, decode_stats, pending.started_at)? {
                completed = completed.saturating_add(1);
            }
        }
    }
    Ok(completed)
}

async fn join_all_quic_decodes(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    decode_stats: &mut QuicDecodeStats,
) -> Result<u64, QuicTransportError> {
    let mut completed = 0u64;
    for decoder in decoders {
        while let Some(mut pending) = decoder.pending_decodes.pop() {
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if finish_quic_decode_outcome(decoder, outcome, decode_stats, pending.started_at)? {
                completed = completed.saturating_add(1);
            }
        }
    }
    Ok(completed)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn finish_quic_streaming_decode_result(
    decoder: &mut QuicEntryDecoder,
    result: SymbolAcceptResult,
    elapsed: Duration,
    decode_stats: &mut QuicDecodeStats,
) -> Result<Option<QuicDecodedBlock>, QuicTransportError> {
    match result {
        SymbolAcceptResult::BlockComplete { block_sbn, data } => {
            decode_stats.record_completed_block(elapsed);
            decoder.complete = decoder
                .pipeline
                .as_ref()
                .is_some_and(DecodingPipeline::is_complete);
            Ok(Some(QuicDecodedBlock {
                entry: decoder.index,
                sbn: block_sbn,
                data,
            }))
        }
        SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. } => {
            Ok(None)
        }
        SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => Err(
            QuicTransportError::Integrity("symbol authentication failed".to_string()),
        ),
        SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_) => Ok(None),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn finish_quic_streaming_decode_outcome(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    outcome: BlockDecodeOutcome,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<Option<QuicDecodedBlock>, QuicTransportError> {
    let elapsed = outcome.elapsed();
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok(None);
        };
        pipeline.finish_decode_job_deferred(outcome)
    };
    match result {
        DeferredSymbolAcceptResult::Immediate(result) => {
            finish_quic_streaming_decode_result(decoder, result, elapsed, decode_stats)
        }
        DeferredSymbolAcceptResult::Decode(job) => dispatch_quic_streaming_decode_job(
            cx,
            decoder,
            job,
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        ),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn dispatch_quic_streaming_decode_job(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    job: BlockDecodeJob,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<Option<QuicDecodedBlock>, QuicTransportError> {
    let block_sbn = job.sbn();
    if decoder.complete
        || decoder.pipeline.is_none()
        || quic_block_decode_pending(decoder, block_sbn)
    {
        return Ok(None);
    }

    let entry_decode_width = quic_entry_decode_width_budget(decoder, config, transfer_decode_width);
    if !allow_spawn_decode
        || entry_decode_width <= 1
        || decoder.pending_decodes.len() >= entry_decode_width
    {
        return finish_quic_streaming_decode_outcome(
            cx,
            decoder,
            run_block_decode_job(job),
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        );
    }

    let fallback_job = job.clone();
    match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
        Ok(handle) => {
            decoder.pending_decodes.push(QuicPendingDecode {
                block_sbn,
                started_at: Instant::now(),
                handle,
            });
            Ok(None)
        }
        Err(_) => finish_quic_streaming_decode_outcome(
            cx,
            decoder,
            run_block_decode_job(fallback_job),
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        ),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn feed_authenticated_symbol_take_block_deferred(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    auth_symbol: AuthenticatedSymbol,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<(bool, Option<QuicDecodedBlock>), QuicTransportError> {
    if decoder.complete {
        return Ok((false, None));
    }
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok((false, None));
        };
        pipeline.feed_streaming_block_deferred(auth_symbol)
    };
    let started_at = Instant::now();
    match result {
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
            block_sbn,
            data,
        })) => {
            decode_stats.record_completed_block(started_at.elapsed());
            decoder.complete = decoder
                .pipeline
                .as_ref()
                .is_some_and(DecodingPipeline::is_complete);
            Ok((
                true,
                Some(QuicDecodedBlock {
                    entry: decoder.index,
                    sbn: block_sbn,
                    data,
                }),
            ))
        }
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. },
        )) => Ok((true, None)),
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(
            RejectReason::AuthenticationFailed,
        ))) => Err(QuicTransportError::Integrity(
            "symbol authentication failed".to_string(),
        )),
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_),
        )) => Ok((false, None)),
        Ok(DeferredSymbolAcceptResult::Decode(job)) => Ok((
            true,
            dispatch_quic_streaming_decode_job(
                cx,
                decoder,
                job,
                config,
                decode_stats,
                allow_spawn_decode,
                transfer_decode_width,
            )?,
        )),
        Err(err) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected symbol: {err}"
        ))),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
async fn drain_ready_quic_decodes_with_blocks(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<Vec<QuicDecodedBlock>, QuicTransportError> {
    let mut completed = Vec::new();
    for decoder in decoders {
        let mut i = 0usize;
        while i < decoder.pending_decodes.len() {
            if !decoder.pending_decodes[i].handle.is_finished() {
                i += 1;
                continue;
            }
            let mut pending = decoder.pending_decodes.swap_remove(i);
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if let Some(block) = finish_quic_streaming_decode_outcome(
                cx,
                decoder,
                outcome,
                config,
                decode_stats,
                allow_spawn_decode,
                transfer_decode_width,
            )? {
                completed.push(block);
            }
        }
    }
    Ok(completed)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
async fn join_all_quic_decodes_with_blocks(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    transfer_decode_width: usize,
) -> Result<Vec<QuicDecodedBlock>, QuicTransportError> {
    let mut completed = Vec::new();
    for decoder in decoders {
        while let Some(mut pending) = decoder.pending_decodes.pop() {
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if let Some(block) = finish_quic_streaming_decode_outcome(
                cx,
                decoder,
                outcome,
                config,
                decode_stats,
                true,
                transfer_decode_width,
            )? {
                completed.push(block);
            }
        }
    }
    Ok(completed)
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

fn verified_authenticated_symbol_from_envelope(
    envelope: &QuicSymbolEnvelope,
    object_id: ObjectId,
    symbol_auth: Option<&SecurityContext>,
) -> Result<AuthenticatedSymbol, QuicTransportError> {
    let mut authenticated =
        authenticated_symbol_from_envelope(envelope, object_id, symbol_auth.is_some())?;
    if let Some(context) = symbol_auth {
        context
            .verify_authenticated_symbol(&mut authenticated)
            .map_err(|_| {
                QuicTransportError::Integrity("symbol authentication failed".to_string())
            })?;
    }
    Ok(authenticated)
}

fn primary_quic_receive_aggregator(remote: impl Into<String>) -> MultipathAggregator {
    let aggregator = MultipathAggregator::new(AggregatorConfig {
        reorder: ReordererConfig {
            immediate_delivery: true,
            ..ReordererConfig::default()
        },
        ..AggregatorConfig::default()
    });
    aggregator.paths().register(TransportPath::new(
        QUIC_PRIMARY_RECEIVE_PATH_ID,
        "quic-primary",
        remote,
    ));
    aggregator
}

fn authenticated_symbol_with_existing_tag(
    symbol: Symbol,
    source: &AuthenticatedSymbol,
) -> AuthenticatedSymbol {
    let tag = *source.tag();
    if tag.is_zero() {
        AuthenticatedSymbol::new_unauthenticated(symbol)
    } else {
        AuthenticatedSymbol::from_parts(symbol, tag)
    }
}

fn trace_aggregated_symbol_result(
    cx: Option<&Cx>,
    entry: u32,
    path: PathId,
    symbol: SymbolId,
    ready: usize,
    accepted: u64,
    duplicate: bool,
) {
    let Some(cx) = cx else {
        return;
    };
    let entry = entry.to_string();
    let path = path.to_string();
    let symbol = symbol.to_string();
    let ready = ready.to_string();
    let accepted = accepted.to_string();
    let duplicate = duplicate.to_string();
    cx.trace_with_fields(
        "atp_quic.receive.aggregate_symbol",
        &[
            ("entry", entry.as_str()),
            ("path", path.as_str()),
            ("symbol", symbol.as_str()),
            ("ready", ready.as_str()),
            ("accepted", accepted.as_str()),
            ("duplicate", duplicate.as_str()),
        ],
    );
}

#[derive(Clone, Copy)]
struct QuicReceiveAggregation<'a> {
    aggregator: &'a MultipathAggregator,
    path: PathId,
    now: Time,
    trace_cx: Option<&'a Cx>,
}

impl<'a> QuicReceiveAggregation<'a> {
    fn new(aggregator: &'a MultipathAggregator, path: PathId, now: Time) -> Self {
        Self {
            aggregator,
            path,
            now,
            trace_cx: None,
        }
    }

    fn with_trace(mut self, cx: &'a Cx) -> Self {
        self.trace_cx = Some(cx);
        self
    }
}

fn feed_aggregated_symbol_for_entry(
    decoders: &mut [QuicEntryDecoder],
    entry: u32,
    auth_symbol: AuthenticatedSymbol,
    receive: QuicReceiveAggregation<'_>,
) -> Result<u64, QuicTransportError> {
    let decoder = decoders
        .iter_mut()
        .find(|decoder| decoder.index == entry)
        .ok_or_else(|| {
            QuicTransportError::Integrity(format!("symbol for unknown manifest entry {entry}"))
        })?;

    let source_symbol_id = auth_symbol.symbol().id();
    let source_tag = *auth_symbol.tag();
    let aggregated =
        receive
            .aggregator
            .process(auth_symbol.symbol().clone(), receive.path, receive.now);
    let duplicate = aggregated.was_duplicate;
    let ready = aggregated.ready.len();
    let mut accepted = 0u64;
    for symbol in aggregated.ready {
        if !source_tag.is_zero() && symbol.id() != source_symbol_id {
            return Err(QuicTransportError::Integrity(
                "authenticated QUIC receive aggregation emitted a buffered symbol without its original tag"
                    .to_string(),
            ));
        }
        let ready = authenticated_symbol_with_existing_tag(symbol, &auth_symbol);
        if feed_authenticated_symbol(decoder, ready)? {
            accepted = accepted.saturating_add(1);
        }
    }
    trace_aggregated_symbol_result(
        receive.trace_cx,
        entry,
        receive.path,
        source_symbol_id,
        ready,
        accepted,
        duplicate,
    );
    Ok(accepted)
}

fn feed_aggregated_symbol_for_entry_deferred(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    entry: u32,
    auth_symbol: AuthenticatedSymbol,
    receive: QuicReceiveAggregation<'_>,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
) -> Result<u64, QuicTransportError> {
    let decoder_index = decoders
        .iter()
        .position(|decoder| decoder.index == entry)
        .ok_or_else(|| {
            QuicTransportError::Integrity(format!("symbol for unknown manifest entry {entry}"))
        })?;

    let source_symbol_id = auth_symbol.symbol().id();
    let source_tag = *auth_symbol.tag();
    let aggregated =
        receive
            .aggregator
            .process(auth_symbol.symbol().clone(), receive.path, receive.now);
    let duplicate = aggregated.was_duplicate;
    let ready = aggregated.ready.len();
    let mut accepted = 0u64;
    for symbol in aggregated.ready {
        if !source_tag.is_zero() && symbol.id() != source_symbol_id {
            return Err(QuicTransportError::Integrity(
                "authenticated QUIC receive aggregation emitted a buffered symbol without its original tag"
                    .to_string(),
            ));
        }
        let ready = authenticated_symbol_with_existing_tag(symbol, &auth_symbol);
        let transfer_decode_width = quic_transfer_decode_width(decoders, config);
        let allow_spawn_decode = quic_pending_decode_jobs(decoders) < transfer_decode_width;
        if feed_authenticated_symbol_deferred(
            cx,
            &mut decoders[decoder_index],
            ready,
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        )? {
            accepted = accepted.saturating_add(1);
        }
    }
    trace_aggregated_symbol_result(
        receive.trace_cx,
        entry,
        receive.path,
        source_symbol_id,
        ready,
        accepted,
        duplicate,
    );
    Ok(accepted)
}

#[allow(dead_code)]
fn drain_symbol_datagrams(
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let aggregator = primary_quic_receive_aggregator("quic-scaffold-peer");
    let receive =
        QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO);
    drain_symbol_datagrams_with_aggregator(conn, manifest, decoders, config, receive)
}

#[allow(dead_code)]
fn drain_symbol_datagrams_with_aggregator(
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    receive: QuicReceiveAggregation<'_>,
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
            .iter()
            .find(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        let auth_symbol = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoder.object_id,
            symbol_auth.as_ref(),
        )?;
        accepted = accepted.saturating_add(feed_aggregated_symbol_for_entry(
            decoders,
            envelope.entry,
            auth_symbol,
            receive,
        )?);
    }
    Ok(accepted)
}

#[allow(dead_code)]
fn assemble_completed_entries(decoders: &mut [QuicEntryDecoder]) -> QuicDecodeStats {
    let mut stats = QuicDecodeStats::default();
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
        let started_at = Instant::now();
        if let Ok(mut bytes) = pipeline.into_data() {
            stats.record_completed_block(started_at.elapsed());
            bytes.truncate(usize::try_from(decoder.size).unwrap_or(usize::MAX));
            decoder.data = bytes;
            decoder.complete = true;
        }
    }
    stats
}

#[allow(dead_code)]
fn pending_entries(decoders: &[QuicEntryDecoder]) -> Vec<u32> {
    decoders
        .iter()
        .filter(|decoder| !decoder.complete)
        .map(|decoder| decoder.index)
        .collect()
}

fn quic_decoder_block_count(decoder: &QuicEntryDecoder, config: &QuicConfig) -> usize {
    if decoder.size == 0 {
        return 0;
    }
    let max_block_size = u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX);
    decoder
        .size
        .div_ceil(max_block_size)
        .min(u64::from(u8::MAX) + 1)
        .try_into()
        .unwrap_or(usize::from(u8::MAX) + 1)
}

#[allow(dead_code)]
fn quic_decoder_block_source_symbols(
    decoder: &QuicEntryDecoder,
    sbn: u8,
    config: &QuicConfig,
) -> usize {
    let max_block_size = u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX);
    let start = u64::from(sbn).saturating_mul(max_block_size);
    if start >= decoder.size {
        return 0;
    }
    let len = decoder.size.saturating_sub(start).min(max_block_size);
    let symbol_size = u64::from(config.symbol_size.max(1));
    usize::try_from(len.div_ceil(symbol_size).max(1)).unwrap_or(usize::MAX)
}

#[allow(dead_code)]
fn quic_targeted_repair_symbols(
    base_deficit: usize,
    block_source_symbols: usize,
    round_loss_fraction: Option<f64>,
    remaining_round_budget: usize,
) -> usize {
    if base_deficit == 0 {
        return 0;
    }
    let measured_loss_target = ((block_source_symbols as f64)
        * quic_feedback_repair_overhead(round_loss_fraction))
    .ceil() as usize;
    let target = base_deficit
        .max(measured_loss_target)
        .min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND);
    if remaining_round_budget == 0 {
        target
    } else {
        target.min(remaining_round_budget)
    }
}

#[allow(dead_code)]
fn block_repair_requests(
    decoders: &[QuicEntryDecoder],
    config: &QuicConfig,
    limit: usize,
    round_loss_fraction: Option<f64>,
) -> Vec<QuicBlockRepairRequest> {
    let mut requests = Vec::new();
    let mut requested_symbols = 0usize;
    'decoders: for decoder in decoders {
        if decoder.complete {
            continue;
        }
        let Some(pipeline) = decoder.pipeline.as_ref() else {
            continue;
        };
        let remaining = if limit == 0 {
            0
        } else {
            limit.saturating_sub(requested_symbols)
        };
        if limit != 0 && remaining == 0 {
            break;
        }

        let mut missing_by_block = std::collections::BTreeMap::<u8, usize>::new();
        for MissingSourceSymbol { sbn, .. } in pipeline.missing_source_symbols(0) {
            *missing_by_block.entry(sbn).or_default() += 1;
        }

        for block_index in 0..quic_decoder_block_count(decoder, config) {
            if limit != 0 && requested_symbols >= limit {
                break 'decoders;
            }
            if requests.len() >= MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND {
                break 'decoders;
            }
            let sbn = u8::try_from(block_index).unwrap_or(u8::MAX);
            let block_source_symbols = quic_decoder_block_source_symbols(decoder, sbn, config);
            let status_deficit = pipeline.block_status(sbn).and_then(|status| {
                if matches!(
                    status.state,
                    BlockStateKind::Decoded | BlockStateKind::Decoding
                ) || status.symbols_needed == 0
                {
                    None
                } else {
                    status
                        .rank_deficit
                        .filter(|deficit| *deficit > 0)
                        .or_else(|| {
                            Some(
                                status
                                    .symbols_needed
                                    .saturating_sub(status.symbols_received)
                                    .max(1),
                            )
                        })
                }
            });
            let missing_source_symbols = missing_by_block.get(&sbn).copied().unwrap_or(0);
            let base_deficit = status_deficit
                .unwrap_or(missing_source_symbols)
                .min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND);
            if base_deficit == 0 {
                continue;
            }
            let remaining = if limit == 0 {
                0
            } else {
                limit.saturating_sub(requested_symbols)
            };
            let mut deficit = quic_targeted_repair_symbols(
                base_deficit,
                block_source_symbols,
                round_loss_fraction,
                remaining,
            )
            .min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND);
            if deficit == 0 {
                continue;
            }
            if limit != 0 {
                deficit = deficit.min(limit.saturating_sub(requested_symbols));
            }
            if deficit == 0 {
                break 'decoders;
            }
            requested_symbols = requested_symbols.saturating_add(deficit);
            requests.push(QuicBlockRepairRequest {
                entry: decoder.index,
                sbn,
                symbols: u32::try_from(deficit).unwrap_or(u32::MAX),
            });
        }
    }
    requests
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
    let metadata_ok = manifest_metadata_commitment(manifest) == manifest.metadata_root_hex;
    let committed = sha_ok && merkle_ok && metadata_ok && pending_entries(decoders).is_empty();
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
        symbols_accepted: 0,
        feedback_rounds: 0,
        decode_count: 0,
        decode_micros: 0,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else if !merkle_ok {
            Some("merkle-root mismatch".to_string())
        } else if !metadata_ok {
            Some("metadata commitment mismatch".to_string())
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
        loop {
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
        }
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
    fn open(cx: &Cx, conn: &mut NativeQuicConnection) -> Result<Self, QuicTransportError> {
        let stream = conn.open_local_bidi(cx)?;
        Ok(Self::for_stream(stream))
    }

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
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.rbuf)
                .map_err(|err| QuicTransportError::Frame(err.to_string()))?
            {
                return Ok(Some(frame));
            }

            let chunk = match conn.read_stream_bytes(cx, self.stream, CONTROL_READ_CHUNK) {
                Ok(chunk) => chunk,
                Err(NativeQuicConnectionError::StreamTable(StreamTableError::UnknownStream(
                    stream,
                ))) if stream == self.stream => {
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            };
            if chunk.is_empty() {
                return Ok(None);
            }
            self.rbuf.extend_from_slice(&chunk);
        }
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
    if hello.symbol_size != config.symbol_size {
        return Some(format!(
            "sender symbol_size ({}) must match receiver symbol_size ({})",
            hello.symbol_size, config.symbol_size
        ));
    }
    let receiver_max_block_size = u64::try_from(config.max_block_size).unwrap_or(u64::MAX);
    if hello.max_block_size != receiver_max_block_size {
        return Some(format!(
            "sender max_block_size ({}) must match receiver max_block_size ({receiver_max_block_size})",
            hello.max_block_size
        ));
    }
    let min_datagram = usize::from(hello.symbol_size) + AUTH_ENVELOPE_HEADER_LEN;
    if min_datagram > config.max_datagram_size {
        return Some(format!(
            "sender symbol_size ({}) plus {AUTH_ENVELOPE_HEADER_LEN}-byte authenticated envelope \
             header exceeds receiver max_datagram_size ({})",
            hello.symbol_size, config.max_datagram_size
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
fn send_native_sender_hello(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
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
fn receive_native_sender_hello_ack(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<QuicHelloAck, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive sender handshake ack")?;
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
fn send_native_manifest(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
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
    round_symbols_sent: u64,
) -> Result<(), QuicTransportError> {
    control.send_json(
        cx,
        conn,
        FrameType::ObjectComplete,
        &QuicRoundComplete { round_symbols_sent },
    )
}

#[allow(dead_code)]
fn receive_object_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<QuicRoundComplete, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive object-complete marker")?;
    if frame.frame_type() != FrameType::ObjectComplete {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "ObjectComplete",
        });
    }
    parse_quic_round_complete(&frame)
}

#[allow(dead_code)]
fn receive_native_object_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<QuicRoundComplete, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive object-complete marker")?;
    if frame.frame_type() != FrameType::ObjectComplete {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "ObjectComplete",
        });
    }
    parse_quic_round_complete(&frame)
}

#[allow(dead_code)]
fn send_native_object_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    round_symbols_sent: u64,
) -> Result<(), QuicTransportError> {
    control.send_json(
        cx,
        conn,
        FrameType::ObjectComplete,
        &QuicRoundComplete { round_symbols_sent },
    )
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

#[allow(dead_code)]
fn receive_native_proof_or_need_more(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<QuicControlReply, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive proof or fountain feedback")?;
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

fn first_client_bidi_stream() -> StreamId {
    StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0)
}

#[allow(dead_code)]
fn send_native_symbol(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    symbol: &Symbol,
    transfer_tag: u64,
    entry: u32,
    auth_tag: Option<[u8; crate::security::tag::TAG_SIZE]>,
) -> Result<(), QuicTransportError> {
    if !conn.can_send_1rtt() {
        return Err(QuicTransportError::Quic(
            "send_native_symbol requires an established 1-RTT connection".to_string(),
        ));
    }
    let envelope = symbol_to_envelope(symbol, transfer_tag, entry, auth_tag);
    let bytes = envelope
        .encode()
        .map_err(SymbolDatagramError::from)
        .map_err(QuicTransportError::from)?;
    conn.send_datagram(cx, bytes)?;
    Ok(())
}

#[allow(dead_code)]
async fn spray_native_symbol_round(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
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
        for block_index in 0..entry.block_count(config)? {
            let sbn = u8::try_from(block_index).map_err(|_| QuicTransportError::TooLarge {
                size: entry.size(),
                max: u64::try_from(config.max_block_size.max(1))
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::from(u8::MAX) + 1),
            })?;
            let block = entry.read_block(cx, sbn, config).await?;
            let already = entry.repair_cursor(sbn);
            let target_repair = if with_source {
                initial_repair_per_block(block.len(), config)
            } else {
                already.saturating_add(repair_batch)
            };
            let repair_count = target_repair.saturating_sub(already);
            if !with_source && repair_count == 0 {
                entry.set_repair_cursor(sbn, target_repair);
                continue;
            }

            let mut pipeline = encoding_pipeline(config);
            let encoded = if with_source {
                EitherNativeEncoding::Source(pipeline.encode_single_block_with_repair(
                    entry.object_id,
                    sbn,
                    &block,
                    target_repair,
                ))
            } else {
                EitherNativeEncoding::Repair(pipeline.encode_single_block_repair_range(
                    entry.object_id,
                    sbn,
                    &block,
                    already,
                    repair_count,
                ))
            };
            for symbol in encoded {
                let symbol = symbol
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
                send_native_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
            }
            entry.set_repair_cursor(sbn, target_repair);
        }
    }
    Ok(sent)
}

enum EitherNativeEncoding<'a> {
    Source(crate::encoding::EncodingIterator<'a>),
    Repair(crate::encoding::RepairEncodingIterator<'a>),
}

impl Iterator for EitherNativeEncoding<'_> {
    type Item = Result<crate::encoding::EncodedSymbol, crate::encoding::EncodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Source(iter) => iter.next(),
            Self::Repair(iter) => iter.next(),
        }
    }
}

#[allow(dead_code)]
async fn spray_native_initial_symbols(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let pending = encoders
        .iter()
        .map(|entry| entry.index)
        .collect::<std::collections::BTreeSet<_>>();
    spray_native_symbol_round(
        cx,
        conn,
        manifest,
        encoders,
        &pending,
        config,
        symbol_auth,
        true,
    )
    .await
}

#[allow(dead_code)]
async fn native_source_symbol_for_request(
    cx: &Cx,
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
    let block = enc.read_block(cx, request.sbn, config).await?;
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_k = block.len().div_ceil(symbol_size).max(1);
    let esi = usize::try_from(request.esi).map_err(|_| {
        QuicTransportError::Integrity("source request ESI does not fit usize".to_string())
    })?;
    if esi >= block_k {
        return Err(QuicTransportError::Integrity(format!(
            "source request esi {} outside entry {} block {} K={}",
            request.esi, enc.index, request.sbn, block_k
        )));
    }

    let start = esi * symbol_size;
    let end = (start + symbol_size).min(block.len());
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        buffer[..end - start].copy_from_slice(&block[start..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

#[allow(dead_code)]
async fn send_native_source_symbol_requests(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    encoders: &[QuicEntryEncoder],
    requests: &[QuicSourceSymbolRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_native_connection(config, conn);
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
        let symbol = native_source_symbol_for_request(cx, enc, *request, config).await?;
        let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
        send_native_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
        sent = sent.saturating_add(1);
        pacer.after_symbol_sent(cx).await?;
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn send_native_block_repair_requests(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    requests: &[QuicBlockRepairRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_native_connection(config, conn);
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let enc = encoders
            .iter_mut()
            .find(|entry| entry.index == request.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "receiver requested repair block for unknown entry {}",
                    request.entry
                ))
            })?;
        let repair_count = usize::try_from(request.symbols).map_err(|_| {
            QuicTransportError::Integrity("repair symbol count does not fit usize".to_string())
        })?;
        let block = enc.read_block(cx, request.sbn, config).await?;
        let already = enc.repair_cursor(request.sbn);
        let target_repair = already.saturating_add(repair_count);
        quic_rqtrace(format_args!(
            "sender-native: repair_block entry={} sbn={} requested_symbols={} repair_cursor_start={} repair_cursor_target={}",
            request.entry, request.sbn, repair_count, already, target_repair
        ));
        let mut pipeline = encoding_pipeline(config);
        for encoded in pipeline.encode_single_block_repair_range(
            enc.object_id,
            request.sbn,
            &block,
            already,
            repair_count,
        ) {
            let symbol = encoded
                .map_err(|err| QuicTransportError::Control(err.to_string()))?
                .into_symbol();
            let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol(&symbol).tag().as_bytes());
            send_native_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
            sent = sent.saturating_add(1);
            pacer.after_symbol_sent(cx).await?;
        }
        enc.set_repair_cursor(request.sbn, target_repair);
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn send_native_repair_round_and_object_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    need: &QuicNeedMore,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    if need.pending.is_empty() && need.repair_blocks.is_empty() && need.source_symbols.is_empty() {
        send_native_object_complete(cx, conn, control, 0)?;
        return Ok(0);
    }
    validate_need_more_feedback(manifest, config, need)?;
    let sent = if !need.repair_blocks.is_empty() {
        send_native_block_repair_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.repair_blocks,
            config,
            symbol_auth,
        )
        .await?
    } else if need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver NeedMore listed pending entries without targeted repair/source deficits"
                .to_string(),
        ));
    } else {
        send_native_source_symbol_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.source_symbols,
            config,
            symbol_auth,
        )
        .await?
    };
    send_native_object_complete(cx, conn, control, sent)?;
    Ok(sent)
}

#[allow(dead_code)]
async fn send_native_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    let symbol_auth = config.symbol_auth_context()?;
    send_native_manifest(cx, conn, control, manifest)?;
    let symbols_sent =
        spray_native_initial_symbols(cx, conn, manifest, encoders, config, symbol_auth.as_ref())
            .await?;
    send_native_object_complete(cx, conn, control, symbols_sent)?;
    Ok(symbols_sent)
}

#[allow(dead_code)]
async fn send_native_prepared_source_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<(Vec<QuicEntryEncoder>, u64), QuicTransportError> {
    let config = prepared.effective_config(config);
    config.validate()?;
    validate_quic_manifest(&prepared.manifest, &config)?;
    let mut encoders = encoders_from_prepared_source(cx, prepared, &config).await?;
    let symbols_sent = send_native_manifest_symbols_complete(
        cx,
        conn,
        control,
        &prepared.manifest,
        &mut encoders,
        &config,
    )
    .await?;
    Ok((encoders, symbols_sent))
}

#[allow(dead_code)]
fn finish_native_sender_transfer(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    peer: SocketAddr,
    receipt: ReceiveReceipt,
    symbols_sent: u64,
    feedback_rounds: u32,
) -> Result<SendReport, QuicTransportError> {
    send_native_close(cx, conn, control)?;
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
        symbols_sent,
        feedback_rounds,
        merkle_root_hex: manifest.merkle_root_hex.clone(),
        receipt,
        peer,
    })
}

#[allow(dead_code)]
async fn handle_native_sender_feedback_or_proof(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    state: &mut QuicSenderFeedbackState<'_>,
) -> Result<Option<SendReport>, QuicTransportError> {
    match receive_native_proof_or_need_more(cx, conn, control)? {
        QuicControlReply::Proof(receipt) => finish_native_sender_transfer(
            cx,
            conn,
            control,
            state.manifest,
            state.peer,
            receipt,
            state.symbols_sent,
            state.feedback_rounds,
        )
        .map(Some),
        QuicControlReply::NeedMore(need) => {
            state.feedback_rounds = state.feedback_rounds.saturating_add(1);
            state.observe_need_more(&need);
            trace_quic_aimd_feedback(cx, state);
            trace_quic_sender_need_more(
                cx,
                state.feedback_rounds,
                state.symbols_sent,
                state.sent_this_round(),
                &need,
                state.config,
                Some(state.aimd_rate_bps),
                None,
            );
            if need.pending.is_empty()
                && need.repair_blocks.is_empty()
                && need.source_symbols.is_empty()
            {
                trace_quic_sender_repair_round(
                    cx,
                    state.feedback_rounds,
                    quic_need_more_response_mode(&need),
                    state.symbols_sent,
                    0,
                    &need,
                );
                return Ok(None);
            }
            let round_config = state.next_round_config();
            let symbol_auth = round_config.symbol_auth_context()?;
            let previous_symbols_sent = state.symbols_sent;
            let response_mode = quic_need_more_response_mode(&need);
            let sent = send_native_repair_round_and_object_complete(
                cx,
                conn,
                control,
                state.manifest,
                state.encoders,
                &need,
                &round_config,
                symbol_auth.as_ref(),
            )
            .await?;
            state.mark_next_round_started(previous_symbols_sent, sent);
            trace_quic_sender_repair_round(
                cx,
                state.feedback_rounds,
                response_mode,
                previous_symbols_sent,
                sent,
                &need,
            );
            Ok(None)
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeSenderDrivePoint {
    HelloSent,
    ObjectCompleteSent,
}

#[allow(dead_code)]
async fn send_prepared_source_over_established_native_connection<F>(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    peer: SocketAddr,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
    peer_id: &str,
    mut drive_peer: F,
) -> Result<SendReport, QuicTransportError>
where
    F: FnMut(NativeSenderDrivePoint, &mut NativeQuicConnection) -> Result<(), QuicTransportError>,
{
    let config = prepared.effective_config(config);
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    validate_quic_manifest(&prepared.manifest, &config)?;
    let fanout_plan =
        quic_plan_initial_fanout_dispatch(&config, usize::MAX, &prepared.manifest, &[])?;
    trace_quic_fanout_dispatch_plan(cx, 0, &fanout_plan);
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();
    let mut control = NativeQuicFrameTransport::open(cx, conn)?;

    send_native_sender_hello(
        cx,
        conn,
        &mut control,
        &config,
        peer_id,
        symbol_auth_enabled,
    )?;
    drive_peer(NativeSenderDrivePoint::HelloSent, conn)?;
    receive_native_sender_hello_ack(cx, conn, &mut control)?;

    let (mut encoders, symbols_sent) = send_native_prepared_source_manifest_symbols_complete(
        cx,
        conn,
        &mut control,
        prepared,
        &config,
    )
    .await?;
    drive_peer(NativeSenderDrivePoint::ObjectCompleteSent, conn)?;

    let mut state = QuicSenderFeedbackState::new(
        &prepared.manifest,
        &mut encoders,
        &config,
        peer,
        symbols_sent,
    );
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        if let Some(report) =
            handle_native_sender_feedback_or_proof(cx, conn, &mut control, &mut state).await?
        {
            return Ok(report);
        }
        drive_peer(NativeSenderDrivePoint::ObjectCompleteSent, conn)?;
    }
}

fn recv_native_symbol_envelope(
    conn: &mut NativeQuicConnection,
    auth_required: bool,
) -> Result<Option<QuicSymbolEnvelope>, QuicTransportError> {
    match conn.recv_datagram() {
        Some(bytes) => QuicSymbolEnvelope::decode_bytes(bytes, auth_required)
            .map(Some)
            .map_err(SymbolDatagramError::from)
            .map_err(QuicTransportError::from),
        None => Ok(None),
    }
}

#[allow(dead_code)]
fn drain_native_symbol_datagrams(
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let aggregator = primary_quic_receive_aggregator("quic-native-peer");
    let receive =
        QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO);
    drain_native_symbol_datagrams_with_aggregator(conn, manifest, decoders, config, receive)
}

fn drain_native_symbol_datagrams_with_aggregator(
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    receive: QuicReceiveAggregation<'_>,
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
            .iter()
            .find(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        let auth_symbol = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoder.object_id,
            symbol_auth.as_ref(),
        )?;
        accepted = accepted.saturating_add(feed_aggregated_symbol_for_entry(
            decoders,
            envelope.entry,
            auth_symbol,
            receive,
        )?);
    }
    Ok(accepted)
}

async fn drain_native_symbol_datagrams_with_aggregator_deferred(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    receive: QuicReceiveAggregation<'_>,
    decode_stats: &mut QuicDecodeStats,
) -> Result<QuicRoundSymbolStats, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut stats = QuicRoundSymbolStats::default();
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
            .iter()
            .find(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        stats.observed = stats.observed.saturating_add(1);
        let auth_symbol = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoder.object_id,
            symbol_auth.as_ref(),
        )?;
        stats.accepted = stats
            .accepted
            .saturating_add(feed_aggregated_symbol_for_entry_deferred(
                cx,
                decoders,
                envelope.entry,
                auth_symbol,
                receive,
                config,
                decode_stats,
            )?);
        let _ = drain_ready_quic_decodes(cx, decoders, decode_stats).await?;
    }
    let _ = drain_ready_quic_decodes(cx, decoders, decode_stats).await?;
    Ok(stats)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
async fn drain_native_symbol_datagrams_with_blocks(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
) -> Result<(u64, u64, Vec<QuicDecodedBlock>), QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut accepted = 0u64;
    let mut completed = Vec::new();
    let mut drained = 0usize;
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
        let decoder_index = decoders
            .iter_mut()
            .position(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        let auth_symbol = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoders[decoder_index].object_id,
            symbol_auth.as_ref(),
        )?;
        let transfer_decode_width = quic_transfer_decode_width(decoders, config);
        let allow_spawn_decode = quic_pending_decode_jobs(decoders) < transfer_decode_width;
        let (was_accepted, block) = feed_authenticated_symbol_take_block_deferred(
            cx,
            &mut decoders[decoder_index],
            auth_symbol,
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        )?;
        if was_accepted {
            accepted = accepted.saturating_add(1);
        }
        if let Some(block) = block {
            completed.push(block);
        }
        completed.extend(
            drain_ready_quic_decodes_with_blocks(
                cx,
                decoders,
                config,
                decode_stats,
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?,
        );
        drained = drained.saturating_add(1);
        if drained >= NATIVE_SYMBOL_DRAIN_BATCH {
            break;
        }
    }
    let transfer_decode_width = quic_transfer_decode_width(decoders, config);
    completed.extend(
        join_all_quic_decodes_with_blocks(
            cx,
            decoders,
            config,
            decode_stats,
            transfer_decode_width,
        )
        .await?,
    );
    Ok((
        u64::try_from(drained).unwrap_or(u64::MAX),
        accepted,
        completed,
    ))
}

fn validate_quic_manifest(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    // The off-wire `transfer_id` is interpolated directly into the receiver's
    // on-disk staging-directory path (native_link.rs:
    // `.atp-quic-staging-{transfer_id}-...`), which is created and then
    // `remove_dir_all`'d during a receive. A legitimate sender always emits a
    // bounded lowercase-hex token, so constrain it to a bounded alphanumeric
    // token here. Without this a hostile peer could set `transfer_id` to e.g.
    // `x/../../../../tmp/pwn` and steer the receiver's staging writes and
    // `remove_dir_all` outside the destination directory (directory traversal /
    // arbitrary delete). Mirrors the transport_tcp `validate_manifest` guard
    // (asupersync-my6ocy).
    if manifest.transfer_id.is_empty()
        || manifest.transfer_id.len() > 64
        || !manifest
            .transfer_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    {
        return Err(QuicTransportError::Source(format!(
            "unsafe manifest transfer_id: {}",
            manifest.transfer_id
        )));
    }
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
    if manifest
        .metadata_root_hex
        .as_ref()
        .is_some_and(|root| root.len() != 64 || !root.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(QuicTransportError::Source(
            "manifest metadata_root_hex is not a 64-byte hex digest".to_string(),
        ));
    }

    let mut seen_paths = std::collections::BTreeSet::new();
    let mut total = 0u64;
    let empty_sha_hex = hex_encode(&Sha256::digest(b""));
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
        let metadata = entry.metadata.clone().unwrap_or_default();
        if metadata.hardlink_target.is_some() && !matches!(metadata.file_kind, FileKind::Regular) {
            return Err(QuicTransportError::Source(format!(
                "manifest entry {} declares hardlink metadata on non-regular kind {:?}",
                entry.rel_path, metadata.file_kind
            )));
        }
        if matches!(metadata.file_kind, FileKind::Symlink)
            && metadata.symlink_target.as_deref().is_none_or(str::is_empty)
        {
            return Err(QuicTransportError::Source(format!(
                "manifest symlink entry {} is missing symlink_target",
                entry.rel_path
            )));
        }
        if let Some(primary_rel) = &metadata.hardlink_target {
            quic_join_relative(Path::new("base"), primary_rel)?;
            if primary_rel == &entry.rel_path || !seen_paths.contains(primary_rel.as_str()) {
                return Err(QuicTransportError::Source(format!(
                    "manifest hardlink entry {} targets missing or later primary {}",
                    entry.rel_path, primary_rel
                )));
            }
        }
        if (!matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some())
            && (entry.size != 0 || entry.sha256_hex.as_str() != empty_sha_hex.as_str())
        {
            return Err(QuicTransportError::Source(format!(
                "manifest metadata-only entry {} must carry zero content",
                entry.rel_path
            )));
        }
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
    if manifest_metadata_commitment(manifest) != manifest.metadata_root_hex {
        return Err(QuicTransportError::Source(
            "manifest metadata commitment mismatch".to_string(),
        ));
    }
    reject_quic_symlink_traversal(manifest)?;
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

async fn reject_quic_destination_symlink_prefix(
    base: &Path,
    out_path: &Path,
) -> Result<(), QuicTransportError> {
    let rel = out_path.strip_prefix(base).map_err(|_| {
        QuicTransportError::Source(format!(
            "destination path {} is outside safe base {}",
            out_path.display(),
            base.display()
        ))
    })?;

    let mut current = base.to_path_buf();
    reject_quic_existing_symlink(&current).await?;
    for component in rel.components() {
        let Component::Normal(component) = component else {
            return Err(QuicTransportError::Source(format!(
                "unsafe destination component in {}",
                out_path.display()
            )));
        };
        current.push(component);
        reject_quic_existing_symlink(&current).await?;
    }
    Ok(())
}

async fn reject_quic_existing_symlink(path: &Path) -> Result<(), QuicTransportError> {
    match crate::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_symlink() => Err(QuicTransportError::Source(format!(
            "destination path crosses existing symlink: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn manifest_metadata_commitment(manifest: &TransferManifest) -> Option<String> {
    let metadata_pairs: Vec<(String, EntryMetadata)> = manifest
        .entries
        .iter()
        .map(|entry| {
            (
                entry.rel_path.clone(),
                entry.metadata.clone().unwrap_or_default(),
            )
        })
        .collect();
    let metadata_refs: Vec<(&str, &EntryMetadata)> = metadata_pairs
        .iter()
        .map(|(path, metadata)| (path.as_str(), metadata))
        .collect();
    metadata_commitment(&metadata_refs)
}

/// Reject a manifest where a later entry is nested under an earlier symlink
/// entry. Lexical path sanitization blocks `..`, but without this check the
/// receiver could create `link -> /tmp/outside` and then write `link/file`.
fn reject_quic_symlink_traversal(manifest: &TransferManifest) -> Result<(), QuicTransportError> {
    let symlink_paths: Vec<&str> = manifest
        .entries
        .iter()
        .filter(|entry| {
            entry
                .metadata
                .as_ref()
                .is_some_and(|metadata| matches!(metadata.file_kind, FileKind::Symlink))
        })
        .map(|entry| entry.rel_path.as_str())
        .collect();
    if symlink_paths.is_empty() {
        return Ok(());
    }
    for entry in &manifest.entries {
        let path = entry.rel_path.as_str();
        for symlink in &symlink_paths {
            if path.len() > symlink.len()
                && path.as_bytes()[symlink.len()] == b'/'
                && path.starts_with(symlink)
            {
                return Err(QuicTransportError::Source(format!(
                    "manifest entry {path} is nested under symlink entry {symlink}; refusing to \
                     write through a link"
                )));
            }
        }
    }
    Ok(())
}

fn trace_quic_metadata_skips(cx: &Cx, out_path: &Path, report: &MetadataApplyReport) {
    if cx.trace_buffer().is_none() {
        return;
    }
    let path = out_path.display().to_string();
    for (field, reason) in &report.skipped {
        cx.trace_with_fields(
            "atp_quic_metadata_skipped",
            &[
                ("path", path.as_str()),
                ("field", *field),
                ("reason", reason.as_str()),
            ],
        );
    }
}

async fn apply_quic_entry_metadata(
    cx: &Cx,
    out_path: &Path,
    entry: &ManifestEntry,
) -> Result<(), QuicTransportError> {
    if let Some(metadata) = &entry.metadata {
        let report = apply_entry_metadata(out_path, metadata).await?;
        trace_quic_metadata_skips(cx, out_path, &report);
    }
    Ok(())
}

fn trace_quic_special_file_skipped(cx: &Cx, out_path: &Path, kind: FileKind) {
    if cx.trace_buffer().is_none() {
        return;
    }
    let path = out_path.display().to_string();
    let kind = format!("{kind:?}");
    cx.trace_with_fields(
        "atp_quic_special_file_skipped",
        &[("path", path.as_str()), ("kind", kind.as_str())],
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicMetadataCommit {
    Regular,
    Committed,
    Skipped,
}

async fn commit_quic_metadata_entry(
    cx: &Cx,
    base: &Path,
    out_path: &Path,
    entry: &ManifestEntry,
    config: &QuicConfig,
) -> Result<QuicMetadataCommit, QuicTransportError> {
    let Some(metadata) = &entry.metadata else {
        return Ok(QuicMetadataCommit::Regular);
    };
    reject_quic_destination_symlink_prefix(base, out_path).await?;

    if metadata.file_kind.is_special() {
        if matches!(metadata.file_kind, FileKind::Fifo) && config.allow_special_files {
            if let Some(parent) = out_path.parent() {
                crate::fs::create_dir_all(parent).await?;
            }
            let mode = metadata.unix_mode.unwrap_or(0o644);
            let _ = crate::fs::remove_file(out_path).await;
            crate::net::atp::transport_common::metadata::recreate_fifo(out_path, mode).await?;
            return Ok(QuicMetadataCommit::Committed);
        }
        trace_quic_special_file_skipped(cx, out_path, metadata.file_kind);
        return Ok(QuicMetadataCommit::Skipped);
    }

    if let Some(parent) = out_path.parent() {
        crate::fs::create_dir_all(parent).await?;
    }

    if matches!(metadata.file_kind, FileKind::Directory) {
        crate::fs::create_dir_all(out_path).await?;
        apply_quic_entry_metadata(cx, out_path, entry).await?;
        return Ok(QuicMetadataCommit::Committed);
    }

    if let Some(target) = metadata
        .symlink_target
        .as_ref()
        .filter(|_| matches!(metadata.file_kind, FileKind::Symlink))
    {
        let _ = crate::fs::remove_file(out_path).await;
        crate::fs::symlink(target, out_path).await?;
        return Ok(QuicMetadataCommit::Committed);
    }

    if let Some(primary_rel) = &metadata.hardlink_target {
        let primary_path = quic_join_relative(base, primary_rel)?;
        let _ = crate::fs::remove_file(out_path).await;
        crate::fs::hard_link(&primary_path, out_path).await?;
        return Ok(QuicMetadataCommit::Committed);
    }

    Ok(QuicMetadataCommit::Regular)
}

async fn commit_decoded_entries(
    cx: &Cx,
    dest_dir: &Path,
    manifest: &TransferManifest,
    decoders: &[QuicEntryDecoder],
    symbols_accepted: u64,
    feedback_rounds: u32,
    decode_stats: QuicDecodeStats,
    config: &QuicConfig,
) -> Result<(ReceiveReceipt, Vec<PathBuf>), QuicTransportError> {
    let mut receipt = verify_in_memory_receipt(manifest, decoders);
    receipt.symbols_accepted = symbols_accepted;
    receipt.feedback_rounds = feedback_rounds;
    receipt.decode_count = decode_stats.decode_count;
    receipt.decode_micros = decode_stats.decode_micros;
    if !receipt.committed {
        return Ok((receipt, Vec::new()));
    }

    let base = quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    let mut committed_paths = Vec::with_capacity(manifest.entries.len().saturating_add(1));
    if manifest.is_directory && manifest.entries.is_empty() {
        reject_quic_destination_symlink_prefix(&base, &base).await?;
        crate::fs::create_dir_all(&base).await?;
        committed_paths.push(base.clone());
    }
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
        match commit_quic_metadata_entry(cx, &base, &out_path, entry, config).await? {
            QuicMetadataCommit::Committed => {
                committed_paths.push(out_path);
                continue;
            }
            QuicMetadataCommit::Skipped => continue,
            QuicMetadataCommit::Regular => {}
        }
        reject_quic_destination_symlink_prefix(&base, &out_path).await?;
        if let Some(parent) = out_path.parent() {
            crate::fs::create_dir_all(parent).await?;
        }
        crate::fs::write_atomic(&out_path, &decoder.data).await?;
        apply_quic_entry_metadata(cx, &out_path, entry).await?;
        committed_paths.push(out_path);
    }

    receipt.committed_paths = committed_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    Ok((receipt, committed_paths))
}

async fn receive_native_symbol_round(
    cx: &Cx,
    connection: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    aggregator: &MultipathAggregator,
    symbols_accepted: &mut u64,
    feedback_rounds: &mut u32,
    decode_stats: &mut QuicDecodeStats,
) -> Result<Option<QuicNeedMore>, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let round_stats = drain_native_symbol_datagrams_with_aggregator_deferred(
        cx,
        connection,
        manifest,
        decoders,
        config,
        QuicReceiveAggregation::new(aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, cx.now())
            .with_trace(cx),
        decode_stats,
    )
    .await?;
    *symbols_accepted = (*symbols_accepted).saturating_add(round_stats.accepted);
    let round_complete = receive_native_object_complete(cx, connection, control)?;
    let _ = join_all_quic_decodes(cx, decoders, decode_stats).await?;
    decode_stats.add(assemble_completed_entries(decoders));

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
    let round_loss_fraction =
        receiver_round_loss_fraction(round_stats.observed, round_complete.round_symbols_sent);
    let repair_blocks = block_repair_requests(
        decoders,
        config,
        MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
        round_loss_fraction,
    );
    let source_symbols = if repair_blocks.is_empty() {
        source_symbol_requests(decoders, MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND)
    } else {
        Vec::new()
    };
    let need = QuicNeedMore {
        pending,
        repair_blocks,
        source_symbols,
        round_symbols_observed: Some(round_stats.observed),
        round_loss_fraction,
        round_symbols_accepted: Some(round_stats.accepted),
    };
    let round = (*feedback_rounds).saturating_add(1);
    let pending_count = need.pending.len().to_string();
    let block_request_count = need.repair_blocks.len().to_string();
    let repair_symbol_count = need
        .repair_blocks
        .iter()
        .fold(0u64, |acc, request| {
            acc.saturating_add(u64::from(request.symbols))
        })
        .to_string();
    let source_request_count = need.source_symbols.len().to_string();
    let accepted_count = symbols_accepted.to_string();
    let round_symbols_sent = round_complete.round_symbols_sent.to_string();
    let round_symbols_observed = round_stats.observed.to_string();
    let round_symbols_accepted = round_stats.accepted.to_string();
    let round_loss_fraction = format!("{:.6}", need.round_loss_fraction.unwrap_or(0.0));
    let repair_block_requests = quic_repair_block_request_summary(&need.repair_blocks);
    let repair_symbol_round_cap = MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND.to_string();
    let repair_block_request_cap = MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND.to_string();
    let round_text = round.to_string();
    cx.trace_with_fields(
        "atp_quic.receive.need_more",
        &[
            ("round", round_text.as_str()),
            ("pending", pending_count.as_str()),
            ("block_requests", block_request_count.as_str()),
            ("repair_symbols", repair_symbol_count.as_str()),
            ("source_requests", source_request_count.as_str()),
            ("round_symbols_sent", round_symbols_sent.as_str()),
            ("round_symbols_observed", round_symbols_observed.as_str()),
            ("round_symbols_accepted", round_symbols_accepted.as_str()),
            ("round_loss_fraction", round_loss_fraction.as_str()),
            ("symbols_accepted", accepted_count.as_str()),
            ("repair_block_requests", repair_block_requests.as_str()),
            ("repair_symbol_round_cap", repair_symbol_round_cap.as_str()),
            (
                "repair_block_request_cap",
                repair_block_request_cap.as_str(),
            ),
        ],
    );
    quic_rqtrace(format_args!(
        "receiver: NeedMore round={} pending={} repair_blocks={} requested_repair_symbols={} source_requests={} round_symbols_sent={} round_symbols_observed={} round_symbols_accepted={} round_loss_fraction={} symbols_accepted={} max_feedback_rounds={} repair_symbol_round_cap={} repair_block_request_cap={} repair_block_requests={}",
        round,
        pending_count,
        block_request_count,
        repair_symbol_count,
        source_request_count,
        round_symbols_sent,
        round_symbols_observed,
        round_symbols_accepted,
        round_loss_fraction,
        accepted_count,
        config.max_feedback_rounds,
        repair_symbol_round_cap,
        repair_block_request_cap,
        repair_block_requests,
    ));
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
    let aggregator = primary_quic_receive_aggregator(peer.to_string());
    let mut symbols_accepted = 0u64;
    let mut feedback_rounds = 0u32;
    let mut decode_stats = QuicDecodeStats::default();

    loop {
        if receive_native_symbol_round(
            cx,
            &mut connection,
            &mut control,
            &manifest,
            &mut decoders,
            &config,
            &aggregator,
            &mut symbols_accepted,
            &mut feedback_rounds,
            &mut decode_stats,
        )
        .await?
        .is_none()
        {
            break;
        }
    }

    let (receipt, committed_paths) = commit_decoded_entries(
        cx,
        dest_dir,
        &manifest,
        &decoders,
        symbols_accepted,
        feedback_rounds,
        decode_stats,
        &config,
    )
    .await?;
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
        symbols_accepted: receipt.symbols_accepted,
        feedback_rounds: receipt.feedback_rounds,
        decode_count: receipt.decode_count,
        decode_micros: receipt.decode_micros,
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
    let bwlimit_bps = config
        .bwlimit_bps
        .map_or_else(|| "none".to_string(), |limit| limit.to_string());
    let max_spray_symbols_per_flush = config.max_spray_symbols_per_flush.to_string();
    let responsiveness_pressure = format!("{:.6}", config.responsiveness_pressure);
    let metadata_policy = format!("{:?}", config.metadata_policy);
    let allow_special_files = config.allow_special_files.to_string();
    let preserve_hardlinks = config.preserve_hardlinks.to_string();
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
    cx.trace_with_fields(
        "atp_quic.transport.config",
        &[
            ("operation", operation),
            ("peer_id", peer_id),
            ("bwlimit_bps", &bwlimit_bps),
            ("max_spray_symbols_per_flush", &max_spray_symbols_per_flush),
            ("responsiveness_pressure", &responsiveness_pressure),
            ("metadata_policy", &metadata_policy),
            ("allow_special_files", &allow_special_files),
            ("preserve_hardlinks", &preserve_hardlinks),
        ],
    );
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Transfer the file or directory at `source` to `addr` over a real QUIC
/// connection.
///
/// Mirrors [`transport_tcp::send_path`]. The B2 sender performs the streaming
/// source walk/hash/manifest preflight, then (with the `tls` feature) opens a
/// real native QUIC connection to `addr`: it runs the genuine `rustls::quic`
/// TLS-1.3 handshake over a UDP socket — verifying the server identity against
/// the configured roots (no insecure skip-verify) — and drives the full sender
/// coroutine (Hello, manifest, RaptorQ symbol spray over QUIC DATAGRAMs, and the
/// fountain feedback loop) until the receiver returns a committed Proof.
///
/// Requires [`QuicConfig::client_tls`] to be set; without it (or without the
/// `tls` feature) it fails closed — there is no insecure transport path.
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
    let config = prepared.effective_config(&config);
    config.validate()?;
    let fanout_plan =
        quic_plan_initial_fanout_dispatch(&config, usize::MAX, &prepared.manifest, &[])?;
    trace_quic_fanout_dispatch_plan(cx, 0, &fanout_plan);
    #[cfg(feature = "tls")]
    {
        native_link::send_prepared_over_udp(cx, addr, &prepared, &config, peer_id).await
    }
    #[cfg(not(feature = "tls"))]
    {
        let _ = (addr, prepared);
        Err(QuicTransportError::Config(
            "ATP-over-QUIC send requires the `tls` feature for the native QUIC/TLS-1.3 \
             handshake; there is no insecure transport path"
                .to_string(),
        ))
    }
}

/// Bind a server UDP socket on `listen`, accept exactly one transfer over a real
/// QUIC connection, write it under `dest_dir`, verify it, and return a report.
///
/// The native-UDP server counterpart to [`send_path`] (parallel to
/// [`transport_tcp::receive_once`], but it owns the UDP endpoint and runs the
/// real `rustls::quic` accept-side handshake presenting the configured server
/// certificate). Requires [`QuicConfig::server_tls`]; only available with the
/// `tls` feature.
///
/// [`transport_tcp::receive_once`]: crate::net::atp::transport_tcp::receive_once
#[cfg(feature = "tls")]
pub async fn receive_path(
    cx: &Cx,
    listen: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "receive_path", &config, peer_id);
    let endpoint = native_link::bind_server_endpoint(cx, listen).await?;
    native_link::receive_on_endpoint(cx, endpoint, dest_dir, &config, peer_id).await
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
        QuicPathStats, QuicTransportMachine, SentPacketMeta, StreamDirection, StreamRole,
        establish_loopback, pump_app_data, pump_until_idle,
    };
    use crate::trace::{TraceBufferHandle, TraceData};

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        futures_lite::future::block_on(fut)
    }

    fn trusted_quic_config() -> QuicConfig {
        QuicConfig::default().allow_unauthenticated_for_trusted_transport()
    }

    #[test]
    fn native_symbol_drain_batch_matches_receiver_pump_width() {
        assert_eq!(NATIVE_SYMBOL_DRAIN_BATCH, 512);
    }

    #[test]
    fn quic_sender_aimd_halves_rate_on_receiver_observed_loss() {
        let manifest = sample_manifest();
        let config = trusted_quic_config();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut encoders = Vec::new();
        let mut state = QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, 100);
        let initial_rate = state.aimd_rate_bps;

        state.observe_need_more(&QuicNeedMore {
            pending: vec![0],
            round_symbols_observed: Some(98),
            round_symbols_accepted: Some(98),
            round_loss_fraction: Some(0.25),
            ..QuicNeedMore::default()
        });

        assert_eq!(state.last_round_loss_fraction, 0.25);
        assert_eq!(state.aimd_rate_bps, initial_rate / 2);
        assert_eq!(
            state.next_round_config().bwlimit_bps,
            Some(initial_rate / 2)
        );
    }

    #[test]
    fn quic_sender_aimd_additively_increases_on_clean_feedback() {
        let manifest = sample_manifest();
        let config = trusted_quic_config();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut encoders = Vec::new();
        let mut state = QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, 200);
        state.aimd_rate_bps = 4 * 1024 * 1024;
        state.aimd_feedback_seen = true;

        state.observe_need_more(&QuicNeedMore {
            pending: vec![0],
            round_symbols_observed: Some(200),
            round_symbols_accepted: Some(200),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        });

        assert_eq!(state.last_round_loss_fraction, 0.0);
        assert_eq!(
            state.aimd_rate_bps,
            4 * 1024 * 1024 + QUIC_AIMD_ADDITIVE_INCREASE_BYTES_PER_S
        );
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

    fn cancelled_test_cx() -> Cx<crate::cx::cap::All> {
        let cx = Cx::for_testing();
        cx.set_cancel_reason(crate::types::CancelReason::user(
            "transport_quic cancellation test",
        ));
        cx
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
            delta_manifest: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
                metadata: None,
            }],
        }
    }

    /// `validate_quic_manifest` must reject an off-wire `transfer_id` that is not a
    /// bounded alphanumeric token, before it can steer the receiver's staging path
    /// / `remove_dir_all` outside the destination (directory traversal). See
    /// `asupersync-my6ocy`; mirrors the transport_tcp `validate_manifest` guard.
    #[test]
    fn validate_quic_manifest_rejects_unsafe_transfer_id() {
        let config = trusted_quic_config();

        // A legitimate alphanumeric transfer_id passes the guard.
        assert!(validate_quic_manifest(&sample_manifest(), &config).is_ok());

        // Traversal / separator / control / whitespace / empty tokens fail closed.
        for bad in [
            "x/../../../../tmp/pwn",
            "..",
            "a/b",
            "a\\b",
            "with space",
            "tab\there",
            "",
        ] {
            let mut manifest = sample_manifest();
            manifest.transfer_id = bad.to_string();
            assert!(
                matches!(
                    validate_quic_manifest(&manifest, &config),
                    Err(QuicTransportError::Source(_))
                ),
                "transfer_id {bad:?} must be rejected fail-closed",
            );
        }

        // Over-length (>64) is rejected even when alphanumeric.
        let mut too_long = sample_manifest();
        too_long.transfer_id = "a".repeat(65);
        assert!(matches!(
            validate_quic_manifest(&too_long, &config),
            Err(QuicTransportError::Source(_))
        ));

        // The 64-char boundary alphanumeric token is accepted.
        let mut boundary = sample_manifest();
        boundary.transfer_id = "a".repeat(64);
        assert!(validate_quic_manifest(&boundary, &config).is_ok());
    }

    fn quic_manifest_with_metadata(entries: Vec<ManifestEntry>) -> TransferManifest {
        let mut manifest = TransferManifest {
            transfer_id: "transfer42".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: entries
                .iter()
                .fold(0u64, |acc, entry| acc.saturating_add(entry.size)),
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            delta_manifest: None,
            entries,
        };
        manifest.metadata_root_hex = manifest_metadata_commitment(&manifest);
        manifest
    }

    fn quic_symlink_entry(index: u32, rel: &str, target: &str) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: rel.to_string(),
            size: 0,
            sha256_hex: sha256_hex(b""),
            metadata: Some(EntryMetadata {
                file_kind: FileKind::Symlink,
                symlink_target: Some(target.to_string()),
                ..Default::default()
            }),
        }
    }

    fn quic_empty_regular_entry(index: u32, rel: &str) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: rel.to_string(),
            size: 0,
            sha256_hex: sha256_hex(b""),
            metadata: None,
        }
    }

    #[test]
    fn validate_quic_manifest_rejects_entries_nested_under_manifest_symlink() {
        let config = trusted_quic_config();
        let bad = quic_manifest_with_metadata(vec![
            quic_symlink_entry(0, "link", "/tmp/outside"),
            quic_empty_regular_entry(1, "link/payload.txt"),
        ]);

        assert!(
            matches!(
                validate_quic_manifest(&bad, &config),
                Err(QuicTransportError::Source(ref message))
                    if message.contains("nested under symlink")
            ),
            "QUIC manifest must reject writes through declared symlink entries"
        );

        let nested_symlink = quic_manifest_with_metadata(vec![
            quic_symlink_entry(0, "a", "/tmp/a"),
            quic_symlink_entry(1, "a/b", "/tmp/b"),
        ]);
        assert!(
            matches!(
                validate_quic_manifest(&nested_symlink, &config),
                Err(QuicTransportError::Source(ref message))
                    if message.contains("nested under symlink")
            ),
            "nested symlink entries must fail closed before commit"
        );
    }

    #[test]
    fn validate_quic_manifest_allows_symlink_siblings_and_plain_entries() {
        let config = trusted_quic_config();
        let sibling = quic_manifest_with_metadata(vec![
            quic_symlink_entry(0, "link", "target.txt"),
            quic_empty_regular_entry(1, "link-sibling/payload.txt"),
        ]);
        assert!(
            validate_quic_manifest(&sibling, &config).is_ok(),
            "component-aligned symlink guard must not reject sibling prefixes"
        );

        let plain = quic_manifest_with_metadata(vec![
            quic_empty_regular_entry(0, "link/payload.txt"),
            quic_empty_regular_entry(1, "link-sibling/payload.txt"),
        ]);
        assert!(validate_quic_manifest(&plain, &config).is_ok());
    }

    fn sample_receipt() -> ReceiveReceipt {
        ReceiveReceipt {
            committed: true,
            bytes_received: 9,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 0,
            feedback_rounds: 0,
            decode_count: 0,
            decode_micros: 0,
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

    fn quic_decode_width_fixture_entry(size: u64) -> QuicEntryDecoder {
        QuicEntryDecoder {
            index: 0,
            object_id: ObjectId::new(0x5155_4943, size),
            size,
            pipeline: None,
            complete: false,
            data: Vec::new(),
            pending_decodes: Vec::new(),
        }
    }

    fn quic_decode_width_fixture_decoder(
        index: u32,
        size: u64,
        config: &QuicConfig,
    ) -> QuicEntryDecoder {
        let object_id = ObjectId::new(0x5155_4943 + u64::from(index), size);
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: config.repair_overhead,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(0),
            verify_auth: false,
        });
        pipeline
            .set_object_params(object_params_for(
                object_id,
                size,
                config.symbol_size,
                config.max_block_size,
            ))
            .expect("fixture object params fit QUIC decode geometry");
        QuicEntryDecoder {
            index,
            object_id,
            size,
            pipeline: Some(pipeline),
            complete: false,
            data: Vec::new(),
            pending_decodes: Vec::new(),
        }
    }

    fn drive_in_memory_loopback_transfer(
        cx: &Cx,
        sender: &mut QuicConnection,
        receiver: &mut QuicConnection,
        entries: &[(String, Vec<u8>)],
        config: QuicConfig,
    ) -> Result<QuicConnectionTransferOutcome, QuicTransportError> {
        let config = effective_quic_config_for_entries(&config, entries)?;
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

        let mut encoders = encoders_from_entries(&manifest, entries, &config)?;
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
                    repair_blocks: Vec::new(),
                    source_symbols: source_symbol_requests(
                        &decoders,
                        MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND,
                    ),
                    ..QuicNeedMore::default()
                },
            )?;
        }
        pump_until_idle(cx, receiver, sender, DEFAULT_MAX_PACKET_BYTES, 5_003)
            .expect("deliver proof");

        let peer = "127.0.0.1:4433".parse().expect("peer addr");
        let (send_report, symbols_sent) = {
            let mut feedback =
                QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, symbols_sent);
            let report = block_on(handle_sender_feedback_or_proof(
                cx,
                sender,
                &mut sender_control,
                &mut feedback,
            ))?
            .ok_or_else(|| {
                QuicTransportError::Integrity(
                    "sender received repair feedback in no-repair loopback transfer".to_string(),
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
        assert_eq!(c.max_block_size, usize::from(DEFAULT_SYMBOL_SIZE) * 512);
        assert_eq!(c.max_datagram_size, DEFAULT_MAX_DATAGRAM_SIZE);
        assert_eq!(c.max_transfer_bytes, DEFAULT_MAX_TRANSFER_BYTES);
        assert_eq!(c.idle_timeout, DEFAULT_IDLE_TIMEOUT);
        assert_eq!(c.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
        assert_eq!(c.accept_timeout, DEFAULT_ACCEPT_TIMEOUT);
        assert_eq!(c.max_active_connections, DEFAULT_MAX_ACTIVE_CONNECTIONS);
        assert_eq!(c.max_feedback_rounds, DEFAULT_MAX_FEEDBACK_ROUNDS);
        assert_eq!(c.datagram_fanout, DEFAULT_DATAGRAM_FANOUT);
        assert_eq!(
            c.max_spray_symbols_per_flush,
            DEFAULT_MAX_SPRAY_SYMBOLS_PER_FLUSH
        );
        assert_eq!(
            c.symbol_auth_mode(),
            QuicSymbolAuthMode::MissingAuthenticationContext
        );
    }

    #[test]
    fn quic_streaming_parallel_decode_returns_byte_identical_block() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1024,
            max_block_size: 32 * 1024,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let object_size = QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES;
        let mut decoder = quic_decode_width_fixture_decoder(7, object_size, &config);
        let entry_width = quic_entry_decode_width_budget(
            &decoder,
            &config,
            QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
        );
        assert!(
            entry_width > 1,
            "fixture must exercise the gated parallel decode path"
        );

        let block = varied_bytes(config.max_block_size, 91);
        let mut encoder = encoding_pipeline(&config);
        let repair_symbols = encoder
            .encode_single_block_repair_range(decoder.object_id, 0, &block, 0, 48)
            .collect::<Result<Vec<_>, _>>()
            .expect("single-block repair symbols encode");

        let mut decode_stats = QuicDecodeStats::default();
        let mut completed = Vec::new();
        let mut accepted_symbols = 0usize;
        for encoded in repair_symbols {
            let (accepted, decoded) = feed_authenticated_symbol_take_block_deferred(
                &cx,
                &mut decoder,
                AuthenticatedSymbol::new_unauthenticated(encoded.into_symbol()),
                &config,
                &mut decode_stats,
                true,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
            )
            .expect("QUIC streaming decoder accepts repair symbol");
            if accepted {
                accepted_symbols += 1;
            }
            if let Some(decoded) = decoded {
                completed.push(decoded);
                break;
            }
        }
        assert!(
            accepted_symbols >= config.max_block_size / usize::from(config.symbol_size),
            "fixture must feed at least K symbols before decode"
        );
        completed.extend(
            block_on(join_all_quic_decodes_with_blocks(
                &cx,
                std::slice::from_mut(&mut decoder),
                &config,
                &mut decode_stats,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
            ))
            .expect("pending QUIC decode jobs join"),
        );

        assert_eq!(completed.len(), 1, "only block 0 should complete");
        assert_eq!(completed[0].entry, 7);
        assert_eq!(completed[0].sbn, 0);
        assert_eq!(completed[0].data, block);
        assert_eq!(decode_stats.decode_count, 1);
        assert!(
            decoder.pending_decodes.is_empty(),
            "decode join must leave no queued blocking jobs"
        );
        assert!(
            !decoder.complete,
            "one decoded block must not mark the multi-block logical entry complete"
        );
    }

    #[test]
    fn quic_decode_width_gate_keeps_tiny_entries_inline_and_50m_wide() {
        let config = trusted_quic_config();
        let tiny_size = 1024 * 1024;
        let tiny = quic_decode_width_fixture_entry(tiny_size);
        assert!(!quic_should_parallel_decode_entry(&tiny, &config));
        assert_eq!(
            quic_entry_decode_width_budget(
                &tiny,
                &config,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            0,
            "tiny encrypted entries should stay on the inline decode path"
        );
        assert_eq!(
            quic_entry_decode_width_budget_for_geometry(
                tiny_size,
                config.max_block_size,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            0,
            "tiny encrypted geometry should not open a decode fanout window"
        );

        let size_50m = 50 * 1024 * 1024;
        let config_50m = effective_quic_config_for_largest_entry(&config, size_50m)
            .expect("50M fixture must fit default QUIC geometry");
        assert!(quic_should_parallel_decode_entry_geometry(
            size_50m as u64,
            config_50m.max_block_size
        ));
        let dec_50m = quic_decode_width_fixture_entry(size_50m as u64);
        assert!(
            quic_should_parallel_decode_entry(&dec_50m, &config_50m),
            "50M encrypted bulk geometry should be eligible for receiver decode fanout"
        );
        assert_eq!(
            quic_entry_decode_width_budget(
                &dec_50m,
                &config_50m,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY,
            "50M encrypted bulk geometry should use the full per-entry fanout window"
        );
        assert_eq!(
            quic_entry_decode_width_budget_for_geometry(
                size_50m as u64,
                config_50m.max_block_size,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY,
            "50M encrypted bulk geometry should open the same fanout as the decoder helper"
        );
        assert_eq!(
            quic_transfer_decode_width(std::slice::from_ref(&dec_50m), &config_50m),
            QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
            "eligible encrypted bulk transfers should open the transfer-wide decode window"
        );
    }

    #[test]
    fn quic_block_sizer_reuses_rq_k512_plan_for_wide_configs() {
        let config = QuicConfig {
            max_block_size: 8 * 1024 * 1024,
            ..trusted_quic_config()
        };
        let effective = effective_quic_config_for_largest_entry(&config, 10 * 1024 * 1024)
            .expect("normal 10MiB entry fits the bounded-K QUIC plan");

        assert_eq!(
            effective.max_block_size,
            usize::from(effective.symbol_size) * 512
        );

        let params = object_params_for(
            entry_object_id("bounded-k512", 0),
            10 * 1024 * 1024,
            effective.symbol_size,
            effective.max_block_size,
        );
        assert_eq!(params.symbols_per_block, 512);
        assert_eq!(params.source_blocks, 20);
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

    #[test]
    fn validate_rejects_invalid_spray_pacing_knobs() {
        for c in [
            QuicConfig {
                bwlimit_bps: Some(0),
                ..trusted_quic_config()
            },
            QuicConfig {
                max_spray_symbols_per_flush: 0,
                ..trusted_quic_config()
            },
            QuicConfig {
                responsiveness_pressure: f64::NAN,
                ..trusted_quic_config()
            },
            QuicConfig {
                responsiveness_pressure: -0.1,
                ..trusted_quic_config()
            },
            QuicConfig {
                responsiveness_pressure: 1.1,
                ..trusted_quic_config()
            },
        ] {
            assert!(matches!(c.validate(), Err(QuicTransportError::Config(_))));
        }
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
            Err(QuicTransportError::Config(m)) if m.contains('k')
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
    fn quic_rate_matched_adaptation_applies_calibrated_fec_and_raw_pacing_cap() {
        let config = QuicConfig {
            symbol_size: 1024,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };
        let policy = QuicAdaptivePolicy {
            min_samples_to_activate: 1,
            max_overhead: 0.50,
            ..QuicAdaptivePolicy::default()
        };
        let decision = quic_adaptive_rate_matched_pacing_decision(
            &config,
            &quic_path_estimate(0.05, 24_000_000.0),
            pacing_signal(0.050, 16 * 1024 * 1024, 0.05),
            &policy,
            8,
        )
        .expect("activated estimate yields a QUIC adaptive pacing decision");

        assert!(!decision.rate_plan.cold_start);
        assert!(
            decision.rate_plan.block.overhead > 0.05,
            "lossy path should request calibrated repair overhead"
        );
        assert_eq!(
            decision.config.repair_overhead,
            1.0 + decision.rate_plan.block.overhead
        );
        assert_eq!(
            decision.config.max_block_size,
            usize::from(config.symbol_size)
                * usize::try_from(decision.rate_plan.block.k).expect("test k fits usize")
        );
        assert_eq!(
            decision.config.datagram_fanout,
            decision.rate_plan.block.fanout
        );
        assert_eq!(
            decision.config.bwlimit_bps,
            Some(adaptive_raw_pacing_bytes_per_s(&config, decision.rate_plan))
        );
        assert!(
            decision.spray.pacing_rate_bps <= decision.config.bwlimit_bps.unwrap(),
            "spray pacer must honor the raw rate-matched cap"
        );
    }

    #[test]
    fn quic_rate_matched_adaptation_preserves_operator_bwlimit() {
        let config = QuicConfig {
            bwlimit_bps: Some(128 * 1024),
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };
        let policy = QuicAdaptivePolicy {
            min_samples_to_activate: 1,
            ..QuicAdaptivePolicy::default()
        };
        let decision = quic_adaptive_rate_matched_pacing_decision(
            &config,
            &quic_path_estimate(0.01, 64_000_000.0),
            pacing_signal(0.025, 64 * 1024 * 1024, 0.0),
            &policy,
            8,
        )
        .expect("operator-capped adaptation should be valid");

        assert_eq!(decision.config.bwlimit_bps, Some(128 * 1024));
        assert_eq!(
            decision.spray.limiter,
            QuicSprayPacingLimiter::BandwidthLimit
        );
        assert!(decision.spray.pacing_rate_bps <= 128 * 1024);
    }

    #[test]
    fn quic_rate_matched_adaptation_cold_starts_without_changing_geometry() {
        let config = trusted_quic_config();
        let decision = quic_adaptive_rate_matched_pacing_decision(
            &config,
            &QuicPathEstimate::unknown(),
            pacing_signal(0.050, 256 * 1024, 0.0),
            &QuicAdaptivePolicy::default(),
            4,
        )
        .expect("thin evidence should still produce a bounded pacing cap");

        assert!(decision.rate_plan.cold_start);
        assert_eq!(decision.config.max_block_size, config.max_block_size);
        assert_eq!(decision.config.repair_overhead, config.repair_overhead);
        assert_eq!(decision.config.datagram_fanout, config.datagram_fanout);
        assert_eq!(decision.config.bwlimit_bps, Some(8 * 1024 * 1024));
    }

    #[test]
    fn quic_path_signal_from_a6_stats_carries_rtt_cwnd_and_loss() {
        let signal = quic_path_signal_from_stats(QuicPathStats {
            smoothed_rtt_micros: Some(75_000),
            latest_rtt_micros: Some(80_000),
            rttvar_micros: Some(5_000),
            congestion_window_bytes: 96_000,
            bytes_in_flight: 24_000,
            pto_count: 1,
            packets_acked: 90,
            packets_lost: 10,
            loss_rate: 0.10,
        });

        assert!((signal.smoothed_rtt_s - 0.075).abs() < f64::EPSILON);
        assert_eq!(signal.congestion_window_bytes, 96_000);
        assert!((signal.loss_rate - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn quic_path_signal_from_transport_uses_recovery_loss_counters() {
        let mut transport = QuicTransportMachine::new();
        transport
            .begin_handshake()
            .expect("transport begins handshake");
        transport.on_established().expect("transport establishes");
        for packet_number in 1..=4 {
            transport.on_packet_sent(SentPacketMeta {
                space: PacketNumberSpace::ApplicationData,
                packet_number,
                bytes: 1_200,
                ack_eliciting: true,
                in_flight: true,
                time_sent_micros: packet_number * 1_000,
            });
        }

        let event = transport.on_ack_received(PacketNumberSpace::ApplicationData, &[4], 0, 20_000);
        assert_eq!(event.acked_packets, 1);
        assert_eq!(event.lost_packets, 1);

        let signal = quic_path_signal_from_transport(&transport);
        assert!((signal.loss_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(
            signal.congestion_window_bytes,
            transport.congestion_window_bytes()
        );
        assert!(signal.smoothed_rtt_s > 0.0);
    }

    #[test]
    fn quic_adaptive_controller_consumes_a6_path_stats_and_shifts_arm() {
        fn train(stats: QuicPathStats) -> usize {
            let mut policy = QuicAdaptivePolicy {
                arm_grid_k: vec![512, 8192],
                arm_grid_fanout: vec![1],
                exp3_eta: 0.30,
                min_samples_to_activate: 1,
                ..QuicAdaptivePolicy::default()
            };
            policy.max_overhead = 0.50;

            let mut controller = QuicAdaptiveController::new(policy, 23);
            controller.update_estimate(QuicPathEstimate {
                samples: 8,
                dec_symbols_per_s: 50_000_000.0,
                ..quic_path_estimate(0.02, 20_000_000.0)
            });
            let mut large_selected_late = 0usize;
            let trials = 700usize;
            for t in 0..trials {
                let plan = controller
                    .next_block_plan(DEFAULT_SYMBOL_SIZE)
                    .expect("controller activates");
                if t >= trials - 200 && plan.k == 8192 {
                    large_selected_late += 1;
                }
                let wall_s = if plan.k == 8192 { 0.004 } else { 0.006 };
                observe_quic_adaptive_path_stats(
                    &mut controller,
                    u64::from(plan.k),
                    u64::from(plan.k),
                    wall_s,
                    u64::from(plan.k) * u64::from(DEFAULT_SYMBOL_SIZE),
                    DEFAULT_SYMBOL_SIZE,
                    stats,
                );
            }
            large_selected_late
        }

        let clean_large = train(QuicPathStats {
            smoothed_rtt_micros: Some(10_000),
            latest_rtt_micros: Some(10_000),
            rttvar_micros: Some(1_000),
            congestion_window_bytes: 64 * 1024 * 1024,
            bytes_in_flight: 0,
            pto_count: 0,
            packets_acked: 999,
            packets_lost: 1,
            loss_rate: 0.001,
        });
        let lossy_large = train(QuicPathStats {
            smoothed_rtt_micros: Some(50_000),
            latest_rtt_micros: Some(50_000),
            rttvar_micros: Some(10_000),
            congestion_window_bytes: 512 * 1024,
            bytes_in_flight: 128 * 1024,
            pto_count: 2,
            packets_acked: 75,
            packets_lost: 25,
            loss_rate: 0.25,
        });

        assert!(
            clean_large > 140,
            "clean/high-cwnd A6 stats should learn the large arm, got {clean_large}/200"
        );
        assert!(
            lossy_large < 80,
            "lossy/small-cwnd A6 stats should shift away from the large arm, got {lossy_large}/200"
        );
    }

    fn pacing_signal(rtt_s: f64, cwnd_bytes: u64, loss_rate: f64) -> QuicPathSignalSample {
        QuicPathSignalSample {
            smoothed_rtt_s: rtt_s,
            congestion_window_bytes: cwnd_bytes,
            loss_rate,
        }
    }

    #[test]
    fn quic_spray_pacing_tracks_cwnd_loss_bwlimit_and_pressure() {
        let config = QuicConfig {
            symbol_size: 1024,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };

        let small_cwnd =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 16_000, 0.0));
        let large_cwnd =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.0));
        assert!(
            large_cwnd.max_burst_symbols > small_cwnd.max_burst_symbols,
            "larger cwnd should permit a larger paced burst: small={small_cwnd:?} large={large_cwnd:?}"
        );
        assert_eq!(large_cwnd.max_burst_symbols, 64);

        let lossy =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.40));
        assert_eq!(lossy.limiter, QuicSprayPacingLimiter::LossBackoff);
        assert!(lossy.pacing_rate_bps < large_cwnd.pacing_rate_bps);
        assert!(lossy.max_burst_symbols < large_cwnd.max_burst_symbols);

        let bwlimited = quic_spray_pacing_decision_from_config(
            &QuicConfig {
                bwlimit_bps: Some(128 * 1024),
                max_spray_symbols_per_flush: 64,
                ..config.clone()
            },
            pacing_signal(0.050, 1_048_576, 0.0),
        );
        assert_eq!(bwlimited.limiter, QuicSprayPacingLimiter::BandwidthLimit);
        assert!(bwlimited.pacing_rate_bps <= 128 * 1024);
        assert_eq!(bwlimited.max_burst_symbols, 1);
        assert!(
            bwlimited.pause_after_burst >= Duration::from_millis(8),
            "128 KiB/s cap should force a real post-flush pause: {bwlimited:?}"
        );

        let pressured = quic_spray_pacing_decision_from_config(
            &QuicConfig {
                responsiveness_pressure: 0.90,
                max_spray_symbols_per_flush: 64,
                ..config
            },
            pacing_signal(0.050, 1_048_576, 0.0),
        );
        assert_eq!(
            pressured.limiter,
            QuicSprayPacingLimiter::ResponsivenessBackoff
        );
        assert!(pressured.pacing_rate_bps < large_cwnd.pacing_rate_bps);
        assert!(pressured.max_burst_symbols < large_cwnd.max_burst_symbols);
    }

    #[test]
    fn quic_spray_pacing_counts_authenticated_envelope_bytes() {
        let symbol_size = 1024usize;
        let datagram_bytes = symbol_size + AUTH_ENVELOPE_HEADER_LEN;
        let config = QuicConfig {
            symbol_size: u16::try_from(symbol_size).expect("test symbol size fits"),
            max_datagram_size: datagram_bytes,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };

        let decision = quic_spray_pacing_decision_from_config(
            &config,
            pacing_signal(0.050, u64::try_from((datagram_bytes * 2) - 1).unwrap(), 0.0),
        );

        assert_eq!(
            decision.cwnd_symbols, 1,
            "cwnd symbol accounting must use the QUIC symbol envelope size, not raw RaptorQ payload bytes"
        );
    }

    #[test]
    fn quic_spray_pacing_trace_emits_stable_epoch_fields() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());

        let signal = pacing_signal(0.025, 512 * 1024, 0.125);
        let decision = quic_spray_pacing_decision_from_config(
            &QuicConfig {
                bwlimit_bps: Some(2 * 1024 * 1024),
                max_spray_symbols_per_flush: 16,
                responsiveness_pressure: 0.25,
                ..trusted_quic_config()
            },
            signal,
        );
        decision.trace_epoch(&cx, 7);

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.spray.pacing_epoch")
            .expect("spray pacing trace entry");
        assert_eq!(entry.get_field("epoch"), Some("7"));
        let expected_burst = decision.max_burst_symbols.to_string();
        assert_eq!(
            entry.get_field("max_burst_symbols"),
            Some(expected_burst.as_str())
        );
        assert_eq!(entry.get_field("limiter"), Some("bandwidth_limit"));
        assert!(entry.get_field("pause_after_burst_micros").is_some());
        assert!(entry.get_field("pacing_rate_bps").is_some());
    }

    #[test]
    fn d1_quic_effective_datagram_fanout_is_bounded_by_config_and_cpu() {
        let config = QuicConfig {
            datagram_fanout: 8,
            max_active_connections: 4,
            ..trusted_quic_config()
        };

        assert_eq!(quic_effective_datagram_fanout(&config, 64), 4);
        assert_eq!(quic_effective_datagram_fanout(&config, 2), 2);
        assert_eq!(quic_effective_datagram_fanout(&config, 0), 1);

        let single_connection_config = QuicConfig {
            datagram_fanout: 8,
            max_active_connections: 0,
            ..trusted_quic_config()
        };
        assert_eq!(
            quic_effective_datagram_fanout(&single_connection_config, 64),
            1,
            "zero max_active_connections is normalized to the existing single-connection behavior"
        );
    }

    #[test]
    fn d1_quic_spray_pacing_uses_effective_fanout_bound() {
        let config = QuicConfig {
            datagram_fanout: 8,
            max_active_connections: 4,
            symbol_size: 1024,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };
        let signal = pacing_signal(0.050, 64 * 1024, 0.0);

        let config_bound = quic_spray_pacing_decision_from_config(&config, signal);
        let cpu_bound = quic_spray_pacing_decision_from_config_with_cpu(&config, signal, 2);

        assert_eq!(
            config_bound.cwnd_share_symbols,
            config_bound.cwnd_symbols / 4,
            "default config path should clamp fanout to max_active_connections"
        );
        assert_eq!(
            cpu_bound.cwnd_share_symbols,
            cpu_bound.cwnd_symbols / 2,
            "explicit CPU path should clamp fanout to available parallelism"
        );
        assert!(
            cpu_bound.pacing_rate_bps > config_bound.pacing_rate_bps,
            "fewer effective lanes should give each lane a larger safe pacing share"
        );
    }

    #[test]
    fn d1_quic_block_interleaving_scheduler_feeds_every_lane_and_block() {
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 2,
            },
            QuicFanoutBlock {
                entry: 0,
                sbn: 1,
                symbols: 2,
            },
            QuicFanoutBlock {
                entry: 1,
                sbn: 0,
                symbols: 2,
            },
        ];

        let slots = QuicBlockInterleavingScheduler::new(&blocks, 3).collect::<Vec<_>>();
        assert_eq!(
            slots
                .iter()
                .map(|slot| {
                    (
                        slot.connection,
                        slot.entry,
                        slot.sbn,
                        slot.symbol_index_in_block,
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (0, 0, 0, 0),
                (1, 0, 1, 0),
                (2, 1, 0, 0),
                (0, 0, 0, 1),
                (1, 0, 1, 1),
                (2, 1, 0, 1),
            ],
            "scheduler must interleave blocks before returning to the same block"
        );

        let mut per_connection = [0usize; 3];
        let mut per_block = std::collections::BTreeMap::<(u32, u8), usize>::new();
        for slot in slots {
            per_connection[slot.connection] += 1;
            *per_block.entry((slot.entry, slot.sbn)).or_default() += 1;
        }
        assert_eq!(per_connection, [2, 2, 2]);
        assert_eq!(per_block.get(&(0, 0)), Some(&2));
        assert_eq!(per_block.get(&(0, 1)), Some(&2));
        assert_eq!(per_block.get(&(1, 0)), Some(&2));
    }

    #[test]
    fn d1_quic_block_interleaving_scheduler_skips_empty_blocks_and_clamps_zero_lanes() {
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 0,
            },
            QuicFanoutBlock {
                entry: 7,
                sbn: 2,
                symbols: 1,
            },
        ];
        let scheduler = QuicBlockInterleavingScheduler::new(&blocks, 0);
        assert_eq!(scheduler.connection_count(), 1);
        assert!(!scheduler.is_empty());

        let slots = scheduler.collect::<Vec<_>>();
        assert_eq!(
            slots,
            vec![QuicFanoutSymbolSlot {
                connection: 0,
                entry: 7,
                sbn: 2,
                symbol_index_in_block: 0,
            }]
        );

        assert!(QuicBlockInterleavingScheduler::new(&[], 4).is_empty());
    }

    #[test]
    fn d1_quic_fanout_spray_plan_counts_lanes_and_synthetic_scaling() {
        let config = QuicConfig {
            datagram_fanout: 4,
            max_active_connections: 4,
            ..trusted_quic_config()
        };
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 4,
            },
            QuicFanoutBlock {
                entry: 0,
                sbn: 1,
                symbols: 4,
            },
            QuicFanoutBlock {
                entry: 1,
                sbn: 0,
                symbols: 4,
            },
        ];

        let two_lane = quic_plan_fanout_spray(&config, 2, &blocks);
        let four_lane = quic_plan_fanout_spray(&config, 4, &blocks);

        assert_eq!(two_lane.connection_count, 2);
        assert_eq!(four_lane.connection_count, 4);
        assert_eq!(two_lane.total_symbols, 12);
        assert_eq!(four_lane.total_symbols, 12);
        assert_eq!(two_lane.per_connection_symbols, vec![6, 6]);
        assert_eq!(four_lane.per_connection_symbols, vec![3, 3, 3, 3]);
        assert!(
            four_lane
                .per_connection_symbols
                .iter()
                .all(|symbols| *symbols > 0),
            "all effective fan-out lanes should receive symbol work"
        );

        let two_lane_rounds = two_lane
            .per_connection_symbols
            .iter()
            .copied()
            .max()
            .unwrap_or(0);
        let four_lane_rounds = four_lane
            .per_connection_symbols
            .iter()
            .copied()
            .max()
            .unwrap_or(0);
        assert!(
            four_lane_rounds < two_lane_rounds,
            "synthetic same-workload completion rounds should improve with more lanes"
        );
    }

    #[test]
    fn d1_quic_fanout_dispatch_groups_slots_by_connection() {
        let config = QuicConfig {
            datagram_fanout: 3,
            max_active_connections: 3,
            ..trusted_quic_config()
        };
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 3,
            },
            QuicFanoutBlock {
                entry: 1,
                sbn: 0,
                symbols: 3,
            },
        ];

        let dispatch = quic_plan_fanout_dispatch(&config, 3, &blocks, &[]);

        assert_eq!(dispatch.connection_count, 3);
        assert_eq!(dispatch.total_symbols, 6);
        assert_eq!(dispatch.batches.len(), 3);
        assert!(!dispatch.is_empty());
        for batch in &dispatch.batches {
            assert_eq!(batch.logical_connection, batch.physical_connection);
            assert_eq!(batch.migration_generation, 0);
            assert_eq!(batch.symbol_count(), 2);
            assert!(
                batch
                    .slots
                    .iter()
                    .all(|slot| slot.connection == batch.logical_connection),
                "dispatch batches must preserve the scheduler's logical lane"
            );
        }
    }

    #[test]
    fn d1_quic_fanout_dispatch_remaps_migrated_physical_connection_only() {
        let config = QuicConfig {
            datagram_fanout: 2,
            max_active_connections: 2,
            ..trusted_quic_config()
        };
        let blocks = [QuicFanoutBlock {
            entry: 7,
            sbn: 3,
            symbols: 4,
        }];
        let dispatch = quic_plan_fanout_dispatch(
            &config,
            2,
            &blocks,
            &[
                QuicFanoutLaneBinding {
                    logical_connection: 1,
                    physical_connection: 9,
                    migration_generation: 2,
                },
                QuicFanoutLaneBinding {
                    logical_connection: 99,
                    physical_connection: 99,
                    migration_generation: 99,
                },
            ],
        );

        assert_eq!(dispatch.connection_count, 2);
        assert_eq!(dispatch.total_symbols, 4);
        assert_eq!(dispatch.batches[0].physical_connection, 0);
        assert_eq!(dispatch.batches[0].migration_generation, 0);
        assert_eq!(dispatch.batches[1].physical_connection, 9);
        assert_eq!(dispatch.batches[1].migration_generation, 2);
        assert_eq!(dispatch.batches[0].symbol_count(), 2);
        assert_eq!(dispatch.batches[1].symbol_count(), 2);

        for batch in &dispatch.batches {
            for slot in &batch.slots {
                assert_eq!(slot.connection, batch.logical_connection);
                assert_eq!(slot.entry, 7);
                assert_eq!(slot.sbn, 3);
            }
        }
    }

    #[test]
    fn d1_quic_initial_fanout_blocks_match_round_zero_source_and_repair_geometry() {
        let config = QuicConfig {
            symbol_size: 100,
            max_datagram_size: 160,
            max_block_size: 250,
            repair_overhead: 1.20,
            ..trusted_quic_config()
        };
        let manifest = manifest_from_entries(
            "payload",
            false,
            &[
                ("alpha.bin".to_string(), vec![1_u8; 500]),
                ("empty.bin".to_string(), Vec::new()),
            ],
        );

        let blocks =
            quic_initial_fanout_blocks_for_manifest(&manifest, &config).expect("initial blocks");

        assert_eq!(
            blocks,
            vec![
                QuicFanoutBlock {
                    entry: 0,
                    sbn: 0,
                    symbols: 4,
                },
                QuicFanoutBlock {
                    entry: 0,
                    sbn: 1,
                    symbols: 4,
                },
            ],
            "each 250-byte block has three source symbols plus one proactive repair symbol"
        );
    }

    #[test]
    fn d1_quic_initial_fanout_dispatch_uses_manifest_geometry_and_migration_bindings() {
        let config = QuicConfig {
            datagram_fanout: 3,
            max_active_connections: 3,
            symbol_size: 128,
            max_block_size: 256,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let manifest = manifest_from_entries(
            "payload",
            false,
            &[("alpha.bin".to_string(), vec![7_u8; 768])],
        );

        let dispatch = quic_plan_initial_fanout_dispatch(
            &config,
            3,
            &manifest,
            &[QuicFanoutLaneBinding {
                logical_connection: 2,
                physical_connection: 7,
                migration_generation: 3,
            }],
        )
        .expect("dispatch plan");

        assert_eq!(dispatch.connection_count, 3);
        assert_eq!(dispatch.total_symbols, 6);
        assert_eq!(
            dispatch
                .batches
                .iter()
                .map(QuicFanoutConnectionBatch::symbol_count)
                .collect::<Vec<_>>(),
            vec![2, 2, 2],
            "three 256-byte blocks with two source symbols each should feed every lane evenly"
        );
        assert_eq!(dispatch.batches[2].physical_connection, 7);
        assert_eq!(dispatch.batches[2].migration_generation, 3);
    }

    #[test]
    fn d1_quic_fanout_dispatch_trace_emits_logical_physical_and_total_fields() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());
        let plan = QuicFanoutDispatchPlan {
            connection_count: 2,
            total_symbols: 5,
            batches: vec![
                QuicFanoutConnectionBatch {
                    logical_connection: 0,
                    physical_connection: 0,
                    migration_generation: 0,
                    slots: vec![QuicFanoutSymbolSlot {
                        connection: 0,
                        entry: 1,
                        sbn: 0,
                        symbol_index_in_block: 0,
                    }],
                },
                QuicFanoutConnectionBatch {
                    logical_connection: 1,
                    physical_connection: 9,
                    migration_generation: 4,
                    slots: vec![
                        QuicFanoutSymbolSlot {
                            connection: 1,
                            entry: 1,
                            sbn: 0,
                            symbol_index_in_block: 1,
                        };
                        4
                    ],
                },
            ],
        };

        trace_quic_fanout_dispatch_plan(&cx, 13, &plan);

        let entries = collector
            .peek()
            .into_iter()
            .filter(|entry| entry.message() == "atp_quic.spray.fanout_dispatch")
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get_field("round"), Some("13"));
        assert_eq!(entries[0].get_field("logical_connection"), Some("0"));
        assert_eq!(entries[0].get_field("physical_connection"), Some("0"));
        assert_eq!(entries[0].get_field("symbols"), Some("1"));
        assert_eq!(entries[0].get_field("total_symbols"), Some("5"));
        assert_eq!(entries[1].get_field("logical_connection"), Some("1"));
        assert_eq!(entries[1].get_field("physical_connection"), Some("9"));
        assert_eq!(entries[1].get_field("migration_generation"), Some("4"));
        assert_eq!(entries[1].get_field("symbols"), Some("4"));
    }

    #[test]
    fn d1_quic_fanout_spray_counts_trace_emits_per_connection_fields() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());

        trace_quic_fanout_spray_counts(&cx, 11, &[3, 5, 8]);

        let entries = collector
            .peek()
            .into_iter()
            .filter(|entry| entry.message() == "atp_quic.spray.fanout_connection")
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].get_field("round"), Some("11"));
        assert_eq!(entries[0].get_field("connection"), Some("0"));
        assert_eq!(entries[0].get_field("connections"), Some("3"));
        assert_eq!(entries[0].get_field("symbols"), Some("3"));
        assert_eq!(entries[1].get_field("connection"), Some("1"));
        assert_eq!(entries[1].get_field("symbols"), Some("5"));
        assert_eq!(entries[2].get_field("connection"), Some("2"));
        assert_eq!(entries[2].get_field("symbols"), Some("8"));
    }

    #[test]
    fn quic_effective_block_size_reuses_rq_sizer_for_large_entries() {
        let config = QuicConfig {
            max_block_size: 8 * 1024 * 1024,
            ..trusted_quic_config()
        };
        let entries = vec![("large.bin".to_string(), vec![7_u8; 1024 * 1024])];

        let transfer_config =
            effective_quic_config_for_entries(&config, &entries).expect("sized config");

        assert_eq!(transfer_config.max_block_size, 512 * 1024);
    }

    #[test]
    fn quic_prepare_source_manifest_carries_effective_block_geometry() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("payload.bin");
        std::fs::write(&file, varied_bytes(1024 * 1024, 19)).expect("write payload");
        let config = QuicConfig {
            chunk_size: 31 * 1024,
            max_block_size: 8 * 1024 * 1024,
            ..trusted_quic_config()
        };

        let prepared = block_on(prepare_source_manifest(&cx, &file, &config))
            .expect("source manifest prepares");
        let transfer_config = prepared.effective_config(&config);

        assert_eq!(prepared.max_block_size, 512 * 1024);
        assert_eq!(transfer_config.max_block_size, 512 * 1024);
        assert_eq!(
            block_count_for_len(prepared.manifest.entries[0].size, &transfer_config)
                .expect("block count"),
            2
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
    fn native_frame_transport_missing_stream_reads_as_eof() {
        let (cx, _client, server) = established_pair();
        let mut native_server = server.inner().clone();
        let mut rx = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());

        let frame = rx
            .try_recv(&cx, &mut native_server)
            .expect("missing local stream behaves like EOF");
        assert!(frame.is_none());
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
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 2,
                sbn: 1,
                symbols: 3,
            }],
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 2,
                sbn: 1,
                esi: 15,
            }],
            ..QuicNeedMore::default()
        };
        let feedback_frame =
            json_frame(FrameType::ObjectRequest, &need_more).expect("feedback frame");
        assert_eq!(feedback_frame.frame_type(), FrameType::ObjectRequest);
        assert_eq!(
            parse_json::<QuicNeedMore>(&feedback_frame).expect("parse feedback"),
            need_more
        );
        assert_eq!(
            feedback_frame.payload(),
            br#"{"pending":[0,2,7],"repair_blocks":[{"entry":2,"sbn":1,"symbols":3}],"source_symbols":[{"entry":2,"sbn":1,"esi":15}]}"#
        );

        let keepalive = Frame::empty(FrameType::KeepAlive).expect("keepalive frame");
        assert_eq!(keepalive.version(), ProtocolVersion::CURRENT);
        assert_eq!(keepalive.frame_type(), FrameType::KeepAlive);
        assert!(keepalive.payload().is_empty());
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
        assert!(need.repair_blocks.is_empty());
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

        send_object_complete(&cx, &mut client, &mut sender_control, 7)
            .expect("send object-complete");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_200,
        )
        .expect("deliver object-complete");
        let complete = receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receive object-complete");
        assert_eq!(complete.round_symbols_sent, 7);

        let need = QuicNeedMore {
            pending: vec![1, 3],
            repair_blocks: Vec::new(),
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 3,
                sbn: 2,
                esi: 99,
            }],
            round_symbols_observed: Some(5),
            round_loss_fraction: Some(0.25),
            round_symbols_accepted: Some(4),
            ..QuicNeedMore::default()
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
    fn quic_prepare_source_manifest_preserves_explicit_empty_directory_entry() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("empty")).expect("create empty dir");
        let dest = tempfile::tempdir().expect("dest dir");

        let config = trusted_quic_config();
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("empty directory marker prepares");
        assert_eq!(prepared.manifest.root_name, "payload");
        assert!(prepared.manifest.is_directory);
        assert_eq!(prepared.manifest.total_bytes, 0);
        assert_eq!(prepared.manifest.entries.len(), 1);
        let entry = &prepared.manifest.entries[0];
        assert_eq!(entry.rel_path, "empty");
        assert_eq!(entry.size, 0);
        assert_eq!(entry.sha256_hex, sha256_hex(b""));
        let metadata = entry.metadata.as_ref().expect("directory metadata");
        assert!(matches!(metadata.file_kind, FileKind::Directory));
        assert!(prepared.manifest.metadata_root_hex.is_some());

        let decoders =
            decoders_from_manifest(&prepared.manifest, &config).expect("decoders from manifest");
        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &prepared.manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &config,
        ))
        .expect("commit empty directory entry");
        assert!(receipt.committed);
        assert_eq!(committed_paths.len(), 1);
        assert!(dest.path().join("payload/empty").is_dir());
    }

    #[test]
    fn quic_prepare_source_manifest_preserves_empty_directory_root() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(&root).expect("create empty root");
        let dest = tempfile::tempdir().expect("dest dir");

        let config = trusted_quic_config();
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("empty directory root prepares");
        assert_eq!(prepared.manifest.root_name, "payload");
        assert!(prepared.manifest.is_directory);
        assert_eq!(prepared.manifest.total_bytes, 0);
        assert!(prepared.manifest.entries.is_empty());
        assert!(prepared.manifest.metadata_root_hex.is_none());

        let decoders =
            decoders_from_manifest(&prepared.manifest, &config).expect("decoders from manifest");
        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &prepared.manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &config,
        ))
        .expect("commit empty directory root");
        assert!(receipt.committed);
        assert_eq!(committed_paths.len(), 1);
        assert!(dest.path().join("payload").is_dir());
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
            ..auth_quic_config(0x00BA_D7A6)
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 61))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let symbol = Symbol::from_slice(
            SymbolId::new(decoders[0].object_id, 0, 0),
            &entries[0].1,
            SymbolKind::Source,
        );
        let bad_tag = *AuthenticationTag::zero().as_bytes();
        let envelope = symbol_to_envelope(
            &symbol,
            transfer_tag(&manifest.transfer_id),
            decoders[0].index,
            Some(bad_tag),
        );
        let symbol_auth = config
            .symbol_auth_context()
            .expect("auth config should be valid")
            .expect("auth context should be present");

        let err = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoders[0].object_id,
            Some(&symbol_auth),
        )
        .expect_err("bad auth tag must fail closed before decoder feed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("authentication failed")
        ));
        assert!(!decoders[0].complete);
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
        let transfer_config = prepared.effective_config(&config);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &transfer_config,
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
            &transfer_config,
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
            &transfer_config,
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
        let mut decoders =
            decoders_from_manifest(&received_manifest, &transfer_config).expect("decoders");
        let symbols_accepted = drain_symbol_datagrams(
            &mut server,
            &received_manifest,
            &mut decoders,
            &transfer_config,
        )
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
    fn quic_prepared_source_feedback_retransmits_source_symbol_from_disk_file() {
        let (cx, mut client, mut server) = established_pair();
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("payload.bin");
        let bytes = varied_bytes(4 * 1024, 53);
        std::fs::write(&source, &bytes).expect("write source");
        let config = QuicConfig {
            chunk_size: 23,
            symbol_size: 16,
            max_block_size: 4 * 1024,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &source, &config))
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
            7_100,
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
            7_101,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives ack");

        let mut encoders = block_on(encoders_from_prepared_source(&cx, &prepared, &config))
            .expect("file-backed encoders");
        let symbol_auth = config.symbol_auth_context().expect("symbol auth context");
        send_manifest(&cx, &mut client, &mut sender_control, &prepared.manifest)
            .expect("send manifest");
        let pending_all = encoders
            .iter()
            .map(|entry| entry.index)
            .collect::<std::collections::BTreeSet<_>>();
        let initial_sent = block_on(spray_streaming_symbol_round(
            &cx,
            &mut client,
            &prepared.manifest,
            &mut encoders,
            &pending_all,
            &config,
            symbol_auth.as_ref(),
            true,
        ))
        .expect("send file-backed source-only round");
        assert_eq!(initial_sent, 256);
        send_object_complete(&cx, &mut client, &mut sender_control, initial_sent)
            .expect("send object complete");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_102,
        )
        .expect("deliver prepared source transfer");

        let dropped = server.recv_datagram().expect("drop one source datagram");
        assert!(!dropped.is_empty());
        let received_manifest = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receiver decodes manifest");
        assert_eq!(received_manifest, prepared.manifest);
        let mut decoders = decoders_from_manifest(&received_manifest, &config).expect("decoders");
        let accepted_before =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains surviving source symbols");
        assert_eq!(accepted_before, 255);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees initial object complete");
        assemble_completed_entries(&mut decoders);
        let pending = pending_entries(&decoders);
        assert_eq!(pending, vec![0]);
        let need = QuicNeedMore {
            pending,
            repair_blocks: Vec::new(),
            source_symbols: source_symbol_requests(
                &decoders,
                MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND,
            ),
            ..QuicNeedMore::default()
        };
        assert_eq!(
            need.source_symbols,
            vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 0,
            }]
        );
        send_need_more(&cx, &mut server, &mut receiver_control, &need).expect("send need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            7_103,
        )
        .expect("deliver need-more");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut feedback = QuicSenderFeedbackState::new(
            &prepared.manifest,
            &mut encoders,
            &config,
            peer,
            initial_sent,
        );
        let report = block_on(handle_sender_feedback_or_proof(
            &cx,
            &mut client,
            &mut sender_control,
            &mut feedback,
        ))
        .expect("sender handles file-backed need-more");
        assert!(report.is_none());
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(feedback.symbols_sent, 257);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_104,
        )
        .expect("deliver source retransmit");

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
            "file-backed source retransmit should complete the decoder"
        );
        let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
        assert!(receipt.committed);
        assert_eq!(receipt.bytes_received, bytes.len() as u64);
    }

    #[test]
    fn native_sender_body_transfers_prepared_source_and_receives_proof() {
        let (cx, client, server) = established_pair();
        let mut native_client = client.inner().clone();
        let mut native_server = server.inner().clone();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(384, 67);
        let beta = varied_bytes(640, 71);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");
        let config = QuicConfig {
            chunk_size: 29,
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares from disk");
        let transfer_config = prepared.effective_config(&config);
        let mut receiver_control = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());
        let mut client_to_server_pn = 0u64;
        let mut server_to_client_pn = 0u64;
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let dest = tempfile::tempdir().expect("dest dir");
        let mut receiver_committed = false;

        let report = block_on(send_prepared_source_over_established_native_connection(
            &cx,
            &mut native_client,
            peer,
            &prepared,
            &transfer_config,
            "sender-peer",
            |drive_point, sender| {
                match drive_point {
                    NativeSenderDrivePoint::HelloSent => {
                        pump_native_until_idle(
                            &cx,
                            sender,
                            &mut native_server,
                            &mut client_to_server_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_000,
                        )?;
                        let hello = receive_native_sender_hello_and_ack(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                            &transfer_config,
                            "receiver-peer",
                            false,
                        )?;
                        assert_eq!(hello.peer_id, "sender-peer");
                        pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender,
                            &mut server_to_client_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_001,
                        )?;
                    }
                    NativeSenderDrivePoint::ObjectCompleteSent => {
                        assert!(!receiver_committed, "receiver should commit only once");
                        pump_native_until_idle(
                            &cx,
                            sender,
                            &mut native_server,
                            &mut client_to_server_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_002,
                        )?;

                        let received_manifest = receive_native_manifest(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                        )?;
                        assert_eq!(received_manifest, prepared.manifest);
                        let mut decoders =
                            decoders_from_manifest(&received_manifest, &transfer_config)?;
                        let symbols_accepted = drain_native_symbol_datagrams(
                            &mut native_server,
                            &received_manifest,
                            &mut decoders,
                            &transfer_config,
                        )?;
                        receive_native_object_complete(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                        )?;
                        let decode_stats = assemble_completed_entries(&mut decoders);
                        assert!(
                            pending_entries(&decoders).is_empty(),
                            "prepared native source symbols should decode without repair feedback"
                        );

                        let (receipt, committed_paths) = block_on(commit_decoded_entries(
                            &cx,
                            dest.path(),
                            &received_manifest,
                            &decoders,
                            symbols_accepted,
                            0,
                            decode_stats,
                            &transfer_config,
                        ))?;
                        assert!(receipt.committed);
                        assert_eq!(committed_paths.len(), 2);
                        assert_eq!(
                            std::fs::read(dest.path().join("payload/alpha.bin"))
                                .expect("read alpha"),
                            alpha
                        );
                        assert_eq!(
                            std::fs::read(dest.path().join("payload/nested/beta.bin"))
                                .expect("read beta"),
                            beta
                        );
                        assert!(symbols_accepted > 0);

                        send_native_proof(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                            &receipt,
                        )?;
                        pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender,
                            &mut server_to_client_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_003,
                        )?;
                        receiver_committed = true;
                    }
                }
                Ok(())
            },
        ))
        .expect("native established sender body returns proof report");

        assert!(receiver_committed);
        assert_eq!(report.transfer_id, prepared.manifest.transfer_id);
        assert_eq!(report.bytes_sent, 1_024);
        assert_eq!(report.files, 2);
        assert!(report.receipt.committed);

        pump_native_until_idle(
            &cx,
            &mut native_client,
            &mut native_server,
            &mut client_to_server_pn,
            DEFAULT_MAX_PACKET_BYTES,
            8_004,
        )
        .expect("deliver native close");
        let close = next_native_control_frame(
            &cx,
            &mut native_server,
            &mut receiver_control,
            "receive native close",
        )
        .expect("native receiver sees close");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn quic_targeted_repair_symbols_requests_exact_deficit() {
        assert_eq!(quic_targeted_repair_symbols(0, 512, None, 0), 0);
        assert_eq!(quic_targeted_repair_symbols(1, 512, None, 0), 1);
        assert_eq!(quic_targeted_repair_symbols(512, 512, None, 0), 512);
        assert_eq!(quic_targeted_repair_symbols(10, 512, None, 12), 10);
        assert_eq!(quic_targeted_repair_symbols(10, 512, None, 4), 4);
        assert_eq!(
            quic_targeted_repair_symbols(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND, 512, None, 0),
            MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND
        );
    }

    #[test]
    fn quic_targeted_repair_symbols_tracks_measured_round_loss() {
        assert_eq!(quic_feedback_repair_overhead(None), 0.0);
        assert_eq!(quic_feedback_repair_overhead(Some(0.001)), 0.0);

        let bad = quic_feedback_repair_overhead(Some(0.02));
        assert!(
            (0.029..=0.031).contains(&bad),
            "2% measured loss should request about 3% repair overhead, got {bad}"
        );

        let broken = quic_feedback_repair_overhead(Some(0.10));
        assert!(
            (0.12..=0.15).contains(&broken),
            "10% measured loss should request a bounded 12-15% repair overhead, got {broken}"
        );
        assert_eq!(
            quic_targeted_repair_symbols(1, 512, Some(0.10), 0),
            67,
            "broken-link repair must send enough symbols to survive another lossy repair round"
        );
        assert_eq!(
            quic_targeted_repair_symbols(1, 512, Some(0.10), 16),
            16,
            "feedback round budget still caps adaptive repair"
        );
    }

    #[test]
    fn quic_bounded_k256_repair_feedback_round_recovers_after_source_loss() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 16,
            max_block_size: 4 * 1024,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        assert_eq!(config.max_block_size / usize::from(config.symbol_size), 256);
        let entries = vec![("alpha.bin".to_string(), varied_bytes(4 * 1024, 47))];
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

        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
        let initial_sent = send_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )
        .expect("send source-only round");
        assert_eq!(initial_sent, 256);
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
        assert_eq!(accepted_before, 255);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees initial object complete");
        assemble_completed_entries(&mut decoders);
        let pending = pending_entries(&decoders);
        assert_eq!(pending, vec![0]);
        let need = QuicNeedMore {
            pending,
            repair_blocks: block_repair_requests(
                &decoders,
                &config,
                MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                None,
            ),
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let expected_repair_symbols = u32::try_from(quic_targeted_repair_symbols(
            1,
            256,
            None,
            MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
        ))
        .unwrap_or(u32::MAX);
        assert_eq!(
            need.repair_blocks,
            vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: expected_repair_symbols,
            }],
            "receiver should request exactly the missing repair deficit"
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
        let report = block_on(handle_sender_feedback_or_proof(
            &cx,
            &mut client,
            &mut sender_control,
            &mut feedback,
        ))
        .expect("sender handles need-more");
        assert!(report.is_none());
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(
            feedback.symbols_sent,
            initial_sent + u64::from(need.repair_blocks[0].symbols)
        );
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_004,
        )
        .expect("deliver repair round");

        let repair_envelope = recv_symbol_envelope(&mut server, false)
            .expect("repair envelope parses")
            .expect("targeted repair datagram delivered");
        assert!(repair_envelope.is_repair);
        assert_eq!(repair_envelope.entry, 0);
        assert_eq!(repair_envelope.sbn, 0);
        assert!(repair_envelope.esi >= 256);
        let repair_symbol =
            authenticated_symbol_from_envelope(&repair_envelope, decoders[0].object_id, false)
                .expect("repair symbol");
        assert!(repair_symbol.symbol().kind().is_repair());
        assert!(feed_authenticated_symbol(&mut decoders[0], repair_symbol).expect("feed repair"));
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

        let report = block_on(handle_sender_feedback_or_proof(
            &cx,
            &mut client,
            &mut sender_control,
            &mut feedback,
        ))
        .expect("sender receives proof report")
        .expect("proof completes transfer");
        assert_eq!(report.transfer_id, manifest.transfer_id);
        assert_eq!(report.receipt.bytes_received, 4 * 1024);
        assert_eq!(report.files, 1);
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(
            feedback.symbols_sent,
            initial_sent + u64::from(need.repair_blocks[0].symbols)
        );
    }

    #[test]
    fn quic_sender_keeps_serving_exact_targeted_repair_rounds() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            max_feedback_rounds: 1,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(512, 53))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut feedback = QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, 0);

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
            8_198,
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
            8_199,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives hello ack");

        let first = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: 2,
            }],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        send_need_more(&cx, &mut server, &mut receiver_control, &first)
            .expect("send first need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_200,
        )
        .expect("deliver first need-more");
        assert!(
            block_on(handle_sender_feedback_or_proof(
                &cx,
                &mut client,
                &mut sender_control,
                &mut feedback,
            ))
            .expect("sender serves first targeted repair")
            .is_none()
        );
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(feedback.symbols_sent, 2);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_201,
        )
        .expect("deliver first repair response");
        let first_complete = receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees first repair completion");
        assert_eq!(first_complete.round_symbols_sent, 2);

        let second = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: 3,
            }],
            source_symbols: Vec::new(),
            round_symbols_observed: Some(2),
            round_symbols_accepted: Some(2),
            round_loss_fraction: Some(0.0),
        };
        send_need_more(&cx, &mut server, &mut receiver_control, &second)
            .expect("send second need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_202,
        )
        .expect("deliver second need-more");
        assert!(
            block_on(handle_sender_feedback_or_proof(
                &cx,
                &mut client,
                &mut sender_control,
                &mut feedback,
            ))
            .expect("sender keeps serving targeted repair")
            .is_none()
        );
        assert_eq!(feedback.feedback_rounds, 2);
        assert_eq!(feedback.symbols_sent, 5);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_203,
        )
        .expect("deliver second repair response");
        let second_complete = receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees second repair completion");
        assert_eq!(second_complete.round_symbols_sent, 3);

        let mut repair_envelopes = Vec::new();
        while let Some(envelope) =
            recv_symbol_envelope(&mut server, false).expect("repair envelope parses")
        {
            repair_envelopes.push(envelope);
        }
        assert_eq!(repair_envelopes.len(), 5);
        assert!(
            repair_envelopes
                .iter()
                .all(|envelope| envelope.is_repair && envelope.entry == 0 && envelope.sbn == 0)
        );
        let repair_esis = repair_envelopes
            .iter()
            .map(|envelope| envelope.esi)
            .collect::<Vec<_>>();
        assert_eq!(repair_esis, vec![4, 5, 6, 7, 8]);
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
        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
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
        send_object_complete(&cx, &mut client, &mut sender_control, sent).expect("send complete");
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
    fn receive_connection_observes_cancel_before_native_body() {
        let (_setup_cx, _client, server) = established_pair();
        let cx = cancelled_test_cx();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let temp = tempfile::tempdir().expect("temp dir");

        let err = block_on(receive_connection(
            &cx,
            server.inner().clone(),
            peer,
            temp.path(),
            trusted_quic_config(),
            "receiver-peer",
        ))
        .expect_err("cancelled receive must fail closed");

        assert!(matches!(err, QuicTransportError::Cancelled));
        assert!(
            std::fs::read_dir(temp.path())
                .expect("dest dir still readable")
                .next()
                .is_none(),
            "cancelled receive must not commit files"
        );
    }

    #[test]
    fn native_sender_body_observes_cancel_before_driving_peer() {
        let (setup_cx, client, _server) = established_pair();
        let mut native_client = client.inner().clone();
        let config = trusted_quic_config();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(&root).expect("create payload root");
        std::fs::write(root.join("alpha.bin"), varied_bytes(256, 83)).expect("write alpha");
        let prepared = block_on(prepare_source_manifest(&setup_cx, &root, &config))
            .expect("source manifest prepares from disk");
        let cx = cancelled_test_cx();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut driver_called = false;

        let err = block_on(send_prepared_source_over_established_native_connection(
            &cx,
            &mut native_client,
            peer,
            &prepared,
            &config,
            "sender-peer",
            |_point, _conn| {
                driver_called = true;
                Ok(())
            },
        ))
        .expect_err("cancelled sender must fail closed");

        assert!(matches!(err, QuicTransportError::Cancelled));
        assert!(!driver_called, "cancelled sender must not drive peer I/O");
    }

    #[test]
    fn native_established_sender_body_returns_report_after_receiver_proof() {
        let (cx, client, server) = established_pair();
        let mut native_client = client.inner().clone();
        let mut native_server = server.inner().clone();
        let config = QuicConfig {
            chunk_size: 17,
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(384, 67);
        let beta = varied_bytes(640, 71);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares from disk");
        let transfer_config = prepared.effective_config(&config);
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut client_packet_number = 0u64;
        let mut server_packet_number = 0u64;
        let mut receiver_control: Option<NativeQuicFrameTransport> = None;
        let mut receiver_manifest: Option<TransferManifest> = None;
        let mut receiver_decoders: Option<Vec<QuicEntryDecoder>> = None;
        let receiver_aggregator = primary_quic_receive_aggregator("native-test-peer");
        let mut symbols_accepted = 0u64;
        let mut feedback_rounds = 0u32;
        let mut decode_stats = QuicDecodeStats::default();
        let mut proof_sent = false;

        let report = block_on(send_prepared_source_over_established_native_connection(
            &cx,
            &mut native_client,
            peer,
            &prepared,
            &transfer_config,
            "sender-peer",
            |point, sender_conn| {
                match point {
                    NativeSenderDrivePoint::HelloSent => {
                        let moved = pump_native_until_idle(
                            &cx,
                            sender_conn,
                            &mut native_server,
                            &mut client_packet_number,
                            DEFAULT_MAX_PACKET_BYTES,
                            6_300,
                        )?;
                        assert!(moved > 0);
                        let control = receiver_control.get_or_insert_with(|| {
                            NativeQuicFrameTransport::for_stream(first_client_bidi_stream())
                        });
                        receive_native_sender_hello_and_ack(
                            &cx,
                            &mut native_server,
                            control,
                            &transfer_config,
                            "receiver-peer",
                            false,
                        )?;
                        let moved = pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender_conn,
                            &mut server_packet_number,
                            DEFAULT_MAX_PACKET_BYTES,
                            6_301,
                        )?;
                        assert!(moved > 0);
                    }
                    NativeSenderDrivePoint::ObjectCompleteSent => {
                        let moved = pump_native_until_idle(
                            &cx,
                            sender_conn,
                            &mut native_server,
                            &mut client_packet_number,
                            DEFAULT_MAX_PACKET_BYTES,
                            6_302 + u64::from(feedback_rounds),
                        )?;
                        assert!(moved > 0);
                        let control = receiver_control
                            .as_mut()
                            .expect("receiver control opened after hello");
                        if receiver_manifest.is_none() {
                            let manifest =
                                receive_native_manifest(&cx, &mut native_server, control)?;
                            assert_eq!(manifest, prepared.manifest);
                            receiver_decoders =
                                Some(decoders_from_manifest(&manifest, &transfer_config)?);
                            receiver_manifest = Some(manifest);
                        }
                        let manifest = receiver_manifest
                            .as_ref()
                            .expect("receiver manifest initialized");
                        let decoders = receiver_decoders
                            .as_mut()
                            .expect("receiver decoders initialized");
                        match block_on(receive_native_symbol_round(
                            &cx,
                            &mut native_server,
                            control,
                            manifest,
                            decoders,
                            &transfer_config,
                            &receiver_aggregator,
                            &mut symbols_accepted,
                            &mut feedback_rounds,
                            &mut decode_stats,
                        ))? {
                            Some(_) => {
                                let moved = pump_native_until_idle(
                                    &cx,
                                    &mut native_server,
                                    sender_conn,
                                    &mut server_packet_number,
                                    DEFAULT_MAX_PACKET_BYTES,
                                    6_400 + u64::from(feedback_rounds),
                                )?;
                                assert!(moved > 0);
                            }
                            None => {
                                assert!(!proof_sent, "proof should be sent exactly once");
                                let receipt = verify_in_memory_receipt(manifest, decoders);
                                assert!(receipt.committed);
                                assert!(receipt.sha_ok);
                                assert!(receipt.merkle_ok);
                                send_native_proof(&cx, &mut native_server, control, &receipt)?;
                                let moved = pump_native_until_idle(
                                    &cx,
                                    &mut native_server,
                                    sender_conn,
                                    &mut server_packet_number,
                                    DEFAULT_MAX_PACKET_BYTES,
                                    6_500,
                                )?;
                                assert!(moved > 0);
                                proof_sent = true;
                            }
                        }
                    }
                }
                Ok(())
            },
        ))
        .expect("native established sender reaches proof");

        assert_eq!(report.transfer_id, prepared.manifest.transfer_id);
        assert_eq!(report.bytes_sent, 1_024);
        assert_eq!(report.files, 2);
        assert_eq!(report.peer, peer);
        assert!(report.receipt.committed);
        assert_eq!(report.receipt.bytes_received, 1_024);
        assert!(symbols_accepted > 0);

        let moved = pump_native_until_idle(
            &cx,
            &mut native_client,
            &mut native_server,
            &mut client_packet_number,
            DEFAULT_MAX_PACKET_BYTES,
            6_600,
        )
        .expect("deliver sender close");
        assert!(moved > 0);
        let close = next_native_control_frame(
            &cx,
            &mut native_server,
            receiver_control.as_mut().expect("receiver control"),
            "receive sender close",
        )
        .expect("receiver sees sender close");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn native_receive_rounds_commit_after_targeted_repair_request() {
        let (cx, mut client, mut server) = established_pair();
        let collector = crate::observability::LogCollector::new(16)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            max_feedback_rounds: 2,
            ..trusted_quic_config()
        };
        let payload_entries = vec![("alpha.bin".to_string(), varied_bytes(384, 47))];
        let manifest = manifest_from_entries("payload", true, &payload_entries);
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
        let mut encoders =
            encoders_from_entries(&manifest, &payload_entries, &config).expect("encoders");
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
        let receiver_aggregator = primary_quic_receive_aggregator("native-test-peer");
        let mut symbols_accepted = 0u64;
        let mut feedback_rounds = 0u32;
        let mut decode_stats = QuicDecodeStats::default();
        let need = match block_on(receive_native_symbol_round(
            &cx,
            &mut native_server,
            &mut receiver_control,
            &received_manifest,
            &mut decoders,
            &config,
            &receiver_aggregator,
            &mut symbols_accepted,
            &mut feedback_rounds,
            &mut decode_stats,
        ))
        .expect("initial native receive round asks for repair")
        {
            Some(need) => need,
            None => panic!("dropped source symbol should require repair"),
        };
        assert_eq!(symbols_accepted, 2);
        assert_eq!(feedback_rounds, 1);
        assert_eq!(need.pending, vec![0]);
        let expected_repair_symbols = u32::try_from(quic_targeted_repair_symbols(
            1,
            3,
            None,
            MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
        ))
        .unwrap_or(u32::MAX);
        assert_eq!(
            need.repair_blocks,
            vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: expected_repair_symbols,
            }],
            "receiver should ask for exactly the fresh repair deficit"
        );
        assert!(need.source_symbols.is_empty());
        let trace_entries = collector.peek();
        let need_more_trace = trace_entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.need_more")
            .expect("need-more trace emitted before feedback is sent");
        assert_eq!(
            need_more_trace.level(),
            crate::observability::LogLevel::Trace
        );
        assert_eq!(need_more_trace.get_field("round"), Some("1"));
        assert_eq!(need_more_trace.get_field("pending"), Some("1"));
        assert_eq!(need_more_trace.get_field("block_requests"), Some("1"));
        let expected_repair_symbols = need.repair_blocks[0].symbols.to_string();
        assert_eq!(
            need_more_trace.get_field("repair_symbols"),
            Some(expected_repair_symbols.as_str())
        );
        assert_eq!(need_more_trace.get_field("source_requests"), Some("0"));
        assert_eq!(need_more_trace.get_field("symbols_accepted"), Some("2"));

        let symbol_auth = config.symbol_auth_context().expect("auth posture");
        let repair_sent = block_on(send_repair_round_and_object_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &received_manifest,
            &mut encoders,
            &need,
            &config,
            symbol_auth.as_ref(),
        ))
        .expect("sender sends requested repair symbols");
        assert_eq!(repair_sent, u64::from(need.repair_blocks[0].symbols));
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
            block_on(receive_native_symbol_round(
                &cx,
                &mut native_server,
                &mut receiver_control,
                &received_manifest,
                &mut decoders,
                &config,
                &receiver_aggregator,
                &mut symbols_accepted,
                &mut feedback_rounds,
                &mut decode_stats,
            ))
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
            symbols_accepted,
            feedback_rounds,
            decode_stats,
            &config,
        ))
        .expect("commit decoded repair result");
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
        assert_eq!(receipt.bytes_received, 384);
        assert_eq!(committed_paths.len(), 1);
        assert_eq!(
            std::fs::read(temp.path().join("payload/alpha.bin")).expect("read alpha"),
            payload_entries[0].1
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
        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
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
        send_object_complete(&cx, &mut client, &mut sender_control, 0)
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
    fn quic_receiver_aggregator_deduplicates_symbols_across_paths_before_decoder() {
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 128,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 21))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let cx = Cx::for_testing();
        let trace = TraceBufferHandle::new(4);
        cx.set_trace_buffer(trace.clone());
        let object_id = decoders[0].object_id;
        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            entries[0].1.clone(),
            SymbolKind::Source,
        );
        let aggregator = primary_quic_receive_aggregator("quic-path-a");
        let secondary_path = PathId::new(2);
        aggregator.paths().register(TransportPath::new(
            secondary_path,
            "quic-secondary",
            "quic-path-b",
        ));

        let first = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbol.clone()),
            QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO)
                .with_trace(&cx),
        )
        .expect("first path symbol reaches decoder");
        let duplicate = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbol),
            QuicReceiveAggregation::new(&aggregator, secondary_path, Time::ZERO).with_trace(&cx),
        )
        .expect("duplicate path symbol is handled");

        assert_eq!(first, 1, "first path delivers one symbol");
        assert_eq!(duplicate, 0, "duplicate path is suppressed pre-decoder");
        let aggregate_traces = trace
            .snapshot()
            .iter()
            .filter(|event| {
                matches!(
                    &event.data,
                    TraceData::Message(message)
                        if message == "atp_quic.receive.aggregate_symbol"
                )
            })
            .count();
        assert_eq!(
            aggregate_traces, 2,
            "accepted and duplicate path decisions should be traced"
        );
        let stats = aggregator.stats();
        assert_eq!(stats.total_processed, 2);
        assert_eq!(stats.dedup.unique_symbols, 1);
        assert_eq!(stats.dedup.duplicates_detected, 1);
        assert_eq!(stats.paths.total_received, 2);
        assert_eq!(stats.paths.total_duplicates, 1);

        assemble_completed_entries(&mut decoders);
        assert!(
            decoders[0].complete,
            "unique symbol should decode the object"
        );
        assert_eq!(decoders[0].data, entries[0].1);
        let receipt = verify_in_memory_receipt(&manifest, &decoders);
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
    }

    #[test]
    fn quic_receiver_aggregator_releases_reordered_symbols_before_decoder() {
        let config = QuicConfig {
            symbol_size: 64,
            max_block_size: 192,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(192, 33))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let object_id = decoders[0].object_id;
        let symbols = entries[0]
            .1
            .chunks_exact(usize::from(config.symbol_size))
            .enumerate()
            .map(|(esi, payload)| {
                Symbol::new(
                    SymbolId::new(object_id, 0, u32::try_from(esi).expect("esi fits")),
                    payload.to_vec(),
                    SymbolKind::Source,
                )
            })
            .collect::<Vec<_>>();
        let aggregator = MultipathAggregator::new(AggregatorConfig {
            reorder: ReordererConfig {
                immediate_delivery: false,
                max_buffer_per_object: 4,
                max_sequence_gap: 4,
                ..ReordererConfig::default()
            },
            ..AggregatorConfig::default()
        });
        let secondary_path = PathId::new(2);
        aggregator.paths().register(TransportPath::new(
            QUIC_PRIMARY_RECEIVE_PATH_ID,
            "quic-primary",
            "quic-path-a",
        ));
        aggregator.paths().register(TransportPath::new(
            secondary_path,
            "quic-secondary",
            "quic-path-b",
        ));

        let seq0 = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbols[0].clone()),
            QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO),
        )
        .expect("first source symbol reaches decoder");
        let seq2 = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbols[2].clone()),
            QuicReceiveAggregation::new(&aggregator, secondary_path, Time::from_millis(1)),
        )
        .expect("out-of-order source symbol is buffered");
        let seq1 = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbols[1].clone()),
            QuicReceiveAggregation::new(
                &aggregator,
                QUIC_PRIMARY_RECEIVE_PATH_ID,
                Time::from_millis(2),
            ),
        )
        .expect("gap-fill source symbol releases buffered symbol");

        assert_eq!(seq0, 1, "in-order symbol reaches decoder immediately");
        assert_eq!(seq2, 0, "gap symbol is held by the reorder window");
        assert_eq!(seq1, 2, "gap fill releases itself and buffered seq2");
        let stats = aggregator.stats();
        assert_eq!(stats.paths.total_received, 3);
        assert_eq!(stats.reorder.symbols_buffered, 0);
        assert_eq!(stats.reorder.in_order_deliveries, 2);
        assert_eq!(stats.reorder.reordered_deliveries, 1);

        assemble_completed_entries(&mut decoders);
        assert!(
            decoders[0].complete,
            "reordered source symbols should decode the object"
        );
        assert_eq!(decoders[0].data, entries[0].1);
        let receipt = verify_in_memory_receipt(&manifest, &decoders);
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
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
    fn quic_sender_rejects_oversized_source_symbol_feedback() {
        let config = trusted_quic_config();
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 21))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut source_symbols =
            Vec::with_capacity(MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND + 1);
        for esi in 0..=MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND {
            source_symbols.push(QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: u32::try_from(esi).unwrap_or(u32::MAX),
            });
        }
        let need = QuicNeedMore {
            pending: vec![0],
            repair_blocks: Vec::new(),
            source_symbols,
            ..QuicNeedMore::default()
        };

        let err = validate_need_more_feedback(&manifest, &config, &need)
            .expect_err("oversized peer feedback should fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("source symbols") && message.contains("max")
        ));
    }

    #[test]
    fn quic_sender_validates_targeted_repair_feedback() {
        let config = trusted_quic_config();
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 23))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let repair = QuicBlockRepairRequest {
            entry: 0,
            sbn: 0,
            symbols: 3,
        };
        let valid = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![repair],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let pending =
            validate_need_more_feedback(&manifest, &config, &valid).expect("valid repair request");
        assert!(pending.contains(&0));

        let mixed = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![repair],
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 0,
            }],
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &mixed)
            .expect_err("mixed source and repair feedback must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("both fresh repair blocks")
        ));

        let zero = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                symbols: 0,
                ..repair
            }],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &zero)
            .expect_err("zero-symbol repair request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("zero repair symbols")
        ));

        let invalid_block = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest { sbn: 1, ..repair }],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &invalid_block)
            .expect_err("out-of-range repair block request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("repair block 1 outside")
        ));

        let duplicate = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![repair, repair],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &duplicate)
            .expect_err("duplicate repair block request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("duplicate repair block")
        ));
    }

    #[test]
    fn quic_sender_rejects_duplicate_source_symbol_feedback() {
        let config = trusted_quic_config();
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 22))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let duplicate = QuicSourceSymbolRequest {
            entry: 0,
            sbn: 0,
            esi: 0,
        };
        let need = QuicNeedMore {
            pending: vec![0],
            repair_blocks: Vec::new(),
            source_symbols: vec![duplicate, duplicate],
            ..QuicNeedMore::default()
        };

        let err = validate_need_more_feedback(&manifest, &config, &need)
            .expect_err("duplicate peer feedback should fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("duplicate source symbol")
        ));

        let invalid_esi = QuicNeedMore {
            pending: vec![0],
            repair_blocks: Vec::new(),
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 1,
            }],
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &invalid_esi)
            .expect_err("out-of-range source ESI request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("source request esi 1 outside")
        ));
    }

    #[test]
    fn quic_source_symbol_request_rebuilds_exact_source_payload() {
        let config = QuicConfig {
            symbol_size: 512,
            max_block_size: 1024,
            ..trusted_quic_config()
        };
        let bytes: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
        let enc = QuicEntryEncoder::memory(
            7,
            entry_object_id("source-request", 7),
            bytes.clone(),
            &config,
        );

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
    fn quic_control_handshake_rejects_encoding_layout_mismatch() {
        let config = trusted_quic_config();
        let mut bad_hello = QuicHello {
            protocol: ATP_QUIC_PROTOCOL,
            role: "sender".to_string(),
            peer_id: "sender-peer".to_string(),
            symbol_size: config.symbol_size.saturating_div(2).max(1),
            max_block_size: u64::try_from(config.max_block_size).unwrap_or(u64::MAX),
            symbol_auth: false,
        };

        let reason = reject_hello_reason(&bad_hello, &config, false)
            .expect("symbol size mismatch must reject at handshake");
        assert!(
            reason.contains("symbol_size") && reason.contains(&config.symbol_size.to_string()),
            "{reason}"
        );

        bad_hello.symbol_size = config.symbol_size;
        bad_hello.max_block_size = u64::try_from(config.max_block_size / 2).unwrap_or(1).max(1);
        let reason = reject_hello_reason(&bad_hello, &config, false)
            .expect("block layout mismatch must reject at handshake");
        assert!(
            reason.contains("max_block_size")
                && reason.contains("sender max_block_size")
                && reason.contains("receiver max_block_size")
                && reason.contains("must match")
                && reason.contains(&config.max_block_size.to_string()),
            "{reason}"
        );
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
    fn send_path_valid_source_fails_closed_without_client_tls() {
        // A valid source preflights fine, but a real QUIC connection cannot be
        // opened without client TLS trust (server name + roots) — or, on a build
        // without the `tls` feature, without any native handshake at all. Either
        // way send_path must fail closed with a typed Config error rather than
        // fabricate a transfer.
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
        assert!(
            matches!(result, Err(QuicTransportError::Config(_))),
            "expected a fail-closed Config error, got {result:?}"
        );
    }

    #[test]
    fn send_path_valid_source_traces_initial_fanout_dispatch_before_client_tls() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(16)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("payload.bin");
        std::fs::write(&source, varied_bytes(768, 31)).expect("write source");
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let config = QuicConfig {
            datagram_fanout: 3,
            max_active_connections: 3,
            symbol_size: 128,
            max_datagram_size: 192,
            max_block_size: 256,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };

        let result = block_on(send_path(&cx, addr, &source, config, "sender"));

        assert!(
            matches!(result, Err(QuicTransportError::Config(_))),
            "valid-source send_path should still fail closed without client TLS, got {result:?}"
        );
        let dispatch_entries = collector
            .peek()
            .into_iter()
            .filter(|entry| entry.message() == "atp_quic.spray.fanout_dispatch")
            .collect::<Vec<_>>();
        assert_eq!(dispatch_entries.len(), 3);
        assert_eq!(
            dispatch_entries
                .iter()
                .map(|entry| entry.get_field("symbols"))
                .collect::<Vec<_>>(),
            vec![Some("2"), Some("2"), Some("2")],
            "round-0 preflight should keep all three configured QUIC fan-out lanes fed"
        );
        assert!(
            dispatch_entries
                .iter()
                .all(|entry| entry.get_field("total_symbols") == Some("6"))
        );
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

    #[cfg(unix)]
    #[test]
    fn quic_commit_rejects_existing_destination_symlink_prefix() {
        let cx = Cx::for_testing();
        let dest = tempfile::tempdir().expect("dest dir");
        let outside = tempfile::tempdir().expect("outside dir");
        let base = dest.path().join("payload");
        std::fs::create_dir_all(&base).expect("create destination base");
        std::os::unix::fs::symlink(outside.path(), base.join("link"))
            .expect("create pre-existing destination symlink");

        let bytes = b"must stay inside destination".to_vec();
        let entries = vec![("link/payload.txt".to_string(), bytes.clone())];
        let manifest = manifest_from_entries("payload", true, &entries);
        let decoders = vec![QuicEntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: u64::try_from(bytes.len()).expect("bytes length fits u64"),
            pipeline: None,
            complete: true,
            data: bytes,
            pending_decodes: Vec::new(),
        }];

        let err = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &trusted_quic_config(),
        ))
        .expect_err("commit must reject pre-existing symlink ancestors");
        assert!(
            matches!(err, QuicTransportError::Source(ref message) if message.contains("existing symlink")),
            "expected existing-symlink source error, got {err:?}"
        );
        assert!(
            !outside.path().join("payload.txt").exists(),
            "commit must not follow a destination symlink outside dest_dir"
        );
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
            delta_manifest: None,
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
            symbols_accepted: 3,
            feedback_rounds: 1,
            decode_count: 1,
            decode_micros: 7,
            reason: None,
            committed_paths: vec!["/dest/a.txt".to_string()],
        };
        let json = serde_json::to_vec(&receipt).unwrap();
        let back: ReceiveReceipt = serde_json::from_slice(&json).unwrap();
        assert_eq!(receipt, back);
    }
}
